//! SQLite storage: one file holds the listings, per-host crawl results, a
//! full-text index (FTS5) over file names and folder paths, and the sites
//! waiting to be crawled.
//!
//! The layout is compact (about 130 bytes per file): a folder's URL is stored
//! once in `dirs`, each file only by name in `entries`, and the search index
//! keeps no copy of the text. The `files` view puts full URLs back together.
//!
//! The crawler never touches SQLite directly. It sends messages to a single
//! writer thread, which batches them into transactions.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use percent_encoding::percent_decode_str;
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use tokio::sync::{mpsc, oneshot};
use url::Url;

use crate::filters::{self, Sensitivity};
use crate::listing::Entry;
use crate::quality::{self, Counts, Thresholds};
use crate::safety::{DROP_SENSITIVE_EXPOSURES, HONOR_OPT_OUT_LIST, HONOR_TAKEDOWN_LIST};

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS hosts (
    host       TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    server     TEXT,
    dirs       INTEGER NOT NULL DEFAULT 0,
    files      INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    crawled_at INTEGER NOT NULL,
    reason     TEXT,
    -- 1 for sites you added yourself (seeds): never judged by the quality check.
    trusted    INTEGER NOT NULL DEFAULT 0
);

-- One row per folder listing that was read.
CREATE TABLE IF NOT EXISTS dirs (
    id      INTEGER PRIMARY KEY,
    host    TEXT NOT NULL,
    url     TEXT NOT NULL UNIQUE,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dirs_host ON dirs(host);

-- One row per file or folder in a listing. Its URL is the folder's URL plus
-- `href` (the name as written in the link), or plus `name` when `href` is null.
CREATE TABLE IF NOT EXISTS entries (
    id     INTEGER PRIMARY KEY,
    dir_id INTEGER NOT NULL,
    name   TEXT NOT NULL,
    href   TEXT,
    is_dir INTEGER NOT NULL,
    size   INTEGER,
    mtime  TEXT
);
CREATE INDEX IF NOT EXISTS entries_dir ON entries(dir_id);

-- Search index over names and folder paths. It stores no copy of the text.
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts
    USING fts5(name, path, content='', contentless_delete=1);

-- Every file and folder with its full URL, for browsing with DB Browser or Datasette.
CREATE VIEW IF NOT EXISTS files AS
SELECT d.host AS host,
       d.url || coalesce(e.href, e.name) || CASE WHEN e.is_dir THEN '/' ELSE '' END AS url,
       e.name AS name, e.is_dir AS is_dir, e.size AS size, e.mtime AS mtime
FROM entries e JOIN dirs d ON d.id = e.dir_id;

-- Work still to do: directory URLs to crawl, found by discovery or saved when a
-- crawl was paused. A host's rows are removed once it is finished.
CREATE TABLE IF NOT EXISTS candidates (
    url      TEXT PRIMARY KEY,
    host     TEXT NOT NULL,
    source   TEXT NOT NULL,
    found_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS candidates_host ON candidates(host);

-- Common Crawl index files already scanned, so an interrupted run can resume.
CREATE TABLE IF NOT EXISTS cc_files (
    path       TEXT PRIMARY KEY,
    candidates INTEGER NOT NULL,
    done_at    INTEGER NOT NULL
);
"#;

/// Outcome of crawling one host, stored in `hosts.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// Every reachable directory was crawled.
    Done,
    /// Stopped by the time limit, Ctrl-C or the per-run directory budget. The
    /// directories still to do are saved as candidates; the next run continues.
    Paused,
    /// On the skip list: not crawled, and nothing stored.
    Skipped,
    /// Holds nothing worth keeping (see `quality`): the listings were deleted.
    LowValue,
    /// Given up after too many errors in a row.
    Partial,
    RobotsDisallowed,
    NotListing,
    Sensitive,
    OptedOut,
    Unreachable,
}

impl HostStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HostStatus::Done => "done",
            HostStatus::Paused => "paused",
            HostStatus::Skipped => "skipped",
            HostStatus::LowValue => "low_value",
            HostStatus::Partial => "partial",
            HostStatus::RobotsDisallowed => "robots_disallowed",
            HostStatus::NotListing => "not_listing",
            HostStatus::Sensitive => "sensitive",
            HostStatus::OptedOut => "opted_out",
            HostStatus::Unreachable => "unreachable",
        }
    }
}

pub enum Msg {
    Entries {
        host: String,
        entries: Vec<Entry>,
    },
    HostDone {
        host: String,
        status: HostStatus,
        server: Option<String>,
        dirs: u64,
        /// Why the host was skipped or dropped, e.g. the file that looked sensitive.
        reason: Option<String>,
        /// Delete what was stored for the host (dropped as sensitive, opted out,
        /// or skipped).
        purge: bool,
        /// A site you added yourself.
        trusted: bool,
        /// Judge what is stored for the host by these thresholds, and drop it as
        /// low value if it fails. `None` for trusted sites.
        judge: Option<Thresholds>,
    },
    /// Directory URLs worth crawling later. Already-known URLs are ignored.
    Candidates {
        urls: Vec<Url>,
        source: String,
    },
    /// A crawl stopped before finishing: the candidates it started from are
    /// done, and `frontier` is what is left to crawl next time.
    Paused {
        host: String,
        finished: Vec<Url>,
        frontier: Vec<Url>,
    },
    /// A Common Crawl index file was scanned completely. Its listings are stored
    /// together with the mark, so a file is never marked done without them.
    CcFileDone {
        path: String,
        urls: Vec<Url>,
        source: String,
    },
    /// Replies once everything sent before it is committed.
    Flush(oneshot::Sender<()>),
}

/// `candidates.source` for directories saved by a paused crawl.
pub const RESUME_SOURCE: &str = "resume";

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    // Wait for other programs (e.g. a DB browser) instead of failing straight away.
    conn.busy_timeout(Duration::from_secs(60))?;
    // Earlier versions stored each file's full URL (about 3x the space).
    let old_layout: bool = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('entries') WHERE name = 'url'",
        [],
        |row| row.get(0),
    )?;
    if old_layout {
        bail!(
            "{} was made by an older version of opendir, with a bigger storage layout. \
             Delete it (and its -wal and -shm files) to start a new database, or pass \
             --db with a new file name.",
            path.display()
        );
    }
    register_functions(&conn)?;
    conn.execute_batch(SCHEMA)?;
    // Databases from before the quality check lack `hosts.trusted`.
    let has_trusted: bool = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('hosts') WHERE name = 'trusted'",
        [],
        |row| row.get(0),
    )?;
    if !has_trusted {
        conn.execute_batch("ALTER TABLE hosts ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0")?;
        eprintln!(
            "Upgraded the database. Sites already in it count as found by discovery, so the \
             quality check may remove those that hold little. Sites in your seeds folder are \
             kept; put any other site you want to keep there."
        );
    }
    Ok(conn)
}

/// SQL functions used by the cleanup queries: `is_useful(name, size)` and
/// `sensitivity(name)` (0 none, 1 weak, 2 strong).
fn register_functions(conn: &Connection) -> rusqlite::Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("is_useful", 2, flags, |ctx| {
        let name = ctx.get_raw(0).as_str().unwrap_or("");
        // A folder listing may give no size (NULL): unknown, not zero.
        let size = ctx
            .get_raw(1)
            .as_i64()
            .ok()
            .and_then(|s| u64::try_from(s).ok());
        Ok(quality::is_useful(name, size))
    })?;
    conn.create_scalar_function("sensitivity", 1, flags, |ctx| {
        Ok(
            match filters::sensitivity(ctx.get_raw(0).as_str().unwrap_or("")) {
                None => 0,
                Some(Sensitivity::Weak) => 1,
                Some(Sensitivity::Strong) => 2,
            },
        )
    })?;
    Ok(())
}

/// Like [`open`], but refuses to create a new, empty database.
pub fn open_existing(path: &Path) -> Result<Connection> {
    if !path.exists() {
        bail!(
            "database {} not found; run `opendir crawl` first or pass --db",
            path.display()
        );
    }
    open(path)
}

/// Hosts previously dropped as sensitive exposures; the crawler skips them.
pub fn sensitive_hosts(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT host FROM hosts WHERE status = 'sensitive'")?;
    let hosts = stmt
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(hosts)
}

/// Starts the writer thread. Drop every `Sender` clone, then join the handle
/// to make sure everything is committed.
pub fn spawn_writer(
    path: PathBuf,
) -> Result<(mpsc::Sender<Msg>, std::thread::JoinHandle<Result<()>>)> {
    let mut conn = open(&path)?;
    let (tx, mut rx) = mpsc::channel::<Msg>(1024);
    let handle = std::thread::spawn(move || -> Result<()> {
        while let Some(first) = rx.blocking_recv() {
            // Batch whatever else is already queued into the same transaction.
            let mut batch = vec![first];
            while batch.len() < 10_000 {
                match rx.try_recv() {
                    Ok(msg) => batch.push(msg),
                    Err(_) => break,
                }
            }
            let mut flushes = Vec::new();
            let msgs: Vec<Msg> = batch
                .into_iter()
                .filter_map(|msg| match msg {
                    Msg::Flush(reply) => {
                        flushes.push(reply);
                        None
                    }
                    msg => Some(msg),
                })
                .collect();

            // Another program holding the write lock (a DB browser with unsaved
            // edits, another opendir) is waited out: 60 s per try, 10 tries.
            let mut tries = 0;
            loop {
                match write_batch(&mut conn, &msgs) {
                    Ok(()) => break,
                    Err(e) if is_busy(&e) && tries < 10 => {
                        tries += 1;
                        eprintln!("database is locked by another program; still waiting...");
                    }
                    Err(e) => return Err(e).context("writing to the database"),
                }
            }
            for reply in flushes {
                let _ = reply.send(());
            }
        }
        Ok(())
    });
    Ok((tx, handle))
}

/// Writes a batch in one transaction. The write lock is taken first
/// (`IMMEDIATE`), so a busy database is waited for instead of failing halfway.
/// Each message is applied atomically: one that fails is undone and logged,
/// and the rest of the batch is kept.
fn write_batch(conn: &mut Connection, msgs: &[Msg]) -> rusqlite::Result<()> {
    let mut txn = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for msg in msgs {
        let savepoint = txn.savepoint()?;
        match apply(&savepoint, msg) {
            Ok(()) => savepoint.commit()?,
            Err(e) => eprintln!("database: skipped one update: {e:#}"),
        }
    }
    txn.commit()
}

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn apply(conn: &Connection, msg: &Msg) -> Result<()> {
    let now = unix_now();
    match msg {
        Msg::Entries { host, entries } => store_listing(conn, host, entries, now)?,
        Msg::HostDone {
            host,
            status,
            server,
            dirs,
            reason,
            purge,
            trusted,
            judge,
        } => {
            if *purge {
                purge_host(conn, host)?;
            }
            conn.execute(
                "INSERT INTO hosts (host, status, server, dirs, files, bytes, crawled_at, reason, trusted)
                 SELECT ?1, ?2, ?3, ?4, count(e.id), CAST(total(e.size) AS INTEGER), ?5, ?6, ?7
                 FROM dirs d JOIN entries e ON e.dir_id = d.id AND e.is_dir = 0
                 WHERE d.host = ?1
                 ON CONFLICT(host) DO UPDATE SET
                    status = excluded.status, server = coalesce(excluded.server, hosts.server),
                    dirs = excluded.dirs
                        + CASE WHEN hosts.status = 'paused' THEN hosts.dirs ELSE 0 END,
                    files = excluded.files, bytes = excluded.bytes,
                    crawled_at = excluded.crawled_at, reason = excluded.reason,
                    trusted = max(hosts.trusted, excluded.trusted)",
                params![host, status.as_str(), server, *dirs as i64, now, reason, *trusted],
            )?;
            if *status != HostStatus::Paused {
                conn.execute("DELETE FROM candidates WHERE host = ?1", [host])?;
            }
            // Judge everything stored for the site, across runs.
            let judged = matches!(
                status,
                HostStatus::Done | HostStatus::Paused | HostStatus::Partial
            );
            let finished = *status == HostStatus::Done;
            if let (Some(thresholds), true) = (judge, judged)
                && let Some(why) = thresholds.judge(&host_counts(conn, host, !finished)?, finished)
            {
                mark_host(conn, host, HostStatus::LowValue, &why)?;
            }
        }
        Msg::Candidates { urls, source } => insert_candidates(conn, urls, source, now)?,
        Msg::Paused {
            host,
            finished,
            frontier,
        } => {
            // Keep only the saved frontier (plus directories saved past the budget
            // during this run): a seed or link URL higher up the tree would make
            // the next run start over from the top.
            conn.execute(
                "DELETE FROM candidates WHERE host = ?1 AND source != ?2",
                params![host, RESUME_SOURCE],
            )?;
            let mut stmt = conn.prepare_cached("DELETE FROM candidates WHERE url = ?1")?;
            for url in finished {
                stmt.execute([url.as_str()])?;
            }
            insert_candidates(conn, frontier, RESUME_SOURCE, now)?;
        }
        // Handled by the writer loop; nothing to store.
        Msg::Flush(_) => {}
        Msg::CcFileDone { path, urls, source } => {
            insert_candidates(conn, urls, source, now)?;
            conn.execute(
                "INSERT OR REPLACE INTO cc_files (path, candidates, done_at) VALUES (?1, ?2, ?3)",
                params![path, urls.len() as i64, now],
            )?;
        }
    }
    Ok(())
}

/// Stores one listing. A listing read again replaces what was stored for it,
/// so files that disappeared from the server disappear here too.
fn store_listing(conn: &Connection, host: &str, entries: &[Entry], now: i64) -> Result<()> {
    // Folder URL -> (id, decoded path for the search index). All entries of a
    // listing share one folder, but don't rely on it.
    let mut dirs: HashMap<String, (i64, String)> = HashMap::new();
    let mut add_entry = conn.prepare_cached(
        "INSERT INTO entries (dir_id, name, href, is_dir, size, mtime) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut add_to_index =
        conn.prepare_cached("INSERT INTO entries_fts (rowid, name, path) VALUES (?1, ?2, ?3)")?;
    for e in entries {
        let (dir_url, href) = split_url(&e.url);
        if !dirs.contains_key(&dir_url) {
            let id: i64 = conn.query_row(
                "INSERT INTO dirs (host, url, seen_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(url) DO UPDATE SET seen_at = excluded.seen_at
                 RETURNING id",
                params![host, dir_url, now],
                |row| row.get(0),
            )?;
            delete_dir_entries(conn, id)?;
            let path = Url::parse(&dir_url).map_or(String::new(), |u| {
                percent_decode_str(u.path())
                    .decode_utf8_lossy()
                    .into_owned()
            });
            dirs.insert(dir_url.clone(), (id, path));
        }
        let (dir_id, path) = &dirs[&dir_url];
        let href = (href != e.name).then_some(href);
        add_entry.execute(params![
            dir_id,
            e.name,
            href,
            e.is_dir,
            e.size.map(|s| s as i64),
            e.mtime
        ])?;
        add_to_index.execute(params![conn.last_insert_rowid(), e.name, path])?;
    }
    Ok(())
}

/// A file's folder URL (ending in `/`) and its name as written in the URL,
/// without the trailing `/` of folders.
fn split_url(url: &Url) -> (String, String) {
    let s = url.as_str();
    let s = s.strip_suffix('/').unwrap_or(s);
    let cut = s.rfind('/').map_or(0, |i| i + 1);
    (s[..cut].to_string(), s[cut..].to_string())
}

fn delete_dir_entries(conn: &Connection, dir_id: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM entries_fts WHERE rowid IN (SELECT id FROM entries WHERE dir_id = ?1)",
        [dir_id],
    )?;
    conn.execute("DELETE FROM entries WHERE dir_id = ?1", [dir_id])?;
    Ok(())
}

/// Deletes every listing stored for a host. Returns how many files that was.
fn purge_host(conn: &Connection, host: &str) -> Result<usize> {
    conn.execute(
        "DELETE FROM entries_fts WHERE rowid IN (
             SELECT e.id FROM entries e JOIN dirs d ON d.id = e.dir_id WHERE d.host = ?1)",
        [host],
    )?;
    let files = conn.execute(
        "DELETE FROM entries WHERE dir_id IN (SELECT id FROM dirs WHERE host = ?1)",
        [host],
    )?;
    conn.execute("DELETE FROM dirs WHERE host = ?1", [host])?;
    Ok(files)
}

/// What a site holds, counted over its stored files. With `leaf_only`, only
/// files in folders that have no sub-folders count: that is all an unfinished
/// crawl can judge, since the top of an archive is README and index files and
/// the downloads are further down.
fn host_counts(conn: &Connection, host: &str, leaf_only: bool) -> Result<Counts> {
    let counts = conn.query_row(
        "SELECT count(e.id), coalesce(sum(e.size >= ?2), 0),
                coalesce(sum(is_useful(e.name, e.size)), 0)
         FROM dirs d JOIN entries e ON e.dir_id = d.id AND e.is_dir = 0
         WHERE d.host = ?1
           AND (?3 = 0 OR NOT EXISTS (
                SELECT 1 FROM entries s WHERE s.dir_id = d.id AND s.is_dir = 1))",
        params![host, quality::BIG_FILE as i64, leaf_only],
        |row| {
            Ok(Counts {
                files: row.get::<_, i64>(0)? as u64,
                big: row.get::<_, i64>(1)? as u64,
                useful: row.get::<_, i64>(2)? as u64,
            })
        },
    )?;
    Ok(counts)
}

/// Deletes everything stored for a site and keeps only its status and the
/// reason, so it is not found and crawled again.
fn mark_host(conn: &Connection, host: &str, status: HostStatus, reason: &str) -> Result<()> {
    let msg = Msg::HostDone {
        host: host.to_string(),
        status,
        server: None,
        dirs: 0,
        reason: Some(reason.to_string()),
        purge: true,
        trusted: false,
        judge: None,
    };
    apply(conn, &msg)
}

// ---------------------------------------------------------------------------
// Candidates: work still to do
// ---------------------------------------------------------------------------

/// Adds directory URLs to crawl for hosts never crawled before. Hosts already
/// in `hosts` are ignored, paused ones included: they continue from their
/// saved frontier instead.
pub fn add_candidates(conn: &Connection, urls: &[Url], source: &str) -> Result<()> {
    insert_candidates(conn, urls, source, unix_now())
}

/// Marks sites you named on the command line as trusted, so the quality check
/// never judges them.
pub fn trust_hosts(conn: &Connection, urls: &[Url]) -> Result<()> {
    let hosts: HashSet<String> = urls.iter().filter_map(filters::canonical_host_of).collect();
    for host in hosts {
        conn.execute("UPDATE hosts SET trusted = 1 WHERE host = ?1", [host])?;
    }
    Ok(())
}

/// `candidates.source` for sites you added yourself.
pub const SEED_SOURCE: &str = "seed";

/// Adds sites you chose. They are trusted, and earlier verdicts that a retry or
/// a fix may change (not a listing, unreachable, given up, low value, and
/// sensitive, since those rules have changed before) are forgotten so they are
/// tried again. Returns how many sites were retried.
pub fn add_seeds(conn: &Connection, urls: &[Url]) -> Result<usize> {
    let hosts: HashSet<String> = urls.iter().filter_map(filters::canonical_host_of).collect();
    let mut retried = 0;
    for host in &hosts {
        retried += conn.execute(
            "DELETE FROM hosts WHERE host = ?1
             AND status IN ('not_listing', 'unreachable', 'partial', 'low_value', 'sensitive')",
            [host],
        )?;
        conn.execute("UPDATE hosts SET trusted = 1 WHERE host = ?1", [host])?;
    }
    insert_candidates(conn, urls, SEED_SOURCE, unix_now())?;
    Ok(retried)
}

fn insert_candidates(conn: &Connection, urls: &[Url], source: &str, now: i64) -> Result<()> {
    // A frontier may be saved for a host that is running or paused; anything
    // else only for hosts never crawled.
    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO candidates (url, host, source, found_at)
         SELECT ?1, ?2, ?3, ?4
         WHERE NOT EXISTS (
             SELECT 1 FROM hosts WHERE host = ?2 AND (?3 != 'resume' OR status != 'paused'))",
    )?;
    for url in urls {
        if let Some(host) = filters::canonical_host_of(url) {
            stmt.execute(params![url.as_str(), host, source, now])?;
        }
    }
    if source == SEED_SOURCE {
        // `INSERT OR IGNORE` keeps an older row for the same URL (a link or a
        // Common Crawl find), which would leave the site looking like one you did
        // not add. A saved folder to continue from keeps its own source.
        let mut promote = conn.prepare_cached(
            "UPDATE candidates SET source = ?2 WHERE url = ?1 AND source NOT IN (?2, ?3)",
        )?;
        for url in urls {
            promote.execute(params![url.as_str(), SEED_SOURCE, RESUME_SOURCE])?;
        }
    }
    Ok(())
}

/// The URLs waiting for a site, shortest first.
pub fn candidate_urls(conn: &Connection, host: &str) -> Result<Vec<Url>> {
    let mut stmt = conn
        .prepare_cached("SELECT url FROM candidates WHERE host = ?1 ORDER BY length(url), url")?;
    let urls = stmt
        .query_map([host], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(urls.iter().filter_map(|u| Url::parse(u).ok()).collect())
}

/// A site with work waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHost {
    pub host: String,
    /// All its seed URLs. They are not pruned to the shallowest: a site's `/` is
    /// often a homepage rather than a listing, so `/pub/` must stay a seed. The
    /// crawler never fetches a URL twice.
    pub urls: Vec<Url>,
    /// You added it (a seed), now or in an earlier run.
    pub trusted: bool,
    /// It was crawled before (paused), so this is not its first run.
    pub known: bool,
}

/// Up to `want` sites with work to do, skipping `exclude` (sites already being
/// crawled). Sites you added come first, then sites being continued, then sites
/// found through links, then Common Crawl finds; oldest first within each.
pub fn pending_hosts(
    conn: &Connection,
    want: usize,
    exclude: &HashSet<String>,
) -> Result<Vec<PendingHost>> {
    let mut stmt = conn.prepare_cached(
        "SELECT c.host, c.url,
                EXISTS (SELECT 1 FROM candidates s WHERE s.host = c.host AND s.source = 'seed')
                    OR coalesce((SELECT h.trusted FROM hosts h WHERE h.host = c.host), 0),
                EXISTS (SELECT 1 FROM hosts h WHERE h.host = c.host)
         FROM candidates c
         JOIN (SELECT c2.host AS host,
                      min(CASE c2.source WHEN 'seed' THEN 0 WHEN 'resume' THEN 1
                                         WHEN 'link' THEN 2 ELSE 3 END) AS prio,
                      min(c2.found_at) AS found
               FROM candidates c2
               WHERE NOT EXISTS (
                   SELECT 1 FROM hosts h WHERE h.host = c2.host AND h.status != 'paused')
               GROUP BY c2.host
               ORDER BY prio, found, c2.host
               LIMIT ?1) r ON r.host = c.host
         ORDER BY r.prio, r.found, c.host, length(c.url), c.url",
    )?;
    let limit = (want + exclude.len()) as i64;
    let rows: Vec<(String, String, bool, bool)> = stmt
        .query_map([limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut hosts: Vec<PendingHost> = Vec::new();
    for (host, raw, trusted, known) in rows {
        if exclude.contains(&host) {
            continue;
        }
        if hosts.last().is_none_or(|h| h.host != host) {
            if hosts.len() == want {
                break;
            }
            hosts.push(PendingHost {
                host,
                urls: Vec::new(),
                trusted,
                known,
            });
        }
        if let (Ok(url), Some(last)) = (Url::parse(&raw), hosts.last_mut()) {
            last.urls.push(url);
        }
    }
    Ok(hosts)
}

/// Drops every known host that is on the opt-out list: its entries and waiting
/// work are deleted and only the `opted_out` status is kept. Returns them.
pub fn apply_optout(conn: &Connection, optout: &[String]) -> Result<Vec<String>> {
    if !HONOR_OPT_OUT_LIST {
        return Ok(Vec::new());
    }
    drop_listed_hosts(conn, optout, HostStatus::OptedOut, "on the opt-out list")
}

/// Applies the skip list to what is already stored: sites on it are dropped
/// like opted-out ones, and listings inside skipped folders are deleted.
/// Returns the sites dropped and the number of listings deleted.
pub fn apply_skip_list(
    conn: &Connection,
    skip: &filters::SkipList,
) -> Result<(Vec<String>, usize)> {
    let hosts = drop_listed_hosts(conn, skip.hosts(), HostStatus::Skipped, "on the skip list")?;
    if !skip.has_folders() {
        return Ok((hosts, 0));
    }
    let mut stmt = conn.prepare("SELECT id, url FROM dirs")?;
    let skipped: Vec<i64> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|row| row.ok())
        .filter(|(_, url)| Url::parse(url).is_ok_and(|u| skip.skips_folder(&u)))
        .map(|(id, _)| id)
        .collect();
    for id in &skipped {
        delete_dir_entries(conn, *id)?;
        conn.execute("DELETE FROM dirs WHERE id = ?1", [id])?;
    }
    Ok((hosts, skipped.len()))
}

fn drop_listed_hosts(
    conn: &Connection,
    list: &[String],
    status: HostStatus,
    reason: &str,
) -> Result<Vec<String>> {
    if list.is_empty() {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT host FROM hosts WHERE status != ?1
         UNION SELECT host FROM candidates
         UNION SELECT host FROM dirs",
    )?;
    let hosts: Vec<String> = stmt
        .query_map([status.as_str()], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let dropped: Vec<String> = hosts
        .into_iter()
        .filter(|h| filters::host_opted_out(h, list))
        .collect();
    for host in &dropped {
        mark_host(conn, host, status, reason)?;
    }
    Ok(dropped)
}

/// What to enforce on stored data.
pub struct CleanRules<'a> {
    pub optout: &'a [String],
    pub skip: &'a filters::SkipList,
    pub quality: Thresholds,
}

/// What `clean` removed.
#[derive(Debug, Default)]
pub struct CleanReport {
    pub opted_out: Vec<String>,
    pub skipped_hosts: Vec<String>,
    pub skipped_dirs: usize,
    /// Sites dropped as sensitive, with the reason.
    pub sensitive: Vec<(String, String)>,
    /// Single entries removed from trusted sites (weak sensitive names).
    pub omitted_entries: usize,
    /// Sites dropped as low value, with the reason.
    pub low_value: Vec<(String, String)>,
}

impl CleanReport {
    pub fn is_empty(&self) -> bool {
        self.opted_out.is_empty()
            && self.skipped_hosts.is_empty()
            && self.skipped_dirs == 0
            && self.sensitive.is_empty()
            && self.omitted_entries == 0
            && self.low_value.is_empty()
    }
}

/// Applies today's rules to what is already stored, so the database heals when
/// the rules improve: opt-outs, the skip list, sensitive names and folders, and
/// the quality check. Runs at the start of every crawl.
pub fn clean(conn: &mut Connection, rules: &CleanRules) -> Result<CleanReport> {
    let txn = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut report = CleanReport {
        opted_out: apply_optout(&txn, rules.optout)?,
        ..CleanReport::default()
    };
    (report.skipped_hosts, report.skipped_dirs) = apply_skip_list(&txn, rules.skip)?;
    if DROP_SENSITIVE_EXPOSURES {
        (report.sensitive, report.omitted_entries) = apply_sensitive(&txn)?;
    }
    if rules.quality.enabled() {
        report.low_value = apply_quality(&txn, rules.quality)?;
    }
    txn.commit()?;
    Ok(report)
}

/// Rewrites the database file without the space freed by deleted rows, if that
/// is a lot: at least `min_free_pages` pages and a quarter of the file. SQLite
/// otherwise keeps the file as big as it ever was. Returns whether it did.
pub fn compact_if_wasteful(conn: &Connection, min_free_pages: i64) -> Result<bool> {
    let free: i64 = conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
    let total: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    if free < min_free_pages || free * 4 < total {
        return Ok(false);
    }
    conn.execute_batch("VACUUM")?;
    Ok(true)
}

/// Sites with a strong sensitive name or folder are dropped; a weak name drops
/// a site you did not add yourself, and only the entry on one you did.
fn apply_sensitive(conn: &Connection) -> Result<(Vec<(String, String)>, usize)> {
    let mut to_drop: HashMap<String, String> = HashMap::new();
    // Entries to remove from sites you added: id, and for a folder its URL.
    let mut omit: Vec<(i64, Option<String>)> = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT d.host, d.url, e.id, e.name, sensitivity(e.name),
                coalesce(h.trusted, 0)
                    OR EXISTS (SELECT 1 FROM candidates c
                               WHERE c.host = d.host AND c.source = 'seed'),
                CASE WHEN e.is_dir THEN d.url || coalesce(e.href, e.name) || '/' END
         FROM entries e JOIN dirs d ON d.id = e.dir_id
         LEFT JOIN hosts h ON h.host = d.host
         WHERE sensitivity(e.name) > 0",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, bool>(5)?,
            row.get::<_, Option<String>>(6)?,
        ))
    })?;
    for row in rows {
        let (host, dir_url, id, name, level, trusted, folder) = row?;
        if level == 2 || !trusted {
            to_drop
                .entry(host)
                .or_insert(format!("found {dir_url}{name}"));
        } else {
            omit.push((id, folder));
        }
    }
    drop(stmt);

    let mut stmt = conn.prepare("SELECT host, url FROM dirs")?;
    let dirs = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    for (host, url) in dirs {
        if Url::parse(&url).is_ok_and(|u| filters::is_sensitive_path(u.path())) {
            to_drop.entry(host).or_insert(format!("listing at {url}"));
        }
    }

    let mut dropped: Vec<(String, String)> = to_drop.into_iter().collect();
    dropped.sort();
    for (host, reason) in &dropped {
        mark_host(conn, host, HostStatus::Sensitive, reason)?;
    }
    // Entries of dropped sites are already gone; delete the rest one by one.
    let mut omitted = 0;
    for (id, folder) in omit {
        conn.execute("DELETE FROM entries_fts WHERE rowid = ?1", [id])?;
        omitted += conn.execute("DELETE FROM entries WHERE id = ?1", [id])?;
        if let Some(folder) = folder {
            delete_below(conn, &folder)?;
        }
    }
    Ok((dropped, omitted))
}

/// Deletes the listings stored for a folder and for everything below it.
fn delete_below(conn: &Connection, folder_url: &str) -> Result<()> {
    const BELOW: &str = "substr(url, 1, length(?1)) = ?1";
    conn.execute(
        &format!(
            "DELETE FROM entries_fts WHERE rowid IN (
                 SELECT id FROM entries WHERE dir_id IN (SELECT id FROM dirs WHERE {BELOW}))"
        ),
        [folder_url],
    )?;
    conn.execute(
        &format!("DELETE FROM entries WHERE dir_id IN (SELECT id FROM dirs WHERE {BELOW})"),
        [folder_url],
    )?;
    conn.execute(&format!("DELETE FROM dirs WHERE {BELOW}"), [folder_url])?;
    Ok(())
}

/// Drops sites you did not add that hold too little to keep.
fn apply_quality(conn: &Connection, thresholds: Thresholds) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT h.host, h.status, count(e.id), coalesce(sum(e.size >= ?1), 0),
                coalesce(sum(is_useful(e.name, e.size)), 0)
         FROM hosts h
         LEFT JOIN dirs d ON d.host = h.host
         LEFT JOIN entries e ON e.dir_id = d.id AND e.is_dir = 0
              AND (h.status = 'done'
                   OR NOT EXISTS (SELECT 1 FROM entries s WHERE s.dir_id = d.id AND s.is_dir = 1))
         WHERE h.trusted = 0 AND h.status IN ('done', 'paused', 'partial')
         GROUP BY h.host
         ORDER BY h.host",
    )?;
    let rows = stmt
        .query_map([quality::BIG_FILE as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)? == HostStatus::Done.as_str(),
                Counts {
                    files: row.get::<_, i64>(2)? as u64,
                    big: row.get::<_, i64>(3)? as u64,
                    useful: row.get::<_, i64>(4)? as u64,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let mut dropped = Vec::new();
    for (host, finished, counts) in rows {
        if let Some(reason) = thresholds.judge(&counts, finished) {
            mark_host(conn, &host, HostStatus::LowValue, &reason)?;
            dropped.push((host, reason));
        }
    }
    Ok(dropped)
}

/// Removes everything known about a host (crawl result, entries, candidates),
/// so it can be crawled or re-checked from scratch. Returns false if unknown.
pub fn forget(conn: &Connection, host: &str) -> Result<bool> {
    let had_dirs = conn.query_row("SELECT count(*) FROM dirs WHERE host = ?1", [host], |row| {
        row.get::<_, i64>(0)
    })? > 0;
    purge_host(conn, host)?;
    let mut known = had_dirs;
    known |= conn.execute("DELETE FROM hosts WHERE host = ?1", [host])? > 0;
    known |= conn.execute("DELETE FROM candidates WHERE host = ?1", [host])? > 0;
    Ok(known)
}

/// Common Crawl index files that were already scanned completely.
pub fn done_cc_files(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare("SELECT path FROM cc_files")?;
    let paths = stmt
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(paths)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

pub struct SearchOptions {
    pub limit: usize,
    /// Only files with one of these extensions, separated by commas: `mp3,flac`.
    pub ext: Option<String>,
    /// Only files at least this many bytes big.
    pub min_bytes: Option<u64>,
    /// Skip the likely-infringement filter.
    pub unfiltered: bool,
    /// URL prefixes hidden from results (`HONOR_TAKEDOWN_LIST`).
    pub takedown: Vec<String>,
    /// Opted-out domains, hidden from results even before a crawl drops them.
    pub optout: Vec<String>,
}

#[derive(Debug)]
pub struct Hit {
    pub url: String,
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub mtime: Option<String>,
}

pub fn search(conn: &Connection, query: &str, opts: SearchOptions) -> Result<Vec<Hit>> {
    let fts_query = fts_query(query).context("the query has no searchable words")?;

    let SearchOptions {
        limit,
        ext,
        min_bytes,
        unfiltered,
        takedown,
        optout,
    } = opts;
    conn.create_scalar_function(
        "ext_in",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let name = ctx.get_raw(0).as_str().unwrap_or("").to_lowercase();
            let list = ctx.get_raw(1).as_str().unwrap_or("");
            Ok(list
                .split(',')
                .any(|ext| !ext.is_empty() && name.ends_with(&format!(".{ext}"))))
        },
    )?;
    conn.create_scalar_function(
        "hidden",
        3,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let url = ctx.get_raw(0).as_str().unwrap_or("");
            let name = ctx.get_raw(1).as_str().unwrap_or("");
            let host = ctx.get_raw(2).as_str().unwrap_or("");
            let taken_down = HONOR_TAKEDOWN_LIST && filters::url_taken_down(url, &takedown);
            let opted_out = HONOR_OPT_OUT_LIST && filters::host_opted_out(host, &optout);
            Ok(taken_down || opted_out || (!unfiltered && filters::is_likely_infringing(name)))
        },
    )?;

    let mut stmt = conn.prepare(
        "SELECT r.url, r.name, r.is_dir, r.size, r.mtime FROM (
             SELECT d.url || coalesce(e.href, e.name)
                        || CASE WHEN e.is_dir THEN '/' ELSE '' END AS url,
                    e.name AS name, e.is_dir AS is_dir, e.size AS size, e.mtime AS mtime,
                    d.host AS host, bm25(entries_fts, 10.0, 1.0) AS rank
             FROM entries_fts
             JOIN entries e ON e.id = entries_fts.rowid
             JOIN dirs d ON d.id = e.dir_id
             WHERE entries_fts MATCH ?1
               AND (?2 IS NULL OR (e.is_dir = 0 AND ext_in(e.name, ?2)))
               AND (?4 IS NULL OR e.size >= ?4)
         ) r
         WHERE NOT hidden(r.url, r.name, r.host)
           AND NOT EXISTS (SELECT 1 FROM hosts h WHERE h.host = r.host
                           AND h.status IN ('opted_out', 'sensitive', 'skipped', 'low_value'))
         ORDER BY r.rank
         LIMIT ?3",
    )?;
    // `mp3, .FLAC` -> `mp3,flac`
    let ext = ext
        .map(|list| {
            list.split([',', ' '])
                .map(|e| e.trim().trim_start_matches('.').to_lowercase())
                .filter(|e| !e.is_empty())
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|list| !list.is_empty());
    let min_bytes = min_bytes.map(|b| i64::try_from(b).unwrap_or(i64::MAX));
    let hits = stmt
        .query_map(params![fts_query, ext, limit as i64, min_bytes], |row| {
            Ok(Hit {
                url: row.get(0)?,
                name: row.get(1)?,
                is_dir: row.get(2)?,
                size: row.get::<_, Option<i64>>(3)?.map(|s| s as u64),
                mtime: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(hits)
}

/// Turns free text into an FTS5 query: every word must match, as a prefix.
fn fts_query(input: &str) -> Option<String> {
    let terms: Vec<String> = input
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| format!("\"{w}\"*"))
        .collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

pub struct StatusCount {
    pub status: String,
    pub hosts: u64,
    pub files: u64,
    pub bytes: u64,
}

/// Work still to do, per source.
/// A crawled (or judged) site, for `opendir sites`.
pub struct Site {
    pub host: String,
    pub status: String,
    pub files: u64,
    pub bytes: u64,
    pub dirs: u64,
    pub server: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteSort {
    Size,
    Files,
    Recent,
    Name,
}

pub fn sites(
    conn: &Connection,
    status: Option<&str>,
    sort: SiteSort,
    limit: usize,
) -> Result<Vec<Site>> {
    let order = match sort {
        SiteSort::Size => "bytes DESC, host",
        SiteSort::Files => "files DESC, host",
        SiteSort::Recent => "crawled_at DESC, host",
        SiteSort::Name => "host",
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT host, status, files, bytes, dirs, server, reason FROM hosts
         WHERE (?1 IS NULL OR status = ?1) ORDER BY {order} LIMIT ?2"
    ))?;
    let rows = stmt
        .query_map(params![status, limit as i64], |row| {
            Ok(Site {
                host: row.get(0)?,
                status: row.get(1)?,
                files: row.get::<_, i64>(2)? as u64,
                bytes: row.get::<_, i64>(3)? as u64,
                dirs: row.get::<_, i64>(4)? as u64,
                server: row.get(5)?,
                reason: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

pub struct CandidateCount {
    pub source: String,
    pub urls: u64,
    pub hosts: u64,
}

pub fn candidate_stats(conn: &Connection) -> Result<Vec<CandidateCount>> {
    let mut stmt = conn.prepare(
        "SELECT source, count(*), count(DISTINCT host)
         FROM candidates GROUP BY source ORDER BY source",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(CandidateCount {
                source: row.get(0)?,
                urls: row.get::<_, i64>(1)? as u64,
                hosts: row.get::<_, i64>(2)? as u64,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

/// `(host, reason)` for hosts dropped as sensitive exposures.
pub fn sensitive_reasons(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT host, coalesce(reason, '(not recorded)') FROM hosts
         WHERE status = 'sensitive' ORDER BY host",
    )?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

pub fn stats(conn: &Connection) -> Result<Vec<StatusCount>> {
    let mut stmt = conn.prepare(
        "SELECT status, count(*), CAST(total(files) AS INTEGER), CAST(total(bytes) AS INTEGER)
         FROM hosts
         GROUP BY status ORDER BY count(*) DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(StatusCount {
                status: row.get(0)?,
                hosts: row.get::<_, i64>(1)? as u64,
                files: row.get::<_, i64>(2)? as u64,
                bytes: row.get::<_, i64>(3)? as u64,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "opendirtest-store-{name}-{}.db",
            std::process::id()
        ));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        path
    }

    #[test]
    fn refuses_databases_with_the_old_layout() {
        let path = temp_path("old-layout");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE entries (url TEXT PRIMARY KEY, name TEXT);")
            .unwrap();
        let error = open(&path).unwrap_err().to_string();
        assert!(error.contains("older version"), "{error}");
    }

    fn entry(url: &str, is_dir: bool, size: Option<u64>) -> Entry {
        let url = Url::parse(url).unwrap();
        let name = url
            .path_segments()
            .and_then(|mut s| s.rfind(|p| !p.is_empty()))
            .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
            .unwrap();
        Entry {
            url,
            name,
            is_dir,
            size,
            mtime: Some("2026-09-28 10:15".into()),
        }
    }

    fn files(conn: &Connection) -> Vec<String> {
        let mut stmt = conn.prepare("SELECT url FROM files ORDER BY url").unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn hits(conn: &Connection, query: &str) -> usize {
        let opts = SearchOptions {
            limit: 100,
            ext: None,
            min_bytes: None,
            unfiltered: true,
            takedown: vec![],
            optout: vec![],
        };
        search(conn, query, opts).unwrap().len()
    }

    #[test]
    fn listings_are_stored_compactly_and_urls_come_back_exactly() {
        let conn = open(&temp_path("compact")).unwrap();
        let urls = [
            "https://h.example/pub/My%20Notes%20%26%20Ideas.txt",
            "https://h.example/pub/linux-6.16.tar.xz",
            "https://h.example/pub/%D0%9A%D0%BD%D0%B8%D0%B3%D0%B8/",
        ];
        let entries = vec![
            entry(urls[0], false, Some(512)),
            entry(urls[1], false, Some(149_213_136)),
            entry(urls[2], true, None),
        ];
        let msg = Msg::Entries {
            host: "h.example".into(),
            entries,
        };
        apply(&conn, &msg).unwrap();

        let mut expected: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
        expected.sort();
        assert_eq!(files(&conn), expected);
        // Names are stored decoded; the link text only when it differs.
        let hrefs: i64 = conn
            .query_row("SELECT count(href) FROM entries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hrefs, 2);
        assert_eq!(hits(&conn, "notes ideas"), 1);
        assert_eq!(hits(&conn, "Книги"), 1);
        assert_eq!(hits(&conn, "pub linux"), 1, "folder path is searchable too");

        // Reading the listing again replaces it: the removed file is gone.
        let msg = Msg::Entries {
            host: "h.example".into(),
            entries: vec![entry(urls[1], false, Some(149_213_137))],
        };
        apply(&conn, &msg).unwrap();
        assert_eq!(files(&conn), vec![urls[1].to_string()]);
        assert_eq!(hits(&conn, "notes"), 0);

        // Dropping the host removes its listings and search entries.
        let done = Msg::HostDone {
            host: "h.example".into(),
            status: HostStatus::Sensitive,
            server: None,
            dirs: 1,
            reason: None,
            purge: true,
            trusted: false,
            judge: None,
        };
        apply(&conn, &done).unwrap();
        assert!(files(&conn).is_empty());
        assert_eq!(hits(&conn, "linux"), 0);
    }

    #[test]
    fn about_130_bytes_per_file() {
        let path = temp_path("size");
        let conn = open(&path).unwrap();
        for d in 0..50 {
            let entries = (0..200)
                .map(|f| {
                    let url = format!(
                        "https://mirror.example.org/pub/project-{d}/release-{f}.0.1-x86_64.tar.gz"
                    );
                    entry(&url, false, Some(1_000_000 + f))
                })
                .collect();
            let msg = Msg::Entries {
                host: "mirror.example.org".into(),
                entries,
            };
            apply(&conn, &msg).unwrap();
        }
        conn.execute_batch("VACUUM").unwrap();
        let pages: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        let page_size: i64 = conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .unwrap();
        let per_file = pages * page_size / 10_000;
        eprintln!("{per_file} bytes per file");
        assert!(per_file < 180, "{per_file} bytes per file");
    }

    /// Stores `files` (name, size) under `https://{host}/{folder}/` and marks the site done.
    fn add_site(
        conn: &Connection,
        host: &str,
        folder: &str,
        files: &[(&str, Option<u64>)],
        trusted: bool,
        judge: Option<Thresholds>,
    ) {
        let entries = files
            .iter()
            .map(|(name, size)| entry(&format!("https://{host}/{folder}/{name}"), false, *size))
            .collect();
        let msg = Msg::Entries {
            host: host.into(),
            entries,
        };
        apply(conn, &msg).unwrap();
        let done = Msg::HostDone {
            host: host.into(),
            status: HostStatus::Done,
            server: None,
            dirs: 1,
            reason: None,
            purge: false,
            trusted,
            judge,
        };
        apply(conn, &done).unwrap();
    }

    fn status(conn: &Connection, host: &str) -> String {
        conn.query_row("SELECT status FROM hosts WHERE host = ?1", [host], |r| {
            r.get(0)
        })
        .unwrap()
    }

    fn photos(n: u64) -> Vec<(String, Option<u64>)> {
        (0..n)
            .map(|i| (format!("photo-{i}.jpg"), Some(40_000)))
            .collect()
    }

    #[test]
    fn clean_applies_todays_rules_to_stored_data() {
        let mut conn = open(&temp_path("clean")).unwrap();
        let junk: Vec<(String, Option<u64>)> = photos(30);
        let junk: Vec<(&str, Option<u64>)> = junk.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        let big = Some(4_000_000_000);
        add_site(&conn, "junk.example", "pics", &junk, false, None);
        add_site(
            &conn,
            "good.example",
            "iso",
            &[("a.iso", big), ("b.iso", big), ("c.iso", big)],
            false,
            None,
        );
        add_site(
            &conn,
            "mine.example",
            "x",
            &[("notes.txt", Some(5))],
            true,
            None,
        );
        add_site(
            &conn,
            "leak.example",
            "www",
            &[(".env", Some(90)), ("index.php", Some(9))],
            false,
            None,
        );
        add_site(
            &conn,
            "weak-mine.example",
            "d",
            &[("backup-2026-01-01.zip", big), ("a.iso", big)],
            true,
            None,
        );
        add_site(
            &conn,
            "weak-other.example",
            "d",
            &[("db_dump.sql.gz", big), ("a.iso", big)],
            false,
            None,
        );
        // A folder of links to other accounts' config files, listed by a compromised server.
        add_site(
            &conn,
            "hacked.example",
            "sym404",
            &[("readme.txt", Some(3))],
            false,
            None,
        );

        let rules = CleanRules {
            optout: &[],
            skip: &filters::SkipList::default(),
            quality: Thresholds::default(),
        };
        let report = clean(&mut conn, &rules).unwrap();

        assert_eq!(status(&conn, "junk.example"), "low_value");
        assert_eq!(status(&conn, "good.example"), "done");
        assert_eq!(
            status(&conn, "mine.example"),
            "done",
            "yours is never judged"
        );
        assert_eq!(status(&conn, "leak.example"), "sensitive");
        assert_eq!(status(&conn, "weak-other.example"), "sensitive");
        assert_eq!(status(&conn, "hacked.example"), "sensitive");
        // Your own site only loses the weak entry.
        assert_eq!(status(&conn, "weak-mine.example"), "done");
        assert_eq!(report.omitted_entries, 1);
        let mine: Vec<String> = files(&conn)
            .into_iter()
            .filter(|u| u.contains("weak-mine"))
            .collect();
        assert_eq!(mine, vec!["https://weak-mine.example/d/a.iso"]);
        assert_eq!(report.low_value.len(), 1);
        assert_eq!(report.sensitive.len(), 3);
        assert!(
            report
                .sensitive
                .iter()
                .any(|(h, why)| h == "hacked.example" && why.contains("sym404"))
        );
        // Dropped sites keep only their status.
        assert!(
            !files(&conn)
                .iter()
                .any(|u| u.contains("junk.example") || u.contains("leak.example"))
        );
        assert_eq!(hits(&conn, "photo"), 0);
        assert_eq!(hits(&conn, "index"), 0);

        // A second pass finds nothing more to do.
        assert!(clean(&mut conn, &rules).unwrap().is_empty());
    }

    #[test]
    fn the_file_shrinks_after_a_big_cleanup() {
        let path = temp_path("compact");
        let mut conn = open(&path).unwrap();
        for host in 0..40 {
            let photos = photos(300);
            let photos: Vec<(&str, Option<u64>)> =
                photos.iter().map(|(n, s)| (n.as_str(), *s)).collect();
            add_site(
                &conn,
                &format!("junk{host}.example"),
                "pics",
                &photos,
                false,
                None,
            );
        }
        let size = |p: &Path| std::fs::metadata(p).unwrap().len();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let before = size(&path);
        assert!(
            !compact_if_wasteful(&conn, 10).unwrap(),
            "nothing to reclaim yet"
        );

        let rules = CleanRules {
            optout: &[],
            skip: &filters::SkipList::default(),
            quality: Thresholds::default(),
        };
        assert_eq!(clean(&mut conn, &rules).unwrap().low_value.len(), 40);
        assert!(compact_if_wasteful(&conn, 10).unwrap());
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let after = size(&path);
        assert!(after * 3 < before, "{before} -> {after} bytes");
        // Still usable afterwards.
        assert_eq!(status(&conn, "junk0.example"), "low_value");
        add_site(
            &conn,
            "new.example",
            "d",
            &[("a.iso", Some(50_000_000))],
            true,
            None,
        );
        assert_eq!(hits(&conn, "iso"), 1);
    }

    #[test]
    fn the_writer_judges_a_site_when_it_finishes() {
        let conn = open(&temp_path("judge")).unwrap();
        let t = Some(Thresholds::default());
        let junk = photos(5);
        let junk: Vec<(&str, Option<u64>)> = junk.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        add_site(&conn, "small.example", "d", &junk, false, t);
        add_site(&conn, "seed.example", "d", &junk, true, None);
        assert_eq!(status(&conn, "small.example"), "low_value");
        assert_eq!(status(&conn, "seed.example"), "done");
        assert!(files(&conn).iter().all(|u| !u.contains("small.example")));
        // An unfinished site with few files so far is not judged yet.
        let msg = Msg::Entries {
            host: "early.example".into(),
            entries: vec![entry("https://early.example/d/a.jpg", false, Some(9_000))],
        };
        apply(&conn, &msg).unwrap();
        let paused = Msg::HostDone {
            host: "early.example".into(),
            status: HostStatus::Paused,
            server: None,
            dirs: 3,
            reason: None,
            purge: false,
            trusted: false,
            judge: t,
        };
        apply(&conn, &paused).unwrap();
        assert_eq!(status(&conn, "early.example"), "paused");
        // The verdict counts everything stored across runs, not just this run.
        let big = Some(50_000_000);
        add_site(
            &conn,
            "grows.example",
            "d",
            &[("a.iso", big), ("b.iso", big)],
            false,
            None,
        );
        add_site(&conn, "grows.example", "e", &[("c.iso", big)], false, t);
        assert_eq!(status(&conn, "grows.example"), "done");
    }

    #[test]
    fn seeds_are_trusted_and_forget_earlier_verdicts() {
        let conn = open(&temp_path("seeds")).unwrap();
        let url = |u: &str| Url::parse(u).unwrap();
        for (host, status) in [
            ("a.example", "not_listing"),
            ("b.example", "low_value"),
            ("c.example", "robots_disallowed"),
            ("d.example", "done"),
        ] {
            conn.execute(
                "INSERT INTO hosts (host, status, crawled_at) VALUES (?1, ?2, 0)",
                [host, status],
            )
            .unwrap();
        }
        let seeds = [
            url("https://a.example/pub/"),
            url("https://b.example/pub/"),
            url("https://c.example/pub/"),
            url("https://d.example/pub/"),
            url("https://new.example/pub/"),
        ];
        let retried = add_seeds(&conn, &seeds).unwrap();
        assert_eq!(retried, 2, "not_listing and low_value are tried again");
        let waiting: Vec<String> = pending_hosts(&conn, 10, &HashSet::new())
            .unwrap()
            .into_iter()
            .map(|h| h.host)
            .collect();
        assert_eq!(waiting, vec!["a.example", "b.example", "new.example"]);
        // Robots.txt verdicts are respected, and finished sites stay finished, but trusted.
        assert_eq!(status(&conn, "c.example"), "robots_disallowed");
        let trusted: i64 = conn
            .query_row(
                "SELECT trusted FROM hosts WHERE host = 'd.example'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(trusted, 1);
    }

    #[test]
    fn upgrades_a_database_without_the_trusted_column() {
        let path = temp_path("no-trusted");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE hosts (host TEXT PRIMARY KEY, status TEXT NOT NULL, server TEXT,
                 dirs INTEGER NOT NULL DEFAULT 0, files INTEGER NOT NULL DEFAULT 0,
                 bytes INTEGER NOT NULL DEFAULT 0, crawled_at INTEGER NOT NULL, reason TEXT);
                 INSERT INTO hosts VALUES ('old.example', 'done', NULL, 3, 10, 99, 0, NULL);",
            )
            .unwrap();
        let conn = open(&path).unwrap();
        let trusted: i64 = conn
            .query_row(
                "SELECT trusted FROM hosts WHERE host = 'old.example'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(trusted, 0);
        assert_eq!(status(&conn, "old.example"), "done");
    }

    #[test]
    fn pending_hosts_skip_finished_and_busy_hosts() {
        let conn = open(&temp_path("candidates")).unwrap();
        let urls = [
            "https://a.example/pub/",
            "https://a.example/pub/linux/",
            "https://a.example/data/",
            "https://b.example/files/",
            "https://done.example/pub/",
        ]
        .iter()
        .map(|u| Url::parse(u).unwrap())
        .collect();
        apply(
            &conn,
            &Msg::Candidates {
                urls,
                source: "test".into(),
            },
        )
        .unwrap();
        let done = Msg::HostDone {
            host: "done.example".into(),
            status: HostStatus::Done,
            server: None,
            dirs: 1,
            reason: None,
            purge: false,
            trusted: false,
            judge: None,
        };
        apply(&conn, &done).unwrap();

        let none = HashSet::new();
        let pending = pending_hosts(&conn, 10, &none).unwrap();
        let urls: Vec<String> = pending
            .iter()
            .flat_map(|h| h.urls.iter().map(Url::to_string))
            .collect();
        assert_eq!(
            urls,
            vec![
                "https://a.example/pub/",
                "https://a.example/data/",
                "https://a.example/pub/linux/",
                "https://b.example/files/"
            ]
        );
        // The finished host's candidates were removed when it finished.
        let left: i64 = conn
            .query_row(
                "SELECT count(*) FROM candidates WHERE host = 'done.example'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);

        let one = pending_hosts(&conn, 1, &none).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].host, "a.example");
        let busy: HashSet<String> = ["a.example".to_string()].into();
        let others = pending_hosts(&conn, 10, &busy).unwrap();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].host, "b.example");

        // Candidates for a finished host are ignored.
        let late = [Url::parse("https://done.example/new/").unwrap()];
        add_candidates(&conn, &late, "link").unwrap();
        let hosts = pending_hosts(&conn, 10, &none).unwrap();
        assert!(hosts.iter().all(|h| h.host != "done.example"));
    }

    #[test]
    fn paused_hosts_resume_from_their_frontier() {
        let conn = open(&temp_path("paused")).unwrap();
        let url = |u: &str| Url::parse(u).unwrap();
        add_candidates(&conn, &[url("https://m.example/pub/")], "seed").unwrap();
        let paused = Msg::Paused {
            host: "m.example".into(),
            finished: vec![url("https://m.example/pub/")],
            frontier: vec![
                url("https://m.example/pub/b/"),
                url("https://m.example/pub/c/"),
            ],
        };
        apply(&conn, &paused).unwrap();
        let status = Msg::HostDone {
            host: "m.example".into(),
            status: HostStatus::Paused,
            server: None,
            dirs: 3,
            reason: None,
            purge: false,
            trusted: false,
            judge: None,
        };
        apply(&conn, &status).unwrap();

        let pending = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        let urls: Vec<&str> = pending[0].urls.iter().map(Url::as_str).collect();
        assert_eq!(
            urls,
            vec!["https://m.example/pub/b/", "https://m.example/pub/c/"]
        );

        // Re-adding the seed (as `auto` does every night) must not restart the walk.
        add_candidates(&conn, &[url("https://m.example/pub/")], "seed").unwrap();
        let pending = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(pending[0].urls.len(), 2);

        // The next run finishes it; directory counts add up across runs.
        let done = Msg::HostDone {
            host: "m.example".into(),
            status: HostStatus::Done,
            server: None,
            dirs: 2,
            reason: None,
            purge: false,
            trusted: false,
            judge: None,
        };
        apply(&conn, &done).unwrap();
        let dirs: i64 = conn
            .query_row("SELECT dirs FROM hosts WHERE host = 'm.example'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(dirs, 5);

        assert!(forget(&conn, "m.example").unwrap());
        assert!(
            pending_hosts(&conn, 10, &HashSet::new())
                .unwrap()
                .is_empty()
        );
        assert!(!forget(&conn, "m.example").unwrap());
    }

    // -- Regression tests for the third independent review ----------------

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// Stores one folder's listing. Names ending in `/` are sub-folders.
    fn put(conn: &Connection, host: &str, folder: &str, items: &[(&str, Option<u64>)]) {
        let entries = items
            .iter()
            .map(|(name, size)| {
                entry(
                    &format!("https://{host}/{folder}/{name}"),
                    name.ends_with('/'),
                    *size,
                )
            })
            .collect();
        let msg = Msg::Entries {
            host: host.into(),
            entries,
        };
        apply(conn, &msg).unwrap();
    }

    fn host_done(
        conn: &Connection,
        host: &str,
        status: HostStatus,
        trusted: bool,
        judge: Option<Thresholds>,
    ) {
        let msg = Msg::HostDone {
            host: host.into(),
            status,
            server: None,
            dirs: 1,
            reason: None,
            purge: false,
            trusted,
            judge,
        };
        apply(conn, &msg).unwrap();
    }

    fn has_row(conn: &Connection, host: &str) -> bool {
        conn.query_row("SELECT count(*) FROM hosts WHERE host = ?1", [host], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
            > 0
    }

    fn default_rules() -> CleanRules<'static> {
        static SKIP: std::sync::LazyLock<filters::SkipList> =
            std::sync::LazyLock::new(filters::SkipList::default);
        CleanRules {
            optout: &[],
            skip: &SKIP,
            quality: Thresholds::default(),
        }
    }

    /// The top folder of a big archive: many small text files and a sub-folder.
    fn readmes(n: usize, with_subfolder: bool) -> Vec<(String, Option<u64>)> {
        let mut items: Vec<(String, Option<u64>)> = (0..n)
            .map(|i| (format!("README-{i}.txt"), Some(900)))
            .collect();
        if with_subfolder {
            items.push(("iso/".into(), None));
        }
        items
    }

    fn borrowed(items: &[(String, Option<u64>)]) -> Vec<(&str, Option<u64>)> {
        items.iter().map(|(n, s)| (n.as_str(), *s)).collect()
    }

    #[test]
    fn a_site_still_being_crawled_is_judged_on_folders_without_sub_folders() {
        let conn = open(&temp_path("leaf")).unwrap();
        let t = Some(Thresholds::default());

        // 120 small files at the top of an archive whose downloads are further
        // down: says nothing yet.
        let top = readmes(120, true);
        put(&conn, "archive.example", "pub", &borrowed(&top));
        host_done(&conn, "archive.example", HostStatus::Paused, false, t);
        assert_eq!(status(&conn, "archive.example"), "paused");

        // The same files with nothing below them are all the site has.
        let flat = readmes(120, false);
        put(&conn, "flat.example", "pub", &borrowed(&flat));
        host_done(&conn, "flat.example", HostStatus::Paused, false, t);
        assert_eq!(status(&conn, "flat.example"), "low_value");

        // Once the archive is finished, every file counts, and it holds disk images.
        let big = Some(4_000_000_000);
        put(
            &conn,
            "archive.example",
            "pub/iso",
            &[("a.iso", big), ("b.iso", big), ("c.iso", big)],
        );
        host_done(&conn, "archive.example", HostStatus::Done, false, t);
        assert_eq!(status(&conn, "archive.example"), "done");

        // A finished site is judged on everything, including its top folder.
        put(&conn, "shallow.example", "pub", &borrowed(&top));
        put(
            &conn,
            "shallow.example",
            "pub/iso",
            &[("t.jpg", Some(9_000))],
        );
        host_done(&conn, "shallow.example", HostStatus::Done, false, t);
        assert_eq!(status(&conn, "shallow.example"), "low_value");
    }

    #[test]
    fn clean_keeps_a_paused_archive_and_its_saved_frontier() {
        let mut conn = open(&temp_path("clean-paused")).unwrap();
        let top = readmes(120, true);
        put(&conn, "big.example", "pub", &borrowed(&top));
        let paused = Msg::Paused {
            host: "big.example".into(),
            finished: vec![],
            frontier: vec![url("https://big.example/pub/iso/")],
        };
        apply(&conn, &paused).unwrap();
        host_done(&conn, "big.example", HostStatus::Paused, false, None);

        let report = clean(&mut conn, &default_rules()).unwrap();

        assert!(report.low_value.is_empty(), "{report:?}");
        assert_eq!(status(&conn, "big.example"), "paused");
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].urls, vec![url("https://big.example/pub/iso/")]);
    }

    #[test]
    fn a_seed_that_was_already_waiting_as_a_discovery_find_is_still_yours() {
        let conn = open(&temp_path("seed-promote")).unwrap();
        add_candidates(
            &conn,
            &[url("https://ftp.example.edu/")],
            "commoncrawl:CC-MAIN-2026-30",
        )
        .unwrap();
        add_candidates(&conn, &[url("https://mirror.example.org/pub/")], "link").unwrap();

        add_seeds(
            &conn,
            &[
                url("https://ftp.example.edu/"),
                url("https://mirror.example.org/pub/"),
            ],
        )
        .unwrap();

        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(waiting.len(), 2);
        assert!(waiting.iter().all(|h| h.trusted), "{waiting:?}");

        // A folder saved to continue from keeps that role, and the site is still trusted.
        conn.execute(
            "INSERT INTO hosts (host, status, crawled_at) VALUES ('paused.example', 'paused', 0)",
            [],
        )
        .unwrap();
        add_candidates(&conn, &[url("https://paused.example/x/")], RESUME_SOURCE).unwrap();
        add_seeds(&conn, &[url("https://paused.example/x/")]).unwrap();
        let source: String = conn
            .query_row(
                "SELECT source FROM candidates WHERE url = 'https://paused.example/x/'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source, RESUME_SOURCE);
        let paused = pending_hosts(&conn, 10, &HashSet::new())
            .unwrap()
            .into_iter()
            .find(|h| h.host == "paused.example")
            .unwrap();
        assert!(paused.trusted);
    }

    #[test]
    fn a_new_address_recorded_as_a_seed_takes_over_a_waiting_find() {
        // A site you added moved: its new address may already be waiting as a link.
        let conn = open(&temp_path("moved")).unwrap();
        let new = url("https://new.example/files/");
        add_candidates(&conn, std::slice::from_ref(&new), "link").unwrap();
        let msg = Msg::Candidates {
            urls: vec![new.clone()],
            source: SEED_SOURCE.into(),
        };
        apply(&conn, &msg).unwrap();
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(waiting.len(), 1);
        assert!(waiting[0].trusted);
    }

    #[test]
    fn a_seed_that_gave_up_keeps_its_trust_when_it_is_tried_again() {
        let mut conn = open(&temp_path("partial-seed")).unwrap();
        let big = Some(4_000_000_000);
        // Stored under an older rule set, before weak names were left out.
        put(
            &conn,
            "flaky.example",
            "d",
            &[
                ("backup-2026-01-01.zip", big),
                ("a.iso", big),
                ("b.iso", big),
                ("c.iso", big),
            ],
        );
        host_done(&conn, "flaky.example", HostStatus::Partial, true, None);

        // Tonight the seed list names the site again: its row goes, its files stay.
        let retried = add_seeds(&conn, &[url("https://flaky.example/d/")]).unwrap();
        assert_eq!(retried, 1);
        assert!(!has_row(&conn, "flaky.example"));

        let report = clean(&mut conn, &default_rules()).unwrap();

        assert!(report.sensitive.is_empty(), "{report:?}");
        assert_eq!(report.omitted_entries, 1);
        assert_eq!(files(&conn).len(), 3);
    }

    #[test]
    fn a_weak_named_folder_on_your_own_site_goes_with_everything_below_it() {
        let mut conn = open(&temp_path("omit-subtree")).unwrap();
        let big = Some(4_000_000_000);
        put(
            &conn,
            "mine.example",
            "d",
            &[
                ("a.iso", big),
                ("backup-2020/", None),
                ("backups-list/", None),
            ],
        );
        put(
            &conn,
            "mine.example",
            "d/backup-2020",
            &[("secret-notes.txt", Some(10)), ("deeper/", None)],
        );
        put(
            &conn,
            "mine.example",
            "d/backup-2020/deeper",
            &[("more-secret.txt", Some(10))],
        );
        put(
            &conn,
            "mine.example",
            "d/backups-list",
            &[("index-notes.txt", Some(10))],
        );
        host_done(&conn, "mine.example", HostStatus::Done, true, None);
        assert_eq!(hits(&conn, "secret"), 2);

        let report = clean(&mut conn, &default_rules()).unwrap();

        assert_eq!(report.omitted_entries, 1);
        assert_eq!(
            hits(&conn, "secret"),
            0,
            "the folder's contents stay searchable"
        );
        assert_eq!(
            hits(&conn, "backup"),
            2,
            "only the unrelated folder and the file listed in it are left"
        );
        let below: i64 = conn
            .query_row(
                "SELECT count(*) FROM dirs WHERE url LIKE '%/backup-2020/%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(below, 0);
        assert_eq!(hits(&conn, "index"), 1);
        assert_eq!(hits(&conn, "iso"), 1);
    }

    #[test]
    fn a_trailing_dot_does_not_make_a_second_site() {
        let conn = open(&temp_path("trailing-dot")).unwrap();
        add_candidates(
            &conn,
            &[
                url("https://Example.ORG./pub/"),
                url("https://example.org/pub/x/"),
            ],
            "link",
        )
        .unwrap();
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(waiting.len(), 1, "{waiting:?}");
        assert_eq!(waiting[0].host, "example.org");
        assert_eq!(waiting[0].urls.len(), 2);
        // A seed written with the dot trusts the same site.
        add_seeds(&conn, &[url("https://example.org./pub/")]).unwrap();
        assert!(pending_hosts(&conn, 10, &HashSet::new()).unwrap()[0].trusted);
    }

    #[test]
    fn a_huge_minimum_size_matches_nothing_instead_of_everything() {
        let conn = open(&temp_path("min-bytes")).unwrap();
        add_site(
            &conn,
            "s.example",
            "d",
            &[("a.iso", Some(5_000))],
            true,
            None,
        );
        let opts = |min| SearchOptions {
            limit: 10,
            ext: None,
            min_bytes: Some(min),
            unfiltered: true,
            takedown: vec![],
            optout: vec![],
        };
        assert_eq!(search(&conn, "iso", opts(u64::MAX)).unwrap().len(), 0);
        assert_eq!(search(&conn, "iso", opts(1)).unwrap().len(), 1);
    }

    #[test]
    fn pending_sites_come_in_priority_order() {
        let conn = open(&temp_path("order")).unwrap();
        let add = |u: &str, host: &str, source: &str, at: i64| {
            conn.execute(
                "INSERT INTO candidates (url, host, source, found_at) VALUES (?1, ?2, ?3, ?4)",
                params![u, host, source, at],
            )
            .unwrap();
        };
        add(
            "https://cc1.example/pub/",
            "cc1.example",
            "commoncrawl:X",
            10,
        );
        add("https://link1.example/pub/", "link1.example", "link", 20);
        add("https://seed1.example/pub/", "seed1.example", "seed", 30);
        add("https://res1.example/pub/", "res1.example", "resume", 40);
        add("https://link2.example/pub/", "link2.example", "link", 5);
        // Both a link and a seed: it counts as a seed.
        add("https://both.example/a/", "both.example", "link", 1);
        add("https://both.example/", "both.example", "seed", 50);
        conn.execute(
            "INSERT INTO hosts (host, status, crawled_at, trusted) VALUES ('paused.example', 'paused', 0, 1)",
            [],
        )
        .unwrap();
        add("https://paused.example/x/", "paused.example", "resume", 60);

        let all = pending_hosts(&conn, 100, &HashSet::new()).unwrap();
        let order: Vec<&str> = all.iter().map(|h| h.host.as_str()).collect();
        assert_eq!(
            order,
            [
                "both.example",
                "seed1.example",
                "res1.example",
                "paused.example",
                "link2.example",
                "link1.example",
                "cc1.example"
            ]
        );
        let skip: HashSet<String> = ["both.example".into(), "seed1.example".into()].into();
        let three = pending_hosts(&conn, 3, &skip).unwrap();
        let order: Vec<&str> = three.iter().map(|h| h.host.as_str()).collect();
        assert_eq!(order, ["res1.example", "paused.example", "link2.example"]);
    }

    /// Whatever order discovery, seeding, crawling and cleaning happen in, a site
    /// you added is never dropped for holding too little.
    #[test]
    fn a_site_you_added_is_never_dropped_for_holding_little() {
        for round in 0..300u64 {
            let mut x = round.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut rnd = move |n: u64| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x % n
            };
            let mut conn = open(Path::new(":memory:")).unwrap();
            let hosts = ["a.example", "b.example", "c.example", "d.example"];
            let dirs = ["/", "/pub/", "/pub/x/"];
            let mut seeded: Vec<&str> = Vec::new();
            let mut log: Vec<String> = Vec::new();
            for _ in 0..40 {
                let host = hosts[rnd(4) as usize];
                let dir = dirs[rnd(3) as usize];
                let target = url(&format!("https://{host}{dir}"));
                match rnd(6) {
                    0 => {
                        let source = ["link", "commoncrawl:X"][rnd(2) as usize];
                        add_candidates(&conn, std::slice::from_ref(&target), source).unwrap();
                        log.push(format!("candidate {target} ({source})"));
                    }
                    1 => {
                        add_seeds(&conn, std::slice::from_ref(&target)).unwrap();
                        if !seeded.contains(&host) {
                            seeded.push(host);
                        }
                        log.push(format!("seed {target}"));
                    }
                    2 | 3 => {
                        // One crawl round, like `crawl --candidates`.
                        let pending = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
                        if let Some(site) = pending.into_iter().next() {
                            let files: Vec<(String, Option<u64>)> = (0..rnd(6))
                                .map(|i| (format!("f{i}.jpg"), Some(1000)))
                                .collect();
                            put(&conn, &site.host, "pub", &borrowed(&files));
                            let end = [
                                HostStatus::Done,
                                HostStatus::Paused,
                                HostStatus::Partial,
                                HostStatus::NotListing,
                            ][rnd(4) as usize];
                            if end == HostStatus::Paused {
                                let frontier =
                                    url(&format!("https://{}{}", site.host, dirs[rnd(3) as usize]));
                                let msg = Msg::Paused {
                                    host: site.host.clone(),
                                    finished: site.urls.clone(),
                                    frontier: vec![frontier],
                                };
                                apply(&conn, &msg).unwrap();
                            }
                            let judge = (!site.trusted).then(Thresholds::default);
                            host_done(&conn, &site.host, end, site.trusted, judge);
                            log.push(format!(
                                "crawl {} (trusted {}) -> {end:?}",
                                site.host, site.trusted
                            ));
                        }
                    }
                    4 => {
                        clean(&mut conn, &default_rules()).unwrap();
                        log.push("clean".into());
                    }
                    _ => {
                        // `crawl URL` by hand: trusted, never judged.
                        put(&conn, host, "pub", &[("a.jpg", Some(10))]);
                        trust_hosts(&conn, std::slice::from_ref(&target)).unwrap();
                        host_done(&conn, host, HostStatus::Done, true, None);
                        if !seeded.contains(&host) {
                            seeded.push(host);
                        }
                        log.push(format!("explicit crawl {host}"));
                    }
                }
                for site in &seeded {
                    let now = conn
                        .query_row("SELECT status FROM hosts WHERE host = ?1", [site], |r| {
                            r.get::<_, String>(0)
                        })
                        .unwrap_or_default();
                    assert!(
                        now != "low_value" && now != "sensitive",
                        "{site} became {now} in round {round}:\n  {}",
                        log.join("\n  ")
                    );
                }
            }
        }
    }

    #[test]
    fn fts_query_quotes_words() {
        assert_eq!(
            fts_query("ubuntu 24.04 iso").unwrap(),
            r#""ubuntu"* "24"* "04"* "iso"*"#
        );
        assert_eq!(
            fts_query("\"OR\" NEAR(x"),
            Some(r#""OR"* "NEAR"* "x"*"#.into())
        );
        assert!(fts_query(" -- ").is_none());
    }
}
