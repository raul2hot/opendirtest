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
use crate::quality::{self, Counts, Progress, Thresholds, Waiting};
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
    trusted    INTEGER NOT NULL DEFAULT 0,
    -- Runs in a row of a paused site that ended in errors (see `MAX_FAILED_RUNS`).
    fails      INTEGER NOT NULL DEFAULT 0
);

-- One row per folder listing that was read.
CREATE TABLE IF NOT EXISTS dirs (
    id      INTEGER PRIMARY KEY,
    host    TEXT NOT NULL,
    url     TEXT NOT NULL UNIQUE,
    seen_at INTEGER NOT NULL,
    -- 1 if the crawl visits nothing below this folder (it lists no sub-folder to
    -- crawl, now or later). Only such folders count when a site that is still
    -- being crawled is judged: see `host_counts`.
    leaf    INTEGER NOT NULL DEFAULT 0
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
    /// The status stored under this name in `hosts.status`.
    fn parse(name: &str) -> Option<HostStatus> {
        Some(match name {
            "done" => HostStatus::Done,
            "paused" => HostStatus::Paused,
            "skipped" => HostStatus::Skipped,
            "low_value" => HostStatus::LowValue,
            "partial" => HostStatus::Partial,
            "robots_disallowed" => HostStatus::RobotsDisallowed,
            "not_listing" => HostStatus::NotListing,
            "sensitive" => HostStatus::Sensitive,
            "opted_out" => HostStatus::OptedOut,
            "unreachable" => HostStatus::Unreachable,
            _ => return None,
        })
    }

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
        /// The crawl visits nothing below this folder: it lists no sub-folder worth
        /// walking (skipped, too deep, too long or looping ones do not count).
        /// Folders are stored either way; only leaf folders count as evidence for
        /// a site that is still being crawled.
        leaf: bool,
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
        /// The run ended because of errors or refusals, not because the crawl is
        /// over. A site that continues stays paused and counts a strike; after
        /// `MAX_FAILED_RUNS` such runs in a row it is ended.
        failed: bool,
    },
    /// Directory URLs worth crawling later. Already-known URLs are ignored.
    Candidates { urls: Vec<Url>, source: String },
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

/// A paused site whose runs end in errors this many times in a row is given up on.
pub const MAX_FAILED_RUNS: i64 = 5;

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
    let has_fails: bool = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('hosts') WHERE name = 'fails'",
        [],
        |row| row.get(0),
    )?;
    if !has_fails {
        conn.execute_batch("ALTER TABLE hosts ADD COLUMN fails INTEGER NOT NULL DEFAULT 0")?;
    }
    // Databases from before the leaf flag: a folder listing no sub-folder is a leaf.
    let has_leaf: bool = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('dirs') WHERE name = 'leaf'",
        [],
        |row| row.get(0),
    )?;
    if !has_leaf {
        // In one transaction: were the back-fill to fail after the column was added,
        // the column would exist and the folders would never be flagged.
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE dirs ADD COLUMN leaf INTEGER NOT NULL DEFAULT 0;
             UPDATE dirs SET leaf = 1 WHERE NOT EXISTS (
                 SELECT 1 FROM entries s WHERE s.dir_id = dirs.id AND s.is_dir = 1);
             COMMIT;",
        )?;
    }
    Ok(conn)
}

/// SQL functions used by the cleanup queries: `is_useful(name, size)`,
/// `url_depth(url)` and `sensitivity(name)` (0 none, 1 weak, 2 strong).
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
    conn.create_scalar_function("url_depth", 1, flags, |ctx| {
        Ok(filters::path_depth(ctx.get_raw(0).as_str().unwrap_or("")) as i64)
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
        Msg::Entries {
            host,
            entries,
            leaf,
        } => store_listing(conn, host, entries, *leaf, now)?,
        Msg::HostDone {
            host,
            status,
            server,
            dirs,
            reason,
            purge,
            trusted,
            judge,
            failed,
        } => {
            // A site you added, or where one of yours moved to, is yours even if the
            // crawl that ends here did not know it yet.
            let trusted = *trusted || has_trust_marker(conn, host)?;
            if *purge {
                purge_host(conn, host)?;
            }
            // A run that ended in errors is a strike against a site that continues;
            // a site that has had too many in a row is ended.
            let mut status = *status;
            let mut reason = reason.clone();
            let mut fails = 0;
            if status == HostStatus::Paused && *failed {
                let before: i64 = conn
                    .query_row("SELECT fails FROM hosts WHERE host = ?1", [host], |row| {
                        row.get(0)
                    })
                    .unwrap_or(0);
                fails = before + 1;
                if fails >= MAX_FAILED_RUNS {
                    let read: bool = conn.query_row(
                        "SELECT EXISTS (SELECT 1 FROM dirs WHERE host = ?1)",
                        [host],
                        |row| row.get(0),
                    )?;
                    status = if read {
                        HostStatus::Partial
                    } else {
                        HostStatus::Unreachable
                    };
                    let last = reason.as_deref().unwrap_or("errors");
                    reason = Some(format!(
                        "gave up after {fails} runs in a row that ended in errors ({last})"
                    ));
                    fails = 0;
                }
            }
            conn.execute(
                "INSERT INTO hosts (host, status, server, dirs, files, bytes, crawled_at, reason, trusted, fails)
                 SELECT ?1, ?2, ?3, ?4, count(e.id), CAST(total(e.size) AS INTEGER), ?5, ?6, ?7, ?8
                 FROM dirs d JOIN entries e ON e.dir_id = d.id AND e.is_dir = 0
                 WHERE d.host = ?1
                 ON CONFLICT(host) DO UPDATE SET
                    status = excluded.status, server = coalesce(excluded.server, hosts.server),
                    dirs = excluded.dirs
                        + CASE WHEN hosts.status = 'paused' THEN hosts.dirs ELSE 0 END,
                    files = excluded.files, bytes = excluded.bytes,
                    crawled_at = excluded.crawled_at, reason = excluded.reason,
                    trusted = max(hosts.trusted, excluded.trusted), fails = excluded.fails",
                params![host, status.as_str(), server, *dirs as i64, now, reason, trusted, fails],
            )?;
            if status != HostStatus::Paused {
                conn.execute("DELETE FROM candidates WHERE host = ?1", [host])?;
            }
            // Judge everything stored for the site, across runs (see `verdict`).
            let judged = matches!(
                status,
                HostStatus::Done
                    | HostStatus::Paused
                    | HostStatus::Partial
                    | HostStatus::Unreachable
                    | HostStatus::NotListing
            );
            if let (Some(thresholds), true, false) = (judge, judged, trusted)
                && let Some(why) = verdict(conn, host, status, *thresholds)?
            {
                mark_host(conn, host, HostStatus::LowValue, &why)?;
            }
        }
        Msg::Candidates { urls, source } if source == MOVED_SOURCE => {
            add_trusted(conn, urls, MOVED_SOURCE)?;
        }
        Msg::Candidates { urls, source } => insert_candidates(conn, urls, source, now)?,
        Msg::Paused {
            host,
            finished,
            frontier,
        } => {
            // The seed and moved rows deleted below are how a site that is not in
            // `hosts` yet shows that it is yours: record that first.
            if has_trust_marker(conn, host)? {
                conn.execute(
                    "INSERT INTO hosts (host, status, crawled_at, trusted)
                     VALUES (?1, 'paused', ?2, 1) ON CONFLICT(host) DO UPDATE SET trusted = 1",
                    params![host, now],
                )?;
            }
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
fn store_listing(
    conn: &Connection,
    host: &str,
    entries: &[Entry],
    leaf: bool,
    now: i64,
) -> Result<()> {
    // Folder URL -> (id, decoded path for the search index). All entries of a
    // listing share one folder, but don't rely on it.
    let mut dirs: HashMap<String, (i64, String)> = HashMap::new();
    let mut add_entry = conn.prepare_cached(
        "INSERT INTO entries (dir_id, name, href, is_dir, size, mtime) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut add_to_index =
        conn.prepare_cached("INSERT INTO entries_fts (rowid, name, path) VALUES (?1, ?2, ?3)")?;
    for e in entries {
        // One spelling per folder, whatever the producer wrote (`host.` is `host`).
        let entry_url = if e.url.host_str().is_some_and(|h| h.ends_with('.')) {
            filters::canonical_url(&e.url)
        } else {
            e.url.clone()
        };
        let (dir_url, href) = split_url(&entry_url);
        if !dirs.contains_key(&dir_url) {
            let id: i64 = conn.query_row(
                "INSERT INTO dirs (host, url, seen_at, leaf) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(url) DO UPDATE SET seen_at = excluded.seen_at, leaf = excluded.leaf
                 RETURNING id",
                params![host, dir_url, now, leaf],
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

/// What is stored for a site, counted over all its files.
fn all_counts(conn: &Connection, host: &str) -> Result<Counts> {
    Ok(conn.query_row(
        "SELECT count(e.id), coalesce(sum(e.size >= ?2), 0),
                coalesce(sum(is_useful(e.name, e.size)), 0)
         FROM dirs d JOIN entries e ON e.dir_id = d.id AND e.is_dir = 0
         WHERE d.host = ?1",
        params![host, quality::BIG_FILE as i64],
        |row| {
            Ok(Counts {
                files: row.get::<_, i64>(0)? as u64,
                big: row.get::<_, i64>(1)? as u64,
                useful: row.get::<_, i64>(2)? as u64,
            })
        },
    )?)
}

/// What has been read of a site that is still being crawled, as it is stored:
/// the same numbers the crawler keeps in memory.
fn progress_of(conn: &Connection, host: &str) -> Result<Progress> {
    let level: Option<i64> = conn.query_row(
        "SELECT max(url_depth(url)) FROM dirs WHERE host = ?1 AND leaf = 1",
        [host],
        |row| row.get(0),
    )?;
    let (level_folders, level_files) = match level {
        Some(level) => conn.query_row(
            "SELECT count(DISTINCT d.id), count(e.id)
             FROM dirs d LEFT JOIN entries e ON e.dir_id = d.id AND e.is_dir = 0
             WHERE d.host = ?1 AND d.leaf = 1 AND url_depth(d.url) = ?2",
            params![host, level],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?,
        None => (0, 0),
    };
    let all = all_counts(conn, host)?;
    let folders_read: i64 = conn.query_row(
        "SELECT coalesce((SELECT dirs FROM hosts WHERE host = ?1), 0)",
        [host],
        |row| row.get(0),
    )?;
    Ok(Progress {
        level: level.map(|l| l as usize),
        level_folders: level_folders as u64,
        level_files: level_files as u64,
        all_files: all.files,
        big: all.big,
        useful: all.useful,
        folders_read: folders_read as u64,
    })
}

/// The folders still waiting for a site, against the level of its deepest leaves.
fn waiting_of(conn: &Connection, host: &str, level: Option<usize>) -> Result<Waiting> {
    let deepest: Option<i64> = conn.query_row(
        "SELECT max(url_depth(url)) FROM candidates WHERE host = ?1",
        [host],
        |row| row.get(0),
    )?;
    let at_level: i64 = match level {
        Some(level) => conn.query_row(
            "SELECT count(*) FROM candidates WHERE host = ?1 AND url_depth(url) = ?2",
            params![host, level as i64],
            |row| row.get(0),
        )?,
        None => 0,
    };
    Ok(Waiting {
        at_level: at_level as u64,
        deepest: deepest.map(|d| d as usize),
    })
}

/// `Some(reason)` if what is stored for the site is too little to keep. The one
/// place that decides, for the writer at the end of a crawl and for `clean`. A
/// finished site is judged by the thresholds; one still being crawled only on
/// strong, fair evidence (`Thresholds::judge_crawling`); one that gave up or is
/// gone only when plainly junk (`Thresholds::judge_ended`).
fn verdict(
    conn: &Connection,
    host: &str,
    status: HostStatus,
    thresholds: Thresholds,
) -> Result<Option<String>> {
    Ok(match status {
        HostStatus::Paused => {
            let progress = progress_of(conn, host)?;
            let waiting = waiting_of(conn, host, progress.level)?;
            thresholds.judge_crawling(&progress, || waiting)
        }
        HostStatus::Done => thresholds.judge_final(&all_counts(conn, host)?),
        _ => thresholds.judge_ended(&all_counts(conn, host)?),
    })
}

/// True if the site has a waiting URL that you added, or that a site you added
/// moved to.
fn has_trust_marker(conn: &Connection, host: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM candidates WHERE host = ?1 AND source IN ('seed', 'moved'))",
        [host],
        |row| row.get(0),
    )?)
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
        failed: false,
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

/// `candidates.source` for sites you added yourself.
pub const SEED_SOURCE: &str = "seed";

/// `candidates.source` for the new address of a site you added that has moved. It
/// is trusted like a seed, but a crawl started from it cannot pass trust on again,
/// so trust never travels further than one hop.
pub const MOVED_SOURCE: &str = "moved";

/// Adds sites you chose. They are trusted, and earlier verdicts that a retry or
/// a fix may change (not a listing, unreachable, given up, low value, and
/// sensitive, since those rules have changed before) are forgotten so they are
/// tried again. Returns how many sites were retried.
pub fn add_seeds(conn: &Connection, urls: &[Url]) -> Result<usize> {
    add_trusted(conn, urls, SEED_SOURCE)
}

/// Adds sites as trusted, recorded under `source`: `SEED_SOURCE` for sites you
/// chose, `MOVED_SOURCE` for the new address of one that moved. A site already
/// known is trusted too, and one that is waiting as a link or a Common Crawl
/// find becomes yours. Verdicts a retry may change are forgotten, except that a
/// moved address keeps a `sensitive` verdict.
fn add_trusted(conn: &Connection, urls: &[Url], source: &str) -> Result<usize> {
    let hosts: HashSet<String> = urls.iter().filter_map(filters::canonical_host_of).collect();
    let mut retried = 0;
    for host in &hosts {
        // A redirect is not a decision: only a site you added yourself is tried
        // again after being dropped as sensitive.
        retried += conn.execute(
            "DELETE FROM hosts WHERE host = ?1
             AND (status IN ('not_listing', 'unreachable', 'partial', 'low_value')
                  OR (status = 'sensitive' AND ?2 = 'seed'))",
            params![host, source],
        )?;
        // A moved address that stays dropped as sensitive is not made yours either.
        conn.execute(
            "UPDATE hosts SET trusted = 1
             WHERE host = ?1 AND (status != 'sensitive' OR ?2 = 'seed')",
            params![host, source],
        )?;
    }
    insert_candidates(conn, urls, source, unix_now())?;
    Ok(retried)
}

/// The sites you named on the command line, ready to crawl: recorded as seeds
/// (so they are trusted, and stay so even if the crawl is killed before it
/// records anything), together with the folders each has waiting from earlier
/// runs, which finishing the crawl would otherwise discard. Only the URLs you
/// gave, and waiting ones that were seeds, count as seeds.
pub fn named_sites(conn: &Connection, urls: &[Url]) -> Result<Vec<PendingHost>> {
    let urls: Vec<Url> = urls.iter().map(filters::canonical_url).collect();
    add_seeds(conn, &urls)?;
    let mut sites: Vec<PendingHost> = Vec::new();
    let mut listed: HashSet<String> = HashSet::new();
    for url in urls {
        let Some(host) = filters::canonical_host_of(&url) else {
            continue;
        };
        let at = match sites.iter().position(|site| site.host == host) {
            Some(at) => at,
            None => {
                let known = host_is_paused(conn, &host)?;
                sites.push(PendingHost {
                    progress: if known {
                        Some(progress_of(conn, &host)?)
                    } else {
                        None
                    },
                    known,
                    host,
                    urls: Vec::new(),
                    seeds: Vec::new(),
                    trusted: true,
                });
                sites.len() - 1
            }
        };
        if listed.insert(url.to_string()) {
            sites[at].urls.push(url.clone());
            sites[at].seeds.push(url);
        }
    }
    for site in &mut sites {
        for (url, is_seed) in waiting_urls(conn, &site.host)? {
            if listed.insert(url.to_string()) {
                site.urls.push(url.clone());
            }
            if is_seed && !site.seeds.contains(&url) {
                site.seeds.push(url);
            }
        }
    }
    Ok(sites)
}

fn host_is_paused(conn: &Connection, host: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM hosts WHERE host = ?1 AND status = 'paused')",
        [host],
        |row| row.get(0),
    )?)
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
    // One spelling per folder: `example.com.` and `example.com` are one site.
    let urls: Vec<Url> = urls.iter().map(filters::canonical_url).collect();
    for url in &urls {
        if let Some(host) = filters::canonical_host_of(url) {
            stmt.execute(params![url.as_str(), host, source, now])?;
        }
    }
    if source == SEED_SOURCE || source == MOVED_SOURCE {
        // `INSERT OR IGNORE` keeps an older row for the same URL (a link or a
        // Common Crawl find), which would leave the site looking like one you did
        // not add. A saved folder to continue from keeps its own source, a seed
        // is never demoted, and a moved address is only ever a step above a find.
        let mut promote = conn.prepare_cached(
            "UPDATE candidates SET source = ?2
             WHERE url = ?1 AND source NOT IN ('seed', 'resume')
               AND NOT (?2 = 'moved' AND source = 'moved')",
        )?;
        for url in &urls {
            promote.execute(params![url.as_str(), source])?;
        }
    }
    Ok(())
}

/// The URLs waiting for a site, shortest first, and whether you added each one.
fn waiting_urls(conn: &Connection, host: &str) -> Result<Vec<(Url, bool)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT url, source = 'seed' FROM candidates WHERE host = ?1
         ORDER BY url_depth(url), rowid",
    )?;
    let rows = stmt
        .query_map([host], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(url, is_seed)| Some((Url::parse(&url).ok()?, is_seed)))
        .collect())
}

/// A site with work waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHost {
    pub host: String,
    /// All its seed URLs. They are not pruned to the shallowest: a site's `/` is
    /// often a homepage rather than a listing, so `/pub/` must stay a seed. The
    /// crawler never fetches a URL twice.
    pub urls: Vec<Url>,
    /// The URLs among `urls` that you added yourself. Only these, being the
    /// addresses you chose, pass trust on if they turn out to have moved.
    pub seeds: Vec<Url>,
    /// You added it (a seed, or the new address of one), now or in an earlier run.
    pub trusted: bool,
    /// It was crawled before and paused, so this run continues it: its first
    /// folders are the frontier saved then.
    pub known: bool,
    /// What was read of it in earlier runs, for a site that continues.
    pub progress: Option<Progress>,
}

/// Up to `want` sites with work to do, skipping `exclude` (sites already being
/// crawled). Sites you added come first, then sites being continued, then sites
/// found through links, then Common Crawl finds; oldest first within each.
///
/// Called every couple of seconds while slots are free, so it stays cheap: the
/// first query reads one row per site, and only the sites handed out have their
/// waiting folders read, never those of the sites already running (a big
/// archive can have tens of thousands).
pub fn pending_hosts(
    conn: &Connection,
    want: usize,
    exclude: &HashSet<String>,
) -> Result<Vec<PendingHost>> {
    if want == 0 {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare_cached(
        "SELECT c.host
         FROM candidates c
         GROUP BY c.host
         HAVING NOT EXISTS (SELECT 1 FROM hosts h WHERE h.host = c.host AND h.status != 'paused')
         ORDER BY min(CASE c.source WHEN 'seed' THEN 0 WHEN 'moved' THEN 0
                                    WHEN 'resume' THEN 1 WHEN 'link' THEN 2 ELSE 3 END),
                  min(c.found_at), c.host
         LIMIT ?1",
    )?;
    // Room for the sites to skip, so that `want` new ones are found if they exist.
    let limit = (want + exclude.len()) as i64;
    let next: Vec<String> = stmt
        .query_map([limit], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;

    let mut hosts = Vec::new();
    for host in next.into_iter().filter(|h| !exclude.contains(h)).take(want) {
        let waiting = waiting_urls(conn, &host)?;
        let (known, trusted, marked): (bool, bool, bool) = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM hosts WHERE host = ?1 AND status = 'paused'),
                    coalesce((SELECT trusted FROM hosts WHERE host = ?1), 0),
                    EXISTS (SELECT 1 FROM candidates
                            WHERE host = ?1 AND source IN ('seed', 'moved'))",
            [&host],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        hosts.push(PendingHost {
            progress: if known {
                Some(progress_of(conn, &host)?)
            } else {
                None
            },
            seeds: waiting
                .iter()
                .filter(|(_, is_seed)| *is_seed)
                .map(|(url, _)| url.clone())
                .collect(),
            urls: waiting.into_iter().map(|(url, _)| url).collect(),
            host,
            trusted: trusted || marked,
            known,
        });
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
                               WHERE c.host = d.host AND c.source IN ('seed', 'moved')),
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

/// Deletes the listings stored for a folder and for everything below it, and the
/// folders below it that are still waiting to be crawled. `folder_url` ends with
/// `/`; the URLs below it are exactly those from `folder_url` up to the same text
/// with the `/` replaced by the next character, so the unique URL indexes serve
/// the lookups.
fn delete_below(conn: &Connection, folder_url: &str) -> Result<()> {
    let Some(stem) = folder_url.strip_suffix('/') else {
        return Ok(());
    };
    let upper = format!("{stem}0");
    let range = params![folder_url, upper];
    conn.execute(
        "DELETE FROM entries_fts WHERE rowid IN (
             SELECT e.id FROM dirs d JOIN entries e ON e.dir_id = d.id
             WHERE d.url >= ?1 AND d.url < ?2)",
        range,
    )?;
    conn.execute(
        "DELETE FROM entries WHERE dir_id IN (
             SELECT id FROM dirs WHERE url >= ?1 AND url < ?2)",
        range,
    )?;
    conn.execute("DELETE FROM dirs WHERE url >= ?1 AND url < ?2", range)?;
    conn.execute("DELETE FROM candidates WHERE url >= ?1 AND url < ?2", range)?;
    Ok(())
}

/// Drops sites you did not add that hold too little to keep. Each site is judged
/// by the same function the writer uses when a crawl ends, so the two agree.
fn apply_quality(conn: &Connection, thresholds: Thresholds) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT host, status FROM hosts
         WHERE trusted = 0
           AND status IN ('done', 'paused', 'partial', 'unreachable', 'not_listing')
         ORDER BY host",
    )?;
    let sites = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let mut dropped = Vec::new();
    for (host, status) in sites {
        let Some(status) = HostStatus::parse(&status) else {
            continue;
        };
        if let Some(reason) = verdict(conn, &host, status, thresholds)? {
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
            leaf: false,
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
            leaf: true,
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
            failed: false,
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
                leaf: true,
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
            leaf: true,
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
            failed: false,
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
            leaf: true,
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
            failed: false,
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
            ("e.example", "sensitive"),
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
            url("https://e.example/pub/"),
            url("https://new.example/pub/"),
        ];
        let retried = add_seeds(&conn, &seeds).unwrap();
        assert_eq!(
            retried, 3,
            "not_listing, low_value and sensitive are tried again"
        );
        let waiting: Vec<String> = pending_hosts(&conn, 10, &HashSet::new())
            .unwrap()
            .into_iter()
            .map(|h| h.host)
            .collect();
        assert_eq!(
            waiting,
            vec!["a.example", "b.example", "e.example", "new.example"]
        );
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
    fn upgrades_a_database_without_the_failed_runs_column() {
        let path = temp_path("no-fails");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE hosts (host TEXT PRIMARY KEY, status TEXT NOT NULL, server TEXT,
                 dirs INTEGER NOT NULL DEFAULT 0, files INTEGER NOT NULL DEFAULT 0,
                 bytes INTEGER NOT NULL DEFAULT 0, crawled_at INTEGER NOT NULL, reason TEXT,
                 trusted INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO hosts VALUES ('old.example', 'paused', NULL, 3, 10, 99, 0, NULL, 0);",
            )
            .unwrap();
        let conn = open(&path).unwrap();
        assert_eq!(fails(&conn, "old.example"), 0);
        // And it counts from there.
        run_ended(&conn, "old.example", HostStatus::Paused, true);
        assert_eq!(fails(&conn, "old.example"), 1);
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
            failed: false,
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
            failed: false,
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
            failed: false,
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
        let leaf = !items.iter().any(|(name, _)| name.ends_with('/'));
        let msg = Msg::Entries {
            host: host.into(),
            entries,
            leaf,
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
            failed: false,
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

    /// Stores `n` leaf folders `parent/f0`, `parent/f1`, ... with the same files.
    fn leaves(
        conn: &Connection,
        host: &str,
        parent: &str,
        n: usize,
        files: &[(&str, Option<u64>)],
    ) {
        for i in 0..n {
            put(conn, host, &format!("{parent}/f{i}"), files);
        }
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

        // 25 leaf folders of small files and nothing waiting: that is the whole site,
        // and it is plainly junk.
        let small = readmes(5, false);
        leaves(&conn, "flat.example", "pub", 25, &borrowed(&small));
        host_done(&conn, "flat.example", HostStatus::Paused, false, t);
        assert_eq!(status(&conn, "flat.example"), "low_value");
        // The same files in fewer than 20 folders are too few places to decide by.
        leaves(
            &conn,
            "few-places.example",
            "pub",
            10,
            &borrowed(&readmes(20, false)),
        );
        host_done(&conn, "few-places.example", HostStatus::Paused, false, t);
        assert_eq!(status(&conn, "few-places.example"), "paused");

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

        // Leaf folders count, the top folder's files do not: 25 leaves of 2 files
        // and 120 README files above them are 50 files of evidence, not 170.
        let two = photos(2);
        put(&conn, "top-heavy.example", "pub", &borrowed(&top));
        leaves(&conn, "top-heavy.example", "pub/iso", 25, &borrowed(&two));
        host_done(&conn, "top-heavy.example", HostStatus::Paused, false, t);
        assert_eq!(status(&conn, "top-heavy.example"), "paused");

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
                        named_sites(&conn, std::slice::from_ref(&target)).unwrap();
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

    // -- Regression tests for the fourth independent review ----------------

    #[test]
    fn a_site_that_gave_up_or_vanished_is_dropped_when_plainly_junk() {
        let conn = open(&temp_path("terminal")).unwrap();
        let t = Some(Thresholds::default());
        let junk = photos(150);
        // A folder that also has a sub-folder: for a site that will not be crawled
        // again every file counts, whatever folder it is in.
        let mut items = borrowed(&junk);
        items.push(("sub/", None));
        for (host, end) in [
            ("gave-up.example", HostStatus::Partial),
            ("vanished.example", HostStatus::Unreachable),
            ("gone.example", HostStatus::NotListing),
        ] {
            put(&conn, host, "pub", &items);
            host_done(&conn, host, end, false, t);
            assert_eq!(status(&conn, host), "low_value", "{host}");
        }
        // Too few files to say, or something big among them: it stays.
        let few = photos(60);
        put(&conn, "few.example", "pub", &borrowed(&few));
        host_done(&conn, "few.example", HostStatus::Partial, false, t);
        assert_eq!(status(&conn, "few.example"), "partial");
        let mut with_image = borrowed(&junk);
        with_image.push(("a.iso", Some(4_000_000_000)));
        put(&conn, "big.example", "pub", &with_image);
        host_done(&conn, "big.example", HostStatus::Partial, false, t);
        assert_eq!(status(&conn, "big.example"), "partial");
        // A site you added is never judged, however it ended.
        put(&conn, "mine.example", "pub", &items);
        host_done(&conn, "mine.example", HostStatus::Partial, true, None);
        assert_eq!(status(&conn, "mine.example"), "partial");
    }

    #[test]
    fn clean_judges_a_site_that_vanished_after_a_pause() {
        let mut conn = open(&temp_path("vanished")).unwrap();
        let junk = photos(150);
        put(&conn, "v.example", "pub", &borrowed(&junk));
        // Paused with a folder still waiting deeper than the leaf: not judged.
        let frontier = vec![url("https://v.example/pub/a/b/")];
        apply(
            &conn,
            &Msg::Paused {
                host: "v.example".into(),
                finished: vec![],
                frontier,
            },
        )
        .unwrap();
        host_done(&conn, "v.example", HostStatus::Paused, false, None);
        assert!(clean(&mut conn, &default_rules()).unwrap().is_empty());
        // The next run found the site gone. Nothing will crawl it again.
        host_done(&conn, "v.example", HostStatus::Unreachable, false, None);
        let report = clean(&mut conn, &default_rules()).unwrap();
        assert_eq!(report.low_value.len(), 1, "{report:?}");
        assert_eq!(status(&conn, "v.example"), "low_value");
    }

    #[test]
    fn a_paused_site_waits_for_a_sample_that_is_as_deep_and_as_big_as_what_waits() {
        let conn = open(&temp_path("deep-frontier")).unwrap();
        let t = Some(Thresholds::default());
        let junk = photos(6);
        let junk = borrowed(&junk);
        let pause = |host: &str, waiting: Vec<String>| {
            let msg = Msg::Paused {
                host: host.into(),
                finished: vec![],
                frontier: waiting.iter().map(|u| url(u)).collect(),
            };
            apply(&conn, &msg).unwrap();
            host_done(&conn, host, HostStatus::Paused, false, t);
        };
        // 25 leaf folders (150 junk files) two levels down, but a folder four levels
        // down is still waiting: what is left to crawl could change the verdict.
        leaves(&conn, "deep.example", "pub", 25, &junk);
        pause(
            "deep.example",
            vec!["https://deep.example/pub/a/b/c/".into()],
        );
        assert_eq!(status(&conn, "deep.example"), "paused");

        // Nothing waiting is deeper than the leaves, and no more of it than was
        // seen: plainly junk, so dropped.
        leaves(&conn, "flat.example", "pub", 25, &junk);
        pause(
            "flat.example",
            vec!["https://flat.example/pub/other/".into()],
        );
        assert_eq!(status(&conn, "flat.example"), "low_value");

        // The same sample, but more folders wait than were looked at (siblings that
        // could differ): not judged.
        leaves(&conn, "wide.example", "pub", 25, &junk);
        let many: Vec<String> = (0..30)
            .map(|i| format!("https://wide.example/pub/w{i}/"))
            .collect();
        pause("wide.example", many);
        assert_eq!(status(&conn, "wide.example"), "paused");

        // A lot of junk (2,500 files in 25 folders) with a deeper folder still
        // waiting is not judged either: the downloads may be down there.
        let hundred: Vec<(String, Option<u64>)> = (0..100)
            .map(|i| (format!("t{i}.jpg"), Some(30_000)))
            .collect();
        leaves(&conn, "huge.example", "pub", 25, &borrowed(&hundred));
        pause(
            "huge.example",
            vec!["https://huge.example/pub/a/b/c/".into()],
        );
        assert_eq!(status(&conn, "huge.example"), "paused");

        // Only a site that has cost 2,000 folders is dropped whatever waits, and only
        // if under 1% of what it holds is useful (and it is not kept by the
        // thresholds: 20 useful files or 3 big ones).
        let long_read = |host: &str, extra: &[(String, Option<u64>)]| {
            leaves(&conn, host, "pub", 10, &borrowed(&hundred));
            if !extra.is_empty() {
                put(&conn, host, "pub/extra", &borrowed(extra));
            }
            let msg = Msg::Paused {
                host: host.into(),
                finished: vec![],
                frontier: vec![url(&format!("https://{host}/pub/a/b/c/"))],
            };
            apply(&conn, &msg).unwrap();
            let done = Msg::HostDone {
                host: host.into(),
                status: HostStatus::Paused,
                server: None,
                dirs: quality::HARD_FOLDERS,
                reason: None,
                purge: false,
                trusted: false,
                judge: t,
                failed: false,
            };
            apply(&conn, &done).unwrap();
        };
        let isos = |n: usize| -> Vec<(String, Option<u64>)> {
            (0..n).map(|i| (format!("d{i}.iso"), Some(1_000))).collect()
        };
        long_read("endless.example", &[]);
        assert_eq!(status(&conn, "endless.example"), "low_value");
        long_read("stray.example", &isos(1));
        assert_eq!(status(&conn, "stray.example"), "low_value");
        // 15 useful files among 1,015 (1.5%): not enough to keep the site, but too
        // many to call it endless junk.
        long_read("share.example", &isos(15));
        assert_eq!(status(&conn, "share.example"), "paused");
        // With the same numbers but fewer folders read, nothing is judged.
        leaves(&conn, "young.example", "pub", 10, &borrowed(&hundred));
        pause(
            "young.example",
            vec!["https://young.example/pub/a/b/c/".into()],
        );
        assert_eq!(status(&conn, "young.example"), "paused");

        // One useful file among the junk keeps a site that has not cost that much.
        let mut with_iso = borrowed(&hundred);
        with_iso.push(("a.iso", Some(1_000)));
        leaves(&conn, "mixed.example", "pub", 25, &with_iso);
        pause(
            "mixed.example",
            vec!["https://mixed.example/pub/a/b/c/".into()],
        );
        assert_eq!(status(&conn, "mixed.example"), "paused");
    }

    fn fails(conn: &Connection, host: &str) -> i64 {
        conn.query_row("SELECT fails FROM hosts WHERE host = ?1", [host], |r| {
            r.get(0)
        })
        .unwrap()
    }

    fn run_ended(conn: &Connection, host: &str, status: HostStatus, failed: bool) {
        let msg = Msg::HostDone {
            host: host.into(),
            status,
            server: None,
            dirs: 1,
            reason: Some("could not be reached this run".into()),
            purge: false,
            trusted: false,
            judge: Some(Thresholds::default()),
            failed,
        };
        apply(conn, &msg).unwrap();
    }

    #[test]
    fn a_paused_site_is_given_up_after_five_runs_in_a_row_that_ended_in_errors() {
        let conn = open(&temp_path("strikes")).unwrap();
        let isos = [
            ("a.iso", Some(4_000_000_000)),
            ("b.iso", Some(4_000_000_000)),
            ("c.iso", Some(4_000_000_000)),
        ];
        put(&conn, "flaky.example", "pub", &isos);
        for run in 1..=4 {
            run_ended(&conn, "flaky.example", HostStatus::Paused, true);
            assert_eq!(status(&conn, "flaky.example"), "paused");
            assert_eq!(fails(&conn, "flaky.example"), run);
        }
        // A run that ends without errors starts the count again.
        run_ended(&conn, "flaky.example", HostStatus::Paused, false);
        assert_eq!(fails(&conn, "flaky.example"), 0);
        for _ in 0..5 {
            run_ended(&conn, "flaky.example", HostStatus::Paused, true);
        }
        // What was read stays, and the site is not crawled again.
        assert_eq!(status(&conn, "flaky.example"), "partial");
        let why: String = conn
            .query_row(
                "SELECT reason FROM hosts WHERE host = 'flaky.example'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(why.contains("gave up after 5 runs"), "{why}");
        assert_eq!(fails(&conn, "flaky.example"), 0);
        assert_eq!(search_count(&conn, "a.iso"), 1);

        // A paused site with nothing stored ends as unreachable.
        for _ in 0..5 {
            run_ended(&conn, "gone.example", HostStatus::Paused, true);
        }
        assert_eq!(status(&conn, "gone.example"), "unreachable");

        // Failing runs of a site you added end it the same way, and are not judged.
        put(&conn, "mine.example", "pub", &isos);
        let msg = |failed| Msg::HostDone {
            host: "mine.example".into(),
            status: HostStatus::Paused,
            server: None,
            dirs: 1,
            reason: None,
            purge: false,
            trusted: true,
            judge: Some(Thresholds::default()),
            failed,
        };
        for _ in 0..5 {
            apply(&conn, &msg(true)).unwrap();
        }
        assert_eq!(status(&conn, "mine.example"), "partial");
    }

    fn search_count(conn: &Connection, name: &str) -> i64 {
        conn.query_row(
            "SELECT count(*) FROM entries WHERE name = ?1",
            [name],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn clean_of_a_paused_site_with_a_big_folder_is_not_quadratic() {
        let mut conn = open(&temp_path("big-folder")).unwrap();
        // 20 leaf folders, one of them holding 20,000 files.
        let many: Vec<(String, Option<u64>)> = (0..20_000)
            .map(|i| (format!("f{i}.jpg"), Some(40_000)))
            .collect();
        put(&conn, "big.example", "pub/big", &borrowed(&many));
        leaves(&conn, "big.example", "pub", 19, &[("a.jpg", Some(9_000))]);
        let paused = Msg::Paused {
            host: "big.example".into(),
            finished: vec![],
            frontier: vec![url("https://big.example/x/y/")],
        };
        apply(&conn, &paused).unwrap();
        host_done(&conn, "big.example", HostStatus::Paused, false, None);

        let started = std::time::Instant::now();
        let report = clean(&mut conn, &default_rules()).unwrap();
        let took = started.elapsed();

        assert_eq!(report.low_value.len(), 1, "{report:?}");
        // Linear in the files: milliseconds. It once compared every file with all
        // the files of its folder, which took a minute for this many.
        assert!(took < Duration::from_secs(5), "clean took {took:?}");
    }

    #[test]
    fn upgrades_a_database_without_the_leaf_flag() {
        let path = temp_path("no-leaf");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE dirs (id INTEGER PRIMARY KEY, host TEXT NOT NULL,
                     url TEXT NOT NULL UNIQUE, seen_at INTEGER NOT NULL);
                 CREATE TABLE entries (id INTEGER PRIMARY KEY, dir_id INTEGER NOT NULL,
                     name TEXT NOT NULL, href TEXT, is_dir INTEGER NOT NULL, size INTEGER,
                     mtime TEXT);
                 INSERT INTO dirs VALUES (1, 'old.example', 'https://old.example/pub/', 0);
                 INSERT INTO dirs VALUES (2, 'old.example', 'https://old.example/pub/iso/', 0);
                 INSERT INTO entries (dir_id, name, is_dir, size)
                     VALUES (1, 'iso', 1, NULL), (1, 'README', 0, 10), (2, 'a.iso', 0, 4000000000);",
            )
            .unwrap();
        let conn = open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT url, leaf FROM dirs ORDER BY url")
            .unwrap();
        let leaves: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        // The folder with a sub-folder is not a leaf; the one below it is.
        assert_eq!(
            leaves,
            vec![
                ("https://old.example/pub/".to_string(), 0),
                ("https://old.example/pub/iso/".to_string(), 1),
            ]
        );
    }

    #[test]
    fn named_sites_are_seeds_and_continue_the_folders_they_have_waiting() {
        let conn = open(&temp_path("named")).unwrap();
        add_candidates(
            &conn,
            &[
                url("https://a.example/pub/iso/"),
                url("https://a.example/pub/doc/"),
                url("https://other.example/x/"),
            ],
            "link",
        )
        .unwrap();
        add_seeds(&conn, &[url("https://a.example/pub/old-seed/")]).unwrap();

        let sites = named_sites(
            &conn,
            &[
                url("https://A.example./pub/iso/"),
                url("https://b.example/"),
            ],
        )
        .unwrap();

        assert_eq!(sites.len(), 2);
        let a = &sites[0];
        assert_eq!(a.host, "a.example");
        assert!(a.trusted);
        // What you typed comes first, then what was waiting, each URL once. Only
        // the URLs you added count as seeds, not the folder found through a link.
        assert_eq!(
            a.urls,
            vec![
                url("https://a.example/pub/iso/"),
                url("https://a.example/pub/doc/"),
                url("https://a.example/pub/old-seed/"),
            ]
        );
        assert_eq!(
            a.seeds,
            vec![
                url("https://a.example/pub/iso/"),
                url("https://a.example/pub/old-seed/"),
            ]
        );
        assert_eq!(sites[1].urls, vec![url("https://b.example/")]);
        assert_eq!(sites[1].seeds, sites[1].urls);
        // Other sites are left alone.
        assert!(sites.iter().all(|s| s.host != "other.example"));
    }

    #[test]
    fn a_named_site_keeps_its_trust_when_its_crawl_was_killed() {
        let mut conn = open(&temp_path("killed")).unwrap();
        let big = Some(4_000_000_000);
        // The crawl stored a listing and was killed before it wrote the site's row.
        put(
            &conn,
            "mine.example",
            "pub",
            &[("a.iso", big), ("backup-2026-01-01.zip", Some(9))],
        );
        assert!(!has_row(&conn, "mine.example"));

        named_sites(&conn, &[url("https://mine.example/pub/")]).unwrap();
        let report = clean(&mut conn, &default_rules()).unwrap();

        // It costs the site you named only the weak-named file.
        assert!(report.sensitive.is_empty(), "{report:?}");
        assert_eq!(report.omitted_entries, 1);
        assert_eq!(files(&conn), vec!["https://mine.example/pub/a.iso"]);
    }

    #[test]
    fn the_new_address_of_a_moved_seed_is_trusted_but_cannot_pass_trust_on() {
        let mut conn = open(&temp_path("moved-addr")).unwrap();
        let moved = |host: &str| Msg::Candidates {
            urls: vec![url(&format!("https://{host}/pub/"))],
            source: MOVED_SOURCE.into(),
        };
        // A new address: waiting, trusted, and not a seed, so a crawl started from
        // it cannot make yet another address trusted.
        apply(&conn, &moved("new.example")).unwrap();
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(waiting.len(), 1);
        assert!(waiting[0].trusted);
        assert!(waiting[0].seeds.is_empty());

        // An address already known and kept, though nobody vouched for it: trusted
        // from now on, so the cleanup keeps it.
        add_site(
            &conn,
            "known.example",
            "pub",
            &[("a.txt", Some(5))],
            false,
            None,
        );
        apply(&conn, &moved("known.example")).unwrap();
        assert!(
            clean(&mut conn, &default_rules())
                .unwrap()
                .low_value
                .is_empty()
        );
        assert_eq!(status(&conn, "known.example"), "done");

        // One dropped for holding little is tried again, as yours.
        let t = Some(Thresholds::default());
        add_site(
            &conn,
            "dropped.example",
            "pub",
            &[("a.txt", Some(5))],
            false,
            t,
        );
        assert_eq!(status(&conn, "dropped.example"), "low_value");
        apply(&conn, &moved("dropped.example")).unwrap();
        assert!(!has_row(&conn, "dropped.example"));
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert!(
            waiting
                .iter()
                .any(|h| h.host == "dropped.example" && h.trusted)
        );

        // The crawl of an address that was found by a link and is still running
        // when it turns out to be a seed's new address ends as yours, not judged.
        apply(&conn, &moved("racy.example")).unwrap();
        let tiny = photos(3);
        put(&conn, "racy.example", "pub", &borrowed(&tiny));
        host_done(&conn, "racy.example", HostStatus::Done, false, t);
        assert_eq!(status(&conn, "racy.example"), "done");

        // A seed you add for the same address later is a seed.
        add_seeds(&conn, &[url("https://new.example/pub/")]).unwrap();
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        let new = waiting.iter().find(|h| h.host == "new.example").unwrap();
        assert_eq!(new.seeds, vec![url("https://new.example/pub/")]);
    }

    #[test]
    fn an_omitted_folder_takes_everything_below_it_including_waiting_folders() {
        let mut conn = open(&temp_path("omit-below")).unwrap();
        let big = Some(4_000_000_000);
        // Folder names that need percent-encoding, and one that does not.
        put(
            &conn,
            "mine.example",
            "d",
            &[
                ("a.iso", big),
                ("backup-2020-%C3%A9/", None),
                ("bak-2019%20old/", None),
                ("other/", None),
            ],
        );
        put(
            &conn,
            "mine.example",
            "d/backup-2020-%C3%A9",
            &[("zzone.txt", Some(5)), ("deeper/", None)],
        );
        put(
            &conn,
            "mine.example",
            "d/backup-2020-%C3%A9/deeper",
            &[("zztwo.txt", Some(5))],
        );
        put(
            &conn,
            "mine.example",
            "d/bak-2019%20old",
            &[("zzthree.txt", Some(5))],
        );
        put(&conn, "mine.example", "d/other", &[("zzkeep.txt", Some(5))]);
        // The crawl was paused with folders below the omitted one still to do.
        let paused = Msg::Paused {
            host: "mine.example".into(),
            finished: vec![],
            frontier: vec![
                url("https://mine.example/d/backup-2020-%C3%A9/deeper/more/"),
                url("https://mine.example/d/other/later/"),
            ],
        };
        apply(&conn, &paused).unwrap();
        host_done(&conn, "mine.example", HostStatus::Paused, true, None);
        assert_eq!(hits(&conn, "zzone"), 1);

        let report = clean(&mut conn, &default_rules()).unwrap();

        assert_eq!(report.omitted_entries, 2);
        for gone in ["zzone", "zztwo", "zzthree"] {
            assert_eq!(hits(&conn, gone), 0, "{gone} is still searchable");
        }
        assert_eq!(hits(&conn, "zzkeep"), 1);
        // What was waiting below the omitted folder is not crawled again.
        let waiting: Vec<String> = waiting_urls(&conn, "mine.example")
            .unwrap()
            .into_iter()
            .map(|(u, _)| u.to_string())
            .collect();
        assert_eq!(waiting, vec!["https://mine.example/d/other/later/"]);
    }

    #[test]
    fn adding_a_seed_tries_a_site_dropped_as_sensitive_again() {
        let conn = open(&temp_path("seed-sensitive")).unwrap();
        conn.execute(
            "INSERT INTO hosts (host, status, crawled_at, reason)
             VALUES ('s.example', 'sensitive', 0, 'found /pub/.env')",
            [],
        )
        .unwrap();
        let retried = add_seeds(&conn, &[url("https://s.example/pub/")]).unwrap();
        assert_eq!(retried, 1);
        assert!(!has_row(&conn, "s.example"));
        let waiting = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert!(waiting.iter().any(|h| h.host == "s.example" && h.trusted));
    }

    /// Random operations; invariants of the store after each one.
    #[test]
    fn random_operations_keep_the_store_consistent() {
        for round in 0..300u64 {
            let mut x = (round + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut rnd = move |n: u64| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x % n
            };
            let mut conn = open(Path::new(":memory:")).unwrap();
            let hosts = ["a.example", "b.example", "c.example"];
            let folders = ["pub", "pub/x", "pub/y"];
            // Sites you added, or that one of yours moved to: the only trusted ones.
            let mut yours: Vec<&str> = Vec::new();
            let mut log: Vec<String> = Vec::new();
            for _ in 0..60 {
                let host = hosts[rnd(3) as usize];
                let folder = folders[rnd(3) as usize];
                let dropped = conn
                    .query_row(
                        "SELECT status IN ('low_value', 'sensitive', 'skipped', 'opted_out')
                         FROM hosts WHERE host = ?1",
                        [host],
                        |r| r.get::<_, bool>(0),
                    )
                    .unwrap_or(false);
                // A dropped site is not crawled again, unless you add it.
                let op = if dropped { 6 + rnd(2) * 3 } else { rnd(10) };
                match op {
                    0 | 1 => {
                        let mut items: Vec<(String, Option<u64>)> = Vec::new();
                        for i in 0..rnd(5) {
                            let name = match rnd(6) {
                                0 => format!("backup-2020-{i}.zip"),
                                1 => format!("backup-2021-{i}/"),
                                2 => format!("sub{i}/"),
                                3 => format!("file{i}.iso"),
                                4 => format!("notes{i}.txt"),
                                _ => format!("f{i}.jpg"),
                            };
                            let size = (!name.ends_with('/')).then(|| rnd(3) * 2_500_000_000 + 10);
                            items.push((name, size));
                        }
                        put(&conn, host, folder, &borrowed(&items));
                        log.push(format!("entries {host}/{folder} {items:?}"));
                    }
                    2 | 3 => {
                        let end = [
                            HostStatus::Done,
                            HostStatus::Paused,
                            HostStatus::Partial,
                            HostStatus::NotListing,
                            HostStatus::Unreachable,
                        ][rnd(5) as usize];
                        let trusted = yours.contains(&host);
                        if end == HostStatus::Paused {
                            let waiting =
                                url(&format!("https://{host}/{}/", folders[rnd(3) as usize]));
                            let msg = Msg::Paused {
                                host: host.into(),
                                finished: vec![],
                                frontier: vec![waiting],
                            };
                            apply(&conn, &msg).unwrap();
                        }
                        let judge = (!trusted).then(Thresholds::default);
                        host_done(&conn, host, end, trusted, judge);
                        log.push(format!("host_done {host} {end:?} trusted={trusted}"));
                    }
                    4 => {
                        let source = ["link", "commoncrawl:X"][rnd(2) as usize];
                        let target = url(&format!("https://{host}/{folder}/"));
                        add_candidates(&conn, &[target], source).unwrap();
                        log.push(format!("candidate {host}/{folder} {source}"));
                    }
                    5 => {
                        add_seeds(&conn, &[url(&format!("https://{host}/{folder}/"))]).unwrap();
                        if !yours.contains(&host) {
                            yours.push(host);
                        }
                        log.push(format!("seed {host}/{folder}"));
                    }
                    6 => {
                        clean(&mut conn, &default_rules()).unwrap();
                        let again = clean(&mut conn, &default_rules()).unwrap();
                        assert!(
                            again.is_empty(),
                            "a second clean found more in round {round}: {again:?}\n  {}",
                            log.join("\n  ")
                        );
                        log.push("clean".into());
                    }
                    7 => {
                        // A crawl of a seed found that its address moved to another site.
                        let target = hosts[rnd(3) as usize];
                        if yours.contains(&host) && target != host {
                            let msg = Msg::Candidates {
                                urls: vec![url(&format!("https://{target}/pub/"))],
                                source: MOVED_SOURCE.into(),
                            };
                            apply(&conn, &msg).unwrap();
                            // A redirect does not clear a sensitive verdict.
                            let dropped_as_sensitive = conn
                                .query_row(
                                    "SELECT status = 'sensitive' FROM hosts WHERE host = ?1",
                                    [target],
                                    |r| r.get::<_, bool>(0),
                                )
                                .unwrap_or(false);
                            if !yours.contains(&target) && !dropped_as_sensitive {
                                yours.push(target);
                            }
                            log.push(format!("moved {host} -> {target}"));
                        }
                    }
                    _ => {}
                }
                let fts: i64 = conn
                    .query_row("SELECT count(*) FROM entries_fts_docsize", [], |r| r.get(0))
                    .unwrap();
                let entries: i64 = conn
                    .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(
                    fts,
                    entries,
                    "search index out of step in round {round}:\n  {}",
                    log.join("\n  ")
                );
                let orphans: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM entries WHERE dir_id NOT IN (SELECT id FROM dirs)",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(
                    orphans,
                    0,
                    "entries without a folder in round {round}:\n  {}",
                    log.join("\n  ")
                );
                let stale: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM hosts h
                         WHERE h.status IN ('low_value', 'sensitive', 'skipped', 'opted_out')
                           AND (EXISTS (SELECT 1 FROM dirs d WHERE d.host = h.host)
                                OR EXISTS (SELECT 1 FROM candidates c WHERE c.host = h.host))",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(
                    stale,
                    0,
                    "a dropped site keeps data in round {round}:\n  {}",
                    log.join("\n  ")
                );
                for h in hosts {
                    let row = conn.query_row(
                        "SELECT status, trusted FROM hosts WHERE host = ?1",
                        [h],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                    );
                    if let Ok((state, trusted)) = row {
                        assert!(
                            trusted == 0 || yours.contains(&h),
                            "{h} is trusted but nobody added it (round {round}):\n  {}",
                            log.join("\n  ")
                        );
                        // Weak names cost a site of yours the entry, never the site.
                        assert!(
                            !yours.contains(&h) || (state != "low_value" && state != "sensitive"),
                            "{h} (yours) became {state} in round {round}:\n  {}",
                            log.join("\n  ")
                        );
                    }
                }
            }
        }
    }

    // -- Regression tests for the fifth independent review ----------------

    fn trusted_flag(conn: &Connection, host: &str) -> i64 {
        conn.query_row(
            "SELECT coalesce((SELECT trusted FROM hosts WHERE host = ?1), -1)",
            [host],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn leaf_flag(conn: &Connection, folder: &str) -> i64 {
        conn.query_row("SELECT leaf FROM dirs WHERE url = ?1", [folder], |r| {
            r.get(0)
        })
        .unwrap()
    }

    #[test]
    fn pausing_keeps_the_trust_a_moved_seed_gave() {
        let mut conn = open(&temp_path("paused-trust")).unwrap();
        // Y is being crawled as an ordinary find: its listings arrive first.
        put(&conn, "y.example", "pub/a", &borrowed(&photos(150)));
        // Meanwhile a seed's crawl finds that its address moved to Y.
        let moved = Msg::Candidates {
            urls: vec![url("https://y.example/pub/")],
            source: MOVED_SOURCE.into(),
        };
        apply(&conn, &moved).unwrap();
        // Y's crawl runs out of budget: the crawler sends Paused, and then HostDone.
        let paused = Msg::Paused {
            host: "y.example".into(),
            finished: vec![],
            frontier: vec![url("https://y.example/pub/b/")],
        };
        apply(&conn, &paused).unwrap();
        host_done(
            &conn,
            "y.example",
            HostStatus::Paused,
            false,
            Some(Thresholds::default()),
        );

        assert_eq!(
            trusted_flag(&conn, "y.example"),
            1,
            "Y is where a seed of yours moved to"
        );
        assert!(
            clean(&mut conn, &default_rules())
                .unwrap()
                .low_value
                .is_empty()
        );
    }

    #[test]
    fn a_redirect_does_not_clear_a_sensitive_verdict() {
        let conn = open(&temp_path("moved-sensitive")).unwrap();
        let dropped = Msg::HostDone {
            host: "evil.example".into(),
            status: HostStatus::Sensitive,
            server: None,
            dirs: 1,
            reason: Some("found https://evil.example/pub/passport-scan.jpg".into()),
            purge: true,
            trusted: false,
            judge: None,
            failed: false,
        };
        apply(&conn, &dropped).unwrap();

        // A seed of yours redirects to it: an automatic step, not a decision.
        let moved = Msg::Candidates {
            urls: vec![url("https://evil.example/pub/")],
            source: MOVED_SOURCE.into(),
        };
        apply(&conn, &moved).unwrap();
        assert_eq!(status(&conn, "evil.example"), "sensitive");
        assert_eq!(trusted_flag(&conn, "evil.example"), 0);
        assert!(
            pending_hosts(&conn, 10, &HashSet::new())
                .unwrap()
                .is_empty()
        );

        // A site you add yourself is tried again.
        add_seeds(&conn, &[url("https://evil.example/pub/")]).unwrap();
        assert!(!has_row(&conn, "evil.example"));
    }

    #[test]
    fn one_folder_has_one_spelling_in_every_table() {
        let conn = open(&temp_path("spelling")).unwrap();
        // A producer that writes the trailing-dot spelling of the host, and a later
        // run that reads the same folder under the canonical one.
        let listing = |host: &str| Msg::Entries {
            host: "mirror.example.org".into(),
            entries: vec![
                entry(
                    &format!("https://{host}/pub/a.iso"),
                    false,
                    Some(4_000_000_000),
                ),
                entry(&format!("https://{host}/pub/sub/"), true, None),
            ],
            leaf: false,
        };
        apply(&conn, &listing("mirror.example.org.")).unwrap();
        apply(&conn, &listing("mirror.example.org")).unwrap();
        let folders: i64 = conn
            .query_row("SELECT count(*) FROM dirs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(folders, 1, "one folder, one row");
        assert_eq!(
            files(&conn),
            vec![
                "https://mirror.example.org/pub/a.iso",
                "https://mirror.example.org/pub/sub/"
            ],
            "and one spelling of what it holds"
        );

        // Waiting folders too: two spellings are one row, stored in the canonical form.
        add_candidates(
            &conn,
            &[
                url("https://Mirror.Example.ORG./pub/sub/"),
                url("https://mirror.example.org/pub/sub/"),
            ],
            "link",
        )
        .unwrap();
        let waiting: Vec<String> = waiting_urls(&conn, "mirror.example.org")
            .unwrap()
            .into_iter()
            .map(|(u, _)| u.to_string())
            .collect();
        assert_eq!(waiting, vec!["https://mirror.example.org/pub/sub/"]);
    }

    #[test]
    fn omitting_a_folder_keeps_the_ones_next_to_it() {
        let mut conn = open(&temp_path("neighbours")).unwrap();
        let host = "xn--bcher-kva.example";
        // Only `Mail.PST` is weak-named. The others sort next to it or share a prefix
        // or a character that is special in URLs.
        let folders = [
            "Mail.PST",
            "mail.pst2",
            "mail.pst0",
            "mail.pst-old",
            "mail.ps",
            "mail.pst%2Fx",
            "mail.pst~",
        ];
        let names: Vec<String> = folders.iter().map(|f| format!("{f}/")).collect();
        let mut root: Vec<(&str, Option<u64>)> = vec![("a.iso", Some(4_000_000_000))];
        root.extend(names.iter().map(|n| (n.as_str(), None)));
        put(&conn, host, "d", &root);
        for f in folders {
            put(&conn, host, &format!("d/{f}"), &[("keep.txt", Some(5))]);
        }
        let waiting = Msg::Paused {
            host: host.into(),
            finished: vec![],
            frontier: folders
                .iter()
                .map(|f| url(&format!("https://{host}/d/{f}/later/")))
                .collect(),
        };
        apply(&conn, &waiting).unwrap();
        host_done(&conn, host, HostStatus::Paused, true, None);

        let report = clean(&mut conn, &default_rules()).unwrap();

        assert_eq!(report.omitted_entries, 1, "only Mail.PST is weak-named");
        let waiting = waiting_urls(&conn, host).unwrap();
        assert_eq!(waiting.len(), folders.len() - 1);
        assert!(
            waiting
                .iter()
                .all(|(u, _)| !u.as_str().contains("Mail.PST"))
        );
        let folders_left: i64 = conn
            .query_row("SELECT count(*) FROM dirs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(folders_left as usize, 1 + folders.len() - 1);
    }

    #[test]
    fn a_failed_leaf_back_fill_is_retried_on_the_next_open() {
        let path = temp_path("backfill");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE dirs (id INTEGER PRIMARY KEY, host TEXT NOT NULL,
                     url TEXT NOT NULL UNIQUE, seen_at INTEGER NOT NULL);
                 CREATE TABLE entries (id INTEGER PRIMARY KEY, dir_id INTEGER NOT NULL,
                     name TEXT NOT NULL, href TEXT, is_dir INTEGER NOT NULL, size INTEGER,
                     mtime TEXT);
                 INSERT INTO dirs VALUES (1, 'old.example', 'https://old.example/pub/', 0);
                 INSERT INTO entries (dir_id, name, is_dir, size) VALUES (1, 'a.iso', 0, 4000000000);
                 -- whatever makes the update fail halfway: a full disk, a lock timeout
                 CREATE TRIGGER boom BEFORE UPDATE ON dirs BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .unwrap();
        assert!(
            open(&path).is_err(),
            "the first open fails in the back-fill"
        );
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER boom")
            .unwrap();
        let conn = open(&path).unwrap();
        assert_eq!(leaf_flag(&conn, "https://old.example/pub/"), 1);
    }

    #[test]
    fn a_folder_read_again_takes_its_new_leaf_flag() {
        let conn = open(&temp_path("leaf-refresh")).unwrap();
        let folder = "https://h.example/pub/";
        let listing = |leaf: bool| Msg::Entries {
            host: "h.example".into(),
            entries: vec![
                entry("https://h.example/pub/a.iso", false, Some(1)),
                entry("https://h.example/pub/sub/", true, None),
            ],
            leaf,
        };
        apply(&conn, &listing(false)).unwrap();
        assert_eq!(leaf_flag(&conn, folder), 0);
        // Later its only sub-folder is skipped: the same folder is a leaf now.
        apply(&conn, &listing(true)).unwrap();
        assert_eq!(leaf_flag(&conn, folder), 1);
        apply(&conn, &listing(false)).unwrap();
        assert_eq!(leaf_flag(&conn, folder), 0);
    }

    #[test]
    fn choosing_the_next_site_does_not_read_the_folders_of_sites_already_running() {
        let conn = open(&temp_path("scheduler")).unwrap();
        conn.execute_batch("BEGIN").unwrap();
        let mut running = HashSet::new();
        for h in 0..3 {
            let host = format!("big{h}.example");
            conn.execute(
                "INSERT INTO hosts (host, status, crawled_at, trusted)
                 VALUES (?1, 'paused', 0, 0)",
                [&host],
            )
            .unwrap();
            let mut stmt = conn
                .prepare(
                    "INSERT INTO candidates (url, host, source, found_at)
                     VALUES (?1, ?2, 'resume', 1)",
                )
                .unwrap();
            for i in 0..4_000 {
                let waiting = format!("https://{host}/a/b{}/c{i}/", i / 100);
                stmt.execute(params![waiting, host]).unwrap();
            }
            running.insert(host);
        }
        conn.execute(
            "INSERT INTO candidates (url, host, source, found_at)
             VALUES ('https://small.example/pub/', 'small.example', 'link', 2)",
            [],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let started = std::time::Instant::now();
        let next = pending_hosts(&conn, 1, &running).unwrap();
        let took = started.elapsed();

        assert_eq!(next.len(), 1);
        assert_eq!(next[0].host, "small.example");
        // The scheduler asks every couple of seconds. The lookup used to rescan the
        // 12,000 waiting folders of the running sites, and to take seconds.
        assert!(took < Duration::from_secs(1), "took {took:?}");
        // A site with 5,000 waiting folders is looked up in a moment too.
        let started = std::time::Instant::now();
        let first = pending_hosts(&conn, 1, &HashSet::new()).unwrap();
        assert_eq!(first[0].urls.len(), 4_000);
        assert!(started.elapsed() < Duration::from_secs(1));
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
