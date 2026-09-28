//! SQLite storage: one file holds the entries, per-host crawl results, a
//! full-text index (FTS5) over file names and directory paths, and the
//! discovery candidates waiting to be crawled.
//!
//! The crawler never touches SQLite directly. It sends messages to a single
//! writer thread, which batches them into transactions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use percent_encoding::percent_decode_str;
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use tokio::sync::{mpsc, oneshot};
use url::Url;

use crate::filters;
use crate::listing::Entry;
use crate::safety::{HONOR_OPT_OUT_LIST, HONOR_TAKEDOWN_LIST};

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
    reason     TEXT
);

CREATE TABLE IF NOT EXISTS entries (
    url     TEXT PRIMARY KEY,
    host    TEXT NOT NULL,
    dir     TEXT NOT NULL,
    name    TEXT NOT NULL,
    is_dir  INTEGER NOT NULL,
    size    INTEGER,
    mtime   TEXT,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_host ON entries(host);

CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts
    USING fts5(name, dir, content='entries', content_rowid='rowid');

CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
    INSERT INTO entries_fts(rowid, name, dir) VALUES (new.rowid, new.name, new.dir);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
    INSERT INTO entries_fts(entries_fts, rowid, name, dir) VALUES ('delete', old.rowid, old.name, old.dir);
END;
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
    INSERT INTO entries_fts(entries_fts, rowid, name, dir) VALUES ('delete', old.rowid, old.name, old.dir);
    INSERT INTO entries_fts(rowid, name, dir) VALUES (new.rowid, new.name, new.dir);
END;

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
        /// Delete the host's entries too (dropped as sensitive, or opted out).
        purge: bool,
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
    conn.execute_batch(SCHEMA)?;
    // Databases created by v1 lack `hosts.reason`.
    let has_reason: bool = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('hosts') WHERE name = 'reason'",
        [],
        |row| row.get(0),
    )?;
    if !has_reason {
        conn.execute_batch("ALTER TABLE hosts ADD COLUMN reason TEXT")?;
    }
    Ok(conn)
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
        Msg::Entries { host, entries } => {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO entries (url, host, dir, name, is_dir, size, mtime, seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(url) DO UPDATE SET
                    name = excluded.name, is_dir = excluded.is_dir, size = excluded.size,
                    mtime = excluded.mtime, seen_at = excluded.seen_at",
            )?;
            for e in entries {
                let path = e.url.path();
                let parent = &path[..path.trim_end_matches('/').rfind('/').map_or(0, |i| i + 1)];
                let dir = percent_decode_str(parent).decode_utf8_lossy();
                stmt.execute(params![
                    e.url.as_str(),
                    host,
                    dir,
                    e.name,
                    e.is_dir,
                    e.size.map(|s| s as i64),
                    e.mtime,
                    now
                ])?;
            }
        }
        Msg::HostDone {
            host,
            status,
            server,
            dirs,
            reason,
            purge,
        } => {
            if *purge {
                conn.execute("DELETE FROM entries WHERE host = ?1", [host])?;
            }
            conn.execute(
                "INSERT INTO hosts (host, status, server, dirs, files, bytes, crawled_at, reason)
                 SELECT ?1, ?2, ?3, ?4, count(*), CAST(total(size) AS INTEGER), ?5, ?6
                 FROM entries WHERE host = ?1 AND is_dir = 0
                 ON CONFLICT(host) DO UPDATE SET
                    status = excluded.status, server = coalesce(excluded.server, hosts.server),
                    dirs = excluded.dirs
                        + CASE WHEN hosts.status = 'paused' THEN hosts.dirs ELSE 0 END,
                    files = excluded.files, bytes = excluded.bytes,
                    crawled_at = excluded.crawled_at, reason = excluded.reason",
                params![host, status.as_str(), server, *dirs as i64, now, reason],
            )?;
            if *status != HostStatus::Paused {
                conn.execute("DELETE FROM candidates WHERE host = ?1", [host])?;
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

// ---------------------------------------------------------------------------
// Candidates: work still to do
// ---------------------------------------------------------------------------

/// Adds directory URLs to crawl for hosts never crawled before. Hosts already
/// in `hosts` are ignored, paused ones included: they continue from their
/// saved frontier instead.
pub fn add_candidates(conn: &Connection, urls: &[Url], source: &str) -> Result<()> {
    insert_candidates(conn, urls, source, unix_now())
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
        if let Some(host) = url.host_str() {
            stmt.execute(params![url.as_str(), host, source, now])?;
        }
    }
    Ok(())
}

/// Up to `want` hosts with work to do, oldest first, skipping `exclude` (hosts
/// already being crawled). Each comes with all its seed URLs. They are not
/// pruned to the shallowest: a site's `/` is often a homepage rather than a
/// listing, so `/pub/` must stay a seed. The crawler never fetches a URL twice.
pub fn pending_hosts(
    conn: &Connection,
    want: usize,
    exclude: &HashSet<String>,
) -> Result<Vec<(String, Vec<Url>)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT host, url FROM candidates WHERE host IN (
             SELECT c.host FROM candidates c
             WHERE NOT EXISTS (SELECT 1 FROM hosts h WHERE h.host = c.host AND h.status != 'paused')
             GROUP BY c.host ORDER BY min(c.found_at), c.host LIMIT ?1)
         ORDER BY host, length(url), url",
    )?;
    let limit = (want + exclude.len()) as i64;
    let rows: Vec<(String, String)> = stmt
        .query_map([limit], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut hosts: Vec<(String, Vec<Url>)> = Vec::new();
    for (host, raw) in rows {
        if exclude.contains(&host) {
            continue;
        }
        if hosts.last().is_none_or(|(h, _)| *h != host) {
            if hosts.len() == want {
                break;
            }
            hosts.push((host, Vec::new()));
        }
        if let (Ok(url), Some((_, seeds))) = (Url::parse(&raw), hosts.last_mut()) {
            seeds.push(url);
        }
    }
    Ok(hosts)
}

/// Drops every known host that is on the opt-out list: its entries and waiting
/// work are deleted and only the `opted_out` status is kept. Returns them.
pub fn apply_optout(conn: &Connection, optout: &[String]) -> Result<Vec<String>> {
    if !HONOR_OPT_OUT_LIST || optout.is_empty() {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT host FROM hosts WHERE status != 'opted_out'
         UNION SELECT host FROM candidates",
    )?;
    let hosts: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let dropped: Vec<String> = hosts
        .into_iter()
        .filter(|h| filters::host_opted_out(h, optout))
        .collect();
    for host in &dropped {
        let msg = Msg::HostDone {
            host: host.clone(),
            status: HostStatus::OptedOut,
            server: None,
            dirs: 0,
            reason: Some("on the opt-out list".into()),
            purge: true,
        };
        apply(conn, &msg)?;
    }
    Ok(dropped)
}

/// Removes everything known about a host (crawl result, entries, candidates),
/// so it can be crawled or re-checked from scratch. Returns false if unknown.
pub fn forget(conn: &Connection, host: &str) -> Result<bool> {
    let mut known = conn.execute("DELETE FROM hosts WHERE host = ?1", [host])? > 0;
    known |= conn.execute("DELETE FROM entries WHERE host = ?1", [host])? > 0;
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
    /// Only files with this extension (without the dot).
    pub ext: Option<String>,
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
        unfiltered,
        takedown,
        optout,
    } = opts;
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
        "SELECT e.url, e.name, e.is_dir, e.size, e.mtime
         FROM entries_fts
         JOIN entries e ON e.rowid = entries_fts.rowid
         WHERE entries_fts MATCH ?1
           AND (?2 IS NULL OR (e.is_dir = 0 AND substr(lower(e.name), -length(?2) - 1) = '.' || ?2))
           AND NOT hidden(e.url, e.name, e.host)
           AND NOT EXISTS (SELECT 1 FROM hosts h
                           WHERE h.host = e.host AND h.status IN ('opted_out', 'sensitive'))
         ORDER BY bm25(entries_fts, 10.0, 1.0)
         LIMIT ?3",
    )?;
    let ext = ext.map(|e| e.trim_start_matches('.').to_lowercase());
    let hits = stmt
        .query_map(params![fts_query, ext, limit as i64], |row| {
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
    fn upgrades_a_v1_database() {
        let path = temp_path("v1");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE hosts (host TEXT PRIMARY KEY, status TEXT NOT NULL, server TEXT,
                 dirs INTEGER NOT NULL DEFAULT 0, files INTEGER NOT NULL DEFAULT 0,
                 bytes INTEGER NOT NULL DEFAULT 0, crawled_at INTEGER NOT NULL);
                 INSERT INTO hosts VALUES ('old.example', 'sensitive', NULL, 1, 0, 0, 0);",
            )
            .unwrap();
        let conn = open(&path).unwrap();
        assert_eq!(
            sensitive_reasons(&conn).unwrap(),
            vec![("old.example".to_string(), "(not recorded)".to_string())]
        );
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
        };
        apply(&conn, &done).unwrap();

        let none = HashSet::new();
        let pending = pending_hosts(&conn, 10, &none).unwrap();
        let urls: Vec<String> = pending
            .iter()
            .flat_map(|(_, u)| u.iter().map(Url::to_string))
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
        assert_eq!(one[0].0, "a.example");
        let busy: HashSet<String> = ["a.example".to_string()].into();
        let others = pending_hosts(&conn, 10, &busy).unwrap();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].0, "b.example");

        // Candidates for a finished host are ignored.
        let late = [Url::parse("https://done.example/new/").unwrap()];
        add_candidates(&conn, &late, "link").unwrap();
        let hosts = pending_hosts(&conn, 10, &none).unwrap();
        assert!(hosts.iter().all(|(h, _)| h != "done.example"));
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
        };
        apply(&conn, &status).unwrap();

        let pending = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        let urls: Vec<&str> = pending[0].1.iter().map(Url::as_str).collect();
        assert_eq!(
            urls,
            vec!["https://m.example/pub/b/", "https://m.example/pub/c/"]
        );

        // Re-adding the seed (as `auto` does every night) must not restart the walk.
        add_candidates(&conn, &[url("https://m.example/pub/")], "seed").unwrap();
        let pending = pending_hosts(&conn, 10, &HashSet::new()).unwrap();
        assert_eq!(pending[0].1.len(), 2);

        // The next run finishes it; directory counts add up across runs.
        let done = Msg::HostDone {
            host: "m.example".into(),
            status: HostStatus::Done,
            server: None,
            dirs: 2,
            reason: None,
            purge: false,
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
