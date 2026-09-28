//! SQLite storage: one file holds the entries, per-host crawl results, a
//! full-text index (FTS5) over file names and directory paths, and the
//! discovery candidates waiting to be crawled.
//!
//! The crawler never touches SQLite directly. It sends messages to a single
//! writer thread, which batches them into transactions.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use percent_encoding::percent_decode_str;
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, params};
use tokio::sync::mpsc;
use url::Url;

use crate::filters;
use crate::listing::Entry;
use crate::safety::HONOR_TAKEDOWN_LIST;

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

-- Directory URLs found by discovery. A host is pending until it appears in `hosts`.
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
    /// Stopped early: directory budget reached, Ctrl-C, or too many errors.
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
    /// Deletes everything stored for a host (sensitive exposure found).
    Purge {
        host: String,
    },
    HostDone {
        host: String,
        status: HostStatus,
        server: Option<String>,
        dirs: u64,
        /// Why the host was skipped or dropped, e.g. the file that looked sensitive.
        reason: Option<String>,
    },
    /// Directory URLs worth crawling later. Already-known URLs are ignored.
    Candidates {
        urls: Vec<Url>,
        source: String,
    },
    /// A Common Crawl index file has been fully scanned.
    CcFileDone {
        path: String,
        candidates: u64,
    },
}

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
            let txn = conn.transaction()?;
            // A failing statement only undoes itself; log it and keep the rest of the batch.
            let mut next = Some(first);
            let mut batched = 0;
            while let Some(msg) = next.take() {
                if let Err(e) = apply(&txn, msg) {
                    eprintln!("database: skipped one update: {e:#}");
                }
                batched += 1;
                // Batch whatever else is already queued into the same transaction.
                if batched < 10_000 {
                    next = rx.try_recv().ok();
                }
            }
            txn.commit().context("committing to the database")?;
        }
        Ok(())
    });
    Ok((tx, handle))
}

fn apply(conn: &Connection, msg: Msg) -> Result<()> {
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
        Msg::Purge { host } => {
            conn.execute("DELETE FROM entries WHERE host = ?1", [&host])?;
        }
        Msg::HostDone {
            host,
            status,
            server,
            dirs,
            reason,
        } => {
            conn.execute(
                "INSERT INTO hosts (host, status, server, dirs, files, bytes, crawled_at, reason)
                 SELECT ?1, ?2, ?3, ?4, count(*), CAST(total(size) AS INTEGER), ?5, ?6
                 FROM entries WHERE host = ?1 AND is_dir = 0
                 ON CONFLICT(host) DO UPDATE SET
                    status = excluded.status, server = coalesce(excluded.server, hosts.server),
                    dirs = excluded.dirs, files = excluded.files, bytes = excluded.bytes,
                    crawled_at = excluded.crawled_at, reason = excluded.reason",
                params![host, status.as_str(), server, dirs as i64, now, reason],
            )?;
        }
        Msg::Candidates { urls, source } => {
            let mut stmt = conn.prepare_cached(
                "INSERT OR IGNORE INTO candidates (url, host, source, found_at)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for url in urls {
                if let Some(host) = url.host_str() {
                    stmt.execute(params![url.as_str(), host, source, now])?;
                }
            }
        }
        Msg::CcFileDone { path, candidates } => {
            conn.execute(
                "INSERT OR REPLACE INTO cc_files (path, candidates, done_at) VALUES (?1, ?2, ?3)",
                params![path, candidates as i64, now],
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery candidates
// ---------------------------------------------------------------------------

/// Seed URLs for up to `max_hosts` hosts that have candidates but were never
/// crawled, oldest first. Within a host, a URL is dropped when one of its
/// ancestor directories is also a candidate, since the crawl reaches it anyway.
pub fn pending_candidates(conn: &Connection, max_hosts: usize) -> Result<Vec<Url>> {
    let mut stmt = conn.prepare(
        "SELECT url FROM candidates WHERE host IN (
             SELECT host FROM candidates
             WHERE host NOT IN (SELECT host FROM hosts)
             GROUP BY host ORDER BY min(found_at), host LIMIT ?1)
         ORDER BY host, length(url), url",
    )?;
    let urls: Vec<String> = stmt
        .query_map([max_hosts as i64], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;

    let mut seeds: Vec<Url> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    let mut current_host = String::new();
    for raw in urls {
        let Ok(url) = Url::parse(&raw) else { continue };
        let host = url.host_str().unwrap_or("").to_string();
        if host != current_host {
            kept.clear();
            current_host = host;
        }
        // Shorter URLs come first, so any ancestor is already in `kept`.
        if !kept
            .iter()
            .any(|ancestor| raw.starts_with(ancestor.as_str()))
        {
            kept.push(raw);
            seeds.push(url);
        }
    }
    Ok(seeds)
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
    } = opts;
    conn.create_scalar_function(
        "hidden",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let url = ctx.get_raw(0).as_str().unwrap_or("");
            let name = ctx.get_raw(1).as_str().unwrap_or("");
            let taken_down = HONOR_TAKEDOWN_LIST && filters::url_taken_down(url, &takedown);
            Ok(taken_down || (!unfiltered && filters::is_likely_infringing(name)))
        },
    )?;

    let mut stmt = conn.prepare(
        "SELECT e.url, e.name, e.is_dir, e.size, e.mtime
         FROM entries_fts
         JOIN entries e ON e.rowid = entries_fts.rowid
         WHERE entries_fts MATCH ?1
           AND (?2 IS NULL OR (e.is_dir = 0 AND substr(lower(e.name), -length(?2) - 1) = '.' || ?2))
           AND NOT hidden(e.url, e.name)
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

pub struct CandidateCount {
    pub source: String,
    pub urls: u64,
    pub hosts: u64,
    pub pending_hosts: u64,
}

pub fn candidate_stats(conn: &Connection) -> Result<Vec<CandidateCount>> {
    let mut stmt = conn.prepare(
        "SELECT source, count(*), count(DISTINCT host),
                count(DISTINCT CASE WHEN host NOT IN (SELECT host FROM hosts) THEN host END)
         FROM candidates GROUP BY source ORDER BY source",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(CandidateCount {
                source: row.get(0)?,
                urls: row.get::<_, i64>(1)? as u64,
                hosts: row.get::<_, i64>(2)? as u64,
                pending_hosts: row.get::<_, i64>(3)? as u64,
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
    fn pending_candidates_skip_crawled_hosts_and_covered_dirs() {
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
            Msg::Candidates {
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
        };
        apply(&conn, done).unwrap();

        let pending: Vec<String> = pending_candidates(&conn, 10)
            .unwrap()
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            pending,
            vec![
                "https://a.example/pub/",
                "https://a.example/data/",
                "https://b.example/files/"
            ]
        );
        assert_eq!(
            pending_candidates(&conn, 1).unwrap().len(),
            2,
            "one host: a.example"
        );
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
