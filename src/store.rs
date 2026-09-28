//! SQLite storage: one file holds the entries, per-host crawl results and a
//! full-text index (FTS5) over file names and directory paths.
//!
//! The crawler never touches SQLite directly. It sends messages to a single
//! writer thread, which batches them into transactions.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use percent_encoding::percent_decode_str;
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, params};
use tokio::sync::mpsc;

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
    crawled_at INTEGER NOT NULL
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
    },
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
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
            apply(&txn, first)?;
            // Batch whatever else is already queued into the same transaction.
            for _ in 0..10_000 {
                match rx.try_recv() {
                    Ok(msg) => apply(&txn, msg)?,
                    Err(_) => break,
                }
            }
            txn.commit()?;
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
        } => {
            conn.execute(
                "INSERT INTO hosts (host, status, server, dirs, files, bytes, crawled_at)
                 SELECT ?1, ?2, ?3, ?4, count(*), coalesce(sum(size), 0), ?5
                 FROM entries WHERE host = ?1 AND is_dir = 0
                 ON CONFLICT(host) DO UPDATE SET
                    status = excluded.status, server = coalesce(excluded.server, hosts.server),
                    dirs = excluded.dirs, files = excluded.files, bytes = excluded.bytes,
                    crawled_at = excluded.crawled_at",
                params![host, status.as_str(), server, dirs as i64, now],
            )?;
        }
    }
    Ok(())
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
           AND (?2 IS NULL OR (e.is_dir = 0 AND lower(e.name) LIKE '%.' || lower(?2)))
           AND NOT hidden(e.url, e.name)
         ORDER BY bm25(entries_fts, 10.0, 1.0)
         LIMIT ?3",
    )?;
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

pub fn stats(conn: &Connection) -> Result<Vec<StatusCount>> {
    let mut stmt = conn.prepare(
        "SELECT status, count(*), sum(files), sum(bytes) FROM hosts
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
