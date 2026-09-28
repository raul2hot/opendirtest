//! End-to-end: crawl a local fake server, then search the database.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opendirtest::crawler::{self, CrawlConfig, Stats};
use opendirtest::store::{self, SearchOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

type Routes = HashMap<String, (u16, &'static str, String)>;

/// Serves `routes` on 127.0.0.1 and records every requested path.
async fn serve(routes: Routes) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let requested = Arc::new(Mutex::new(Vec::new()));
    let log = requested.clone();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let routes = routes.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&buf);
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                log.lock().unwrap().push(path.clone());
                let (status, content_type, body) =
                    routes
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, "text/plain", "not found".into()));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, requested)
}

/// An nginx-style listing. Entries ending in `/` are directories.
fn listing(path: &str, entries: &[(&str, u64)]) -> (u16, &'static str, String) {
    let mut body = format!(
        "<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1><hr><pre><a href=\"../\">../</a>\n"
    );
    for (name, size) in entries {
        let size = if name.ends_with('/') {
            "-".to_string()
        } else {
            size.to_string()
        };
        body.push_str(&format!(
            "<a href=\"{name}\">{name}</a>                28-Sep-2026 10:15                {size}\n"
        ));
    }
    body.push_str("</pre><hr></body></html>");
    (200, "text/html", body)
}

fn temp_db(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("opendirtest-{name}-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

async fn run_crawl(seed: &Url, db: &Path) {
    let cfg = CrawlConfig {
        concurrency: 4,
        per_host_delay: Duration::from_millis(5),
        ..CrawlConfig::default()
    };
    let (tx, writer) = store::spawn_writer(db.to_path_buf()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    crawler::crawl(
        vec![seed.clone()],
        cfg,
        tx,
        stop,
        Arc::new(Stats::default()),
    )
    .await
    .unwrap();
    writer.join().unwrap().unwrap();
}

fn host_status(db: &Path) -> String {
    store::open(db)
        .unwrap()
        .query_row("SELECT status FROM hosts", [], |row| row.get(0))
        .unwrap()
}

fn search(db: &Path, query: &str, unfiltered: bool, takedown: Vec<String>) -> Vec<String> {
    let conn = store::open(db).unwrap();
    let opts = SearchOptions {
        limit: 50,
        ext: None,
        unfiltered,
        takedown,
    };
    store::search(&conn, query, opts)
        .unwrap()
        .into_iter()
        .map(|hit| hit.url)
        .collect()
}

#[tokio::test]
async fn crawls_indexes_and_searches() {
    let root = [
        ("pub/", 0),
        ("private/", 0),
        ("loop/", 0),
        ("readme.txt", 42),
    ];
    let routes: Routes = [
        (
            "/robots.txt".to_string(),
            (
                200,
                "text/plain",
                "User-agent: *\nDisallow: /private/\n".to_string(),
            ),
        ),
        ("/".into(), listing("/", &root)),
        // A symlink back to the root: same content, must not be crawled again.
        ("/loop/".into(), listing("/loop/", &root)),
        (
            "/pub/".into(),
            listing(
                "/pub/",
                &[
                    ("deep/", 0),
                    ("ubuntu-24.04-desktop-amd64.iso", 6_000_000_000),
                    ("Show.S01E02.1080p.WEB-DL-NTb.mkv", 1_500_000_000),
                ],
            ),
        ),
        (
            "/pub/deep/".into(),
            listing("/pub/deep/", &[("stations.csv", 1234)]),
        ),
        (
            "/private/".into(),
            listing("/private/", &[("secret.txt", 1)]),
        ),
    ]
    .into_iter()
    .collect();
    let (base, requested) = serve(routes).await;
    let db = temp_db("crawl");

    run_crawl(&base, &db).await;

    let requested = requested.lock().unwrap().clone();
    assert_eq!(requested[0], "/robots.txt", "robots.txt must come first");
    assert!(
        !requested.iter().any(|p| p.starts_with("/private/")),
        "robots.txt ignored: {requested:?}"
    );
    assert!(
        !requested.iter().any(|p| p.starts_with("/loop/pub")),
        "loop followed: {requested:?}"
    );
    assert!(
        !requested.iter().any(|p| p.ends_with(".iso")),
        "a file was downloaded: {requested:?}"
    );
    assert!(requested.contains(&"/pub/deep/".to_string()));
    assert_eq!(host_status(&db), "done");

    let iso = format!("{base}pub/ubuntu-24.04-desktop-amd64.iso");
    assert_eq!(search(&db, "ubuntu iso", false, vec![]), vec![iso.clone()]);
    assert_eq!(
        search(&db, "stations", false, vec![]),
        vec![format!("{base}pub/deep/stations.csv")]
    );

    // Likely infringement is hidden at search time, but was still indexed.
    assert!(search(&db, "S01E02", false, vec![]).is_empty());
    assert_eq!(search(&db, "S01E02", true, vec![]).len(), 1);

    // The takedown list hides a URL prefix.
    assert!(search(&db, "ubuntu", false, vec![format!("{base}pub/")]).is_empty());
}

#[tokio::test]
async fn drops_hosts_with_sensitive_files() {
    let routes: Routes = [
        (
            "/".to_string(),
            listing("/", &[("site/", 0), ("notes.txt", 5)]),
        ),
        (
            "/site/".into(),
            listing("/site/", &[(".env", 120), ("index.php", 900)]),
        ),
    ]
    .into_iter()
    .collect();
    let (base, _) = serve(routes).await;
    let db = temp_db("sensitive");

    run_crawl(&base, &db).await;

    assert_eq!(host_status(&db), "sensitive");
    let rows: i64 = store::open(&db)
        .unwrap()
        .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        rows, 0,
        "entries stored before the leak was found must be purged"
    );
    assert_eq!(
        store::sensitive_hosts(&store::open(&db).unwrap()).unwrap(),
        vec!["127.0.0.1"]
    );
}

#[tokio::test]
async fn respects_robots_disallow_for_our_bot() {
    let routes: Routes = [
        (
            "/robots.txt".to_string(),
            (
                200,
                "text/plain",
                "User-agent: opendirtest\nDisallow: /\n".to_string(),
            ),
        ),
        ("/".into(), listing("/", &[("a.txt", 1)])),
    ]
    .into_iter()
    .collect();
    let (base, requested) = serve(routes).await;
    let db = temp_db("robots");

    run_crawl(&base, &db).await;

    assert_eq!(*requested.lock().unwrap(), vec!["/robots.txt"]);
    assert_eq!(host_status(&db), "robots_disallowed");
}

#[tokio::test]
async fn robots_server_error_means_stay_out() {
    let routes: Routes = [
        (
            "/robots.txt".to_string(),
            (500, "text/plain", "oops".to_string()),
        ),
        ("/".into(), listing("/", &[("a.txt", 1)])),
    ]
    .into_iter()
    .collect();
    let (base, requested) = serve(routes).await;
    let db = temp_db("robots5xx");

    run_crawl(&base, &db).await;

    assert_eq!(*requested.lock().unwrap(), vec!["/robots.txt"]);
    assert_eq!(host_status(&db), "robots_disallowed");
}
