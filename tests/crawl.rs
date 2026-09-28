//! End-to-end: crawl local fake servers, then check what was requested and stored.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Route, listing, query_one, serve, temp_db};
use opendirtest::crawler::{self, CrawlConfig, Stats};
use opendirtest::store::{self, SearchOptions};
use tokio_util::sync::CancellationToken;
use url::Url;

fn routes(list: Vec<(&str, Route)>) -> HashMap<String, Route> {
    list.into_iter().map(|(p, r)| (p.to_string(), r)).collect()
}

fn fast_config() -> CrawlConfig {
    CrawlConfig {
        concurrency: 4,
        per_host_delay: Duration::from_millis(5),
        ..CrawlConfig::default()
    }
}

async fn run_crawl(seeds: Vec<Url>, db: &Path, cfg: CrawlConfig) {
    run_crawl_with_stop(seeds, db, cfg, CancellationToken::new()).await
}

async fn run_crawl_with_stop(
    seeds: Vec<Url>,
    db: &Path,
    cfg: CrawlConfig,
    stop: CancellationToken,
) {
    let (tx, writer) = store::spawn_writer(db.to_path_buf()).unwrap();
    crawler::crawl(seeds, cfg, tx, stop, Arc::new(Stats::default()))
        .await
        .unwrap();
    writer.join().unwrap().unwrap();
}

fn host_status(db: &Path, host: &str) -> String {
    query_one(
        db,
        &format!("SELECT status FROM hosts WHERE host = '{host}'"),
    )
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
    let server = serve(routes(vec![
        (
            "/robots.txt",
            Route::text(200, "User-agent: *\nDisallow: /private/\n"),
        ),
        ("/", listing("/", &root)),
        // A symlink back to the root: same content, must not be walked again.
        ("/loop/", listing("/loop/", &root)),
        (
            "/pub/",
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
            "/pub/deep/",
            listing("/pub/deep/", &[("stations.csv", 1234)]),
        ),
        ("/private/", listing("/private/", &[("secret.txt", 1)])),
    ]))
    .await;
    let base = server.base.clone();
    let db = temp_db("crawl");

    run_crawl(vec![base.clone()], &db, fast_config()).await;

    let requested = server.requested();
    assert_eq!(requested[0], "/robots.txt", "robots.txt must come first");
    assert!(
        !requested.iter().any(|p| p.starts_with("/private/")),
        "{requested:?}"
    );
    assert!(
        !requested.iter().any(|p| p.starts_with("/loop/pub")),
        "{requested:?}"
    );
    assert!(
        !requested.iter().any(|p| p.ends_with(".iso")),
        "{requested:?}"
    );
    assert!(requested.contains(&"/pub/deep/".to_string()));
    assert_eq!(host_status(&db, "127.0.0.1"), "done");

    let iso = format!("{base}pub/ubuntu-24.04-desktop-amd64.iso");
    assert_eq!(search(&db, "ubuntu iso", false, vec![]), vec![iso]);
    let csv = format!("{base}pub/deep/stations.csv");
    assert_eq!(search(&db, "stations", false, vec![]), vec![csv]);

    // Likely infringement is hidden at search time, but was still indexed.
    assert!(search(&db, "S01E02", false, vec![]).is_empty());
    assert_eq!(search(&db, "S01E02", true, vec![]).len(), 1);

    // The takedown list hides a URL prefix.
    assert!(search(&db, "ubuntu", false, vec![format!("{base}pub/")]).is_empty());
}

#[tokio::test]
async fn drops_hosts_with_sensitive_files_and_says_why() {
    let server = serve(routes(vec![
        ("/", listing("/", &[("site/", 0), ("notes.txt", 5)])),
        (
            "/site/",
            listing("/site/", &[(".env", 120), ("index.php", 900)]),
        ),
    ]))
    .await;
    let db = temp_db("sensitive");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    assert_eq!(host_status(&db, "127.0.0.1"), "sensitive");
    let rows: i64 = query_one(&db, "SELECT count(*) FROM entries");
    assert_eq!(
        rows, 0,
        "entries stored before the leak was found must be purged"
    );
    let reason: String = query_one(&db, "SELECT reason FROM hosts");
    assert!(reason.ends_with("/site/.env"), "{reason}");
    let conn = store::open(&db).unwrap();
    assert_eq!(store::sensitive_hosts(&conn).unwrap(), vec!["127.0.0.1"]);
}

#[tokio::test]
async fn respects_robots_disallow_for_our_bot() {
    let server = serve(routes(vec![
        (
            "/robots.txt",
            Route::text(200, "User-agent: opendirtest\nDisallow: /\n"),
        ),
        ("/", listing("/", &[("a.txt", 1)])),
    ]))
    .await;
    let db = temp_db("robots");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    assert_eq!(server.requested(), vec!["/robots.txt"]);
    assert_eq!(host_status(&db, "127.0.0.1"), "robots_disallowed");
}

#[tokio::test]
async fn robots_server_error_means_stay_out() {
    let server = serve(routes(vec![
        ("/robots.txt", Route::text(500, "oops")),
        ("/", listing("/", &[("a.txt", 1)])),
    ]))
    .await;
    let db = temp_db("robots5xx");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    assert_eq!(server.requested(), vec!["/robots.txt"]);
    assert_eq!(host_status(&db, "127.0.0.1"), "robots_disallowed");
}

#[tokio::test]
async fn redirects_are_checked_against_robots() {
    let server = serve(routes(vec![
        (
            "/robots.txt",
            Route::text(200, "User-agent: *\nDisallow: /private/\n"),
        ),
        ("/", listing("/", &[("pub/", 0), ("ok.txt", 1)])),
        ("/pub/", Route::redirect("/private/")),
        ("/private/", listing("/private/", &[("secret.txt", 1)])),
    ]))
    .await;
    let db = temp_db("redirect-robots");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    let requested = server.requested();
    assert!(
        !requested.contains(&"/private/".to_string()),
        "{requested:?}"
    );
    assert!(search(&db, "secret", true, vec![]).is_empty());
}

#[tokio::test]
async fn each_origin_gets_its_own_robots_txt() {
    let open = serve(routes(vec![("/", listing("/", &[("a.txt", 1)]))])).await;
    let closed = serve(routes(vec![
        (
            "/robots.txt",
            Route::text(200, "User-agent: *\nDisallow: /\n"),
        ),
        ("/", listing("/", &[("b-secret.txt", 1)])),
    ]))
    .await;
    let db = temp_db("per-origin");

    // Same host name (127.0.0.1), different ports: one crawl task, two origins.
    run_crawl(
        vec![open.base.clone(), closed.base.clone()],
        &db,
        fast_config(),
    )
    .await;

    assert_eq!(closed.requested(), vec!["/robots.txt"]);
    assert!(search(&db, "secret", true, vec![]).is_empty());
    assert_eq!(search(&db, "a txt", true, vec![]).len(), 1);
}

#[tokio::test]
async fn robots_redirect_to_another_host_is_followed() {
    let rules = serve(routes(vec![(
        "/robots.txt",
        Route::text(200, "User-agent: *\nDisallow: /\n"),
    )]))
    .await;
    let target = format!("{}robots.txt", rules.as_localhost());
    let site = serve(routes(vec![
        ("/robots.txt", Route::redirect(&target)),
        ("/", listing("/", &[("a.txt", 1)])),
    ]))
    .await;
    let db = temp_db("robots-redirect");

    run_crawl(vec![site.base.clone()], &db, fast_config()).await;

    assert_eq!(site.requested(), vec!["/robots.txt"]);
    assert_eq!(rules.requested(), vec!["/robots.txt"]);
    assert_eq!(host_status(&db, "127.0.0.1"), "robots_disallowed");
}

#[tokio::test]
async fn responses_without_content_type_are_not_read() {
    let body = listing("/", &[("a.txt", 1)]).body;
    let server = serve(routes(vec![("/", Route::new(200, None, body))])).await;
    let db = temp_db("no-content-type");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    assert_eq!(host_status(&db, "127.0.0.1"), "not_listing");
    let rows: i64 = query_one(&db, "SELECT count(*) FROM entries");
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn stop_interrupts_back_off() {
    let server = serve(routes(vec![(
        "/",
        Route::text(503, "busy").header("Retry-After", "60"),
    )]))
    .await;
    let db = temp_db("stop");
    let stop = CancellationToken::new();
    let canceller = stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        canceller.cancel();
    });

    let started = Instant::now();
    run_crawl_with_stop(vec![server.base.clone()], &db, fast_config(), stop).await;

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // Stopped before anything was found: not recorded, so it stays pending.
    let hosts: i64 = query_one(&db, "SELECT count(*) FROM hosts");
    assert_eq!(hosts, 0);
}

#[tokio::test]
async fn queue_is_bounded_by_the_directory_budget() {
    let dirs: Vec<String> = (0..50).map(|i| format!("d{i}/")).collect();
    let entries: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let server = serve(routes(vec![("/", listing("/", &entries))])).await;
    let db = temp_db("budget");
    let cfg = CrawlConfig {
        max_dirs_per_host: 3,
        ..fast_config()
    };

    run_crawl(vec![server.base.clone()], &db, cfg).await;

    let requested = server.requested();
    assert!(
        requested.len() <= 4,
        "robots.txt + 3 dirs, got {requested:?}"
    );
    assert_eq!(host_status(&db, "127.0.0.1"), "partial");
    let reason: String = query_one(&db, "SELECT reason FROM hosts");
    assert_eq!(reason, "directory budget reached");
}

#[tokio::test]
async fn names_only_listings_with_the_same_names_are_both_indexed() {
    let python = |path: &str, names: &[&str]| {
        let items: String = names
            .iter()
            .map(|n| format!("<li><a href=\"{n}\">{n}</a></li>\n"))
            .collect();
        let body = format!("<title>Directory listing for {path}</title><ul>{items}</ul>");
        Route::new(200, Some("text/html"), body)
    };
    let server = serve(routes(vec![
        ("/", python("/", &["p1/", "p2/"])),
        ("/p1/", python("/p1/", &["src/", "README.md"])),
        ("/p2/", python("/p2/", &["src/", "README.md"])),
        ("/p1/src/", python("/p1/src/", &["main.rs"])),
        ("/p2/src/", python("/p2/src/", &["lib.rs"])),
    ]))
    .await;
    let db = temp_db("names-only");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    assert!(server.requested().contains(&"/p2/src/".to_string()));
    assert_eq!(search(&db, "README", true, vec![]).len(), 2);
    assert_eq!(search(&db, "lib rs", true, vec![]).len(), 1);
}

#[tokio::test]
async fn links_to_other_sites_become_candidates_and_get_crawled() {
    let mirror = serve(routes(vec![
        ("/pub/", listing("/pub/", &[("mirror-file.tar.gz", 10)])),
        ("/data/", listing("/data/", &[("dataset.csv", 10)])),
    ]))
    .await;
    let mirror_pub = format!("{}pub/", mirror.as_localhost());
    let mirror_data = format!("{}data/", mirror.as_localhost());
    let header = format!(
        "<html><head><title>Index of /</title></head><body><h1>Index of /</h1>\
         <p>Also on <a href=\"{mirror_pub}\">our mirror</a>.</p><pre>\
         <a href=\"moved/\">moved/</a>   28-Sep-2026 10:15    -\n</pre></body></html>"
    );
    let site = serve(routes(vec![
        ("/", Route::new(200, Some("text/html"), header)),
        ("/moved/", Route::redirect(&mirror_data)),
    ]))
    .await;
    let db = temp_db("links");

    run_crawl(vec![site.base.clone()], &db, fast_config()).await;

    // Nothing was sent to the mirror yet: its URLs are only recorded.
    assert!(mirror.requested().is_empty());
    let conn = store::open(&db).unwrap();
    let mut pending: Vec<String> = store::pending_candidates(&conn, 10)
        .unwrap()
        .into_iter()
        .map(String::from)
        .collect();
    pending.sort();
    assert_eq!(pending, vec![mirror_data.clone(), mirror_pub.clone()]);
    drop(conn);

    let seeds = pending.iter().map(|u| Url::parse(u).unwrap()).collect();
    run_crawl(seeds, &db, fast_config()).await;

    assert_eq!(host_status(&db, "localhost"), "done");
    assert_eq!(search(&db, "mirror file", true, vec![]).len(), 1);
    assert_eq!(search(&db, "dataset", true, vec![]).len(), 1);
    let conn = store::open(&db).unwrap();
    assert!(store::pending_candidates(&conn, 10).unwrap().is_empty());
}
