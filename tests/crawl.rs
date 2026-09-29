//! End-to-end: crawl local fake servers, then check what was requested and stored.

mod common;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Route, listing, query_one, serve, serve_with, temp_db};
use opendirtest::crawler::{self, CrawlConfig, Pending, Stats};
use opendirtest::quality::Thresholds;
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
        // The test servers live on localhost.
        allow_private_links: true,
        // The tiny test listings would not pass the quality check; tests of the
        // check turn it back on.
        quality: Thresholds::OFF,
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
    run(seeds, None, db, cfg, stop).await
}

/// Crawls `seeds` plus everything waiting in the database, like `crawl --candidates`.
async fn run_with_pending(seeds: Vec<Url>, db: &Path, cfg: CrawlConfig) {
    let pending = Pending {
        db: db.to_path_buf(),
        max_hosts: None,
    };
    run(seeds, Some(pending), db, cfg, CancellationToken::new()).await
}

async fn run(
    seeds: Vec<Url>,
    pending: Option<Pending>,
    db: &Path,
    cfg: CrawlConfig,
    stop: CancellationToken,
) {
    // The sites you name are recorded as seeds first, like the real command does.
    let named = store::named_sites(&store::open(db).unwrap(), &seeds).unwrap();
    let (tx, writer) = store::spawn_writer(db.to_path_buf()).unwrap();
    crawler::crawl(named, pending, cfg, tx, stop, Arc::new(Stats::default()))
        .await
        .unwrap();
    writer.join().unwrap().unwrap();
}

fn pending_urls(db: &Path) -> Vec<String> {
    let conn = store::open(db).unwrap();
    let mut urls: Vec<String> = store::pending_hosts(&conn, 100, &Default::default())
        .unwrap()
        .into_iter()
        .flat_map(|h| h.urls.into_iter().map(String::from))
        .collect();
    urls.sort();
    urls
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
        min_bytes: None,
        unfiltered,
        takedown,
        optout: vec![],
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
async fn budget_pauses_the_site_and_the_next_run_continues() {
    let dirs: Vec<String> = (0..8).map(|i| format!("d{i}/")).collect();
    let mut list = vec![(
        "/",
        listing(
            "/",
            &dirs.iter().map(|d| (d.as_str(), 0)).collect::<Vec<_>>(),
        ),
    )];
    let pages: Vec<(String, Route)> = (0..8)
        .map(|i| {
            (
                format!("/d{i}/"),
                listing(&format!("/d{i}/"), &[(&format!("f{i}.txt"), 1)]),
            )
        })
        .collect();
    list.extend(pages.iter().map(|(p, r)| (p.as_str(), r.clone())));
    let server = serve(routes(list)).await;
    let db = temp_db("budget");
    let cfg = || CrawlConfig {
        max_dirs_per_host: 3,
        ..fast_config()
    };

    // Run 1: the root plus two directories, then the budget is used up. The
    // queue is capped at the budget; the rest is saved in the database.
    run_crawl(vec![server.base.clone()], &db, cfg()).await;
    assert_eq!(server.requested().len(), 4, "robots.txt + 3 listings");
    assert_eq!(host_status(&db, "127.0.0.1"), "paused");
    let reason: String = query_one(&db, "SELECT reason FROM hosts");
    assert!(reason.contains("continues next run"), "{reason}");
    assert_eq!(pending_urls(&db).len(), 6);

    // Runs 2 and 3 continue where the last one stopped; nothing is fetched twice.
    run_with_pending(vec![], &db, cfg()).await;
    run_with_pending(vec![], &db, cfg()).await;
    let listings: Vec<String> = server
        .requested()
        .into_iter()
        .filter(|p| p != "/robots.txt")
        .collect();
    let unique: std::collections::HashSet<_> = listings.iter().collect();
    assert_eq!(listings.len(), 9, "{listings:?}");
    assert_eq!(unique.len(), 9, "fetched twice: {listings:?}");
    assert_eq!(host_status(&db, "127.0.0.1"), "done");
    assert!(pending_urls(&db).is_empty());
    assert_eq!(search(&db, "txt", true, vec![]).len(), 8);
}

#[tokio::test]
async fn stopping_saves_the_rest_for_the_next_run() {
    let server = serve(routes(vec![
        ("/", listing("/", &[("a/", 0), ("b/", 0), ("c/", 0)])),
        ("/a/", listing("/a/", &[("a.txt", 1)])),
        ("/b/", listing("/b/", &[("b.txt", 1)])),
        ("/c/", listing("/c/", &[("c.txt", 1)])),
    ]))
    .await;
    let db = temp_db("resume");
    // Slow pacing, so the stop lands in the middle of the crawl.
    let cfg = || CrawlConfig {
        per_host_delay: Duration::from_millis(300),
        ..fast_config()
    };
    let stop = CancellationToken::new();
    let canceller = stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(750)).await;
        canceller.cancel();
    });

    run_crawl_with_stop(vec![server.base.clone()], &db, cfg(), stop).await;

    assert_eq!(host_status(&db, "127.0.0.1"), "paused");
    let first_run = server.requested().len();
    assert!(first_run < 5, "{:?}", server.requested());

    run_with_pending(vec![], &db, cfg()).await;
    let listings: Vec<String> = server
        .requested()
        .into_iter()
        .filter(|p| p != "/robots.txt")
        .collect();
    let unique: std::collections::HashSet<_> = listings.iter().collect();
    assert_eq!(unique.len(), listings.len(), "fetched twice: {listings:?}");
    assert_eq!(unique.len(), 4);
    assert_eq!(host_status(&db, "127.0.0.1"), "done");
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
async fn links_to_other_sites_are_crawled_in_the_same_run() {
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

    // Plain crawl: the mirror is only recorded, not contacted.
    let db = temp_db("links");
    run_crawl(vec![site.base.clone()], &db, fast_config()).await;
    assert!(mirror.requested().is_empty());
    assert_eq!(
        pending_urls(&db),
        vec![mirror_data.clone(), mirror_pub.clone()]
    );

    // With pending sites included, the mirror found mid-run is crawled in the same run.
    let db = temp_db("links-same-run");
    run_with_pending(vec![site.base.clone()], &db, fast_config()).await;
    assert_eq!(host_status(&db, "localhost"), "done");
    assert_eq!(search(&db, "mirror file", true, vec![]).len(), 1);
    assert_eq!(search(&db, "dataset", true, vec![]).len(), 1);
    assert!(pending_urls(&db).is_empty());
}

#[tokio::test]
async fn a_homepage_candidate_does_not_hide_a_listing_below_it() {
    let server = serve(routes(vec![
        (
            "/",
            Route::new(200, Some("text/html"), "<title>Welcome</title>"),
        ),
        ("/pub/", listing("/pub/", &[("tool.tar.gz", 10)])),
    ]))
    .await;
    let db = temp_db("homepage");
    let conn = store::open(&db).unwrap();
    let seeds = [server.base.clone(), server.base.join("pub/").unwrap()];
    store::add_candidates(&conn, &seeds, "link").unwrap();
    drop(conn);

    run_with_pending(vec![], &db, fast_config()).await;

    assert!(server.requested().contains(&"/pub/".to_string()));
    assert_eq!(search(&db, "tool", true, vec![]).len(), 1);
    assert_eq!(host_status(&db, "127.0.0.1"), "done");
}

#[tokio::test]
async fn links_to_private_networks_are_not_recorded() {
    let body = "<title>Index of /</title><pre>\
        <a href=\"http://192.168.1.1/admin/\">router</a>\
        <a href=\"http://nas.local/share/\">nas</a>\
        <a href=\"https://mirror.example.org/pub/\">mirror</a>\n</pre>";
    let server = serve(routes(vec![(
        "/",
        Route::new(200, Some("text/html"), body),
    )]))
    .await;
    let db = temp_db("private-links");
    let cfg = CrawlConfig {
        allow_private_links: false,
        ..fast_config()
    };

    run_crawl(vec![server.base.clone()], &db, cfg).await;

    assert_eq!(pending_urls(&db), vec!["https://mirror.example.org/pub/"]);
}

#[tokio::test]
async fn opting_out_removes_what_was_already_indexed() {
    let server = serve(routes(vec![("/", listing("/", &[("report.pdf", 10)]))])).await;
    let db = temp_db("optout");
    run_crawl(vec![server.base.clone()], &db, fast_config()).await;
    assert_eq!(search(&db, "report", true, vec![]).len(), 1);

    // Hidden from search as soon as the owner is on the list...
    let conn = store::open(&db).unwrap();
    let optout = vec!["127.0.0.1".to_string()];
    let opts = SearchOptions {
        limit: 10,
        ext: None,
        min_bytes: None,
        unfiltered: true,
        takedown: vec![],
        optout: optout.clone(),
    };
    assert!(store::search(&conn, "report", opts).unwrap().is_empty());

    // ...and deleted when the next crawl starts, keeping only the status.
    assert_eq!(
        store::apply_optout(&conn, &optout).unwrap(),
        vec!["127.0.0.1"]
    );
    drop(conn);
    assert_eq!(host_status(&db, "127.0.0.1"), "opted_out");
    let rows: i64 = query_one(&db, "SELECT count(*) FROM entries");
    assert_eq!(rows, 0);

    // A crawl of an opted-out site sends nothing and stores nothing.
    let before = server.requested().len();
    let cfg = CrawlConfig {
        optout,
        ..fast_config()
    };
    run_crawl(vec![server.base.clone()], &db, cfg).await;
    assert_eq!(server.requested().len(), before);
}

#[tokio::test]
async fn the_writer_waits_for_another_program_holding_the_database() {
    let server = serve(routes(vec![
        ("/", listing("/", &[("sub/", 0), ("a.txt", 1)])),
        ("/sub/", listing("/sub/", &[("b.txt", 1)])),
    ]))
    .await;
    let db = temp_db("locked");
    drop(store::open(&db).unwrap());

    // Another program takes the write lock for a while, like a DB browser with
    // unsaved edits. The crawl must wait for it, not drop its updates.
    let other = rusqlite::Connection::open(&db).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let holder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1500));
        other.execute_batch("COMMIT").unwrap();
    });

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;
    holder.join().unwrap();

    assert_eq!(host_status(&db, "127.0.0.1"), "done");
    assert_eq!(search(&db, "txt", true, vec![]).len(), 2);
}

#[tokio::test]
async fn skipped_folders_and_sites_are_not_crawled() {
    let server = serve(routes(vec![
        ("/", listing("/", &[("ubuntu/", 0), ("notes.txt", 1)])),
        (
            "/ubuntu/",
            listing("/ubuntu/", &[("pool/", 0), ("releases/", 0)]),
        ),
        ("/ubuntu/pool/", listing("/ubuntu/pool/", &[("main/", 0)])),
        (
            "/ubuntu/releases/",
            listing("/ubuntu/releases/", &[("desktop.iso", 5)]),
        ),
    ]))
    .await;
    let db = temp_db("skip");
    let lines = vec!["/pool/".to_string()];
    let cfg = CrawlConfig {
        skip: opendirtest::filters::SkipList::from_lines(&lines),
        ..fast_config()
    };

    run_crawl(vec![server.base.clone()], &db, cfg).await;

    let requested = server.requested();
    assert!(
        !requested.iter().any(|p| p.contains("/pool/")),
        "{requested:?}"
    );
    assert_eq!(search(&db, "desktop iso", true, vec![]).len(), 1);
    assert_eq!(host_status(&db, "127.0.0.1"), "done");

    // Putting the site itself on the skip list drops what was stored.
    let lines = vec!["127.0.0.1".to_string()];
    let skip = opendirtest::filters::SkipList::from_lines(&lines);
    let conn = store::open(&db).unwrap();
    let (hosts, _) = store::apply_skip_list(&conn, &skip).unwrap();
    assert_eq!(hosts, vec!["127.0.0.1"]);
    drop(conn);
    assert_eq!(host_status(&db, "127.0.0.1"), "skipped");
    assert!(search(&db, "desktop", true, vec![]).is_empty());
    let before = server.requested().len();
    let cfg = CrawlConfig {
        skip,
        ..fast_config()
    };
    run_crawl(vec![server.base.clone()], &db, cfg).await;
    assert_eq!(
        server.requested().len(),
        before,
        "a skipped site gets no requests"
    );
}

#[tokio::test]
async fn skip_list_cleans_up_folders_stored_before_it_was_added() {
    let server = serve(routes(vec![
        ("/", listing("/", &[("pool/", 0), ("iso/", 0)])),
        ("/pool/", listing("/pool/", &[("pkg_1.0.deb", 5)])),
        ("/iso/", listing("/iso/", &[("disk.iso", 5)])),
    ]))
    .await;
    let db = temp_db("skip-cleanup");
    run_crawl(vec![server.base.clone()], &db, fast_config()).await;
    assert_eq!(search(&db, "pkg", true, vec![]).len(), 1);

    let skip = opendirtest::filters::SkipList::from_lines(&["/pool/".to_string()]);
    let conn = store::open(&db).unwrap();
    let (_, dirs) = store::apply_skip_list(&conn, &skip).unwrap();
    assert_eq!(dirs, 1);
    drop(conn);
    assert!(search(&db, "pkg", true, vec![]).is_empty());
    assert_eq!(search(&db, "disk", true, vec![]).len(), 1);
}

/// Crawls `mine` (trusted) plus the sites waiting in the database, with the quality check on.
async fn run_judged(mine: Vec<Url>, db: &Path) {
    let cfg = CrawlConfig {
        quality: Thresholds::default(),
        ..fast_config()
    };
    run_with_pending(mine, db, cfg).await
}

fn add_waiting(db: &Path, urls: &[Url]) {
    store::add_candidates(&store::open(db).unwrap(), urls, "link").unwrap();
}

#[tokio::test]
async fn sites_with_nothing_worth_keeping_are_dropped_but_your_own_are_kept() {
    let photos: Vec<(String, u64)> = (0..30)
        .map(|i| (format!("photo-{i}.jpg"), 40_000))
        .collect();
    let photos: Vec<(&str, u64)> = photos.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    let junk = serve(routes(vec![("/", listing("/", &photos))])).await;
    let isos = [
        ("a.iso", 4_000_000_000),
        ("b.iso", 4_000_000_000),
        ("c.iso", 4_000_000_000),
    ];
    let good = serve(routes(vec![("/", listing("/", &isos))])).await;
    let mine = serve(routes(vec![("/", listing("/", &[("notes.txt", 12)]))])).await;
    let db = temp_db("quality");
    add_waiting(&db, &[junk.as_host("127.0.0.2"), good.as_host("127.0.0.3")]);

    run_judged(vec![mine.base.clone()], &db).await;

    // Found by a link, holding thumbnails: dropped, and nothing of it stays.
    assert_eq!(host_status(&db, "127.0.0.2"), "low_value");
    let reason: String = query_one(&db, "SELECT reason FROM hosts WHERE host = '127.0.0.2'");
    assert!(reason.contains("nothing worth keeping"), "{reason}");
    assert!(search(&db, "photo", true, vec![]).is_empty());
    // Found by a link, holding three big disk images: kept.
    assert_eq!(host_status(&db, "127.0.0.3"), "done");
    assert_eq!(search(&db, "iso", true, vec![]).len(), 3);
    // Added by you: tiny, but never judged.
    assert_eq!(host_status(&db, "127.0.0.1"), "done");
    assert_eq!(search(&db, "notes", true, vec![]).len(), 1);
    let trusted: i64 = query_one(&db, "SELECT trusted FROM hosts WHERE host = '127.0.0.1'");
    assert_eq!(trusted, 1);
    // A dropped site is not found and crawled again.
    let conn = store::open(&db).unwrap();
    store::add_candidates(&conn, &[junk.as_host("127.0.0.2")], "link").unwrap();
    assert!(pending_urls(&db).is_empty());
}

#[tokio::test]
async fn a_new_site_full_of_junk_is_dropped_early_without_crawling_it_all() {
    let dirs: Vec<String> = (0..150).map(|i| format!("d{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    for i in 0..150 {
        site.push((
            format!("/d{i}/"),
            listing(&format!("/d{i}/"), &[("t.jpg", 9_000)]),
        ));
    }
    let server = serve(site.into_iter().collect()).await;
    let db = temp_db("probe");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    assert_eq!(host_status(&db, "127.0.0.2"), "low_value");
    let requested = server.requested().len();
    assert!(
        requested <= 115,
        "{requested} requests: should stop after ~100 folders"
    );
    let files: i64 = query_one(&db, "SELECT count(*) FROM entries");
    assert_eq!(files, 0);
}

#[tokio::test]
async fn a_compromised_server_is_dropped_at_first_sight_even_if_you_added_it() {
    let hacked = serve(routes(vec![
        ("/", listing("/", &[("sym404/", 0), ("index.html", 5)])),
        (
            "/sym404/",
            listing(
                "/sym404/",
                &[
                    ("daemon-Wordpress26.txt404/", 0),
                    ("dbus-BoxBilling444.txt404/", 0),
                ],
            ),
        ),
    ]))
    .await;
    let db = temp_db("hacked");

    run_crawl(vec![hacked.base.clone()], &db, fast_config()).await;

    assert_eq!(host_status(&db, "127.0.0.1"), "sensitive");
    let reason: String = query_one(&db, "SELECT reason FROM hosts");
    assert!(reason.contains("sym404"), "{reason}");
    let files: i64 = query_one(&db, "SELECT count(*) FROM entries");
    assert_eq!(files, 0);
    assert!(search(&db, "wordpress", true, vec![]).is_empty());
}

#[tokio::test]
async fn weak_sensitive_names_cost_your_own_site_one_entry_and_others_the_site() {
    let files = [
        ("backup-2026-09-01.zip", 5_000_000_000),
        ("a.iso", 4_000_000_000),
    ];
    let mine = serve(routes(vec![("/", listing("/", &files))])).await;
    let other = serve(routes(vec![("/", listing("/", &files))])).await;
    let db = temp_db("weak");
    add_waiting(&db, &[other.as_host("127.0.0.2")]);

    run_judged(vec![mine.base.clone()], &db).await;

    // Yours: only the backup file is left out.
    assert_eq!(host_status(&db, "127.0.0.1"), "done");
    assert_eq!(search(&db, "backup", true, vec![]).len(), 0);
    assert_eq!(search(&db, "iso", true, vec![]).len(), 1);
    // Found by a link: the whole site is dropped.
    assert_eq!(host_status(&db, "127.0.0.2"), "sensitive");
}

#[tokio::test]
async fn sites_you_add_are_crawled_before_sites_found_by_links() {
    let db = temp_db("priority");
    let conn = store::open(&db).unwrap();
    let url = |u: &str| Url::parse(u).unwrap();
    store::add_candidates(&conn, &[url("https://found.example/pub/")], "link").unwrap();
    store::add_candidates(&conn, &[url("https://cc.example/pub/")], "commoncrawl:X").unwrap();
    store::add_seeds(&conn, &[url("https://mine.example/pub/")]).unwrap();

    let order: Vec<String> = store::pending_hosts(&conn, 10, &Default::default())
        .unwrap()
        .into_iter()
        .map(|h| h.host)
        .collect();
    let trusted: Vec<bool> = store::pending_hosts(&conn, 10, &Default::default())
        .unwrap()
        .into_iter()
        .map(|h| h.trusted)
        .collect();
    assert_eq!(order.len(), 3);
    assert_eq!(order[0], "mine.example", "{order:?}");
    assert!(trusted[0] && !trusted[1] && !trusted[2]);
}

#[tokio::test]
async fn a_deep_archive_is_not_judged_before_its_files_are_reached() {
    // Like a real image server: the top folders hold no files, the disk images
    // are three levels down.
    let isos = [
        ("a.iso", 4_000_000_000),
        ("b.iso", 4_000_000_000),
        ("c.iso", 4_000_000_000),
    ];
    let server = serve(routes(vec![
        ("/", listing("/", &[("releases/", 0)])),
        ("/releases/", listing("/releases/", &[("24.04/", 0)])),
        (
            "/releases/24.04/",
            listing("/releases/24.04/", &[("release/", 0)]),
        ),
        (
            "/releases/24.04/release/",
            listing("/releases/24.04/release/", &isos),
        ),
    ]))
    .await;
    let db = temp_db("deep");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);
    let cfg = || CrawlConfig {
        max_dirs_per_host: 3,
        quality: Thresholds::default(),
        ..fast_config()
    };

    // The first run stops after three folders, having seen no files at all.
    run_with_pending(vec![], &db, cfg()).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");

    // The next run reaches the images, and the site is kept.
    run_with_pending(vec![], &db, cfg()).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "done");
    assert_eq!(search(&db, "iso", true, vec![]).len(), 3);
}

// -- Regression tests for the third independent review ------------------------

/// A mirror-like archive: project folders with a README and an index page at the
/// top, and the disk image one level down.
fn mirror_like(projects: usize) -> HashMap<String, Route> {
    let dirs: Vec<String> = (0..projects).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    for i in 0..projects {
        site.push((
            format!("/p{i}/"),
            listing(
                &format!("/p{i}/"),
                &[
                    ("README.txt", 900 + i as u64),
                    ("index.html", 4_000),
                    ("releases/", 0),
                ],
            ),
        ));
        let iso = format!("p{i}-1.0.iso");
        site.push((
            format!("/p{i}/releases/"),
            listing(
                &format!("/p{i}/releases/"),
                &[(iso.as_str(), 4_000_000_000)],
            ),
        ));
    }
    site.into_iter().collect()
}

fn reason(db: &Path, host: &str) -> String {
    query_one(
        db,
        &format!("SELECT coalesce(reason, '') FROM hosts WHERE host = '{host}'"),
    )
}

#[tokio::test]
async fn an_archive_with_readmes_at_the_top_and_disk_images_below_is_kept() {
    let server = serve(mirror_like(110)).await;
    let db = temp_db("mirror");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    let images: i64 = query_one(&db, "SELECT count(*) FROM files WHERE url LIKE '%.iso'");
    assert_eq!(images, 110);
}

#[tokio::test]
async fn an_archive_paused_among_its_top_folders_is_kept_and_continues() {
    let server = serve(mirror_like(110)).await;
    let db = temp_db("mirror-paused");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);
    let cfg = || CrawlConfig {
        max_dirs_per_host: 60,
        quality: Thresholds::default(),
        ..fast_config()
    };

    // The first run ends among the project folders: 59 READMEs and index pages
    // stored, no disk image yet.
    run_with_pending(vec![], &db, cfg()).await;
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    assert!(!pending_urls(&db).is_empty());

    // Each new run starts by checking what is stored against the rules, like the
    // real command does, and must not throw the site away either.
    for _ in 0..8 {
        if host_status(&db, "127.0.0.2") == "done" {
            break;
        }
        let mut conn = store::open(&db).unwrap();
        let rules = store::CleanRules {
            optout: &[],
            skip: &opendirtest::filters::SkipList::default(),
            quality: Thresholds::default(),
        };
        let report = store::clean(&mut conn, &rules).unwrap();
        assert!(report.low_value.is_empty(), "{:?}", report.low_value);
        drop(conn);
        run_with_pending(vec![], &db, cfg()).await;
    }
    assert_eq!(host_status(&db, "127.0.0.2"), "done");
    let images: i64 = query_one(&db, "SELECT count(*) FROM files WHERE url LIKE '%.iso'");
    assert_eq!(images, 110);
}

#[tokio::test]
async fn a_site_you_add_that_moved_to_another_address_passes_its_trust_on() {
    // The old address answers with a redirect. The new one is a different host
    // name and holds a tiny folder that has no sign of being an archive.
    let new = serve(routes(vec![(
        "/stuff/",
        listing("/stuff/", &[("a.txt", 5)]),
    )]))
    .await;
    let destination = format!("{}stuff/", new.as_host("127.0.0.2"));
    let old = serve(routes(vec![("/", Route::redirect(&destination))])).await;
    let db = temp_db("moved");

    run_judged(vec![old.base.clone()], &db).await;

    // The new address was crawled in the same run and kept although it is tiny.
    assert_eq!(host_status(&db, "127.0.0.2"), "done");
    let trusted: i64 = query_one(&db, "SELECT trusted FROM hosts WHERE host = '127.0.0.2'");
    assert_eq!(trusted, 1);
    assert_eq!(search(&db, "a.txt", true, vec![]).len(), 1);
    assert_eq!(host_status(&db, "127.0.0.1"), "not_listing");
}

#[tokio::test]
async fn a_site_you_did_not_add_does_not_pass_trust_on_when_it_redirects() {
    let new = serve(routes(vec![("/pub/", listing("/pub/", &[("a.txt", 5)]))])).await;
    let destination = format!("{}pub/", new.as_host("127.0.0.3"));
    let old = serve(routes(vec![("/", Route::redirect(&destination))])).await;
    let db = temp_db("moved-untrusted");
    add_waiting(&db, &[old.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    // Found through a link and looking like an archive, so it is crawled, but it
    // is judged like any other site.
    assert_eq!(host_status(&db, "127.0.0.3"), "low_value");
}

#[tokio::test]
async fn a_site_you_add_passes_its_trust_to_only_a_few_new_addresses() {
    // Five URLs of one site, each moved to a different host.
    let mut targets = Vec::new();
    let mut moved = HashMap::new();
    for i in 0..5 {
        let target = serve(routes(vec![(
            "/stuff/",
            listing("/stuff/", &[("a.txt", 5)]),
        )]))
        .await;
        let to = format!("{}stuff/", target.as_host(&format!("127.0.0.{}", 10 + i)));
        moved.insert(format!("/r{i}/"), Route::redirect(&to));
        targets.push(target);
    }
    let old = serve(moved).await;
    let seeds: Vec<Url> = (0..5)
        .map(|i| old.base.join(&format!("r{i}/")).unwrap())
        .collect();
    let db = temp_db("moved-many");

    run_judged(seeds, &db).await;

    let kept: i64 = query_one(
        &db,
        "SELECT count(*) FROM hosts WHERE host LIKE '127.0.0.1_' AND status = 'done'",
    );
    assert_eq!(kept as usize, crawler::MAX_MOVED_SEEDS);
}

#[tokio::test]
async fn a_site_you_add_is_kept_even_if_discovery_found_it_first() {
    let photos: Vec<(String, u64)> = (0..30)
        .map(|i| (format!("photo-{i}.jpg"), 40_000))
        .collect();
    let photos: Vec<(&str, u64)> = photos.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    let mine = serve(routes(vec![("/", listing("/", &photos))])).await;
    let db = temp_db("seed-after-find");
    let url = mine.as_host("127.0.0.2");
    // Found by Common Crawl on an earlier night; tonight `auto` adds your seeds first.
    let conn = store::open(&db).unwrap();
    store::add_candidates(
        &conn,
        std::slice::from_ref(&url),
        "commoncrawl:CC-MAIN-2026-30",
    )
    .unwrap();
    store::add_seeds(&conn, &[url]).unwrap();
    drop(conn);

    run_judged(vec![], &db).await;

    assert_eq!(host_status(&db, "127.0.0.2"), "done");
}

// -- Regression tests for the fourth independent review -----------------------

fn host_trusted(db: &Path, host: &str) -> i64 {
    query_one(
        db,
        &format!("SELECT coalesce((SELECT trusted FROM hosts WHERE host = '{host}'), -1)"),
    )
}

fn clean_with_the_quality_check(db: &Path) -> store::CleanReport {
    let mut conn = store::open(db).unwrap();
    let rules = store::CleanRules {
        optout: &[],
        skip: &opendirtest::filters::SkipList::default(),
        quality: Thresholds::default(),
    };
    store::clean(&mut conn, &rules).unwrap()
}

/// A site you added has a folder, `moved/`, that redirects to another site, which
/// holds a tiny folder and would be dropped as junk unless someone vouched for it.
/// With `pause_first` the crawl is split over two runs, so `moved/` is only reached
/// in the second.
async fn folder_that_redirects(db_name: &str, pause_first: bool) -> (String, i64) {
    let target = serve(routes(vec![("/pub/", listing("/pub/", &[("a.txt", 5)]))])).await;
    let to = format!("{}pub/", target.as_host("127.0.0.3"));
    let mine = serve(routes(vec![
        (
            "/pub/",
            listing("/pub/", &[("moved/", 0), ("a.iso", 4_000_000_000)]),
        ),
        ("/pub/moved/", Route::redirect(&to)),
    ]))
    .await;
    let db = temp_db(db_name);
    let seed = mine.as_host("127.0.0.2").join("pub/").unwrap();
    if pause_first {
        let one_folder = CrawlConfig {
            max_dirs_per_host: 1,
            quality: Thresholds::default(),
            ..fast_config()
        };
        run_with_pending(vec![seed], &db, one_folder).await;
        assert_eq!(host_status(&db, "127.0.0.2"), "paused");
        run_judged(vec![], &db).await;
    } else {
        run_judged(vec![seed], &db).await;
    }
    (
        query_one(
            &db,
            "SELECT coalesce((SELECT status FROM hosts WHERE host = '127.0.0.3'), '(none)')",
        ),
        host_trusted(&db, "127.0.0.3"),
    )
}

#[tokio::test]
async fn a_folder_of_your_site_that_redirects_elsewhere_gives_the_new_site_no_trust() {
    // Reached in one run, or after a pause: the same outcome. Only an address you
    // added yourself passes trust on when it has moved, not a folder inside a site.
    for (name, pause_first) in [("leak-single", false), ("leak-resumed", true)] {
        let (status, trusted) = folder_that_redirects(name, pause_first).await;
        assert_eq!(status, "low_value", "{name}: trusted={trusted}");
        assert_eq!(trusted, 0, "{name}");
    }
}

#[tokio::test]
async fn a_waiting_folder_of_a_site_you_name_gives_no_trust_either() {
    let target = serve(routes(vec![("/pub/", listing("/pub/", &[("a.txt", 5)]))])).await;
    let to = format!("{}pub/", target.as_host("127.0.0.3"));
    let mine = serve(routes(vec![
        ("/pub/", listing("/pub/", &[("a.iso", 4_000_000_000)])),
        ("/pub/moved/", Route::redirect(&to)),
    ]))
    .await;
    let db = temp_db("named-waiting");
    // A folder of the site found through a link earlier; you now crawl the site by
    // name, which also crawls the folders it has waiting.
    add_waiting(
        &db,
        &[mine.as_host("127.0.0.2").join("pub/moved/").unwrap()],
    );

    run_judged(vec![mine.as_host("127.0.0.2").join("pub/").unwrap()], &db).await;

    assert_eq!(host_status(&db, "127.0.0.2"), "done");
    assert_eq!(host_status(&db, "127.0.0.3"), "low_value");
    assert_eq!(host_trusted(&db, "127.0.0.3"), 0);
}

#[tokio::test]
async fn trust_does_not_travel_down_a_chain_of_moved_sites() {
    // Your seed moved to B, and B redirects to C. C is not yours.
    let c = serve(routes(vec![("/pub/", listing("/pub/", &[("a.txt", 5)]))])).await;
    let to_c = format!("{}pub/", c.as_host("127.0.0.4"));
    let b = serve(routes(vec![("/pub/", Route::redirect(&to_c))])).await;
    let to_b = format!("{}pub/", b.as_host("127.0.0.3"));
    let a = serve(routes(vec![("/pub/", Route::redirect(&to_b))])).await;
    let db = temp_db("chain");

    run_judged(vec![a.as_host("127.0.0.2").join("pub/").unwrap()], &db).await;

    assert_eq!(
        host_trusted(&db, "127.0.0.3"),
        1,
        "B is where your seed moved"
    );
    assert_eq!(
        host_trusted(&db, "127.0.0.4"),
        0,
        "C is judged like any find"
    );
    assert_eq!(host_status(&db, "127.0.0.4"), "low_value");
}

#[tokio::test]
async fn a_moved_seed_whose_new_address_was_already_found_is_kept_too() {
    let target = serve(routes(vec![("/pub/", listing("/pub/", &[("a.txt", 5)]))])).await;
    let to = format!("{}pub/", target.as_host("127.0.0.3"));
    let old = serve(routes(vec![("/pub/", Route::redirect(&to))])).await;
    let db = temp_db("moved-known");
    // The new address was found through a link earlier and crawled while the
    // quality check was off: kept, but not trusted.
    add_waiting(&db, &[target.as_host("127.0.0.3").join("pub/").unwrap()]);
    run_with_pending(vec![], &db, fast_config()).await;
    assert_eq!(host_status(&db, "127.0.0.3"), "done");
    assert_eq!(host_trusted(&db, "127.0.0.3"), 0);

    // Now your seed, which has moved there, is crawled.
    run_judged(vec![old.as_host("127.0.0.2").join("pub/").unwrap()], &db).await;

    assert_eq!(host_trusted(&db, "127.0.0.3"), 1);
    assert!(clean_with_the_quality_check(&db).low_value.is_empty());
    assert_eq!(host_status(&db, "127.0.0.3"), "done");
}

/// `/pN/` holds README.txt, `docs/` (three small pages, a leaf) and `download/`,
/// which holds `v1/` and, in there, the disk image.
fn mirror_with_docs(projects: usize) -> HashMap<String, Route> {
    let dirs: Vec<String> = (0..projects).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    for i in 0..projects {
        let readme = 900 + i as u64;
        site.push((
            format!("/p{i}/"),
            listing(
                &format!("/p{i}/"),
                &[("README.txt", readme), ("docs/", 0), ("download/", 0)],
            ),
        ));
        let index = 4_000 + i as u64;
        site.push((
            format!("/p{i}/docs/"),
            listing(
                &format!("/p{i}/docs/"),
                &[
                    ("index.html", index),
                    ("intro.html", 6_000),
                    ("faq.html", 7_000),
                ],
            ),
        ));
        site.push((
            format!("/p{i}/download/"),
            listing(&format!("/p{i}/download/"), &[("v1/", 0)]),
        ));
        let iso = format!("p{i}-1.0.iso");
        site.push((
            format!("/p{i}/download/v1/"),
            listing(
                &format!("/p{i}/download/v1/"),
                &[(iso.as_str(), 4_000_000_000)],
            ),
        ));
    }
    site.into_iter().collect()
}

#[tokio::test]
async fn small_pages_in_shallow_folders_do_not_hide_the_downloads_below() {
    let server = serve(mirror_with_docs(110)).await;
    let db = temp_db("docs");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    // 330 small pages sit in leaf folders one level above the disk images. The
    // early check waits until the crawl has reached leaves as deep as what is
    // still queued, and the folders that only hold `v1/` all list the same names
    // and dates but are not copies of each other.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    let images: i64 = query_one(&db, "SELECT count(*) FROM files WHERE url LIKE '%.iso'");
    assert_eq!(images, 110);
}

#[tokio::test]
async fn folders_that_only_hold_sub_folders_are_never_taken_for_copies() {
    // Three projects made together: their `download/` folders list the same single
    // sub-folder with the same date, and each `v1/` holds a different file.
    let server = serve(routes(vec![
        ("/", listing("/", &[("p0/", 0), ("p1/", 0), ("p2/", 0)])),
        ("/p0/", listing("/p0/", &[("download/", 0)])),
        ("/p1/", listing("/p1/", &[("download/", 0)])),
        ("/p2/", listing("/p2/", &[("download/", 0)])),
        ("/p0/download/", listing("/p0/download/", &[("v1/", 0)])),
        ("/p1/download/", listing("/p1/download/", &[("v1/", 0)])),
        ("/p2/download/", listing("/p2/download/", &[("v1/", 0)])),
        (
            "/p0/download/v1/",
            listing("/p0/download/v1/", &[("zero.iso", 1_000)]),
        ),
        (
            "/p1/download/v1/",
            listing("/p1/download/v1/", &[("one.iso", 2_000)]),
        ),
        (
            "/p2/download/v1/",
            listing("/p2/download/v1/", &[("two.iso", 3_000)]),
        ),
    ]))
    .await;
    let db = temp_db("not-copies");

    run_crawl(vec![server.base.clone()], &db, fast_config()).await;

    for name in ["zero", "one", "two"] {
        assert_eq!(
            search(&db, name, true, vec![]).len(),
            1,
            "{name}.iso was never reached"
        );
    }
}

fn junk_folder_with_broken_sub_folders() -> HashMap<String, Route> {
    let photos: Vec<(String, u64)> = (0..150)
        .map(|i| (format!("photo-{i}.jpg"), 40_000))
        .collect();
    let mut root: Vec<(&str, u64)> = photos.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    // Six sub-folders that answer 500: five errors in a row make the crawl give up.
    let subs: Vec<String> = (0..6).map(|i| format!("s{i}/")).collect();
    root.extend(subs.iter().map(|s| (s.as_str(), 0)));
    let mut site = vec![("/pub/".to_string(), listing("/pub/", &root))];
    for i in 0..6 {
        site.push((format!("/pub/s{i}/"), Route::text(500, "boom")));
    }
    site.into_iter().collect()
}

#[tokio::test]
async fn junk_that_keeps_failing_is_dropped_when_the_site_is_given_up() {
    let server = serve(junk_folder_with_broken_sub_folders()).await;
    let db = temp_db("gave-up");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);

    // Five errors in a row end a run, but not the site: it stays paused with the
    // folders that failed, and the next runs try them again.
    for run in 1..=4 {
        run_judged(vec![], &db).await;
        let why = reason(&db, "127.0.0.2");
        assert_eq!(host_status(&db, "127.0.0.2"), "paused", "run {run}: {why}");
        assert_eq!(strikes(&db, "127.0.0.2"), run);
    }
    assert!(stored_files(&db) > 0);

    // The fifth run in a row that ends in errors gives the site up. It is never
    // crawled again, so 150 photos must not stay searchable.
    run_judged(vec![], &db).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "low_value");
    assert_eq!(stored_files(&db), 0);
}

#[tokio::test]
async fn a_site_that_cannot_be_reached_in_a_later_run_stays_paused_with_its_frontier() {
    // A paused archive: 120 README files at the top and `iso/` waiting below. In
    // the next run `iso/` answers with a server error (down for the night, a
    // hiccup). That must not end the site or throw away what it has stored.
    let readmes: Vec<String> = (0..120).map(|i| format!("README-{i}.txt")).collect();
    let mut top: Vec<(&str, u64)> = readmes.iter().map(|n| (n.as_str(), 900)).collect();
    top.push(("iso/", 0));
    let server = serve(routes(vec![
        ("/pub/", listing("/pub/", &top)),
        ("/pub/iso/", Route::text(500, "boom")),
    ]))
    .await;
    let db = temp_db("hiccup");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);
    let one_folder = CrawlConfig {
        max_dirs_per_host: 1,
        quality: Thresholds::default(),
        ..fast_config()
    };
    run_with_pending(vec![], &db, one_folder).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    assert!(why.contains("will try again"), "{why}");
    let stored: i64 = query_one(&db, "SELECT count(*) FROM files WHERE is_dir = 0");
    assert_eq!(stored, 120);
    // The folder is still waiting, so the next run tries it again.
    let iso = server.as_host("127.0.0.2").join("pub/iso/").unwrap();
    assert_eq!(pending_urls(&db), vec![iso.to_string()]);
}

#[tokio::test]
async fn junk_folders_with_skipped_sub_folders_are_dropped_early() {
    let n = 300;
    let dirs: Vec<String> = (0..n).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/pub/".to_string(), listing("/pub/", &root))];
    for i in 0..n {
        site.push((
            format!("/pub/p{i}/"),
            listing(
                &format!("/pub/p{i}/"),
                &[
                    ("a.jpg", 40_000),
                    ("b.jpg", 41_000),
                    ("c.jpg", 42_000),
                    ("cache/", 0),
                ],
            ),
        ));
    }
    let server = serve(site.into_iter().collect()).await;
    let db = temp_db("skipped-below");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);
    // Each folder lists a `cache/` sub-folder that the skip list keeps the crawl out
    // of, so nothing below the folders is ever visited: they are leaves.
    let skip = opendirtest::filters::SkipList::from_lines(&["/cache/".to_string()]);
    let cfg = CrawlConfig {
        skip,
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![], &db, cfg).await;

    assert_eq!(host_status(&db, "127.0.0.2"), "low_value");
    // Dropped once the folders looked at are as many as the ones still waiting:
    // about half of the 300, not all of them.
    let requested = server.requested().len();
    assert!(
        requested < 200,
        "the whole junk site was crawled ({requested} requests)"
    );
}

fn caddy(entries: &[(&str, u64)]) -> Route {
    let items: Vec<String> = entries
        .iter()
        .map(|(name, size)| {
            let is_dir = name.ends_with('/');
            format!(
                "{{\"name\":\"{name}\",\"size\":{},\"url\":\"./{name}\",\
                 \"mod_time\":\"2026-09-28T10:15:00Z\",\"mode\":420,\"is_dir\":{is_dir},\
                 \"is_symlink\":false}}",
                if is_dir { 4096 } else { *size }
            )
        })
        .collect();
    Route::new(
        200,
        Some("application/json"),
        format!("[{}]", items.join(",")),
    )
}

#[tokio::test]
async fn a_caddy_archive_with_readmes_at_the_top_is_kept() {
    let dirs: Vec<String> = (0..110).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), caddy(&root))];
    for i in 0..110 {
        let readme = 900 + i as u64;
        site.push((
            format!("/p{i}/"),
            caddy(&[
                ("README.txt", readme),
                ("index.html", 4_000),
                ("releases/", 0),
            ]),
        ));
        let iso = format!("p{i}-1.0.iso");
        site.push((
            format!("/p{i}/releases/"),
            caddy(&[(iso.as_str(), 4_000_000_000)]),
        ));
    }
    let server = serve(site.into_iter().collect()).await;
    let db = temp_db("caddy-mirror");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    let images: i64 = query_one(&db, "SELECT count(*) FROM files WHERE url LIKE '%.iso'");
    assert_eq!(images, 110);
}

// -- Regression tests for the fifth independent review ------------------------

/// `sections` junk sections, each with four leaf folders of 25 small images and a
/// `deeper/` folder holding one more leaf, so the crawl always has something
/// deeper waiting than the leaves it has seen.
fn sectioned_junk(sections: usize) -> HashMap<String, Route> {
    let names: Vec<String> = (0..sections).map(|i| format!("t{i}/")).collect();
    let root: Vec<(&str, u64)> = names.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    let images = |seed: usize| -> Vec<(String, u64)> {
        (0..25)
            .map(|j| {
                (
                    format!("img-{j}.jpg"),
                    30_000 + seed as u64 * 100 + j as u64,
                )
            })
            .collect()
    };
    let mut leaf = |path: String, seed: usize| {
        let files = images(seed);
        let files: Vec<(&str, u64)> = files.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        site.push((path.clone(), listing(&path, &files)));
    };
    for i in 0..sections {
        for k in 0..4 {
            leaf(format!("/t{i}/s{k}/"), i * 4 + k);
        }
        leaf(format!("/t{i}/deeper/x0/"), 1_000 + i);
    }
    for i in 0..sections {
        let mut items: Vec<(String, u64)> = (0..4).map(|k| (format!("s{k}/"), 0)).collect();
        items.push(("deeper/".into(), 0));
        let items: Vec<(&str, u64)> = items.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        site.push((format!("/t{i}/"), listing(&format!("/t{i}/"), &items)));
        site.push((
            format!("/t{i}/deeper/"),
            listing(&format!("/t{i}/deeper/"), &[("x0/", 0)]),
        ));
    }
    site.into_iter().collect()
}

#[tokio::test]
async fn a_junk_site_with_a_deeper_layer_is_dropped_once_that_layer_has_been_sampled() {
    let server = serve(sectioned_junk(100)).await;
    let db = temp_db("sectioned");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    // Every section has a folder deeper than its leaves, so nothing can be said
    // until the deepest layer has been read: the images are 30 KB, the folders
    // below them hold more of the same, and only then is it junk. The site has 701
    // folders, and the last of them are not read.
    assert_eq!(host_status(&db, "127.0.0.2"), "low_value");
    let requested = server.requested().len();
    assert!(requested < 701, "{requested} requests");
    assert_eq!(stored_files(&db), 0);
}

/// 200 project folders: the even ones hold three images, the odd ones three images
/// and an `iso/` folder with three disk images.
fn wide_archive(n: usize) -> HashMap<String, Route> {
    let dirs: Vec<String> = (0..n).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    for i in 0..n {
        let mut items: Vec<(&str, u64)> =
            vec![("a.jpg", 40_000), ("b.jpg", 41_000), ("c.jpg", 42_000)];
        if i % 2 == 1 {
            items.push(("iso/", 0));
        }
        site.push((format!("/p{i}/"), listing(&format!("/p{i}/"), &items)));
        if i % 2 == 1 {
            let isos = [
                ("x.iso", 4_000_000_000),
                ("y.iso", 4_000_000_000),
                ("z.iso", 4_000_000_000),
            ];
            site.push((
                format!("/p{i}/iso/"),
                listing(&format!("/p{i}/iso/"), &isos),
            ));
        }
    }
    site.into_iter().collect()
}

#[tokio::test]
async fn folders_saved_past_the_budget_still_count_as_waiting() {
    // The queue is full after the root, so every `iso/` folder is saved for the next
    // run instead of being queued. The crawler must weigh them like the ones queued,
    // as the cleanup does, or it drops an archive that `clean` would keep.
    let server = serve(wide_archive(200)).await;
    let db = temp_db("overflow");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);
    let cfg = CrawlConfig {
        max_dirs_per_host: 150,
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![], &db, cfg).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    assert!(clean_with_the_quality_check(&db).low_value.is_empty());
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");
}

/// The listing of every path made of `a` and `b` up to `depth`: two sub-folders,
/// like a site with two symlinks back to its root.
fn looping_site(depth: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let mut paths = vec![String::from("/")];
    while let Some(path) = paths.pop() {
        site.insert(path.clone(), listing(&path, &[("a/", 0), ("b/", 0)]));
        if path.matches('/').count() <= depth {
            paths.push(format!("{path}a/"));
            paths.push(format!("{path}b/"));
        }
    }
    site
}

#[tokio::test]
async fn a_listing_that_repeats_at_every_level_is_walked_once() {
    let server = serve(looping_site(6)).await;
    let db = temp_db("loop");
    let cfg = CrawlConfig {
        max_dirs_per_host: 400,
        ..fast_config()
    };

    run_crawl(vec![server.base.clone()], &db, cfg).await;

    // `/a/` and `/b/` list exactly what `/` lists: copies of a parent, not walked.
    let listings = server
        .requested()
        .iter()
        .filter(|path| path.as_str() != "/robots.txt")
        .count();
    assert!(listings <= 5, "walked {listings} identical listings");
}

/// `projects` projects that each hold README.txt and `docs/` (three small pages);
/// the ones from `docs_only` on also hold `download/v1/` with a disk image.
fn mirror_docs_first(projects: usize, docs_only: usize) -> HashMap<String, Route> {
    let dirs: Vec<String> = (0..projects).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = dirs.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    for i in 0..projects {
        let mut items: Vec<(&str, u64)> = vec![("README.txt", 900 + i as u64), ("docs/", 0)];
        if i >= docs_only {
            items.push(("download/", 0));
        }
        site.push((format!("/p{i}/"), listing(&format!("/p{i}/"), &items)));
        let index = 4_000 + i as u64;
        let pages = [
            ("index.html", index),
            ("intro.html", 6_000),
            ("faq.html", 7_000),
        ];
        site.push((
            format!("/p{i}/docs/"),
            listing(&format!("/p{i}/docs/"), &pages),
        ));
        if i >= docs_only {
            site.push((
                format!("/p{i}/download/"),
                listing(&format!("/p{i}/download/"), &[("v1/", 0)]),
            ));
            let iso = format!("p{i}-1.0.iso");
            let files = [(iso.as_str(), 4_000_000_000)];
            site.push((
                format!("/p{i}/download/v1/"),
                listing(&format!("/p{i}/download/v1/"), &files),
            ));
        }
    }
    site.into_iter().collect()
}

#[tokio::test]
async fn an_archive_whose_first_projects_are_docs_only_is_kept() {
    // Sixty of 110 projects hold only documentation, and come first. The leaf folders
    // seen early are all small pages, and nothing deeper is queued yet, but there are
    // more folders waiting than were looked at, and some of them lead to disk images.
    let server = serve(mirror_docs_first(110, 60)).await;
    let db = temp_db("docs-first");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    let images: i64 = query_one(&db, "SELECT count(*) FROM files WHERE url LIKE '%.iso'");
    assert_eq!(images, 50);
}

#[tokio::test]
async fn clean_keeps_the_same_archive_when_it_was_paused_among_the_docs() {
    let server = serve(mirror_docs_first(110, 60)).await;
    let db = temp_db("docs-first-paused");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);
    // A budget that ends the run among the level-2 folders.
    let cfg = CrawlConfig {
        max_dirs_per_host: 160,
        quality: Thresholds::OFF,
        ..fast_config()
    };
    run_with_pending(vec![], &db, cfg).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");

    let report = clean_with_the_quality_check(&db);

    assert!(report.low_value.is_empty(), "{:?}", report.low_value);
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");
}

#[tokio::test]
async fn a_paused_crawl_of_the_new_address_of_a_moved_seed_keeps_its_trust() {
    // Y was found through a link and is being crawled while your seed A turns out
    // to have moved to Y. Y asks for a one second crawl delay, so A's redirect is
    // recorded while Y's crawl is still running, and Y then runs out of budget.
    let y = serve(routes(vec![
        (
            "/robots.txt",
            Route::text(200, "User-agent: *\nCrawl-delay: 1\n"),
        ),
        ("/pub/", listing("/pub/", &[("later/", 0), ("a.txt", 5)])),
        ("/pub/later/", listing("/pub/later/", &[("b.txt", 5)])),
    ]))
    .await;
    let to = format!("{}pub/", y.as_host("127.0.0.3"));
    let a = serve(routes(vec![("/pub/", Route::redirect(&to))])).await;
    let db = temp_db("moved-paused");
    add_waiting(&db, &[y.as_host("127.0.0.3").join("pub/").unwrap()]);
    let cfg = CrawlConfig {
        max_dirs_per_host: 1,
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![a.as_host("127.0.0.2").join("pub/").unwrap()], &db, cfg).await;

    assert_eq!(host_status(&db, "127.0.0.3"), "paused");
    assert_eq!(
        host_trusted(&db, "127.0.0.3"),
        1,
        "Y is where a seed of yours moved to"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crawl_by_name_on_the_command_line_keeps_a_tiny_site() {
    // The real command: a site you name is recorded as yours before anything is
    // judged, so thirty small images are kept, and it is crawled at all.
    let photos: Vec<(String, u64)> = (0..30)
        .map(|i| (format!("photo-{i}.jpg"), 40_000 + i as u64))
        .collect();
    let photos: Vec<(&str, u64)> = photos.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    let server = serve(routes(vec![("/", listing("/", &photos))])).await;
    let db = temp_db("cli-named");
    let url = server.base.to_string();
    let program = env!("CARGO_BIN_EXE_opendir");
    let db_arg = db.to_str().unwrap().to_string();

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(program)
            .args(["crawl", &url, "--max-dirs", "5", "--db", &db_arg])
            .current_dir(std::env::temp_dir())
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let log = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{log}");
    assert_eq!(host_status(&db, "127.0.0.1"), "done", "{log}");
    assert_eq!(host_trusted(&db, "127.0.0.1"), 1);
    let stored: i64 = query_one(&db, "SELECT count(*) FROM files WHERE is_dir = 0");
    assert_eq!(stored, 30);
}

#[tokio::test]
async fn a_finished_site_that_fails_when_crawled_again_by_name_is_not_left_paused() {
    // The same site name on two ports: first answering, then only with errors.
    let good = serve(routes(vec![(
        "/pub/",
        listing("/pub/", &[("a.iso", 4_000_000_000)]),
    )]))
    .await;
    let broken = serve(routes(vec![("/pub/", Route::text(500, "boom"))])).await;
    let db = temp_db("done-then-fails");
    run_crawl(
        vec![good.as_host("127.0.0.2").join("pub/").unwrap()],
        &db,
        fast_config(),
    )
    .await;
    assert_eq!(host_status(&db, "127.0.0.2"), "done");

    run_crawl(
        vec![broken.as_host("127.0.0.2").join("pub/").unwrap()],
        &db,
        fast_config(),
    )
    .await;

    // Only a site that was paused, with folders saved to continue from, stays
    // paused after a run that could not reach it. A finished one has nothing to
    // resume, so "paused" would be a dead end.
    assert_eq!(host_status(&db, "127.0.0.2"), "unreachable");
    assert!(pending_urls(&db).is_empty());
}

#[tokio::test]
async fn folders_saved_past_the_budget_weigh_as_much_as_the_queued_ones() {
    // 300 folders side by side: the first 200 hold three small images, the last 100
    // hold a disk image. With a budget of 150 the queue fills up after the root, so
    // all the disk image folders are saved for the next run. The junk seen first is
    // 100 leaf folders at the same depth as those, and 100 saved folders is not a
    // sample that says anything about the rest.
    let names: Vec<String> = (0..300).map(|i| format!("p{i}/")).collect();
    let root: Vec<(&str, u64)> = names.iter().map(|d| (d.as_str(), 0)).collect();
    let mut site = vec![("/".to_string(), listing("/", &root))];
    for i in 0..300 {
        let files: Vec<(String, u64)> = if i < 200 {
            (0..3)
                .map(|j| (format!("img-{j}.jpg"), 30_000 + i as u64 * 10 + j))
                .collect()
        } else {
            vec![(format!("p{i}.iso"), 4_000_000_000)]
        };
        let files: Vec<(&str, u64)> = files.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        site.push((format!("/p{i}/"), listing(&format!("/p{i}/"), &files)));
    }
    let server = serve(site.into_iter().collect()).await;
    let db = temp_db("overflow-count");
    add_waiting(&db, &[server.as_host("127.0.0.2")]);
    let cfg = CrawlConfig {
        max_dirs_per_host: 150,
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![], &db, cfg).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    assert!(clean_with_the_quality_check(&db).low_value.is_empty());
}

// ---------------------------------------------------------------------------
// Realistic site shapes (sixth review): what is kept, what is dropped, and what
// it costs.
// ---------------------------------------------------------------------------

const MB: u64 = 1024 * 1024;

/// Adds the listing of `path` to a site; names ending in `/` are folders.
fn add_listing(site: &mut HashMap<String, Route>, path: &str, entries: &[(String, u64)]) {
    let borrowed: Vec<(&str, u64)> = entries.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    site.insert(path.to_string(), listing(path, &borrowed));
}

fn folder(name: impl Into<String>) -> (String, u64) {
    (format!("{}/", name.into()), 0)
}

fn item(name: impl Into<String>, size: u64) -> (String, u64) {
    (name.into(), size)
}

fn stored_files(db: &Path) -> i64 {
    query_one(db, "SELECT count(*) FROM entries WHERE is_dir = 0")
}

fn stored_dirs(db: &Path) -> i64 {
    query_one(db, "SELECT count(*) FROM dirs")
}

/// Runs in a row that ended in errors (`hosts.fails`).
fn strikes(db: &Path, host: &str) -> i64 {
    query_one(
        db,
        &format!("SELECT fails FROM hosts WHERE host = '{host}'"),
    )
}

/// `n` project folders under `/pub/`, each with three tarballs, a signature and a
/// sub-folder of small files (which is a leaf, like the pages of a `doc/` folder).
fn projects_with_leaf(n: usize, leaf: &str, small: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let names: Vec<String> = (0..n).map(|i| format!("proj{i}")).collect();
    let top: Vec<_> = names.iter().map(folder).collect();
    add_listing(&mut site, "/pub/", &top);
    for (i, name) in names.iter().enumerate() {
        let entries = vec![
            item(format!("{name}-1.0.tar.gz"), 3 * MB),
            item(format!("{name}-1.1.tar.gz"), 4 * MB),
            item(format!("{name}-1.2.tar.gz"), 5 * MB),
            item(format!("{name}-1.2.tar.gz.sig"), 488),
            folder(leaf),
        ];
        add_listing(&mut site, &format!("/pub/{name}/"), &entries);
        let small: Vec<_> = (0..small)
            .map(|k| {
                let size = 3_000 + ((i * 7 + k) as u64 * 1_237) % 40_000;
                item(format!("file{k}.html"), size)
            })
            .collect();
        add_listing(&mut site, &format!("/pub/{name}/{leaf}/"), &small);
    }
    site
}

#[tokio::test]
async fn an_archive_whose_folders_each_have_a_small_doc_folder_is_kept() {
    // The downloads are in the folders that have a sub-folder, and the leaves are
    // all pages: judged on the leaves alone this looks like a website.
    let server = serve(projects_with_leaf(120, "doc", 6)).await;
    let db = temp_db("proj-docs");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert_eq!(stored_files(&db), 120 * (4 + 6));
}

#[tokio::test]
async fn an_archive_whose_folders_each_have_an_image_folder_is_kept() {
    let server = serve(projects_with_leaf(60, "images", 10)).await;
    let db = temp_db("proj-images");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert_eq!(stored_files(&db), 60 * (4 + 10));
}

/// `n` releases, each with a `docs/` folder of `pages` pages and, one level further
/// down, `download/v<i>/` with a tarball. Breadth first, all the docs are read
/// before any download.
fn releases(n: usize, pages: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let names: Vec<String> = (0..n).map(|i| format!("r{i}")).collect();
    let top: Vec<_> = names.iter().map(folder).collect();
    add_listing(&mut site, "/releases/", &top);
    for (i, name) in names.iter().enumerate() {
        let base = format!("/releases/{name}");
        add_listing(
            &mut site,
            &format!("{base}/"),
            &[folder("docs"), folder("download")],
        );
        let docs: Vec<_> = (0..pages)
            .map(|k| item(format!("page{k}.html"), 3_000 + (i * pages + k) as u64 * 37))
            .collect();
        add_listing(&mut site, &format!("{base}/docs/"), &docs);
        add_listing(
            &mut site,
            &format!("{base}/download/"),
            &[folder(format!("v{i}"))],
        );
        let files = vec![
            item(format!("{name}.tar.gz"), (1 + i as u64 % 8) * MB),
            item(format!("{name}.tar.gz.sig"), 488),
        ];
        add_listing(&mut site, &format!("{base}/download/v{i}/"), &files);
    }
    site
}

#[tokio::test]
async fn docs_read_before_the_downloads_do_not_condemn_a_project_site() {
    let server = serve(releases(100, 15)).await;
    let db = temp_db("releases");
    add_waiting(
        &db,
        &[server.as_host("127.0.0.2").join("releases/").unwrap()],
    );

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert_eq!(stored_files(&db), 100 * (15 + 2));
}

/// `n` leaf folders of 15 thumbnails each, nothing else.
fn thumbnail_folders(n: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let names: Vec<String> = (0..n).map(|i| format!("g{i:03}")).collect();
    let top: Vec<_> = names.iter().map(folder).collect();
    add_listing(&mut site, "/gal/", &top);
    for (i, name) in names.iter().enumerate() {
        let thumbs: Vec<_> = (0..15)
            .map(|k| {
                item(
                    format!("t{k:02}-150x150.jpg"),
                    3_000 + ((i * 15 + k) as u64 * 811) % 23_000,
                )
            })
            .collect();
        add_listing(&mut site, &format!("/gal/{name}/"), &thumbs);
    }
    site
}

#[tokio::test]
async fn a_pause_does_not_switch_off_the_early_junk_check() {
    let server = serve(thumbnail_folders(400)).await;
    let db = temp_db("pause-junk");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("gal/").unwrap()]);
    let short = CrawlConfig {
        max_dirs_per_host: 150,
        quality: Thresholds::default(),
        ..fast_config()
    };
    run_with_pending(vec![], &db, short).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");

    // The next run continues with what the first one read, and is judged as early
    // as a site that was never paused: not after all 401 folders.
    run_judged(vec![], &db).await;

    assert_eq!(host_status(&db, "127.0.0.2"), "low_value");
    let requested = server.requested().len();
    assert!(
        requested < 240,
        "{requested} requests for a site of 401 folders"
    );
    assert_eq!(stored_files(&db), 0);
}

#[tokio::test]
async fn an_endless_calendar_is_given_up_after_two_thousand_folders() {
    // Every folder lists 12 month folders and 5 pictures, whatever its address, so
    // the site never ends and no folder without sub-folders is ever reached.
    let server = serve_with(Arc::new(|path, _| {
        if !path.starts_with("/cal/") || !path.ends_with('/') {
            return Route::text(404, "not found");
        }
        let depth = path.matches('/').count();
        let hash = path
            .bytes()
            .fold(7u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
        let mut entries: Vec<(String, u64)> =
            (0..12).map(|m| folder(format!("n{depth}x{m}"))).collect();
        entries.extend((0..5).map(|k| item(format!("shot{k}.jpg"), 10_000 + hash % 50_000 + k)));
        let borrowed: Vec<(&str, u64)> = entries.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        listing(path, &borrowed)
    }))
    .await;
    let db = temp_db("calendar");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("cal/").unwrap()]);
    let cfg = || CrawlConfig {
        max_dirs_per_host: 700,
        per_host_delay: Duration::ZERO,
        quality: Thresholds::default(),
        ..fast_config()
    };

    let mut runs = 0;
    while host_status_or(&db, "127.0.0.2", "new") != "low_value" && runs < 6 {
        run_with_pending(vec![], &db, cfg()).await;
        runs += 1;
    }

    assert_eq!(
        host_status(&db, "127.0.0.2"),
        "low_value",
        "after {runs} runs"
    );
    let requested = server.requested().len();
    assert!(requested < 2_300, "{requested} requests");
    assert_eq!(stored_files(&db), 0);
}

fn host_status_or(db: &Path, host: &str, none: &str) -> String {
    store::open(db)
        .unwrap()
        .query_row("SELECT status FROM hosts WHERE host = ?1", [host], |r| {
            r.get(0)
        })
        .unwrap_or_else(|_| none.to_string())
}

#[tokio::test]
async fn a_link_into_a_skipped_folder_reads_the_front_page_instead() {
    let isos = [
        ("disk1.iso", 4_000_000_000),
        ("disk2.iso", 4_000_000_000),
        ("disk3.iso", 4_000_000_000),
    ];
    let server = serve(routes(vec![
        (
            "/",
            listing("/", &[("pool/", 0), ("iso/", 0), ("README", 100)]),
        ),
        ("/pool/", listing("/pool/", &[("main/", 0)])),
        ("/pool/main/", listing("/pool/main/", &[("a/", 0)])),
        (
            "/pool/main/a/",
            listing("/pool/main/a/", &[("a_1.0.deb", 500)]),
        ),
        ("/iso/", listing("/iso/", &isos)),
    ]))
    .await;
    let db = temp_db("skip-front");
    add_waiting(
        &db,
        &[server.as_host("127.0.0.2").join("pool/main/a/").unwrap()],
    );
    let cfg = CrawlConfig {
        skip: opendirtest::filters::SkipList::from_lines(&["/pool/".to_string()]),
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![], &db, cfg).await;

    // The only way in was a skipped folder. Nothing was read there, and that is no
    // reason to call the mirror worthless.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert_eq!(search(&db, "disk1", true, vec![]).len(), 1);
    let requested = server.requested();
    assert!(
        !requested.iter().any(|p| p.starts_with("/pool")),
        "{requested:?}"
    );
}

/// A listing of `n` files with long names, in the Apache table style, as big as a
/// folder of that many papers is in real life.
fn big_folder(n: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let files: Vec<_> = (0..n)
        .map(|i| {
            item(
                format!("proceedings-of-the-annual-workshop-paper-{i:06}.pdf"),
                2 * MB + i as u64,
            )
        })
        .collect();
    add_listing(&mut site, "/papers/", &files);
    site
}

#[tokio::test]
async fn a_listing_of_fifty_thousand_files_is_read_completely() {
    // About 9 MB of HTML: more than the 8 MiB an earlier version cut listings at.
    let server = serve(big_folder(50_000)).await;
    let db = temp_db("big-listing");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("papers/").unwrap()]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert_eq!(stored_files(&db), 50_000);
    assert!(!why.contains("cut short"), "{why}");
}

#[tokio::test]
async fn a_listing_longer_than_the_cap_is_cut_short_and_the_site_says_so() {
    let server = serve(big_folder(3_000)).await;
    let db = temp_db("cut-short");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("papers/").unwrap()]);
    let cfg = CrawlConfig {
        max_listing_bytes: 64 * 1024,
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![], &db, cfg).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert!(why.contains("cut short"), "{why}");
    let files = stored_files(&db);
    assert!(0 < files && files < 3_000, "{files} files");
}

/// `/pub/` lists `n` folders, every one of which answers `status`.
fn folders_that_answer(n: usize, status: u16) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let names: Vec<String> = (0..n).map(|i| format!("f{i}")).collect();
    let top: Vec<_> = names.iter().map(folder).collect();
    add_listing(&mut site, "/pub/", &top);
    for name in &names {
        site.insert(format!("/pub/{name}/"), Route::text(status, "no"));
    }
    site
}

#[tokio::test]
async fn folders_that_are_all_refused_cost_fifty_requests_a_run_and_end_the_site_after_five() {
    for status in [403, 404] {
        let server = serve(folders_that_answer(2_000, status)).await;
        let db = temp_db(&format!("refused-{status}"));
        add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);

        run_judged(vec![], &db).await;

        // The run stops after 50 refusals in a row, with the rest still waiting.
        let why = reason(&db, "127.0.0.2");
        assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{status}: {why}");
        assert!(why.contains("refused 50 folders in a row"), "{why}");
        assert!(
            server.requested().len() <= 60,
            "{}",
            server.requested().len()
        );
        // Nothing is forgotten: the 1,950 not asked for and the 50 that were refused.
        assert_eq!(pending_urls(&db).len(), 2_000);

        for _ in 0..4 {
            run_judged(vec![], &db).await;
        }

        // Five runs in a row that ended so: the site is given up, with what it has.
        let why = reason(&db, "127.0.0.2");
        assert_eq!(host_status(&db, "127.0.0.2"), "partial", "{status}: {why}");
        assert!(why.contains("gave up after 5 runs"), "{why}");
        assert!(pending_urls(&db).is_empty());
        assert!(
            server.requested().len() <= 5 * 60,
            "{} requests",
            server.requested().len()
        );
    }
}

/// `/gnu/` lists `n` projects, each with three tarballs and a signature.
fn gnu(n: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let names: Vec<String> = (0..n).map(|i| format!("proj{i:03}")).collect();
    let top: Vec<_> = names.iter().map(folder).collect();
    add_listing(&mut site, "/gnu/", &top);
    for (i, name) in names.iter().enumerate() {
        let files = vec![
            item(format!("{name}-1.0.tar.gz"), MB + i as u64 * 1_000),
            item(format!("{name}-1.1.tar.xz"), 2 * MB + i as u64 * 1_000),
            item(format!("{name}-1.2.tar.gz"), 3 * MB + i as u64 * 1_000),
            item(format!("{name}-1.2.tar.gz.sig"), 488),
        ];
        add_listing(&mut site, &format!("/gnu/{name}/"), &files);
    }
    site
}

#[tokio::test]
async fn six_broken_folders_in_a_row_do_not_end_the_crawl() {
    let mut site = gnu(300);
    for i in 100..106 {
        site.insert(format!("/gnu/proj{i:03}/"), Route::text(500, "boom"));
    }
    let server = serve(site).await;
    let db = temp_db("six-broken");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("gnu/").unwrap()]);

    let mut runs = 0;
    while runs < 8 && host_status_or(&db, "127.0.0.2", "new") != "partial" {
        run_judged(vec![], &db).await;
        runs += 1;
    }

    // The first run stops after five errors in a row, and the next one goes on
    // from there: every folder that can be read is read. The six that cannot are
    // tried again, and the site is given up after five runs that ended in errors.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "partial", "{why}");
    assert!(why.contains("gave up after 5 runs"), "{why}");
    assert_eq!(runs, 5);
    assert_eq!(stored_dirs(&db), 1 + 294);
    assert_eq!(stored_files(&db), 294 * 4);
}

#[tokio::test]
async fn a_blocked_crawler_is_not_a_finished_crawl() {
    // The server answers the first 50 requests and then refuses everything.
    let inner = gnu(300);
    let server = serve_with(Arc::new(move |path, n| {
        if n > 50 {
            return Route::text(403, "forbidden");
        }
        inner
            .get(path)
            .cloned()
            .unwrap_or_else(|| Route::text(404, "not found"))
    }))
    .await;
    let db = temp_db("blocked");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("gnu/").unwrap()]);

    run_judged(vec![], &db).await;

    // Not `done`: 250 folders were never read, and the site says why.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    assert!(why.contains("refused"), "{why}");
    assert_eq!(strikes(&db, "127.0.0.2"), 1);
    assert!(pending_urls(&db).len() >= 240);
}

#[tokio::test]
async fn folders_that_failed_are_read_in_the_next_run() {
    // Three folders answer with a server error the first time they are asked for.
    let inner = gnu(40);
    let failed_once: Arc<Mutex<HashSet<String>>> = Arc::default();
    let server = serve_with(Arc::new(move |path, _| {
        let flaky = ["/gnu/proj007/", "/gnu/proj021/", "/gnu/proj033/"];
        if flaky.contains(&path) && failed_once.lock().unwrap().insert(path.to_string()) {
            return Route::text(500, "boom");
        }
        inner
            .get(path)
            .cloned()
            .unwrap_or_else(|| Route::text(404, "not found"))
    }))
    .await;
    let db = temp_db("flaky");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("gnu/").unwrap()]);

    run_judged(vec![], &db).await;

    // The other 37 folders are read, and the site is not called finished.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    assert!(why.contains("could not be read"), "{why}");
    assert_eq!(strikes(&db, "127.0.0.2"), 1);
    assert_eq!(stored_files(&db), 37 * 4);
    assert_eq!(pending_urls(&db).len(), 3);

    run_judged(vec![], &db).await;

    assert_eq!(host_status(&db, "127.0.0.2"), "done");
    assert_eq!(strikes(&db, "127.0.0.2"), 0);
    assert_eq!(stored_files(&db), 40 * 4);
    assert!(pending_urls(&db).is_empty());
}

#[tokio::test]
async fn dead_links_among_live_folders_do_not_end_a_crawl_and_are_not_retried() {
    // Every third folder of 300 is a dead link: 100 refusals, never two in a row.
    let mut site = gnu(300);
    for i in (0..300).step_by(3) {
        site.insert(format!("/gnu/proj{i:03}/"), Route::text(404, "gone"));
    }
    let server = serve(site).await;
    let db = temp_db("dead-links");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("gnu/").unwrap()]);

    run_judged(vec![], &db).await;

    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert_eq!(stored_files(&db), 200 * 4);
    assert!(pending_urls(&db).is_empty());
}

/// A WordPress network: `sites/<s>/<year>/<month>/` with 12 full-size pictures and
/// their thumbnails in every month, and, if `pdf`, one document in the first month.
fn wordpress_network(sites: usize, pdf: bool) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let ids: Vec<String> = (1..=sites).map(|s| format!("s{s}")).collect();
    let top: Vec<_> = ids.iter().map(folder).collect();
    add_listing(&mut site, "/wp-content/uploads/", &[folder("sites")]);
    add_listing(&mut site, "/wp-content/uploads/sites/", &top);
    for (s, id) in ids.iter().enumerate() {
        let years: Vec<String> = (2019..2024).map(|y| y.to_string()).collect();
        let list: Vec<_> = years.iter().map(folder).collect();
        add_listing(
            &mut site,
            &format!("/wp-content/uploads/sites/{id}/"),
            &list,
        );
        for year in &years {
            let months: Vec<String> = (1..=12).map(|m| format!("{m:02}")).collect();
            let list: Vec<_> = months.iter().map(folder).collect();
            add_listing(
                &mut site,
                &format!("/wp-content/uploads/sites/{id}/{year}/"),
                &list,
            );
            for month in &months {
                let mut files = Vec::new();
                for k in 0..12 {
                    let size = 80_000 + ((s * 5 + k) as u64 * 7_919) % 900_000;
                    files.push(item(format!("photo-{k}.jpg"), size));
                    files.push(item(format!("photo-{k}-150x150.jpg"), size / 30));
                }
                if pdf && s == 0 && year == "2019" && month == "01" {
                    files.push(item("brochure.pdf", 900_000));
                }
                let path = format!("/wp-content/uploads/sites/{id}/{year}/{month}/");
                add_listing(&mut site, &path, &files);
            }
        }
    }
    site
}

#[tokio::test]
async fn one_stray_document_does_not_multiply_the_cost_of_a_junk_site() {
    let mut costs = Vec::new();
    for pdf in [false, true] {
        let server = serve(wordpress_network(12, pdf)).await;
        let db = temp_db(&format!("wp-{pdf}"));
        add_waiting(
            &db,
            &[server
                .as_host("127.0.0.2")
                .join("wp-content/uploads/")
                .unwrap()],
        );

        run_judged(vec![], &db).await;

        let why = reason(&db, "127.0.0.2");
        assert_eq!(
            host_status(&db, "127.0.0.2"),
            "low_value",
            "pdf {pdf}: {why}"
        );
        assert_eq!(stored_files(&db), 0);
        costs.push(server.requested().len());
    }
    // 12 sites of 60 months each are 720 folders; junk is called on a fair sample of them.
    assert!(costs[0] < 600, "{} requests", costs[0]);
    assert!(costs[1] <= costs[0] * 3 / 2, "{costs:?}");
}

/// `/pub/` lists `n` folders; three of every four are dead links, and the rest hold
/// a tarball each.
fn mostly_dead_links(n: usize) -> HashMap<String, Route> {
    let mut site = HashMap::new();
    let names: Vec<String> = (0..n).map(|i| format!("f{i:03}")).collect();
    let top: Vec<_> = names.iter().map(folder).collect();
    add_listing(&mut site, "/pub/", &top);
    for (i, name) in names.iter().enumerate() {
        let path = format!("/pub/{name}/");
        if i % 4 == 0 {
            let files = [item(format!("{name}.tar.gz"), 3 * MB + i as u64)];
            add_listing(&mut site, &path, &files);
        } else {
            site.insert(path, Route::text(404, "gone"));
        }
    }
    site
}

#[tokio::test]
async fn folders_asked_for_count_against_the_budget_whether_or_not_they_answer() {
    let server = serve(mostly_dead_links(400)).await;
    let db = temp_db("budget-attempts");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("pub/").unwrap()]);
    let cfg = || CrawlConfig {
        max_dirs_per_host: 100,
        quality: Thresholds::default(),
        ..fast_config()
    };

    run_with_pending(vec![], &db, cfg()).await;

    // 100 folders asked for (the listing of `/pub/` and 99 of its sub-folders), not
    // 100 that answered: a site of dead links must not cost more than one of real ones.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused", "{why}");
    let first = server.requested().len();
    assert!(first <= 102, "{first} requests");
    assert!(pending_urls(&db).len() >= 300);

    // The next run starts with 300 folders waiting, more than its budget, and asks
    // for 100 of them.
    run_with_pending(vec![], &db, cfg()).await;

    let second = server.requested().len() - first;
    assert!(second <= 102, "{second} requests");
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");
}

#[tokio::test]
async fn the_depth_limit_holds_across_runs() {
    // A chain of 40 folders, one inside the next, crawled three folders at a time:
    // the limit is on how deep an address is, not on how far one run has walked.
    let mut site = HashMap::new();
    let mut path = String::from("/c/");
    for level in 0..40u64 {
        let next = format!("d{level}");
        let note = item(format!("note{level}.txt"), 1_000 + level);
        add_listing(&mut site, &path, &[folder(&next), note]);
        path = format!("{path}{next}/");
    }
    add_listing(&mut site, &path, &[item("end.txt", 5)]);
    let server = serve(site).await;
    let db = temp_db("depth-runs");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("c/").unwrap()]);
    let cfg = || CrawlConfig {
        max_depth: 6,
        max_dirs_per_host: 3,
        ..fast_config()
    };

    let mut runs = 0;
    while runs < 12 {
        run_with_pending(vec![], &db, cfg()).await;
        runs += 1;
        if host_status(&db, "127.0.0.2") != "paused" {
            break;
        }
    }

    assert_eq!(host_status(&db, "127.0.0.2"), "done");
    assert_eq!(stored_dirs(&db), 6);
    assert_eq!(runs, 2);
}

#[tokio::test]
async fn a_continued_site_whose_waiting_folders_are_gone_is_done_not_a_non_listing() {
    // The first run reads the listing and one project, and leaves five folders
    // waiting. By the next run they have been deleted.
    let inner = gnu(6);
    let deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = deleted.clone();
    let server = serve_with(Arc::new(move |path, _| {
        if flag.load(std::sync::atomic::Ordering::SeqCst) && path.starts_with("/gnu/proj") {
            return Route::text(404, "gone");
        }
        inner
            .get(path)
            .cloned()
            .unwrap_or_else(|| Route::text(404, "not found"))
    }))
    .await;
    let db = temp_db("folders-gone");
    add_waiting(&db, &[server.as_host("127.0.0.2").join("gnu/").unwrap()]);
    // (The quality check is off: one project is too little to keep, and this test is
    // about how the crawl ends.)
    let cfg = || CrawlConfig {
        max_dirs_per_host: 2,
        ..fast_config()
    };
    run_with_pending(vec![], &db, cfg()).await;
    assert_eq!(host_status(&db, "127.0.0.2"), "paused");
    assert_eq!(pending_urls(&db).len(), 5);

    deleted.store(true, std::sync::atomic::Ordering::SeqCst);
    run_with_pending(vec![], &db, cfg()).await;

    // Not "not a listing": the site has a listing and a project, and no more to read.
    let why = reason(&db, "127.0.0.2");
    assert_eq!(host_status(&db, "127.0.0.2"), "done", "{why}");
    assert!(pending_urls(&db).is_empty());
    assert_eq!(stored_files(&db), 4);
}
