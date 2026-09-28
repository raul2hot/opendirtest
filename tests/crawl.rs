//! End-to-end: crawl local fake servers, then check what was requested and stored.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Route, listing, query_one, serve, temp_db};
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
    let (tx, writer) = store::spawn_writer(db.to_path_buf()).unwrap();
    crawler::crawl(seeds, pending, cfg, tx, stop, Arc::new(Stats::default()))
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
        requested <= 105,
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
