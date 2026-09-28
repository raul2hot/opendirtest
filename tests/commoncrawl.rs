//! Common Crawl discovery against a local fake of data.commoncrawl.org, serving
//! a synthetic index file with the same columns as the real one.

mod common;

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use arrow_array::{ArrayRef, Int32Array, RecordBatch, StringArray};
use common::{Route, serve, temp_db};
use opendirtest::commoncrawl::{self, DiscoverConfig, DiscoverStats};
use opendirtest::store;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use tokio_util::sync::CancellationToken;

const CRAWL: &str = "CC-MAIN-2099-01";
const ROWS: usize = 200_000;

/// A pseudo-random, poorly compressible token, like the paths in real URLs.
fn token(i: usize) -> String {
    let mut x = (i as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    x ^= x >> 29;
    format!("{x:016x}")
}

/// An index file where a few rows are directory-listing sort links.
fn index_file(listing_rows: &[(usize, &str, &str)]) -> Vec<u8> {
    let mut urls: Vec<String> = Vec::with_capacity(ROWS);
    let mut queries: Vec<Option<String>> = Vec::with_capacity(ROWS);
    for i in 0..ROWS {
        let t = token(i);
        if i % 10 == 0 {
            urls.push(format!("https://site{}.example/search?q={t}", i / 1000));
            queries.push(Some(format!("q={t}")));
        } else {
            urls.push(format!("https://site{}.example/{t}/page.html", i / 1000));
            queries.push(None);
        }
    }
    for &(row, url, query) in listing_rows {
        urls[row] = url.to_string();
        queries[row] = Some(query.to_string());
    }
    let status: Vec<i32> = vec![200; ROWS];
    let batch = RecordBatch::try_from_iter(vec![
        ("url", Arc::new(StringArray::from(urls)) as ArrayRef),
        (
            "url_query",
            Arc::new(StringArray::from(queries)) as ArrayRef,
        ),
        (
            "fetch_status",
            Arc::new(Int32Array::from(status)) as ArrayRef,
        ),
    ])
    .unwrap();

    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
        .set_max_row_group_row_count(Some(50_000))
        .set_data_page_row_count_limit(2_000)
        .set_statistics_enabled(EnabledStatistics::Page)
        .build();
    let mut out = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut out, batch.schema(), Some(props)).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    out
}

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

fn file_path(part: usize) -> String {
    format!("cc-index/table/cc-main/warc/crawl={CRAWL}/subset=warc/part-{part:05}.zstd.parquet")
}

async fn fake_common_crawl() -> (common::Server, usize) {
    let with_listings = index_file(&[
        (120_000, "https://ftp.example.org/pub/?C=N;O=D", "C=N;O=D"),
        (120_001, "https://ftp.example.org/pub/?C=M;O=A", "C=M;O=A"),
        (
            120_002,
            "https://ftp.example.org/pub/linux/?C=S;O=A",
            "C=S;O=A",
        ),
        (
            170_500,
            "https://mirror.example.net/data/?C=N&O=A",
            "C=N&O=A",
        ),
        // A package pool on a distro mirror: on the skip list.
        (
            180_000,
            "https://deb.example.edu/ubuntu/pool/main/?C=M;O=A",
            "C=M;O=A",
        ),
        // Website internals: nothing suggests a public archive.
        (
            185_000,
            "https://blog.example.com/wp-content/uploads/2020/?C=N;O=D",
            "C=N;O=D",
        ),
        (
            185_001,
            "https://random.example.org/stuff/?C=M;O=A",
            "C=M;O=A",
        ),
        // Sort-like query on a page that is not a directory: ignored.
        (
            170_501,
            "https://app.example.com/list.php?C=N;O=D",
            "C=N;O=D",
        ),
    ]);
    let without_listings = index_file(&[]);
    let size = with_listings.len();
    let paths = format!(
        "{}\n{}\ncc-index/table/cc-main/warc/crawl={CRAWL}/subset=crawldiagnostics/part-00000.parquet\n",
        file_path(0),
        file_path(1)
    );
    let collinfo =
        format!(r#"[{{"id": "{CRAWL}", "name": "test crawl"}}, {{"id": "CC-MAIN-2098-52"}}]"#);
    let routes: HashMap<String, Route> = [
        (
            "/collinfo.json".to_string(),
            Route::new(200, Some("application/json"), collinfo),
        ),
        (
            format!("/crawl-data/{CRAWL}/cc-index-table.paths.gz"),
            Route::new(200, Some("application/octet-stream"), gzip(&paths)),
        ),
        (
            format!("/{}", file_path(0)),
            Route::new(200, None, with_listings),
        ),
        (
            format!("/{}", file_path(1)),
            Route::new(200, None, without_listings),
        ),
    ]
    .into_iter()
    .collect();
    (serve(routes).await, size)
}

fn config(server: &common::Server, max_files: usize, done: HashSet<String>) -> DiscoverConfig {
    let mut cfg = DiscoverConfig::new("latest".into(), max_files, 2, done);
    cfg.skip = opendirtest::filters::SkipList::from_lines(&["/pool/".to_string()]);
    cfg.data_url = server.base.clone();
    cfg.collinfo_url = server.base.join("collinfo.json").unwrap();
    cfg
}

async fn run(
    cfg: DiscoverConfig,
    db: &std::path::Path,
) -> (commoncrawl::DiscoverSummary, Arc<DiscoverStats>) {
    let (tx, writer) = store::spawn_writer(db.to_path_buf()).unwrap();
    let stats = Arc::new(DiscoverStats::default());
    let summary = commoncrawl::discover(cfg, tx, CancellationToken::new(), stats.clone())
        .await
        .unwrap();
    writer.join().unwrap().unwrap();
    (summary, stats)
}

#[tokio::test]
async fn finds_listings_reading_only_a_fraction_of_the_index() {
    let (server, file_size) = fake_common_crawl().await;
    let db = temp_db("cc");

    let (summary, stats) = run(config(&server, 10, HashSet::new()), &db).await;

    assert_eq!(summary.crawl, CRAWL);
    assert_eq!(summary.files_left, 0);
    assert_eq!(stats.files_done.load(Relaxed), 2);
    assert_eq!(stats.files_failed.load(Relaxed), 0);
    // Two listings show no sign of a public archive and are left out.
    assert_eq!(stats.rejected.load(Relaxed), 2);

    let conn = store::open(&db).unwrap();
    let mut found: Vec<String> = store::pending_hosts(&conn, 100, &HashSet::new())
        .unwrap()
        .into_iter()
        .flat_map(|h| h.urls.into_iter().map(String::from))
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            // Each site's root is tried too; the skipped pool only yields its root.
            "https://deb.example.edu/",
            "https://ftp.example.org/",
            "https://ftp.example.org/pub/",
            "https://ftp.example.org/pub/linux/",
            "https://mirror.example.net/",
            "https://mirror.example.net/data/"
        ]
    );
    let source: String = conn
        .query_row("SELECT DISTINCT source FROM candidates", [], |r| r.get(0))
        .unwrap();
    assert_eq!(source, format!("commoncrawl:{CRAWL}"));

    // The url column is only fetched where a sort link was found.
    let sent = server.sent.lock().unwrap().clone();
    let read = sent[&format!("/{}", file_path(0))] as usize;
    eprintln!("downloaded {read} of {file_size} bytes");
    assert!(
        read * 3 < file_size,
        "downloaded {read} of {file_size} bytes: too much of the file"
    );
    // The crawldiagnostics subset is never touched.
    assert!(
        !server
            .requested()
            .iter()
            .any(|p| p.contains("crawldiagnostics/"))
    );
}

#[tokio::test]
async fn resumes_where_the_last_run_stopped() {
    let (server, _) = fake_common_crawl().await;
    let db = temp_db("cc-resume");

    let (first, _) = run(config(&server, 1, HashSet::new()), &db).await;
    assert_eq!(first.files_left, 1);

    let done = store::done_cc_files(&store::open(&db).unwrap()).unwrap();
    assert_eq!(done.len(), 1);
    let (second, stats) = run(config(&server, 10, done), &db).await;
    assert_eq!(stats.files_done.load(Relaxed), 1);
    assert_eq!(second.files_left, 0);

    let done = store::done_cc_files(&store::open(&db).unwrap()).unwrap();
    let (third, stats) = run(config(&server, 10, done), &db).await;
    assert_eq!(stats.files_planned.load(Relaxed), 0);
    assert_eq!(third.files_left, 0);
}

#[test]
fn listing_dir_from_index_urls() {
    let dir = commoncrawl::listing_dir("https://ftp.example.org/pub/?C=M;O=A");
    assert_eq!(dir.unwrap().as_str(), "https://ftp.example.org/pub/");
}
