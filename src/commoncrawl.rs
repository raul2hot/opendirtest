//! Discovery from the Common Crawl URL index.
//!
//! Apache (and nginx fancyindex) listings have column-sort links such as
//! `?C=N;O=D`. Common Crawl follows those links, so any URL in its index with
//! that query string is almost certainly a directory listing.
//!
//! The index is a set of Parquet files. Using HTTP range requests, we read the
//! small `url_query` column for every row, and the `url` column only for rows
//! that match. Nothing is sent to the sites themselves.

use std::collections::HashSet;
use std::io::Read;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arrow_array::cast::AsArray;
use arrow_array::{Array, BooleanArray, RecordBatch};
use arrow_schema::ArrowError;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt, TryStreamExt};
use parquet::arrow::arrow_reader::{ArrowPredicateFn, ArrowReaderOptions, RowFilter};
use parquet::arrow::async_reader::AsyncFileReader;
use parquet::arrow::{ParquetRecordBatchStreamBuilder, ProjectionMask};
use parquet::errors::ParquetError;
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};
use regex::Regex;
use reqwest::header::RANGE;
use reqwest::{Client, StatusCode};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::crawler::USER_AGENT;
use crate::filters;
use crate::store::Msg;

pub const DATA_URL: &str = "https://data.commoncrawl.org/";
pub const COLLINFO_URL: &str = "https://index.commoncrawl.org/collinfo.json";

const MAX_ATTEMPTS: u32 = 6;

pub struct DiscoverConfig {
    /// A crawl id such as `CC-MAIN-2026-30`, or `latest`.
    pub crawl: String,
    /// Scan at most this many index files that were not scanned before.
    pub max_files: usize,
    /// Index files scanned at the same time.
    pub parallel: usize,
    /// Index files already scanned in earlier runs.
    pub done_files: HashSet<String>,
    /// Finds inside skipped folders are replaced by the site's root.
    pub skip: filters::SkipList,
    pub data_url: Url,
    pub collinfo_url: Url,
}

impl DiscoverConfig {
    pub fn new(crawl: String, max_files: usize, parallel: usize, done: HashSet<String>) -> Self {
        Self {
            crawl,
            max_files,
            parallel,
            done_files: done,
            skip: filters::SkipList::default(),
            data_url: Url::parse(DATA_URL).unwrap(),
            collinfo_url: Url::parse(COLLINFO_URL).unwrap(),
        }
    }
}

/// Live counters, read by the progress printer.
#[derive(Default)]
pub struct DiscoverStats {
    pub files_planned: AtomicU64,
    pub files_done: AtomicU64,
    pub files_failed: AtomicU64,
    pub candidates: AtomicU64,
    pub bytes: AtomicU64,
}

pub struct DiscoverSummary {
    pub crawl: String,
    /// Index files in this crawl not scanned yet (after this run).
    pub files_left: usize,
}

/// Scans index files and sends the directory URLs found to the store as
/// candidates. Each fully scanned file is recorded, so runs can be resumed.
pub async fn discover(
    cfg: DiscoverConfig,
    tx: mpsc::Sender<Msg>,
    stop: CancellationToken,
    stats: Arc<DiscoverStats>,
) -> Result<DiscoverSummary> {
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()?;

    let crawl = if cfg.crawl.eq_ignore_ascii_case("latest") {
        tokio::select! {
            crawl = latest_crawl(&client, &cfg.collinfo_url) => crawl?,
            _ = stop.cancelled() => bail!("stopped"),
        }
    } else {
        cfg.crawl.clone()
    };
    let all_files = tokio::select! {
        files = index_files(&client, &cfg.data_url, &crawl) => files?,
        _ = stop.cancelled() => bail!("stopped"),
    };
    let todo: Vec<String> = all_files
        .iter()
        .filter(|path| !cfg.done_files.contains(*path))
        .take(cfg.max_files)
        .cloned()
        .collect();
    stats.files_planned.store(todo.len() as u64, Relaxed);
    let not_done = all_files
        .iter()
        .filter(|p| !cfg.done_files.contains(*p))
        .count();

    let source = format!("commoncrawl:{crawl}");
    let mut scans = futures::stream::iter(todo)
        .map(|path| {
            let url = cfg.data_url.join(&path);
            let (client, stats, stop) = (client.clone(), stats.clone(), stop.clone());
            let skip = cfg.skip.clone();
            // Each file on its own task, so decoding uses all CPU cores.
            let scan = tokio::spawn(async move {
                let file = HttpFile {
                    client,
                    url: url?,
                    stats,
                };
                scan_file(file, &skip, &stop).await
            });
            async move {
                let result = match scan.await {
                    Ok(result) => result,
                    Err(e) => Err(anyhow::anyhow!("scan task failed: {e}")),
                };
                (path, result)
            }
        })
        .buffer_unordered(cfg.parallel.max(1));

    let mut scanned = 0;
    loop {
        let next = tokio::select! {
            next = scans.next() => next,
            _ = stop.cancelled() => break,
        };
        let Some((path, result)) = next else { break };
        match result {
            Ok(found) => {
                scanned += 1;
                stats.files_done.fetch_add(1, Relaxed);
                stats.candidates.fetch_add(found.len() as u64, Relaxed);
                // One message, so the file is only marked done together with its finds.
                let msg = Msg::CcFileDone {
                    path,
                    urls: found.into_iter().collect(),
                    source: source.clone(),
                };
                tx.send(msg).await.context("database writer stopped")?;
            }
            Err(e) => {
                stats.files_failed.fetch_add(1, Relaxed);
                eprintln!("skipped {path}: {e:#}");
            }
        }
    }
    Ok(DiscoverSummary {
        crawl,
        files_left: not_done - scanned,
    })
}

/// The newest crawl id, e.g. `CC-MAIN-2026-30`.
async fn latest_crawl(client: &Client, collinfo: &Url) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Collection {
        id: String,
    }
    let hint =
        || format!("looking up the latest crawl at {collinfo} (or pass --crawl CC-MAIN-YYYY-WW)");
    let body = client
        .get(collinfo.clone())
        .send()
        .await
        .with_context(hint)?
        .error_for_status()
        .with_context(hint)?
        .bytes()
        .await
        .with_context(hint)?;
    let collections: Vec<Collection> =
        serde_json::from_slice(&body).context("reading the Common Crawl crawl list")?;
    collections
        .into_iter()
        .map(|c| c.id)
        .find(|id| id.starts_with("CC-MAIN-"))
        .context("the Common Crawl crawl list is empty")
}

/// Paths of the index files holding successful fetches (`subset=warc`).
async fn index_files(client: &Client, data: &Url, crawl: &str) -> Result<Vec<String>> {
    let url = data.join(&format!("crawl-data/{crawl}/cc-index-table.paths.gz"))?;
    let response = client.get(url.clone()).send().await?;
    if response.status() == StatusCode::NOT_FOUND {
        bail!("crawl {crawl} not found (no {url})");
    }
    let gz = response.error_for_status()?.bytes().await?;
    let mut text = String::new();
    flate2::read::MultiGzDecoder::new(&gz[..])
        .read_to_string(&mut text)
        .context("unpacking the index file list")?;
    let files: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|p| p.contains("/subset=warc/") && p.ends_with(".parquet"))
        .map(str::to_owned)
        .collect();
    if files.is_empty() {
        bail!("crawl {crawl} lists no index files");
    }
    Ok(files)
}

/// `url_query` values that only directory-listing sort links have
/// (Apache: `C=N;O=D`, nginx fancyindex: `C=N&O=A`).
pub fn is_sort_query(query: &str) -> bool {
    static SORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^C=[NMSD][;&]O=[AD]$").unwrap());
    SORT.is_match(query.trim_start_matches('?'))
}

/// The listing's own URL for a sort link like `https://h/pub/?C=N;O=D`.
pub fn listing_dir(url: &str) -> Option<Url> {
    let mut url = Url::parse(url).ok()?;
    if !url.query().is_some_and(is_sort_query) || !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_query(None);
    url.set_fragment(None);
    url.path().ends_with('/').then_some(url)
}

async fn scan_file(
    file: HttpFile,
    skip: &filters::SkipList,
    stop: &CancellationToken,
) -> Result<HashSet<Url>> {
    let options = ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Optional);
    let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, options).await?;
    let schema = builder.parquet_schema();
    for column in ["url", "url_query"] {
        if !schema.columns().iter().any(|c| c.path().string() == column) {
            bail!("index file has no `{column}` column");
        }
    }
    let predicate = ArrowPredicateFn::new(
        ProjectionMask::columns(schema, ["url_query"]),
        |batch: RecordBatch| {
            let queries = strings(batch.column(0).as_ref())?;
            Ok(BooleanArray::from_iter(
                queries.iter().map(|q| Some(q.is_some_and(is_sort_query))),
            ))
        },
    );
    let projection = ProjectionMask::columns(schema, ["url"]);
    let mut batches = builder
        .with_projection(projection)
        .with_row_filter(RowFilter::new(vec![Box::new(predicate)]))
        .with_batch_size(8192)
        .build()?;

    let mut found = HashSet::new();
    loop {
        let batch = tokio::select! {
            batch = batches.try_next() => batch?,
            _ = stop.cancelled() => bail!("stopped"),
        };
        let Some(batch) = batch else { break };
        for url in strings(batch.column(0).as_ref())?.into_iter().flatten() {
            // A public index can still point at private addresses; skip those.
            let Some(dir) = listing_dir(url).filter(filters::is_public_host) else {
                continue;
            };
            // Also try the site's root: a site with one listing often has more.
            // A find in a skipped folder (a package archive) only yields the root.
            let mut root = dir.clone();
            root.set_path("/");
            found.insert(root);
            if !skip.skips_folder(&dir) {
                found.insert(dir);
            }
        }
    }
    Ok(found)
}

/// The values of a string column, whichever Arrow string type it was read as.
/// Any other type is an error: silently matching nothing would mark the file
/// as scanned with no finds.
fn strings(column: &dyn Array) -> std::result::Result<Vec<Option<&str>>, ArrowError> {
    if let Some(a) = column.as_string_opt::<i32>() {
        Ok(a.iter().collect())
    } else if let Some(a) = column.as_string_opt::<i64>() {
        Ok(a.iter().collect())
    } else if let Some(a) = column.as_string_view_opt() {
        Ok(a.iter().collect())
    } else {
        Err(ArrowError::SchemaError(format!(
            "expected a string column, found {}",
            column.data_type()
        )))
    }
}

/// A remote Parquet file read with HTTP range requests.
struct HttpFile {
    client: Client,
    url: Url,
    stats: Arc<DiscoverStats>,
}

impl HttpFile {
    /// The file's length, from the `Content-Range` of a one-byte request.
    async fn len(&self) -> parquet::errors::Result<u64> {
        let (_, total) = self.fetch_with_total("bytes=0-0".into()).await?;
        total.ok_or_else(|| ParquetError::General(format!("no file size for {}", self.url)))
    }

    async fn fetch(&self, range: String) -> parquet::errors::Result<Bytes> {
        Ok(self.fetch_with_total(range).await?.0)
    }

    /// Fetches a byte range; also returns the total file size when the server says it.
    async fn fetch_with_total(
        &self,
        range: String,
    ) -> parquet::errors::Result<(Bytes, Option<u64>)> {
        let url = &self.url;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let error = match self
                .client
                .get(url.clone())
                .header(RANGE, &range)
                .send()
                .await
            {
                Ok(r) if r.status() == StatusCode::PARTIAL_CONTENT => {
                    let total = r
                        .headers()
                        .get(reqwest::header::CONTENT_RANGE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.rsplit('/').next())
                        .and_then(|v| v.parse().ok());
                    match r.bytes().await {
                        Ok(bytes) => {
                            self.stats.bytes.fetch_add(bytes.len() as u64, Relaxed);
                            return Ok((bytes, total));
                        }
                        Err(e) => e.to_string(),
                    }
                }
                // Common Crawl answers 503 "Slow Down" when busy.
                Ok(r)
                    if r.status() == StatusCode::TOO_MANY_REQUESTS
                        || r.status().is_server_error() =>
                {
                    format!("HTTP {}", r.status())
                }
                // A 200 would mean the whole file is coming; never download that.
                Ok(r) => {
                    let msg = format!("HTTP {} for {url} ({range})", r.status());
                    return Err(ParquetError::General(msg));
                }
                Err(e) => e.to_string(),
            };
            if attempt >= MAX_ATTEMPTS {
                return Err(ParquetError::General(format!("{error} for {url}")));
            }
            tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
        }
    }
}

impl AsyncFileReader for HttpFile {
    fn get_bytes(&mut self, range: Range<u64>) -> BoxFuture<'_, parquet::errors::Result<Bytes>> {
        async move {
            if range.is_empty() {
                return Ok(Bytes::new());
            }
            self.fetch(format!("bytes={}-{}", range.start, range.end - 1))
                .await
        }
        .boxed()
    }

    fn get_metadata<'a>(
        &'a mut self,
        options: Option<&'a ArrowReaderOptions>,
    ) -> BoxFuture<'a, parquet::errors::Result<Arc<ParquetMetaData>>> {
        async move {
            // The footer points at the page index earlier in the file, so the
            // reader needs the file length to fetch arbitrary ranges.
            let len = self.len().await?;
            let metadata = ParquetMetaDataReader::new()
                .with_arrow_reader_options(options)
                .with_prefetch_hint(Some(64 * 1024))
                .load_and_finish(&mut *self, len)
                .await?;
            Ok(Arc::new(metadata))
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_queries() {
        for q in ["C=N;O=D", "C=M;O=A", "?C=S;O=A", "C=D;O=D", "C=N&O=A"] {
            assert!(is_sort_query(q), "{q}");
        }
        for q in ["C=N;O=D;F=0", "c=n;o=d", "id=5", "", "C=X;O=A", "sort=name"] {
            assert!(!is_sort_query(q), "{q}");
        }
    }

    #[test]
    fn listing_dirs() {
        let dir = |u: &str| listing_dir(u).map(String::from);
        assert_eq!(
            dir("https://ftp.example.org/pub/?C=M;O=A").as_deref(),
            Some("https://ftp.example.org/pub/")
        );
        assert_eq!(dir("https://h.example/index.php?C=N;O=D"), None);
        assert_eq!(dir("https://h.example/pub/?page=2"), None);
        assert_eq!(dir("ftp://h.example/pub/?C=N;O=D"), None);
    }
}
