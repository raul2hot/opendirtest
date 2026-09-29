//! The crawler. Each host gets its own task that walks the host's directory tree
//! one request at a time. All politeness state (robots.txt, pacing, back-off)
//! lives in that task, so hosts never need to coordinate.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use anyhow::Result;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION, RETRY_AFTER};
use reqwest::{Client, Response, StatusCode};
use texting_robots::Robot;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::filters::{self, Sensitivity};
use crate::listing::{self, Entry, Listing};
use crate::quality::{self, Progress, Thresholds, Waiting};
use crate::safety::{
    DROP_SENSITIVE_EXPOSURES, ENFORCE_PER_HOST_RATE_LIMIT, FOLLOW_LISTED_LINKS_ONLY,
    HONOR_OPT_OUT_LIST, RESPECT_ROBOTS_TXT, SEND_IDENTIFYING_USER_AGENT,
};
use crate::store::{self, HostStatus, Msg, PendingHost, RESUME_SOURCE};

/// Product token matched against `User-agent:` lines in robots.txt.
pub const BOT_TOKEN: &str = "opendirtest";
pub const USER_AGENT: &str = concat!(
    "opendirtest/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/raul2hot/opendirtest)"
);
/// `candidates.source` for directory links found on other sites' listings.
pub const LINK_SOURCE: &str = "link";

/// The default for `CrawlConfig::max_listing_bytes`. A folder of 50,000 files is
/// about 11 MB as an Apache table.
pub const MAX_LISTING_BYTES: usize = 32 * 1024 * 1024;
/// RFC 9309 asks crawlers to parse at least 500 KiB.
const MAX_ROBOTS_BYTES: usize = 500 * 1024;
const MAX_URL_LEN: usize = 2048;
/// RFC 9309 asks crawlers to follow at least five robots.txt redirects.
const MAX_REDIRECTS: usize = 5;
const MAX_RETRIES: u32 = 3;
const MAX_CONSECUTIVE_ERRORS: u32 = 5;
/// This many folders in a row refused with 403, 404 and the like end the run: the
/// server is blocking us, or the listing is full of dead links.
const MAX_REFUSED_IN_A_ROW: usize = 50;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Hosts asking for a longer Crawl-delay than this are skipped rather than
/// holding a crawl slot for days.
const MAX_CRAWL_DELAY: Duration = Duration::from_secs(60);
/// Directories past the per-run budget saved for the next run, at most (per host).
const MAX_SAVED_OVERFLOW: usize = 50_000;
/// The early check of a new site is made at every this many folders.
const PROBE_EVERY: u64 = 8;
/// How often the scheduler looks for newly found sites while slots are free.
const POLL_EVERY: Duration = Duration::from_secs(2);
/// A site you added that has moved to another host passes its trust on to the
/// new address. At most this many such addresses per crawl of one site, so a
/// site that redirects every folder elsewhere cannot fill the queue.
pub const MAX_MOVED_SEEDS: usize = 3;

pub struct CrawlConfig {
    /// Hosts crawled at the same time.
    pub concurrency: usize,
    pub max_dirs_per_host: u64,
    pub max_depth: usize,
    /// Minimum time between request starts on one host.
    pub per_host_delay: Duration,
    /// Domains whose owners opted out.
    pub optout: Vec<String>,
    /// Hosts dropped as sensitive exposures in earlier runs.
    pub sensitive_hosts: HashSet<String>,
    /// Sites and folders not to crawl (`lists/skip.txt`).
    pub skip: filters::SkipList,
    /// Record links to local and private-network hosts as sites to crawl.
    /// Only for tests against local servers.
    pub allow_private_links: bool,
    /// Sites you did not add are dropped if they hold less than this.
    pub quality: Thresholds,
    /// Record links to any directory, not only ones that look like a public
    /// archive (`filters::has_archive_signal`).
    pub broad: bool,
    /// A listing page is read up to this many bytes; a longer one is cut short (and
    /// the site's reason says so).
    pub max_listing_bytes: usize,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            concurrency: 256,
            max_dirs_per_host: 5_000,
            max_depth: 32,
            per_host_delay: Duration::from_secs(1),
            optout: Vec::new(),
            sensitive_hosts: HashSet::new(),
            skip: filters::SkipList::default(),
            allow_private_links: false,
            quality: Thresholds::default(),
            broad: false,
            max_listing_bytes: MAX_LISTING_BYTES,
        }
    }
}

/// Live counters, read by the progress printer.
#[derive(Default)]
pub struct Stats {
    pub hosts_total: AtomicU64,
    pub hosts_started: AtomicU64,
    pub hosts_done: AtomicU64,
    pub requests: AtomicU64,
    pub listings: AtomicU64,
    pub entries: AtomicU64,
    pub errors: AtomicU64,
}

/// Hosts waiting in the database (the `candidates` table).
pub struct Pending {
    pub db: PathBuf,
    /// Take at most this many hosts in this run (`None`: no limit).
    pub max_hosts: Option<usize>,
}

/// Crawls the sites you named (`named`, from `store::named_sites`), and then,
/// with `pending`, the hosts waiting in the database. The database is re-read as
/// slots free up, so sites found during the run are crawled in the same run.
///
/// Returns when nothing is left, or soon after `stop` is cancelled. Hosts that
/// were running then are recorded as paused, with what is left of their crawl
/// saved for the next run.
pub async fn crawl(
    named: Vec<PendingHost>,
    pending: Option<Pending>,
    cfg: CrawlConfig,
    tx: mpsc::Sender<Msg>,
    stop: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let client = build_client()?;
    let mut ready: VecDeque<PendingHost> = named.into();
    let source = match &pending {
        Some(p) => Some(store::open(&p.db)?),
        None => None,
    };
    let max_hosts = pending.and_then(|p| p.max_hosts).unwrap_or(usize::MAX);

    let cfg = Arc::new(cfg);
    let slots = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut tasks = JoinSet::new();
    // Every host started in this run; they are never started twice.
    let mut dispatched: HashSet<String> = HashSet::new();
    let mut taken = 0;
    let mut last_poll: Option<Instant> = None;

    loop {
        if stop.is_cancelled() {
            break;
        }
        let free = slots.available_permits();
        let due = tasks.is_empty() || last_poll.is_none_or(|t| t.elapsed() >= POLL_EVERY);
        let want = free.min(max_hosts - taken);
        if ready.is_empty() && source.is_some() && due && want > 0 {
            // Commit what finished hosts found, so the query sees it.
            flush(&tx).await;
            if let Some(conn) = &source {
                let batch = store::pending_hosts(conn, want, &dispatched)?;
                taken += batch.len();
                ready.extend(batch);
            }
            last_poll = Some(Instant::now());
        }

        match ready.pop_front() {
            Some(site) => {
                if !dispatched.insert(site.host.clone()) {
                    continue;
                }
                let permit = tokio::select! {
                    permit = slots.clone().acquire_owned() => permit?,
                    _ = stop.cancelled() => break,
                };
                stats.hosts_total.fetch_add(1, Relaxed);
                let worker = HostCrawl {
                    host: site.host,
                    trusted: site.trusted,
                    first_run: !site.known,
                    seed_urls: site.seeds.iter().map(Url::to_string).collect(),
                    progress: site.progress,
                    client: client.clone(),
                    pacer: Pacer::new(cfg.per_host_delay),
                    cfg: cfg.clone(),
                    tx: tx.clone(),
                    stop: stop.clone(),
                    stats: stats.clone(),
                    robots: HashMap::new(),
                    robots_blocked: None,
                    last_error: None,
                    moved_seeds: 0,
                };
                let urls = site.urls;
                tasks.spawn(async move {
                    worker.run(urls).await;
                    drop(permit);
                });
                continue;
            }
            // Nothing queued, nothing running, and the database had nothing new.
            None if tasks.is_empty() => break,
            None => {}
        }
        tokio::select! {
            Some(result) = tasks.join_next() => report_panic(result),
            _ = tokio::time::sleep(POLL_EVERY) => {}
            _ = stop.cancelled() => break,
        }
    }
    while let Some(result) = tasks.join_next().await {
        report_panic(result);
    }
    Ok(())
}

/// Waits until the database writer has committed everything sent so far.
async fn flush(tx: &mpsc::Sender<Msg>) {
    let (reply, committed) = oneshot::channel();
    if tx.send(Msg::Flush(reply)).await.is_ok() {
        let _ = committed.await;
    }
}

fn report_panic(result: Result<(), tokio::task::JoinError>) {
    if let Err(e) = result {
        eprintln!("a host task failed: {e}");
    }
}

fn build_client() -> reqwest::Result<Client> {
    // Redirects are followed by hand, so every hop gets a robots.txt check and pacing.
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .redirect(reqwest::redirect::Policy::none());
    if SEND_IDENTIFYING_USER_AGENT {
        builder = builder.user_agent(USER_AGENT);
    }
    builder.build()
}

/// robots.txt rules for one origin (scheme, host and port).
enum Robots {
    AllowAll,
    /// Stay out of the whole origin; the text says why.
    DisallowAll(String),
    /// The server could not be reached at all.
    Unreachable(String),
    Rules(Box<Robot>),
}

/// Spaces out requests to one host.
struct Pacer {
    gap: Duration,
    next: Instant,
    last_start: Option<Instant>,
}

impl Pacer {
    fn new(gap: Duration) -> Self {
        Self {
            gap: if ENFORCE_PER_HOST_RATE_LIMIT {
                gap
            } else {
                Duration::ZERO
            },
            next: Instant::now(),
            last_start: None,
        }
    }

    /// Widens the gap, starting from the request that was just sent.
    fn slow_down_to(&mut self, gap: Duration) {
        if ENFORCE_PER_HOST_RATE_LIMIT {
            self.gap = self.gap.max(gap);
            if let Some(last) = self.last_start {
                self.next = self.next.max(last + self.gap);
            }
        }
    }

    fn back_off(&mut self, wait: Duration) {
        self.next = self.next.max(Instant::now() + wait);
    }

    /// Waits for the next request slot. Returns false if the crawl was stopped.
    async fn wait(&mut self, stop: &CancellationToken) -> bool {
        tokio::select! {
            _ = tokio::time::sleep_until(self.next) => {}
            _ = stop.cancelled() => return false,
        }
        let now = Instant::now();
        self.last_start = Some(now);
        self.next = now + self.gap;
        true
    }
}

struct Page {
    url: Url,
    content_type: Option<String>,
    body: String,
    /// The listing was longer than `MAX_BODY_BYTES` and was cut short.
    truncated: bool,
}

enum Fetch {
    Page(Page),
    /// Nothing usable here (a file, robots.txt says no, ...).
    Skipped,
    /// The server refused the folder (403, 404, ...), with the status line.
    Refused(String),
    Failed(String),
    Stopped,
}

enum Access {
    Allowed,
    Blocked,
    Stopped,
}

enum Outcome {
    Stopped,
    Failed(String),
}

struct HostCrawl {
    host: String,
    /// You added the site: it is never judged by the quality check, and only
    /// strong sensitive names can drop it.
    trusted: bool,
    /// Its first run (not a continuation).
    first_run: bool,
    /// The URLs you added yourself, as text. Only a crawl started from one of these
    /// passes trust on when it turns out to have moved.
    seed_urls: HashSet<String>,
    /// What was read of the site in earlier runs, for one that continues.
    progress: Option<Progress>,
    client: Client,
    cfg: Arc<CrawlConfig>,
    tx: mpsc::Sender<Msg>,
    stop: CancellationToken,
    stats: Arc<Stats>,
    pacer: Pacer,
    /// Keyed by origin: one host can serve http and https, or several ports.
    robots: HashMap<String, Robots>,
    /// Why robots.txt kept us out, if it did.
    robots_blocked: Option<String>,
    last_error: Option<String>,
    /// Redirect targets recorded as seeds so far (`MAX_MOVED_SEEDS`).
    moved_seeds: usize,
}

/// What to record for a finished host.
struct Report {
    status: HostStatus,
    server: Option<&'static str>,
    dirs: u64,
    reason: Option<String>,
    /// Delete what was stored for the host.
    purge: bool,
    /// The run ended because of errors or refusals, not because the crawl is over.
    failed: bool,
}

impl HostCrawl {
    async fn run(mut self, seeds: Vec<Url>) {
        self.stats.hosts_started.fetch_add(1, Relaxed);
        if let Some(report) = self.walk(seeds).await {
            let msg = Msg::HostDone {
                host: self.host.clone(),
                status: report.status,
                server: report.server.map(str::to_owned),
                dirs: report.dirs,
                reason: report.reason,
                purge: report.purge,
                trusted: self.trusted,
                judge: (!self.trusted && self.cfg.quality.enabled()).then_some(self.cfg.quality),
                failed: report.failed,
            };
            let _ = self.tx.send(msg).await;
        }
        self.stats.hosts_done.fetch_add(1, Relaxed);
    }

    /// Breadth-first walk of the host's directory tree. `None` means nothing
    /// should be recorded (stopped before anything happened, or already dropped).
    async fn walk(&mut self, seeds: Vec<Url>) -> Option<Report> {
        if HONOR_OPT_OUT_LIST && filters::host_opted_out(&self.host, &self.cfg.optout) {
            // Also removes anything indexed before the owner opted out.
            return Some(Report {
                status: HostStatus::OptedOut,
                server: None,
                dirs: 0,
                reason: Some("on the opt-out list".into()),
                purge: true,
                failed: false,
            });
        }
        if DROP_SENSITIVE_EXPOSURES && self.cfg.sensitive_hosts.contains(&self.host) {
            return None; // keeps the reason recorded when it was dropped
        }
        if self.cfg.skip.skips_host(&self.host) {
            return Some(Report {
                status: HostStatus::Skipped,
                server: None,
                dirs: 0,
                reason: Some("on the skip list".into()),
                purge: true,
                failed: false,
            });
        }

        let started_from = seeds.clone();
        let mut seeds: Vec<Url> = seeds
            .into_iter()
            .filter(|u| !self.cfg.skip.skips_folder(u))
            .collect();
        if seeds.is_empty() {
            // Every folder this site was found by is on the skip list (a link into a
            // mirror's `/pool/`). A first run reads the site's front page instead, which
            // may hold more than the folder it was found through; a site that continues
            // has nothing left to read.
            let front = started_from
                .first()
                .and_then(|u| u.join("/").ok())
                .filter(|root| self.first_run && !self.cfg.skip.skips_folder(root));
            match front {
                Some(root) => seeds.push(filters::canonical_url(&root)),
                None => {
                    let (status, why) = if self.first_run {
                        (
                            HostStatus::Skipped,
                            "every folder it was found by is on the skip list",
                        )
                    } else {
                        (
                            HostStatus::Done,
                            "nothing left to read outside skipped folders",
                        )
                    };
                    return Some(Report {
                        status,
                        server: None,
                        dirs: 0,
                        reason: Some(why.into()),
                        purge: false,
                        failed: false,
                    });
                }
            }
        }
        // The depth of a folder is how deep its address is, so that a site continued
        // from a saved frontier is not given a fresh depth allowance every run.
        let mut queue: VecDeque<(Url, usize)> = seeds
            .into_iter()
            .map(|u| {
                let depth = filters::path_depth(u.as_str());
                (u, depth)
            })
            .collect();
        let mut seen: HashSet<String> = queue.iter().map(|(u, _)| u.to_string()).collect();
        let mut listings = Listings::default();
        let mut server = None;
        // Listings read this run, and folders asked for (the budget counts these, so
        // that a site full of dead links costs no more than one full of listings).
        let mut dirs = 0u64;
        let mut visited = 0u64;
        let mut stopped = false;
        let mut budget_reached = false;
        let mut overflow_saved = 0;
        // How deep the folders saved past this run's budget are, for `judge_crawling`.
        let mut overflow_depths: BTreeMap<usize, u64> = BTreeMap::new();
        let mut gave_up: Option<String> = None;
        let mut errors_in_a_row = 0;
        // Folders refused (403, 404, ...) one after another, and folders that could
        // not be read at all: both wait for the next run instead of being forgotten
        // (refusals only when they end the run, since a dead link is nothing to retry).
        let mut refused_in_a_row: Vec<Url> = Vec::new();
        let mut failed: Vec<Url> = Vec::new();
        let mut truncated = 0u32;
        // A new site you did not add is judged early, so junk does not hold a crawl
        // slot: from PROBE_DIRS folders on, by what its files look like. A site that
        // continues brings what was read in earlier runs.
        let mut progress = self.progress.take().unwrap_or_default();
        let early_judge = (!self.trusted && self.cfg.quality.enabled()).then_some(self.cfg.quality);

        while let Some((url, depth)) = queue.pop_front() {
            if self.stop.is_cancelled() || visited >= self.cfg.max_dirs_per_host {
                stopped = self.stop.is_cancelled();
                budget_reached = !stopped;
                queue.push_front((url, depth));
                break;
            }
            visited += 1;
            let top = self.seed_urls.contains(url.as_str());
            let page = match self.fetch_page(url.clone(), top).await {
                Fetch::Page(page) => page,
                Fetch::Skipped => {
                    errors_in_a_row = 0;
                    refused_in_a_row.clear();
                    continue;
                }
                Fetch::Refused(why) => {
                    errors_in_a_row = 0;
                    refused_in_a_row.push(url);
                    if refused_in_a_row.len() >= MAX_REFUSED_IN_A_ROW {
                        gave_up = Some(format!(
                            "the server refused {MAX_REFUSED_IN_A_ROW} folders in a row (last: {why})"
                        ));
                        self.last_error = Some(why);
                        failed.append(&mut refused_in_a_row);
                        break;
                    }
                    continue;
                }
                Fetch::Stopped => {
                    stopped = true;
                    queue.push_front((url, depth));
                    break;
                }
                Fetch::Failed(error) => {
                    self.stats.errors.fetch_add(1, Relaxed);
                    errors_in_a_row += 1;
                    refused_in_a_row.clear();
                    failed.push(url);
                    if errors_in_a_row >= MAX_CONSECUTIVE_ERRORS {
                        gave_up = Some(format!("too many errors, last: {error}"));
                        self.last_error = Some(error);
                        break;
                    }
                    self.last_error = Some(error);
                    continue;
                }
            };
            errors_in_a_row = 0;
            refused_in_a_row.clear();
            truncated += u32::from(page.truncated);

            // Parsing a big page takes a while; keep it off the async threads.
            let parsed = tokio::task::spawn_blocking(move || {
                let listing = listing::parse(&page.url, page.content_type.as_deref(), &page.body);
                (page.url, listing)
            })
            .await;
            let Ok((page_url, Some(mut listing))) = parsed else {
                continue;
            };
            dirs += 1;
            self.stats.listings.fetch_add(1, Relaxed);
            server.get_or_insert(listing.server.as_str());

            if DROP_SENSITIVE_EXPOSURES
                && let Some(why) = check_exposure(&page_url, &mut listing, self.trusted)
            {
                // The purge and the status are stored together, in one message.
                return Some(Report {
                    status: HostStatus::Sensitive,
                    server,
                    dirs,
                    reason: Some(why),
                    purge: true,
                    failed: false,
                });
            }

            let Listing {
                entries,
                other_dirs,
                external_dirs,
                ..
            } = listing;
            if !external_dirs.is_empty() {
                self.save_candidates(external_dirs).await;
            }

            // The sub-folders worth walking: not skipped, too deep, too long or
            // looping. A leaf is a folder with none, so the crawl goes no further
            // from it.
            let mut next: Vec<Url> = entries
                .iter()
                .filter(|e| e.is_dir)
                .map(|e| e.url.clone())
                .collect();
            if !FOLLOW_LISTED_LINKS_ONLY {
                next.extend(other_dirs);
            }
            next.retain(|dir| {
                depth < self.cfg.max_depth
                    && dir.as_str().len() <= MAX_URL_LEN
                    && !has_repeating_segments(dir.path())
                    && !self.cfg.skip.skips_folder(dir)
            });
            let leaf = next.is_empty();

            // Content already seen on this host (a symlink loop or an alias such
            // as `latest -> 2.4.1`): keep the entries, but don't walk it again.
            if !listings.is_copy(&page_url, &entries) {
                // Past this run's budget, directories go to the database for the
                // next run instead of into memory.
                let mut overflow = Vec::new();
                for dir in next {
                    if seen.insert(dir.to_string()) {
                        if queue.len() as u64 + visited < self.cfg.max_dirs_per_host {
                            queue.push_back((dir, depth + 1));
                        } else if overflow_saved < MAX_SAVED_OVERFLOW {
                            overflow_saved += 1;
                            *overflow_depths
                                .entry(filters::path_depth(dir.as_str()))
                                .or_default() += 1;
                            overflow.push(dir);
                        }
                    }
                }
                if !overflow.is_empty() {
                    budget_reached = true;
                    let msg = Msg::Candidates {
                        urls: overflow,
                        source: RESUME_SOURCE.to_string(),
                    };
                    let _ = self.tx.send(msg).await;
                }
            }

            // A new site you did not add is judged early, on what it holds so far
            // (`Thresholds::judge_crawling`): any big or useful file anywhere is a sign
            // of value, but junk is only called on the deepest layer of leaf folders
            // read, since a tree's downloads are at its bottom and its top is README
            // and index pages. Empty folders leave nothing stored, so they do not count.
            if early_judge.is_some() {
                progress.folders_read += 1;
                let mut files = 0;
                for e in entries.iter().filter(|e| !e.is_dir) {
                    progress.note_file(&e.name, e.size);
                    files += 1;
                }
                if leaf && !entries.is_empty() {
                    progress.note_leaf(filters::path_depth(page_url.as_str()), files);
                }
            }
            // Not at every folder: looking at the queue costs a little.
            if let Some(thresholds) = early_judge
                && progress.folders_read >= quality::PROBE_DIRS
                && dirs.is_multiple_of(PROBE_EVERY)
            {
                let level = progress.level;
                let waiting = || waiting_at(&queue, &overflow_depths, level);
                if let Some(why) = thresholds.judge_crawling(&progress, waiting) {
                    return Some(Report {
                        status: HostStatus::LowValue,
                        server,
                        dirs,
                        reason: Some(why),
                        purge: true,
                        failed: false,
                    });
                }
            }

            self.stats.entries.fetch_add(entries.len() as u64, Relaxed);
            let msg = Msg::Entries {
                host: self.host.clone(),
                entries,
                leaf,
            };
            if self.tx.send(msg).await.is_err() {
                // The database writer is gone, so nothing more can be saved.
                self.stop.cancel();
                stopped = true;
                break;
            }
        }

        if stopped && dirs == 0 {
            return None; // untouched: its candidates stay for the next run
        }
        let unfinished = (stopped || budget_reached) && (!queue.is_empty() || overflow_saved > 0);
        // Folders that could not be read wait for the next run, so a site with a few
        // broken folders is not called finished.
        let retry = !failed.is_empty();
        let mut failed_run = false;
        let (status, reason) = match dirs {
            0 if self.robots_blocked.is_some() => {
                (HostStatus::RobotsDisallowed, self.robots_blocked.take())
            }
            0 if self.last_error.is_some() && !self.first_run => {
                // A site continued from an earlier run that could not be reached this
                // time (down for the night, a server error on its last folders): keep
                // it paused with what was waiting and try again, instead of ending it.
                let error = self.last_error.take().unwrap_or_default();
                let msg = Msg::Paused {
                    host: self.host.clone(),
                    finished: Vec::new(),
                    frontier: started_from,
                };
                let _ = self.tx.send(msg).await;
                failed_run = true;
                let why = format!("could not be reached this run ({error}); will try again");
                (HostStatus::Paused, Some(why))
            }
            0 if self.last_error.is_some() => (HostStatus::Unreachable, self.last_error.take()),
            // What a continued site had waiting is gone (deleted folders, dead links):
            // it has been read as far as it can be, and what it holds is judged as final.
            0 if !self.first_run => (HostStatus::Done, None),
            0 => (HostStatus::NotListing, None),
            _ if gave_up.is_some() || unfinished || retry => {
                let frontier = queue
                    .into_iter()
                    .map(|(url, _)| url)
                    .chain(failed)
                    .collect();
                let msg = Msg::Paused {
                    host: self.host.clone(),
                    finished: started_from,
                    frontier,
                };
                let _ = self.tx.send(msg).await;
                let why = if let Some(why) = gave_up {
                    failed_run = true;
                    format!("{why}; continues next run")
                } else if stopped {
                    "stopped; continues next run".to_string()
                } else if budget_reached {
                    "directory budget for this run reached; continues next run".to_string()
                } else {
                    failed_run = true;
                    let error = self.last_error.take().unwrap_or_default();
                    format!("some folders could not be read ({error}); will try them again")
                };
                (HostStatus::Paused, Some(why))
            }
            _ => (HostStatus::Done, None),
        };
        Some(Report {
            status,
            server,
            dirs,
            reason: with_truncation_note(reason, truncated, self.cfg.max_listing_bytes),
            purge: false,
            failed: failed_run,
        })
    }

    /// Records directories on other sites for a later crawl, except on local
    /// and private networks, and (unless `broad`) except ones that show no sign
    /// of being a public archive.
    async fn save_candidates(&self, urls: Vec<Url>) {
        self.save_candidates_as(urls, LINK_SOURCE, true).await;
    }

    /// Like `save_candidates`, under another source. Without `need_signal` the
    /// archive-signal test is skipped, for sites you chose.
    async fn save_candidates_as(&self, mut urls: Vec<Url>, source: &str, need_signal: bool) {
        if !self.cfg.allow_private_links {
            urls.retain(filters::is_public_host);
        }
        if need_signal && !self.cfg.broad {
            urls.retain(filters::has_archive_signal);
        }
        if urls.is_empty() {
            return;
        }
        let msg = Msg::Candidates {
            urls,
            source: source.to_string(),
        };
        let _ = self.tx.send(msg).await;
    }

    /// Fetches one directory page, following same-host redirects by hand so
    /// that every hop is checked against robots.txt and paced. `top` is true for
    /// a URL you added yourself, which passes trust on if it has moved.
    async fn fetch_page(&mut self, start: Url, top: bool) -> Fetch {
        let mut url = start;
        for _ in 0..=MAX_REDIRECTS {
            match self.robots_check(&url).await {
                Access::Allowed => {}
                Access::Blocked => return Fetch::Skipped,
                Access::Stopped => return Fetch::Stopped,
            }
            let response = match self.get(&url, "application/json, text/html;q=0.9").await {
                Ok(response) => response,
                Err(Outcome::Stopped) => return Fetch::Stopped,
                Err(Outcome::Failed(e)) => return Fetch::Failed(e),
            };
            let status = response.status();

            if status.is_redirection() {
                let Some(next) = location(&response, &url) else {
                    return Fetch::Skipped;
                };
                if !filters::same_site(&next, &url) {
                    // Another site: remember it for later instead of following it.
                    if next.path().ends_with('/') && next.query().is_none() {
                        if top && self.moved_seeds < MAX_MOVED_SEEDS {
                            // You added this address and it has moved: the new one
                            // is yours too (but cannot pass trust on again).
                            self.moved_seeds += 1;
                            self.save_candidates_as(vec![next], store::MOVED_SOURCE, false)
                                .await;
                        } else {
                            self.save_candidates(vec![next]).await;
                        }
                    }
                    return Fetch::Skipped;
                }
                // One spelling per folder (`host.` is `host`), as stored and queued.
                url = filters::canonical_url(&next);
                continue;
            }
            if status.is_server_error() {
                return Fetch::Failed(format!("{status} from {url}"));
            }
            if !status.is_success() {
                return Fetch::Refused(format!("{status} from {url}"));
            }

            // Only listing pages are read. Anything else, including a response
            // without a Content-Type (Apache sends none for unknown files), is a
            // file, and its body is never downloaded.
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_ascii_lowercase);
            if !content_type
                .as_deref()
                .is_some_and(|ct| ct.contains("html") || ct.contains("json"))
            {
                return Fetch::Skipped;
            }
            let body = tokio::select! {
                body = read_capped(response, self.cfg.max_listing_bytes) => body,
                _ = self.stop.cancelled() => return Fetch::Stopped,
            };
            return match body {
                Ok((body, truncated)) => Fetch::Page(Page {
                    url,
                    content_type,
                    body: String::from_utf8_lossy(&body).into_owned(),
                    truncated,
                }),
                Err(e) => Fetch::Failed(e.to_string()),
            };
        }
        Fetch::Skipped // too many redirects
    }

    /// One paced GET. Retries 429 and 503, honouring `Retry-After`.
    async fn get(&mut self, url: &Url, accept: &str) -> Result<Response, Outcome> {
        let mut retries = 0;
        loop {
            if !self.pacer.wait(&self.stop).await {
                return Err(Outcome::Stopped);
            }
            self.stats.requests.fetch_add(1, Relaxed);
            let request = self.client.get(url.clone()).header(ACCEPT, accept).send();
            let response = tokio::select! {
                response = request => response.map_err(|e| Outcome::Failed(e.to_string()))?,
                _ = self.stop.cancelled() => return Err(Outcome::Stopped),
            };
            let status = response.status();
            if status != StatusCode::TOO_MANY_REQUESTS && status != StatusCode::SERVICE_UNAVAILABLE
            {
                return Ok(response);
            }
            retries += 1;
            let default_wait =
                self.cfg.per_host_delay.max(Duration::from_secs(1)) * 2u32.pow(retries);
            let wait = retry_after(&response).unwrap_or(default_wait);
            if retries > MAX_RETRIES || wait > MAX_BACKOFF {
                return Err(Outcome::Failed(format!("{status} from {url}, giving up")));
            }
            self.pacer.back_off(wait);
        }
    }

    /// Checks `url` against the robots.txt of its origin, fetching it first if needed.
    async fn robots_check(&mut self, url: &Url) -> Access {
        if !RESPECT_ROBOTS_TXT {
            return Access::Allowed;
        }
        let origin = url.origin().ascii_serialization();
        if !self.robots.contains_key(&origin) {
            let Some(mut robots) = self.fetch_robots(url).await else {
                return Access::Stopped;
            };
            if let Robots::Rules(robot) = &robots
                && let Some(delay) = crawl_delay(robot)
            {
                if delay > MAX_CRAWL_DELAY {
                    let why = format!("Crawl-delay of {}s is too slow to crawl", delay.as_secs());
                    robots = Robots::DisallowAll(why);
                } else {
                    self.pacer.slow_down_to(delay);
                }
            }
            self.robots.insert(origin.clone(), robots);
        }
        match &self.robots[&origin] {
            Robots::AllowAll => Access::Allowed,
            Robots::Rules(robot) if robot.allowed(url.as_str()) => Access::Allowed,
            Robots::Rules(_) => {
                self.robots_blocked = Some(format!("robots.txt disallows {}", url.path()));
                Access::Blocked
            }
            Robots::DisallowAll(why) => {
                self.robots_blocked = Some(why.clone());
                Access::Blocked
            }
            Robots::Unreachable(why) => {
                self.last_error = Some(why.clone());
                Access::Blocked
            }
        }
    }

    /// Fetches robots.txt per RFC 9309: follow up to five redirects (even to
    /// other hosts), 4xx means no rules, 5xx means stay out. `None` if stopped.
    async fn fetch_robots(&mut self, url: &Url) -> Option<Robots> {
        let Ok(mut robots_url) = url.join("/robots.txt") else {
            return Some(Robots::DisallowAll("invalid URL".into()));
        };
        for _ in 0..=MAX_REDIRECTS {
            let response = match self.get(&robots_url, "text/plain, */*;q=0.5").await {
                Ok(response) => response,
                Err(Outcome::Stopped) => return None,
                Err(Outcome::Failed(e)) => {
                    self.stats.errors.fetch_add(1, Relaxed);
                    return Some(Robots::Unreachable(format!("robots.txt: {e}")));
                }
            };
            let status = response.status();
            if status.is_redirection() {
                match location(&response, &robots_url) {
                    Some(next) => {
                        robots_url = next;
                        continue;
                    }
                    None => {
                        let why = "robots.txt redirect without a Location".to_string();
                        return Some(Robots::DisallowAll(why));
                    }
                }
            }
            if status.is_server_error() {
                return Some(Robots::DisallowAll(format!("robots.txt returned {status}")));
            }
            if !status.is_success() {
                return Some(Robots::AllowAll); // 4xx: no robots.txt
            }
            let body = tokio::select! {
                body = read_capped(response, MAX_ROBOTS_BYTES) => body,
                _ = self.stop.cancelled() => return None,
            };
            let robots = match body.map(|(b, _)| Robot::new(BOT_TOKEN, &b)) {
                Ok(Ok(robot)) => Robots::Rules(Box::new(robot)),
                _ => Robots::DisallowAll("robots.txt could not be read".into()),
            };
            return Some(robots);
        }
        Some(Robots::DisallowAll(
            "robots.txt redirected too many times".into(),
        ))
    }
}

fn crawl_delay(robot: &Robot) -> Option<Duration> {
    robot
        .delay
        .filter(|d| d.is_finite() && *d > 0.0)
        .map(|d| Duration::from_secs_f32(d.min(86_400.0)))
}

fn location(response: &Response, base: &Url) -> Option<Url> {
    let value = response.headers().get(LOCATION)?.to_str().ok()?;
    let mut url = base.join(value).ok()?;
    url.set_fragment(None);
    matches!(url.scheme(), "http" | "https").then_some(url)
}

/// Checks a listing for signs of an accidental exposure or a compromised
/// server. Returns why the site should be dropped, if so. On a trusted site,
/// entries with only a weak sensitive name are removed from the listing instead.
fn check_exposure(page_url: &Url, listing: &mut Listing, trusted: bool) -> Option<String> {
    if filters::is_sensitive_path(page_url.path()) {
        return Some(format!("listing at {page_url}"));
    }
    let mut has_weak = false;
    for e in &listing.entries {
        match filters::sensitivity(&e.name) {
            Some(Sensitivity::Strong) => return Some(format!("found {}", e.url)),
            Some(Sensitivity::Weak) if !trusted => return Some(format!("found {}", e.url)),
            Some(Sensitivity::Weak) => has_weak = true,
            None => {}
        }
    }
    if has_weak {
        listing
            .entries
            .retain(|e| filters::sensitivity(&e.name) != Some(Sensitivity::Weak));
    }
    None
}

/// Reads a body up to `cap` bytes, and says whether there was more.
async fn read_capped(mut response: Response, cap: usize) -> reqwest::Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = cap - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

/// `Retry-After` in seconds (the HTTP-date form is ignored).
fn retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?;
    value.trim().parse().ok().map(Duration::from_secs)
}

/// The listings seen on one host, to spot copies: an alias such as
/// `latest -> 2.4.1`, or a symlink back to a parent.
#[derive(Default)]
struct Listings {
    /// Listings that hold files, by content.
    with_files: HashSet<u64>,
    /// Listings that hold nothing but sub-folders, by content, with the addresses
    /// they were seen at.
    folders_only: HashMap<u64, Vec<String>>,
}

impl Listings {
    /// True if `entries`, the listing of `url`, is a copy of one seen before, so
    /// that its sub-folders need not be walked again.
    ///
    /// A listing with files is a copy of any earlier one with the same content.
    /// Folders that hold only sub-folders and were made together list the same
    /// names and dates, and skipping them would lose what is below, so such a
    /// listing is a copy only of one seen at a parent (a loop). Listings with
    /// neither sizes nor dates cannot be compared and are never copies.
    fn is_copy(&mut self, url: &Url, entries: &[Entry]) -> bool {
        if !entries
            .iter()
            .any(|e| e.size.is_some() || e.mtime.is_some())
        {
            return false;
        }
        let mut hasher = DefaultHasher::new();
        for e in entries {
            (&e.name, e.is_dir, e.size, &e.mtime).hash(&mut hasher);
        }
        let key = hasher.finish();
        if entries.iter().any(|e| !e.is_dir) {
            return !self.with_files.insert(key);
        }
        let here = url.as_str();
        let earlier = self.folders_only.entry(key).or_default();
        let looped = earlier
            .iter()
            .any(|parent| here.starts_with(parent.as_str()));
        earlier.push(here.to_string());
        looped
    }
}

/// The folders of a crawl that still wait, against the level of the deepest leaf
/// folders read (see `quality::Waiting`): the queue in memory and the ones saved past
/// the budget.
fn waiting_at(
    queue: &VecDeque<(Url, usize)>,
    saved: &BTreeMap<usize, u64>,
    level: Option<usize>,
) -> Waiting {
    let mut at_level = level.and_then(|l| saved.get(&l)).copied().unwrap_or(0);
    let mut deepest = saved.keys().next_back().copied();
    for (url, _) in queue {
        let depth = filters::path_depth(url.as_str());
        deepest = deepest.max(Some(depth));
        at_level += u64::from(Some(depth) == level);
    }
    Waiting { at_level, deepest }
}

/// Adds to a host's reason that listings were cut short, if any were.
fn with_truncation_note(reason: Option<String>, truncated: u32, cap: usize) -> Option<String> {
    if truncated == 0 {
        return reason;
    }
    let note = format!(
        "{truncated} listing(s) were longer than {} and cut short",
        if cap >= 1024 * 1024 {
            format!("{} MiB", cap / (1024 * 1024))
        } else {
            format!("{} KiB", cap / 1024)
        }
    );
    Some(match reason {
        Some(reason) => format!("{reason}; {note}"),
        None => note,
    })
}

fn has_repeating_segments(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let n = segments.len();
    (1..=n / 3).any(|k| {
        let last = &segments[n - k..];
        last == &segments[n - 2 * k..n - k] && last == &segments[n - 3 * k..n - 2 * k]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeating_segments() {
        assert!(has_repeating_segments("/a/a/a/"));
        assert!(has_repeating_segments("/x/a/b/a/b/a/b/"));
        assert!(!has_repeating_segments("/a/b/a/b/"));
        assert!(!has_repeating_segments("/pub/pub/"));
        assert!(!has_repeating_segments("/"));
    }

    #[test]
    fn robots_rules() {
        let robot = Robot::new(
            BOT_TOKEN,
            b"User-agent: *\nDisallow: /private/\nCrawl-delay: 2",
        )
        .unwrap();
        assert!(robot.allowed("https://h.example/pub/"));
        assert!(!robot.allowed("https://h.example/private/x/"));
        assert_eq!(crawl_delay(&robot), Some(Duration::from_secs(2)));
    }

    #[test]
    fn robots_group_for_our_token_wins() {
        let txt = b"User-agent: opendirtest\nDisallow: /\n\nUser-agent: *\nDisallow:";
        let robot = Robot::new(BOT_TOKEN, txt).unwrap();
        assert!(!robot.allowed("https://h.example/pub/"));
    }

    #[tokio::test]
    async fn crawl_delay_applies_to_the_very_next_request() {
        let stop = CancellationToken::new();
        let mut pacer = Pacer::new(Duration::from_millis(1));
        assert!(pacer.wait(&stop).await); // the robots.txt request
        let robots_sent = pacer.last_start.unwrap();
        pacer.slow_down_to(Duration::from_secs(5));
        assert_eq!(pacer.next, robots_sent + Duration::from_secs(5));
    }

    #[tokio::test]
    async fn pacer_wait_stops_on_cancel() {
        let stop = CancellationToken::new();
        let mut pacer = Pacer::new(Duration::from_secs(1));
        pacer.back_off(Duration::from_secs(3600));
        stop.cancel();
        assert!(!pacer.wait(&stop).await);
    }

    #[test]
    fn copies_of_listings_are_spotted_without_losing_folders_made_together() {
        let entry = |is_dir: bool, size: Option<u64>, mtime: Option<&str>| Entry {
            url: Url::parse("https://h.example/p1/src/").unwrap(),
            name: "src".into(),
            is_dir,
            size,
            mtime: mtime.map(str::to_string),
        };
        let at = |path: &str| Url::parse(&format!("https://h.example{path}")).unwrap();
        let mut seen = Listings::default();
        // Nothing to compare by: never a copy.
        assert!(!seen.is_copy(&at("/a/"), &[entry(false, None, None)]));
        assert!(!seen.is_copy(&at("/b/"), &[entry(false, None, None)]));
        // Files with sizes: the same listing twice, anywhere, is a copy.
        assert!(!seen.is_copy(&at("/c/"), &[entry(false, Some(1), None)]));
        assert!(seen.is_copy(&at("/d/"), &[entry(false, Some(1), None)]));
        // A listing of nothing but sub-folders is not a copy of a sibling: folders
        // made together list the same names and dates.
        let dated = [entry(true, None, Some("2026-09-28 10:15"))];
        assert!(!seen.is_copy(&at("/x/p0/download/"), &dated));
        assert!(!seen.is_copy(&at("/x/p1/download/"), &dated));
        // ...but it is a copy of one of its own parents: a loop.
        assert!(seen.is_copy(&at("/x/p1/download/loop/"), &dated));
        assert!(seen.is_copy(&at("/x/p0/download/a/b/"), &dated));
    }
}
