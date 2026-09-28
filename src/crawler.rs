//! The crawler. Each host gets its own task that walks the host's directory tree
//! one request at a time. All politeness state (robots.txt, pacing, back-off)
//! lives in that task, so hosts never need to coordinate.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use anyhow::Result;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION, RETRY_AFTER};
use reqwest::{Client, Response, StatusCode};
use texting_robots::Robot;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::filters;
use crate::listing::{self, Entry, Listing};
use crate::safety::{
    DROP_SENSITIVE_EXPOSURES, ENFORCE_PER_HOST_RATE_LIMIT, FOLLOW_LISTED_LINKS_ONLY,
    HONOR_OPT_OUT_LIST, RESPECT_ROBOTS_TXT, SEND_IDENTIFYING_USER_AGENT,
};
use crate::store::{HostStatus, Msg};

/// Product token matched against `User-agent:` lines in robots.txt.
pub const BOT_TOKEN: &str = "opendirtest";
pub const USER_AGENT: &str = concat!(
    "opendirtest/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/raul2hot/opendirtest)"
);
/// `candidates.source` for directory links found on other sites' listings.
pub const LINK_SOURCE: &str = "link";

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// RFC 9309 asks crawlers to parse at least 500 KiB.
const MAX_ROBOTS_BYTES: usize = 500 * 1024;
const MAX_URL_LEN: usize = 2048;
/// RFC 9309 asks crawlers to follow at least five robots.txt redirects.
const MAX_REDIRECTS: usize = 5;
const MAX_RETRIES: u32 = 3;
const MAX_CONSECUTIVE_ERRORS: u32 = 5;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Hosts asking for a longer Crawl-delay than this are skipped rather than
/// holding a crawl slot for days.
const MAX_CRAWL_DELAY: Duration = Duration::from_secs(60);

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
    pub skip_hosts: HashSet<String>,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            concurrency: 256,
            max_dirs_per_host: 20_000,
            max_depth: 32,
            per_host_delay: Duration::from_secs(1),
            optout: Vec::new(),
            skip_hosts: HashSet::new(),
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

/// Crawls every seed, grouped by host. Returns when all hosts are finished, or
/// soon after `stop` is cancelled. Hosts that were stopped before their first
/// listing are not recorded, so they stay pending for the next run.
pub async fn crawl(
    seeds: Vec<Url>,
    cfg: CrawlConfig,
    tx: mpsc::Sender<Msg>,
    stop: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let client = build_client()?;

    let mut hosts: Vec<(String, Vec<Url>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for seed in seeds {
        let Some(host) = seed.host_str().map(str::to_ascii_lowercase) else {
            continue;
        };
        let i = *index.entry(host.clone()).or_insert_with(|| {
            hosts.push((host, Vec::new()));
            hosts.len() - 1
        });
        hosts[i].1.push(seed);
    }
    stats.hosts_total.store(hosts.len() as u64, Relaxed);

    let cfg = Arc::new(cfg);
    let slots = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for (host, seeds) in hosts {
        let permit = tokio::select! {
            permit = slots.clone().acquire_owned() => permit?,
            _ = stop.cancelled() => break,
        };
        let worker = HostCrawl {
            host,
            client: client.clone(),
            pacer: Pacer::new(cfg.per_host_delay),
            cfg: cfg.clone(),
            tx: tx.clone(),
            stop: stop.clone(),
            stats: stats.clone(),
            robots: HashMap::new(),
            robots_blocked: None,
            last_error: None,
        };
        tasks.spawn(async move {
            worker.run(seeds).await;
            drop(permit);
        });
        while let Some(result) = tasks.try_join_next() {
            report_panic(result);
        }
    }
    while let Some(result) = tasks.join_next().await {
        report_panic(result);
    }
    Ok(())
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
}

enum Fetch {
    Page(Page),
    /// Nothing usable here (404, a file, robots.txt says no, ...).
    Skipped,
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
}

/// What to record for a finished host.
struct Report {
    status: HostStatus,
    server: Option<&'static str>,
    dirs: u64,
    reason: Option<String>,
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
            };
            let _ = self.tx.send(msg).await;
        }
        self.stats.hosts_done.fetch_add(1, Relaxed);
    }

    /// Breadth-first walk of the host's directory tree. `None` means nothing
    /// should be recorded (stopped before anything happened, or already dropped).
    async fn walk(&mut self, seeds: Vec<Url>) -> Option<Report> {
        let report = |status, reason: &str| Report {
            status,
            server: None,
            dirs: 0,
            reason: Some(reason.to_string()),
        };
        if HONOR_OPT_OUT_LIST && filters::host_opted_out(&self.host, &self.cfg.optout) {
            return Some(report(HostStatus::OptedOut, "on the opt-out list"));
        }
        if DROP_SENSITIVE_EXPOSURES && self.cfg.skip_hosts.contains(&self.host) {
            return None; // keeps the reason recorded when it was dropped
        }

        let mut queue: VecDeque<(Url, usize)> = seeds.into_iter().map(|u| (u, 0)).collect();
        let mut seen: HashSet<String> = queue.iter().map(|(u, _)| u.to_string()).collect();
        let mut listing_hashes = HashSet::new();
        let mut server = None;
        let mut dirs = 0u64;
        let mut stopped = false;
        let mut truncated: Option<String> = None;
        let mut errors_in_a_row = 0;

        while let Some((url, depth)) = queue.pop_front() {
            if self.stop.is_cancelled() {
                stopped = true;
                break;
            }
            if dirs >= self.cfg.max_dirs_per_host {
                truncated = Some("directory budget reached".into());
                break;
            }
            let page = match self.fetch_page(url).await {
                Fetch::Page(page) => page,
                Fetch::Skipped => {
                    errors_in_a_row = 0;
                    continue;
                }
                Fetch::Stopped => {
                    stopped = true;
                    break;
                }
                Fetch::Failed(error) => {
                    self.stats.errors.fetch_add(1, Relaxed);
                    self.last_error = Some(error);
                    errors_in_a_row += 1;
                    if errors_in_a_row >= MAX_CONSECUTIVE_ERRORS {
                        truncated = Some(format!(
                            "too many errors, last: {}",
                            self.last_error.as_deref().unwrap_or("")
                        ));
                        break;
                    }
                    continue;
                }
            };
            errors_in_a_row = 0;

            // Parsing a big page takes a while; keep it off the async threads.
            let parsed = tokio::task::spawn_blocking(move || {
                let listing = listing::parse(&page.url, page.content_type.as_deref(), &page.body);
                (page.url, listing)
            })
            .await;
            let Ok((page_url, Some(listing))) = parsed else {
                continue;
            };
            dirs += 1;
            self.stats.listings.fetch_add(1, Relaxed);
            server.get_or_insert(listing.server.as_str());

            if DROP_SENSITIVE_EXPOSURES && let Some(why) = sensitive_reason(&page_url, &listing) {
                let _ = self
                    .tx
                    .send(Msg::Purge {
                        host: self.host.clone(),
                    })
                    .await;
                return Some(Report {
                    status: HostStatus::Sensitive,
                    server,
                    dirs,
                    reason: Some(why),
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

            // Content already seen on this host (a symlink loop or an alias such
            // as `latest -> 2.4.1`): keep the entries, but don't walk it again.
            if !is_duplicate(&entries, &mut listing_hashes) {
                let mut next: Vec<Url> = entries
                    .iter()
                    .filter(|e| e.is_dir)
                    .map(|e| e.url.clone())
                    .collect();
                if !FOLLOW_LISTED_LINKS_ONLY {
                    next.extend(other_dirs);
                }
                for dir in next {
                    if queue.len() as u64 + dirs >= self.cfg.max_dirs_per_host {
                        truncated = Some("directory budget reached".into());
                        break;
                    }
                    if depth < self.cfg.max_depth
                        && dir.as_str().len() <= MAX_URL_LEN
                        && !has_repeating_segments(dir.path())
                        && seen.insert(dir.to_string())
                    {
                        queue.push_back((dir, depth + 1));
                    }
                }
            }

            self.stats.entries.fetch_add(entries.len() as u64, Relaxed);
            let msg = Msg::Entries {
                host: self.host.clone(),
                entries,
            };
            if self.tx.send(msg).await.is_err() {
                // The database writer is gone, so nothing more can be saved.
                self.stop.cancel();
                stopped = true;
                break;
            }
        }

        if stopped && dirs == 0 {
            return None; // try this host again next time
        }
        let (status, reason) = match dirs {
            0 if self.robots_blocked.is_some() => {
                (HostStatus::RobotsDisallowed, self.robots_blocked.take())
            }
            0 if self.last_error.is_some() => (HostStatus::Unreachable, self.last_error.take()),
            0 => (HostStatus::NotListing, None),
            _ if stopped => (HostStatus::Partial, Some("stopped".to_string())),
            _ if truncated.is_some() => (HostStatus::Partial, truncated),
            _ => (HostStatus::Done, None),
        };
        Some(Report {
            status,
            server,
            dirs,
            reason,
        })
    }

    async fn save_candidates(&self, urls: Vec<Url>) {
        let msg = Msg::Candidates {
            urls,
            source: LINK_SOURCE.to_string(),
        };
        let _ = self.tx.send(msg).await;
    }

    /// Fetches one directory page, following same-host redirects by hand so
    /// that every hop is checked against robots.txt and paced.
    async fn fetch_page(&mut self, start: Url) -> Fetch {
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
                if next.host_str() != url.host_str() {
                    // Another site: remember it for later instead of following it.
                    if next.path().ends_with('/') && next.query().is_none() {
                        self.save_candidates(vec![next]).await;
                    }
                    return Fetch::Skipped;
                }
                url = next;
                continue;
            }
            if status.is_server_error() {
                return Fetch::Failed(format!("{status} from {url}"));
            }
            if !status.is_success() {
                return Fetch::Skipped;
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
                body = read_capped(response, MAX_BODY_BYTES) => body,
                _ = self.stop.cancelled() => return Fetch::Stopped,
            };
            return match body {
                Ok(body) => Fetch::Page(Page {
                    url,
                    content_type,
                    body: String::from_utf8_lossy(&body).into_owned(),
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
            let robots = match body.map(|b| Robot::new(BOT_TOKEN, &b)) {
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

/// Why a listing looks like an accidental exposure, if it does.
fn sensitive_reason(page_url: &Url, listing: &Listing) -> Option<String> {
    if filters::is_sensitive_path(page_url.path()) {
        return Some(format!("listing at {page_url}"));
    }
    listing
        .entries
        .iter()
        .find(|e| filters::is_sensitive_name(&e.name))
        .map(|e| format!("found {}", e.url))
}

async fn read_capped(mut response: Response, cap: usize) -> reqwest::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = cap - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if body.len() >= cap {
            break;
        }
    }
    Ok(body)
}

/// `Retry-After` in seconds (the HTTP-date form is ignored).
fn retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?;
    value.trim().parse().ok().map(Duration::from_secs)
}

/// True if a listing with exactly this content was already seen on the host.
/// Names-only listings (no sizes or dates) can't be told apart, so they never count.
fn is_duplicate(entries: &[Entry], seen: &mut HashSet<u64>) -> bool {
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
    !seen.insert(hasher.finish())
}

/// True if the path ends with the same run of segments three times in a row,
/// like `/a/b/a/b/a/b/`: a loop the listing hash did not catch.
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
    fn names_only_listings_are_never_duplicates() {
        let url = Url::parse("https://h.example/p1/src/").unwrap();
        let entry = |size: Option<u64>| Entry {
            url: url.clone(),
            name: "src".into(),
            is_dir: true,
            size,
            mtime: None,
        };
        let mut seen = HashSet::new();
        assert!(!is_duplicate(&[entry(None)], &mut seen));
        assert!(!is_duplicate(&[entry(None)], &mut seen));
        assert!(!is_duplicate(&[entry(Some(1))], &mut seen));
        assert!(is_duplicate(&[entry(Some(1))], &mut seen));
    }
}
