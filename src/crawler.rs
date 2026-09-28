//! The crawler. Each host gets its own task that walks the host's directory tree
//! one request at a time. All politeness state (robots.txt, pacing, back-off)
//! lives in that task, so hosts never need to coordinate.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use anyhow::{Result, bail};
use reqwest::header::{ACCEPT, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use texting_robots::Robot;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::Instant;
use url::Url;

use crate::filters;
use crate::listing::{self, Entry};
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

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// RFC 9309 asks crawlers to parse at least 500 KiB.
const MAX_ROBOTS_BYTES: usize = 500 * 1024;
const MAX_URL_LEN: usize = 2048;
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

/// Crawls every seed, grouped by host. Returns when all hosts are finished or
/// `stop` is set and in-flight work has wound down.
pub async fn crawl(
    seeds: Vec<Url>,
    cfg: CrawlConfig,
    tx: mpsc::Sender<Msg>,
    stop: Arc<AtomicBool>,
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
        let permit = slots.clone().acquire_owned().await?;
        if stop.load(Relaxed) {
            break;
        }
        let worker = HostCrawl {
            host,
            client: client.clone(),
            cfg: cfg.clone(),
            tx: tx.clone(),
            stop: stop.clone(),
            stats: stats.clone(),
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
    // Follow at most 3 redirects, and only within the same host.
    let redirects = reqwest::redirect::Policy::custom(|attempt| {
        let origin_host = attempt.previous().first().and_then(Url::host_str);
        if attempt.previous().len() > 3 || origin_host != attempt.url().host_str() {
            attempt.stop()
        } else {
            attempt.follow()
        }
    });
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .redirect(redirects);
    if SEND_IDENTIFYING_USER_AGENT {
        builder = builder.user_agent(USER_AGENT);
    }
    builder.build()
}

enum Robots {
    AllowAll,
    DisallowAll,
    Unreachable,
    Rules(Box<Robot>),
}

impl Robots {
    fn allows(&self, url: &Url) -> bool {
        match self {
            Robots::AllowAll => true,
            Robots::DisallowAll | Robots::Unreachable => false,
            Robots::Rules(robot) => robot.allowed(url.as_str()),
        }
    }

    fn crawl_delay(&self) -> Option<Duration> {
        match self {
            Robots::Rules(robot) => robot
                .delay
                .filter(|d| d.is_finite() && *d > 0.0)
                .map(|d| Duration::from_secs_f32(d.min(86_400.0))),
            _ => None,
        }
    }
}

/// Spaces out requests to one host.
struct Pacer {
    gap: Duration,
    next: Instant,
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
        }
    }

    fn slow_down_to(&mut self, gap: Duration) {
        if ENFORCE_PER_HOST_RATE_LIMIT {
            self.gap = self.gap.max(gap);
        }
    }

    fn back_off(&mut self, wait: Duration) {
        self.next = self.next.max(Instant::now() + wait);
    }

    async fn wait(&mut self) {
        tokio::time::sleep_until(self.next).await;
        self.next = Instant::now() + self.gap;
    }
}

struct Page {
    url: Url,
    content_type: Option<String>,
    body: String,
}

struct HostCrawl {
    host: String,
    client: Client,
    cfg: Arc<CrawlConfig>,
    tx: mpsc::Sender<Msg>,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
}

impl HostCrawl {
    async fn run(self, seeds: Vec<Url>) {
        self.stats.hosts_started.fetch_add(1, Relaxed);
        let (status, server, dirs) = self.walk(seeds).await;
        let _ = self
            .tx
            .send(Msg::HostDone {
                host: self.host.clone(),
                status,
                server: server.map(str::to_owned),
                dirs,
            })
            .await;
        self.stats.hosts_done.fetch_add(1, Relaxed);
    }

    /// Breadth-first walk of the host's directory tree.
    async fn walk(&self, seeds: Vec<Url>) -> (HostStatus, Option<&'static str>, u64) {
        if HONOR_OPT_OUT_LIST && filters::host_opted_out(&self.host, &self.cfg.optout) {
            return (HostStatus::OptedOut, None, 0);
        }
        if DROP_SENSITIVE_EXPOSURES && self.cfg.skip_hosts.contains(&self.host) {
            return (HostStatus::Sensitive, None, 0);
        }

        let mut pacer = Pacer::new(self.cfg.per_host_delay);
        let robots = if RESPECT_ROBOTS_TXT {
            self.fetch_robots(&seeds[0], &mut pacer).await
        } else {
            Robots::AllowAll
        };
        match &robots {
            Robots::DisallowAll => return (HostStatus::RobotsDisallowed, None, 0),
            Robots::Unreachable => return (HostStatus::Unreachable, None, 0),
            _ => {}
        }
        if let Some(delay) = robots.crawl_delay() {
            if delay > MAX_CRAWL_DELAY {
                return (HostStatus::RobotsDisallowed, None, 0);
            }
            pacer.slow_down_to(delay);
        }

        let mut queue: VecDeque<(Url, usize)> = seeds.into_iter().map(|u| (u, 0)).collect();
        let mut seen: HashSet<String> = queue.iter().map(|(u, _)| u.to_string()).collect();
        let mut listing_hashes = HashSet::new();
        let mut server = None;
        let mut dirs = 0u64;
        let mut complete = true;
        let mut robots_blocked = false;
        let mut had_errors = false;
        let mut errors_in_a_row = 0;

        while let Some((url, depth)) = queue.pop_front() {
            if self.stop.load(Relaxed) || dirs >= self.cfg.max_dirs_per_host {
                complete = false;
                break;
            }
            if !robots.allows(&url) {
                robots_blocked = true;
                continue;
            }
            let page = match self.fetch(&url, &mut pacer).await {
                Ok(page) => {
                    errors_in_a_row = 0;
                    match page {
                        Some(page) => page,
                        None => continue,
                    }
                }
                Err(_) => {
                    self.stats.errors.fetch_add(1, Relaxed);
                    had_errors = true;
                    errors_in_a_row += 1;
                    if errors_in_a_row >= MAX_CONSECUTIVE_ERRORS {
                        complete = false;
                        break;
                    }
                    continue;
                }
            };
            let Some(listing) = listing::parse(&page.url, page.content_type.as_deref(), &page.body)
            else {
                continue;
            };
            dirs += 1;
            self.stats.listings.fetch_add(1, Relaxed);
            server.get_or_insert(listing.server.as_str());

            if DROP_SENSITIVE_EXPOSURES
                && (filters::is_sensitive_path(page.url.path())
                    || listing
                        .entries
                        .iter()
                        .any(|e| filters::is_sensitive_name(&e.name)))
            {
                let _ = self
                    .tx
                    .send(Msg::Purge {
                        host: self.host.clone(),
                    })
                    .await;
                return (HostStatus::Sensitive, server, dirs);
            }

            // Identical content already seen on this host: a symlink loop or an
            // alias such as `latest -> 2.4.1`. Skip it.
            if !listing.entries.is_empty() && !listing_hashes.insert(listing_hash(&listing.entries))
            {
                continue;
            }

            let mut next: Vec<Url> = listing
                .entries
                .iter()
                .filter(|e| e.is_dir)
                .map(|e| e.url.clone())
                .collect();
            if !FOLLOW_LISTED_LINKS_ONLY {
                next.extend(listing.other_dirs);
            }
            for dir in next {
                if depth < self.cfg.max_depth
                    && dir.as_str().len() <= MAX_URL_LEN
                    && !has_repeating_segments(dir.path())
                    && seen.insert(dir.to_string())
                {
                    queue.push_back((dir, depth + 1));
                }
            }

            self.stats
                .entries
                .fetch_add(listing.entries.len() as u64, Relaxed);
            let msg = Msg::Entries {
                host: self.host.clone(),
                entries: listing.entries,
            };
            if self.tx.send(msg).await.is_err() {
                break; // writer is gone; nothing more can be stored
            }
        }

        let status = match (dirs, complete) {
            (0, _) if robots_blocked => HostStatus::RobotsDisallowed,
            (0, _) if had_errors => HostStatus::Unreachable,
            (0, _) => HostStatus::NotListing,
            (_, true) => HostStatus::Done,
            (_, false) => HostStatus::Partial,
        };
        (status, server, dirs)
    }

    /// Fetches robots.txt and applies RFC 9309: 4xx means no rules, 5xx or an
    /// unreachable host means stay out.
    async fn fetch_robots(&self, any_url: &Url, pacer: &mut Pacer) -> Robots {
        let Ok(robots_url) = any_url.join("/robots.txt") else {
            return Robots::DisallowAll;
        };
        pacer.wait().await;
        self.stats.requests.fetch_add(1, Relaxed);
        let response = match self.client.get(robots_url).send().await {
            Ok(response) => response,
            Err(_) => {
                self.stats.errors.fetch_add(1, Relaxed);
                return Robots::Unreachable;
            }
        };
        let status = response.status();
        if status.is_success() {
            match read_capped(response, MAX_ROBOTS_BYTES).await {
                Ok(body) => match Robot::new(BOT_TOKEN, &body) {
                    Ok(robot) => Robots::Rules(Box::new(robot)),
                    Err(_) => Robots::DisallowAll,
                },
                Err(_) => Robots::DisallowAll,
            }
        } else if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            Robots::DisallowAll
        } else {
            // 4xx, or a redirect we refused to follow: robots.txt is unavailable.
            Robots::AllowAll
        }
    }

    /// Fetches one directory page. `Ok(None)` means the page is not usable
    /// (404, not HTML/JSON, ...); errors are network failures and 5xx.
    async fn fetch(&self, url: &Url, pacer: &mut Pacer) -> Result<Option<Page>> {
        let mut retries = 0;
        loop {
            pacer.wait().await;
            self.stats.requests.fetch_add(1, Relaxed);
            let response = self
                .client
                .get(url.clone())
                .header(ACCEPT, "application/json, text/html;q=0.9")
                .send()
                .await?;
            let status = response.status();

            if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE
            {
                retries += 1;
                let wait = retry_after(&response).unwrap_or(
                    self.cfg.per_host_delay.max(Duration::from_secs(1)) * 2u32.pow(retries),
                );
                if retries > MAX_RETRIES || wait > MAX_BACKOFF {
                    bail!("{status} from {url}, giving up");
                }
                pacer.back_off(wait);
                continue;
            }
            if status.is_server_error() {
                bail!("{status} from {url}");
            }
            if !status.is_success() {
                return Ok(None);
            }

            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_ascii_lowercase);
            if content_type
                .as_deref()
                .is_some_and(|ct| !ct.contains("html") && !ct.contains("json"))
            {
                return Ok(None); // a file, not a directory page; don't download it
            }
            let final_url = response.url().clone();
            let body = read_capped(response, MAX_BODY_BYTES).await?;
            return Ok(Some(Page {
                url: final_url,
                content_type,
                body: String::from_utf8_lossy(&body).into_owned(),
            }));
        }
    }
}

async fn read_capped(mut response: reqwest::Response, cap: usize) -> reqwest::Result<Vec<u8>> {
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
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?;
    value.trim().parse().ok().map(Duration::from_secs)
}

fn listing_hash(entries: &[Entry]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for e in entries {
        (&e.name, e.is_dir, e.size, &e.mtime).hash(&mut hasher);
    }
    hasher.finish()
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
        let robots = Robots::Rules(Box::new(robot));
        assert!(robots.allows(&Url::parse("https://h.example/pub/").unwrap()));
        assert!(!robots.allows(&Url::parse("https://h.example/private/x/").unwrap()));
        assert_eq!(robots.crawl_delay(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn robots_group_for_our_token_wins() {
        let txt = b"User-agent: opendirtest\nDisallow: /\n\nUser-agent: *\nDisallow:";
        let robots = Robots::Rules(Box::new(Robot::new(BOT_TOKEN, txt).unwrap()));
        assert!(!robots.allows(&Url::parse("https://h.example/pub/").unwrap()));
    }
}
