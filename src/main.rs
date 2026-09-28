use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;
use url::Url;

use opendirtest::commoncrawl::{self, DiscoverConfig, DiscoverStats, DiscoverSummary};
use opendirtest::crawler::{self, CrawlConfig, Pending, Stats};
use opendirtest::quality::Thresholds;
use opendirtest::store::{CleanReport, CleanRules, SiteSort};
use opendirtest::{filters, store};

#[derive(Parser)]
#[command(
    name = "opendir",
    version,
    about = "Fast, polite indexer for public open directories"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Unattended run for a scheduled task: add seeds, discover, then crawl until time is up
    Auto {
        /// Stop after this many hours; unfinished sites continue next run
        #[arg(long, default_value_t = 7.0)]
        hours: f64,
        /// Seed list: a file, or a folder whose *.txt files are all read
        #[arg(long, default_value = "seeds")]
        seeds: PathBuf,
        /// Common Crawl index files to scan first (0 to skip discovery)
        #[arg(long, default_value_t = 10)]
        discover_files: usize,
        /// Common Crawl crawl id, or `latest`
        #[arg(long, default_value = "latest")]
        crawl: String,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        #[command(flatten)]
        crawl_args: CrawlArgs,
    },
    /// Crawl open directories from seed URLs and/or the sites waiting in the database
    Crawl {
        /// Seed directory URLs
        urls: Vec<String>,
        /// Seed list: a file, or a folder whose *.txt files are all read
        #[arg(long, short)]
        seeds: Option<PathBuf>,
        /// Also crawl the sites waiting in the database: found by discovery, or paused
        #[arg(long)]
        candidates: bool,
        /// With --candidates: take at most this many sites in this run
        #[arg(long)]
        max_sites: Option<usize>,
        /// Stop after this many hours; unfinished sites continue next run
        #[arg(long)]
        hours: Option<f64>,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        #[command(flatten)]
        crawl_args: CrawlArgs,
    },
    /// Find new directory listings in the Common Crawl index (sends nothing to the sites)
    Discover {
        /// Crawl id such as CC-MAIN-2026-30, or `latest`
        #[arg(long, default_value = "latest")]
        crawl: String,
        /// Index files to scan in this run (a crawl has about 300; runs resume where they stopped)
        #[arg(long, default_value_t = 10)]
        files: usize,
        /// Index files scanned at the same time
        #[arg(long, default_value_t = 4)]
        parallel: usize,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        /// Skip list: finds in skipped folders only add the site's root
        #[arg(long, default_value = "lists/skip.txt")]
        skip: PathBuf,
        /// Keep listings that show no sign of a public archive too
        #[arg(long)]
        broad: bool,
    },
    /// Search the index
    Search {
        #[arg(required = true)]
        query: Vec<String>,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        #[arg(long, short = 'n', default_value_t = 20)]
        limit: usize,
        /// Only files with one of these extensions, e.g. `iso` or `mp3,flac`
        #[arg(long)]
        ext: Option<String>,
        /// Only files at least this many MiB big
        #[arg(long)]
        min_mb: Option<u64>,
        /// Include results the likely-infringement filter would hide
        #[arg(long)]
        unfiltered: bool,
        /// Takedown list: one URL prefix per line
        #[arg(long, default_value = "lists/takedown.txt")]
        takedown: PathBuf,
        /// Opt-out list: sites on it are never shown
        #[arg(long, default_value = "lists/optout.txt")]
        optout: PathBuf,
    },
    /// Summarise what has been crawled and what is waiting
    Stats {
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
    },
    /// List sites: the biggest first, or those with a given status
    Sites {
        /// Only sites with this status: done, paused, not_listing, unreachable,
        /// robots_disallowed, low_value, sensitive, skipped, opted_out, partial
        #[arg(long)]
        status: Option<String>,
        #[arg(long, value_enum, default_value_t = SortArg::Size)]
        sort: SortArg,
        #[arg(long, short = 'n', default_value_t = 40)]
        limit: usize,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
    },
    /// Apply the current rules (opt-out, skip list, sensitive names, quality) to what is stored
    Clean {
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        #[command(flatten)]
        crawl_args: CrawlArgs,
    },
    /// Remove everything known about sites, so they are crawled or re-checked from scratch
    Forget {
        #[arg(required = true)]
        hosts: Vec<String>,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SortArg {
    Size,
    Files,
    Recent,
    Name,
}

#[derive(Args, Clone)]
struct CrawlArgs {
    /// Sites crawled at the same time
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
    /// Directory budget per site per run; the rest continues next run
    #[arg(long, default_value_t = 5_000)]
    max_dirs: u64,
    #[arg(long, default_value_t = 32)]
    max_depth: usize,
    /// Opt-out list: one domain per line
    #[arg(long, default_value = "lists/optout.txt")]
    optout: PathBuf,
    /// Skip list: sites and folder patterns not to crawl
    #[arg(long, default_value = "lists/skip.txt")]
    skip: PathBuf,
    /// Follow links to any directory, not only ones that look like a public archive
    #[arg(long)]
    broad: bool,
    /// Drop a site you did not add unless it has at least this many big files (10 MiB+)...
    #[arg(long, default_value_t = 3)]
    min_big: u64,
    /// ...or at least this many useful files (archives, disk images, documents, audio, video, data)
    #[arg(long, default_value_t = 20)]
    min_useful: u64,
    /// Keep every site, even one with nothing useful
    #[arg(long)]
    keep_all: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Auto {
            hours,
            seeds,
            discover_files,
            crawl,
            db,
            crawl_args,
        } => run_auto(hours, &seeds, discover_files, crawl, db, crawl_args).await,
        Command::Crawl {
            urls,
            seeds,
            candidates,
            max_sites,
            hours,
            db,
            crawl_args,
        } => {
            let explicit = read_seeds(urls, seeds.as_deref())?;
            if explicit.is_empty() && !candidates {
                bail!("no seed URLs: pass URLs, --seeds FILE, or --candidates");
            }
            let stop = stop_on_ctrl_c();
            if let Some(hours) = hours {
                stop_after(&stop, hours)?;
            }
            let pending = candidates.then(|| Pending {
                db: db.clone(),
                max_hosts: max_sites,
            });
            let cfg = crawl_config(&crawl_args)?;
            let every = Duration::from_secs(5);
            run_crawl(explicit, pending, cfg, &db, stop, every).await?;
            eprintln!("Saved to {}. Try: opendir search <words>", db.display());
            Ok(())
        }
        Command::Discover {
            crawl,
            files,
            parallel,
            db,
            skip,
            broad,
        } => {
            let skip = load_skip(&skip)?;
            let stop = stop_on_ctrl_c();
            run_discover(crawl, files, parallel, (skip, broad), &db, stop).await?;
            eprintln!("Next: opendir crawl --candidates --db {}", db.display());
            Ok(())
        }
        Command::Search {
            query,
            db,
            limit,
            ext,
            min_mb,
            unfiltered,
            takedown,
            optout,
        } => {
            let conn = store::open_existing(&db)?;
            let takedown = load_list_or_warn(&takedown, "takedown")?
                .iter()
                .map(|p| filters::normalize_url_prefix(p))
                .collect();
            let opts = store::SearchOptions {
                limit,
                ext,
                min_bytes: min_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
                unfiltered,
                takedown,
                optout: load_optout(&optout)?,
            };
            let hits = store::search(&conn, &query.join(" "), opts)?;
            if hits.is_empty() {
                println!("No results.");
            }
            for hit in hits {
                let size = match (hit.is_dir, hit.size) {
                    (true, _) => "dir".to_string(),
                    (false, Some(bytes)) => human_bytes(bytes),
                    (false, None) => "?".to_string(),
                };
                let mtime = hit.mtime.as_deref().unwrap_or("");
                println!("{size:>10}  {mtime:<19}  {}", hit.url);
            }
            Ok(())
        }
        Command::Stats { db } => print_stats(&db),
        Command::Sites {
            status,
            sort,
            limit,
            db,
        } => print_sites(&db, status.as_deref(), sort, limit),
        Command::Clean { db, crawl_args } => {
            let cfg = crawl_config(&crawl_args)?;
            let mut conn = store::open_existing(&db)?;
            if !clean_stored(&mut conn, &cfg)? {
                println!("Nothing to clean: everything stored follows the current rules.");
            }
            Ok(())
        }
        Command::Forget { hosts, db } => {
            let conn = store::open_existing(&db)?;
            for host in hosts {
                let host = filters::normalize_domain(&host);
                if store::forget(&conn, &host)? {
                    println!(
                        "Forgot {host}. It is crawled again when it is in your seeds or found by discovery."
                    );
                } else {
                    println!("{host} is not in the database.");
                }
            }
            Ok(())
        }
    }
}

/// The nightly job: seeds, then discovery (at most a quarter of the time), then
/// crawling until the time is up. Everything resumes on the next run.
async fn run_auto(
    hours: f64,
    seeds: &Path,
    discover_files: usize,
    crawl: String,
    db: PathBuf,
    crawl_args: CrawlArgs,
) -> Result<()> {
    eprintln!(
        "=== opendir auto started {} (stops after {hours} h)",
        utc_now()
    );
    let stop = stop_on_ctrl_c();
    stop_after(&stop, hours)?;
    let cfg = crawl_config(&crawl_args)?;

    if seeds.exists() {
        let urls = read_seeds(Vec::new(), Some(seeds))?;
        let retried = store::add_seeds(&store::open(&db)?, &urls)?;
        eprintln!(
            "Seeds: {} URLs from {} ({retried} sites that failed before are tried again; finished sites are skipped)",
            urls.len(),
            seeds.display()
        );
    } else {
        eprintln!("warning: seed list {} not found", seeds.display());
    }

    if discover_files > 0 && !stop.is_cancelled() {
        let discover_stop = stop.child_token();
        let quarter = discover_stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs_f64(hours * 3600.0 / 4.0)).await;
            quarter.cancel();
        });
        // A night without Common Crawl is still a useful night of crawling.
        let filter = (cfg.skip.clone(), cfg.broad);
        if let Err(e) = run_discover(crawl, discover_files, 4, filter, &db, discover_stop).await {
            eprintln!("Discovery skipped: {e:#}");
        }
    }

    if !stop.is_cancelled() {
        let pending = Pending {
            db: db.clone(),
            max_hosts: None,
        };
        run_crawl(
            Vec::new(),
            Some(pending),
            cfg,
            &db,
            stop,
            Duration::from_secs(60),
        )
        .await?;
    }
    eprintln!("=== opendir auto finished {}", utc_now());
    print_stats(&db)
}

fn load_optout(path: &Path) -> Result<Vec<String>> {
    Ok(load_list_or_warn(path, "opt-out")?
        .iter()
        .map(|d| filters::normalize_domain(d))
        .collect())
}

fn load_skip(path: &Path) -> Result<filters::SkipList> {
    Ok(filters::SkipList::from_lines(&load_list_or_warn(
        path, "skip",
    )?))
}

fn crawl_config(args: &CrawlArgs) -> Result<CrawlConfig> {
    let quality = if args.keep_all {
        Thresholds::OFF
    } else {
        Thresholds {
            min_big: args.min_big,
            min_useful: args.min_useful,
        }
    };
    Ok(CrawlConfig {
        concurrency: args.concurrency,
        max_dirs_per_host: args.max_dirs,
        max_depth: args.max_depth,
        optout: load_optout(&args.optout)?,
        skip: load_skip(&args.skip)?,
        quality,
        broad: args.broad,
        ..CrawlConfig::default()
    })
}

/// Seed URLs from the command line and a seed list: a file, or a folder whose
/// `*.txt` files are all read.
fn read_seeds(mut raw: Vec<String>, list: Option<&Path>) -> Result<Vec<Url>> {
    if let Some(list) = list {
        if !list.exists() {
            bail!("seed list {} not found", list.display());
        }
        let files = if list.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(list)?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|ext| ext == "txt"))
                .collect();
            files.sort();
            files
        } else {
            vec![list.to_path_buf()]
        };
        for file in files {
            raw.extend(filters::load_list(&file)?);
        }
    }
    let mut seeds: Vec<Url> = Vec::new();
    for s in raw {
        match Url::parse(&s) {
            Ok(url) if matches!(url.scheme(), "http" | "https") && url.host().is_some() => {
                // The same URL in two lists is crawled once.
                if !seeds.contains(&url) {
                    seeds.push(url)
                }
            }
            _ => eprintln!("skipping seed that is not an http(s) URL: {s}"),
        }
    }
    Ok(seeds)
}

/// A missing list is allowed, but say so: it usually means the command was run
/// from another folder and the list is being silently ignored.
fn load_list_or_warn(path: &Path, what: &str) -> Result<Vec<String>> {
    if !path.exists() {
        eprintln!(
            "warning: {what} list {} not found, so it is empty (run from the project folder, or pass its path)",
            path.display()
        );
    }
    filters::load_list(path)
}

/// Cancels the returned token on Ctrl-C. A second Ctrl-C explains the wait;
/// a third quits at once.
fn stop_on_ctrl_c() -> CancellationToken {
    let stop = CancellationToken::new();
    let token = stop.clone();
    tokio::spawn(async move {
        let mut presses = 0;
        while tokio::signal::ctrl_c().await.is_ok() {
            presses += 1;
            match presses {
                1 => {
                    eprintln!("\nStopping: saving what was found...");
                    token.cancel();
                }
                2 => eprintln!("Still saving. Press Ctrl-C again to quit without saving."),
                _ => std::process::exit(130),
            }
        }
    });
    stop
}

/// Cancels `stop` after `hours`.
fn stop_after(stop: &CancellationToken, hours: f64) -> Result<()> {
    if !(hours.is_finite() && hours > 0.0) {
        bail!("--hours must be a positive number");
    }
    let token = stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs_f64(hours * 3600.0)).await;
        if !token.is_cancelled() {
            eprintln!("Time is up ({hours} h): stopping and saving...");
            token.cancel();
        }
    });
    Ok(())
}

/// Applies today's rules to what is stored, and says what was removed.
/// Returns false if there was nothing to do.
fn clean_stored(conn: &mut rusqlite::Connection, cfg: &CrawlConfig) -> Result<bool> {
    let rules = CleanRules {
        optout: &cfg.optout,
        skip: &cfg.skip,
        quality: cfg.quality,
    };
    let report = store::clean(conn, &rules)?;
    print_clean_report(&report);
    Ok(!report.is_empty())
}

fn print_clean_report(report: &CleanReport) {
    for host in &report.opted_out {
        eprintln!("Removed {host}: it is on the opt-out list");
    }
    for host in &report.skipped_hosts {
        eprintln!("Removed {host}: it is on the skip list");
    }
    if report.skipped_dirs > 0 {
        eprintln!(
            "Removed {} stored listings inside skipped folders",
            report.skipped_dirs
        );
    }
    for (host, why) in &report.sensitive {
        eprintln!("Removed {host}: it looks like an accidental exposure ({why})");
    }
    if report.omitted_entries > 0 {
        eprintln!(
            "Removed {} sensitive-looking files from sites you added",
            report.omitted_entries
        );
    }
    if !report.low_value.is_empty() {
        eprintln!(
            "Removed {} sites with nothing worth keeping (see them with: opendir sites --status low_value)",
            report.low_value.len()
        );
    }
}

async fn run_crawl(
    seeds: Vec<Url>,
    pending: Option<Pending>,
    mut cfg: CrawlConfig,
    db: &Path,
    stop: CancellationToken,
    progress_every: Duration,
) -> Result<()> {
    let mut conn = store::open(db)?;
    // Sites you name now are trusted, so the cleanup below cannot judge them.
    store::trust_hosts(&conn, &seeds)?;
    clean_stored(&mut conn, &cfg)?;
    cfg.sensitive_hosts = store::sensitive_hosts(&conn)?.into_iter().collect();
    drop(conn);
    let (tx, writer) = store::spawn_writer(db.to_path_buf())?;
    let stats = Arc::new(Stats::default());
    let started = Instant::now();
    let progress = {
        let stats = stats.clone();
        spawn_ticker(progress_every, move || progress_line(&stats, started))
    };

    let result = crawler::crawl(seeds, pending, cfg, tx, stop, stats.clone()).await;
    progress.abort();
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("database writer panicked"))?
        .context("writing to the database")?;
    result?;
    eprintln!("{}", progress_line(&stats, started));
    Ok(())
}

/// `filter` is the skip list and whether to keep listings with no archive signal.
async fn run_discover(
    crawl: String,
    files: usize,
    parallel: usize,
    filter: (filters::SkipList, bool),
    db: &Path,
    stop: CancellationToken,
) -> Result<DiscoverSummary> {
    let done = store::done_cc_files(&store::open(db)?)?;
    let mut cfg = DiscoverConfig::new(crawl, files, parallel, done);
    (cfg.skip, cfg.broad) = filter;
    let (tx, writer) = store::spawn_writer(db.to_path_buf())?;
    let stats = Arc::new(DiscoverStats::default());
    let started = Instant::now();
    let progress = {
        let stats = stats.clone();
        spawn_ticker(Duration::from_secs(5), move || {
            discover_line(&stats, started)
        })
    };

    let result = commoncrawl::discover(cfg, tx, stop, stats.clone()).await;
    progress.abort();
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("database writer panicked"))?
        .context("writing to the database")?;
    let summary = result?;
    eprintln!("{}", discover_line(&stats, started));
    eprintln!(
        "Crawl {}: {} index files not scanned yet (run discover again to continue).",
        summary.crawl, summary.files_left
    );
    Ok(summary)
}

fn spawn_ticker(
    every: Duration,
    line: impl Fn() -> String + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.tick().await;
        loop {
            tick.tick().await;
            eprintln!("{}", line());
        }
    })
}

fn discover_line(stats: &DiscoverStats, started: Instant) -> String {
    format!(
        "[{:>5.0}s] index files {}/{} ({} failed) | {} listings kept, {} left out | {} downloaded",
        started.elapsed().as_secs_f64(),
        stats.files_done.load(Relaxed),
        stats.files_planned.load(Relaxed),
        stats.files_failed.load(Relaxed),
        stats.candidates.load(Relaxed),
        stats.rejected.load(Relaxed),
        human_bytes(stats.bytes.load(Relaxed)),
    )
}

fn progress_line(stats: &Stats, started: Instant) -> String {
    let secs = started.elapsed().as_secs_f64().max(0.001);
    let requests = stats.requests.load(Relaxed);
    let done = stats.hosts_done.load(Relaxed);
    format!(
        "[{:>5.0}s] sites {}/{} ({} active) | {} dirs | {} entries | {} errors | {:.1} req/s",
        secs,
        done,
        stats.hosts_total.load(Relaxed),
        stats.hosts_started.load(Relaxed).saturating_sub(done),
        stats.listings.load(Relaxed),
        stats.entries.load(Relaxed),
        stats.errors.load(Relaxed),
        requests as f64 / secs,
    )
}

fn print_stats(db: &Path) -> Result<()> {
    let conn = store::open_existing(db)?;
    println!(
        "{:<18} {:>8} {:>12} {:>10}",
        "status", "sites", "files", "size"
    );
    for row in store::stats(&conn)? {
        println!(
            "{:<18} {:>8} {:>12} {:>10}",
            row.status,
            row.hosts,
            row.files,
            human_bytes(row.bytes)
        );
    }

    let waiting = store::candidate_stats(&conn)?;
    if !waiting.is_empty() {
        println!();
        println!(
            "{:<28} {:>10} {:>8}",
            "waiting to crawl, from", "dirs", "sites"
        );
        for c in waiting {
            println!("{:<28} {:>10} {:>8}", c.source, c.urls, c.hosts);
        }
    }

    let sensitive = store::sensitive_reasons(&conn)?;
    if !sensitive.is_empty() {
        println!();
        println!("Dropped as sensitive (use `opendir forget <site>` to re-check one):");
        for (host, reason) in sensitive {
            println!("  {host}: {reason}");
        }
    }
    Ok(())
}

fn print_sites(db: &Path, status: Option<&str>, sort: SortArg, limit: usize) -> Result<()> {
    let conn = store::open_existing(db)?;
    let sort = match sort {
        SortArg::Size => SiteSort::Size,
        SortArg::Files => SiteSort::Files,
        SortArg::Recent => SiteSort::Recent,
        SortArg::Name => SiteSort::Name,
    };
    let sites = store::sites(&conn, status, sort, limit)?;
    if sites.is_empty() {
        println!("No sites.");
        return Ok(());
    }
    println!(
        "{:<36} {:<17} {:>9} {:>10} {:>6}  note",
        "site", "status", "files", "size", "dirs"
    );
    for site in sites {
        let note = site.reason.or(site.server).unwrap_or_default();
        println!(
            "{:<36} {:<17} {:>9} {:>10} {:>6}  {}",
            truncate(&site.host, 36),
            site.status,
            site.files,
            human_bytes(site.bytes),
            site.dirs,
            truncate(&note, 70)
        );
    }
    Ok(())
}

/// Cuts `text` to at most `max` characters, ending with `…` if it was longer.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// The current time in UTC, for log lines.
fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_seed_lists_are_valid_and_public() {
        let seeds = read_seeds(Vec::new(), Some(Path::new("seeds"))).unwrap();
        assert!(seeds.len() > 80, "{} seeds", seeds.len());
        for url in &seeds {
            assert!(filters::is_public_host(url), "{url}");
            assert!(url.path().ends_with('/'), "a seed is a folder: {url}");
            assert!(url.query().is_none(), "{url}");
        }
        // Every list contributes, and nothing is listed twice.
        let mut unique = seeds.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), seeds.len());
        let hosts: std::collections::HashSet<_> =
            seeds.iter().filter_map(|u| u.host_str()).collect();
        assert!(hosts.contains("releases.ubuntu.com") && hosts.contains("ftp.ncbi.nlm.nih.gov"));
    }

    #[test]
    fn the_bundled_skip_list_keeps_package_archives_and_website_junk_out() {
        let lines = filters::load_list(Path::new("lists/skip.txt")).unwrap();
        let skip = filters::SkipList::from_lines(&lines);
        let skipped = |u: &str| skip.skips_folder(&Url::parse(u).unwrap());
        for junk in [
            "https://mirror.example.edu/ubuntu/pool/main/",
            "https://mirror.example.edu/fedora/updates/repodata/",
            "https://blog.example.com/wp-content/uploads/2020/05/",
            "https://example.org/cgi-bin/",
            "https://example.org/backup/",
        ] {
            assert!(skipped(junk), "{junk}");
        }
        for fine in [
            "https://releases.ubuntu.com/24.04/",
            "https://ftp.gnu.org/gnu/emacs/",
            "https://download.blender.org/release/",
            "https://example.org/pub/data/",
        ] {
            assert!(!skipped(fine), "{fine}");
        }
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(
            truncate("a-very-long-host-name.example.org", 10),
            "a-very-lo…"
        );
    }
}
