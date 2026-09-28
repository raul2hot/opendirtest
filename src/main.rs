use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use url::Url;

use opendirtest::commoncrawl::{self, DiscoverConfig, DiscoverStats};
use opendirtest::crawler::{self, CrawlConfig, Stats};
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
    /// Crawl open directories, starting from seed URLs and/or discovered candidates
    Crawl {
        /// Seed directory URLs
        urls: Vec<String>,
        /// File with one seed URL per line (# starts a comment)
        #[arg(long, short)]
        seeds: Option<PathBuf>,
        /// Also crawl sites found by discovery (links and Common Crawl) that were never crawled
        #[arg(long)]
        candidates: bool,
        /// With --candidates: sites to take from the candidates per round
        #[arg(long, default_value_t = 1000)]
        hosts: usize,
        /// With --candidates: repeat, so sites linked from newly crawled sites get crawled too
        #[arg(long, default_value_t = 1)]
        rounds: usize,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        /// Sites crawled at the same time
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        /// Directory budget per site
        #[arg(long, default_value_t = 20_000)]
        max_dirs: u64,
        #[arg(long, default_value_t = 32)]
        max_depth: usize,
        /// Opt-out list: one domain per line
        #[arg(long, default_value = "lists/optout.txt")]
        optout: PathBuf,
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
    },
    /// Search the index
    Search {
        #[arg(required = true)]
        query: Vec<String>,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        #[arg(long, short = 'n', default_value_t = 20)]
        limit: usize,
        /// Only files with this extension, e.g. `iso`
        #[arg(long)]
        ext: Option<String>,
        /// Include results the likely-infringement filter would hide
        #[arg(long)]
        unfiltered: bool,
        /// Takedown list: one URL prefix per line
        #[arg(long, default_value = "lists/takedown.txt")]
        takedown: PathBuf,
    },
    /// Summarise what has been crawled and discovered
    Stats {
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Crawl {
            urls,
            seeds,
            candidates,
            hosts,
            rounds,
            db,
            concurrency,
            max_dirs,
            max_depth,
            optout,
        } => {
            let explicit = read_seeds(urls, seeds.as_deref())?;
            if explicit.is_empty() && !candidates {
                bail!("no seed URLs: pass URLs, --seeds FILE, or --candidates");
            }
            let optout = load_list_or_warn(&optout, "opt-out")?
                .iter()
                .map(|d| filters::normalize_domain(d))
                .collect();
            let settings = CrawlSettings {
                concurrency,
                max_dirs,
                max_depth,
                optout,
            };
            let rounds = if candidates { rounds.max(1) } else { 1 };
            run_crawl(explicit, candidates.then_some(hosts), rounds, settings, db).await
        }
        Command::Discover {
            crawl,
            files,
            parallel,
            db,
        } => run_discover(crawl, files, parallel, db).await,
        Command::Search {
            query,
            db,
            limit,
            ext,
            unfiltered,
            takedown,
        } => {
            let conn = store::open_existing(&db)?;
            let takedown = load_list_or_warn(&takedown, "takedown")?
                .iter()
                .map(|p| filters::normalize_url_prefix(p))
                .collect();
            let opts = store::SearchOptions {
                limit,
                ext,
                unfiltered,
                takedown,
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
    }
}

struct CrawlSettings {
    concurrency: usize,
    max_dirs: u64,
    max_depth: usize,
    optout: Vec<String>,
}

fn read_seeds(mut raw: Vec<String>, file: Option<&Path>) -> Result<Vec<Url>> {
    if let Some(file) = file {
        if !file.exists() {
            bail!("seed file {} not found", file.display());
        }
        raw.extend(filters::load_list(file)?);
    }
    let mut seeds = Vec::new();
    for s in raw {
        match Url::parse(&s) {
            Ok(url) if matches!(url.scheme(), "http" | "https") && url.host().is_some() => {
                seeds.push(url)
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

async fn run_crawl(
    explicit: Vec<Url>,
    candidate_hosts: Option<usize>,
    rounds: usize,
    settings: CrawlSettings,
    db: PathBuf,
) -> Result<()> {
    let stop = stop_on_ctrl_c();
    let mut explicit = Some(explicit);
    for round in 1..=rounds {
        let conn = store::open(&db)?;
        let mut seeds = explicit.take().unwrap_or_default();
        if let Some(max_hosts) = candidate_hosts {
            seeds.extend(store::pending_candidates(&conn, max_hosts)?);
        }
        let skip_hosts = store::sensitive_hosts(&conn)?.into_iter().collect();
        drop(conn);
        if seeds.is_empty() {
            eprintln!("Nothing to crawl: no pending candidates. Run `opendir discover` first.");
            break;
        }
        if rounds > 1 {
            eprintln!("Round {round}/{rounds}: {} seed directories", seeds.len());
        }

        let cfg = CrawlConfig {
            concurrency: settings.concurrency,
            max_dirs_per_host: settings.max_dirs,
            max_depth: settings.max_depth,
            optout: settings.optout.clone(),
            skip_hosts,
            ..CrawlConfig::default()
        };
        let (tx, writer) = store::spawn_writer(db.clone())?;
        let stats = Arc::new(Stats::default());
        let started = Instant::now();
        let progress = tokio::spawn(print_progress(stats.clone(), started));

        let result = crawler::crawl(seeds, cfg, tx, stop.clone(), stats.clone()).await;
        progress.abort();
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("database writer panicked"))?
            .context("writing to the database")?;
        result?;
        eprintln!("{}", progress_line(&stats, started));
        if stop.is_cancelled() {
            break;
        }
    }
    eprintln!(
        "Saved to {}. Try: opendir search <words> --db {}",
        db.display(),
        db.display()
    );
    Ok(())
}

async fn run_discover(crawl: String, files: usize, parallel: usize, db: PathBuf) -> Result<()> {
    let done = store::done_cc_files(&store::open(&db)?)?;
    let cfg = DiscoverConfig::new(crawl, files, parallel, done);
    let stop = stop_on_ctrl_c();
    let (tx, writer) = store::spawn_writer(db.clone())?;
    let stats = Arc::new(DiscoverStats::default());
    let started = Instant::now();

    let progress = {
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.tick().await;
            loop {
                tick.tick().await;
                eprintln!("{}", discover_line(&stats, started));
            }
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
        "Crawl {}: {} index files not scanned yet (run `opendir discover` again to continue).",
        summary.crawl, summary.files_left
    );
    eprintln!("Next: opendir crawl --candidates --db {}", db.display());
    Ok(())
}

fn discover_line(stats: &DiscoverStats, started: Instant) -> String {
    format!(
        "[{:>5.0}s] index files {}/{} ({} failed) | {} listing dirs found | {} downloaded",
        started.elapsed().as_secs_f64(),
        stats.files_done.load(Relaxed),
        stats.files_planned.load(Relaxed),
        stats.files_failed.load(Relaxed),
        stats.candidates.load(Relaxed),
        human_bytes(stats.bytes.load(Relaxed)),
    )
}

async fn print_progress(stats: Arc<Stats>, started: Instant) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.tick().await;
    loop {
        tick.tick().await;
        eprintln!("{}", progress_line(&stats, started));
    }
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

    let candidates = store::candidate_stats(&conn)?;
    if !candidates.is_empty() {
        println!();
        println!(
            "{:<28} {:>10} {:>8} {:>14}",
            "candidates from", "dirs", "sites", "not crawled"
        );
        for c in candidates {
            println!(
                "{:<28} {:>10} {:>8} {:>14}",
                c.source, c.urls, c.hosts, c.pending_hosts
            );
        }
    }

    let sensitive = store::sensitive_reasons(&conn)?;
    if !sensitive.is_empty() {
        println!();
        println!("Dropped as sensitive:");
        for (host, reason) in sensitive {
            println!("  {host}: {reason}");
        }
    }
    Ok(())
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
