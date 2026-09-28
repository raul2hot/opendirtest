use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use url::Url;

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
    /// Crawl open directories, starting from seed URLs
    Crawl {
        /// Seed directory URLs
        urls: Vec<String>,
        /// File with one seed URL per line (# starts a comment)
        #[arg(long, short)]
        seeds: Option<PathBuf>,
        #[arg(long, default_value = "opendir.db")]
        db: PathBuf,
        /// Hosts crawled at the same time
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        /// Directory budget per host
        #[arg(long, default_value_t = 20_000)]
        max_dirs: u64,
        #[arg(long, default_value_t = 32)]
        max_depth: usize,
        /// Opt-out list: one domain per line
        #[arg(long, default_value = "lists/optout.txt")]
        optout: PathBuf,
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
    /// Summarise what has been crawled
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
            db,
            concurrency,
            max_dirs,
            max_depth,
            optout,
        } => {
            let cfg = CrawlConfig {
                concurrency,
                max_dirs_per_host: max_dirs,
                max_depth,
                optout: filters::load_list(&optout)?,
                ..CrawlConfig::default()
            };
            run_crawl(read_seeds(urls, seeds.as_deref())?, cfg, db).await
        }
        Command::Search {
            query,
            db,
            limit,
            ext,
            unfiltered,
            takedown,
        } => {
            let conn = store::open(&db)?;
            let opts = store::SearchOptions {
                limit,
                ext,
                unfiltered,
                takedown: filters::load_list(&takedown)?,
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
        Command::Stats { db } => {
            let conn = store::open(&db)?;
            println!(
                "{:<18} {:>8} {:>12} {:>10}",
                "status", "hosts", "files", "size"
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
            Ok(())
        }
    }
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
    if seeds.is_empty() {
        bail!("no seed URLs: pass URLs or --seeds FILE");
    }
    Ok(seeds)
}

async fn run_crawl(seeds: Vec<Url>, mut cfg: CrawlConfig, db: PathBuf) -> Result<()> {
    cfg.skip_hosts = store::sensitive_hosts(&store::open(&db)?)?
        .into_iter()
        .collect();
    let (tx, writer) = store::spawn_writer(db.clone())?;

    let stop = Arc::new(AtomicBool::new(false));
    let on_ctrl_c = stop.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\nStopping: finishing in-flight requests and saving...");
            on_ctrl_c.store(true, Relaxed);
        }
    });

    let stats = Arc::new(Stats::default());
    let started = Instant::now();
    let progress = tokio::spawn(print_progress(stats.clone(), started));

    crawler::crawl(seeds, cfg, tx, stop, stats.clone()).await?;
    progress.abort();
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("database writer panicked"))?
        .context("writing to the database")?;

    eprintln!("{}", progress_line(&stats, started));
    eprintln!(
        "Saved to {}. Try: opendir search <words> --db {}",
        db.display(),
        db.display()
    );
    Ok(())
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
        "[{:>5.0}s] hosts {}/{} ({} active) | {} dirs | {} entries | {} errors | {:.1} req/s",
        secs,
        done,
        stats.hosts_total.load(Relaxed),
        stats.hosts_started.load(Relaxed) - done,
        stats.listings.load(Relaxed),
        stats.entries.load(Relaxed),
        stats.errors.load(Relaxed),
        requests as f64 / secs,
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
