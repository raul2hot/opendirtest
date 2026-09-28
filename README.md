# opendirtest

A fast, polite scanner and indexer for **public, legal open directories**. These are web
servers that publish auto-generated file listings, such as software mirrors, public
datasets and academic archives.

It stores file metadata only (name, size, date) and never downloads files. It follows
robots.txt, sends at most about one request per second to each site, and drops sites that
look like accidental leaks.

## Quick start (Windows)

1. Install Rust from <https://rustup.rs>. When the installer asks, let it install the
   Visual Studio C++ build tools.
2. Build it:

   ```powershell
   git clone https://github.com/raul2hot/opendirtest
   cd opendirtest
   cargo build --release
   ```

3. Crawl the bundled list of official mirrors. `--max-dirs 500` keeps the first run to
   roughly 10 minutes (longer for sites whose robots.txt asks for a slower pace):

   ```powershell
   .\target\release\opendir.exe crawl --seeds seeds\mirrors.txt --max-dirs 500
   ```

4. Search and inspect:

   ```powershell
   .\target\release\opendir.exe search ubuntu desktop --ext iso
   .\target\release\opendir.exe search debian netinst -n 50
   .\target\release\opendir.exe search linux --ext xz
   .\target\release\opendir.exe stats
   ```

Press Ctrl-C during a crawl to stop cleanly. Everything found so far is saved.
On Linux or macOS, the same commands work with `./target/release/opendir`.

## Finding new sites

The crawler only visits sites it has been given. Discovery adds more to a list of
sites *waiting to crawl*, which `crawl --candidates` (and `auto`) work through:

- **Links between sites (automatic).** When a listing links to a directory on
  another site, or redirects there, that site is added to the waiting list. With
  `--candidates` it is crawled in the same run; otherwise it waits.
- **Common Crawl (`discover`).** Common Crawl publishes an index of billions of
  pages it has crawled. Apache listings have sort links like `?C=N;O=D`, so their
  URLs stand out in the index. `discover` downloads only the parts of the index
  needed to spot them, and sends nothing to the sites themselves.

```powershell
# Scan 10 of the ~300 index files of the latest crawl (runs resume where they stopped).
.\target\release\opendir.exe discover --files 10

# Crawl everything waiting, including sites found along the way, for up to 2 hours.
.\target\release\opendir.exe crawl --candidates --hours 2

.\target\release\opendir.exe stats
```

The discover progress line shows how much it downloaded. Try `--files 1` first to
see what one index file costs on your connection. Use `--crawl CC-MAIN-2026-30` to
pick a specific crawl instead of the latest.

## Running every night (Windows)

`opendir auto` is made for a scheduled task. Each run:

1. adds the sites in `seeds\mirrors.txt` that were never crawled,
2. scans 10 more Common Crawl index files (at most a quarter of the time; if Common
   Crawl can't be reached, it just skips this),
3. crawls the waiting sites until the time is up, including sites found that night,
4. stops cleanly. Sites it didn't finish are marked `paused`, and the next run
   carries on from where they stopped, without re-fetching what it already has.

Each site also has a budget of 20,000 directories per run (`--max-dirs`). A bigger
mirror is paused at that point and continues the next night, so one huge site
can't take a whole night's slot.

`nightly.bat` in the project folder runs `auto --hours 7` and appends its output to
`logs\nightly.log`. Change the hours in it to fit your night. To set it up:

1. Build once: `cargo build --release`.
2. Try a 3-minute run to check everything works:
   `.\target\release\opendir.exe auto --hours 0.05`
3. Schedule it for every night at 23:30 (adjust the path and time):

   ```
   schtasks /Create /TN "opendir nightly" /TR "D:\opendirtest\nightly.bat" /SC DAILY /ST 23:30
   ```

4. Keep the PC from sleeping at night: in Windows Settings, go to System, then
   Power, and set sleep to *Never* when plugged in. Or open Task Scheduler, find
   "opendir nightly", and under **Conditions** tick *Wake the computer to run this
   task*. Under **Settings**, *Run task as soon as possible after a scheduled start
   is missed* covers nights when the PC was off.

Useful commands: `schtasks /Run /TN "opendir nightly"` starts it now, and
`schtasks /Delete /TN "opendir nightly" /F` removes it. The task as created runs
while you are logged in (a locked screen is fine). To run it when logged out, open
the task in Task Scheduler and choose *Run whether user is logged on or not*.

During the day, browse the results with `opendir search`, `opendir stats`, or a
database browser (see below). If you use DB Browser for SQLite while a run is going,
open the database read-only.

## Browsing the database

- `opendir search <words>` and `opendir stats` from the command line.
- [DB Browser for SQLite](https://sqlitebrowser.org/dl/): open `opendir.db` and use
  *Browse Data* on the `entries` and `hosts` tables.
- [Datasette](https://datasette.io/) (needs Python): `pip install datasette`, then
  `datasette opendir.db` and open http://127.0.0.1:8001 for search and filters.

## Commands

| Command | What it does |
|---|---|
| `auto` | The nightly job described above. Options: `--hours` (default 7), `--seeds` (default `seeds/mirrors.txt`), `--discover-files` (default 10, 0 to skip), `--crawl`, `--db`, and the crawl options below. |
| `crawl [URL...] [--seeds FILE] [--candidates]` | Crawls the given directory URLs, and with `--candidates` every site waiting in the database (found by discovery, or paused). Options: `--hours` (time limit), `--max-sites` (sites to take from the waiting list), `--db` (default `opendir.db`), `--concurrency` (sites crawled at once, default 256), `--max-dirs` (directory budget per site per run, default 20000), `--max-depth` (default 32), `--optout` (default `lists/optout.txt`). |
| `discover` | Finds listings in the Common Crawl index. Options: `--crawl` (default `latest`), `--files` (index files this run, default 10), `--parallel` (default 4), `--db`. |
| `search WORDS...` | Full-text search over file and folder names. Options: `--ext iso`, `-n 50`, `--unfiltered` (show results the piracy filter hides), `--takedown` (default `lists/takedown.txt`). |
| `stats` | Sites per crawl status with file counts and total size, what is waiting to be crawled, and why any site was dropped as sensitive. |
| `forget SITE...` | Removes everything known about a site, so it is crawled or re-checked from scratch the next time it is in the seeds or found again. |

Everything lives in one SQLite file (`opendir.db`), so you can also query it with any
SQLite tool.

## How it works

- **One task per site.** Each site's directories are walked one request at a time, at
  least 1 second apart (longer if robots.txt asks for a `Crawl-delay`). Up to
  `--concurrency` sites run at once, so total speed grows with the number of sites.
- **robots.txt first**, following RFC 9309, for every scheme/host/port the crawl touches,
  including redirect targets. A 4xx means no rules. A 5xx, 429 or network error means
  stay out.
- **Never downloads files.** Only pages served as HTML or JSON are read; anything else,
  including a response without a Content-Type, is skipped unread.
- **Listing parser** for Apache, nginx (plain and fancyindex), lighttpd, IIS, Python
  `http.server` and Caddy (asks Caddy for JSON). Pages that are not listings are skipped.
- **Loop guards:** a directory whose listing matches one already seen on that site (for
  example a symlink back to its parent) is indexed but not descended into. There are
  also depth, URL length and per-site budget limits.
- **Search-time filters:** names that look like pirated media or cracked software, and
  URLs on the takedown list, are hidden from results but not from the crawl.

The safety behaviours are constant boolean flags in [`src/safety.rs`](src/safety.rs). All
of them default to `true`. The design rationale is in [`docs/GUIDE.md`](docs/GUIDE.md).

## For site owners

This crawler identifies itself as:

```
opendirtest/0.1.0 (+https://github.com/raul2hot/opendirtest)
```

It only reads directory listing pages (never the files themselves), and it sends at most
about one request per second to your site.

To opt out, add this to your `robots.txt`:

```
User-agent: opendirtest
Disallow: /
```

You can also open an issue on this repository to have your domain added to
[`lists/optout.txt`](lists/optout.txt). For takedown or deletion requests, open an
issue with the URLs; they go into [`lists/takedown.txt`](lists/takedown.txt).

## Limits

- Common Crawl discovery recognises Apache and nginx-fancyindex listings (they have sort
  links). Plain nginx listings are found only through seeds and links.
- Sites that failed with too many errors (`partial`) or were unreachable are not retried
  automatically; use `forget` to retry one.
- A new crawl re-fetches everything. Entries that disappeared from a site stay in the
  database until you delete the database file.
- Dates are stored as the server shows them, with no time zone.
- JavaScript-based listers (h5ai, AList, File Browser) and Go's bare `http.FileServer`
  pages are not recognised.

## Development

```
cargo test
cargo clippy --all-targets -- -D warnings
```

The parser tests use saved listings in [`tests/fixtures`](tests/fixtures). The crawl and
discovery tests in [`tests/`](tests) run against a small local HTTP server; the discovery
test serves a synthetic index file with Common Crawl's columns.
