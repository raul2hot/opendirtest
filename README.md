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

The crawler only visits sites it has been given. Discovery adds more, as
*candidates* that the next crawl picks up:

- **Links between sites (automatic).** When a listing links to a directory on
  another site, or redirects there, that URL is saved as a candidate. The other
  site is not contacted until you crawl the candidates.
- **Common Crawl (`discover`).** Common Crawl publishes an index of billions of
  pages it has crawled. Apache listings have sort links like `?C=N;O=D`, so their
  URLs stand out in the index. `discover` downloads only the parts of the index
  needed to spot them, and sends nothing to the sites themselves.

```powershell
# Scan 10 of the ~300 index files of the latest crawl (runs resume where they stopped).
.\target\release\opendir.exe discover --files 10

# Crawl the sites found so far (up to 1000 per round), following new links for 3 rounds.
.\target\release\opendir.exe crawl --candidates --rounds 3 --max-dirs 500

.\target\release\opendir.exe stats
```

The discover progress line shows how much it downloaded. Try `--files 1` first to
see what one index file costs on your connection. Use `--crawl CC-MAIN-2026-30` to
pick a specific crawl instead of the latest.

## Commands

| Command | What it does |
|---|---|
| `crawl [URL...] [--seeds FILE] [--candidates]` | Crawls the given directory URLs, and with `--candidates` the discovered sites not crawled yet (`--hosts` per round, default 1000; `--rounds`, default 1). Options: `--db` (default `opendir.db`), `--concurrency` (sites crawled at once, default 256), `--max-dirs` (directory budget per site, default 20000), `--max-depth` (default 32), `--optout` (default `lists/optout.txt`). |
| `discover` | Finds listings in the Common Crawl index. Options: `--crawl` (default `latest`), `--files` (index files this run, default 10), `--parallel` (default 4), `--db`. |
| `search WORDS...` | Full-text search over file and folder names. Options: `--ext iso`, `-n 50`, `--unfiltered` (show results the piracy filter hides), `--takedown` (default `lists/takedown.txt`). |
| `stats` | Sites per crawl status with file counts and total size, discovery candidates, and why any site was dropped as sensitive. |

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
- Sites are crawled round by round: a round ends when its slowest site finishes.
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
