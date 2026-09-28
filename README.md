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
   .\target\release\opendir.exe search ubuntu iso
   .\target\release\opendir.exe search debian --ext iso -n 50
   .\target\release\opendir.exe stats
   ```

Press Ctrl-C during a crawl to stop cleanly. Everything found so far is saved.
On Linux or macOS, the same commands work with `./target/release/opendir`.

## Commands

| Command | What it does |
|---|---|
| `crawl [URL...] [--seeds FILE]` | Crawls the given directory URLs. Options: `--db` (default `opendir.db`), `--concurrency` (sites crawled at once, default 256), `--max-dirs` (directory budget per site, default 20000), `--max-depth` (default 32), `--optout` (default `lists/optout.txt`). |
| `search WORDS...` | Full-text search over file and folder names. Options: `--ext iso`, `-n 50`, `--unfiltered` (show results the piracy filter hides), `--takedown` (default `lists/takedown.txt`). |
| `stats` | Sites per crawl status, with file counts and total size. |

Everything lives in one SQLite file (`opendir.db`), so you can also query it with any
SQLite tool.

## How it works

- **One task per site.** Each site's directories are walked one request at a time, at
  least 1 second apart (longer if robots.txt asks for a `Crawl-delay`). Up to
  `--concurrency` sites run at once, so total speed grows with the number of sites.
- **robots.txt first**, following RFC 9309. A 4xx means no rules. A 5xx, 429 or network
  error means stay out.
- **Listing parser** for Apache, nginx (plain and fancyindex), lighttpd, IIS, Python
  `http.server` and Caddy (asks Caddy for JSON). Pages that are not listings are skipped.
- **Loop guards:** a directory whose listing matches one already seen on that site (for
  example a symlink back to its parent) is not descended into. There are also depth, URL
  length and per-site budget limits.
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

## v1 limits

- Seeds come from you (or `seeds/mirrors.txt`). Discovery from Common Crawl, Censys and
  similar sources (guide §3) is not built yet.
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

The parser tests use saved listings in [`tests/fixtures`](tests/fixtures). The crawl
tests in [`tests/crawl.rs`](tests/crawl.rs) run against a small local HTTP server.
