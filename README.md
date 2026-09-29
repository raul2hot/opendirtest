# opendirtest

A fast, polite scanner and indexer for **public, legal open directories**. These are web
servers that publish auto-generated file listings, such as software mirrors, public
datasets and academic archives.

It stores file metadata only (name, size, date) and never downloads files. It follows
robots.txt, sends at most about one request per second to each site, drops sites that
look like accidental leaks or hacked servers, and keeps only sites that hold real
downloads.

## Quick start (Windows)

1. Install Rust from <https://rustup.rs>. When the installer asks, let it install the
   Visual Studio C++ build tools.
2. Build it:

   ```powershell
   git clone https://github.com/raul2hot/opendirtest
   cd opendirtest
   cargo build --release
   ```

3. Crawl the bundled starting points: about 100 official archives (operating system
   images, big mirrors, open source releases, science data, books). All sites run in
   parallel, and `--max-dirs 300` limits each to 300 folders, so this takes roughly
   10 minutes:

   ```powershell
   .\target\release\opendir.exe crawl --seeds seeds --max-dirs 300
   ```

4. Look at what you got:

   ```powershell
   .\target\release\opendir.exe sites
   .\target\release\opendir.exe search ubuntu desktop --ext iso
   .\target\release\opendir.exe search dataset --ext csv,parquet --min-mb 100
   .\target\release\opendir.exe stats
   ```

Press Ctrl-C during a crawl to stop cleanly. Everything found so far is saved.
On Linux or macOS, the same commands work with `./target/release/opendir`.

## Seeds: where the crawl starts

The crawler visits the sites you give it and the sites it finds. Good seeds decide
whether the database is full of useful things. [`seeds/`](seeds) holds lists you can
edit, one folder URL per line:

| File | What is in it |
|---|---|
| `os-images.txt` | Ubuntu, Debian, Fedora, Rocky, Arch, openSUSE, the BSDs, Alpine, Kali, ... |
| `mirrors.txt` | Big university and research-network mirrors. They hold old software collections and open data far beyond the distributions. |
| `software.txt` | Release servers of GNU, the Linux kernel, Mozilla, KDE, GNOME, Blender, Python, Node.js, ... |
| `science-data.txt` | NCBI, EBI, UCSC, NOAA, NASA, US Census, OpenStreetMap, Wikimedia dumps, internet registries. |
| `books-media.txt` | Project Gutenberg, CTAN, PubMed Central open access, Xiph and Chaos Computer Club media. |

`crawl --seeds seeds` and `auto` read every `.txt` file in the folder. Put your own
lists next to them.

Sites you add are **trusted**: they are never dropped for holding too little (see below).
If an address you added has moved, so that it redirects to another site, the new address
is trusted too. That goes one step only (the new address cannot pass trust on again), for
at most 3 addresses per site, and only for addresses you added: a folder inside a site that
redirects elsewhere is just a link.
I could not open most of these addresses from where I wrote them, so a few may not be
plain listings. After the first run, `opendir sites --status not_listing` and
`--status unreachable` show which ones did not work; delete those lines.

## Finding new sites

Discovery adds more sites to a list of sites *waiting to crawl*, which
`crawl --candidates` (and `auto`) work through:

- **Links between sites (automatic).** When a listing links to a directory on another
  site, or redirects there, and the address looks like a public archive, that site is
  added to the waiting list.
- **Common Crawl (`discover`).** Common Crawl publishes an index of billions of pages it
  has crawled. Apache listings have sort links like `?C=N;O=D`, so their URLs stand out.
  `discover` downloads only the parts of the index needed to spot them, and sends
  nothing to the sites themselves.

Most open directories a web crawl finds are website internals, such as image and
upload folders. Discovery therefore keeps only listings that show a sign of a public
archive: a site name like `ftp.`, `mirror.`, `download.`, `releases.`, `.edu`, `.gov`,
or a folder like `/pub/`, `/mirror/`, `/downloads/`, `/dist/`, `/data/` in the address.
`--broad` turns this filter off. The `discover` progress line shows how many listings
were kept and how many were left out.

```powershell
# Scan 10 of the ~300 index files of the latest crawl (runs resume where they stopped).
.\target\release\opendir.exe discover --files 10

# Crawl everything waiting, including sites found along the way, for up to 2 hours.
.\target\release\opendir.exe crawl --candidates --hours 2
```

Sites are crawled in this order: the ones you added, then ones being continued from an
earlier run, then ones found through links, then Common Crawl finds.

Try `discover --files 1` first to see what one index file costs on your connection. Use
`--crawl CC-MAIN-2026-30` to pick a specific crawl instead of the latest.

## What is kept

Only sites that hold real downloads are kept. A site you did not add is dropped, and
its listings deleted, unless it has at least **3 files of 10 MiB or more**, or at least
**20 files of a useful kind** (disk images, archives, installers, documents, ebooks,
audio, video, data files). Web page files (html, php, js, css, jpg, png, ...) are not a
useful kind (though a file of 10 MiB or more is big whatever it is), a text file counts
only if it is at least 100 KiB (a book or a dataset, not a readme), and a compressed log
(`access.log.3.gz`) is not an archive.

A site that is finished is judged by that rule. One that is still being crawled is
dropped early only when it is junk beyond doubt, because an archive's downloads can be
anywhere: in its top folders, or many levels down next to small folders of docs and
pictures. Every big file and every useful file counts, in whatever folder it was found,
and a site with even one big file is never dropped early. Otherwise it is dropped when

- the folders with nothing below them at the deepest level read so far (where downloads
  hide; the layers above are README and picture folders) are a fair sample: at least 20
  of them, nothing waiting deeper, and at least as many read as still wait (siblings not
  looked at yet can differ), and they hold at least 100 files of which under 5% (in the
  whole site) are of a useful kind; or
- it has cost 2,000 folders and under 1% of what it holds is useful, whatever waits. This
  bounds what an endless site (a calendar that links to next month for ever) can cost.

Anything closer to the line waits for the verdict when the site is finished. A site that
continues from an earlier run is judged the same way, from what its earlier runs read.

Errors do not end a site at once. A run stops after 5 errors in a row, or 50 folders in a
row that the server refuses (403, 404, ...: it is blocking us, or the listing is full of
dead links), and the site stays paused with the folders that failed, to be tried again
the next night. A site that read everything it could but had a few folders fail also
stays paused until they are read. After 5 runs in a row that end in errors the site is
given up and keeps what it has (`partial`, or `unreachable` if nothing was read); it is
dropped if that is plainly junk: at least 100 files, none big, under 5% useful. A single
dead link among live folders is skipped, not retried.

The per-run budget (`--max-dirs`, 5,000 folders by default) counts every folder asked for,
whether or not it answered. A listing page is read up to 32 MiB (a folder of 50,000 files
is about 10 MB); a longer one is cut short, and the site's reason says so. If the only
address a site was found by is inside a skipped folder (a link into a mirror's `/pool/`),
the crawl starts from the site's front page instead.

Change the limits with `--min-big`, `--min-useful`, or `--keep-all`.

Sites are also dropped when a listing looks like an accidental exposure or a broken-into
server: `.env` files, SSH keys, password stores, CMS config files, and folders of links to
other accounts' config files on a hacked host. Weaker signs (a database dump, a dated
backup, a scan of a passport) drop a site you did not add, and cost a site you added only
that file. `opendir sites --status sensitive` shows what was dropped and why.

Dropped sites keep only a one-line record, so they are not found and crawled again. Run
`opendir clean` (it also runs at the start of every crawl) to apply today's rules to what
is already stored, so the database improves when the rules do.

## Running every night (Windows)

`opendir auto` is made for a scheduled task. Each run:

1. adds the sites in the `seeds` folder that were never crawled, and tries again the
   ones that failed before,
2. scans 10 more Common Crawl index files (at most a quarter of the time; if Common
   Crawl can't be reached, it just skips this),
3. crawls the waiting sites until the time is up, including sites found that night,
4. stops cleanly. Sites it didn't finish are marked `paused`, and the next run
   carries on from where they stopped, without re-fetching what it already has.

Each site also has a budget of 5,000 folders per run (`--max-dirs`). A bigger site
is paused at that point and continues the next night, so one huge site can't take
a whole night's slot.

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

## Browsing during the day

- `opendir sites` lists the biggest sites; `--status paused|done|low_value|sensitive|
  not_listing|unreachable|robots_disallowed` lists those with a status, and
  `--sort files|recent|name` changes the order.
- `opendir search <words>` searches file and folder names. `--ext mp3,flac` limits the
  file type, `--min-mb 500` the size, `-n 100` shows more results.
- `opendir stats` counts sites by status and shows what is waiting.
- [DB Browser for SQLite](https://sqlitebrowser.org/dl/): open `opendir.db` and use
  *Browse Data* on the `files` view (every file with its full URL) and the `hosts` table.
  If a run is going, open the database read-only.
- [Datasette](https://datasette.io/) (needs Python): `pip install datasette`, then
  `datasette opendir.db` and open http://127.0.0.1:8001 for search and filters.

## What gets stored, and how much

Only names, sizes and dates, about **140 bytes per file**: a million files take about
140 MB. Each folder's URL is stored once, and the search index keeps no copy of the
text. Reading a folder again replaces what was stored for it, so files that
disappeared from the server disappear here too.

Most of the internet's open directories are software mirrors, and most of a mirror is
package archives: Debian and Ubuntu `pool/`, RPM `Packages/`, CRAN, CPAN and so on.
They are legal but huge, repeated on hundreds of servers, and rarely what you are
after. [`lists/skip.txt`](lists/skip.txt) keeps the crawler out of them, and out of
website junk (`wp-content`, `cgi-bin`, cache and log folders) and other people's backups:

- A line starting with `/` is a folder pattern, matched anywhere in a path and ignoring
  case: `/pool/` skips every folder called `pool` and everything inside it.
- Any other line is a site, e.g. `cran.r-project.org` (its subdomains too).

The list is yours to edit. At the start of each crawl, anything already stored for a
skipped site or folder is removed. Common Crawl finds inside skipped folders are
turned into the site's root, so a mirror's other folders (like ISO images) still get
crawled.

If you have a database from an early version, opendir asks you to start a new one:
delete `opendir.db`, `opendir.db-wal` and `opendir.db-shm`.

A database from just before the quality check is upgraded in place, and opendir says so.
It cannot know which of its sites you added yourself, so they all count as found by
discovery, and the check may remove those that hold little. Sites in your `seeds` folder
are kept. Put any other site you want to keep there, or crawl it once by name with
`crawl URL`, which records it as one of yours before the check runs (and also crawls the
folders it has waiting from earlier runs, which finishing would otherwise discard).

## Commands

| Command | What it does |
|---|---|
| `auto` | The nightly job described above. Options: `--hours` (default 7), `--seeds` (a file or folder, default `seeds`), `--discover-files` (default 10, 0 to skip), `--crawl`, `--db`, and the crawl options below. |
| `crawl [URL...] [--seeds FILE-OR-FOLDER] [--candidates]` | Crawls the given directory URLs, and with `--candidates` every site waiting in the database (found by discovery, or paused). A site paused earlier continues from where it stopped, even when you name it. Options: `--hours` (time limit), `--max-sites`, `--db` (default `opendir.db`). |
| `discover` | Finds listings in the Common Crawl index. Options: `--crawl` (default `latest`), `--files` (index files this run, default 10), `--parallel` (default 4), `--db`, `--skip`, `--broad`. |
| `search WORDS...` | Full-text search over file and folder names. Options: `--ext iso,img`, `--min-mb`, `-n 50`, `--unfiltered` (show results the piracy filter hides), `--takedown`, `--optout`. |
| `sites` | Lists sites with status, files, size and a note. Options: `--status`, `--sort size\|files\|recent\|name`, `-n`. |
| `stats` | Sites per crawl status with file counts and total size, what is waiting to be crawled, and why any site was dropped as sensitive. |
| `clean` | Applies the current opt-out list, skip list, sensitive-name rules and quality check to what is stored. |
| `forget SITE...` | Removes everything known about a site, so it is crawled or re-checked from scratch the next time it is in the seeds or found again. |

Options shared by `auto`, `crawl` and `clean`: `--concurrency` (sites crawled at once,
default 256), `--max-dirs` (folder budget per site per run, default 5000), `--max-depth`
(default 32), `--optout` (default `lists/optout.txt`), `--skip` (default
`lists/skip.txt`), `--broad`, `--min-big`, `--min-useful`, `--keep-all`.

Everything lives in one SQLite file (`opendir.db`), so you can also query it with any
SQLite tool.

## How it works

- **One task per site.** Each site's directories are walked one request at a time, at
  least 1 second apart (longer if robots.txt asks for a `Crawl-delay`). Up to
  `--concurrency` sites run at once, so total speed grows with the number of sites.
- **robots.txt first**, following RFC 9309, for every scheme/host/port the crawl touches,
  including redirect targets. A 4xx means no rules. A 5xx, 429 or network error means
  stay out.
- **Stays out of private networks.** Links or redirects to `localhost`, private IP
  ranges or names like `*.local` are never added to the waiting list.
- **Never downloads files.** Only pages served as HTML or JSON are read; anything else,
  including a response without a Content-Type, is skipped unread.
- **Listing parser** for Apache, nginx (plain and fancyindex), lighttpd, IIS, Python
  `http.server` and Caddy (asks Caddy for JSON). Pages with a custom title or header are
  recognised by Apache's sort links, or by their links (a name and a date next to each).
  Pages that are not listings are skipped.
- **Loop guards:** a directory whose listing has files and matches one already seen on
  that site (for example a symlink back to its parent) is indexed but not descended into.
  Folders that hold nothing but sub-folders are never taken for copies, since folders made
  together look alike. There are also depth, URL length and per-site budget limits.
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
[`lists/optout.txt`](lists/optout.txt). A site on that list is hidden from search at
once, and its indexed files are deleted at the start of the next crawl. For takedown
or deletion requests, open an issue with the URLs; they go into
[`lists/takedown.txt`](lists/takedown.txt).

## Limits

- Common Crawl discovery recognises Apache and nginx-fancyindex listings (they have sort
  links). Plain nginx listings are found only through seeds and links.
- Sites that were unreachable or not a listing are retried only if they are in your
  seeds. Use `forget` to retry any other one. A site that was paused earlier and stays
  unreachable is tried once a night for ever, which costs a request or two; `forget` it to
  stop.
- Finished sites are not re-crawled automatically yet. To refresh one, `forget` it and
  keep it in your seeds.
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
