# Ultra-fast scanner for public, legal open directories: 2026 build guide

> Status: design guide (September 2026). Not legal advice. Check the law where you
> operate (CFAA in the US, the Computer Misuse Act in the UK, GDPR/DSM Directive in the EU)
> before you publish anything you index.

An "open directory" (OD) is a web server that shows an auto-generated file listing
(Apache `mod_autoindex`, nginx `autoindex`, IIS directory browsing, Caddy `browse`, and so on).
This guide shows how to find and index the **legal** ones (software mirrors, public
datasets, academic archives, open-licensed media) fast, and how to stay polite and lawful
while doing it.

---

## 0. TL;DR

1. **Speed comes from discovery, not from port scanning.** Mine datasets that already
   crawled or scanned the internet: the Common Crawl columnar index, Censys/Shodan, CT logs
   and official mirror lists. You can find hundreds of thousands of candidate ODs without
   sending a single packet to their servers.
2. **Shard the crawler by host.** Per-host politeness is the real throughput limit. A
   host-sharded async crawler keeps thousands of hosts busy at once, each at about 1 req/s.
   You then get very high total throughput without any distributed rate limiter.
3. **Hot path in Rust (1.98) or Go (1.27).** Use Python 3.15 only for orchestration and
   analytics.
4. **Parse listings as a stream and never download the files.** The file metadata (name,
   size, mtime) is the product.
5. **Safety is hoisted into constant boolean flags** in [`src/safety.rs`](../src/safety.rs):
   robots.txt (RFC 9309), per-host rate limit, identifying User-Agent, opt-out list,
   listed-links-only, sensitive-exposure drop, and takedown list. "Metadata only" is not a
   flag, because nothing downloads file bodies. Likely piracy is filtered at search time,
   not during the crawl.
6. **Storage:** Parquet + DuckDB on a single box, ClickHouse ≥ 26.2 (native text index,
   GA in 2026) at billions of rows, and Meilisearch or Tantivy/Quickwit for user-facing
   relevance search.

```
 ┌──────────────── DISCOVERY (zero/low-touch) ────────────────┐
 │ Common Crawl idx │ Censys/Shodan │ Mirror lists │ CT logs  │
 └──────────┬───────────────┬──────────────┬────────────┬─────┘
            ▼               ▼              ▼            ▼
      ┌──────────────────────────────────────────────────────┐
      │ Candidate hosts/URLs  → dedupe (host-level)          │
      └───────────────┬──────────────────────────────────────┘
                      ▼
      ┌──────────────────────────────────────────────────────┐
      │ VERIFY: robots.txt + 1 GET of the dir → fingerprint   │
      └───────────────┬──────────────────────────────────────┘
                      ▼
      ┌──────────────────────────────────────────────────────┐
      │ SAFETY GATE: opt-out list / sensitive exposure?       │──► drop (+ optional notify)
      └───────────────┬──────────────────────────────────────┘
                      ▼
      ┌──────────────────────────────────────────────────────┐
      │ CRAWL: host-sharded, per-host token bucket, streaming │
      │ autoindex parser, trap guards, ls-lR shortcuts        │
      └───────────────┬──────────────────────────────────────┘
                      ▼
      ┌──────────────────────────────────────────────────────┐
      │ STORE: Parquet → ClickHouse   SEARCH: Meilisearch     │
      │ + search-time filters: takedown list, likely piracy   │
      └──────────────────────────────────────────────────────┘
```

---

## 1. Ground rules: what "legal" means in engineering terms

Each safety behaviour is a constant boolean flag in [`src/safety.rs`](../src/safety.rs).
All of them default to `true`, and turning one off is a reviewed code change, not a runtime
option.

| Rule | Flag | Implementation |
|---|---|---|
| Only index what the owner **published** | `FOLLOW_LISTED_LINKS_ONLY` | Only follow links that appear in a listing. **Never** guess paths, run wordlists or dirbusting, try credentials, or exploit misconfigurations (path traversal, `.git` exposure) on hosts you don't own. |
| Honor robots.txt ([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309)) | `RESPECT_ROBOTS_TXT` | Fetch `/robots.txt` before anything else and cache it for ≤ 24 h. **4xx** means allowed. **5xx or unreachable** means treat as fully disallowed. Parse at most 500 KiB. Honor `Crawl-delay` even though the RFC doesn't define it. |
| Be polite | `ENFORCE_PER_HOST_RATE_LIMIT` | Default ≤ 1 request/s and ≤ 2 connections per host. On 429/503, back off exponentially and honor `Retry-After`. Stop crawling a host after N consecutive errors. |
| Be identifiable | `SEND_IDENTIFYING_USER_AGENT` | Use a descriptive `User-Agent`, e.g. `ODIndexBot/0.1 (+https://yourdomain/bot)`. That page should explain the bot, list your crawler IPs, give an opt-out form and an abuse contact. Set reverse DNS on your crawler IPs. |
| Honor opt-outs | `HONOR_OPT_OUT_LIST` | Skip every host whose owner opted out through the bot page. |
| Exclude sensitive exposures | `DROP_SENSITIVE_EXPOSURES` | If a listing looks accidental (see §6.2), drop the host from the index. Optionally notify the owner via `/.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)). |
| Operate a takedown channel | `HONOR_TAKEDOWN_LIST` | If you publish a search UI, run a DMCA/notice-and-takedown process and GDPR deletion requests, and hide listed hosts and URLs from results. Filenames can be personal data. |
| Metadata only | *(not a flag)* | Store name, size, mtime and URL. **Do not download file bodies.** There is no code path for it, so there is nothing to switch. This keeps you fast and far away from redistribution and liability problems. |

Likely infringement is **not** a crawl-time rule. It is filtered at search time (§6.3).

**Active internet-wide scanning (ZMap/masscan on :80/:443)** is legal in many
jurisdictions and is how Censys and Shodan work. It still brings abuse complaints and ISP
terminations, and it needs an exclusion list, a dedicated IP range, and an opt-out
process. **Recommendation: don't do it.** Buy or query the scan data instead (§3.2). It's
faster, cheaper and cleaner.

---

## 2. The key insight: where the time goes

| Stage | Naive approach | Why it's slow | Fast approach |
|---|---|---|---|
| Find hosts | Scan IPv4 or Google-dork | Billions of probes, or rate-limited and dying APIs | Query pre-crawled datasets (minutes to hours of compute) |
| Verify | Headless browser | 100–1000× the cost of raw HTTP | 1 raw GET per host, fingerprint the HTML |
| Crawl | One queue with a global rate limit | One slow host blocks all the others | Per-host queues and a ready-time heap, so thousands of hosts run in parallel |
| Parse | Build a DOM per page | Allocation-heavy | Streaming tokenizer with fingerprint-specific extractors |
| Recrawl | Re-fetch everything | Wastes the whole politeness budget | mtime-guided incremental recrawl (§5.6) |

Throughput math for one box: listings average about 10–50 KB. At **10k req/s × 30 KB
≈ 300 MB/s ≈ 2.4 Gbit/s**. With 1 req/s per host, you need **≥ 10k hosts active at the
same time** to hit that rate. That is why discovery breadth matters more than
per-request speed.

---

## 3. Discovery: finding candidates without touching them

### 3.1 Common Crawl, the zero-touch goldmine ★ best first source

Common Crawl publishes a monthly crawl of about 2.1–2.3 billion pages (latest at the time
of writing: **CC-MAIN-2026-30**, July 2026). Its **columnar URL index** is Parquet on S3
(`s3://commoncrawl/cc-index/table/cc-main/warc/`). From 2026-30 on, the index uses zstd
compression. There's also a newer **Host Index** with one row per host per crawl.

The index has no HTML-title column, but Apache autoindex has a telltale fingerprint:
its column-sort links carry the query string `?C=N;O=D`, `?C=M;O=A` and so on. Crawlers
follow those links, so **any URL whose query matches `^C=[NMSD];O=[AD]$` is almost
certainly an Apache directory listing.**

```sql
-- DuckDB (run in AWS us-east-1 next to the data; S3 access needs AWS credentials)
INSTALL httpfs; LOAD httpfs; INSTALL aws; LOAD aws;
CREATE SECRET cc (TYPE s3, PROVIDER credential_chain, REGION 'us-east-1');

COPY (
  SELECT DISTINCT
         url_host_name                    AS host,
         split_part(url, '?', 1)          AS dir_url,
         warc_filename, warc_record_offset, warc_record_length
  FROM read_parquet(
         's3://commoncrawl/cc-index/table/cc-main/warc/crawl=CC-MAIN-2026-30/subset=warc/*.parquet',
         hive_partitioning = true)
  WHERE fetch_status = 200
    AND content_mime_detected = 'text/html'
    AND regexp_matches(url_query, '^C=[NMSD];O=[AD]$')
) TO 'apache_od_candidates.parquet' (FORMAT parquet, COMPRESSION zstd);
```

Other high-signal filters on the same table:

- `url_path` ending in `/` **and** a segment such as `/pub/`, `/mirror/`, `/mirrors/`,
  `/dist/`, `/releases/`, `/datasets/`, `/data/`, `/archive/`, `/files/`, `/downloads/`.
  This catches nginx and others that have no sort links.
- `url_host_name` starting with `mirror.`, `mirrors.`, `ftp.`, `dl.`, `download.`,
  `files.`, `archive.` or `repo.`.

**Confirm without touching the origin.** Each WARC record is its own gzip member, so you
can byte-range-fetch just that page from Common Crawl's own servers:

```bash
# length L, offset O from the query above
curl -s -r "$O-$((O+L-1))" "https://data.commoncrawl.org/$WARC_FILENAME" \
  | gunzip | grep -m1 -iE '<title>(Index of|Directory listing for)'
```

Run the query over several crawls (say, the last 12). This gives you a large, already
verified seed set, and your crawler has sent nothing to anyone yet.

### 3.2 Internet-scan datasets (Censys, Shodan and others)

These services already probed every IPv4 address and many hostnames, and they store the
HTML title.

- **Shodan:** `http.title:"Index of /"`, and `http.title:"Directory listing for"` for
  Python `http.server`.
- **Censys:** the HTML-title field. In the legacy language it was
  `services.http.response.html_title: "Index of /"`. **Legacy Search and its API are being
  retired in September 2026.** Build against the **Censys Platform API / CenQL** and use
  Censys's query converter.
- Alternatives with similar data: Netlas, FOFA, ZoomEye, Criminal IP. Check each one's
  terms of service for bulk-export rights.

Use their bulk exports or APIs (licensed) and treat the results as candidates only. Scan
data mostly covers bare IPs and default vhosts, so it complements Common Crawl rather than
replacing it.

### 3.3 Official mirror lists: the legal allowlist seed

These are guaranteed legal, and most of them autoindex:

- Linux and BSD distros: Debian, Ubuntu (Launchpad mirror list), Fedora (MirrorManager),
  Arch (`mirrorlist`), openSUSE, Alpine, the BSDs.
- Language ecosystems: CPAN, CTAN, CRAN, the Apache dist mirrors, GNU `ftp` mirrors.
- Open-data and science: NASA, NOAA, USGS, EU Open Data, university research archives
  (`.edu`, `.ac.*`).

These seed **tier 0** of your legal allowlist (§6.1). They also point you to other ODs
hosted by the same institutions.

**Shortcut for huge mirrors:** many publish a full recursive file list at the root, e.g.
`ls-lR.gz`, Fedora's `fullfiletimelist-*`, or CPAN's `indices/find-ls.gz`. Check the root
listing for such a file before crawling. **One request can replace 100k directory
fetches.** Also use the mirror network's own API or rsync module list if it has one.

### 3.4 Certificate Transparency: hostnames

CT logs expose every new TLS hostname. Filter for `mirror.*`, `files.*`, `dl.*`,
`archive.*` and similar, then probe **only `/`**.

2026 note: Let's Encrypt shut down its RFC 6962 logs on 2026-02-28 and now runs
**static-ct-api / Sunlight tiled logs**. Chrome's policy accepts tiled logs. Make sure
your CT tailer or monitor speaks static-ct-api; old RFC 6962-only tailers will miss most
new certificates.

### 3.5 Search APIs: mostly gone

- **Bing Search APIs:** retired 2025-08-11.
- **Google Custom Search JSON API:** closed to new customers. Existing customers lose it
  on **2027-01-01**. Its successor, Vertex AI Search, isn't built for this.
- **Brave Search API:** an independent index and still the practical option. Dorks such
  as `intitle:"index of" "parent directory" site:edu` give good but modest yield.

Treat search APIs as a trickle source, not the main pipe.

### 3.6 Link expansion (free, compounding)

ODs link to other ODs through mirror pages, `README` pointers, and "see also" mirror
listings. Queue any off-host link that appears **inside a listing page** as a new
candidate host. It still has to pass verification and the safety gate.

---

## 4. Verification: one GET per host

For each candidate, in order:

1. `GET /robots.txt`, then decide per RFC 9309.
2. `GET <dir_url>` with a body cap (e.g. 2 MB) and short timeouts.
3. Fingerprint the response (§5.3). If nothing matches, the host is not an OD, so drop it.

Off-the-shelf fast option: **ProjectDiscovery `httpx`** (Go, v1.12.x in September 2026)
at a few thousand probes/s from one box:

```bash
httpx -l candidates.txt -sc -title -mc 200 \
      -mr '(?i)<title>(index of|directory listing for)' \
      -t 300 -rl 2000 -timeout 8 -retries 1 -json -o verified.jsonl
```

This sends one request per host, so its global rate limit (`-rl`) is safe. **Do not** use
its `-path` wordlist feature against third-party hosts; that is exactly the path-guessing
§1 forbids. `httpx` doesn't check robots.txt, so filter your candidate list against cached
robots decisions first, or do verification inside your own crawler (recommended once it
exists).

---

## 5. The crawler core

### 5.1 2026 stack choice

| Layer | Recommended (max speed) | Alternative (dev velocity) |
|---|---|---|
| Language | **Rust 1.98** (edition 2024) | **Go 1.27** |
| Async runtime | `tokio` (multi-threaded) | goroutines |
| HTTP client | `hyper` 1.x + `hyper-util` pool (or `reqwest`), `rustls` with `aws-lc-rs` | `net/http` with a tuned `Transport` |
| DNS | `hickory-resolver` **≥ 0.26.3**, plus a local **Unbound** cache | local Unbound with a custom `net.Resolver` |
| HTML | **`lol_html`** (streaming, Cloudflare) or `tl` | `golang.org/x/net/html` tokenizer (not goquery) |
| robots.txt | `texting_robots` or `robotstxt` crate | `github.com/temoto/robotstxt` |
| Frontier / seen-set | `fjall` (pure-Rust LSM) or RocksDB, plus an in-RAM xor/binary-fuse filter | Pebble, plus a bloom filter |
| Framework (optional) | `spider` crate (spider-rs 2.5x) as a reference | Colly |

Why not a framework as the core? General crawlers optimise for "follow links on web
pages". ODs are a tree walk with a very regular structure. A purpose-built walker of about
1–2k lines, with per-format extractors and trap guards, is simpler and faster. Read
spider-rs for ideas and don't depend on it.

Python 3.15 ships on 2026-10-01 with free-threading and a faster JIT. It's fine for
orchestration and analytics glue, but not for the fetch and parse hot path.

### 5.2 Scheduler: host-sharded, ready-time heap

```
             ┌────────────── shard k (one per core, or per node) ─────────┐
 hash(host)─►│ HostTable: host → {robots, token_bucket, url_queue, conns} │
             │ ReadyHeap: min-heap of (next_allowed_at, host)             │
             │ loop:                                                      │
             │   pop host whose next_allowed_at <= now                    │
             │   pop 1 URL from host.url_queue  (spill to fjall if huge)  │
             │   spawn fetch (global semaphore caps in-flight, e.g. 20k)  │
             │   on done: parse → push child dirs to host.url_queue       │
             │            next_allowed_at = now + max(1/rate, crawl_delay)│
             │            re-insert host into ReadyHeap if queue non-empty│
             └────────────────────────────────────────────────────────────┘
```

- **Shard by `hash(registered_domain)` with consistent hashing.** Every request to a
  given site then goes through one shard, so politeness state is local: no Redis locks,
  no distributed rate limiter. Hashing on the registered domain rather than the hostname
  stops `a.example.org` and `b.example.org` from ganging up on the same backend. Also cap
  concurrency per resolved IP, because shared hosting puts thousands of vhosts on one box.
- **Big-host problem:** a 200k-directory mirror at 1 req/s takes about 55 h. Handle it
  with the `ls-lR` shortcut (§3.3), by scheduling big hosts first so they overlap
  everything else, and by adaptive rate. If p50 latency stays low and there are no
  errors, go up to the host's `Crawl-delay` or a ceiling you publish on your bot page.
- **Per-host keep-alive** means TLS handshakes scale with the number of hosts, not the
  number of requests. That's the biggest CPU saving. HTTP/2 via ALPN is fine when it's
  offered. HTTP/3 brings almost nothing here, since most autoindex servers are
  HTTP/1.1.

### 5.3 Fingerprints and parsers

| Server | Fingerprint | Entry format / notes |
|---|---|---|
| Apache `mod_autoindex` | `<title>Index of /…`, `?C=N;O=D` sort links, "Parent Directory", `<address>Apache/… Server at` | `<pre>` (FancyIndexing) or `<table>` (HTMLTable). Sizes like `1.2M`, `-` for dirs. Dates `2026-09-28 10:15`. |
| nginx `autoindex` | `<h1>Index of /…/</h1><hr><pre><a href="../">../</a>` | Dates `28-Sep-2026 10:15`. Size in exact bytes by default, `1K/1M` if `autoindex_exact_size off`. |
| nginx fancyindex | `<table id="list">` | Table rows with a size column. |
| lighttpd `mod_dirlisting` | `<div class="list">`, footer `lighttpd/…` | Table. Sizes like `1.2M`. |
| IIS directory browsing | `[To Parent Directory]`, `<pre>` with `<br>` lines | US-style dates, `<dir>` marker for directories. |
| **Caddy `browse`** | Caddy template | **Send `Accept: application/json`** to get a JSON array `{name,size,url,mod_time,is_dir,…}`, with no HTML parsing needed. |
| Python `http.server` | `<title>Directory listing for /…` | Names only, no size or mtime. |
| Go `http.FileServer` | Bare `<pre>\n<a href=…>` with no title | Names only. |
| h5ai, AList, File Browser (JS SPAs) | `_h5ai`, SPA shells | Skip in v1. These need their own APIs or rendering. |

Send `Accept: application/json, text/html;q=0.9` everywhere. Caddy then answers with JSON
and everything else ignores the header.

Parser rules:

- **Stream.** With `lol_html`, register `a[href]` handlers and pick up the text that
  follows for size and date on `<pre>` formats. Stop at the body cap.
- Resolve hrefs against the page URL. **Keep only same-host links that are strictly
  under the current path.** Treat `?C=…` links, `../` and absolute off-tree links as
  navigation, not entries.
- Normalise sizes to bytes (`K/M/G/T` are 1024-based on Apache and nginx). Parse dates in
  per-format layouts and store them as UTC with a precision flag (minute or second).
- Decide dir vs. file from the trailing `/` on the href, or `is_dir` in JSON.

Build a **fixture corpus first**: 3–5 saved real listings per server type plus weird ones
(non-UTF-8 names, `&amp;` in names, 100k-entry pages). Write golden tests before writing
the crawler.

### 5.4 Trap and loop guards

- Maximum depth (e.g. 32), maximum URL length (2 KB), and a maximum directory budget per
  host that you raise for allowlisted mirrors.
- A repeated-segment detector (`/a/b/a/b/…` means stop).
- **Listing hash:** hash the sorted `(name,size,mtime)` list. If a new directory's hash
  equals its parent's or an ancestor's, it's a symlink loop, so stop. The same hash on
  different hosts identifies mirror clusters, which is great for dedup in search results.
- Canonicalise percent-encoding, drop fragments, drop the `?C=` queries, and enforce a
  trailing slash on directories.

### 5.5 HTTP details that matter

- `Accept-Encoding: gzip, br, zstd` and decompress as a stream.
- Timeouts: connect 5 s, first byte 10 s, total 30 s. Follow redirects **only on the same
  site**, at most 3.
- Cap the body at 2–8 MB. Mark a listing that hits the cap as truncated and flag the host
  for an `ls-lR` check.
- Record status code, server header, latency, bytes and the fingerprint result for every
  request. Export them with OpenTelemetry or Prometheus.

### 5.6 mtime-guided incremental recrawl

Autoindex pages rarely send useful `ETag`/`Last-Modified`, because they're generated
dynamically. POSIX semantics help instead: **a directory's mtime changes when entries are
added, removed or renamed in it**, and the parent listing shows that mtime.

- On recrawl, **skip** directory X if its mtime in the parent listing is unchanged **and**
  X had no subdirectories last time (a leaf).
- Still fetch non-leaf directories. A change deep inside does not bump ancestor mtimes.
- File size and content changes don't bump the directory mtime, so do a full refresh on a
  slower cycle (e.g. monthly).
- Leaves are usually most of the directories, so this skips much of the recrawl.

### 5.7 Linux and host tuning (fetcher boxes)

```bash
ulimit -n 1048576
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.somaxconn=65535
# conntrack is a classic silent crawler killer: raise it or bypass tracking for egress
sysctl -w net.netfilter.nf_conntrack_max=4194304
```

- Run a local Unbound with a large cache, prefetch, and a few upstreams. At over 5k new
  hosts/s, DNS is often the first bottleneck.
- Use Happy Eyeballs (IPv4 plus IPv6). Some mirrors are faster over IPv6.
- One process per NUMA node, with shards pinned to cores.
- `io_uring` runtimes (`monoio`, `glommio`) give only marginal gains, because this
  workload is bound by network and remote latency, not syscalls. Stay on tokio.

---

## 6. The legality pipeline

### 6.1 Tiered trust

| Tier | Source | Action |
|---|---|---|
| 0 | Official mirror networks, `.gov`, `.edu`, `.ac.*`, known open-data portals | Index, with higher crawl budgets |
| 1 | Every other verified open directory | Index, with default budgets |
| X | Sensitive exposure, opt-out, or whole-host takedown | Exclude, keep only a tombstone (host plus reason) so you don't re-crawl |

There is no per-host content classifier; it was dropped because of its cost. Likely
piracy is handled at search time instead (§6.3).

### 6.2 Sensitive-exposure detector: exclude and don't index

Trigger on names like: `.env`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.kdbx`,
`wp-config.php.bak`, `*.sql`, `*.sql.gz`, `dump*.sql`, `backup*.zip`, `.git/`,
`.aws/credentials`, `*.pst`, `passport*`, `payroll*`, `tax*`, `invoice*`, or `scan*.pdf`
in home-style directories, and anything under `/home/<user>/`.

These are almost always accidental exposures. Don't fetch them, don't index them, and
consider a courtesy notice via `security.txt`.

### 6.3 Likely-infringement filter (search time, not crawl time)

The crawler indexes every verified host outside tier X. Likely piracy is filtered in the
search layer, either as a `NOT match(name, …)` clause in the query or as a boolean
attribute computed while loading the search index. Changing the rules then needs a
re-index at most, never a re-crawl. Use these patterns as signals, not proof:

```regex
(?i)\b(2160p|1080p|720p|x26[45]|hevc|web-?dl|webrip|bluray|brrip|hdrip|dvdrip|remux)\b
(?i)\bS\d{1,2}E\d{1,3}\b
(?i)\b(crack(ed)?|keygen|repack|patch-?only|serial)\b
\.[A-Za-z0-9-]+-[A-Za-z0-9]{2,12}\.(mkv|mp4|avi)$   # dotted release name ending in -GROUP (weak alone)
```

Skip the filter for tier 0 hosts, since official mirrors legitimately carry names like
`patch` or `serial`.

---

## 7. Storage and search

| Scale | Store | Search UI |
|---|---|---|
| ≤ ~500M file rows, 1 box | Parquet (zstd), partitioned by `host_bucket`, queried with **DuckDB** | **Meilisearch** (typo-tolerant, instant) |
| Billions of rows | **ClickHouse ≥ 26.2**. Its native inverted **text index is GA** (fast token filtering over billions of rows), but it doesn't rank. | **Tantivy/Quickwit** (Apache-2.0 after the Datadog acquisition) or Meilisearch for BM25 relevance |

Minimal schema:

```sql
-- ClickHouse
CREATE TABLE files (
  host        LowCardinality(String),
  dir         String,
  name        String,
  ext         LowCardinality(String),
  size        UInt64,
  mtime       DateTime,
  first_seen  DateTime,
  last_seen   DateTime,
  tier        Enum8('t0'=0,'t1'=1,'x'=2),
  INDEX name_text name TYPE text(tokenizer = 'splitByNonAlpha')
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (host, dir, name);

CREATE TABLE hosts (
  host String, ip String, asn UInt32, server String, fingerprint LowCardinality(String),
  robots_ok UInt8, tier Enum8('t0'=0,'t1'=1,'x'=2),
  n_dirs UInt64, n_files UInt64, total_bytes UInt64, listing_cluster UInt64,
  first_seen DateTime, last_crawled DateTime
) ENGINE = ReplacingMergeTree(last_crawled) ORDER BY host;
```

(Check the `text` index parameter syntax against your ClickHouse version's docs. The API
changed on the way to GA.)

Also keep the raw listing HTML/JSON snapshots, zstd-compressed, in object storage. You
can then re-parse after fixing a parser bug without re-crawling.

For the search UI, index `name` and `dir` tokens, filter by `ext`, `size` and `tier`, and
collapse results by `listing_cluster` so that 400 identical Debian mirrors appear as one
result with a mirror picker. Apply the search-time filters here: the takedown list
(`HONOR_TAKEDOWN_LIST`) and the likely-infringement patterns (§6.3).

---

## 8. Reference deployments

**Stack A, one strong box (fastest to build):** 16–32 cores, 64–128 GB RAM, NVMe, 1–10
Gbit/s.
- Discovery: DuckDB over the Common Crawl index (on a spot instance in us-east-1),
  Censys/Shodan export, mirror lists.
- Crawler: one Rust binary with in-process shards, a `fjall` frontier and Parquet output.
- Search: Meilisearch.
- Expected: thousands to low tens of thousands of listing fetches/s across many hosts.
  Total crawl time is dominated by the few largest hosts, unless you use `ls-lR`.

**Stack B, scale-out:**
- N fetcher nodes, each owning a consistent-hash range of registered domains.
- NATS JetStream (or Redpanda) carries discovered candidates and parsed batches.
- ClickHouse cluster, plus Quickwit or Meilisearch.
- Everything observable with OpenTelemetry.

---

## 9. Build roadmap

**Status (in this repo):** steps 1–3, 5 and 6 are built, and discovery (steps 4 and
7) has started, with a few simplifications:

- The scheduler is one task per host plus a concurrency cap, instead of a ready-time heap.
- Metrics are a progress line, not Prometheus.
- Storage and search are a single SQLite file with FTS5, instead of Parquet, DuckDB and
  Meilisearch. The layout stores each folder URL once and a contentless FTS index,
  about 140 bytes per file.
- Package archives (`pool/`, `Packages/`, CRAN, ...) are skipped through an editable
  skip list, since they make up most of every mirror.
- Discovery covers the Common Crawl sort-link query (§3.1, as `opendir discover`, reading
  the Parquet index with HTTP range requests instead of DuckDB) and link expansion
  (§3.6, including cross-site redirects). Censys/Shodan and CT logs are not built.
- Crawls are resumable: a time limit or the per-run directory budget pauses a host
  and saves its frontier as candidates, and `opendir auto` chains nightly runs.
- There are no trust tiers yet (§6.1). Every verified host is handled like tier 1.
- The `ls-lR` shortcut and mtime-guided recrawl are next.

1. **Parser first:** fixtures and golden tests for the 8 server types in §5.3.
2. **Single-host walker:** robots, politeness, trap guards, the `ls-lR` shortcut, Caddy
   JSON.
3. **Scheduler:** host-sharded ready-heap, a global in-flight cap, metrics.
4. **Discovery v1:** the Common Crawl query (§3.1) plus mirror lists, reaching the first
   10k hosts.
5. **Safety flags wired in:** every flag in `src/safety.rs` checked at its call site, the
   §6.2 rules, the tier system, the bot info and opt-out page.
6. **Storage and search:** Parquet → DuckDB → Meilisearch, with the search-time filters
   (takedown list, §6.3 patterns).
7. **Discovery v2:** Censys Platform and Shodan, CT tailing (static-ct-api), link
   expansion.
8. **Recrawl:** mtime-guided incremental recrawl, adaptive per-host rate.
9. **Scale-out:** Stack B, when one box stops being enough.

---

## 10. Sources (checked September 2026)

- Common Crawl 2026 crawls: [CC-MAIN-2026-30](https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-30/index.html), [July 2026 announcement](https://commoncrawl.org/blog/july-2026-crawl-archive-now-available), [cc-index-table](https://github.com/commoncrawl/cc-index-table), [Host Index](https://commoncrawl.org/blog/introducing-the-host-index)
- Censys: [Legacy Search deprecation](https://censys.com/blog/legacy-search-deprecation/), [Platform API transition guide](https://docs.censys.com/docs/platform-api-transition-guide), [CenQL](https://docs.censys.com/docs/censys-query-language)
- Google Custom Search JSON API: [overview](https://developers.google.com/custom-search/v1/overview), [heise report on shutdown](https://www.heise.de/en/news/Google-is-discontinuing-its-free-web-search-index-for-developers-11152411.html)
- Bing API retirement and alternatives: [Brave vs Bing API](https://brave.com/search/api/guides/brave-search-api-vs-bing-api/), [Firecrawl overview](https://www.firecrawl.dev/blog/bing-search-api-alternatives)
- CT: [static-ct-api in Chrome policy](https://groups.google.com/a/chromium.org/g/ct-policy/c/nuJOpwj06QA), [Chrome CT log policy](https://googlechrome.github.io/CertificateTransparency/log_policy.html)
- Caddy JSON listings: [file_server docs](https://caddyserver.com/docs/caddyfile/directives/file_server)
- Rust: [Rust 1.98.1](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/). Go: [Go 1.27 release notes](https://go.dev/doc/go1.27). Python: [3.15 JIT status](https://blog.python.org/2026/03/jit-on-track/)
- Hickory DNS: [releases](https://github.com/hickory-dns/hickory-dns/releases). spider-rs: [repo](https://github.com/spider-rs/spider). lol_html: [repo](https://github.com/cloudflare/lol-html). httpx: [releases](https://github.com/projectdiscovery/httpx/releases)
- ClickHouse text index GA: [announcement](https://clickhouse.com/blog/full-text-search-ga-release), [docs](https://clickhouse.com/docs/engines/table-engines/mergetree-family/textindexes)
- Quickwit relicensing: [Quickwit joins Datadog](https://quickwit.io/blog/quickwit-joins-datadog)
- Standards: [RFC 9309 robots.txt](https://www.rfc-editor.org/rfc/rfc9309), [RFC 9116 security.txt](https://www.rfc-editor.org/rfc/rfc9116)
