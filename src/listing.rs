//! Detects auto-generated directory listings and extracts their entries.
//!
//! Covers Apache, nginx (plain and fancyindex), lighttpd, IIS, Python
//! `http.server` and Caddy (JSON). The parser is format-agnostic: every link on
//! the page that points to a direct child of the listed directory becomes an
//! entry, and its size and date are read from the text next to the link.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::Regex;
use serde::Deserialize;
use url::Url;

use crate::filters;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub url: Url,
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    /// As shown by the server, normalised to `YYYY-MM-DD HH:MM[:SS]` (no time zone).
    pub mtime: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    Apache,
    Nginx,
    Lighttpd,
    Iis,
    Caddy,
    PythonHttp,
    Other,
}

impl Server {
    pub fn as_str(self) -> &'static str {
        match self {
            Server::Apache => "apache",
            Server::Nginx => "nginx",
            Server::Lighttpd => "lighttpd",
            Server::Iis => "iis",
            Server::Caddy => "caddy",
            Server::PythonHttp => "python-http",
            Server::Other => "other",
        }
    }
}

#[derive(Debug)]
pub struct Listing {
    pub server: Server,
    pub entries: Vec<Entry>,
    /// Same-site directory links on the page that are not entries of this
    /// directory (navigation, "see also" links). Only followed when
    /// `FOLLOW_LISTED_LINKS_ONLY` is off.
    pub other_dirs: Vec<Url>,
    /// Directory links to other sites, kept as discovery candidates.
    pub external_dirs: Vec<Url>,
}

/// Parses `body` fetched from `base`. Returns `None` if it is not a directory listing.
pub fn parse(base: &Url, content_type: Option<&str>, body: &str) -> Option<Listing> {
    if content_type.is_some_and(|ct| ct.contains("json")) {
        return parse_caddy_json(base, body);
    }
    parse_html(base, body)
}

/// Returns true if `url` is a direct child (file or subdirectory) of the directory `base`.
pub fn is_child(base: &Url, url: &Url) -> bool {
    if url.origin() != base.origin() || url.query().is_some() {
        return false;
    }
    let Some(rest) = url.path().strip_prefix(dir_path(base)) else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    !rest.is_empty() && !rest.contains('/')
}

/// The directory part of the URL path, including the trailing slash.
fn dir_path(url: &Url) -> &str {
    let path = url.path();
    &path[..=path.rfind('/').unwrap_or(0)]
}

fn name_from_url(url: &Url) -> String {
    let last = url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
        .unwrap_or("");
    percent_decode_str(last).decode_utf8_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Caddy
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CaddyItem {
    size: u64,
    url: String,
    mod_time: String,
    is_dir: bool,
}

fn parse_caddy_json(base: &Url, body: &str) -> Option<Listing> {
    static RFC3339: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})").unwrap());

    let items: Vec<CaddyItem> = serde_json::from_str(body).ok()?;
    let entries = items
        .into_iter()
        .filter_map(|item| {
            let url = base.join(&item.url).ok()?;
            if !is_child(base, &url) {
                return None;
            }
            let mtime = RFC3339
                .captures(&item.mod_time)
                .map(|c| format!("{} {}", &c[1], &c[2]));
            // Caddy appends `/` to directory names, so take the name from the URL.
            Some(Entry {
                name: name_from_url(&url),
                url,
                is_dir: item.is_dir,
                size: (!item.is_dir)
                    .then_some(item.size)
                    .filter(|&s| s <= MAX_SIZE),
                mtime,
            })
        })
        .collect();
    Some(Listing {
        server: Server::Caddy,
        entries,
        other_dirs: Vec::new(),
        external_dirs: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// HTML listings
// ---------------------------------------------------------------------------

// `href` must follow whitespace, so `data-href` is not mistaken for it.
static ANCHOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<a\s(?:[^>]*?\s)?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a\s*>"#,
    )
    .unwrap()
});
/// The column-header links Apache's `mod_autoindex` (and nginx fancyindex) put
/// on every listing, e.g. `href="?C=N;O=D"`. Sites that customise the page
/// title and header still have them.
static SORT_LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"href\s*=\s*["']?\?c=[nmsd](?:;|&amp;|&)o=[ad]"#).unwrap());
static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").unwrap());
static LISTING_HEADING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<(?:title|h1|h2)[^>]*>\s*(?:index of\b|directory listing for\b)").unwrap()
});
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());
/// An IIS row: date, time and `<dir>` or a size, then the link. Needed because
/// IIS omits "[To Parent Directory]" at the site root.
static IIS_ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"<br>\s*\d{1,2}[./]\d{1,2}[./]\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]m)?\s+(?:&lt;dir&gt;|\d+)\s+<a\s",
    )
    .unwrap()
});

fn detect(lower: &str) -> Option<Server> {
    let is_iis = lower.contains("[to parent directory]") || IIS_ROW.is_match(lower);
    if !is_iis && !LISTING_HEADING.is_match(lower) {
        // A customised title or header: Apache still gives itself away.
        return SORT_LINK.is_match(lower).then(|| {
            if lower.contains("<table id=\"list\">") {
                Server::Nginx
            } else {
                Server::Apache
            }
        });
    }
    let server = if is_iis {
        Server::Iis
    } else if lower.contains("<div class=\"list\">") || lower.contains("lighttpd/") {
        Server::Lighttpd
    } else if lower.contains("directory listing for") {
        Server::PythonHttp
    } else if lower.contains("?c=n;o=") || lower.contains("<address>apache") {
        Server::Apache
    } else if lower.contains("<table id=\"list\">") || lower.contains("<a href=\"../\">../</a>") {
        Server::Nginx
    } else {
        Server::Other
    };
    Some(server)
}

/// One link on the page.
struct Anchor<'a> {
    start: usize,
    end: usize,
    href: &'a str,
    /// The link's inner HTML.
    text: &'a str,
}

fn parse_html(base: &Url, body: &str) -> Option<Listing> {
    let body = &*COMMENT.replace_all(body, "");
    // Pages that give no sign of being a listing are still accepted if their
    // links look like one (see `looks_like_listing`).
    let detected = detect(&body.to_ascii_lowercase());
    let server = detected.unwrap_or(Server::Other);

    let anchors: Vec<Anchor> = ANCHOR
        .captures_iter(body)
        .map(|c| {
            let whole = c.get(0).unwrap();
            let href = c
                .get(1)
                .or(c.get(2))
                .or(c.get(3))
                .map_or("", |m| m.as_str());
            Anchor {
                start: whole.start(),
                end: whole.end(),
                href,
                text: c.get(4).map_or("", |m| m.as_str()),
            }
        })
        .collect();
    let mut evidence = Evidence::default();

    let mut entries: Vec<Entry> = Vec::new();
    let mut by_url: HashMap<String, usize> = HashMap::new();
    let mut other_dirs = Vec::new();
    let mut external_dirs = Vec::new();

    for (i, anchor) in anchors.iter().enumerate() {
        let Anchor {
            start, end, href, ..
        } = *anchor;
        let Ok(mut url) = base.join(&decode_entities(href)) else {
            continue;
        };
        url.set_fragment(None);
        if !matches!(url.scheme(), "http" | "https") || url.query().is_some() {
            continue; // sort links like ?C=N;O=D
        }
        // The same site spelled another way (`example.com.`) is still this site.
        if url.host_str() != base.host_str() && filters::same_site(&url, base) {
            let _ = url.set_host(base.host_str());
        }
        if url.host_str() != base.host_str() {
            if url.path().ends_with('/') {
                external_dirs.push(url);
            }
            continue;
        }
        if !is_child(base, &url) {
            let is_ancestor = base.path().starts_with(url.path());
            if url.origin() == base.origin() && url.path().ends_with('/') && !is_ancestor {
                other_dirs.push(url);
            }
            continue;
        }

        // IIS prints the date and size before the link; everyone else after it.
        let detail = if server == Server::Iis {
            let prev_end = if i == 0 { 0 } else { anchors[i - 1].end };
            clean_text(&body[prev_end..start])
        } else {
            let next_start = anchors.get(i + 1).map_or(body.len(), |a| a.start);
            clean_text(row_tail(&body[end..next_start]))
        };
        let (mtime, size) = parse_details(&detail);

        let name = name_from_url(&url);
        if name.is_empty() {
            continue;
        }
        let is_dir = url.path().ends_with('/');
        let entry = Entry {
            url,
            name,
            is_dir,
            size: if is_dir { None } else { size },
            mtime,
        };
        match by_url.get(entry.url.as_str()) {
            // Icons can link to the same target: keep the copy with details, and
            // let any of the links show that the row is worded as a file name.
            Some(&j) => {
                evidence.note(j, &entries[j], anchor.text);
                if entries[j].mtime.is_none() && entry.mtime.is_some() {
                    entries[j] = entry;
                }
            }
            None => {
                evidence.note(entries.len(), &entry, anchor.text);
                by_url.insert(entry.url.to_string(), entries.len());
                entries.push(entry);
            }
        }
    }

    if detected.is_none() && !evidence.looks_like_listing(&entries) {
        return None;
    }
    Some(Listing {
        server,
        entries,
        other_dirs,
        external_dirs,
    })
}

/// What the links on a page say about whether it is a directory listing, for
/// pages that don't announce it ("Index of ...").
///
/// Ordinary pages have links whose text differs from the file name in the URL
/// (`Read the article` -> `post-17.html`). A listing prints the name itself, and
/// a date next to it.
#[derive(Default)]
struct Evidence {
    /// Per entry, in the order of the entries: whether a link to it has the file
    /// name as its text (or its truncation, `name..>`).
    named: Vec<bool>,
}

impl Evidence {
    fn note(&mut self, index: usize, entry: &Entry, link_html: &str) {
        if self.named.len() <= index {
            self.named.resize(index + 1, false);
        }
        self.named[index] |= link_text_is_name(entry, link_html);
    }

    fn looks_like_listing(&self, entries: &[Entry]) -> bool {
        let dated = entries.iter().filter(|e| e.mtime.is_some()).count();
        let named = self.named.iter().filter(|&&n| n).count();
        dated >= 3 && named * 10 >= entries.len() * 8
    }
}

fn link_text_is_name(entry: &Entry, link_html: &str) -> bool {
    let text = clean_text(link_html);
    let text = text.trim_end_matches('/');
    let truncated = text
        .strip_suffix("..>")
        .or_else(|| text.strip_suffix('…'))
        .filter(|prefix| !prefix.is_empty());
    match truncated {
        Some(prefix) => entry.name.starts_with(prefix.trim_end_matches('.')),
        None => text == entry.name,
    }
}

/// The part of the text after a link that belongs to the same row: up to the
/// end of the table row, or the end of the line for `<pre>` listings.
fn row_tail(segment: &str) -> &str {
    let cut = segment
        .to_ascii_lowercase()
        .find("</tr")
        .or_else(|| segment.find('\n'))
        .unwrap_or(segment.len());
    &segment[..cut]
}

fn clean_text(html: &str) -> String {
    let no_tags = TAG.replace_all(html, " ");
    decode_entities(&no_tags)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_entities(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let semicolon = rest.bytes().take(12).position(|b| b == b';');
        match semicolon.and_then(|e| decode_entity(&rest[1..e]).map(|c| (c, e))) {
            Some((c, e)) => {
                out.push(c);
                rest = &rest[e + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

fn decode_entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let code = if let Some(hex) = name.strip_prefix("#x").or(name.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                name.strip_prefix('#')?.parse().ok()?
            };
            char::from_u32(code).filter(|c| !c.is_control())
        }
    }
}

// ---------------------------------------------------------------------------
// Dates and sizes
// ---------------------------------------------------------------------------

/// Finds the modification date and size in the text of one listing row.
fn parse_details(text: &str) -> (Option<String>, Option<u64>) {
    let Some((mtime, start, end)) = find_date(text) else {
        return (None, None);
    };
    // Most servers print the size after the date; nginx fancyindex prints it before.
    let size = match size_prefix(&text[end..]) {
        Some(size) => size,
        None => size_exact(text[..start].trim()).flatten(),
    };
    (Some(mtime), size)
}

static DATE_PATTERNS: LazyLock<Vec<(DateOrder, Regex)>> = LazyLock::new(|| {
    let time = r"(\d{1,2}):(\d{2})(?::(\d{2}))?";
    let ampm = r"(?:\s*([AaPp][Mm]))?";
    [
        // Apache 2.4: 2026-09-28 14:04
        (
            DateOrder::Ymd,
            format!(r"(\d{{4}})-(\d{{2}})-(\d{{2}})[ T]{time}"),
        ),
        // nginx, Apache 2.2: 28-Sep-2026 10:15
        (
            DateOrder::DMonY,
            format!(r"(\d{{1,2}})-([A-Za-z]{{3}})-(\d{{4}}) {time}"),
        ),
        // Node.js's release server: 22 Sept 2026, 09:01
        (
            DateOrder::DMonY,
            format!(r"(\d{{1,2}})\s+([A-Za-z]{{3,9}})\.?\s+(\d{{4}}),?\s+{time}{ampm}"),
        ),
        // lighttpd, fancyindex: 2026-Sep-28 10:15:00
        (
            DateOrder::YMonD,
            format!(r"(\d{{4}})-([A-Za-z]{{3}})-(\d{{1,2}}) {time}"),
        ),
        // IIS: 9/28/2026 10:15 AM
        (
            DateOrder::Mdy,
            format!(r"(\d{{1,2}})/(\d{{1,2}})/(\d{{4}})\s+{time}{ampm}"),
        ),
        // IIS in many non-US locales: 28.09.2026 10:15
        (
            DateOrder::DmyDots,
            format!(r"(\d{{1,2}})\.(\d{{1,2}})\.(\d{{4}})\s+{time}"),
        ),
        // IIS long form: Monday, September 28, 2026 10:15 AM
        (
            DateOrder::MonDY,
            format!(
                r"(?:[A-Za-z]+,\s+)?([A-Za-z]{{3,9}})\s+(\d{{1,2}}),\s+(\d{{4}})\s+{time}{ampm}"
            ),
        ),
    ]
    .into_iter()
    .map(|(order, pattern)| (order, Regex::new(&pattern).unwrap()))
    .collect()
});

#[derive(Clone, Copy)]
enum DateOrder {
    Ymd,
    DMonY,
    YMonD,
    Mdy,
    MonDY,
    DmyDots,
}

/// Returns the normalised date and the byte range it covered in `text`.
fn find_date(text: &str) -> Option<(String, usize, usize)> {
    DATE_PATTERNS
        .iter()
        .filter_map(|(order, re)| {
            let c = re.captures(text)?;
            let whole = c.get(0)?;
            let normalised = normalise_date(*order, &c)?;
            Some((normalised, whole.start(), whole.end()))
        })
        .min_by_key(|&(_, start, _)| start)
}

fn normalise_date(order: DateOrder, c: &regex::Captures<'_>) -> Option<String> {
    let num = |i: usize| c.get(i).and_then(|m| m.as_str().parse::<u32>().ok());
    let (year, month, day) = match order {
        DateOrder::Ymd => (num(1)?, num(2)?, num(3)?),
        DateOrder::DMonY => (num(3)?, month_number(&c[2])?, num(1)?),
        DateOrder::YMonD => (num(1)?, month_number(&c[2])?, num(3)?),
        DateOrder::Mdy => (num(3)?, num(1)?, num(2)?),
        DateOrder::MonDY => (num(3)?, month_number(&c[1])?, num(2)?),
        DateOrder::DmyDots => (num(3)?, num(2)?, num(1)?),
    };
    let mut hour = num(4)?;
    let minute = num(5)?;
    let second = num(6);
    if let Some(ampm) = c.get(7) {
        let pm = ampm.as_str().eq_ignore_ascii_case("pm");
        hour = match (hour, pm) {
            (12, false) => 0,
            (12, true) => 12,
            (h, true) => h + 12,
            (h, false) => h,
        };
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let mut out = format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}");
    if let Some(s) = second {
        out.push_str(&format!(":{s:02}"));
    }
    Some(out)
}

fn month_number(name: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let prefix = name.get(..3)?.to_ascii_lowercase();
    MONTHS
        .iter()
        .position(|m| *m == prefix)
        .map(|i| i as u32 + 1)
}

/// Largest size we believe (2^53 bytes, 8 PiB).
const MAX_SIZE: u64 = 1 << 53;

const SIZE_TOKEN: &str = r"(?:-|<dir>|(\d+(?:\.\d+)?)\s*([KMGTP])?(?:i?B(?:ytes)?)?)";

/// Size at the start of `text`. `Some(None)` means an explicit "no size" (`-`, `<dir>`).
fn size_prefix(text: &str) -> Option<Option<u64>> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"(?i)^\s*{SIZE_TOKEN}(?:\s|$)")).unwrap());
    size_from(RE.captures(text)?)
}

/// `text` is exactly one size token.
fn size_exact(text: &str) -> Option<Option<u64>> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"(?i)^{SIZE_TOKEN}$")).unwrap());
    size_from(RE.captures(text)?)
}

fn size_from(c: regex::Captures<'_>) -> Option<Option<u64>> {
    let Some(number) = c.get(1) else {
        return Some(None);
    };
    let value: f64 = number.as_str().parse().ok()?;
    let power = match c.get(2).map(|u| u.as_str().to_ascii_uppercase()) {
        None => 0,
        Some(unit) => "KMGTP".find(&unit)? as i32 + 1,
    };
    let bytes = (value * 1024f64.powi(power)).round();
    // Anything above 8 PiB is not a real file size; don't let it overflow sums.
    Some((bytes <= MAX_SIZE as f64).then_some(bytes as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fixture(base: &str, content_type: Option<&str>, body: &str) -> Listing {
        parse(&Url::parse(base).unwrap(), content_type, body).expect("should be a listing")
    }

    /// (name, is_dir, size, mtime) for compact assertions.
    fn rows(listing: &Listing) -> Vec<(&str, bool, Option<u64>, Option<&str>)> {
        listing
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.is_dir, e.size, e.mtime.as_deref()))
            .collect()
    }

    #[test]
    fn apache_table_real_ubuntu() {
        let listing = parse_fixture(
            "https://archive.ubuntu.com/ubuntu/",
            Some("text/html"),
            include_str!("../tests/fixtures/apache_table_ubuntu.html"),
        );
        assert_eq!(listing.server, Server::Apache);
        assert_eq!(
            rows(&listing),
            vec![
                ("dists", true, None, Some("2026-04-24 09:23")),
                ("indices", true, None, Some("2026-09-28 14:00")),
                (
                    "ls-lR.gz",
                    false,
                    Some(37 * 1024 * 1024),
                    Some("2026-09-28 14:04")
                ),
                ("pool", true, None, Some("2010-02-27 06:30")),
                ("project", true, None, Some("2024-11-24 21:31")),
                ("ubuntu", true, None, Some("2026-09-28 14:37")),
            ]
        );
        assert_eq!(
            listing.entries[2].url.as_str(),
            "https://archive.ubuntu.com/ubuntu/ls-lR.gz"
        );
    }

    #[test]
    fn apache_pre() {
        let listing = parse_fixture(
            "https://ftp.example.org/pub/gnu/",
            None,
            include_str!("../tests/fixtures/apache_pre.html"),
        );
        assert_eq!(listing.server, Server::Apache);
        assert_eq!(
            rows(&listing),
            vec![
                ("bash", true, None, Some("2026-09-24 23:47")),
                (
                    "hello-2.12.1.tar.gz",
                    false,
                    Some(1024 * 1024),
                    Some("2022-05-29 10:12")
                ),
                ("README", false, Some(12 * 1024), Some("2026-01-02 03:04")),
                (
                    "a-very-long-release-name-that-apache-truncates-1.0.tar.xz",
                    false,
                    Some(5 * 1024 * 1024 * 1024 / 2),
                    Some("2025-12-31 23:59")
                ),
                (
                    "My Notes & Ideas.txt",
                    false,
                    Some(512),
                    Some("2026-03-04 05:06")
                ),
            ]
        );
    }

    #[test]
    fn apache_with_a_custom_title_and_header() {
        // Real structure of releases.ubuntu.com: the title says "Ubuntu Releases".
        let listing = parse_fixture(
            "https://releases.ubuntu.com/",
            Some("text/html"),
            include_str!("../tests/fixtures/apache_custom_header.html"),
        );
        assert_eq!(listing.server, Server::Apache);
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"24.04.4") && names.contains(&"14.04"),
            "{names:?}"
        );
        let iso = listing
            .entries
            .iter()
            .find(|e| e.name.ends_with(".iso"))
            .unwrap();
        assert_eq!(iso.size, Some(6_657_199_309));
        assert_eq!(iso.mtime.as_deref(), Some("2025-08-05 10:00"));
        // The page's own link to another site is kept for discovery.
        assert!(
            listing
                .external_dirs
                .iter()
                .any(|u| u.as_str() == "http://old-releases.ubuntu.com/releases/")
        );
    }

    #[test]
    fn unannounced_listings_are_recognised_by_their_links() {
        let base = Url::parse("https://h.example/pub/").unwrap();
        let rows = |lines: &[(&str, &str, &str)]| -> String {
            let mut body = String::from("<html><head><title>Files</title></head><body><pre>\n");
            for (name, text, date) in lines {
                body.push_str(&format!("<a href=\"{name}\">{text}</a>  {date}  1.5M\n"));
            }
            body + "</pre></body></html>"
        };
        // Link text equals the name, with dates: a listing (custom nginx page).
        let listing = rows(&[
            ("a.iso", "a.iso", "28-Sep-2026 10:15"),
            ("b.iso", "b.iso", "27-Sep-2026 10:15"),
            (
                "very-long-name.tar.gz",
                "very-long-na..&gt;",
                "26-Sep-2026 10:15",
            ),
        ]);
        assert!(parse(&base, None, &listing).is_some());
        // A blog index: dates next to links, but the link text is a title.
        let blog = rows(&[
            ("post-1.html", "Why I like Rust", "28-Sep-2026 10:15"),
            ("post-2.html", "Notes from a trip", "27-Sep-2026 10:15"),
            ("post-3.html", "Ten small tips", "26-Sep-2026 10:15"),
        ]);
        assert!(parse(&base, None, &blog).is_none());
        // Matching names but no dates: not enough evidence.
        let undated = "<title>Files</title><a href=\"a.txt\">a.txt</a> <a href=\"b.txt\">b.txt</a> \
                       <a href=\"c.txt\">c.txt</a>";
        assert!(parse(&base, None, undated).is_none());
    }

    #[test]
    fn nginx() {
        let listing = parse_fixture(
            "https://cdn.example.org/pub/linux/",
            Some("text/html"),
            include_str!("../tests/fixtures/nginx.html"),
        );
        assert_eq!(listing.server, Server::Nginx);
        assert_eq!(
            rows(&listing),
            vec![
                ("docs", true, None, Some("2025-01-01 00:00")),
                ("kernel", true, None, Some("2026-09-12 08:15")),
                ("README", false, Some(2048), Some("2026-09-28 10:15")),
                ("a b.txt", false, Some(12), Some("2026-03-05 07:07")),
                (
                    "linux-6.16.tar.xz",
                    false,
                    Some(149_213_136),
                    Some("2026-07-27 22:30")
                ),
            ]
        );
    }

    #[test]
    fn nginx_fancyindex_size_before_date() {
        let listing = parse_fixture(
            "https://mirror.example.net/mirror/",
            None,
            include_str!("../tests/fixtures/nginx_fancyindex.html"),
        );
        assert_eq!(listing.server, Server::Nginx);
        assert_eq!(
            rows(&listing),
            vec![
                ("alpine", true, None, Some("2026-09-27 04:00")),
                ("index.json", false, Some(12_595), Some("2026-09-28 06:01")),
            ]
        );
    }

    #[test]
    fn lighttpd() {
        let listing = parse_fixture(
            "https://data.example.edu/data/",
            None,
            include_str!("../tests/fixtures/lighttpd.html"),
        );
        assert_eq!(listing.server, Server::Lighttpd);
        assert_eq!(
            rows(&listing),
            vec![
                ("climate", true, None, Some("2026-08-03 11:22:33")),
                (
                    "stations.csv",
                    false,
                    Some(1_572_864),
                    Some("2026-09-01 00:00:05")
                ),
            ]
        );
    }

    #[test]
    fn iis_date_before_link() {
        let listing = parse_fixture(
            "https://files.example.edu/pub/",
            None,
            include_str!("../tests/fixtures/iis.html"),
        );
        assert_eq!(listing.server, Server::Iis);
        assert_eq!(
            rows(&listing),
            vec![
                ("datasets", true, None, Some("2026-09-28 10:15")),
                (
                    "report 2025.pdf",
                    false,
                    Some(123_456),
                    Some("2026-01-05 15:07")
                ),
                ("readme.txt", false, Some(2048), Some("2025-12-31 00:01")),
            ]
        );
    }

    #[test]
    fn iis_site_root_without_parent_link() {
        let listing = parse_fixture(
            "https://files.example.edu/",
            None,
            include_str!("../tests/fixtures/iis_root.html"),
        );
        assert_eq!(listing.server, Server::Iis);
        assert_eq!(
            rows(&listing),
            vec![
                ("pub", true, None, Some("2026-09-28 10:15")),
                ("readme.txt", false, Some(123_456), Some("2026-01-05 15:07")),
            ]
        );
    }

    #[test]
    fn ignores_data_href_and_commented_out_links() {
        let base = Url::parse("https://h.example/pub/").unwrap();
        let body = r#"<title>Index of /pub/</title><pre>
            <a data-href="evil/" href="good.txt">good.txt</a> 2026-09-28 10:15 1K
            <!-- <a href="hidden/">hidden/</a> -->
            </pre>"#;
        let listing = parse(&base, None, body).unwrap();
        let names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["good.txt"]);
    }

    #[test]
    fn collects_directory_links_to_other_sites() {
        let base = Url::parse("https://h.example/pub/").unwrap();
        let body = r#"<title>Index of /pub/</title>
            <a href="https://mirror.example.net/pub/">mirror</a>
            <a href="https://mirror.example.net/about.html">about</a>
            <a href="https://other.example/list/?C=N;O=D">sorted</a>
            <a href="f.txt">f.txt</a>"#;
        let listing = parse(&base, None, body).unwrap();
        let external: Vec<_> = listing.external_dirs.iter().map(Url::as_str).collect();
        assert_eq!(external, vec!["https://mirror.example.net/pub/"]);
    }

    #[test]
    fn day_month_year_dates_with_a_comma_and_sizes_with_units() {
        // Node.js's release server: `22 Sept 2026, 09:01`, `87 MB`, absolute links,
        // and a dash where folders have no date or size.
        let listing = parse_fixture(
            "https://nodejs.org/dist/latest/",
            Some("text/html"),
            include_str!("../tests/fixtures/nodejs_dist.html"),
        );
        let at = |t: &'static str| Some(t);
        assert_eq!(
            rows(&listing),
            vec![
                ("docs", true, None, None),
                ("win-x64", true, None, None),
                ("SHASUMS256.txt", false, Some(3277), at("2026-09-22 09:01")),
                (
                    "SHASUMS256.txt.sig",
                    false,
                    Some(119),
                    at("2026-09-22 09:02")
                ),
                (
                    "node-v26.10.0-aix-ppc64.tar.gz",
                    false,
                    Some(87 * 1024 * 1024),
                    at("2026-09-22 09:01")
                ),
                (
                    "node-v26.10.0-headers.tar.xz",
                    false,
                    Some(584 * 1024),
                    at("2026-09-22 09:01")
                ),
            ]
        );
    }

    #[test]
    fn caddy_json() {
        let listing = parse_fixture(
            "https://files.example.com/pub/",
            Some("application/json"),
            include_str!("../tests/fixtures/caddy.json"),
        );
        assert_eq!(listing.server, Server::Caddy);
        assert_eq!(
            rows(&listing),
            vec![
                ("isos", true, None, Some("2026-09-20 12:00:00")),
                ("SHA256SUMS", false, Some(512), Some("2026-09-21 08:30:15")),
            ]
        );
        assert_eq!(
            listing.entries[0].url.as_str(),
            "https://files.example.com/pub/isos/"
        );
    }

    #[test]
    fn python_http_server_names_only() {
        let listing = parse_fixture(
            "http://192.0.2.10:8000/share/",
            None,
            include_str!("../tests/fixtures/python_http_server.html"),
        );
        assert_eq!(listing.server, Server::PythonHttp);
        assert_eq!(
            rows(&listing),
            vec![
                ("notes", true, None, None),
                ("paper.pdf", false, None, None)
            ]
        );
    }

    #[test]
    fn a_link_that_spells_the_host_with_a_trailing_dot_is_still_this_site() {
        let base = Url::parse("https://mirror.example.org/pub/").unwrap();
        let page = "<html><head><title>Index of /pub</title></head><body><pre>\n\
            <a href=\"https://mirror.example.org./pub/iso/\">iso/</a>  28-Sep-2026 10:15  -\n\
            <a href=\"https://other.example.net/pub/\">other/</a>  28-Sep-2026 10:15  -\n\
            </pre></body></html>";
        let listing = parse(&base, Some("text/html"), page).unwrap();
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["iso"]);
        assert_eq!(
            listing.entries[0].url.as_str(),
            "https://mirror.example.org/pub/iso/"
        );
        // A real other site is still only recorded for later.
        assert_eq!(listing.external_dirs.len(), 1);
    }

    #[test]
    fn icon_links_do_not_hide_an_unannounced_listing() {
        let base = Url::parse("https://h.example/pub/").unwrap();
        // Each row: an icon that is itself a link, then the name as a link, then
        // the date and size. Nothing on the page says "Index of".
        let page = |names: &[(&str, &str)]| -> String {
            let mut body = String::from("<html><head><title>Files</title></head><body><table>\n");
            for (name, text) in names {
                body.push_str(&format!(
                    "<tr><td><a href=\"{name}\"><img src=\"/i/file.png\"></a></td>\
                     <td><a href=\"{name}\">{text}</a></td><td>28-Sep-2026 10:15</td>\
                     <td>1.5M</td></tr>\n"
                ));
            }
            body + "</table></body></html>"
        };
        let listing = parse(
            &base,
            None,
            &page(&[("a.iso", "a.iso"), ("b.iso", "b.iso"), ("c.iso", "c.iso")]),
        )
        .expect("the icon links hid the listing");
        assert_eq!(listing.entries.len(), 3);
        assert!(listing.entries.iter().all(|e| e.mtime.is_some()));
        assert!(listing.entries.iter().all(|e| e.size == Some(1_572_864)));
        // With titles instead of names it is still a blog, icons or not.
        let blog = page(&[
            ("post-1.html", "Why I like Rust"),
            ("post-2.html", "Notes from a trip"),
            ("post-3.html", "Ten small tips"),
        ]);
        assert!(parse(&base, None, &blog).is_none());
    }

    #[test]
    fn ordinary_page_is_not_a_listing() {
        let base = Url::parse("https://example.org/").unwrap();
        let body = include_str!("../tests/fixtures/not_a_listing.html");
        assert!(parse(&base, Some("text/html"), body).is_none());
    }

    #[test]
    fn navigation_links_are_not_entries() {
        let base = Url::parse("https://h.example/a/b/").unwrap();
        let body = r##"<title>Index of /a/b/</title>
            <a href="../">up</a> <a href="/">root</a> <a href="/other/">other</a>
            <a href="https://elsewhere.example/x/">x</a> <a href="c/d/">deep</a>
            <a href="?C=N;O=D">sort</a> <a href="#top">top</a> <a href="f.txt">f</a>"##;
        let listing = parse(&base, None, body).unwrap();
        let names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["f.txt"]);
        let others: Vec<_> = listing.other_dirs.iter().map(Url::as_str).collect();
        assert_eq!(
            others,
            vec!["https://h.example/other/", "https://h.example/a/b/c/d/"]
        );
    }

    #[test]
    fn child_detection() {
        let base = Url::parse("https://h.example/pub/").unwrap();
        let child = |s: &str| is_child(&base, &Url::parse(s).unwrap());
        assert!(child("https://h.example/pub/file.iso"));
        assert!(child("https://h.example/pub/dir/"));
        assert!(!child("https://h.example/pub/"));
        assert!(!child("https://h.example/pub/dir/deeper/"));
        assert!(!child("https://h.example/"));
        assert!(!child("http://h.example/pub/file.iso"));
        assert!(!child("https://h.example/pub/?C=N;O=D"));
    }

    #[test]
    fn sizes() {
        assert_eq!(size_prefix(" 37M"), Some(Some(37 * 1024 * 1024)));
        assert_eq!(size_prefix("1.5K text/csv"), Some(Some(1536)));
        assert_eq!(size_prefix("12345"), Some(Some(12345)));
        assert_eq!(size_prefix("- Directory"), Some(None));
        assert_eq!(size_prefix("<dir>"), Some(None));
        assert_eq!(size_prefix("GNU Hello"), None);
        assert_eq!(size_exact("12.3 KiB"), Some(Some(12_595)));
        assert_eq!(size_exact("3 B"), Some(Some(3)));
        // Absurd sizes (a hostile listing) are dropped instead of overflowing totals.
        assert_eq!(size_prefix("5000P"), Some(None));
    }

    #[test]
    fn dates() {
        let d = |s: &str| find_date(s).map(|(date, _, _)| date);
        assert_eq!(d("2026-09-28 14:04"), Some("2026-09-28 14:04".into()));
        assert_eq!(d("28-Sep-2026 10:15"), Some("2026-09-28 10:15".into()));
        assert_eq!(
            d("2026-Sep-28 10:15:00"),
            Some("2026-09-28 10:15:00".into())
        );
        assert_eq!(d("9/28/2026 12:05 AM"), Some("2026-09-28 00:05".into()));
        assert_eq!(d("9/28/2026 1:05 PM"), Some("2026-09-28 13:05".into()));
        assert_eq!(
            d("Monday, September 28, 2026 10:15 PM"),
            Some("2026-09-28 22:15".into())
        );
        assert_eq!(d("28.09.2026 10:15"), Some("2026-09-28 10:15".into()));
        assert_eq!(d("22 Sept 2026, 09:01"), Some("2026-09-22 09:01".into()));
        assert_eq!(d("5 January 2026 9:05 PM"), Some("2026-01-05 21:05".into()));
        assert_eq!(d("5 Dogs 2026, 09:01"), None);
        assert_eq!(d("2026-13-01 10:00"), None);
        assert_eq!(d("no date here"), None);
    }

    #[test]
    fn entities() {
        assert_eq!(
            decode_entities("a &amp; b &lt;dir&gt; &#39;x&#x27;"),
            "a & b <dir> 'x'"
        );
        assert_eq!(
            decode_entities("fish & chips &bogus;"),
            "fish & chips &bogus;"
        );
        assert_eq!(decode_entities("é&amp;"), "é&");
        assert_eq!(decode_entities("a&#0;b"), "a&#0;b");
    }
}
