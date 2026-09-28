//! Crawl safety switches, hoisted into one place.
//!
//! Each switch is a compile-time constant, so turning one off is a reviewed code
//! change rather than a runtime option. All of them default to `true`.
//!
//! "Metadata only" is deliberately not a switch: the crawler stores names, sizes
//! and dates and has no code path that downloads file bodies.
//!
//! Likely-infringement filtering is not a crawl-time switch either. It happens at
//! search time (see `docs/GUIDE.md`, §6.3).

/// Fetch `/robots.txt` before crawling a host and obey it (RFC 9309).
/// 4xx means allowed; 5xx or unreachable means fully disallowed.
pub const RESPECT_ROBOTS_TXT: bool = true;

/// Keep each host to about 1 request/s and at most 2 connections, honor
/// `Crawl-delay`, and back off on 429/503 using `Retry-After`.
pub const ENFORCE_PER_HOST_RATE_LIMIT: bool = true;

/// Send a descriptive `User-Agent` that links to the bot info and opt-out page.
pub const SEND_IDENTIFYING_USER_AGENT: bool = true;

/// Skip hosts whose owners opted out through the bot page.
pub const HONOR_OPT_OUT_LIST: bool = true;

/// Only follow links that appear in a listing. Never guess paths or run
/// wordlists against servers we don't own.
pub const FOLLOW_LISTED_LINKS_ONLY: bool = true;

/// Drop hosts whose listings look like accidental leaks (`.env` files, SSH keys,
/// SQL dumps and similar; see `docs/GUIDE.md`, §6.2).
pub const DROP_SENSITIVE_EXPOSURES: bool = true;

/// Hide hosts and URLs on the takedown list (DMCA notices, GDPR deletion
/// requests) from search results.
pub const HONOR_TAKEDOWN_LIST: bool = true;
