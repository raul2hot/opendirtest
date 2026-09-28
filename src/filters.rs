//! Name-based rules and the operator-maintained lists.
//!
//! - Sensitive exposures are checked at crawl time (`DROP_SENSITIVE_EXPOSURES`).
//! - Likely infringement is checked at search time only.
//! - The opt-out list is checked at crawl time, the takedown list at search time.
//! - Whether a discovered listing looks like a public archive is checked when
//!   it is found (`has_archive_signal`).

use std::path::Path;
use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::{Regex, RegexSet};
use url::{Host, Url};

/// How serious a sensitive-looking name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Probably exposed by accident, but also normal on some legitimate sites
    /// (a database dump in a dataset). A site you trust only loses that entry;
    /// any other site is dropped.
    Weak,
    /// Credentials, keys, or the mark of a compromised server. The site is
    /// dropped, whoever added it.
    Strong,
}

/// Names that almost always mean a listing was exposed by accident, or that a
/// server was broken into. Deliberately narrow: public keys, `.pem` bundles and
/// dataset SQL dumps (e.g. Wikimedia) are normal on legitimate mirrors.
static STRONG_NAMES: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)^\.env(\.[\w.-]+)?$",
        r"^id_(rsa|dsa|ecdsa|ed25519)$",
        r"(?i)^\.(git|svn|hg|ssh|aws|gnupg|bash_history|zsh_history|htpasswd)$",
        r"(?i)^wp-config\.php",
        r"(?i)\.(kdbx|ppk)$",
        r"(?i)^wallet\.dat$",
        // Links to other hosting accounts' CMS config files, left in a web folder
        // by an intruder: `<account>-Wordpress26.txt`, `<account>-BoxBilling444.txt404`.
        r"(?i)^[a-z0-9_.-]+-(wordpress|joomla|phpbb\d*|boxbilling|whmcs|vbulletin|drupal|magento|opencart|prestashop|smf|mybb|moodle)\d*\.txt\d*$",
    ])
    .unwrap()
});

static WEAK_NAMES: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\.(pst|ost)$",
        r"(?i)(backup|dump|database|mysql|db)[^/]*\.sql(\.(gz|bz2|xz|zip|7z))?$",
        // Dated backup files, and archives of a whole web root.
        r"(?i)^(backup|bak)[-_]?\d{4}",
        r"(?i)^(public_html|htdocs|wwwroot)[^/]*\.(zip|tar|tgz|tar\.gz|7z|rar)$",
        // Personal documents: only as documents or scans, so that software such
        // as CRAN's `passport_0.3.0.tar.gz` package does not match.
        r"(?i)^(passport|payroll|tax[-_ ]?return|bank[-_ ]?statement)[^/]*\.(pdf|jpe?g|png|tiff?|heic|docx?|xlsx?|odt|ods)$",
    ])
    .unwrap()
});

/// Listing paths that expose a home directory or the filesystem root, or that
/// are the folder of links to other accounts' config files (see above).
static SENSITIVE_PATHS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"^/home/[^/]+/",
        r"^/root/",
        r"^/Users/[^/]+/",
        r"(?i)(^|/)sym404(/|$)",
    ])
    .unwrap()
});

/// Release-style names that suggest pirated media or cracked software.
/// Signals, not proof: applied only when searching, never while crawling.
static LIKELY_INFRINGING: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\b(2160p|1080p|720p|x26[45]|hevc|web-?dl|webrip|blu-?ray|brrip|hdrip|dvdrip|remux)\b",
        r"(?i)\bS\d{1,2}E\d{1,3}\b",
        r"(?i)\b(crack|cracked|keygen)\b.*\.(exe|zip|rar|7z|iso)$",
        r"\.[A-Za-z0-9-]+-[A-Za-z0-9]{2,12}\.(mkv|mp4|avi)$",
    ])
    .unwrap()
});

/// `name` may carry a trailing `/` for directories (Caddy does this).
pub fn sensitivity(name: &str) -> Option<Sensitivity> {
    let name = name.trim_end_matches('/');
    if STRONG_NAMES.is_match(name) {
        Some(Sensitivity::Strong)
    } else if WEAK_NAMES.is_match(name) {
        Some(Sensitivity::Weak)
    } else {
        None
    }
}

pub fn is_sensitive_name(name: &str) -> bool {
    sensitivity(name).is_some()
}

/// `path` is a URL path, still percent-encoded.
pub fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.is_match(path)
}

pub fn is_likely_infringing(name: &str) -> bool {
    LIKELY_INFRINGING.is_match(name)
}

/// Reads a list file: one item per line, `#` starts a comment. A missing file
/// is an empty list. Handles the UTF-8 BOM and UTF-16 that Windows tools write.
pub fn load_list(path: &Path) -> anyhow::Result<Vec<String>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    };
    Ok(decode_text(&bytes)
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

fn decode_text(bytes: &[u8]) -> String {
    fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| unit([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    }
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).into_owned()
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, u16::from_le_bytes)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, u16::from_be_bytes)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Turns an opt-out entry into a host name as crawled URLs have it: accepts a
/// bare domain, a URL, `*.domain` and a trailing dot; lower-cases it and
/// converts international names to their ASCII form.
pub fn normalize_domain(entry: &str) -> String {
    let entry = entry.trim();
    let from_url = entry
        .contains("://")
        .then(|| Url::parse(entry).ok()?.host_str().map(str::to_owned))
        .flatten();
    let domain = from_url.unwrap_or_else(|| entry.to_string());
    let domain = domain.trim_start_matches("*.").trim_end_matches('.');
    Url::parse(&format!("http://{domain}/"))
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| domain.to_ascii_lowercase())
}

/// False for hosts on a local or private network (`localhost`, `192.168.x.x`,
/// `*.local`, ...). Links and redirects there are never recorded as sites to
/// crawl, so a listing can't point the crawler into your own network.
pub fn is_public_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => {
            const LOCAL: [&str; 6] = [
                ".localhost",
                ".local",
                ".internal",
                ".lan",
                ".home.arpa",
                ".intranet",
            ];
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain.contains('.')
                && domain != "localhost"
                && !LOCAL.iter().any(|suffix| domain.ends_with(suffix))
        }
        Some(Host::Ipv4(ip)) => {
            let [a, b, ..] = ip.octets();
            let shared = a == 100 && (64..128).contains(&b); // carrier-grade NAT
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation()
                || shared)
        }
        Some(Host::Ipv6(ip)) => {
            let mapped_private = ip.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            });
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || mapped_private)
        }
        None => false,
    }
}

/// Normalises a takedown URL prefix the same way crawled URLs are stored
/// (lower-case host, no default port, percent-encoded path).
pub fn normalize_url_prefix(prefix: &str) -> String {
    Url::parse(prefix).map_or_else(|_| prefix.to_string(), String::from)
}

/// Sites and folders the crawler leaves alone (`lists/skip.txt`): by default
/// the big software package archives that mirrors are full of.
#[derive(Clone, Debug, Default)]
pub struct SkipList {
    hosts: Vec<String>,
    /// Lower-case folder patterns such as `/pool/`, matched anywhere in a path.
    folders: Vec<String>,
}

impl SkipList {
    /// Lines starting with `/` are folder patterns; any other line is a site.
    pub fn from_lines(lines: &[String]) -> Self {
        let mut list = SkipList::default();
        for line in lines {
            if line.starts_with('/') {
                let mut folder = line.to_lowercase();
                if !folder.ends_with('/') {
                    folder.push('/');
                }
                list.folders.push(folder);
            } else {
                list.hosts.push(normalize_domain(line));
            }
        }
        list
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn has_folders(&self) -> bool {
        !self.folders.is_empty()
    }

    pub fn skips_host(&self, host: &str) -> bool {
        host_opted_out(host, &self.hosts)
    }

    /// True if the URL is a skipped folder or inside one.
    pub fn skips_folder(&self, url: &Url) -> bool {
        if self.folders.is_empty() {
            return false;
        }
        let path = percent_decode_str(url.path())
            .decode_utf8_lossy()
            .to_lowercase();
        self.folders
            .iter()
            .any(|folder| path.contains(folder.as_str()))
    }
}

/// Host name parts that suggest a public file server or archive:
/// `ftp.`, `mirror.`, `download.`, `releases.`, `cdimage.`, `.edu`, `.gov`, `.ac.uk`.
static ARCHIVE_HOST_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(ftp|mirrors?|dl|downloads?|files|archives?|dist|distros?|releases?|pub|data|opendata|dumps|software|isos?|cdimage|edu|gov|ac)\d*$",
    )
    .unwrap()
});

/// Folder names that suggest a public file server or archive.
static ARCHIVE_SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(pub|mirrors?|dist|distrib|downloads?|dl|releases?|isos?|archives?|software|data|datasets?|ebooks?|books|library|papers|publications|linux|gnu|bsd|opendata|ftp)$",
    )
    .unwrap()
});

/// Hosting services where anyone picks a name under the service's domain, so a
/// name like `files.` says nothing about the content.
const USER_HOSTED: &[&str] = &[
    "wordpress.com",
    "blogspot.com",
    "github.io",
    "gitlab.io",
    "netlify.app",
    "herokuapp.com",
    "appspot.com",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "weebly.com",
    "wixsite.com",
    "tumblr.com",
    "neocities.org",
    "000webhostapp.com",
];

fn is_user_hosted(host: &str) -> bool {
    USER_HOSTED
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

/// True if the site's name (`ftp.example.org`, `dl.example.com`, `example.edu`)
/// suggests a public file server or archive.
pub fn has_archive_host(url: &Url) -> bool {
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    !is_user_hosted(&host)
        && host
            .split(['.', '-'])
            .any(|t| ARCHIVE_HOST_TOKEN.is_match(t))
}

/// True if the URL looks like part of a public archive: an archive-like site
/// name, or a folder such as `/pub/`, `/mirror/` or `/downloads/` in the path.
/// Discovery keeps only such listings, because most of the open directories a
/// web crawl finds are website internals (upload folders, image folders).
pub fn has_archive_signal(url: &Url) -> bool {
    if is_user_hosted(&url.host_str().unwrap_or("").to_ascii_lowercase()) {
        return false;
    }
    has_archive_host(url)
        || url.path_segments().is_some_and(|mut segments| {
            segments.any(|s| {
                ARCHIVE_SEGMENT.is_match(&percent_decode_str(s).decode_utf8_lossy().to_lowercase())
            })
        })
}

/// Opt-out list entries are domains; a domain also covers its subdomains.
pub fn host_opted_out(host: &str, optout: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    optout.iter().any(|domain| {
        let domain = domain.to_ascii_lowercase();
        host == domain || host.ends_with(&format!(".{domain}"))
    })
}

/// Takedown list entries are URL prefixes.
pub fn url_taken_down(url: &str, takedown: &[String]) -> bool {
    takedown
        .iter()
        .any(|prefix| url.starts_with(prefix.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_names() {
        for name in [
            ".env",
            ".env.production",
            "id_rsa",
            "id_ed25519",
            ".git",
            ".ssh",
            "wp-config.php.bak",
            "Passwords.kdbx",
            "backup-2026.sql.gz",
            "mysql_dump.sql",
            "payroll_2025.xlsx",
            "passport-scan.jpg",
        ] {
            assert!(is_sensitive_name(name), "{name} should be sensitive");
        }
        for name in [
            "id_rsa.pub",
            "cacert.pem",
            "RPM-GPG-KEY-fedora",
            "jenkins.io.key",
            "enwiki-20260901-page.sql.gz",
            "environment.yml",
            "taxonomy.txt",
            "gitlab-17.0.tar.gz",
            "passport_0.3.0.tar.gz",
            "payroll-engine-2.1.zip",
        ] {
            assert!(!is_sensitive_name(name), "{name} should not be sensitive");
        }
    }

    #[test]
    fn sensitive_paths() {
        assert!(is_sensitive_path("/home/alice/"));
        assert!(is_sensitive_path("/root/.cache/"));
        assert!(!is_sensitive_path("/~alice/public/"));
        assert!(!is_sensitive_path("/pub/home/"));
    }

    #[test]
    fn likely_infringing() {
        assert!(is_likely_infringing("Show.S01E02.1080p.WEB-DL-NTb.mkv"));
        assert!(is_likely_infringing(
            "Movie.2024.2160p.BluRay.x265-GROUP.mkv"
        ));
        assert!(is_likely_infringing("PhotoApp.2026.Cracked.zip"));
        assert!(!is_likely_infringing("ubuntu-24.04.3-desktop-amd64.iso"));
        assert!(!is_likely_infringing("foo_1.0+repack.orig.tar.gz"));
        assert!(!is_likely_infringing("ssh-keygen.1.html"));
        assert!(!is_likely_infringing("lecture-01.mp4"));
    }

    #[test]
    fn compromised_server_signatures() {
        // From a real crawl: a folder of links to other accounts' config files.
        for name in [
            "daemon-Wordpress26.txt404/",
            "daemon-phpBB3.txt404/",
            "dbus-BoxBilling444.txt404/",
            "shop-joomla2.txt",
        ] {
            assert_eq!(sensitivity(name), Some(Sensitivity::Strong), "{name}");
        }
        assert!(is_sensitive_path("/sym404/"));
        assert!(is_sensitive_path("/pub/SYM404/daemon-Wordpress1.txt404/"));
        assert!(!is_sensitive_path("/pub/symbols/"));
        for name in [
            "wordpress-6.6.zip",
            "wordpress-plugin-1.txt-notes.tar.gz",
            "joomla-cms-5.2.tar.gz",
        ] {
            assert_eq!(sensitivity(name), None, "{name}");
        }
    }

    #[test]
    fn weak_names_only_cost_a_trusted_site_the_entry() {
        assert_eq!(
            sensitivity("backup-2026-09-01.zip"),
            Some(Sensitivity::Weak)
        );
        assert_eq!(sensitivity("db_dump.sql.gz"), Some(Sensitivity::Weak));
        assert_eq!(sensitivity("public_html.zip"), Some(Sensitivity::Weak));
        assert_eq!(sensitivity("Outlook.pst"), Some(Sensitivity::Weak));
        assert_eq!(sensitivity(".env"), Some(Sensitivity::Strong));
        assert_eq!(sensitivity("backups.txt"), None);
        assert_eq!(sensitivity("backup-tool-1.0.tar.gz"), None);
    }

    #[test]
    fn archive_signals() {
        let has = |u: &str| has_archive_signal(&Url::parse(u).unwrap());
        for good in [
            "https://ftp.funet.fi/pub/",
            "https://mirror.example.edu/ubuntu/",
            "https://download.blender.org/release/",
            "https://old-releases.ubuntu.com/releases/",
            "https://cdimage.debian.org/debian-cd/",
            "https://data.example.com/x/",
            "https://www.math.example.ac.uk/",
            "https://nodejs.org/download/release/",
            "https://example.org/pub/gnu/",
            "https://example.org/Downloads/iso/",
        ] {
            assert!(has(good), "{good}");
        }
        for junk in [
            "https://blog.example.com/wp-content/uploads/2020/05/",
            "https://random-shop.example.com/images/",
            "https://example.com/",
            "http://203.0.113.9/movies/",
            "https://foo.files.wordpress.com/",
            "https://example.org/publish/",
        ] {
            assert!(!has(junk), "{junk}");
        }
    }

    #[test]
    fn caddy_style_directory_names() {
        assert!(is_sensitive_name(".git/"));
        assert!(is_sensitive_name(".aws/"));
    }

    #[test]
    fn list_files_from_windows_tools() {
        let dir = std::env::temp_dir().join(format!("opendirtest-lists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bom = dir.join("bom.txt");
        std::fs::write(&bom, b"\xEF\xBB\xBFexample.org\r\nother.net # note\r\n").unwrap();
        assert_eq!(load_list(&bom).unwrap(), vec!["example.org", "other.net"]);

        let utf16 = dir.join("utf16.txt");
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "example.org\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&utf16, bytes).unwrap();
        assert_eq!(load_list(&utf16).unwrap(), vec!["example.org"]);

        assert!(load_list(&dir.join("missing.txt")).unwrap().is_empty());
    }

    #[test]
    fn public_hosts() {
        let public = |u: &str| is_public_host(&Url::parse(u).unwrap());
        assert!(public("https://mirror.example.org/pub/"));
        assert!(public("http://8.8.8.8/"));
        assert!(public("http://[2001:4860:4860::8888]/"));
        for private in [
            "http://localhost:8000/",
            "http://printer/",
            "http://nas.local/",
            "http://router.home.arpa/",
            "http://127.0.0.1/",
            "http://192.168.1.1/",
            "http://10.0.0.5/",
            "http://172.16.3.4/",
            "http://169.254.1.1/",
            "http://100.64.0.1/",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://[::ffff:192.168.1.1]/",
        ] {
            assert!(!public(private), "{private}");
        }
    }

    #[test]
    fn normalisation() {
        assert_eq!(normalize_domain("Example.ORG"), "example.org");
        assert_eq!(
            normalize_domain("https://Example.org/some/path"),
            "example.org"
        );
        assert_eq!(normalize_domain("*.example.org"), "example.org");
        assert_eq!(normalize_domain("example.org."), "example.org");
        assert_eq!(normalize_domain("  example.org  "), "example.org");
        assert_eq!(normalize_domain("bücher.example"), "xn--bcher-kva.example");
        assert_eq!(
            normalize_url_prefix("HTTPS://H.Example:443/pub/my file"),
            "https://h.example/pub/my%20file"
        );
    }

    #[test]
    fn skip_list() {
        let lines: Vec<String> = ["/pool/", "/src/contrib", "cran.r-project.org"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let skip = SkipList::from_lines(&lines);
        let folder = |u: &str| skip.skips_folder(&Url::parse(u).unwrap());
        assert!(folder("https://mirror.example.edu/ubuntu/pool/"));
        assert!(folder("https://mirror.example.edu/ubuntu/pool/main/p/"));
        assert!(folder("https://mirror.example.edu/cran/src/contrib/"));
        assert!(folder("https://mirror.example.edu/POOL/"), "ignores case");
        assert!(!folder("https://mirror.example.edu/ubuntu/"));
        assert!(!folder("https://mirror.example.edu/whirlpool/"));
        assert!(skip.skips_host("cran.r-project.org"));
        assert!(!skip.skips_host("cloud.r-project.org"));
        assert!(!skip.skips_host("r-project.org"));
    }

    #[test]
    fn lists() {
        let optout = vec!["example.org".to_string()];
        assert!(host_opted_out("example.org", &optout));
        assert!(host_opted_out("Mirror.Example.org", &optout));
        assert!(!host_opted_out("notexample.org", &optout));

        let takedown = vec!["https://h.example/pub/private/".to_string()];
        assert!(url_taken_down(
            "https://h.example/pub/private/a.txt",
            &takedown
        ));
        assert!(!url_taken_down("https://h.example/pub/a.txt", &takedown));
    }
}
