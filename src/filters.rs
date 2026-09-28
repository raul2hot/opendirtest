//! Name-based rules and the operator-maintained lists.
//!
//! - Sensitive exposures are checked at crawl time (`DROP_SENSITIVE_EXPOSURES`).
//! - Likely infringement is checked at search time only.
//! - The opt-out list is checked at crawl time, the takedown list at search time.

use std::path::Path;
use std::sync::LazyLock;

use regex::RegexSet;

/// File or directory names that almost always mean a listing was exposed by
/// accident. Deliberately narrow: public keys, `.pem` bundles and dataset SQL
/// dumps (e.g. Wikimedia) are normal on legitimate mirrors.
static SENSITIVE_NAMES: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)^\.env(\.[\w.-]+)?$",
        r"^id_(rsa|dsa|ecdsa|ed25519)$",
        r"(?i)^\.(git|svn|hg|ssh|aws|gnupg|bash_history|zsh_history|htpasswd)$",
        r"(?i)^wp-config\.php",
        r"(?i)\.(kdbx|pst|ost|ppk)$",
        r"(?i)^wallet\.dat$",
        r"(?i)(backup|dump|database|mysql|db)[^/]*\.sql(\.(gz|bz2|xz|zip|7z))?$",
        r"(?i)^(passport|payroll|tax[-_ ]?return|bank[-_ ]?statement)",
    ])
    .unwrap()
});

/// Listing paths that expose a home directory or the filesystem root.
static SENSITIVE_PATHS: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new([r"^/home/[^/]+/", r"^/root/", r"^/Users/[^/]+/"]).unwrap());

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

pub fn is_sensitive_name(name: &str) -> bool {
    SENSITIVE_NAMES.is_match(name)
}

/// `path` is a URL path, still percent-encoded.
pub fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.is_match(path)
}

pub fn is_likely_infringing(name: &str) -> bool {
    LIKELY_INFRINGING.is_match(name)
}

/// Reads a list file: one item per line, `#` starts a comment. A missing file
/// is an empty list.
pub fn load_list(path: &Path) -> anyhow::Result<Vec<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    };
    Ok(text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
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
