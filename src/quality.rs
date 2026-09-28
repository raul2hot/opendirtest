//! What makes a site worth keeping.
//!
//! Most open directories a web crawl finds are website internals: image and
//! upload folders, log folders, half-empty test folders. A site is kept if it
//! holds real downloads, meaning either a few big files or a fair number of
//! files of a useful kind (disk images, archives, documents, audio, video, data).
//!
//! Sites you add yourself (seeds) are trusted and never judged.

/// A file this size or bigger counts as "big" (10 MiB).
pub const BIG_FILE: u64 = 10 * 1024 * 1024;

/// A first-time site is judged early, without waiting for a large site to
/// finish, once it has been crawled for this many folders...
pub const PROBE_DIRS: u64 = 100;

/// ...and only if at least this many files have been seen. A big archive's top
/// folders hold no files at all (the disk images are four levels down), so a
/// site with few files so far is not judged until it is finished.
pub const MIN_EVIDENCE: u64 = 100;

/// Extensions (lower case, without the dot) of files people go looking for.
/// Web page assets (html, php, js, css, jpg, png, gif, ...) are left out on
/// purpose: a site made of them is a website, not an archive.
const USEFUL_EXTENSIONS: &[&str] = &[
    // archives and disk images
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzma", "iso", "img", "dmg",
    "vhd", "vhdx", "vmdk", "qcow2", "wim", "squashfs", // installers and packages
    "exe", "msi", "deb", "rpm", "apk", "appimage", "pkg", "whl", // documents and books
    "pdf", "epub", "mobi", "azw3", "djvu", "cbz", "cbr", "doc", "docx", "odt", "ppt", "pptx",
    "tex", // audio
    "mp3", "flac", "ogg", "opus", "wav", "m4a", "aac", "wma", "ape", "mid", "midi",
    // video
    "mp4", "mkv", "webm", "avi", "mov", "wmv", "flv", "mpg", "mpeg", "m4v", "vob", "ogv",
    // data
    "csv", "tsv", "json", "parquet", "sqlite", "sqlite3", "nc", "h5", "hdf5", "fits", "grib",
    "grib2", "shp", "kml", "kmz", "gpx", "geojson", "pbf", "xls", "xlsx", "mat", "rdata", "npy",
    "npz", "arrow", // large images and scans
    "tif", "tiff", "psd", "cr2", "nef", "arw", "dng", "raw", "svs", "torrent",
];

/// The extension of a file name, lower case: `Disk.ISO` -> `iso`, `a.tar.gz` -> `gz`.
pub fn extension(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty() && ext.len() <= 10).then(|| ext.to_ascii_lowercase())
}

/// True if the file is of a kind people go looking for.
pub fn is_useful(name: &str) -> bool {
    extension(name).is_some_and(|ext| USEFUL_EXTENSIONS.contains(&ext.as_str()))
}

/// What a site holds, counted over its files (not folders).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub files: u64,
    /// Files of `BIG_FILE` bytes or more.
    pub big: u64,
    /// Files of a useful kind.
    pub useful: u64,
}

impl Counts {
    pub fn add(&mut self, name: &str, size: Option<u64>) {
        self.files += 1;
        self.big += u64::from(size.is_some_and(|s| s >= BIG_FILE));
        self.useful += u64::from(is_useful(name));
    }
}

/// When a site holds enough to be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// Keep a site with at least this many big files...
    pub min_big: u64,
    /// ...or at least this many useful files.
    pub min_useful: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            min_big: 3,
            min_useful: 20,
        }
    }
}

impl Thresholds {
    /// Keep every site.
    pub const OFF: Thresholds = Thresholds {
        min_big: 0,
        min_useful: 0,
    };

    pub fn enabled(&self) -> bool {
        *self != Self::OFF
    }

    /// `Some(reason)` if the site holds too little to be kept. A site that is
    /// not `finished` is only judged once `MIN_EVIDENCE` files have been seen.
    pub fn judge(&self, counts: &Counts, finished: bool) -> Option<String> {
        if !finished && counts.files < MIN_EVIDENCE {
            return None;
        }
        if counts.big >= self.min_big || counts.useful >= self.min_useful {
            return None;
        }
        Some(format!(
            "nothing worth keeping: {} big files (need {}) and {} useful files (need {}) among {} files",
            counts.big, self.min_big, counts.useful, self.min_useful, counts.files
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions() {
        assert_eq!(extension("Disk.ISO").as_deref(), Some("iso"));
        assert_eq!(extension("a.tar.gz").as_deref(), Some("gz"));
        assert_eq!(extension("README"), None);
        assert_eq!(extension(".env"), None);
        assert_eq!(extension("archive."), None);
        assert!(is_useful("ubuntu-24.04-desktop-amd64.iso"));
        assert!(is_useful("Lecture 03.PDF"));
        assert!(is_useful("song.flac"));
        assert!(!is_useful("index.html"));
        assert!(!is_useful("photo-150x150.jpg"));
        assert!(!is_useful("style.css"));
        assert!(!is_useful("error_log"));
    }

    #[test]
    fn websites_are_judged_low_and_archives_high() {
        let t = Thresholds::default();

        // A WordPress uploads folder: thumbnails and pages.
        let mut site = Counts::default();
        for i in 0..500 {
            site.add(&format!("photo-{i}-150x150.jpg"), Some(9_000));
            site.add(&format!("photo-{i}.jpg"), Some(2_000_000));
        }
        site.add("index.php", Some(28));
        assert!(t.judge(&site, true).is_some());

        // A few big files: a small software archive.
        let mut isos = Counts::default();
        for v in ["a", "b", "c"] {
            isos.add(&format!("{v}.iso"), Some(4_000_000_000));
        }
        assert_eq!(t.judge(&isos, true), None);

        // Many documents, none big: a paper archive.
        let mut papers = Counts::default();
        for i in 0..20 {
            papers.add(&format!("paper-{i}.pdf"), Some(400_000));
        }
        assert_eq!(t.judge(&papers, true), None);
        papers.useful = 19;
        assert!(t.judge(&papers, true).is_some());

        // An unfinished site with few files so far is not judged yet: its top
        // folders may simply not hold any files.
        let few = Counts {
            files: 40,
            big: 0,
            useful: 0,
        };
        assert_eq!(t.judge(&few, false), None);
        assert!(t.judge(&few, true).is_some());
        let many = Counts { files: 400, ..few };
        assert!(t.judge(&many, false).is_some());

        // Turned off: everything is kept.
        assert!(!Thresholds::OFF.enabled());
        assert_eq!(Thresholds::OFF.judge(&Counts::default(), true), None);
    }
}
