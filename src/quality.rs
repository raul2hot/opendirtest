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

/// ...and only if at least this many files have been seen in folders that hold
/// no sub-folders. A big archive's top folders hold README and index files, and
/// the disk images are further down, so a crawl that is still near the top
/// says nothing yet. Files in folders that do have sub-folders are not counted
/// for an unfinished site.
pub const MIN_EVIDENCE: u64 = 100;

/// Extensions (lower case, without the dot) of files people go looking for.
/// Web page assets (html, php, js, css, jpg, png, gif, ...) are left out on
/// purpose: a site made of them is a website, not an archive.
const USEFUL_EXTENSIONS: &[&str] = &[
    // archives and disk images
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzma", "iso", "img", "dmg",
    "vhd", "vhdx", "vmdk", "qcow2", "wim", "squashfs", // installers and packages
    "exe", "msi", "deb", "rpm", "apk", "appimage", "pkg", "whl", "bin",
    // older archive formats, common on software collections
    "z", "lzh", "lha", "cab", "sit", "arj", "zoo", // documents and books
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

/// Text and data formats that only count when the file is big enough to be a
/// real book or dataset: a website's `readme.txt` or `sitemap.xml` is not one.
const TEXT_EXTENSIONS: &[&str] = &["txt", "dat", "xml", "rtf", "ps"];

/// The size from which a text file counts as useful (100 KiB).
pub const TEXT_FILE_MIN: u64 = 100 * 1024;

/// The extension of a file name, lower case: `Disk.ISO` -> `iso`, `a.tar.gz` -> `gz`.
pub fn extension(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty() && ext.len() <= 10).then(|| ext.to_ascii_lowercase())
}

/// True if the file is of a kind people go looking for.
pub fn is_useful(name: &str, size: Option<u64>) -> bool {
    let Some(ext) = extension(name) else {
        return false;
    };
    let ext = ext.as_str();
    USEFUL_EXTENSIONS.contains(&ext)
        || (TEXT_EXTENSIONS.contains(&ext) && size.is_some_and(|s| s >= TEXT_FILE_MIN))
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
        self.useful += u64::from(is_useful(name, size));
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

    /// `Some(reason)` if the site holds too little to be kept.
    ///
    /// A finished site is judged by the thresholds. A site that is not finished
    /// is only dropped when what it holds so far is plainly junk: at least
    /// `MIN_EVIDENCE` files (counted in folders without sub-folders), nothing
    /// big, and under 5% useful files. Closer to the thresholds it may still
    /// get there, so it is left for the verdict at the end.
    pub fn judge(&self, counts: &Counts, finished: bool) -> Option<String> {
        if !finished
            && (counts.files < MIN_EVIDENCE || counts.big > 0 || counts.useful * 20 >= counts.files)
        {
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
        assert!(is_useful("ubuntu-24.04-desktop-amd64.iso", None));
        assert!(is_useful("Lecture 03.PDF", None));
        assert!(is_useful("song.flac", None));
        assert!(is_useful("old-tool.lzh", None));
        assert!(!is_useful("index.html", None));
        assert!(!is_useful("photo-150x150.jpg", Some(9_000)));
        assert!(!is_useful("style.css", None));
        assert!(!is_useful("error_log", None));
    }

    #[test]
    fn text_files_count_only_when_they_are_big() {
        // A book or a dataset, not a website's readme.
        assert!(is_useful("moby-dick.txt", Some(1_200_000)));
        assert!(is_useful("stations.dat", Some(5_000_000)));
        assert!(!is_useful("readme.txt", Some(900)));
        assert!(!is_useful("sitemap.xml", Some(30_000)));
        assert!(!is_useful("notes.txt", None));
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
        // Plainly junk so far: plenty of files, nothing big, almost nothing useful.
        let many = Counts { files: 400, ..few };
        assert!(t.judge(&many, false).is_some());
        // Not plainly junk: any big file, or a fair share of useful ones, waits
        // for the verdict at the end, even if it is under the absolute thresholds.
        let one_big = Counts { big: 1, ..many };
        assert_eq!(t.judge(&one_big, false), None);
        let some_useful = Counts {
            files: 300,
            big: 0,
            useful: 19,
        };
        assert_eq!(t.judge(&some_useful, false), None);
        assert!(t.judge(&some_useful, true).is_some());
        // Under 5% useful is plainly junk even when a few files are useful.
        let few_useful = Counts {
            files: 400,
            big: 0,
            useful: 19,
        };
        assert!(t.judge(&few_useful, false).is_some());

        // Turned off: everything is kept.
        assert!(!Thresholds::OFF.enabled());
        assert_eq!(Thresholds::OFF.judge(&Counts::default(), true), None);
    }
}
