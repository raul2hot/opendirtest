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

/// ...and only if at least this many files have been seen in leaf folders (folders
/// with nothing below them to crawl). A big archive's top folders hold README and
/// index files, and the disk images are further down, so a crawl that is still
/// near the top says nothing yet. Files in folders that do have sub-folders are not
/// counted for a site that is still being crawled.
pub const MIN_EVIDENCE: u64 = 100;

/// A verdict on a site still being crawled needs leaf folders from at least this
/// many different places, so that the first few folders cannot decide.
pub const MIN_SAMPLE_FOLDERS: u64 = 20;

/// This many files in leaf folders, none big and none useful, is junk whatever is
/// left to crawl. It bounds what a big junk site can cost: below it, a sample that
/// the rest of the site could contradict decides nothing.
pub const HARD_EVIDENCE: u64 = 2_000;

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

/// How far the files counted for a site can be trusted to speak for all of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sample {
    /// Everything the site has, at the end of a crawl that finished.
    Final,
    /// What is known of a site that will not be crawled again (it gave up, or is
    /// gone), or a sample of one still being crawled that is as large as what is
    /// left and reaches as deep: dropped only when plainly junk.
    Representative,
    /// A sample of a site still being crawled that what is left could contradict:
    /// only overwhelming evidence counts.
    Partial,
}

/// How much to trust the leaf folders seen so far on a site that is still being
/// crawled, given the folders still waiting. `None` if there are too few to say
/// anything. The crawler (in memory) and the database (after a run) both ask
/// this, so they agree.
///
/// The sample must have leaves as deep as the deepest folder still waiting (small
/// pages in shallow folders say nothing about downloads deeper down), and be at
/// least as large as what waits (siblings not looked at yet can differ).
pub fn sample(
    leaf_folders: u64,
    deepest_leaf: Option<usize>,
    waiting: u64,
    deepest_waiting: Option<usize>,
) -> Option<Sample> {
    let deepest_leaf = deepest_leaf?;
    if leaf_folders < MIN_SAMPLE_FOLDERS {
        return None;
    }
    let reaches_as_deep = deepest_waiting.is_none_or(|waiting| waiting <= deepest_leaf);
    Some(if reaches_as_deep && waiting <= leaf_folders {
        Sample::Representative
    } else {
        Sample::Partial
    })
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
    /// A finished site is judged by the thresholds. Anything else is only dropped
    /// when what it holds is plainly junk: nothing big, and either under 5% useful
    /// files among at least `MIN_EVIDENCE` (if the sample is representative), or no
    /// useful file at all among `HARD_EVIDENCE`. Closer to the thresholds it may
    /// still get there, so it is left for the verdict at the end.
    pub fn judge(&self, counts: &Counts, sample: Sample) -> Option<String> {
        if counts.big >= self.min_big || counts.useful >= self.min_useful {
            return None;
        }
        let overwhelming = counts.files >= HARD_EVIDENCE && counts.big == 0 && counts.useful == 0;
        let plainly_junk =
            counts.files >= MIN_EVIDENCE && counts.big == 0 && counts.useful * 20 < counts.files;
        let junk = match sample {
            Sample::Final => true,
            Sample::Representative => plainly_junk || overwhelming,
            Sample::Partial => overwhelming,
        };
        junk.then(|| {
            format!(
                "nothing worth keeping: {} big files (need {}) and {} useful files (need {}) among {} files",
                counts.big, self.min_big, counts.useful, self.min_useful, counts.files
            )
        })
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
        assert!(t.judge(&site, Sample::Final).is_some());

        // A few big files: a small software archive.
        let mut isos = Counts::default();
        for v in ["a", "b", "c"] {
            isos.add(&format!("{v}.iso"), Some(4_000_000_000));
        }
        assert_eq!(t.judge(&isos, Sample::Final), None);

        // Many documents, none big: a paper archive.
        let mut papers = Counts::default();
        for i in 0..20 {
            papers.add(&format!("paper-{i}.pdf"), Some(400_000));
        }
        assert_eq!(t.judge(&papers, Sample::Final), None);
        papers.useful = 19;
        assert!(t.judge(&papers, Sample::Final).is_some());

        // An unfinished site with few files so far is not judged yet: its top
        // folders may simply not hold any files.
        let few = Counts {
            files: 40,
            big: 0,
            useful: 0,
        };
        assert_eq!(t.judge(&few, Sample::Representative), None);
        assert!(t.judge(&few, Sample::Final).is_some());
        // Plainly junk so far: plenty of files, nothing big, almost nothing useful.
        let many = Counts { files: 400, ..few };
        assert!(t.judge(&many, Sample::Representative).is_some());
        // Not plainly junk: any big file, or a fair share of useful ones, waits
        // for the verdict at the end, even if it is under the absolute thresholds.
        let one_big = Counts { big: 1, ..many };
        assert_eq!(t.judge(&one_big, Sample::Representative), None);
        let some_useful = Counts {
            files: 300,
            big: 0,
            useful: 19,
        };
        assert_eq!(t.judge(&some_useful, Sample::Representative), None);
        assert!(t.judge(&some_useful, Sample::Final).is_some());
        // Under 5% useful is plainly junk even when a few files are useful.
        let few_useful = Counts {
            files: 400,
            big: 0,
            useful: 19,
        };
        assert!(t.judge(&few_useful, Sample::Representative).is_some());

        // Turned off: everything is kept.
        assert!(!Thresholds::OFF.enabled());
        assert_eq!(
            Thresholds::OFF.judge(&Counts::default(), Sample::Final),
            None
        );
    }

    #[test]
    fn a_partial_sample_only_condemns_overwhelming_junk() {
        let t = Thresholds::default();
        // Plainly junk, but only a part of a site that has more to show.
        let plain = Counts {
            files: 400,
            big: 0,
            useful: 0,
        };
        assert!(t.judge(&plain, Sample::Representative).is_some());
        assert_eq!(t.judge(&plain, Sample::Partial), None);
        // Thousands of files, nothing big and nothing useful: junk whatever is left.
        let overwhelming = Counts {
            files: HARD_EVIDENCE,
            big: 0,
            useful: 0,
        };
        assert!(t.judge(&overwhelming, Sample::Partial).is_some());
        // One useful file among them, or one big one, and it waits for the end.
        let one_useful = Counts {
            useful: 1,
            ..overwhelming
        };
        assert_eq!(t.judge(&one_useful, Sample::Partial), None);
        let one_big = Counts {
            big: 1,
            ..overwhelming
        };
        assert_eq!(t.judge(&one_big, Sample::Partial), None);
        assert_eq!(t.judge(&one_big, Sample::Representative), None);
        // Turned off: kept whatever the sample says.
        assert_eq!(Thresholds::OFF.judge(&overwhelming, Sample::Partial), None);
    }

    #[test]
    fn a_sample_is_representative_when_it_is_as_big_and_as_deep_as_what_waits() {
        use Sample::{Partial, Representative};
        // Too few leaf folders, or none: nothing to say.
        assert_eq!(sample(MIN_SAMPLE_FOLDERS - 1, Some(2), 0, None), None);
        assert_eq!(sample(0, None, 5, Some(1)), None);
        assert_eq!(sample(50, None, 5, Some(1)), None);
        // Nothing waits: the sample is all there is.
        assert_eq!(sample(30, Some(2), 0, None), Some(Representative));
        // Waiting folders no deeper than the deepest leaf, and no more of them.
        assert_eq!(sample(30, Some(2), 30, Some(2)), Some(Representative));
        assert_eq!(sample(30, Some(3), 10, Some(1)), Some(Representative));
        // More waiting than sampled: siblings not seen yet may differ.
        assert_eq!(sample(30, Some(2), 31, Some(2)), Some(Partial));
        // A waiting folder deeper than every leaf seen.
        assert_eq!(sample(300, Some(2), 1, Some(3)), Some(Partial));
    }
}
