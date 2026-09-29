//! What makes a site worth keeping.
//!
//! Most open directories a web crawl finds are website internals: image and
//! upload folders, log folders, half-empty test folders. A site is kept if it
//! holds real downloads, meaning either a few big files or a fair number of
//! files of a useful kind (disk images, archives, documents, audio, video, data).
//!
//! Sites you add yourself (seeds) are trusted and never judged.
//!
//! A site is judged three ways. When its crawl is over it is judged by the
//! thresholds (`judge_final`). One that gave up or is gone is judged only when
//! plainly junk (`judge_ended`). A site still being crawled is judged early only
//! on strong, fair evidence (`judge_crawling`), because what has been read so far
//! is the top of the tree and the folders that happened to come first.

/// A file this size or bigger counts as "big" (10 MiB).
pub const BIG_FILE: u64 = 10 * 1024 * 1024;

/// A site is judged early, without waiting for a large site to finish, once it has
/// been crawled for this many folders...
pub const PROBE_DIRS: u64 = 100;

/// ...and only if at least this many files have been seen in the leaf folders of
/// its deepest level (leaf folders: folders with nothing below them to crawl). A
/// big archive's top folders hold README and index files, and the disk images are
/// further down, so a crawl that is still near the top says nothing yet.
pub const MIN_EVIDENCE: u64 = 100;

/// A verdict on a site still being crawled needs leaf folders from at least this
/// many different places at that level, so that the first few cannot decide.
pub const MIN_SAMPLE_FOLDERS: u64 = 20;

/// A site still being crawled that has had this many folders read, and holds fewer
/// than 1% useful files and nothing big, is junk whatever is left to crawl. This
/// bounds what a crawler trap or a huge website can cost.
pub const HARD_FOLDERS: u64 = 2_000;

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

/// Compression formats that also wrap rotated log files.
const COMPRESSED: &[&str] = &["gz", "bz2", "xz", "zst", "lz", "lzma"];

/// True for a rotated, compressed log: `access.log.3.gz`, `error_log-20260101.gz`.
fn is_rotated_log(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some((stem, ext)) = lower.rsplit_once('.') else {
        return false;
    };
    if !COMPRESSED.contains(&ext) {
        return false;
    }
    // Drop rotation numbers and dates: `access.log.3` -> `access.log`.
    let mut stem = stem;
    while let Some(cut) = stem.rfind(['.', '-', '_']) {
        let (head, tail) = stem.split_at(cut);
        let tail = &tail[1..];
        if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        stem = head;
    }
    stem == "log" || stem.ends_with(".log") || stem.ends_with("_log") || stem.ends_with("-log")
}

/// True if the file is of a kind people go looking for.
pub fn is_useful(name: &str, size: Option<u64>) -> bool {
    let Some(ext) = extension(name) else {
        return false;
    };
    let ext = ext.as_str();
    if COMPRESSED.contains(&ext) && is_rotated_log(name) {
        return false;
    }
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

/// What has been read of a site that is still being crawled. The crawler keeps it
/// in memory and the database keeps the same numbers, so that both reach the same
/// verdict.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Progress {
    /// How many folders deep the deepest leaf folder read so far is, how many leaf
    /// folders are at that level, and how many files they hold. Junk is judged on
    /// these: downloads hide in the deepest layers of a tree, which come last, and
    /// the shallower layers are documentation and images.
    pub level: Option<usize>,
    pub level_folders: u64,
    pub level_files: u64,
    /// Every file read, in any folder, and how many of them are big or useful. One
    /// download anywhere is a sign of value, whatever folder it is in.
    pub all_files: u64,
    pub big: u64,
    pub useful: u64,
    /// Every folder read.
    pub folders_read: u64,
}

impl Progress {
    /// Notes one file that was read.
    pub fn note_file(&mut self, name: &str, size: Option<u64>) {
        self.all_files += 1;
        self.big += u64::from(size.is_some_and(|s| s >= BIG_FILE));
        self.useful += u64::from(is_useful(name, size));
    }

    /// Notes a leaf folder `depth` folders deep that holds `files` files.
    pub fn note_leaf(&mut self, depth: usize, files: u64) {
        match self.level {
            Some(level) if depth < level => {}
            Some(level) if depth == level => {
                self.level_folders += 1;
                self.level_files += files;
            }
            _ => {
                self.level = Some(depth);
                self.level_folders = 1;
                self.level_files = files;
            }
        }
    }
}

/// The folders of a site that are still waiting to be crawled.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Waiting {
    /// How many of them are at the level of the deepest leaf folders read.
    pub at_level: u64,
    /// How deep the deepest of them is.
    pub deepest: Option<usize>,
}

impl Progress {
    /// True if the leaf folders read at the deepest level speak for the rest of the
    /// site: there are enough of them, nothing waits deeper than they are (small
    /// pages in shallow folders say nothing about downloads further down), and no
    /// more of their siblings wait than were read (siblings not looked at yet can
    /// differ).
    pub fn is_fair(&self, waiting: &Waiting) -> bool {
        self.level.is_some_and(|level| {
            self.level_folders >= MIN_SAMPLE_FOLDERS
                && waiting.deepest.is_none_or(|deepest| deepest <= level)
                && waiting.at_level <= self.level_folders
        })
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

    fn reason(&self, files: u64, big: u64, useful: u64) -> String {
        format!(
            "nothing worth keeping: {big} big files (need {}) and {useful} useful files (need {}) among {files} files",
            self.min_big, self.min_useful
        )
    }

    /// `Some(reason)` if a site whose crawl is over holds too little to be kept.
    pub fn judge_final(&self, counts: &Counts) -> Option<String> {
        if counts.big >= self.min_big || counts.useful >= self.min_useful {
            return None;
        }
        Some(self.reason(counts.files, counts.big, counts.useful))
    }

    /// The same for a site that will not be crawled again but was not finished (it
    /// gave up after errors, or is gone): what it holds is all there is to go by,
    /// but the rest is unknown, so it is only dropped when plainly junk: at least
    /// `MIN_EVIDENCE` files, nothing big, and under 5% useful.
    pub fn judge_ended(&self, counts: &Counts) -> Option<String> {
        if counts.big >= self.min_big || counts.useful >= self.min_useful {
            return None;
        }
        let plainly_junk =
            counts.files >= MIN_EVIDENCE && counts.big == 0 && counts.useful * 20 < counts.files;
        plainly_junk.then(|| self.reason(counts.files, counts.big, counts.useful))
    }

    /// `Some(reason)` if a site that is still being crawled is junk beyond doubt.
    ///
    /// Either the leaf folders at its deepest level are a fair sample (see
    /// `Progress::is_fair`) with at least `MIN_EVIDENCE` files, nothing big anywhere
    /// and under 5% useful files anywhere; or `HARD_FOLDERS` folders have been read
    /// and there is nothing big and under 1% useful. Anything closer to the
    /// thresholds waits for the verdict at the end.
    ///
    /// `waiting` says what still waits; it is only asked for when the rest of the
    /// numbers could condemn the site, since it costs a look at the queue.
    pub fn judge_crawling(
        &self,
        p: &Progress,
        waiting: impl FnOnce() -> Waiting,
    ) -> Option<String> {
        // Anything big, or enough useful files, and the site is worth keeping (and
        // with the thresholds off, everything is).
        let kept = p.big >= self.min_big || p.useful >= self.min_useful;
        if kept || p.big > 0 {
            return None;
        }
        let fair_junk = p.level_files >= MIN_EVIDENCE
            && p.useful * 20 < p.level_files
            && p.level_folders >= MIN_SAMPLE_FOLDERS
            && p.is_fair(&waiting());
        let endless = p.folders_read >= HARD_FOLDERS
            && p.all_files >= MIN_EVIDENCE
            && p.useful * 100 < p.all_files;
        (fair_junk || endless).then(|| self.reason(p.all_files, p.big, p.useful))
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
    fn rotated_logs_are_not_archives() {
        for log in [
            "access.log.3.gz",
            "error_log-20260101.gz",
            "Access.LOG.12.GZ",
            "nginx.log.1.xz",
            "app-log.7.bz2",
            "log.2.gz",
        ] {
            assert!(!is_useful(log, Some(40_000_000)), "{log}");
        }
        for archive in [
            "catalog.tar.gz",
            "dialog-1.0.tgz",
            "backup-2026.tar.gz",
            "logo.svg.gz",
            "data.csv.gz",
            "blog.tar.xz",
            "package-1.2.tar.gz",
        ] {
            assert!(is_useful(archive, Some(5_000_000)), "{archive}");
        }
    }

    fn counts(files: u64, big: u64, useful: u64) -> Counts {
        Counts { files, big, useful }
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
        assert!(t.judge_final(&site).is_some());

        // A few big files: a small software archive.
        let mut isos = Counts::default();
        for v in ["a", "b", "c"] {
            isos.add(&format!("{v}.iso"), Some(4_000_000_000));
        }
        assert_eq!(t.judge_final(&isos), None);

        // Many documents, none big: a paper archive.
        let mut papers = Counts::default();
        for i in 0..20 {
            papers.add(&format!("paper-{i}.pdf"), Some(400_000));
        }
        assert_eq!(t.judge_final(&papers), None);
        papers.useful = 19;
        assert!(t.judge_final(&papers).is_some());

        // Turned off: everything is kept.
        assert!(!Thresholds::OFF.enabled());
        assert_eq!(Thresholds::OFF.judge_final(&Counts::default()), None);
        assert_eq!(Thresholds::OFF.judge_ended(&counts(9_999, 0, 0)), None);
    }

    #[test]
    fn a_site_that_will_not_be_crawled_again_is_dropped_only_when_plainly_junk() {
        let t = Thresholds::default();
        // Few files so far: its top folders may simply not hold any.
        assert_eq!(t.judge_ended(&counts(40, 0, 0)), None);
        // Plenty of files, nothing big, almost nothing useful.
        assert!(t.judge_ended(&counts(400, 0, 0)).is_some());
        assert!(t.judge_ended(&counts(400, 0, 19)).is_some());
        // 5% useful or more, any big file, or enough useful files: not plainly junk.
        assert_eq!(t.judge_ended(&counts(400, 0, 20)), None);
        assert_eq!(t.judge_ended(&counts(300, 0, 15)), None);
        assert_eq!(t.judge_ended(&counts(400, 1, 0)), None);
        assert_eq!(t.judge_ended(&counts(30_000, 3, 0)), None);
    }

    /// 30 leaf folders three levels down with 300 files, nothing waiting.
    fn junk_progress() -> Progress {
        Progress {
            level: Some(3),
            level_folders: 30,
            level_files: 300,
            all_files: 300,
            big: 0,
            useful: 0,
            folders_read: 130,
        }
    }

    fn waiting(at_level: u64, deepest: usize) -> Waiting {
        Waiting {
            at_level,
            deepest: Some(deepest),
        }
    }

    #[test]
    fn a_site_still_being_crawled_is_judged_only_on_a_fair_sample() {
        let t = Thresholds::default();
        let junk = junk_progress();
        // Fair: leaves as deep as anything waiting, as many read as wait.
        assert!(t.judge_crawling(&junk, || waiting(30, 3)).is_some());
        assert!(t.judge_crawling(&junk, Waiting::default).is_some());
        // Something waits deeper than the leaves: small pages in shallow folders say
        // nothing about downloads further down.
        assert_eq!(t.judge_crawling(&junk, || waiting(0, 4)), None);
        // More siblings wait than were read: they may differ.
        assert_eq!(t.judge_crawling(&junk, || waiting(31, 3)), None);
        // Too few places, or too few files.
        let few_places = Progress {
            level_folders: MIN_SAMPLE_FOLDERS - 1,
            ..junk_progress()
        };
        assert_eq!(t.judge_crawling(&few_places, Waiting::default), None);
        let few_files = Progress {
            level_files: MIN_EVIDENCE - 1,
            ..junk_progress()
        };
        assert_eq!(t.judge_crawling(&few_files, Waiting::default), None);
        assert_eq!(
            t.judge_crawling(&Progress::default(), Waiting::default),
            None
        );
    }

    #[test]
    fn value_in_any_folder_keeps_a_site_that_is_still_being_crawled() {
        let t = Thresholds::default();
        let none = Waiting::default();
        // The downloads are in the folders above the leaves (books next to an
        // images/ folder): the leaves alone look like junk, the site does not.
        let books = Progress {
            all_files: 2_500,
            useful: 1_200,
            ..junk_progress()
        };
        assert_eq!(t.judge_crawling(&books, || none), None);
        // A few useful files among thousands of images is still junk...
        let stray = Progress {
            useful: 5,
            all_files: 5_000,
            level_files: 4_000,
            ..junk_progress()
        };
        assert!(t.judge_crawling(&stray, || none).is_some());
        // ...but not when they are 5% of the leaf files, or when one file is big.
        let some = Progress {
            useful: 15,
            ..junk_progress()
        };
        assert_eq!(t.judge_crawling(&some, || none), None);
        let big = Progress {
            big: 1,
            ..junk_progress()
        };
        assert_eq!(t.judge_crawling(&big, || none), None);
        // Enough useful files anywhere, and the thresholds are met.
        let enough = Progress {
            useful: 20,
            ..junk_progress()
        };
        assert_eq!(t.judge_crawling(&enough, || none), None);
    }

    #[test]
    fn a_site_that_has_cost_thousands_of_folders_for_nothing_is_junk_whatever_waits() {
        let t = Thresholds::default();
        // A trap: every folder holds a few junk files and there is always a deeper
        // one waiting, so no sample is ever fair.
        let trap = Progress {
            level: Some(30),
            level_folders: 5,
            level_files: 25,
            all_files: 15_000,
            folders_read: HARD_FOLDERS,
            ..Progress::default()
        };
        let deeper = waiting(1, 31);
        assert!(t.judge_crawling(&trap, || deeper).is_some());
        // Not yet.
        let early = Progress {
            folders_read: HARD_FOLDERS - 1,
            ..trap.clone()
        };
        assert_eq!(t.judge_crawling(&early, || deeper), None);
        // A little value (under 1%) does not save it; 1% or more does.
        let stray = Progress {
            useful: 14,
            ..trap.clone()
        };
        assert!(t.judge_crawling(&stray, || deeper).is_some());
        let some = Progress {
            useful: 16,
            all_files: 1_500,
            ..trap.clone()
        };
        assert_eq!(t.judge_crawling(&some, || deeper), None);
        // Turned off: kept whatever it costs.
        assert_eq!(Thresholds::OFF.judge_crawling(&trap, || deeper), None);
    }

    #[test]
    fn progress_follows_the_deepest_leaf_level() {
        let mut p = Progress::default();
        p.note_leaf(2, 10);
        p.note_leaf(2, 5);
        assert_eq!((p.level, p.level_folders, p.level_files), (Some(2), 2, 15));
        // A deeper level replaces it: that is where the downloads come last.
        p.note_leaf(3, 4);
        assert_eq!((p.level, p.level_folders, p.level_files), (Some(3), 1, 4));
        // A shallower one no longer counts.
        p.note_leaf(1, 99);
        assert_eq!((p.level, p.level_folders, p.level_files), (Some(3), 1, 4));
        p.note_leaf(3, 6);
        assert_eq!((p.level, p.level_folders, p.level_files), (Some(3), 2, 10));
        // Value is counted in every folder.
        p.note_file("a.iso", Some(4_000_000_000));
        p.note_file("photo.jpg", Some(9_000));
        assert_eq!((p.all_files, p.big, p.useful), (2, 1, 1));
    }
}
