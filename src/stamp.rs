//! One generation of a file as a stat sees it ([`FileStamp`]), and how often a live reader may stat
//! ([`STAT_DEBOUNCE`]).
//!
//! A long-running process that honors a file another process writes (a denylist, a set of disabled
//! roots, a pin) cannot re-read it on every check, and cannot wait for a restart either. It stats the
//! file at most once per [`STAT_DEBOUNCE`], and re-reads only when the stamp differs from the one it read
//! at. Both [`FileDenylist`](crate::FileDenylist) and [`DisabledRoots`](crate::DisabledRoots) work this
//! way, and a store of its own can use the same pieces, deciding by [`FileStamp::unchanged`].
//!
//! The stamp decides only WHETHER to re-read. What a missing, unreadable or shorter file means is the
//! reader's own policy, and it differs between stores: a denylist keeps the last set it read, because a
//! deleted denylist must never un-revoke, while a store whose absence means "nothing is trusted" drops
//! what it held.

use core::time::Duration;
use std::time::SystemTime;

/// How long a live reader goes between stats of its file.
///
/// The admit hot path checks a store once per connection, but a change written by another process only
/// needs to be seen within a short window, so a reader stats at most once per this interval rather than
/// on every check. A change goes live within one interval. A test that writes a file and then expects a
/// running reader to see it waits past this.
pub const STAT_DEBOUNCE: Duration = Duration::from_millis(100);

/// One generation of a file as a stat sees it. A reader re-reads only when this changes.
///
/// It records the length and mtime, and on unix the inode and ctime. The length rides with the mtime so
/// a change inside one coarse mtime tick is still seen when it grows the file. The inode makes a
/// same-length replacement renamed into place visible however coarse the clock, and the ctime moves
/// when an mtime is set back by hand. What stays invisible is an in-place rewrite to the same length
/// inside one tick of a coarse filesystem.
///
/// [`of`](Self::of) returns `None` when the platform reports no mtime. A reader treats `None` as "re-read",
/// never as "unchanged": two `None`s say nothing about whether the file is the same one.
///
/// ```
/// # fn main() -> std::io::Result<()> {
/// let path = std::env::temp_dir().join(format!("nauthy-stamp-doc-{}", std::process::id()));
/// std::fs::write(&path, "one\n")?;
/// let before = nauthy::FileStamp::of(&std::fs::metadata(&path)?);
/// std::fs::write(&path, "one\ntwo\n")?;
/// let after = nauthy::FileStamp::of(&std::fs::metadata(&path)?);
/// assert_ne!(before, after);
/// # std::fs::remove_file(&path)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    mtime: SystemTime,
    pub(crate) len: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime: (i64, i64),
}

impl FileStamp {
    /// The stamp of `meta`, or `None` when the platform will not report an mtime.
    ///
    /// `None` is not a stamp to compare against: a reader holding it re-reads at its next stat.
    pub fn of(meta: &std::fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        #[cfg(test)]
        if NO_MTIME.with(core::cell::Cell::get) {
            return None;
        }
        Some(Self {
            mtime: meta.modified().ok()?,
            len: meta.len(),
            #[cfg(unix)]
            ino: meta.ino(),
            #[cfg(unix)]
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }

    /// This stamp with its length replaced by `len`: the bytes a writer knows it wrote, which a stat
    /// taken right after the write can under-report on some filesystems.
    #[cfg(feature = "tokio-fs")]
    pub(crate) fn with_len(self, len: u64) -> Self {
        Self { len, ..self }
    }

    /// Whether a reader that read its file at `held` may skip reading it again now that a stat says
    /// `seen`. Only two equal stamps may skip: a missing stamp on either side re-reads.
    ///
    /// A store of its own should decide by this rather than comparing the two `Option`s itself: `None ==
    /// None` would call a file with no mtime unchanged forever, and the reader would never see a change.
    ///
    /// ```
    /// # fn main() -> std::io::Result<()> {
    /// use nauthy::FileStamp;
    ///
    /// let path = std::env::temp_dir().join(format!("nauthy-unchanged-doc-{}", std::process::id()));
    /// std::fs::write(&path, "one\n")?;
    /// let held = FileStamp::of(&std::fs::metadata(&path)?);
    /// let seen = FileStamp::of(&std::fs::metadata(&path)?);
    /// assert!(FileStamp::unchanged(held, seen));
    /// assert!(!FileStamp::unchanged(None, None));
    /// # std::fs::remove_file(&path)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn unchanged(held: Option<Self>, seen: Option<Self>) -> bool {
        matches!((held, seen), (Some(held), Some(seen)) if held == seen)
    }

    /// This stamp with its ctime blanked, so a test can show the other fields tell two generations apart
    /// on their own.
    #[cfg(all(test, unix))]
    pub(crate) fn without_ctime(self) -> Self {
        Self {
            ctime: (0, 0),
            ..self
        }
    }

    /// The inode this stamp recorded.
    #[cfg(all(test, unix))]
    pub(crate) fn ino(self) -> u64 {
        self.ino
    }
}

#[cfg(test)]
thread_local! {
    /// Stamps taken on this thread report no mtime, as on a platform that has none, so a test can drive a
    /// reader down the `None` path no real stat here takes.
    pub(crate) static NO_MTIME: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}
