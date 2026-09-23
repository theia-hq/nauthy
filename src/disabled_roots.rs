//! Root-key disable: a file-backed set of authority keys this node no longer trusts ([`DisabledRoots`]),
//! and the [`Revocations`] oracle that refuses every cap rooted at one of them ([`Latch`]).
//!
//! A [`FileDenylist`](crate::FileDenylist) names grants by revocation id, so it can recall what an
//! authority already signed but never what it signs next. A lost root key keeps signing. Disabling it
//! has to refuse every cap it ever mints, past and future, so this store records the KEY, and the latch
//! asks it about [`Cap::root`]. That root is the one `Cap::parse` authenticated against the whole
//! signature chain, so a cap cannot claim its way past the check with a root it does not carry.
//!
//! The set is TERMINAL, and that is where it must differ from the denylist it sits beside. Everything it
//! observes is a union: a file rewritten shorter, replaced, corrupted, or deleted under a running process
//! never removes a key it has already read, and there is no method that removes one. Nothing on this
//! surface re-enables a root; recovery is a new root.
//!
//! The file is one key per line in the [`VerifyKey`] string form (`bf01...`), the same text a consumer
//! compares it against, so the latch and the authority it names speak one encoding. Its location is the
//! consuming process's to choose, as with the denylist.

use std::collections::HashSet;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use crate::cap::Cap;
use crate::key::{KeyParseError, VerifyKey};
use crate::revocations::{
    LockError, Revocations, WitnessError, WriteLock, check_witness, read_to_string,
    write_atomically,
};
use crate::stamp::{FileStamp, STAT_DEBOUNCE};

/// The largest latch file read, in bytes: room for some eighteen thousand keys. The file is read on the
/// admit hot path under the latch's lock, so a local writer that grows it without bound must not be able
/// to turn the next admission into an allocation that size. A larger file is refused at load and ignored
/// by a refresh, which keeps what it holds.
const MAX_LEN: u64 = 1 << 20;

/// The root keys this node has disabled, persisted one per line, read live, and only ever grown.
///
/// [`is_disabled`](Self::is_disabled) re-reads the file when its stamp changes (debounced, as the denylist
/// is), so a key disabled by another process takes effect on the next check of a long-running one without
/// a restart.
///
/// UNION ONLY. A refresh ADDS what it reads and never assigns. A stat or read failure, an oversized file,
/// or the file disappearing keeps every key already held. The denylist's refresh replaces its set, which
/// is right for ids an issuer may legitimately prune and wrong here, where a shorter file is either a
/// mistake or an attack and must not revive a root either way.
///
/// A LINE THAT IS NOT A KEY DOES NOT HIDE THE ONES THAT ARE. A running latch adds every valid line of a
/// partly malformed file and reports the first bad line through
/// [`malformed_line`](Self::malformed_line), so a typo, a torn append, or a key form this version cannot
/// read never freezes it at the set it held before. [`load`](Self::load) still refuses a malformed file:
/// a process starting on a set it can only partly read is the case a human should see.
///
/// A STARTING process is held to the same law by the `<path>.written` witness, the high-water count of
/// keys a durable [`disable`](Self::disable) left in the file: [`load`](Self::load) refuses a file
/// holding fewer, absent included, with [`Lost`](DisabledRootsError::Lost). Three ways out, in order:
/// restore the file; re-apply every disable through [`open_for_repair`](Self::open_for_repair), which
/// clears it only once the file is back at the mark; or `rm <path>.written`, which trusts again every root
/// the file lost and asserts that nothing was disabled. Never remove `<path>.lock`: writers serialize on
/// it, and it says nothing about what was written.
///
/// THE LIMIT, NAMED AND NOT CLOSED: a process that starts after the file and its witness are both gone
/// loads an empty set and trusts every root again, because that cannot be told apart from a node that
/// never disabled anything. The boundary is the DIRECTORY, not the file: anyone who can write the parent
/// can unlink both whatever the file's mode, so keep them in a directory only the node's own user can
/// write, on durable storage. A file last written before the witness existed has none, and is held to
/// this only from its next disable.
///
/// Persisting needs a cross-process lock that only unix has at the crate's minimum Rust version, so
/// elsewhere [`disable`](Self::disable) refuses and a root is disabled in memory only.
pub struct DisabledRoots {
    path: PathBuf,
    state: Mutex<State>,
}

/// The keys held, the stamp of the file they were last read at, the last moment the file was
/// stat'd, and the first line of the last read that was not a key.
struct State {
    roots: HashSet<VerifyKey>,
    stamp: Option<FileStamp>,
    last_stat: Option<Instant>,
    malformed: Option<u32>,
}

impl DisabledRoots {
    /// Load the disabled roots from `path`. The keys and the stamp come from one opened handle, so a file
    /// replaced during the load cannot stamp the old keys as current.
    ///
    /// An absent file is an empty set, unless its witness says a durable write left keys there: a file
    /// holding fewer keys than that, absent included, is [`Lost`](DisabledRootsError::Lost), since no
    /// write shrinks it. A malformed or oversized file is an error too, so a caller never starts on a latch
    /// it could not read.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub async fn load(path: PathBuf) -> Result<Self, DisabledRootsError> {
        let (roots, stamp) = match tokio::fs::File::open(&path).await {
            Ok(mut file) => {
                let text = read_to_string(&mut file, MAX_LEN)
                    .await
                    .map_err(DisabledRootsError::from_read)?;
                let stamp = file
                    .metadata()
                    .await
                    .ok()
                    .and_then(|meta| FileStamp::of(&meta));
                let parsed = Parsed::from(text.as_str());
                if let Some(rejected) = parsed.rejected.into_iter().next() {
                    return Err(DisabledRootsError::Parse {
                        line: rejected.line,
                        source: rejected.error,
                    });
                }
                (parsed.roots, stamp)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (HashSet::new(), None),
            Err(error) => return Err(DisabledRootsError::Io(error)),
        };
        check_witness(&path, roots.len()).map_err(|error| match error {
            WitnessError::Lost { expected } => DisabledRootsError::Lost {
                path: path.clone(),
                expected,
                found: u64::try_from(roots.len()).unwrap_or(u64::MAX),
            },
            WitnessError::Io(error) => DisabledRootsError::Io(error),
        })?;
        Ok(Self::unread(path, roots, stamp))
    }

    /// An instance for REPAIRING a latch that [`load`](Self::load) refused as
    /// [`Lost`](DisabledRootsError::Lost). It refuses nothing and reads nothing up front: its
    /// [`disable`](Self::disable) unions whatever the file holds under the lock, so it can never shrink
    /// anything, and only a file back at its high-water mark clears the refusal, so a partial repair does
    /// not quietly trust the rest. Use it to write, never to serve.
    pub fn open_for_repair(path: PathBuf) -> Self {
        Self::unread(path, HashSet::new(), None)
    }

    /// An instance over `path` holding `roots`, read at `stamp`, not yet stat'd by a refresh.
    fn unread(path: PathBuf, roots: HashSet<VerifyKey>, stamp: Option<FileStamp>) -> Self {
        Self {
            path,
            state: Mutex::new(State {
                roots,
                stamp,
                last_stat: None,
                malformed: None,
            }),
        }
    }

    /// Whether `root` is disabled at this node. Refreshes from disk first when the file changed, so a key
    /// another process disabled is honored without a restart.
    pub fn is_disabled(&self, root: VerifyKey) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        state.roots.contains(&root)
    }

    /// The first line (1-based) of the file, as last read, that was not a key, or `None` when it read
    /// clean. A running latch keeps every valid line of a malformed file, so this is the one sign that
    /// something in the file is being skipped; an operator or a health check reads it.
    pub fn malformed_line(&self) -> Option<u32> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        state.malformed
    }

    /// Disable `root` and persist. Terminal: there is no inverse.
    ///
    /// The write is the denylist's: under the sibling `<path>.lock`, re-read the file, write the union of
    /// the disk and this instance, atomically and durably (the file and its directory are `fsync`ed, so an
    /// `Ok` survives a power cut), then raise the `<path>.written` witness to the keys now on disk. Two
    /// writers disabling different roots therefore both survive. It always writes, even for a root this
    /// instance already holds, so disabling again restores a file a deletion lost. A line on disk that is not a key is carried over verbatim rather than dropped, since it may be
    /// a key form this version cannot read; [`malformed_line`](Self::malformed_line) still reports it. A
    /// lock or read failure, or an oversized file, returns WITHOUT writing, and the root stays disabled in
    /// this instance either way.
    ///
    /// Blocks the calling thread while another writer holds the lock, so call it where blocking is
    /// allowed. The parent directory must already exist; the consuming process provisions it.
    pub async fn disable(&mut self, root: VerifyKey) -> Result<(), DisabledRootsError> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .roots
            .insert(root);
        // Adopt the stamp of the bytes this call wrote, taken from the handle that wrote them, so a second
        // writer's rename cannot lend us its freshness.
        let stamp = self.persist()?;
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stamp = stamp;
        Ok(())
    }

    /// Union the file into the held set if its stamp changed. Synchronous and on the admit hot path, so the
    /// stat is debounced to once per [`STAT_DEBOUNCE`] and the file is read only when it changed.
    ///
    /// Every failure returns with the set untouched. The stamp is taken before the read, so a file replaced
    /// between the two is read under the older stamp; that only costs one extra read on the next refresh,
    /// because the union cannot lose a key to it.
    fn refresh(&self, state: &mut State) {
        // The first check after a load always stats, so a fresh instance sees the current file at once.
        if let Some(last) = state.last_stat {
            if last.elapsed() < STAT_DEBOUNCE {
                return;
            }
        }
        state.last_stat = Some(Instant::now());
        // A missing file is a deletion, not an empty latch: keep what is held.
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return;
        };
        let current = FileStamp::of(&meta);
        if FileStamp::unchanged(state.stamp, current) {
            return;
        }
        let Some(text) = read_bounded(&self.path) else {
            return;
        };
        let parsed = Parsed::from(text.as_str());
        // THE line that makes the latch terminal. `state.roots = parsed.roots` would let a shorter file
        // revive a root, which is the denylist's shape and exactly the one not to copy here. Every valid
        // line lands even when another line is bad, so one bad line cannot freeze the latch.
        state.roots.extend(parsed.roots);
        state.malformed = parsed.rejected.first().map(|rejected| rejected.line);
        // A malformed read is current too. Re-reading an unchanged bad file on every refresh would parse
        // up to the whole size cap ten times a second, under the lock every admission takes, and learn
        // nothing; any edit, a repair included, changes the stamp (its inode and ctime move) and is read.
        state.stamp = current;
    }

    /// Re-read the file under the write lock, union it into the held set, and replace the file with that
    /// union, owner-only, atomically and durably. Returns the stamp of the bytes written. Synchronous
    /// throughout, so a task holding the lock can never be suspended while another on the same executor
    /// waits for it.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn persist(&self) -> Result<Option<FileStamp>, DisabledRootsError> {
        let _lock = WriteLock::acquire(&self.path)?;
        let text = match std::fs::File::open(&self.path) {
            Ok(file) => read_capped(file).map_err(DisabledRootsError::from_read)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(DisabledRootsError::Io(error)),
        };
        let parsed = Parsed::from(text.as_str());
        let (body, entries) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.roots.extend(parsed.roots);
            // Written through `Display` and read back through `FromStr`, so the file and the key's API
            // encoding cannot diverge. Sorted so the same set is always the same bytes. Unreadable lines
            // follow, untouched, so a rewrite never drops a line that may be a disabled root.
            let mut lines = state
                .roots
                .iter()
                .map(VerifyKey::to_string)
                .collect::<Vec<_>>();
            lines.sort();
            // The witness counts keys only, so an operator who repairs a carried-over bad line by
            // deleting it does not trip the refusal.
            let entries = lines.len();
            lines.extend(
                parsed
                    .rejected
                    .iter()
                    .map(|rejected| rejected.text.to_owned()),
            );
            (lines.join("\n") + "\n", entries)
        };
        write_atomically(&self.path, body.as_bytes(), entries).map_err(DisabledRootsError::Io)
    }
}

/// Read the latch file for a refresh, or `None` on any failure, an oversized file included, so the caller
/// keeps what it holds.
fn read_bounded(path: &std::path::Path) -> Option<String> {
    read_capped(std::fs::File::open(path).ok()?).ok()
}

/// Read at most [`MAX_LEN`] bytes of `file` as text; more is `FileTooLarge`, found before the excess is
/// buffered.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn read_capped(file: std::fs::File) -> std::io::Result<String> {
    let mut text = String::new();
    file.take(MAX_LEN + 1).read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_LEN {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    Ok(text)
}

/// A latch file body, decoded line by line: every line that is a key, and every non-blank line that is
/// not. One bad line never discards the good ones; each caller decides what the bad ones mean.
struct Parsed<'a> {
    roots: HashSet<VerifyKey>,
    rejected: Vec<Rejected<'a>>,
}

/// A non-blank line that was not a [`VerifyKey`]: where it is, what it says, and why it failed.
struct Rejected<'a> {
    line: u32,
    text: &'a str,
    error: KeyParseError,
}

impl<'a> From<&'a str> for Parsed<'a> {
    fn from(text: &'a str) -> Self {
        let mut parsed = Parsed {
            roots: HashSet::new(),
            rejected: Vec::new(),
        };
        for (index, line) in text.lines().enumerate() {
            let line_text = line.trim();
            if line_text.is_empty() {
                continue;
            }
            match line_text.parse() {
                Ok(root) => {
                    parsed.roots.insert(root);
                }
                Err(error) => parsed.rejected.push(Rejected {
                    line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    text: line_text,
                    error,
                }),
            }
        }
        parsed
    }
}

/// A [`Revocations`] oracle that refuses every cap whose root is disabled, then defers to `inner`.
///
/// This is the whole revocation policy a gate sees, so a gate built with the inner store alone gets no
/// latch: the root check holds only where the caller composes this. On the authority-bound path the gate
/// asks about the foreign badge too, so a disabled foreign authority's devices are refused there as well.
pub struct Latch<R> {
    disabled: DisabledRoots,
    inner: R,
}

impl<R: Revocations> Latch<R> {
    /// Layer `disabled` over `inner`. The only constructor, so the order (disabled root first, then the
    /// inner store) is fixed in one place and cannot be inverted at a call site.
    pub fn new(disabled: DisabledRoots, inner: R) -> Self {
        Self { disabled, inner }
    }

    /// The disabled roots this latch refuses. A reader that must agree with the gate after admission, on
    /// roots it kept rather than a cap it still holds, asks this instance rather than loading a second.
    pub fn disabled(&self) -> &DisabledRoots {
        &self.disabled
    }

    /// The store this latch defers to once a root is not disabled, for the same kind of reader.
    pub fn inner(&self) -> &R {
        &self.inner
    }
}

impl<R: Revocations> Revocations for Latch<R> {
    fn is_revoked(&self, cap: &Cap) -> bool {
        self.disabled.is_disabled(cap.root()) || self.inner.is_revoked(cap)
    }
}

/// Why loading or persisting the disabled roots failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DisabledRootsError {
    /// The backing file could not be read or written.
    #[error("access disabled roots")]
    Io(#[source] std::io::Error),
    /// A line in the file was not a root key. Only [`load`](DisabledRoots::load) refuses on this; a
    /// running latch skips the line and reports it through
    /// [`malformed_line`](DisabledRoots::malformed_line).
    #[error("parse disabled root on line {line}")]
    Parse {
        /// The 1-based line that failed.
        line: u32,
        /// Why it is not a key.
        #[source]
        source: KeyParseError,
    },
    /// The file is larger than a latch can be, so it was not read.
    #[error("disabled roots file is too large")]
    TooLarge,
    /// The file holds fewer keys than a durable write once left there (an absent file holds none). No
    /// write shrinks it, so keys were lost to a deletion, a truncation, or a crash, and loading it would
    /// trust those roots again. The ways out are on [`DisabledRoots`]; the message names them.
    #[error(
        "{} holds {found} disabled roots but held {expected}: restore it, re-apply every disable, or remove {}.written to trust the lost roots again",
        path.display(),
        path.display()
    )]
    Lost {
        /// The latch file.
        path: PathBuf,
        /// The high-water count the witness records.
        expected: u64,
        /// The count the file holds now.
        found: u64,
    },
    /// This platform has no cross-process file lock at the crate's minimum Rust version, so a durable
    /// disable cannot be serialized and is refused rather than raced. The root is still disabled in this
    /// process; only the durable record is unavailable.
    #[cfg(not(unix))]
    #[error("cross-process locking is unavailable on this platform")]
    LockUnsupported,
}

impl DisabledRootsError {
    /// Name a bounded read's failure: an oversized file is its own refusal, anything else is I/O.
    // `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn from_read(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::FileTooLarge => DisabledRootsError::TooLarge,
            _ => DisabledRootsError::Io(error),
        }
    }
}

impl From<LockError> for DisabledRootsError {
    fn from(error: LockError) -> Self {
        match error {
            LockError::Io(error) => DisabledRootsError::Io(error),
            #[cfg(not(unix))]
            LockError::Unsupported => DisabledRootsError::LockUnsupported,
        }
    }
}
