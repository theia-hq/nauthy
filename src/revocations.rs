//! Offline revocation for `sheer:` bearer caps: the [`Revocations`] oracle the gate consults, and a
//! file-backed [`FileDenylist`] that implements it.
//!
//! A cap is offline-verifiable, so there is no server to ask "is this revoked?". Instead the issuer keeps
//! its own set of biscuit revocation identifiers: revoking a cap records its narrowest block's id, and the
//! gate refuses any presented cap whose chain includes a revoked id (the cap itself, or an ancestor it was
//! attenuated from). Pure-offline, node-local, and it survives restarts, which a short TTL cannot: a TTL
//! ages a leaked cap out eventually but cannot recall it now.
//!
//! [`Revocations`] is the extension point. It is a synchronous, one-method trait, so a consumer whose distributed
//! system keeps revocations in Redis, a database, or a gossip set implements it over that store and needs
//! no file and no async runtime. The batteries-included impl is [`FileDenylist`] (behind the `tokio-fs`
//! feature), a persisted set of ids on disk.
//!
//! Revocation through [`FileDenylist`] is LIVE: [`is_revoked`](FileDenylist::is_revoked) re-reads the file
//! when its [`FileStamp`](crate::FileStamp) changes, so a revocation written by a separate process takes effect on
//! the next connection to a long-running issuer; it does not wait for a restart. The stamp carries the
//! length with the mtime on purpose: a revoke only ever grows the file, so a change within one coarse
//! mtime tick is still seen. The reload is a small, rare read (only when the file actually changed), guarded by
//! interior mutability so the gate's synchronous admit path stays synchronous.
//!
//! Revocation WRITES are SERIALIZED: [`revoke`](FileDenylist::revoke) takes an exclusive advisory lock on a
//! sibling `<path>.lock` file, re-reads the on-disk set under that lock, and writes the union of the disk
//! set and its own, so two writers revoking different ids both survive instead of the last rewrite dropping
//! the other's. The rewrite is atomic (a temp sibling unique per write, then one rename over the target), so
//! a crash mid-write can never truncate the denylist. Failures leave the file untouched: a set that might
//! be missing a revocation never replaces one that holds it.

#[cfg(feature = "tokio-fs")]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "tokio-fs")]
use std::collections::HashSet;
#[cfg(all(feature = "tokio-fs", unix))]
use std::os::fd::AsRawFd as _;
#[cfg(feature = "tokio-fs")]
use std::path::{Path, PathBuf};
#[cfg(feature = "tokio-fs")]
use std::process;
use std::sync::Arc;
#[cfg(feature = "tokio-fs")]
use std::sync::{Mutex, PoisonError};
#[cfg(feature = "tokio-fs")]
use std::time::Instant;

use data_encoding::HEXLOWER;
#[cfg(feature = "tokio-fs")]
use tokio::io::AsyncRead as _;

use crate::VerifyKey;
use crate::cap::Cap;
#[cfg(feature = "tokio-fs")]
use crate::stamp::{FileStamp, STAT_DEBOUNCE};

/// The revocation oracle a [`Gate::Rooted`](crate::Gate::Rooted) or [`Gate::Anchored`](crate::Gate::Anchored)
/// consults on the admit hot path.
///
/// Synchronous by design: admission is synchronous policy, so a revocation check must never require an
/// async runtime. A consumer whose distributed system keeps revocations in Redis, a database, or a gossip
/// set implements this over that store; nauthy's core needs no file and no runtime. The provided
/// file-backed impl is [`FileDenylist`] behind the `tokio-fs` feature, and [`Latch`](crate::Latch) layers
/// a set of disabled root keys over any store.
///
/// The gate asks about EVERY cap presented to it, a foreign badge on the authority-bound path included, so
/// an impl must answer for a cap rooted at an authority it did not issue. Answering `true` there can only
/// refuse, never admit: the oracle is deny-only.
pub trait Revocations {
    /// Whether a presented cap is revoked: any id in its chain (the cap's own blocks, including any it
    /// inherited from the grant it was attenuated from) is recalled, or anything else the store keys on,
    /// such as the cap's [`root`](Cap::root). See [`Cap::revocation_ids`].
    fn is_revoked(&self, cap: &Cap) -> bool;

    /// Whether the proven peer's own key is revoked: a device key recalled as a key, not through any cap
    /// it carries. A [`Gate::Rooted`](crate::Gate::Rooted) and a [`Gate::Anchored`](crate::Gate::Anchored)
    /// ask this about the transport-proven dialer first, before they read or verify any presented cap, and
    /// refuse a `true` as
    /// [`Revoked`](crate::Refusal::Revoked), so a revoked device is refused whatever token it presents,
    /// including one minted for it after the revocation.
    ///
    /// Provided, answering `false`: a store that keeps no keys keeps the default. A wrapper that holds a
    /// store must forward this as well as [`is_revoked`](Self::is_revoked), because a provided method a
    /// wrapper does not write answers the default, not the inner store.
    fn is_revoked_peer(&self, _peer: &VerifyKey) -> bool {
        false
    }
}

/// A shared store answers as the store it shares, so one instance can back a gate and any other reader
/// that must agree with it, rather than two instances over one file drifting by a refresh.
impl<R: Revocations + ?Sized> Revocations for Arc<R> {
    fn is_revoked(&self, cap: &Cap) -> bool {
        R::is_revoked(self, cap)
    }

    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        R::is_revoked_peer(self, peer)
    }
}

/// A biscuit revocation identifier: the opaque, per-block id whose presence in a revocation set (see
/// [`Revocations`]) revokes a cap (one entry of [`Cap::revocation_ids`]). It is an OPAQUE HANDLE: nauthy
/// never interprets its bytes and construction does NOT verify they name a real block. A bogus id simply
/// never matches a presented cap's chain, so a wrong id can only ever over-deny, never grant, which is why
/// [`from_bytes`](Self::from_bytes) and [`from_hex`](Self::from_hex) are plain wrappers, not validating
/// parsers.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RevocationId(Box<[u8]>);

impl RevocationId {
    /// Wrap raw id bytes. No validation: an id that names no real block just never matches (over-deny only).
    pub fn from_bytes(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(bytes.into())
    }

    /// The raw id bytes, for a caller that encodes them for its own store.
    pub fn as_bytes(&self) -> &[u8] {
        let Self(bytes) = self;
        bytes
    }

    /// The id as lowercase hex, the form an issuer's audit log records it in AND the exact form a
    /// [`FileDenylist`] writes one per line, so a grep of `to_hex` output against the file finds it.
    pub fn to_hex(&self) -> String {
        HEXLOWER.encode(self.as_bytes())
    }

    /// Parse an id from the lowercase hex [`to_hex`](Self::to_hex) writes. Decodes hex only; it does not (and
    /// cannot) verify the bytes name a real block, so a decoded-but-bogus id simply never matches.
    pub fn from_hex(text: &str) -> Result<Self, RevocationIdParseError> {
        HEXLOWER
            .decode(text.as_bytes())
            .map(|bytes| Self(bytes.into()))
            .map_err(|_| RevocationIdParseError)
    }
}

/// The text passed to [`RevocationId::from_hex`] was not valid hex.
#[derive(Debug, thiserror::Error)]
#[error("parse revocation id")]
pub struct RevocationIdParseError;

/// A persisted set of revoked capability ids (biscuit revocation identifiers), one lowercase-hex id per
/// line, and the batteries-included [`Revocations`] impl.
///
/// nauthy is cross-cutting, so the file location is the consuming process's to choose; this type owns only
/// the load / revoke / check logic over a path. The loaded set is behind a [`Mutex`] with the
/// [`FileStamp`](crate::FileStamp) it was read at, so a check can refresh it in place when the file changed
/// underneath a running process.
///
/// CONCURRENT REVOCATIONS SURVIVE. A write locks a sibling `<path>.lock` file, re-reads the on-disk set
/// under that lock, and rewrites the union, so two issuers that each loaded the file before either wrote
/// (two processes, or two instances) both keep their ids. The rewrite is atomic, and a crash mid-write can
/// never truncate the denylist. The lock is an advisory unix one at the current minimum Rust version; other
/// platforms refuse a durable revoke loudly instead of racing it (see `persist`).
///
/// DURABILITY IS A HARD PRECONDITION: the backing file must live on durable storage that survives a
/// restart. A restart on ephemeral storage resurrects every revoked cap, because [`load`](Self::load) of an
/// absent file is an empty set, and an empty set revokes nothing.
#[cfg(feature = "tokio-fs")]
pub struct FileDenylist {
    path: PathBuf,
    state: Mutex<State>,
}

/// The loaded ids, the [`FileStamp`](crate::FileStamp) of the file they were read at (`None` = the file was absent or
/// reported no stamp), and the last moment we stat'd the file. The length pairs with mtime so a change within one
/// coarse mtime tick is still seen: a revoke only ever GROWS the file, so a differing length is a reliable
/// "changed" signal on its own.
#[cfg(feature = "tokio-fs")]
struct State {
    ids: HashSet<RevocationId>,
    stamp: Option<FileStamp>,
    last_stat: Option<Instant>,
}

#[cfg(feature = "tokio-fs")]
impl FileDenylist {
    /// Load the denylist from `path`; an absent file is an empty set. The ids and the stamp come from one
    /// opened handle, so a file replaced during this load cannot stamp the old ids as current and make every
    /// later refresh skip a real revocation.
    ///
    /// A file holding FEWER ids than a durable write once left there, absent included, is
    /// [`Lost`](DenylistError::Lost), never loaded: no write shrinks the denylist, so a shorter file is a
    /// deletion, a truncation, or a crash, and loading it would un-revoke what went missing. The count is
    /// the high-water mark in the `<path>.written` witness each write raises; a denylist with no witness
    /// (never durably written, or written before the witness existed) loads as it reads.
    pub async fn load(path: PathBuf) -> Result<Self, DenylistError> {
        let (ids, stamp) = read_ids(&path).await?;
        Ok(Self {
            path,
            state: Mutex::new(State {
                ids,
                stamp,
                last_stat: None,
            }),
        })
    }

    /// Whether a presented cap is revoked: any id in its chain (the cap's own blocks, including any it
    /// inherited from the grant it was attenuated from) is on the denylist.
    ///
    /// Refreshes from disk first if the file changed since the last read, so a revocation written by
    /// another process is honored by a long-running issuer without a restart. The stat is debounced (see
    /// `STAT_DEBOUNCE`); the file is re-read only when it actually changed.
    pub fn is_revoked(&self, cap: &Cap) -> bool {
        self.is_revoked_any(&cap.revocation_ids())
    }

    /// Whether any of `ids` is on the denylist: the membership query [`is_revoked`](Self::is_revoked)
    /// runs over one cap's chain, for a caller that kept the ids and let the cap go. Holding a parsed cap
    /// for as long as the thing it admitted stays open pins the whole token in memory and re-derives its
    /// chain on every check; the ids are all a revocation ever matches, so they are all such a caller
    /// needs to keep. One lock and one refresh however many ids are asked about.
    pub fn is_revoked_any<'a>(&self, ids: impl IntoIterator<Item = &'a RevocationId>) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        ids.into_iter().any(|id| state.ids.contains(id))
    }

    /// Reload the ids in place if the backing file's [`FileStamp`](crate::FileStamp) differs from what we last read.
    /// Synchronous and on the admit hot path, so it debounces the stat to at most once per
    /// [`STAT_DEBOUNCE`] and re-reads only on change.
    ///
    /// Fail closed on every uncertainty: a stat/read error, a parse failure, OR the file DISAPPEARING all
    /// leave the last-known set intact and return. Deletion is not "the denylist is now empty": a `rm` of
    /// the file (a botched cleanup, or a local attacker) must never silently un-revoke every recalled cap.
    /// A denylist that never had a file stays empty (nothing to un-revoke); revocations only ever grow a
    /// file, and a fresh file appearing is picked up through the `Ok` stat arm below.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut State) {
        // Debounce: skip the stat entirely if we checked within the last STAT_DEBOUNCE. The first check
        // after construction (`last_stat` is None) always stats, so a freshly-loaded denylist sees the
        // current file at once.
        if let Some(last) = state.last_stat {
            if last.elapsed() < STAT_DEBOUNCE {
                return;
            }
        }
        state.last_stat = Some(Instant::now());
        let current = match std::fs::metadata(&self.path) {
            Ok(meta) => FileStamp::of(&meta),
            // Missing file: keep the last-known set. If one was ever loaded, this is deletion, not empty.
            Err(_) => return,
        };
        if FileStamp::unchanged(state.stamp, current) {
            return;
        }
        let ids = match std::fs::read_to_string(&self.path) {
            // An empty body never replaces the set: no write leaves one, so it is a truncation or a crash,
            // and replacing would un-revoke every cap at once.
            Ok(text) if text.trim().is_empty() => return,
            Ok(text) => match parse_ids(&text) {
                Ok(ids) => ids,
                Err(_) => return,
            },
            // Raced away between stat and read: keep last-known rather than dropping revocations.
            Err(_) => return,
        };
        state.ids = ids;
        state.stamp = current;
    }

    /// Revoke a cap and persist. Records the cap's narrowest block id, which denies this exact cap and
    /// every cap attenuated from it, but not the ancestors it was narrowed from. Revoking a freshly minted
    /// cap (one block) denies it and all its delegations.
    pub async fn revoke(&mut self, cap: &Cap) -> Result<(), DenylistError> {
        // A biscuit always has at least its authority block, so `pop` yields the narrowest id; stay total.
        let Some(id) = cap.revocation_ids().pop() else {
            return Ok(());
        };
        self.revoke_id(id).await
    }

    /// Revoke a cap at its ROOT authority block and persist. Records the cap's FIRST (authority-block) id,
    /// the one every cap attenuated or delegated from it inherits, so this denies the WHOLE tree at once: the
    /// root grant AND every narrower cap descended from it, however deep the delegation chain. Contrast
    /// [`revoke`](Self::revoke), which records only the NARROWEST block and so denies a single leaf while its
    /// ancestors keep granting. Revoking the root of a token you issued cuts off its holder and everyone they
    /// re-shared it to in one entry, because [`is_revoked`](Self::is_revoked) checks the whole chain and every
    /// descendant carries this root id.
    pub async fn revoke_root(&mut self, cap: &Cap) -> Result<(), DenylistError> {
        // `revocation_ids` is authority-block-first, so the first id is the root's; a biscuit always has an
        // authority block, but stay total against an empty chain rather than indexing.
        let Some(root) = cap.revocation_ids().into_iter().next() else {
            return Ok(());
        };
        self.revoke_id(root).await
    }

    /// Revoke one raw biscuit revocation id and persist. The single primitive both [`revoke`](Self::revoke)
    /// and [`revoke_root`](Self::revoke_root) funnel through: it inserts the id and, only if it was new,
    /// merges the on-disk set into ours and atomically rewrites the file under an exclusive lock, adopting
    /// the stamp of the bytes it just wrote, taken from the writing handle, so a second writer's rename
    /// can never lend this instance its freshness. A caller that already holds an id it recorded when
    /// the cap was minted (an issuer's audit index from grantee to root id) can revoke by that id directly,
    /// without still holding the cap the id came from.
    pub async fn revoke_id(&mut self, id: RevocationId) -> Result<(), DenylistError> {
        let inserted = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.ids.insert(id)
        };
        if inserted {
            // Adopt the stamp of the bytes this call just wrote (`persist` takes it from the same handle
            // that wrote them). Stat-ing the path here instead is the defect this closes: a second writer's
            // rename between our write and our stat made us adopt their stamp while keeping our
            // in-memory set, so the next refresh saw the stamp current and skipped their revocation. A
            // stamp the platform will not report is `None`, so the next refresh re-reads instead of
            // trusting a stale stamp.
            let stamp = self.persist()?;
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stamp = stamp;
        }
        Ok(())
    }

    /// An empty denylist backed by `path`, before any load, and reading nothing yet. The first
    /// [`revoke`](Self::revoke) creates and persists the file.
    ///
    /// This is also the REPAIR path when [`load`](Self::load) refuses with [`Lost`](DenylistError::Lost): a
    /// revoke from here unions whatever the file holds under the lock, so it can never shrink anything,
    /// and re-revoking everything that went missing brings the file back to its high-water mark, which is
    /// the only thing that clears `Lost`. Use it to write, never to serve.
    pub fn empty(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(State {
                ids: HashSet::new(),
                stamp: None,
                last_stat: None,
            }),
        }
    }

    /// The file backing this denylist.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Merge the on-disk set into this instance's set, then atomically rewrite the backing file with the
    /// union under an exclusive cross-writer lock, owner-only and durably, and return the stamp of the
    /// bytes written. The stamp comes from the ONE handle that received the bytes ([`write_and_stamp`]),
    /// never from stat-ing the path after the rename, so a writer that replaces the path between our write
    /// and our stamp cannot make this instance adopt the replacement's stamp and skip the replacement's
    /// revocation on the next refresh.
    ///
    /// The read-merge-write under the lock is what keeps concurrent revocations: two writers that each
    /// loaded the file before either wrote would otherwise rewrite it from their own view, and the last
    /// rename would drop the other's id. Re-reading under the lock means the second writer writes both.
    ///
    /// Fail closed on every uncertainty: a lock, read, or parse failure returns WITHOUT writing, so a set
    /// that might be missing a revocation never replaces the file. The id stays in this instance's set, so
    /// this process still refuses it.
    ///
    /// The whole section is synchronous on purpose: a task that holds the lock can never be suspended on an
    /// await while another task on the same executor blocks in [`WriteLock::acquire`], so the lock cannot
    /// deadlock an async runtime.
    ///
    /// The parent directory must already exist: the consuming process owns the store location and
    /// provisions it (with whatever mode it wants), so nauthy does NOT create the dir. nauthy writes only
    /// its OWN files there: the denylist, its `<denylist>.lock` sibling, its `<denylist>.written` witness,
    /// and a temp sibling whose name is unique per write. The denylist is tightened to `0600` so the recall trace is not exposed to other
    /// local users; the lock and temp are created owner-only too.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn persist(&self) -> Result<Option<FileStamp>, DenylistError> {
        // Held across the WHOLE read-merge-write: the re-read must see every id another writer already
        // persisted, and no other writer may slip a rename in before ours. Dropping the guard releases it,
        // so a crash never strands the lock.
        let _lock = WriteLock::acquire(&self.path)?;
        // Re-read the current on-disk set under the lock and union it with our in-memory set. An absent
        // file contributes nothing. A read or parse failure aborts WITHOUT writing: the file may hold ids
        // we cannot see, and replacing it with ours would drop them.
        let on_disk = match std::fs::read_to_string(&self.path) {
            Ok(text) => parse_ids(&text)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(error) => return Err(DenylistError::Io(error)),
        };
        let (body, entries) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.ids.extend(on_disk);
            // Encode through RevocationId::to_hex so the file and the API encoding cannot diverge: the file
            // is exactly what to_hex writes, and decode_id reads it back through from_hex.
            let mut lines = state
                .ids
                .iter()
                .map(RevocationId::to_hex)
                .collect::<Vec<_>>();
            lines.sort();
            (lines.join("\n") + "\n", lines.len())
        };
        write_atomically(&self.path, body.as_bytes(), entries).map_err(DenylistError::Io)
    }
}

#[cfg(feature = "tokio-fs")]
impl Revocations for FileDenylist {
    fn is_revoked(&self, cap: &Cap) -> bool {
        FileDenylist::is_revoked(self, cap)
    }
}

/// The sibling `<denylist>.lock` whose stable inode every writer flocks. `with_extension` would REPLACE
/// an existing extension, letting `caps.deny` and `caps.other` collide on one sibling name, so the suffix
/// is appended to the whole path instead (`with_suffix`). `pub(crate)` so a test can clean it up.
#[cfg(feature = "tokio-fs")]
#[cfg(unix)]
pub(crate) fn lock_path(denylist: &Path) -> PathBuf {
    with_suffix(denylist, ".lock")
}

/// A temp sibling unique to ONE write: the denylist path plus `.tmp.<pid>.<seq>`. The pid separates
/// processes and an atomic sequence separates writes within one, so two writers can never share one temp
/// path; the old fixed `<denylist>.tmp` let one writer truncate the other's in-flight body. `pub(crate)` so
/// a test can pin the uniqueness.
#[cfg(feature = "tokio-fs")]
pub(crate) fn temp_path(denylist: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    with_suffix(denylist, &format!(".tmp.{}.{seq}", process::id()))
}

/// Append `suffix` to the full path, keeping the parent directory.
#[cfg(feature = "tokio-fs")]
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut sibling = path.as_os_str().to_os_string();
    sibling.push(suffix);
    PathBuf::from(sibling)
}

/// The exclusive cross-writer lock `persist` holds across its read-merge-write.
///
/// The lock is an advisory `flock` on a sibling `<denylist>.lock`, NOT on the denylist itself: the atomic
/// rewrite replaces the denylist's inode each time, so a lock on that moving inode would not serialize two
/// writers. The lock file's inode is stable, so every writer contends on the same one. Being advisory, it
/// only serializes writers that take it; a process that ignores it can still race, as with any advisory
/// lock. Shared with the disabled-roots latch, whose writer holds the same law.
#[cfg(feature = "tokio-fs")]
#[cfg(unix)]
pub(crate) struct WriteLock {
    file: std::fs::File,
}

#[cfg(feature = "tokio-fs")]
#[cfg(unix)]
impl WriteLock {
    /// Take the exclusive lock, creating the lock file (`0600`) if absent. Blocks (`LOCK_EX`, no
    /// `LOCK_NB`) until any other in-flight writer releases, so a concurrent revoke waits rather than
    /// failing. The critical section this guards is fully synchronous, so a task that holds the lock can
    /// never be suspended while another task on the same executor blocks here.
    pub(crate) fn acquire(denylist: &Path) -> Result<Self, LockError> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            // The lock file's contents are never written, so an existing one is opened as it is.
            .truncate(false)
            .mode(0o600)
            .open(lock_path(denylist))
            .map_err(LockError::Io)?;
        // SAFETY: `file` owns a valid fd for the duration of the call, and `flock` only associates an
        // advisory lock with that open file description; it touches no memory.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if locked != 0 {
            return Err(LockError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self { file })
    }
}

#[cfg(feature = "tokio-fs")]
#[cfg(unix)]
impl Drop for WriteLock {
    fn drop(&mut self) {
        // Best-effort explicit unlock; closing the fd (right after) releases the flock regardless, so a
        // failure here cannot strand the lock.
        // SAFETY: `self.file` still owns a valid fd here; `LOCK_UN` only drops this fd's advisory lock and
        // touches no memory.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Non-unix builds have no cross-process file lock at the crate's minimum Rust version: std's file locking
/// lands at 1.89 and nauthy supports 1.85, and `flock` is unix-only. Rather than racing the read-merge-write
/// (the lost update this store exists to fix), a durable revoke FAILS: `persist` returns
/// `LockUnsupported` and leaves the file untouched. The in-memory set still refuses the id
/// for this process; only the durable record is unavailable. Revisit when the MSRV passes 1.89 (then this
/// becomes `std::fs::File::lock`) or a platform lock lands.
#[cfg(feature = "tokio-fs")]
#[cfg(not(unix))]
pub(crate) struct WriteLock;

#[cfg(feature = "tokio-fs")]
#[cfg(not(unix))]
impl WriteLock {
    pub(crate) fn acquire(_denylist: &Path) -> Result<Self, LockError> {
        Err(LockError::Unsupported)
    }
}

/// Why [`WriteLock::acquire`] failed, before a store names it in its own public error. Crate-private so
/// the lock stays one implementation while each store keeps its own matchable error type.
#[cfg(feature = "tokio-fs")]
pub(crate) enum LockError {
    /// The lock file could not be opened or locked.
    Io(std::io::Error),
    /// This platform has no cross-process file lock at the crate's minimum Rust version.
    #[cfg(not(unix))]
    Unsupported,
}

#[cfg(feature = "tokio-fs")]
impl From<LockError> for DenylistError {
    fn from(error: LockError) -> Self {
        match error {
            LockError::Io(error) => DenylistError::Io(error),
            #[cfg(not(unix))]
            LockError::Unsupported => DenylistError::LockUnsupported,
        }
    }
}

/// Open the denylist's temp sibling for a whole-body rewrite, owner-only from creation. Opening this ONE
/// handle is what lets [`write_and_stamp`] take the stamp from the bytes it wrote rather than from the path.
/// A pre-existing temp is truncated in place and tightened again below before the rename carries `0600` onto
/// the target.
#[cfg(feature = "tokio-fs")]
#[cfg(unix)]
fn open_tmp(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

/// The non-unix twin of `open_tmp`; there is no creation mode to tighten.
#[cfg(feature = "tokio-fs")]
#[cfg(not(unix))]
fn open_tmp(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// Replace the file at `path` with `body`, which holds `entries` entries, atomically and durably, owner-only,
/// then raise the `<path>.written` witness to `entries`, and return the stamp of the bytes written. The
/// caller holds the [`WriteLock`].
///
/// The witness moves only AFTER the body is durably in place, so a write that fails anywhere leaves it
/// where it was, and no crash ordering can make a store look shorter than its witness when nothing was
/// lost: a crash after the rename leaves the file ahead of the witness, which loads.
///
/// ATOMIC: the body goes to a temp sibling unique per write, then one rename over the target, so a crash
/// mid-write can never leave a half-written store, and two writers never share a temp. A failure removes
/// the temp best-effort, so it leaves no litter.
///
/// DURABLE, and this is what an `Ok` promises: the temp is `fsync`ed before the rename and the parent
/// directory after it. Without both, a power cut after the caller saw success can leave the old body or
/// a zero-length file, and either one brings back what was just revoked.
#[cfg(feature = "tokio-fs")]
pub(crate) fn write_atomically(
    path: &Path,
    body: &[u8],
    entries: usize,
) -> std::io::Result<Option<FileStamp>> {
    let stamp = replace_durably(path, body)?;
    raise_witness(path, entries)?;
    Ok(stamp)
}

/// The one place a file is renamed into place: temp sibling, `fsync`, rename, parent `fsync`.
#[cfg(feature = "tokio-fs")]
fn replace_durably(path: &Path, body: &[u8]) -> std::io::Result<Option<FileStamp>> {
    let tmp = temp_path(path);
    let written = write_body(&tmp, body).and_then(|stamp| {
        std::fs::rename(&tmp, path)?;
        Ok(stamp)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    let stamp = written?;
    sync_parent(path)?;
    Ok(stamp)
}

/// Write `body` through a fresh temp sibling, owner-only (unix) before the first byte lands, and return the
/// stamp of the bytes written. The rename carries the `0600` mode onto the target.
#[cfg(feature = "tokio-fs")]
fn write_body(path: &Path, body: &[u8]) -> std::io::Result<Option<FileStamp>> {
    let mut file = open_tmp(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    write_and_stamp(&mut file, body)
}

/// `fsync` the directory holding `path`, so the rename that put the new body there survives a power cut.
/// Unix only: a directory cannot be opened as a file elsewhere, and no other platform persists at all
/// (see [`WriteLock`]).
#[cfg(feature = "tokio-fs")]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The `<path>.written` witness: the high-water count of entries a durable write has left in the store.
///
/// It is not the lock. `<path>.lock` is created before any write, so it proves only that a write was
/// attempted, and it must never be removed, because its inode is what serializes writers. The witness
/// is written only after a write is durably in place, and it is the one file an operator removes to
/// accept a loss.
#[cfg(feature = "tokio-fs")]
pub(crate) fn witness_path(path: &Path) -> PathBuf {
    with_suffix(path, ".written")
}

/// Raise the witness to `entries` if that is higher than it holds; never lower it. A repair write from a
/// short file therefore leaves the mark where it was, so a partial repair does not clear the refusal.
#[cfg(feature = "tokio-fs")]
fn raise_witness(path: &Path, entries: usize) -> std::io::Result<()> {
    let entries = u64::try_from(entries).unwrap_or(u64::MAX);
    if read_witness(path)?.is_some_and(|mark| mark >= entries) {
        return Ok(());
    }
    replace_durably(&witness_path(path), format!("{entries}\n").as_bytes()).map(|_| ())
}

/// The witness's count, or `None` when there is no witness. A witness that is not a count is an error:
/// guessing it would either refuse a sound store forever or accept a lost one.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[cfg(feature = "tokio-fs")]
#[allow(clippy::std_instead_of_core)]
fn read_witness(path: &Path) -> std::io::Result<Option<u64>> {
    let text = match std::fs::read_to_string(witness_path(path)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    text.trim().parse().map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "store witness is not a count",
        )
    })
}

/// Why a store may not be loaded as it reads.
#[cfg(feature = "tokio-fs")]
pub(crate) enum WitnessError {
    /// It holds fewer entries than a durable write once left there.
    Lost {
        /// The high-water count the witness records.
        expected: u64,
    },
    /// The witness could not be read.
    Io(std::io::Error),
}

/// The one startup check both stores run: a store that `found` entries in, absent counting as zero, must
/// hold at least what its witness says a durable write left there. Neither store has a removal API, so a
/// shorter file can only be a loss, and loading it would turn a deny into an admit.
#[cfg(feature = "tokio-fs")]
pub(crate) fn check_witness(path: &Path, found: usize) -> Result<(), WitnessError> {
    let found = u64::try_from(found).unwrap_or(u64::MAX);
    match read_witness(path).map_err(WitnessError::Io)? {
        Some(expected) if found < expected => Err(WitnessError::Lost { expected }),
        _ => Ok(()),
    }
}

/// Write `body` to ONE already-open handle, `fsync` it, and return that handle's stamp. The single
/// handle is the invariant: the stamp names the same inode the bytes went to, so a writer that replaces the
/// target path can never pair these bytes with the replacement's freshness and make the next refresh skip
/// the replacement's revocation. A stamp the platform will not report degrades to `None`, so the next
/// refresh re-reads rather than trusting a stale stamp. `pub(crate)` so the regression test can drive the
/// single-handle write path.
#[cfg(feature = "tokio-fs")]
pub(crate) fn write_and_stamp(
    file: &mut std::fs::File,
    body: &[u8],
) -> std::io::Result<Option<FileStamp>> {
    use std::io::Write as _;

    file.write_all(body)?;
    // Before the rename, or a power cut can leave the renamed name pointing at blocks never written.
    file.sync_all()?;
    // The length is the bytes we just wrote, not a post-write stat: a stat can race the write's
    // visibility on some filesystems and report the pre-write size with the same mtime tick, which
    // would make this instance adopt a stamp that no longer matches the file it just wrote. The
    // mtime still comes from the handle, so the stamp names the inode that received the bytes.
    let written = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let stamp = file
        .metadata()
        .ok()
        .and_then(|meta| FileStamp::of(&meta))
        .map(|stamp| stamp.with_len(written));
    Ok(stamp)
}

/// Read and decode the denylist file; an absent file is an empty set. Returns the ids and the file's stamp
/// (`None` if absent).
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[cfg(feature = "tokio-fs")]
#[allow(clippy::std_instead_of_core)]
async fn read_ids(
    path: &Path,
) -> Result<(HashSet<RevocationId>, Option<FileStamp>), DenylistError> {
    // Open ONCE and take both the ids and the stamp from that handle (`read_ids_from`). Reading the path
    // and then stat-ing the path again is the defect this closes: a writer that replaces the file between
    // the two calls made the old ids wear the new file's stamp, so every later refresh saw the
    // stamp as current and a revocation froze until the next edit.
    let (ids, stamp) = match tokio::fs::File::open(path).await {
        Ok(mut file) => read_ids_from(&mut file).await?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (HashSet::new(), None),
        Err(error) => return Err(DenylistError::Io(error)),
    };
    // Absent counts: a deleted denylist beside its witness is a loss, not a fresh start.
    check_witness(path, ids.len()).map_err(|error| match error {
        WitnessError::Lost { expected } => DenylistError::Lost {
            path: path.to_path_buf(),
            expected,
            found: u64::try_from(ids.len()).unwrap_or(u64::MAX),
        },
        WitnessError::Io(error) => DenylistError::Io(error),
    })?;
    Ok((ids, stamp))
}

/// Read the ids and their stamp from ONE already-open handle. The single handle is the
/// invariant: the bytes and the stamp describe the same inode, so a path replacement between the open and
/// the read can never pair old ids with the replacement's freshness. An unreadable body or an unparsable
/// line is an error; a stamp the platform will not report degrades to `None`, so the next refresh re-reads
/// rather than trusting a stale stamp. `pub(crate)` so the regression test can drive the single-handle path.
#[cfg(feature = "tokio-fs")]
pub(crate) async fn read_ids_from(
    file: &mut tokio::fs::File,
) -> Result<(HashSet<RevocationId>, Option<FileStamp>), DenylistError> {
    // Unbounded, as the denylist has always been: an issuer's own revocations are its to grow.
    let text = read_to_string(file, u64::MAX)
        .await
        .map_err(DenylistError::Io)?;
    let ids = parse_ids(&text)?;
    let stamp = file
        .metadata()
        .await
        .ok()
        .and_then(|meta| FileStamp::of(&meta));
    Ok((ids, stamp))
}

/// Read an open file to a string through the core [`AsyncRead`] trait. The `tokio-fs` feature enables only
/// `tokio/fs`; the `io-util` extension traits would add `bytes` to every consumer's lock just to read a
/// small control file, so this loop drives `poll_read` directly. More than `max` bytes is
/// `FileTooLarge`, found before the excess is buffered.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[cfg(feature = "tokio-fs")]
#[allow(clippy::std_instead_of_core)]
pub(crate) async fn read_to_string(
    file: &mut tokio::fs::File,
    max: u64,
) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let filled = core::future::poll_fn(|cx| {
            let mut buf = tokio::io::ReadBuf::new(&mut chunk);
            core::task::ready!(core::pin::Pin::new(&mut *file).poll_read(cx, &mut buf))?;
            core::task::Poll::Ready(Ok::<_, std::io::Error>(buf.filled().len()))
        })
        .await?;
        if filled == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..filled]);
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
    }
    String::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "file is not valid UTF-8")
    })
}

/// Decode a denylist file body into a set of revocation ids.
#[cfg(feature = "tokio-fs")]
fn parse_ids(text: &str) -> Result<HashSet<RevocationId>, DenylistError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(decode_id)
        .collect()
}

/// Decode one lowercase-hex revocation-id line into a [`RevocationId`], through the same
/// [`RevocationId::from_hex`] the API uses, so the file and API encodings can never diverge.
#[cfg(feature = "tokio-fs")]
fn decode_id(line: &str) -> Result<RevocationId, DenylistError> {
    RevocationId::from_hex(line).map_err(|_| DenylistError::Parse)
}

/// Why loading or persisting the denylist failed.
#[cfg(feature = "tokio-fs")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DenylistError {
    /// The backing file could not be read or written.
    #[error("access revocation denylist")]
    Io(#[source] std::io::Error),
    /// A line in the file was not a valid lowercase-hex revocation id.
    #[error("parse revocation id")]
    Parse,
    /// The file holds fewer ids than a durable write once left there (an absent file holds none). No write
    /// shrinks the denylist, so ids were lost to a deletion, a truncation, or a crash, and loading it would
    /// un-revoke them. Three ways out, in order: restore the file; re-revoke everything that went missing
    /// through [`FileDenylist::empty`], which clears this once the file is back at `expected`; or remove
    /// the `<path>.written` witness, which accepts the loss and un-revokes whatever was lost. Never remove
    /// the `.lock`: writers serialize on it.
    #[error(
        "{} holds {found} revocations but held {expected}: restore it, re-revoke what is missing, or remove {}.written to accept the loss",
        path.display(),
        path.display()
    )]
    Lost {
        /// The denylist file.
        path: PathBuf,
        /// The high-water count the witness records.
        expected: u64,
        /// The count the file holds now.
        found: u64,
    },
    /// This platform has no cross-process file lock at the crate's minimum Rust version, so a durable
    /// revoke cannot be serialized and is refused rather than raced. The in-memory set still refuses
    /// the id for this process; only the durable record is unavailable.
    #[cfg(not(unix))]
    #[error("cross-process denylist locking is unavailable on this platform")]
    LockUnsupported,
}
