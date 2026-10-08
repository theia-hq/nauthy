//! Offline revocation for bearer caps: the [`Revocations`] oracle the gate consults, and a file-backed
//! [`Denylist`] that implements it.
//!
//! A cap is offline-verifiable, so there is no server to ask "is this revoked?". Instead the issuer keeps
//! its own set of what it refuses for good. Revoking a cap records its narrowest block's id, and the gate
//! refuses any presented cap whose chain includes a revoked id (the cap itself, or an ancestor it was
//! attenuated from). Revoking a KEY refuses it as a proven peer and refuses every cap rooted at it, past
//! and future, which an id cannot do: an id names only what a key already signed. Pure-offline,
//! node-local, and it survives restarts, which a short TTL cannot: a TTL ages a leaked cap out eventually
//! but cannot recall it now.
//!
//! [`Revocations`] is the extension point. It is a synchronous trait, so a consumer whose distributed
//! system keeps revocations in Redis, a database, or a gossip set implements it over that store and needs
//! no file. The batteries-included impl is [`Denylist`] (behind the `fs` feature), one grow-only file of
//! ids and keys.
//!
//! Revocation through [`Denylist`] is LIVE: a check re-reads the file when its
//! [stamp](crate::FileStamp) changes, so a revocation written by a separate process takes effect on
//! the next connection to a long-running issuer; it does not wait for a restart. The reload is a small,
//! rare read (only when the file actually changed), guarded by interior mutability so the gate's
//! synchronous admit path stays synchronous.
//!
//! Revocation WRITES are SERIALIZED by a lock the caller holds, named by an [`Exclusive`] value: its own,
//! or the store's [`lock`](Denylist::lock). Under it a write re-reads the file and writes the union of the
//! file and its own set, so two writers revoking different entries both survive instead of the last
//! rewrite dropping the other's. The rewrite is atomic (a temp sibling unique per write, then one rename
//! over the target), so a crash mid-write can never truncate the denylist. Failures leave the file
//! untouched: a set that might be missing a revocation never replaces one that holds it.

use core::fmt;
#[cfg(feature = "fs")]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "fs")]
use std::collections::{BTreeMap, HashSet};
#[cfg(feature = "fs")]
use std::io::Read as _;
#[cfg(all(feature = "fs", unix))]
use std::os::fd::AsRawFd as _;
#[cfg(feature = "fs")]
use std::path::{Path, PathBuf};
#[cfg(feature = "fs")]
use std::process;
use std::sync::Arc;
#[cfg(feature = "fs")]
use std::sync::{Mutex, MutexGuard, PoisonError};
#[cfg(feature = "fs")]
use std::time::Instant;

use data_encoding::HEXLOWER;

use crate::VerifyKey;
use crate::cap::Cap;
#[cfg(feature = "fs")]
use crate::stamp::{FileStamp, STAT_DEBOUNCE};

/// The revocation oracle a [`Gate::Rooted`](crate::Gate::Rooted) or [`Gate::Anchored`](crate::Gate::Anchored)
/// consults on the admit hot path.
///
/// Synchronous by design: admission is synchronous policy, so a revocation check must never require an
/// async runtime. A consumer whose distributed system keeps revocations in Redis, a database, or a gossip
/// set implements this over that store; nauthy's core needs no file and no runtime. The provided
/// file-backed impl is [`Denylist`] behind the `fs` feature.
///
/// The gate asks about EVERY cap presented to it, a foreign badge on the authority-bound path included, so
/// an impl must answer for a cap rooted at an authority it did not issue. Answering `true` there can only
/// refuse, never admit: the oracle is deny-only.
pub trait Revocations {
    /// Whether a grant rooted at `root` whose chain is `ids` is revoked: any of `ids` is recalled, or
    /// `root` is, or anything else the store keys on about them.
    ///
    /// The one question a store answers. A presented cap is asked through
    /// [`is_revoked`](Self::is_revoked), with its [`root`](Cap::root) and its whole chain
    /// ([`Cap::revocation_ids`]: its own blocks, and any it inherited from the grant it was narrowed
    /// from). A [`HeldSlip`](crate::HeldSlip), which keeps a slip's facts and not the slip, is asked with
    /// its signer and its id. Both reach this method, so a cap and a slip known by its facts can never
    /// get two answers about one chain.
    fn is_revoked_ids(&self, root: &VerifyKey, ids: &[RevocationId]) -> bool;

    /// Whether a presented cap is revoked: [`is_revoked_ids`](Self::is_revoked_ids) of its
    /// [`root`](Cap::root) and its chain. Provided, and an impl does not override it: answering a cap
    /// differently from its facts is the drift this shape exists to rule out.
    fn is_revoked(&self, cap: &Cap) -> bool {
        self.is_revoked_ids(&cap.root(), &cap.revocation_ids())
    }

    /// Whether the proven peer's own key is revoked: a device key recalled as a key, not through any cap
    /// it carries. A [`Gate::Rooted`](crate::Gate::Rooted) and a [`Gate::Anchored`](crate::Gate::Anchored)
    /// ask this about the transport-proven dialer first, before they read or verify any presented cap, and
    /// refuse a `true` as
    /// [`Revoked`](crate::Refusal::Revoked), so a revoked device is refused whatever token it presents,
    /// including one minted for it after the revocation. [`Gate::proven`](crate::Gate::proven) asks it too,
    /// so a revoked key gets no witness that presents nothing.
    ///
    /// Provided, answering `false`: a store that keeps no keys keeps the default. A wrapper that holds a
    /// store must forward this as well as [`is_revoked_ids`](Self::is_revoked_ids), because a provided
    /// method a wrapper does not write answers the default, not the inner store.
    fn is_revoked_peer(&self, _peer: &VerifyKey) -> bool {
        false
    }
}

/// A shared store answers as the store it shares, so one instance can back a gate and any other reader
/// that must agree with it, rather than two instances over one file drifting by a refresh.
impl<R: Revocations + ?Sized> Revocations for Arc<R> {
    fn is_revoked_ids(&self, root: &VerifyKey, ids: &[RevocationId]) -> bool {
        R::is_revoked_ids(self, root, ids)
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
    /// [`Denylist`] writes after `id `, so a grep of `to_hex` output against the file finds it.
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

/// Print the id as the hex a denylist file and an audit log carry it in.
impl fmt::Debug for RevocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RevocationId").field(&self.to_hex()).finish()
    }
}

/// The text passed to [`RevocationId::from_hex`] was not valid hex.
#[derive(Debug, thiserror::Error)]
#[error("parse revocation id")]
pub struct RevocationIdParseError;

/// One entry of a [`Denylist`]: a recalled cap id, or a key refused for good.
#[cfg(feature = "fs")]
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Revocation {
    /// A biscuit revocation id: refuses every cap whose chain carries it.
    Id(RevocationId),
    /// A verify key: refuses it as a proven peer, and every cap rooted at it.
    Key(VerifyKey),
}

#[cfg(feature = "fs")]
impl From<RevocationId> for Revocation {
    fn from(id: RevocationId) -> Self {
        Self::Id(id)
    }
}

#[cfg(feature = "fs")]
impl From<VerifyKey> for Revocation {
    fn from(key: VerifyKey) -> Self {
        Self::Key(key)
    }
}

/// A value whose life is an exclusive lock over every writer, in every process, of one denylist file.
///
/// The caller implements it on its own lock guard, so a write shows its lock at the call site and the
/// compiler refuses a write with none. A caller with no lock of its own takes [`Denylist::lock`].
///
/// Within one process nauthy serializes every write to a denylist directory itself (one directory holds
/// one denylist, see [`Denylist`]), so the promise is about OTHER processes, and nauthy cannot check it
/// for a lock it does not know, as
/// [`ProvenPeer`](crate::ProvenPeer) marks a handshake it cannot see. A false promise can lose a
/// revocation: two processes writing at once both return `Ok`, one body lands over the other, and a
/// process that loads the file later admits what the lost entry refused. The writer that lost it still
/// refuses it in memory until it exits.
#[cfg(feature = "fs")]
pub trait Exclusive {
    /// Whether this guard excludes the writers of the denylist at `path`. A write asks before it touches
    /// the file and refuses a `false` with [`WrongLock`](DenylistError::WrongLock).
    ///
    /// Provided, answering `true`: nauthy cannot see a caller's own lock, so it takes that guard at its
    /// word. [`DenylistLock`] answers for the one lock file it holds, by identity: only while that very
    /// file is still the one at `<path>.lock`.
    fn guards(&self, path: &Path) -> bool {
        let _ = path;
        true
    }
}

/// The denylist's own lock: an advisory `flock` on the sibling `<path>.lock`, for a writer with no lock
/// of its own. Held until dropped. [`Denylist::lock`] is the only place nauthy takes a file lock, so a
/// caller that brings its own [`Exclusive`] guard never contends on, or creates, this file.
#[cfg(feature = "fs")]
pub struct DenylistLock {
    /// The denylist this guard was taken for, to name in a `Debug`; what it guards is decided by `held`.
    path: PathBuf,
    held: WriteLock,
}

#[cfg(feature = "fs")]
impl Exclusive for DenylistLock {
    /// Only while the lock file this guard holds is the one now at `<path>.lock`, compared by inode, not
    /// by name. A name can reach one file by several spellings (a case-insensitive or
    /// normalization-insensitive filesystem, a symlinked or `..` parent), and one spelling can reach a
    /// different file after its directory is renamed and recreated; only the inode says which lock the
    /// other writers of `path` take.
    fn guards(&self, path: &Path) -> bool {
        self.held.is_at(path)
    }
}

#[cfg(feature = "fs")]
impl fmt::Debug for DenylistLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DenylistLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// The largest denylist file, in bytes: room for some thirty thousand ids. The file is read on the admit
/// hot path under the store's lock and never pruned, so a local writer that grows it without bound must
/// not be able to turn the next admission into an allocation that size. A larger file is refused at load,
/// ignored by a refresh, which keeps what it holds, and never written: a write that would cross it is
/// refused, so no `Ok` leaves a file the next load refuses.
#[cfg(feature = "fs")]
const MAX_LEN: u64 = 4 << 20;

/// The kind tag of a revocation id line: `id <lowercase hex>`.
#[cfg(feature = "fs")]
const ID: &str = "id";

/// The kind tag of a key line: `key <ed01...>`. A tag, not a length rule, tells an id from a key: a hex id
/// and a key's text share characters, and a length rule would tie the file to today's id size.
#[cfg(feature = "fs")]
const KEY: &str = "key";

/// A persisted, grow-only set of revocation ids and verify keys, read live: the [`Revocations`] impl nauthy
/// ships.
///
/// The file is one entry per line, `id <hex>` or `key <ed01...>`, written sorted so the same set is always
/// the same bytes. nauthy is cross-cutting, so the file location is the consuming process's to choose; this
/// type owns only the load / revoke / check logic over a path.
///
/// UNION ONLY. A check refreshes the held set when the file's stamp changed (debounced, see
/// [`STAT_DEBOUNCE`]), and a refresh ADDS what it reads and never assigns. A stat or read failure, an
/// oversized file, or the file disappearing keeps every entry already held. No write shrinks the file, so a
/// shorter one is a mistake or an attack and must not un-revoke either way.
///
/// A LINE THAT IS NOT AN ENTRY DOES NOT HIDE THE ONES THAT ARE. A running store adds every well-formed line
/// of a partly malformed file and reports the first bad one through
/// [`malformed_line`](Self::malformed_line); a write carries the bad line over verbatim, since the file is
/// deny-only and dropping it might drop a revocation. [`load`](Self::load) still refuses a malformed file:
/// a process starting on a set it can only partly read is the case a human should see.
///
/// A STARTING process is held to the same law by the `<path>.written` witness, the high-water count of
/// entries a durable write left in the file: [`load`](Self::load) refuses a file holding fewer, absent
/// included, with [`Lost`](DenylistError::Lost).
///
/// ONE DIRECTORY HOLDS ONE DENYLIST. Writes in one process take turns per directory, found by its
/// identity rather than its name, so two spellings of one file (`deny` and `DENY` on a case-insensitive
/// filesystem, NFC and NFD forms of one name, a `..` or symlinked parent) can never write at once. A second
/// denylist placed in the same directory loses nothing, but its writes are refused with
/// [`WrongLock`](DenylistError::WrongLock) where its lock file collides; give each denylist its own directory.
///
/// DURABILITY IS A HARD PRECONDITION, and the boundary is the DIRECTORY: a process that starts after the
/// file and its witness are both gone loads an empty set and refuses nothing, because that cannot be told
/// apart from a store that never revoked anything. Keep both in a directory only the node's own user can
/// write, on storage that survives a restart.
#[cfg(feature = "fs")]
pub struct Denylist {
    path: PathBuf,
    /// The held set and what it was read at. A `Mutex` rather than a channel because the admit path asks
    /// synchronously and must see a write made through this instance at once. It is held for a lookup, a
    /// merge, or a refresh's stat and bounded read of a regular file, never across a write, and never
    /// while caller code runs.
    state: Mutex<State>,
}

#[cfg(feature = "fs")]
impl fmt::Debug for Denylist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Denylist")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// The entries held, the stamp of the file they were last read at (`None` = absent, or no stamp), the last
/// moment the file was stat'd, and the first line of the last read that was not an entry.
#[cfg(feature = "fs")]
struct State {
    held: Entries,
    stamp: Option<FileStamp>,
    last_stat: Option<Instant>,
    malformed: Option<u32>,
}

#[cfg(feature = "fs")]
impl Denylist {
    /// Load the denylist from `path`; an absent file is an empty set. The entries and the stamp come from
    /// one opened handle, so a file replaced during this load cannot stamp the old entries as current and
    /// make every later refresh skip a real revocation.
    ///
    /// Refused, never loaded: a malformed line ([`Parse`](DenylistError::Parse)), a file over the size cap
    /// ([`TooLarge`](DenylistError::TooLarge)), and a file holding FEWER entries than its `<path>.written`
    /// witness says a durable write left there, absent included ([`Lost`](DenylistError::Lost)). No write
    /// shrinks the denylist, so a shorter file is a deletion, a truncation, or a crash, and loading it would
    /// un-revoke what went missing. A denylist with no witness loads as it reads.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub fn load(path: PathBuf) -> Result<Self, DenylistError> {
        let (held, stamp) = match open_regular(&path) {
            Ok(mut file) => read_entries_from(&mut file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (Entries::default(), None)
            }
            Err(error) => return Err(DenylistError::Io(error)),
        };
        check_witness(&path, held.len()).map_err(|error| match error {
            WitnessError::Lost { expected } => DenylistError::Lost {
                path: path.clone(),
                expected,
                found: u64::try_from(held.len()).unwrap_or(u64::MAX),
            },
            WitnessError::Io(error) => DenylistError::Io(error),
        })?;
        Ok(Self::unread(path, held, stamp))
    }

    /// An instance over `path` that holds nothing and reads nothing up front: the REPAIR path when
    /// [`load`](Self::load) refuses with [`Lost`](DenylistError::Lost). Its [`revoke`](Self::revoke) unions
    /// whatever the file holds under the lock, so it can never shrink anything, and only a file back at its
    /// high-water mark clears the refusal, so a partial repair does not quietly un-revoke the rest. Use it
    /// to write, never to serve.
    pub fn for_repair(path: PathBuf) -> Self {
        Self::unread(path, Entries::default(), None)
    }

    /// An instance over `path` holding `held`, read at `stamp`, not yet stat'd by a refresh.
    fn unread(path: PathBuf, held: Entries, stamp: Option<FileStamp>) -> Self {
        Self {
            path,
            state: Mutex::new(State {
                held,
                stamp,
                last_stat: None,
                malformed: None,
            }),
        }
    }

    /// Take the denylist's own lock, an advisory `flock` on the sibling `<path>.lock` (created `0600` if
    /// absent), for a writer with no lock of its own. Blocks the calling thread until any other holder
    /// releases, so call it where blocking is allowed. Pass the guard to [`revoke`](Self::revoke) and drop
    /// it when done. Never remove `<path>.lock`: writers serialize on its inode.
    ///
    /// The guard answers for this file only: a write to another denylist refuses it with
    /// [`WrongLock`](DenylistError::WrongLock). Something other than a regular file at `<path>.lock` (a
    /// FIFO, a device) is refused at once rather than waited on. Only unix has a cross-process file lock
    /// at the crate's minimum Rust version, so elsewhere this is `DenylistError::LockUnsupported`.
    #[must_use = "the lock is released when the guard is dropped"]
    pub fn lock(&self) -> Result<DenylistLock, DenylistError> {
        Ok(DenylistLock {
            path: self.path.clone(),
            held: WriteLock::acquire(&self.path)?,
        })
    }

    /// Revoke `entries` and persist, under the lock `held` names. Takes no file lock of its own.
    ///
    /// The entries are drained first, before any lock is taken, so an iterator that asks this store a
    /// question cannot deadlock it; then they join this instance's set, so this process refuses them
    /// whatever happens next. A `held` that does not guard this file is refused with
    /// [`WrongLock`](DenylistError::WrongLock) before the file is touched.
    ///
    /// Then, one write at a time per directory in this process and under the caller's lock across
    /// processes:
    /// read the file, union it into the held set, and if the file already holds every entry of that union,
    /// return without writing, so a repeat pays no `fsync` (a witness left behind by a crash is still
    /// raised to what the file holds). Otherwise write the union once, atomically and durably (the file and
    /// its directory are `fsync`ed, so an `Ok` survives a power cut), owner-only, then raise the
    /// `<path>.written` witness. Writing the union rather than only what is new restores an entry the file
    /// lost while this instance held it, and ids and keys given in one call land in one rename.
    ///
    /// A line on disk that is not an entry is carried after the sorted ones, uncounted, with its bytes as
    /// read except the ASCII whitespace trimmed from its ends. A
    /// read failure, an oversized file, or a union that would grow the file past its cap returns WITHOUT
    /// writing: the file may hold entries this instance cannot see, and replacing it would drop them. The
    /// parent directory must already exist; the consuming process provisions it.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub fn revoke(
        &self,
        held: &impl Exclusive,
        entries: impl IntoIterator<Item = Revocation>,
    ) -> Result<(), DenylistError> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        self.state().held.extend(entries);
        if !held.guards(&self.path) {
            return Err(DenylistError::WrongLock {
                path: self.path.clone(),
            });
        }
        let writers = writers_of(dir_id(&self.path).map_err(DenylistError::Io)?);
        let _one_writer = writers.lock().unwrap_or_else(PoisonError::into_inner);

        let (bytes, read_at) = match open_regular(&self.path) {
            Ok(mut file) => {
                let bytes = read_capped(&mut file).map_err(DenylistError::from_read)?;
                (bytes, stamp_of(&file))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (Vec::new(), None),
            Err(error) => return Err(DenylistError::Io(error)),
        };
        let on_disk = Parsed::from(bytes.as_slice());

        let (body, count, carried) = {
            let mut state = self.state();
            state.held.union(&on_disk.entries);
            if state.held.is_subset(&on_disk.entries) {
                // What was just read is now all this instance holds, so it is current.
                state.stamp = read_at;
                state.malformed = on_disk.first_rejected();
                drop(state);
                return raise_witness(&self.path, on_disk.entries.len()).map_err(DenylistError::Io);
            }
            let lines = state.held.lines();
            let mut body = Vec::new();
            for line in &lines {
                body.extend_from_slice(line.as_bytes());
                body.push(b'\n');
            }
            for rejected in &on_disk.rejected {
                body.extend_from_slice(rejected.bytes);
                body.push(b'\n');
            }
            (body, lines.len(), !on_disk.rejected.is_empty())
        };
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_LEN {
            return Err(DenylistError::TooLarge);
        }
        // Adopt the stamp of the bytes this call wrote, taken from the handle that wrote them, so a
        // replacement renamed in after our rename cannot lend this instance its freshness and make the next
        // refresh skip its revocation.
        let stamp = write_atomically(&self.path, &body, count).map_err(DenylistError::Io)?;
        let mut state = self.state();
        state.stamp = stamp;
        // The carried lines follow the `count` sorted ones in the body just written.
        state.malformed = carried.then(|| u32::try_from(count + 1).unwrap_or(u32::MAX));
        Ok(())
    }

    /// Whether any of `ids` is revoked: the membership query [`is_revoked`](Revocations::is_revoked) runs
    /// over one cap's chain, for a caller that kept the ids and let the cap go. The ids are all a recalled
    /// grant ever matches, so they are all such a caller needs to keep. One lock and one refresh however
    /// many ids are asked about. The ids are drained before the lock is taken, so an iterator that asks
    /// this store a question cannot deadlock it.
    pub fn is_revoked_any<'a>(&self, ids: impl IntoIterator<Item = &'a RevocationId>) -> bool {
        let ids = ids.into_iter().collect::<Vec<_>>();
        let state = self.refreshed();
        ids.into_iter().any(|id| state.held.ids.contains(id))
    }

    /// Whether `key` is revoked: the question a pin or a peer check asks of a key it holds rather than a
    /// cap. [`is_revoked_peer`](Revocations::is_revoked_peer) is this.
    pub fn is_revoked_key(&self, key: &VerifyKey) -> bool {
        self.refreshed().held.keys.contains(key)
    }

    /// The first line (1-based) of the file, as last read, that was not an entry, or `None` when it read
    /// clean. A running store keeps every entry of a malformed file, so this is the one sign that something
    /// in it is being skipped; an operator or a health check reads it.
    pub fn malformed_line(&self) -> Option<u32> {
        self.refreshed().malformed
    }

    /// The file backing this denylist.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The held state, refreshed from disk first if the file changed.
    fn refreshed(&self) -> MutexGuard<'_, State> {
        let mut state = self.state();
        self.refresh(&mut state);
        state
    }

    /// The held state. A panic elsewhere while it was held cannot have removed an entry (nothing does), so
    /// a poisoned lock is still a sound set.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Union the file into the held set if its stamp changed. Synchronous and on the admit hot path, so the
    /// stat is debounced to once per [`STAT_DEBOUNCE`] and the file is read only when it changed.
    ///
    /// Every failure returns with the set untouched: a stat or read error, an oversized file, something
    /// other than a regular file renamed over it, or the file DISAPPEARING. Deletion is not "the denylist is now empty": a `rm` of the file (a botched cleanup, or
    /// a local attacker) must never silently un-revoke. The stamp is taken before the read, so a file
    /// replaced between the two is read under the older stamp; that only costs one extra read on the next
    /// refresh, because the union cannot lose an entry to it.
    fn refresh(&self, state: &mut State) {
        // The first check after construction always stats, so a fresh instance sees the current file at once.
        if let Some(last) = state.last_stat {
            if last.elapsed() < STAT_DEBOUNCE {
                return;
            }
        }
        state.last_stat = Some(Instant::now());
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return;
        };
        let current = FileStamp::of(&meta);
        if FileStamp::unchanged(state.stamp, current) {
            return;
        }
        let Some(bytes) = open_regular(&self.path)
            .ok()
            .and_then(|mut file| read_capped(&mut file).ok())
        else {
            return;
        };
        let parsed = Parsed::from(bytes.as_slice());
        // THE line that makes the denylist monotone. Assigning the parsed set would let a shorter file, an
        // empty one included, un-revoke whatever it left out, live and without a restart. Every
        // well-formed line lands even when another line is bad, so one bad line cannot freeze the set.
        state.held.union(&parsed.entries);
        state.malformed = parsed.first_rejected();
        // A malformed read is current too. Re-reading an unchanged bad file on every refresh would parse up
        // to the whole size cap ten times a second, under the lock every admission takes, and learn
        // nothing; any edit, a repair included, changes the stamp (its inode and ctime move) and is read.
        state.stamp = current;
    }
}

#[cfg(feature = "fs")]
impl Revocations for Denylist {
    /// Any of `ids` is held, or `root` is. For a cap the root is the key `Cap::parse` verified the whole
    /// chain against, so a cap cannot claim its way past this with a root it does not carry, and a revoked
    /// key refuses what it signs next as well as what it signed.
    fn is_revoked_ids(&self, root: &VerifyKey, ids: &[RevocationId]) -> bool {
        let state = self.refreshed();
        state.held.keys.contains(root) || ids.iter().any(|id| state.held.ids.contains(id))
    }

    /// The peer's key is held.
    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.is_revoked_key(peer)
    }
}

/// The well-formed entries of a denylist, by kind.
#[cfg(feature = "fs")]
#[derive(Default)]
pub(crate) struct Entries {
    pub(crate) ids: HashSet<RevocationId>,
    pub(crate) keys: HashSet<VerifyKey>,
}

#[cfg(feature = "fs")]
impl Entries {
    /// How many distinct entries, both kinds: the count the witness records. One count serves both
    /// kinds because no write removes either.
    fn len(&self) -> usize {
        self.ids.len() + self.keys.len()
    }

    fn insert(&mut self, entry: Revocation) {
        match entry {
            Revocation::Id(id) => {
                self.ids.insert(id);
            }
            Revocation::Key(key) => {
                self.keys.insert(key);
            }
        }
    }

    fn union(&mut self, other: &Self) {
        self.ids.extend(other.ids.iter().cloned());
        self.keys.extend(other.keys.iter().copied());
    }

    fn is_subset(&self, other: &Self) -> bool {
        self.ids.is_subset(&other.ids) && self.keys.is_subset(&other.keys)
    }

    /// Every entry as its file line, sorted bytewise over whole lines (so every `id` line precedes every
    /// `key` line) and so one body for the same set every time. Written through
    /// [`RevocationId::to_hex`] and the key's `Display`, and read back through
    /// [`RevocationId::from_hex`] and its `FromStr`, so the file and the API encodings cannot diverge.
    fn lines(&self) -> Vec<String> {
        let ids = self.ids.iter().map(|id| format!("{ID} {}", id.to_hex()));
        let keys = self.keys.iter().map(|key| format!("{KEY} {key}"));
        let mut lines = ids.chain(keys).collect::<Vec<_>>();
        lines.sort();
        lines
    }
}

#[cfg(feature = "fs")]
impl Extend<Revocation> for Entries {
    fn extend<I: IntoIterator<Item = Revocation>>(&mut self, entries: I) {
        entries.into_iter().for_each(|entry| self.insert(entry));
    }
}

/// A denylist body, decoded line by line: every well-formed entry, and every non-blank line that is not
/// one. One bad line never discards the good ones; each caller decides what the bad ones mean.
#[cfg(feature = "fs")]
struct Parsed<'a> {
    entries: Entries,
    rejected: Vec<Rejected<'a>>,
}

/// A non-blank line that was not an entry: where it is, and its bytes with the ASCII whitespace at its ends
/// trimmed, to carry it over. Bytes, not text: a line that is not UTF-8 is one bad line, never a reason to
/// drop the good ones around it.
#[cfg(feature = "fs")]
struct Rejected<'a> {
    line: u32,
    bytes: &'a [u8],
}

#[cfg(feature = "fs")]
impl Parsed<'_> {
    /// The first line that was not an entry, 1-based.
    fn first_rejected(&self) -> Option<u32> {
        self.rejected.first().map(|rejected| rejected.line)
    }
}

#[cfg(feature = "fs")]
impl<'a> From<&'a [u8]> for Parsed<'a> {
    /// Split on `\n` and decode each line on its own, so one line that is not UTF-8 or not an entry is
    /// reported alone and the lines around it still land.
    fn from(bytes: &'a [u8]) -> Self {
        let mut parsed = Parsed {
            entries: Entries::default(),
            rejected: Vec::new(),
        };
        for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            match core::str::from_utf8(line).ok().and_then(decode_line) {
                Some(entry) => parsed.entries.insert(entry),
                None => parsed.rejected.push(Rejected {
                    line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    bytes: line,
                }),
            }
        }
        parsed
    }
}

/// Decode one `<kind> <value>` line, or `None` when it is not one: an unknown kind, a value that does not
/// parse as its kind, or anything but one space between them.
#[cfg(feature = "fs")]
fn decode_line(line: &str) -> Option<Revocation> {
    let (kind, value) = line.split_once(' ')?;
    match kind {
        ID => RevocationId::from_hex(value).ok().map(Revocation::Id),
        KEY => value.parse().ok().map(Revocation::Key),
        _ => None,
    }
}

/// Read, decode and stamp the denylist from ONE already-open handle. The single handle is the invariant:
/// the entries and the stamp describe the same inode, so a path replacement between the open and the read
/// can never pair old entries with the replacement's freshness. A malformed line, an oversized file, or an
/// unreadable body is an error; a stamp the platform will not report degrades to `None`, so the next
/// refresh re-reads rather than trusting a stale stamp. `pub(crate)` so the regression test can drive the
/// single-handle path.
#[cfg(feature = "fs")]
pub(crate) fn read_entries_from(
    file: &mut std::fs::File,
) -> Result<(Entries, Option<FileStamp>), DenylistError> {
    let bytes = read_capped(file).map_err(DenylistError::from_read)?;
    let parsed = Parsed::from(bytes.as_slice());
    if let Some(line) = parsed.first_rejected() {
        return Err(DenylistError::Parse { line });
    }
    Ok((parsed.entries, stamp_of(file)))
}

/// Read at most [`MAX_LEN`] bytes of `file`; more is `FileTooLarge`, found before the excess is buffered.
/// Bytes, not text, so the line decoder judges each line on its own.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[cfg(feature = "fs")]
#[allow(clippy::std_instead_of_core)]
fn read_capped(file: &mut std::fs::File) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_LEN + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LEN {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    Ok(bytes)
}

/// Open `path` for reading only if it is a regular file. The open is non-blocking on unix, so a FIFO
/// renamed over the path returns at once instead of waiting for a writer while the admit path holds the
/// store's lock; anything that is not a regular file (a FIFO, a device, a directory) is then refused, so
/// no read can wait on it or stream from it without end. `NotFound` passes through for the caller to
/// read as absent.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[cfg(feature = "fs")]
#[allow(clippy::std_instead_of_core)]
pub(crate) fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_a_regular_file());
    }
    Ok(file)
}

/// The refusal for a store, witness or lock path that holds something other than a regular file.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[cfg(feature = "fs")]
#[allow(clippy::std_instead_of_core)]
fn not_a_regular_file() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file")
}

/// A directory by identity, not by name: its device and inode on unix, where every spelling of one
/// directory (a `..`, a symlink, a case or Unicode form the filesystem folds) stats to the same pair.
#[cfg(feature = "fs")]
#[cfg(unix)]
type DirId = (u64, u64);

/// Elsewhere the canonical path, the nearest thing to an identity std offers there.
#[cfg(feature = "fs")]
#[cfg(not(unix))]
type DirId = PathBuf;

/// The identity of the directory `path` lives in. The file itself may not exist yet, so only its
/// directory is asked; a directory that does not exist is an error, as the write that follows would be.
#[cfg(feature = "fs")]
#[cfg(unix)]
fn dir_id(path: &Path) -> std::io::Result<DirId> {
    use std::os::unix::fs::MetadataExt as _;

    let meta = std::fs::metadata(parent_of(path))?;
    Ok((meta.dev(), meta.ino()))
}

/// The non-unix twin of `dir_id`.
#[cfg(feature = "fs")]
#[cfg(not(unix))]
fn dir_id(path: &Path) -> std::io::Result<DirId> {
    std::fs::canonicalize(parent_of(path))
}

/// The directory `path` names its file in: its parent, or `.` for a bare file name.
#[cfg(feature = "fs")]
fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// The one write slot for the directory `dir` names, shared by every [`Denylist`] in it in this process.
///
/// A `Mutex` per directory, not per instance or per name: two instances over one file, two spellings of
/// its name, or two threads through one instance may hold the same guard, and nothing but this orders
/// their read-merge-writes. Unordered, the smaller body can land last, and a revocation both callers were
/// told was written is gone from the file. Keyed on the directory's identity because only the
/// filesystem knows which names it folds together; one directory holds one denylist, so a slot per
/// directory is a slot per denylist. The map grows by one entry per directory a process writes, which is
/// a handful; it is never pruned, so two writers can never hold different slots for one directory.
#[cfg(feature = "fs")]
fn writers_of(dir: DirId) -> Arc<Mutex<()>> {
    static WRITERS: Mutex<BTreeMap<DirId, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());
    let mut writers = WRITERS.lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(writers.entry(dir).or_default())
}

/// The stamp of an open handle, or `None` when the platform will not report one.
#[cfg(feature = "fs")]
fn stamp_of(file: &std::fs::File) -> Option<FileStamp> {
    file.metadata().ok().and_then(|meta| FileStamp::of(&meta))
}

/// The sibling `<denylist>.lock` whose stable inode every self-locking writer flocks. `with_extension`
/// would REPLACE an existing extension, letting `caps.deny` and `caps.other` collide on one sibling name,
/// so the suffix is appended to the whole path instead (`with_suffix`). `pub(crate)` so a test can clean it
/// up.
#[cfg(feature = "fs")]
#[cfg(unix)]
pub(crate) fn lock_path(denylist: &Path) -> PathBuf {
    with_suffix(denylist, ".lock")
}

/// A temp sibling unique to ONE write: the denylist path plus `.tmp.<pid>.<seq>`. The pid separates
/// processes and an atomic sequence separates writes within one, so two writers can never share one temp
/// path, and one can never truncate the other's in-flight body. `pub(crate)` so a test can pin the
/// uniqueness.
#[cfg(feature = "fs")]
pub(crate) fn temp_path(denylist: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    with_suffix(denylist, &format!(".tmp.{}.{seq}", process::id()))
}

/// Append `suffix` to the full path, keeping the parent directory.
#[cfg(feature = "fs")]
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut sibling = path.as_os_str().to_os_string();
    sibling.push(suffix);
    PathBuf::from(sibling)
}

/// The exclusive cross-writer lock a [`DenylistLock`] holds.
///
/// The lock is an advisory `flock` on a sibling `<denylist>.lock`, NOT on the denylist itself: the atomic
/// rewrite replaces the denylist's inode each time, so a lock on that moving inode would not serialize two
/// writers. The lock file's inode is stable, so every writer contends on the same one. Being advisory, it
/// only serializes writers that take it; a process that ignores it can still race, as with any advisory
/// lock.
#[cfg(feature = "fs")]
#[cfg(unix)]
struct WriteLock {
    file: std::fs::File,
}

#[cfg(feature = "fs")]
#[cfg(unix)]
impl WriteLock {
    /// Take the exclusive lock, creating the lock file (`0600`) if absent. Blocks (`LOCK_EX`, no
    /// `LOCK_NB`) until any other holder releases, so a concurrent writer waits rather than failing.
    ///
    /// The OPEN never blocks: it is non-blocking, so a FIFO planted at `<denylist>.lock` fails at once
    /// (no reader) instead of waiting for one, and anything that is not a regular file is refused. The
    /// flag does not reach the `flock`, which waits only on `LOCK_NB`.
    fn acquire(denylist: &Path) -> Result<Self, DenylistError> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            // The lock file's contents are never written, so an existing one is opened as it is.
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NONBLOCK)
            .open(lock_path(denylist))
            .map_err(DenylistError::Io)?;
        if !file.metadata().map_err(DenylistError::Io)?.is_file() {
            return Err(DenylistError::Io(not_a_regular_file()));
        }
        // SAFETY: `file` owns a valid fd for the duration of the call, and `flock` only associates an
        // advisory lock with that open file description; it touches no memory.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if locked != 0 {
            return Err(DenylistError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self { file })
    }

    /// Whether the file this lock holds is the one now at `<denylist>.lock`, by device and inode. A lock
    /// file that is gone, or replaced (its directory renamed and recreated), is not the one the next
    /// writer of `denylist` will take, so holding this one excludes nobody there.
    fn is_at(&self, denylist: &Path) -> bool {
        use std::os::unix::fs::MetadataExt as _;

        let (Ok(held), Ok(there)) = (self.file.metadata(), std::fs::metadata(lock_path(denylist)))
        else {
            return false;
        };
        (held.dev(), held.ino()) == (there.dev(), there.ino())
    }
}

#[cfg(feature = "fs")]
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
/// lands at 1.89 and nauthy supports 1.85, and `flock` is unix-only. Rather than hand out a guard that
/// serializes nothing, [`Denylist::lock`] refuses with `LockUnsupported`; a caller that holds a lock of its
/// own still writes. Revisit when the MSRV passes 1.89 (then this becomes `std::fs::File::lock`).
#[cfg(feature = "fs")]
#[cfg(not(unix))]
struct WriteLock;

#[cfg(feature = "fs")]
#[cfg(not(unix))]
impl WriteLock {
    fn acquire(_denylist: &Path) -> Result<Self, DenylistError> {
        Err(DenylistError::LockUnsupported)
    }

    /// Never reached: no lock is ever acquired here.
    fn is_at(&self, _denylist: &Path) -> bool {
        false
    }
}

/// Create the denylist's temp sibling for a whole-body rewrite, owner-only from creation. Opening this ONE
/// handle is what lets [`write_and_stamp`] take the stamp from the bytes it wrote rather than from the path.
///
/// Created new (`O_EXCL`), never opened: a name that already exists, left by a crashed writer or planted
/// as a symlink by anyone who can write the directory, fails with `AlreadyExists` rather than being
/// followed or truncated, and [`create_temp`] moves on to a fresh name. `pub(crate)` so a test can plant
/// the symlink.
#[cfg(feature = "fs")]
#[cfg(unix)]
pub(crate) fn open_tmp(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// The non-unix twin of `open_tmp`; there is no creation mode to tighten.
#[cfg(feature = "fs")]
#[cfg(not(unix))]
pub(crate) fn open_tmp(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// A fresh temp sibling of `path` and its open handle. A name already taken is skipped for the next
/// sequence number, a bounded number of times, so a stale or planted name cannot wedge every write.
// `core::io::ErrorKind` is still unstable, so the kind check reads from `std`.
#[cfg(feature = "fs")]
#[allow(clippy::std_instead_of_core)]
fn create_temp(path: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    const ATTEMPTS: u32 = 16;
    let mut attempt = 1;
    loop {
        let tmp = temp_path(path);
        match open_tmp(&tmp) {
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < ATTEMPTS =>
            {
                attempt += 1;
            }
            opened => return opened.map(|file| (tmp, file)),
        }
    }
}

/// Replace the file at `path` with `body`, which holds `entries` entries, atomically and durably, owner-only,
/// then raise the `<path>.written` witness to `entries`, and return the stamp of the bytes written. The
/// caller holds the writers' lock.
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
#[cfg(feature = "fs")]
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
#[cfg(feature = "fs")]
fn replace_durably(path: &Path, body: &[u8]) -> std::io::Result<Option<FileStamp>> {
    let (tmp, file) = create_temp(path)?;
    let written = write_body(file, body).and_then(|stamp| {
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

/// Write `body` through a fresh temp sibling's handle, owner-only (unix) before the first byte lands, and
/// return the stamp of the bytes written. The rename carries the `0600` mode onto the target.
#[cfg(feature = "fs")]
fn write_body(mut file: std::fs::File, body: &[u8]) -> std::io::Result<Option<FileStamp>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    write_and_stamp(&mut file, body)
}

/// `fsync` the directory holding `path`, so the rename that put the new body there survives a power cut.
/// Unix only: a directory cannot be opened as a file elsewhere.
#[cfg(feature = "fs")]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(parent_of(path))?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The `<path>.written` witness: the high-water count of entries a durable write has left in the store.
///
/// It is not the lock. `<path>.lock` exists only for a self-locking writer and proves only that a write
/// was attempted, and it must never be removed, because its inode is what serializes those writers. The
/// witness is written only after a write is durably in place, and it is the one file an operator removes
/// to accept a loss.
#[cfg(feature = "fs")]
pub(crate) fn witness_path(path: &Path) -> PathBuf {
    with_suffix(path, ".written")
}

/// Raise the witness to `entries` if that is higher than it holds; never lower it. A repair write from a
/// short file therefore leaves the mark where it was, so a partial repair does not clear the refusal.
#[cfg(feature = "fs")]
fn raise_witness(path: &Path, entries: usize) -> std::io::Result<()> {
    let entries = u64::try_from(entries).unwrap_or(u64::MAX);
    if read_witness(path)?.is_some_and(|mark| mark >= entries) {
        return Ok(());
    }
    replace_durably(&witness_path(path), format!("{entries}\n").as_bytes()).map(|_| ())
}

/// The witness's count, or `None` when there is no witness. A witness that is not a count is an error:
/// guessing it would either refuse a sound store forever or accept a lost one. It is read through the
/// same regular-file open as the store and at most [`WITNESS_MAX_LEN`] bytes, so a witness replaced by a
/// FIFO or grown without bound cannot wedge or balloon a load.
// `core::io::ErrorKind` is still unstable, so the error construction reads from `std`.
#[cfg(feature = "fs")]
#[allow(clippy::std_instead_of_core)]
fn read_witness(path: &Path) -> std::io::Result<Option<u64>> {
    let not_a_count = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "store witness is not a count",
        )
    };
    let file = match open_regular(&witness_path(path)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut text = String::new();
    file.take(WITNESS_MAX_LEN + 1).read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > WITNESS_MAX_LEN {
        return Err(not_a_count());
    }
    text.trim().parse().map(Some).map_err(|_| not_a_count())
}

/// The longest witness read, in bytes: the twenty digits of `u64::MAX` and a newline, with room to spare.
#[cfg(feature = "fs")]
const WITNESS_MAX_LEN: u64 = 32;

/// Why a store may not be loaded as it reads.
#[cfg(feature = "fs")]
enum WitnessError {
    /// It holds fewer entries than a durable write once left there.
    Lost {
        /// The high-water count the witness records.
        expected: u64,
    },
    /// The witness could not be read.
    Io(std::io::Error),
}

/// The startup check: a store that `found` entries in, absent counting as zero, must hold at least what
/// its witness says a durable write left there. There is no removal API, so a shorter file can only be a
/// loss, and loading it would turn a deny into an admit.
#[cfg(feature = "fs")]
fn check_witness(path: &Path, found: usize) -> Result<(), WitnessError> {
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
#[cfg(feature = "fs")]
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
    Ok(stamp_of(file).map(|stamp| stamp.with_len(written)))
}

/// Why loading or persisting the denylist failed.
#[cfg(feature = "fs")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DenylistError {
    /// The backing file could not be read or written.
    #[error("access revocation denylist")]
    Io(#[source] std::io::Error),
    /// A line in the file was not an `id` or `key` entry. Only [`load`](Denylist::load) refuses on this; a
    /// running store skips the line and reports it through [`malformed_line`](Denylist::malformed_line).
    #[error("parse revocation denylist line {line}")]
    Parse {
        /// The 1-based line that failed.
        line: u32,
    },
    /// The file is larger than a denylist can be, so it was not read, or a write would have made it so,
    /// so it was not written. [`load`](Denylist::load) and [`revoke`](Denylist::revoke) refuse on this; a
    /// running store keeps what it holds, and a refused write's entries still refuse in this process.
    #[error("revocation denylist file is too large")]
    TooLarge,
    /// The lock passed to [`revoke`](Denylist::revoke) guards another file, so it excludes none of this
    /// file's writers. Nothing was written; the entries still refuse in this process.
    #[error("the lock passed to a write on {} guards another file", path.display())]
    WrongLock {
        /// The denylist the write was for.
        path: PathBuf,
    },
    /// The file holds fewer entries than a durable write once left there (an absent file holds none). No
    /// write shrinks the denylist, so entries were lost to a deletion, a truncation, or a crash, and loading
    /// it would un-revoke them. Three ways out, in order: restore the file; re-revoke everything that went
    /// missing through [`Denylist::for_repair`], which clears this once the file is back at `expected`; or
    /// remove the `<path>.written` witness, which accepts the loss and un-revokes whatever was lost.
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
    /// This platform has no cross-process file lock at the crate's minimum Rust version, so
    /// [`Denylist::lock`] cannot hand out a guard that serializes anything. A caller holding a lock of
    /// its own still writes.
    #[cfg(not(unix))]
    #[error("cross-process denylist locking is unavailable on this platform")]
    LockUnsupported,
}

#[cfg(feature = "fs")]
impl DenylistError {
    /// Name a bounded read's failure: an oversized file is its own refusal, anything else is I/O.
    // `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn from_read(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::FileTooLarge => DenylistError::TooLarge,
            _ => DenylistError::Io(error),
        }
    }
}
