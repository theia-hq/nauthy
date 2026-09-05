//! Offline revocation for `sheer:` bearer caps: the [`Revocations`] oracle the gate consults, and a
//! file-backed [`FileDenylist`] that implements it.
//!
//! A cap is offline-verifiable, so there is no server to ask "is this revoked?". Instead the issuer keeps
//! its own set of biscuit revocation identifiers: revoking a cap records its narrowest block's id, and the
//! gate refuses any presented cap whose chain includes a revoked id (the cap itself, or an ancestor it was
//! attenuated from). Pure-offline, node-local, and it survives restarts, which a short TTL cannot: a TTL
//! ages a leaked cap out eventually but cannot recall it now.
//!
//! [`Revocations`] is the seam. It is a synchronous, one-method trait, so a consumer whose distributed
//! system keeps revocations in Redis, a database, or a gossip set implements it over that store and needs
//! no file and no async runtime. The batteries-included impl is [`FileDenylist`] (behind the `tokio-fs`
//! feature), a persisted set of ids on disk.
//!
//! Revocation through [`FileDenylist`] is LIVE: [`is_revoked`](FileDenylist::is_revoked) re-reads the file
//! when its mtime changes, so a revocation written by a separate process takes effect on the next
//! connection to a long-running issuer; it does not wait for a restart. The file's mtime is the freshness
//! signal; the reload is a small, rare read (only when the file actually changed), guarded by interior
//! mutability so the gate's synchronous admit path stays synchronous.

#[cfg(feature = "tokio-fs")]
use core::time::Duration;
#[cfg(feature = "tokio-fs")]
use std::collections::HashSet;
#[cfg(feature = "tokio-fs")]
use std::path::{Path, PathBuf};
#[cfg(feature = "tokio-fs")]
use std::sync::{Mutex, PoisonError};
#[cfg(feature = "tokio-fs")]
use std::time::{Instant, SystemTime};

use data_encoding::HEXLOWER;

use crate::cap::Cap;

/// The revocation oracle a [`Gate::Rooted`](crate::Gate::Rooted) consults on the admit hot path.
///
/// Synchronous by design: admission is synchronous policy, so a revocation check must never require an
/// async runtime. A consumer whose distributed system keeps revocations in Redis, a database, or a gossip
/// set implements this over that store; nauthy's core needs no file and no runtime. The provided
/// file-backed impl is [`FileDenylist`] behind the `tokio-fs` feature.
pub trait Revocations {
    /// Whether a presented cap is revoked: any id in its chain (the cap's own blocks, including any it
    /// inherited from the grant it was attenuated from) is recalled. See [`Cap::revocation_ids`].
    fn is_revoked(&self, cap: &Cap) -> bool;
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
/// the load / revoke / check logic over a path. The loaded set is behind a [`Mutex`] with the mtime it was
/// read at, so a check can refresh it in place when the file changed underneath a running process.
///
/// DURABILITY IS A HARD PRECONDITION: the backing file must live on durable storage that survives a
/// restart. A restart on ephemeral storage resurrects every revoked cap, because [`load`](Self::load) of an
/// absent file is an empty set, and an empty set revokes nothing.
#[cfg(feature = "tokio-fs")]
pub struct FileDenylist {
    path: PathBuf,
    state: Mutex<State>,
}

/// The loaded ids, the `(mtime, len)` stamp of the file they were read at (`None` = the file was absent
/// when loaded), and the last moment we stat'd the file. The length pairs with mtime so a change within one
/// coarse mtime tick is still seen: a revoke only ever GROWS the file, so a differing length is a reliable
/// "changed" signal on its own.
#[cfg(feature = "tokio-fs")]
struct State {
    ids: HashSet<RevocationId>,
    stamp: Option<(SystemTime, u64)>,
    last_stat: Option<Instant>,
}

/// The admit hot path calls [`is_revoked`](FileDenylist::is_revoked) once per connection, but a revocation
/// written by another process only needs to be seen within a short window. So the refresh stats the file at
/// most once per this interval rather than on every admit under the lock; a revocation goes live within one
/// interval, which is well inside "the next connection" the doc promises. `pub(crate)` so a timing-sensitive
/// test can wait past it deterministically.
#[cfg(feature = "tokio-fs")]
pub(crate) const STAT_DEBOUNCE: Duration = Duration::from_millis(100);

#[cfg(feature = "tokio-fs")]
impl FileDenylist {
    /// Load the denylist from `path`; an absent file is an empty set.
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
        let chain = cap.revocation_ids();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        chain.iter().any(|id| state.ids.contains(id))
    }

    /// Reload the ids in place if the backing file's mtime differs from what we last read. Synchronous and
    /// on the admit hot path, so it debounces the stat to at most once per [`STAT_DEBOUNCE`] and re-reads
    /// only on change.
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
            Ok(meta) => meta.modified().ok().map(|mtime| (mtime, meta.len())),
            // Missing file: keep the last-known set. If one was ever loaded, this is deletion, not empty.
            Err(_) => return,
        };
        if current == state.stamp {
            return;
        }
        let ids = match std::fs::read_to_string(&self.path) {
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
    /// atomically rewrites the file and adopts the `(mtime, len)` stamp so our OWN write triggers no
    /// redundant reload on the next check. A caller that already holds an id it recorded when the cap was
    /// minted (an issuer's audit index from grantee to root id) can revoke by that id directly, without still
    /// holding the cap the id came from.
    pub async fn revoke_id(&mut self, id: RevocationId) -> Result<(), DenylistError> {
        let inserted = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.ids.insert(id)
        };
        if inserted {
            self.persist().await?;
            // Adopt the (mtime, len) we just wrote so our own write does not trigger a redundant reload.
            if let Ok((mtime, len)) = tokio::fs::metadata(&self.path)
                .await
                .and_then(|meta| Ok((meta.modified()?, meta.len())))
            {
                self.state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .stamp = Some((mtime, len));
            }
        }
        Ok(())
    }

    /// An empty denylist backed by `path`, before any load. Equivalent to loading an absent file; the
    /// first [`revoke`](Self::revoke) creates and persists the file.
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

    async fn persist(&self) -> Result<(), DenylistError> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(DenylistError::Io)?;
        }
        let mut lines = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            // Encode through RevocationId::to_hex so the file and the API encoding cannot diverge: the file
            // is exactly what to_hex writes, and decode_id reads it back through from_hex.
            state
                .ids
                .iter()
                .map(RevocationId::to_hex)
                .collect::<Vec<_>>()
        };
        lines.sort();
        let body = lines.join("\n") + "\n";
        // Atomic replace: write a temp sibling, then rename over the target. A crash mid-write can never
        // truncate the denylist and silently bring a revoked cap back to life; the rename is all-or-nothing.
        let tmp = self.path.with_extension("tmp");
        tokio::fs::write(&tmp, body)
            .await
            .map_err(DenylistError::Io)?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .map_err(DenylistError::Io)
    }
}

#[cfg(feature = "tokio-fs")]
impl Revocations for FileDenylist {
    fn is_revoked(&self, cap: &Cap) -> bool {
        FileDenylist::is_revoked(self, cap)
    }
}

/// Read and decode the denylist file; an absent file is an empty set. Returns the ids and the file's
/// `(mtime, len)` stamp (`None` if absent).
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[cfg(feature = "tokio-fs")]
#[allow(clippy::std_instead_of_core)]
#[allow(clippy::type_complexity)]
async fn read_ids(
    path: &Path,
) -> Result<(HashSet<RevocationId>, Option<(SystemTime, u64)>), DenylistError> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => {
            let ids = parse_ids(&text)?;
            let stamp = tokio::fs::metadata(path)
                .await
                .ok()
                .and_then(|meta| Some((meta.modified().ok()?, meta.len())));
            Ok((ids, stamp))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((HashSet::new(), None)),
        Err(error) => Err(DenylistError::Io(error)),
    }
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
pub enum DenylistError {
    /// The backing file could not be read or written.
    #[error("access revocation denylist")]
    Io(#[source] std::io::Error),
    /// A line in the file was not a valid lowercase-hex revocation id.
    #[error("parse revocation id")]
    Parse,
}
