//! A persisted denylist of revoked capability ids: the offline revocation story for `sheer:` bearer caps.
//!
//! A cap is offline-verifiable, so there is no server to ask "is this revoked?". Instead the exposer keeps
//! its own denylist of biscuit revocation identifiers: revoking a cap records its narrowest block's id, and
//! the gate refuses any presented cap whose chain includes a revoked id (the cap itself, or an ancestor it
//! was attenuated from). Pure-offline, node-local, and it survives restarts, which a short TTL cannot: a
//! TTL ages a leaked cap out eventually but cannot recall it now.
//!
//! Revocation is LIVE: [`is_revoked`](Denylist::is_revoked) re-reads the file whenever its mtime changes,
//! so a revocation written by a separate process takes effect on the next connection to a long-running
//! exposer; it does not wait for a restart. The file's mtime is the freshness signal; the reload is a
//! small, rare read (only when the file actually changed), guarded by interior mutability so the gate's
//! synchronous admit path stays synchronous.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use data_encoding::{BASE32_NOPAD, HEXLOWER};

use crate::cap::Cap;

/// A biscuit revocation identifier: the opaque, per-block id whose presence in a [`Denylist`] revokes a cap
/// (one entry of [`Cap::revocation_ids`]). It is an OPAQUE HANDLE: nauthy never interprets its bytes and
/// construction does NOT verify they name a real block. A bogus id simply never matches a presented cap's
/// chain, so a wrong id can only ever over-deny, never grant, which is why [`from_bytes`](Self::from_bytes)
/// and [`from_hex`](Self::from_hex) are plain wrappers, not validating parsers.
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

    /// The id as lowercase hex, the form an issuer's audit log records it in.
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

/// A persisted set of revoked capability ids (biscuit revocation identifiers), one base32 id per line.
///
/// nauthy is cross-cutting, so the file location is the consuming process's to choose; this type owns only
/// the load / revoke / check logic over a path. The loaded set is behind a [`Mutex`] with the mtime it was
/// read at, so a check can refresh it in place when the file changed underneath a running process.
pub struct Denylist {
    path: PathBuf,
    state: Mutex<State>,
}

/// The loaded ids and the `(mtime, len)` stamp of the file they were read at (`None` = the file was absent
/// when loaded). The length pairs with mtime so a change within one coarse mtime tick is still seen: a
/// revoke only ever GROWS the file, so a differing length is a reliable "changed" signal on its own.
struct State {
    ids: HashSet<RevocationId>,
    stamp: Option<(SystemTime, u64)>,
}

impl Denylist {
    /// Load the denylist from `path`; an absent file is an empty set.
    pub async fn load(path: PathBuf) -> Result<Self, DenylistError> {
        let (ids, stamp) = read_ids(&path).await?;
        Ok(Self {
            path,
            state: Mutex::new(State { ids, stamp }),
        })
    }

    /// Whether a presented cap is revoked: any id in its chain (the cap's own blocks, including any it
    /// inherited from the grant it was attenuated from) is on the denylist.
    ///
    /// Refreshes from disk first if the file changed since the last read, so a revocation written by
    /// another process is honored by a long-running exposer without a restart. The
    /// mtime check is a cheap stat; the file is re-read only when it actually changed.
    pub fn is_revoked(&self, cap: &Cap) -> bool {
        let chain = cap.revocation_ids();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        chain.iter().any(|id| state.ids.contains(id))
    }

    /// Reload the ids in place if the backing file's mtime differs from what we last read. Synchronous and
    /// on the admit hot path, so it stats every call but re-reads only on change.
    ///
    /// Fail closed on every uncertainty: a stat/read error, a parse failure, OR the file DISAPPEARING all
    /// leave the last-known set intact and return. Deletion is not "the denylist is now empty": a `rm` of
    /// the file (a botched cleanup, or a local attacker) must never silently un-revoke every recalled cap.
    /// A denylist that never had a file stays empty (nothing to un-revoke); revocations only ever grow a
    /// file, and a fresh file appearing is picked up through the `Ok` stat arm below.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut State) {
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
            state
                .ids
                .iter()
                .map(|id| BASE32_NOPAD.encode(id.as_bytes()))
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

/// Read and decode the denylist file; an absent file is an empty set. Returns the ids and the file's
/// `(mtime, len)` stamp (`None` if absent).
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
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
fn parse_ids(text: &str) -> Result<HashSet<RevocationId>, DenylistError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(decode_id)
        .collect()
}

/// Decode one base32 revocation-id line into a [`RevocationId`].
fn decode_id(line: &str) -> Result<RevocationId, DenylistError> {
    BASE32_NOPAD
        .decode(line.to_uppercase().as_bytes())
        .map(RevocationId::from_bytes)
        .map_err(|_| DenylistError::Parse)
}

/// Why loading or persisting the denylist failed.
#[derive(Debug, thiserror::Error)]
pub enum DenylistError {
    /// The backing file could not be read or written.
    #[error("access revocation denylist")]
    Io(#[source] std::io::Error),
    /// A line in the file was not a valid base32 revocation id.
    #[error("parse revocation id")]
    Parse,
}
