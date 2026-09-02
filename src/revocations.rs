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

use data_encoding::BASE32_NOPAD;

use crate::cap::Cap;

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
    ids: HashSet<Vec<u8>>,
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
        let mut ids = cap.revocation_ids();
        // A biscuit always has at least its authority block, so `pop` yields the narrowest id; stay total.
        let Some(id) = ids.pop() else {
            return Ok(());
        };
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
                .map(|id| BASE32_NOPAD.encode(id))
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
) -> Result<(HashSet<Vec<u8>>, Option<(SystemTime, u64)>), DenylistError> {
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

/// Decode a denylist file body into a set of raw revocation ids.
fn parse_ids(text: &str) -> Result<HashSet<Vec<u8>>, DenylistError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(decode_id)
        .collect()
}

/// Decode one base32 revocation-id line into raw bytes.
fn decode_id(line: &str) -> Result<Vec<u8>, DenylistError> {
    BASE32_NOPAD
        .decode(line.to_uppercase().as_bytes())
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
