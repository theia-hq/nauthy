//! A persisted denylist of revoked capability ids: the offline revocation story for `sheer:` bearer caps.
//!
//! A cap is offline-verifiable, so there is no server to ask "is this revoked?". Instead the exposer keeps
//! its own denylist of biscuit revocation identifiers: revoking a cap records its narrowest block's id, and
//! the gate refuses any presented cap whose chain includes a revoked id (the cap itself, or an ancestor it
//! was attenuated from). Pure-offline, node-local, and it survives restarts, which a short TTL cannot: a
//! TTL ages a leaked cap out eventually but cannot recall it now.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use data_encoding::BASE32_NOPAD;

use crate::cap::Cap;

/// A persisted set of revoked capability ids (biscuit revocation identifiers), one base32 id per line.
///
/// nauthy is cross-cutting, so the file location is the consumer's to choose (tightbeam keeps its own at
/// `~/.config/tightbeam/revoked`); this type owns only the load / revoke / check logic over a path.
pub struct Denylist {
    path: PathBuf,
    ids: HashSet<Vec<u8>>,
}

impl Denylist {
    /// Load the denylist from `path`; an absent file is an empty set.
    // `core::io::ErrorKind` is still unstable (the core_io feature), so the NotFound check reads from
    // `std`; drop this once it lands in core.
    #[allow(clippy::std_instead_of_core)]
    pub async fn load(path: PathBuf) -> Result<Self, DenylistError> {
        let ids = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(decode_id)
                .collect::<Result<HashSet<Vec<u8>>, _>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(error) => return Err(DenylistError::Io(error)),
        };
        Ok(Self { path, ids })
    }

    /// Whether a presented cap is revoked: any id in its chain (the cap itself or an ancestor block) is on
    /// the denylist.
    pub fn is_revoked(&self, cap: &Cap) -> bool {
        cap.revocation_ids().iter().any(|id| self.ids.contains(id))
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
        if self.ids.insert(id) {
            self.persist().await?;
        }
        Ok(())
    }

    /// An empty denylist backed by `path`, before any load. Equivalent to loading an absent file; the
    /// first [`revoke`](Self::revoke) creates and persists the file.
    pub fn empty(path: PathBuf) -> Self {
        Self {
            path,
            ids: HashSet::new(),
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
        let mut lines = self
            .ids
            .iter()
            .map(|id| BASE32_NOPAD.encode(id))
            .collect::<Vec<_>>();
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
