//! A persisted set of peer keys approved to connect, for pairing mode.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::NodeId;

/// A persisted set of peer keys approved to connect, grown by consent. One node id per line.
///
/// nauthy is cross-cutting, so the file location is the consumer's to choose (tightbeam keeps its own at
/// `~/.config/tightbeam/approved`); this type owns only the load/approve/persist logic over a path it is
/// handed.
pub struct Approvals {
    path: PathBuf,
    keys: HashSet<NodeId>,
}

impl Approvals {
    /// Load the approved set from `path`; an absent file is an empty set.
    // `core::io::ErrorKind` is still unstable (the core_io feature), so the NotFound check below reads
    // from `std`; drop this once it lands in core.
    #[allow(clippy::std_instead_of_core)]
    pub async fn load(path: PathBuf) -> Result<Self, ApprovalsError> {
        let keys = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|line| line.parse::<NodeId>().map_err(ApprovalsError::Parse))
                .collect::<Result<HashSet<NodeId>, _>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(error) => return Err(ApprovalsError::Io(error)),
        };
        Ok(Self { path, keys })
    }

    /// The approved keys.
    pub fn keys(&self) -> &HashSet<NodeId> {
        &self.keys
    }

    /// The file backing this set.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Approve a peer and persist the set.
    pub async fn approve(&mut self, peer: NodeId) -> Result<(), ApprovalsError> {
        if self.keys.insert(peer) {
            self.persist().await?;
        }
        Ok(())
    }

    async fn persist(&self) -> Result<(), ApprovalsError> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(ApprovalsError::Io)?;
        }
        let mut lines = self.keys.iter().map(NodeId::to_string).collect::<Vec<_>>();
        lines.sort();
        tokio::fs::write(&self.path, lines.join("\n") + "\n")
            .await
            .map_err(ApprovalsError::Io)
    }
}

/// Why loading or persisting the approved set failed.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalsError {
    /// The backing file could not be read or written.
    #[error("access approved set")]
    Io(#[source] std::io::Error),
    /// A line in the file was not a valid node id.
    #[error("parse approved node id")]
    Parse(#[source] bifrost_core::NodeIdParseError),
}
