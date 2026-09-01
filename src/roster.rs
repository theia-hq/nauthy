//! The membership snapshot an operator's signet vouches for: the payload of a signed roster.
//!
//! B1 (deliberation 28, D1) is bootstrap roster-sync: one member node serves the operator's fleet
//! membership to a fresh device, SIGNED by the signet so a courier that merely relays the blob cannot forge
//! it. This module is the payload and its canonical encoding. The signer and verifier
//! ([`Identity::sign_roster`](crate::Identity) / [`SignedRoster::verify`](crate::SignedRoster)) live beside
//! it, in [`cap`](crate::cap), because they reuse the same ed25519 key the identity already holds.
//!
//! A member entry is (who, what the operator calls it) and NOTHING else: no last-seen (a pattern-of-life
//! oracle, delib-28 fix 1) and no capability (a roster that grants is a coordinator, delib-28 fix 2). Both
//! are TYPE properties here, unrepresentable rather than merely omitted.

use core::fmt;
use core::str::FromStr;

use crate::VerifyKey;

/// The domain-separating prefix over the signed bytes: a `MAGIC`-prefixed message this key signs can never
/// be confused with a cap or anything else it signs, and the trailing version byte lets a later layout bump
/// it so an old verifier refuses rather than misreads.
const MAGIC: &[u8] = b"theia-roster\x01";

/// A monotonically-increasing version of an operator's roster, bumped each time the snapshot is re-cut (a
/// member added or removed). It orders two snapshots a device might see from two courier nodes: the higher
/// epoch is newer. It is NOT a timestamp (no wall clock, so no pattern-of-life leak) and NOT a per-member
/// field (no last-seen): it versions the WHOLE doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u64);

/// A member's advertised label: one non-empty segment, no slash, no whitespace or control bytes, bounded so
/// the length-prefixed encoding is total. Parse-don't-validate at construction so the canonical encoding can
/// never carry a byte that would reframe the signed bytes at the puller (a smuggled newline, a slash that
/// reads as a path). Same discipline as `swoosh`'s `DeviceLabel`, restated here so nauthy carries no swoosh
/// dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterLabel(String);

impl RosterLabel {
    /// The maximum label length in bytes. Small: a device label (`desk`, `ci-runner`) is never long, and a
    /// bound keeps the `u16` length prefix in the canonical encoding total.
    pub const MAX_LEN: usize = 255;

    /// The label as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RosterLabel {
    type Err = RosterError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            return Err(RosterError::LabelEmpty);
        }
        if text.len() > Self::MAX_LEN {
            return Err(RosterError::LabelTooLong);
        }
        if text.contains('/') {
            return Err(RosterError::LabelSlash);
        }
        if text
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(RosterError::LabelBadByte);
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for RosterLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One member advertisement: a fleet node's identity and the operator's own label for it, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member node's identity: the key it is dialed at and its badge is bound to.
    pub node: VerifyKey,
    /// The operator's device label for this member (`ci-runner`, `desk`). A display/suggestion string, not
    /// authority: the puller keeps its OWN petnames (names are local).
    pub label: RosterLabel,
}

/// The membership snapshot an operator's signet vouches for: a set of members at an epoch. This is the
/// payload that gets signed. Sorted and de-duplicated at construction so its canonical bytes are a pure
/// function of its logical content (two docs with the same members in any input order sign identically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterDoc {
    epoch: Epoch,
    // invariant: sorted by node bytes, unique by node (upheld by `new`).
    members: Vec<Member>,
}

impl RosterDoc {
    /// Build a doc from an epoch and members. Sorts by `node` bytes and rejects a duplicate node (two labels
    /// for one key is operator error, not a merge case), so the stored order is canonical and
    /// [`canonical_bytes`](Self::canonical_bytes) is deterministic regardless of caller insertion order.
    pub fn new(epoch: Epoch, mut members: Vec<Member>) -> Result<Self, RosterError> {
        members.sort_by(|a, b| a.node.bytes().cmp(b.node.bytes()));
        if let Some(pair) = members.windows(2).find(|pair| pair[0].node == pair[1].node) {
            return Err(RosterError::DuplicateNode(pair[0].node));
        }
        Ok(Self { epoch, members })
    }

    /// The roster's epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The members, in canonical (node-sorted) order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The exact bytes that get signed and verified. Stable across runs and machines: the same logical doc
    /// yields the same bytes yields the same signature. Layout (all integers big-endian): `MAGIC` domain
    /// tag, then `epoch:u64`, then `member_count:u32`, then for each member in sorted order the raw
    /// `node:[u8; 32]`, a `label_len:u16`, and the label's UTF-8 bytes. Fixed field order, fixed-width keys,
    /// sorted members, and length-prefixed labels make it a pure function of the doc's content, so no
    /// delimiter can be spoofed and no insertion order can change the signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAGIC.len() + 12 + self.members.len() * 40);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        // A fleet is small; the count never approaches u32::MAX, and the cast is deterministic.
        out.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        for member in &self.members {
            out.extend_from_slice(member.node.bytes());
            let label = member.label.0.as_bytes();
            // RosterLabel bounds the length to MAX_LEN (< u16::MAX), so this cast never truncates.
            out.extend_from_slice(&(label.len() as u16).to_be_bytes());
            out.extend_from_slice(label);
        }
        out
    }
}

/// Why a roster could not be built (or, in [`cap`](crate::cap), verified).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    /// A member label was empty.
    #[error("roster label is empty")]
    LabelEmpty,
    /// A member label exceeded [`RosterLabel::MAX_LEN`].
    #[error("roster label is too long")]
    LabelTooLong,
    /// A member label contained a `/`.
    #[error("roster label cannot contain '/'")]
    LabelSlash,
    /// A member label contained whitespace or a control byte.
    #[error("roster label cannot contain whitespace or control bytes")]
    LabelBadByte,
    /// Two members shared one node identity.
    #[error("roster lists node {0} twice")]
    DuplicateNode(VerifyKey),
}
