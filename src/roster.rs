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

use ed25519_dalek::{Signature, VerifyingKey};

use crate::VerifyKey;

/// The domain-separating prefix over the signed bytes: a `MAGIC`-prefixed message this key signs can never
/// be confused with a cap or anything else it signs, and the trailing version byte lets a later layout bump
/// it so an old verifier refuses rather than misreads.
const MAGIC: &[u8] = b"theia-roster\x01";

/// The maximum number of members [`SignedRoster::decode`] will parse from an untrusted blob. A DoS bound: a
/// personal fleet is tiny, and a hostile courier must not make a puller allocate for a huge count before the
/// signature is even checked.
const MAX_MEMBERS: usize = 4096;

/// The detached signature length (ed25519).
const SIG_LEN: usize = 64;

/// Take `n` bytes from `bytes` at `*cur`, advancing the cursor, or [`RosterError::Truncated`] if the input
/// runs out. Bounds-checked so untrusted input is a clean error, never a panic.
fn take<'a>(bytes: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8], RosterError> {
    let end = cur.checked_add(n).ok_or(RosterError::Truncated)?;
    let slice = bytes.get(*cur..end).ok_or(RosterError::Truncated)?;
    *cur = end;
    Ok(slice)
}

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

    /// Parse canonical bytes back into a doc, returning the doc and the number of bytes consumed. The inverse
    /// of [`canonical_bytes`](Self::canonical_bytes), bounds-checked so untrusted input is a clean error.
    /// Re-runs [`new`](Self::new)'s sort + dedup, so a blob with out-of-order or duplicate members is
    /// rejected rather than trusted.
    fn parse_canonical(bytes: &[u8]) -> Result<(Self, usize), RosterError> {
        let mut cur = 0;
        if take(bytes, &mut cur, MAGIC.len())? != MAGIC {
            return Err(RosterError::BadMagic);
        }
        let epoch = Epoch(u64::from_be_bytes(
            take(bytes, &mut cur, 8)?
                .try_into()
                .map_err(|_| RosterError::Truncated)?,
        ));
        let count = u32::from_be_bytes(
            take(bytes, &mut cur, 4)?
                .try_into()
                .map_err(|_| RosterError::Truncated)?,
        ) as usize;
        if count > MAX_MEMBERS {
            return Err(RosterError::TooManyMembers);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let node: [u8; VerifyKey::LEN] = take(bytes, &mut cur, VerifyKey::LEN)?
                .try_into()
                .map_err(|_| RosterError::Truncated)?;
            let label_len = usize::from(u16::from_be_bytes(
                take(bytes, &mut cur, 2)?
                    .try_into()
                    .map_err(|_| RosterError::Truncated)?,
            ));
            let label = core::str::from_utf8(take(bytes, &mut cur, label_len)?)
                .map_err(|_| RosterError::LabelBadByte)?
                .parse()?;
            members.push(Member {
                node: VerifyKey::new(node),
                label,
            });
        }
        Ok((Self::new(epoch, members)?, cur))
    }
}

/// A [`RosterDoc`] plus a detached ed25519 signature over its canonical bytes and the key that signed it.
/// Holding one proves NOTHING: [`verify`](SignedRoster::verify) against the signet you actually trust is the
/// security seam, and the ONLY path from a decoded blob to a `&RosterDoc` a caller may trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRoster {
    doc: RosterDoc,
    signer: VerifyKey,
    signature: [u8; SIG_LEN],
}

impl SignedRoster {
    /// Assemble from a freshly-signed doc. Crate-internal: the only signer is `Identity::sign_roster`, which
    /// signs with the signet secret, so a `SignedRoster` a caller can construct is always genuinely signed.
    pub(crate) fn from_parts(doc: RosterDoc, signer: VerifyKey, signature: [u8; SIG_LEN]) -> Self {
        Self {
            doc,
            signer,
            signature,
        }
    }

    /// Verify this blob was signed by `signet` and return the enclosed doc ONLY on success. This is the whole
    /// trust check: a doc signed by a FOREIGN key, or tampered after signing, is rejected here, before any
    /// contact is touched. Mirrors a cap's "roots at the key I trust or nothing".
    pub fn verify(&self, signet: VerifyKey) -> Result<&RosterDoc, RosterError> {
        if self.signer != signet {
            return Err(RosterError::ForeignSigner);
        }
        let verifying =
            VerifyingKey::from_bytes(signet.bytes()).map_err(|_| RosterError::BadSignature)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying
            .verify_strict(&self.doc.canonical_bytes(), &signature)
            .map_err(|_| RosterError::BadSignature)?;
        Ok(&self.doc)
    }

    /// The doc WITHOUT a trust check. Named to shame misuse: for display/debug only, never to hydrate.
    pub fn doc_unverified(&self) -> &RosterDoc {
        &self.doc
    }

    /// The key this blob claims to be signed by (unverified until [`verify`](Self::verify)).
    pub fn signer(&self) -> VerifyKey {
        self.signer
    }

    /// The wire blob the `roster:` handler serves and the puller reads: the doc's canonical bytes (which are
    /// self-delimiting), then the 32-byte signer, then the 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.doc.canonical_bytes();
        out.extend_from_slice(self.signer.bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a wire blob into an UNVERIFIED `SignedRoster` (parse-don't-validate: NO trust check here, call
    /// [`verify`](Self::verify) against the signet you trust). Bounds-checked throughout, so a truncated,
    /// oversized, or trailing-garbage blob is a clean error, never a panic or an allocation blow-up.
    pub fn decode(bytes: &[u8]) -> Result<Self, RosterError> {
        let (doc, consumed) = RosterDoc::parse_canonical(bytes)?;
        let mut cur = consumed;
        let signer: [u8; VerifyKey::LEN] = take(bytes, &mut cur, VerifyKey::LEN)?
            .try_into()
            .map_err(|_| RosterError::Truncated)?;
        let signature: [u8; SIG_LEN] = take(bytes, &mut cur, SIG_LEN)?
            .try_into()
            .map_err(|_| RosterError::Truncated)?;
        if cur != bytes.len() {
            return Err(RosterError::Truncated);
        }
        Ok(Self {
            doc,
            signer: VerifyKey::new(signer),
            signature,
        })
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
    /// The blob's leading magic did not match: not a roster, or a version this build does not know.
    #[error("not a roster (bad magic)")]
    BadMagic,
    /// The blob ended before a field was complete, or carried trailing bytes.
    #[error("roster blob is truncated or malformed")]
    Truncated,
    /// The blob claimed more members than the decode bound allows.
    #[error("roster lists too many members")]
    TooManyMembers,
    /// The blob's signer is not the signet the puller trusts.
    #[error("roster is signed by a key other than the trusted signet")]
    ForeignSigner,
    /// The signature did not verify against the signet.
    #[error("roster signature is invalid")]
    BadSignature,
}
