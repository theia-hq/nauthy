//! Unit tests for the roster payload + its canonical encoding. Determinism (the signature depends only on
//! logical content, never input order) and the parse-don't-validate label guard are the load-bearing
//! properties: a signature over ambiguous bytes is a forgeable signature.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::str::FromStr as _;

use crate::roster::{Epoch, Member, RosterDoc, RosterError, RosterLabel, SignedRoster};
use crate::{Identity, VerifyKey};

/// A deterministic signing identity for the sign/verify tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).unwrap()
}

fn sample_doc() -> RosterDoc {
    RosterDoc::new(Epoch(9), vec![member(1, "desk"), member(2, "ci-runner")]).unwrap()
}

fn key(n: u8) -> VerifyKey {
    VerifyKey::new([n; 32])
}

fn member(node: u8, label: &str) -> Member {
    Member {
        node: key(node),
        label: RosterLabel::from_str(label).unwrap(),
    }
}

#[test]
fn canonical_bytes_are_order_independent() {
    // The same members handed in opposite orders must sign identically: `new` sorts by node bytes, so the
    // canonical encoding is a pure function of the SET, not the caller's insertion order.
    let forward = RosterDoc::new(Epoch(7), vec![member(1, "desk"), member(2, "phone")]).unwrap();
    let reversed = RosterDoc::new(Epoch(7), vec![member(2, "phone"), member(1, "desk")]).unwrap();
    assert_eq!(forward.canonical_bytes(), reversed.canonical_bytes());
    assert_eq!(forward, reversed);
}

#[test]
fn canonical_bytes_change_with_every_field() {
    let base = RosterDoc::new(Epoch(1), vec![member(1, "desk")]).unwrap();
    let other_epoch = RosterDoc::new(Epoch(2), vec![member(1, "desk")]).unwrap();
    let other_node = RosterDoc::new(Epoch(1), vec![member(9, "desk")]).unwrap();
    let other_label = RosterDoc::new(Epoch(1), vec![member(1, "phone")]).unwrap();
    let extra_member = RosterDoc::new(Epoch(1), vec![member(1, "desk"), member(2, "phone")]).unwrap();

    let bytes = base.canonical_bytes();
    assert_ne!(bytes, other_epoch.canonical_bytes());
    assert_ne!(bytes, other_node.canonical_bytes());
    assert_ne!(bytes, other_label.canonical_bytes());
    assert_ne!(bytes, extra_member.canonical_bytes());
}

#[test]
fn canonical_bytes_are_domain_separated() {
    // The signed bytes lead with the roster magic, so this key's roster signature can never be replayed as
    // a signature over anything else it signs.
    let doc = RosterDoc::new(Epoch(1), vec![member(1, "desk")]).unwrap();
    assert!(doc.canonical_bytes().starts_with(b"theia-roster\x01"));
}

#[test]
fn labels_reject_ambiguous_bytes() {
    assert_eq!(RosterLabel::from_str(""), Err(RosterError::LabelEmpty));
    assert_eq!(RosterLabel::from_str("a/b"), Err(RosterError::LabelSlash));
    assert_eq!(RosterLabel::from_str("a b"), Err(RosterError::LabelBadByte));
    assert_eq!(RosterLabel::from_str("a\nb"), Err(RosterError::LabelBadByte));
    assert_eq!(
        RosterLabel::from_str(&"x".repeat(RosterLabel::MAX_LEN + 1)),
        Err(RosterError::LabelTooLong)
    );
    assert!(RosterLabel::from_str("ci-runner").is_ok());
}

#[test]
fn new_rejects_a_duplicate_node() {
    let err = RosterDoc::new(Epoch(1), vec![member(3, "a"), member(3, "b")]).unwrap_err();
    assert_eq!(err, RosterError::DuplicateNode(key(3)));
}

#[test]
fn new_sorts_members_by_node() {
    let doc = RosterDoc::new(Epoch(1), vec![member(5, "e"), member(1, "a"), member(3, "c")]).unwrap();
    let nodes: Vec<_> = doc.members().iter().map(|m| *m.node.bytes()).collect();
    assert_eq!(nodes, vec![[1u8; 32], [3u8; 32], [5u8; 32]]);
}

#[test]
fn a_signed_roster_verifies_against_its_signer() {
    // The signer key equals the identity's node_id (so biscuit and ed25519-dalek derive the SAME public key
    // from one secret), and the doc comes back ONLY through verify against that key.
    let id = identity(7);
    let doc = sample_doc();
    let signed = id.sign_roster(&doc);
    assert_eq!(signed.signer(), id.node_id());
    assert_eq!(signed.verify(id.node_id()), Ok(&doc));
}

#[test]
fn verify_rejects_a_foreign_signet() {
    let signed = identity(7).sign_roster(&sample_doc());
    let stranger = identity(8).node_id();
    assert_eq!(signed.verify(stranger), Err(RosterError::ForeignSigner));
}

#[test]
fn verify_rejects_a_tampered_signature() {
    let id = identity(7);
    let mut blob = id.sign_roster(&sample_doc()).encode();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    let tampered = SignedRoster::decode(&blob).unwrap();
    assert_eq!(tampered.verify(id.node_id()), Err(RosterError::BadSignature));
}

#[test]
fn verify_rejects_a_tampered_doc() {
    // Flip an epoch byte: the blob still decodes (any u64 is a valid epoch), but its canonical bytes no
    // longer match what the signature covers, so verify fails.
    let id = identity(7);
    let mut blob = id.sign_roster(&sample_doc()).encode();
    blob[15] ^= 0xff;
    let tampered = SignedRoster::decode(&blob).unwrap();
    assert_eq!(tampered.verify(id.node_id()), Err(RosterError::BadSignature));
}

#[test]
fn encode_then_decode_round_trips_and_verifies() {
    let id = identity(7);
    let signed = id.sign_roster(&sample_doc());
    let decoded = SignedRoster::decode(&signed.encode()).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(decoded.verify(id.node_id()), Ok(&sample_doc()));
}

#[test]
fn decode_rejects_truncated_trailing_and_bad_magic() {
    let blob = identity(7).sign_roster(&sample_doc()).encode();
    assert_eq!(
        SignedRoster::decode(&blob[..blob.len() - 1]),
        Err(RosterError::Truncated)
    );
    let mut trailing = blob.clone();
    trailing.push(0);
    assert_eq!(SignedRoster::decode(&trailing), Err(RosterError::Truncated));
    assert_eq!(
        SignedRoster::decode(b"not-a-roster-blob-here"),
        Err(RosterError::BadMagic)
    );
}
