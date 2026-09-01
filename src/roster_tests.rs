//! Unit tests for the roster payload + its canonical encoding. Determinism (the signature depends only on
//! logical content, never input order) and the parse-don't-validate label guard are the load-bearing
//! properties: a signature over ambiguous bytes is a forgeable signature.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::str::FromStr as _;

use crate::VerifyKey;
use crate::roster::{Epoch, Member, RosterDoc, RosterError, RosterLabel};

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
