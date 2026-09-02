//! Unit tests for the generic signed-document primitive. Authenticity (only the signing key's signature
//! verifies) and a lossless encode/decode round-trip are the load-bearing properties: a payload is opaque,
//! so the whole job here is proving WHO signed the bytes and that they arrived untampered.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::signed::{SignError, Signed};
use crate::{Identity, VerifyKey};

/// A deterministic signing identity for the sign/verify tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).unwrap()
}

#[test]
fn a_signed_document_verifies_against_its_signer() {
    let id = identity(7);
    let signed = id.sign_document(b"hello world");
    assert_eq!(signed.verify(id.node_id()), Ok(b"hello world".as_slice()));
}

#[test]
fn verify_rejects_a_foreign_signer() {
    let signed = identity(7).sign_document(b"payload");
    let stranger = identity(8).node_id();
    assert_eq!(signed.verify(stranger), Err(SignError::ForeignSigner));
}

#[test]
fn verify_rejects_a_tampered_signature() {
    let id = identity(7);
    let mut blob = id.sign_document(b"payload").encode();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    let tampered = Signed::decode(&blob).unwrap();
    assert_eq!(tampered.verify(id.node_id()), Err(SignError::BadSignature));
}

#[test]
fn verify_rejects_a_tampered_payload() {
    // Flip a payload byte after signing: the blob still decodes, but the signature no longer covers these
    // bytes, so verify fails.
    let id = identity(7);
    let mut blob = id.sign_document(b"payload").encode();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    // The signature is fixed-width at the front, so the last byte is payload; flip it and re-verify.
    let tampered = Signed::decode(&blob).unwrap();
    assert_eq!(tampered.verify(id.node_id()), Err(SignError::BadSignature));
}

#[test]
fn encode_then_decode_round_trips_and_verifies() {
    let id = identity(7);
    let signed = id.sign_document(b"a longer document body");
    let decoded = Signed::decode(&signed.encode()).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.verify(id.node_id()),
        Ok(b"a longer document body".as_slice())
    );
}

#[test]
fn an_empty_payload_signs_and_verifies() {
    // The header (signer + signature) alone is a valid blob with an empty payload; verify must accept it.
    let id = identity(7);
    let signed = id.sign_document(b"");
    let decoded = Signed::decode(&signed.encode()).unwrap();
    assert_eq!(decoded.verify(id.node_id()), Ok(b"".as_slice()));
}

#[test]
fn decode_rejects_a_blob_shorter_than_its_header() {
    // A blob too short to hold the 32-byte signer + 64-byte signature is truncated, not an empty payload.
    let short = vec![0u8; VerifyKey::LEN + 63];
    assert_eq!(Signed::decode(&short), Err(SignError::Truncated));
}
