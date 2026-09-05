//! Unit tests for the generic signed-document primitive. Authenticity (only the signing key's signature
//! verifies) and a lossless encode/decode round-trip are the load-bearing properties: a payload is opaque,
//! so the whole job here is proving WHO signed the bytes and that they arrived untampered. Plus the
//! domain-separation regression: a document signature can never be reused as a biscuit block signature.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::cap::SIGNED_DOCUMENT_CONTEXT;
use crate::signed::{SignError, Signed};
use crate::{Identity, VerifyKey};

/// A deterministic signing identity for the sign/verify tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).unwrap()
}

/// The detached ed25519 signature a real [`Identity::sign_document`] produced, read back off the wire blob
/// (32-byte signer, then the 64-byte signature).
fn document_signature(id: &Identity, bytes: &[u8]) -> Signature {
    let blob = id.sign_document(bytes).encode();
    let raw: [u8; 64] = blob[VerifyKey::LEN..VerifyKey::LEN + 64]
        .try_into()
        .unwrap();
    Signature::from_bytes(&raw)
}

#[test]
fn a_signed_document_verifies_against_its_signer() {
    let id = identity(7);
    let signed = id.sign_document(b"hello world");
    assert_eq!(
        signed.verify(id.verifying_key()),
        Ok(b"hello world".as_slice())
    );
}

#[test]
fn verify_rejects_a_foreign_signer() {
    let signed = identity(7).sign_document(b"payload");
    let stranger = identity(8).verifying_key();
    assert_eq!(signed.verify(stranger), Err(SignError::ForeignSigner));
}

#[test]
fn verify_rejects_a_tampered_signature() {
    let id = identity(7);
    let mut blob = id.sign_document(b"payload").encode();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    let tampered = Signed::decode(&blob).unwrap();
    assert_eq!(
        tampered.verify(id.verifying_key()),
        Err(SignError::BadSignature)
    );
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
    assert_eq!(
        tampered.verify(id.verifying_key()),
        Err(SignError::BadSignature)
    );
}

#[test]
fn encode_then_decode_round_trips_and_verifies() {
    let id = identity(7);
    let signed = id.sign_document(b"a longer document body");
    let decoded = Signed::decode(&signed.encode()).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.verify(id.verifying_key()),
        Ok(b"a longer document body".as_slice())
    );
}

#[test]
fn an_empty_payload_signs_and_verifies() {
    // The header (signer + signature) alone is a valid blob with an empty payload; verify must accept it.
    let id = identity(7);
    let signed = id.sign_document(b"");
    let decoded = Signed::decode(&signed.encode()).unwrap();
    assert_eq!(decoded.verify(id.verifying_key()), Ok(b"".as_slice()));
}

#[test]
fn decode_rejects_a_blob_shorter_than_its_header() {
    // A blob too short to hold the 32-byte signer + 64-byte signature is truncated, not an empty payload.
    let short = vec![0u8; VerifyKey::LEN + 63];
    assert_eq!(Signed::decode(&short), Err(SignError::Truncated));
}

#[test]
fn a_document_signature_is_domain_separated_from_the_raw_bytes() {
    // The mechanism: sign_document signs TAG || bytes, so the produced signature verifies over the TAGGED
    // message and NEVER over the raw bytes. The raw-bytes case is exactly what a spliced biscuit block
    // signature would need (see the two-version forgery test below).
    let victim = identity(1);
    let bytes = b"attacker-influenced bytes";
    let sig = document_signature(&victim, bytes);
    let vk = VerifyingKey::from_bytes(victim.verifying_key().bytes()).unwrap();
    assert!(
        vk.verify_strict(bytes, &sig).is_err(),
        "the signature must not verify over the raw bytes"
    );
    let mut tagged = SIGNED_DOCUMENT_CONTEXT.to_vec();
    tagged.extend_from_slice(bytes);
    assert!(
        vk.verify_strict(&tagged, &sig).is_ok(),
        "the signature is over TAG || bytes"
    );
}

#[test]
fn a_document_signature_cannot_forge_a_biscuit_block_signature_v0_or_v1() {
    // Mount the confused-deputy forgery (F1) for BOTH biscuit crypto signature versions. An attacker crafts
    // the exact authority-block SIGNING PAYLOAD biscuit verifies (v0: payload||alg||next_key, NO prefix; v1:
    // \0BLOCK\0...). If the victim could be tricked into producing a signature valid over that payload, the
    // attacker would hold a forged authority-block signature (a minted member(true) badge). The victim signs
    // only via sign_document (TAG || bytes), so for each version we assert the produced signature does NOT
    // verify over the biscuit payload, i.e. cannot be spliced as that block's signature. The control (a raw
    // signature, no tag) DOES verify, proving the tag is the sole cause. Byte layout tracks
    // biscuit-auth 6.0.0 `crypto::mod::generate_*_block_signature_payload_{v0,v1}`.
    let victim = identity(1);
    let vk = VerifyingKey::from_bytes(victim.verifying_key().bytes()).unwrap();
    // A stand-in Block protobuf: begins with a valid field key (0x0a = field 1, wire type 2), which is what
    // makes a real v0 payload NOT start with our tag. The exact contents do not matter to the signature.
    let block_data: &[u8] = &[0x0a, 0x02, 0x08, 0x03, 0x12, 0x04, b'm', b'e', b'm', b'b'];
    let next_key = [7u8; 32];
    let alg_le = 0i32.to_le_bytes(); // Ed25519

    // v0: no prefix at all.
    let mut v0 = block_data.to_vec();
    v0.extend_from_slice(&alg_le);
    v0.extend_from_slice(&next_key);

    // v1: the \0BLOCK\0 framing.
    let mut v1 = b"\0BLOCK\0\0VERSION\0".to_vec();
    v1.extend_from_slice(&1u32.to_le_bytes());
    v1.extend_from_slice(b"\0PAYLOAD\0");
    v1.extend_from_slice(block_data);
    v1.extend_from_slice(b"\0ALGORITHM\0");
    v1.extend_from_slice(&alg_le);
    v1.extend_from_slice(b"\0NEXTKEY\0");
    v1.extend_from_slice(&next_key);

    // The same ed25519 key sign_document uses, as a raw signer for the control (no tag).
    let raw_signer = SigningKey::from_bytes(&[1u8; 32]);

    for payload in [v0, v1] {
        let control = raw_signer.sign(&payload);
        assert!(
            vk.verify_strict(&payload, &control).is_ok(),
            "control: without the tag the victim's signature over the payload IS a valid block signature"
        );
        let sig = document_signature(&victim, &payload);
        assert!(
            vk.verify_strict(&payload, &sig).is_err(),
            "a sign_document signature must never verify over a raw biscuit block signing payload"
        );
    }
}

#[test]
fn the_domain_tag_first_byte_cannot_begin_any_biscuit_block_signing_payload() {
    // Pin the load-bearing invariant so a future tag rename is a deliberate re-check, not a silent
    // regression (Adversary condition on M3.1). See SIGNED_DOCUMENT_CONTEXT.
    let first = SIGNED_DOCUMENT_CONTEXT[0];
    // v1 payloads begin with \0 (\0BLOCK\0...); a tag beginning with \0 could masquerade as a v1 payload.
    assert_ne!(
        first, 0x00,
        "tag must not begin with the v1 payload's leading NUL byte"
    );
    // v0 payloads begin with the block protobuf, whose first byte is a field key (field << 3 | wire_type),
    // wire_type in {0,1,2,5}. 0x6e = 'n' = field 13 wire-type 6 (illegal), so a v0 block can never start
    // with the tag. If the tag's first byte were a legal wire type, this guard trips.
    let wire_type = first & 0x07;
    assert!(
        !matches!(wire_type, 0 | 1 | 2 | 5),
        "tag's first byte must not be a legal protobuf field-key wire type"
    );
}
