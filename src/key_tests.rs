//! The key text: the exact string a key prints, and what parses back.

use crate::key::VerifyKey;

/// The shared test vector: key bytes `[1; 32]` in the key text format. Any library that prints an
/// Ed25519 key in this format asserts this same literal for the same bytes.
const SHARED_VECTOR: &str = "ed01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";

#[test]
fn the_key_text_is_the_shared_vector() {
    let key = VerifyKey::new([1; 32]);
    assert_eq!(key.to_string(), SHARED_VECTOR);
    assert_eq!(SHARED_VECTOR.parse::<VerifyKey>(), Ok(key));
}

#[test]
fn an_uppercase_key_text_parses() {
    let upper = SHARED_VECTOR.to_ascii_uppercase();
    assert_eq!(upper.parse::<VerifyKey>(), Ok(VerifyKey::new([1; 32])));
}
