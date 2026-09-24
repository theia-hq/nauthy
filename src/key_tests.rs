//! The key text: the exact string a key prints, and what parses back.

use crate::key::{KeyParseError, VerifyKey};

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

/// Key bytes `[37; 32]`, whose key text holds an `s` to imitate.
const LOOKALIKE_BYTES: [u8; 32] = [37; 32];

/// `text` with the first `ascii` after the tag swapped for `lookalike`.
fn swap_first(text: &str, ascii: char, lookalike: char) -> String {
    let (tag, body) = text.split_at(4);
    format!("{tag}{}", body.replacen(ascii, &lookalike.to_string(), 1))
}

#[test]
fn a_long_s_in_place_of_s_is_refused() {
    // U+017F uppercases to ASCII `S` under Unicode rules, so a Unicode fold would read this as the key.
    let text = swap_first(&VerifyKey::new(LOOKALIKE_BYTES).to_string(), 's', '\u{17F}');
    assert_eq!(text.parse::<VerifyKey>(), Err(KeyParseError::BadEncoding));
}

#[test]
fn a_dotless_i_in_place_of_i_is_refused() {
    // U+0131 uppercases to ASCII `I` under Unicode rules.
    let text = swap_first(SHARED_VECTOR, 'i', '\u{131}');
    assert_eq!(text.parse::<VerifyKey>(), Err(KeyParseError::BadEncoding));
}
