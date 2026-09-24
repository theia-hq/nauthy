//! The key parse and the key text: which 32 bytes are a key, the exact string a key prints, and what
//! parses back.

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::key::{KeyError, KeyParseError, VerifyKey};

// The key vectors. The transport layer's identity parse is tested with the same bytes, in the same order,
// under the same clause names, so a clause that drifts in one crate fails that crate's CI against the other's
// vector.

/// The public key the seed `[7; 32]` binds: a real key, sign bit 0.
const A: [u8; 32] = [
    0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
    0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,
];

/// `A` plus the order-8 torsion point `EIGHT_TORSION[1]`: canonical, not small-order, and a second
/// spelling of `A` whose signatures the holder of `A`'s secret can forge.
const A_PLUS_T: [u8; 32] = [
    0x1f, 0x4f, 0x58, 0x0e, 0x73, 0xac, 0x20, 0x8f, 0x06, 0x76, 0x01, 0x90, 0xe9, 0xed, 0xc6, 0xf5,
    0x91, 0x67, 0x75, 0xda, 0xbd, 0x9c, 0x1c, 0xdc, 0xa3, 0x93, 0x17, 0x5c, 0x2d, 0x6d, 0x10, 0x83,
];

/// The identity point, `y = 1`.
const IDENTITY_POINT: [u8; 32] = {
    let mut key = [0; 32];
    key[0] = 1;
    key
};

/// The point of order two, `y = p - 1`.
const ORDER_TWO: [u8; 32] = {
    let mut key = [0xff; 32];
    key[0] = 0xec;
    key[31] = 0x7f;
    key
};

/// `y = p + 1`: the identity point in its second, non-canonical spelling.
const NON_CANONICAL: [u8; 32] = {
    let mut key = [0xff; 32];
    key[0] = 0xee;
    key[31] = 0x7f;
    key
};

/// `-A`: `A` with its sign bit flipped, sign bit 1.
const MINUS_A: [u8; 32] = {
    let mut key = A;
    key[31] ^= 0x80;
    key
};

fn seeded(seed: [u8; 32]) -> VerifyKey {
    VerifyKey::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&seed))
}

#[test]
fn the_identity_point_is_refused_as_small_order() {
    assert_eq!(
        VerifyKey::try_new(IDENTITY_POINT),
        Err(KeyError::SmallOrder)
    );
}

#[test]
fn the_all_zero_key_is_refused_as_small_order() {
    assert_eq!(VerifyKey::try_new([0; 32]), Err(KeyError::SmallOrder));
}

#[test]
fn the_order_two_point_is_refused_as_small_order() {
    assert_eq!(VerifyKey::try_new(ORDER_TWO), Err(KeyError::SmallOrder));
}

#[test]
fn bytes_off_the_curve_are_refused() {
    assert_eq!(VerifyKey::try_new([2; 32]), Err(KeyError::NotOnCurve));
}

#[test]
fn a_non_canonical_spelling_is_refused() {
    assert_eq!(
        VerifyKey::try_new(NON_CANONICAL),
        Err(KeyError::NotCanonical)
    );
}

#[test]
fn a_torsion_twin_of_a_real_identity_is_refused() {
    assert!(
        VerifyKey::try_new(A).is_ok(),
        "the untwisted key is a real key"
    );
    assert_eq!(VerifyKey::try_new(A_PLUS_T), Err(KeyError::HasTorsion));
}

#[test]
fn a_sign_twin_parses_and_is_a_different_identity() {
    let a = VerifyKey::try_new(A).expect("A is a real key");
    let minus_a = VerifyKey::try_new(MINUS_A).expect("-A is a real key");
    assert_ne!(minus_a, a, "exact bytes name a key; -A is not A");
}

#[test]
fn every_key_a_secret_binds_parses() {
    let mut sign_bit_one = 0;
    for seq in 0u8..200 {
        let key = seeded([seq; 32]);
        assert_eq!(
            VerifyKey::try_new(*key.bytes()),
            Ok(key),
            "seed [{seq}; 32]"
        );
        sign_bit_one += usize::from(key.bytes()[31] >> 7);
    }
    assert!(
        sign_bit_one > 0,
        "the seeds must reach keys with sign bit 1"
    );
}

#[test]
fn a_key_round_trips_through_its_string() {
    let key = seeded([7; 32]);
    assert_eq!(key.to_string().parse::<VerifyKey>(), Ok(key));
}

#[test]
fn a_string_naming_a_torsion_twin_is_refused_at_parse() {
    let text = format!(
        "ed01{}",
        data_encoding::BASE32_NOPAD.encode(&A_PLUS_T).to_lowercase()
    );
    assert_eq!(
        text.parse::<VerifyKey>(),
        Err(KeyParseError::Key(KeyError::HasTorsion))
    );
}

#[test]
fn counter_seeded_keys_are_all_valid_keys() {
    // Seeds shaped as a counter, little-endian in the first eight bytes: read as a key, most of those name
    // no key at all; read as a seed, every one does.
    for seq in 1u64..=10_000 {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&seq.to_le_bytes());
        let key = seeded(seed);
        assert_eq!(VerifyKey::try_new(*key.bytes()), Ok(key), "counter {seq}");
    }
}

/// The shared test vector: key `A`, the one the seed `[7; 32]` binds, in the key text format. Any library
/// that prints an Ed25519 key in this format asserts this same literal for the same bytes. Its body holds
/// both an `s` and an `i` for the lookalike tests below.
const SHARED_VECTOR: &str = "ed015jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwa";

#[test]
fn the_key_text_is_the_shared_vector() {
    let key = VerifyKey::try_new(A).expect("A is a real key");
    assert_eq!(key.to_string(), SHARED_VECTOR);
    assert_eq!(SHARED_VECTOR.parse::<VerifyKey>(), Ok(key));
}

#[test]
fn an_uppercase_key_text_parses() {
    let upper = SHARED_VECTOR.to_ascii_uppercase();
    assert_eq!(
        upper.parse::<VerifyKey>(),
        VerifyKey::try_new(A).map_err(KeyParseError::Key)
    );
}

/// `text` with the first `ascii` after the tag swapped for `lookalike`.
fn swap_first(text: &str, ascii: char, lookalike: char) -> String {
    let (tag, body) = text.split_at(4);
    format!("{tag}{}", body.replacen(ascii, &lookalike.to_string(), 1))
}

#[test]
fn a_long_s_in_place_of_s_is_refused() {
    // U+017F uppercases to ASCII `S` under Unicode rules, so a Unicode fold would read this as the key.
    let text = swap_first(SHARED_VECTOR, 's', '\u{17F}');
    assert_eq!(text.parse::<VerifyKey>(), Err(KeyParseError::BadEncoding));
}

#[test]
fn a_dotless_i_in_place_of_i_is_refused() {
    // U+0131 uppercases to ASCII `I` under Unicode rules.
    let text = swap_first(SHARED_VECTOR, 'i', '\u{131}');
    assert_eq!(text.parse::<VerifyKey>(), Err(KeyParseError::BadEncoding));
}

/// No Montgomery coordinate leaves this crate. A public `u` is the one value that lets a caller key a set
/// on a key's equivalence class instead of its exact bytes, which is the one configuration in which a
/// sign twin is a break, and nauthy performs no Diffie-Hellman that would need one. The scan is
/// stricter than the rule: neither name may appear in any non-test source file.
#[test]
fn no_public_item_returns_a_montgomery_coordinate() {
    // Assembled from halves because this file is under `src/` too.
    let needles = [
        ["to_mont", "gomery"].concat(),
        ["Montgomery", "Point"].concat(),
    ];
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for source in rust_sources(&src).expect("read the crate's sources") {
        if source.to_string_lossy().ends_with("_tests.rs") {
            continue;
        }
        let text = fs::read_to_string(&source).expect("read a source file");
        for needle in &needles {
            assert!(
                !text.contains(needle.as_str()),
                "{}: `{needle}` must not appear in nauthy",
                source.display()
            );
        }
    }
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(rust_sources(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    Ok(found)
}
