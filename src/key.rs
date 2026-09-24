//! The identity a cap roots at: a raw ed25519 public (verifying) key.
//!
//! nauthy names a peer by its 32-byte ed25519 public key, the same key a transport handshake proves the
//! peer holds. This is a standalone newtype so nauthy carries no dependency on any transport crate: it
//! only needs the key's bytes and its string form, not the reach machinery behind it.

use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;

/// The suite tag at the front of a key's text: `ed01` is Ed25519. The key text format is the tag, then the
/// 32 key bytes in RFC 4648 base32, lowercase, unpadded. Any library that prints an Ed25519 key in this
/// format prints exactly this text; `the_key_text_is_the_shared_vector` pins it.
const TAG: &str = "ed01";

/// A peer identity nauthy authorizes: a raw 32-byte ed25519 public (verifying) key.
///
/// This is the key a cap roots at and a transport handshake proves the peer holds. Its string form is the
/// suite tag `ed01`, then the base32-lowercase key body. The bytes are a plain ed25519 public
/// key, so a `VerifyKey` is interchangeable with any transport that identifies a peer by its ed25519 key:
/// a link embeds this string form and round-trips across that boundary with no conversion at the
/// wire.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct VerifyKey([u8; Self::LEN]);

impl VerifyKey {
    /// The length of the raw key material, in bytes.
    pub const LEN: usize = 32;

    /// Wrap raw ed25519 public-key bytes.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The raw public key bytes.
    pub const fn bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for VerifyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{TAG}{}", BASE32_NOPAD.encode(&self.0).to_lowercase())
    }
}

impl FromStr for VerifyKey {
    type Err = KeyParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (tag, encoded) = text
            .split_at_checked(TAG.len())
            .ok_or(KeyParseError::TooShort)?;
        if !tag.eq_ignore_ascii_case(TAG) {
            return Err(KeyParseError::UnknownSuite);
        }
        let raw = decode_base32(encoded).ok_or(KeyParseError::BadEncoding)?;
        let bytes = <[u8; Self::LEN]>::try_from(raw).map_err(|_| KeyParseError::WrongLength)?;
        Ok(Self(bytes))
    }
}

/// Decode unpadded base32 text in either case. Case folding is ASCII-only and any non-ASCII input is
/// refused first: a Unicode fold maps some non-ASCII letters onto ASCII ones (`ſ` to `S`, `ı` to `I`),
/// which would let text that is not the key's text decode to the same bytes.
pub(crate) fn decode_base32(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.is_ascii() {
        return None;
    }
    BASE32_NOPAD
        .decode(encoded.to_ascii_uppercase().as_bytes())
        .ok()
}

/// Why a string could not be parsed into a [`VerifyKey`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyParseError {
    /// The input was shorter than the suite tag.
    #[error("identity string too short")]
    TooShort,
    /// The suite tag was not recognized.
    #[error("unknown crypto suite tag")]
    UnknownSuite,
    /// The key body was not valid base32.
    #[error("invalid base32 encoding")]
    BadEncoding,
    /// The decoded key was not the expected length.
    #[error("wrong key length")]
    WrongLength,
}
