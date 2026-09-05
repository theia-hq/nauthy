//! The identity a cap roots at: a raw ed25519 public (verifying) key.
//!
//! nauthy names a peer by its 32-byte ed25519 public key, the same key a transport handshake proves the
//! peer holds. This is a standalone newtype so nauthy carries no dependency on any transport crate: it
//! only needs the key's bytes and its string form, not the reach machinery behind it.

use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;

/// The four-character wire tag prefixing a key's string form.
///
/// SHARED BY CONVENTION with `bifrost_core::id` (its `CryptoKind::Ed25519` tag). A [`VerifyKey`] and a
/// `bifrost_core::NodeId` for the same ed25519 key MUST render to the same string, because a `sheer:` link
/// embeds that string and both sides parse it: if this tag ever diverges from bifrost's, minted links stop
/// round-tripping across the boundary silently. Change one, change both.
const TAG: &str = "bf01";

/// A peer identity nauthy authorizes: a raw 32-byte ed25519 public (verifying) key.
///
/// This is the key a cap roots at and a transport handshake proves the peer holds. Its string form is a
/// four-character suite tag `bf01` then the base32-lowercase key body, identical to a `bifrost_core::NodeId`
/// for the same key, so a `sheer:` link is portable across the nauthy/bifrost boundary with no conversion at
/// the wire.
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
        if tag != TAG {
            return Err(KeyParseError::UnknownSuite);
        }
        let raw = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(|_| KeyParseError::BadEncoding)?;
        let bytes = <[u8; Self::LEN]>::try_from(raw).map_err(|_| KeyParseError::WrongLength)?;
        Ok(Self(bytes))
    }
}

/// Why a string could not be parsed into a [`VerifyKey`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyParseError {
    /// The input was shorter than the four-character suite tag.
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
