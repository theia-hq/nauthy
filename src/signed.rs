//! A signed document: opaque bytes an identity vouches for with a detached ed25519 signature.
//!
//! The generic primitive under any signed artifact rooted at an identity. [`Identity::sign_document`]
//! signs a payload with the same ed25519 key the identity mints caps with, and [`Signed::verify`] against
//! the key you actually trust is the whole security seam: only that key's secret makes a signature the
//! key verifies, so any holder may relay the blob and none can forge it. The payload is OPAQUE
//! here (nauthy attaches no meaning to the bytes): a consumer canonicalizes and parses its own document,
//! and this layer only proves who signed the bytes and that they were not tampered.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::VerifyKey;
use crate::cap::SIGNED_DOCUMENT_CONTEXT;

/// The detached signature length (ed25519).
const SIG_LEN: usize = 64;

/// An opaque payload plus the identity that signed it and its detached ed25519 signature.
///
/// Holding one proves NOTHING on its own: [`verify`](Signed::verify) against the key you actually trust is
/// the security seam, and the ONLY path from a decoded blob to a payload a caller may trust. The signer is
/// carried so a blob is self-describing on the wire, but it is UNTRUSTED until `verify` roots it at the key
/// the caller names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    payload: Vec<u8>,
    signer: VerifyKey,
    signature: [u8; SIG_LEN],
}

impl Signed {
    /// Assemble from a freshly-signed payload. Crate-internal: the only signer is
    /// [`Identity::sign_document`](crate::Identity::sign_document), which signs with a real secret, so a
    /// `Signed` a caller can construct is always genuinely signed (a foreign or forged signer can only
    /// enter through [`decode`](Signed::decode), where [`verify`](Signed::verify) then rejects it).
    pub(crate) fn from_parts(
        payload: Vec<u8>,
        signer: VerifyKey,
        signature: [u8; SIG_LEN],
    ) -> Self {
        Self {
            payload,
            signer,
            signature,
        }
    }

    /// Verify this blob was signed by `authority` and return the enclosed payload ONLY on success. This is
    /// the whole trust check: a blob signed by a FOREIGN key, or tampered after signing, is rejected here.
    ///
    /// The claimed `signer` field is used ONLY for the equality gate; the actual signature check keys off
    /// the caller's trusted `authority`, so a blob claiming a signer it did not sign for cannot slip
    /// through. The signature is checked over the domain-separation tag `SIGNED_DOCUMENT_CONTEXT` followed
    /// by the payload, the same message [`sign_document`](crate::Identity::sign_document) signed, so a
    /// document signature can never be replayed as any other kind of signature this identity makes.
    /// `verify_strict` rejects the ed25519 malleability (non-canonical `S`, small-order `R`) that would let
    /// a second valid signature exist over the same bytes. Proves AUTHENTICITY, not freshness: a caller that
    /// needs to reject a stale-but-genuine replay owns that check (there is no epoch memory here).
    pub fn verify(&self, authority: VerifyKey) -> Result<&[u8], SignError> {
        if self.signer != authority {
            return Err(SignError::ForeignSigner);
        }
        let verifying =
            VerifyingKey::from_bytes(authority.bytes()).map_err(|_| SignError::BadSignature)?;
        let signature = Signature::from_bytes(&self.signature);
        // Verify over TAG || payload, matching sign_document. The tag domain-separates a document signature
        // from a biscuit authority-block signature made by the same key (see SIGNED_DOCUMENT_CONTEXT).
        let mut message = SIGNED_DOCUMENT_CONTEXT.to_vec();
        message.extend_from_slice(&self.payload);
        verifying
            .verify_strict(&message, &signature)
            .map_err(|_| SignError::BadSignature)?;
        Ok(&self.payload)
    }

    /// The on-wire form one node serves and another reads: the 32-byte signer, the 64-byte signature, then
    /// the payload bytes verbatim (which run to the end of the blob, so no length prefix is needed). The
    /// domain-separation tag is a signing-time prefix only, never stored, so the payload here is exactly the
    /// caller's opaque bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VerifyKey::LEN + SIG_LEN + self.payload.len());
        out.extend_from_slice(self.signer.bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a wire blob into an UNVERIFIED `Signed` (parse-don't-validate: NO trust check here, call
    /// [`verify`](Signed::verify) against the key you trust). The 32-byte signer and 64-byte signature are
    /// fixed-width at the front; everything after is the payload. A blob too short to hold both is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignError> {
        let header = VerifyKey::LEN + SIG_LEN;
        let head = bytes.get(..header).ok_or(SignError::Truncated)?;
        let mut signer = [0u8; VerifyKey::LEN];
        signer.copy_from_slice(&head[..VerifyKey::LEN]);
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&head[VerifyKey::LEN..]);
        Ok(Self {
            payload: bytes[header..].to_vec(),
            signer: VerifyKey::new(signer),
            signature,
        })
    }
}

/// Why a signed document could not be verified or decoded.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    /// The blob ended before its fixed-width signer + signature header was complete.
    #[error("signed blob is truncated")]
    Truncated,
    /// The blob's signer is not the key the verifier trusts.
    #[error("signed by a key other than the trusted one")]
    ForeignSigner,
    /// The signature did not verify against the trusted key.
    #[error("signature is invalid")]
    BadSignature,
}
