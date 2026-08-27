//! The capability primitive: a `sheer` bearer token, offline-verifiable, rooted at an exposer's own
//! identity, with no central authority.
//!
//! A [`Cap`] is a [biscuit](biscuit_auth): an ed25519-signed, datalog-attenuable token. Its root key is
//! the exposer's [`NodeId`] key, so verification asks one question, "does this token chain back to the
//! key I am?", answered with pure pubkey identity and no PKI, registry, or server.
//!
//! A cap carries two kinds of check, both *monotone*: appending a block can only ever ADD checks, never
//! remove one, so every operation below either holds the grant the same or narrows it, and broadening is
//! impossible by construction (the crypto, not our code, enforces this).
//! - a **service** check (`check if service($s), $s == "ssh"`): the token is usable only for that service.
//! - an **expiry** check (`check if time($t), $t <= <expiry>`): the token is usable only until that time.
//!
//! A `sheer` link is `sheer:<node-id>.<base32-biscuit>`: it carries the exposer's [`NodeId`] (its public
//! identity, never a secret) alongside the token, so any holder can decode, attenuate, and hand it off
//! entirely offline, and a connector learns which node to dial from the link alone.
//!
//! The lifecycle, all offline except the initial mint (which needs only the exposer's own secret, still
//! no network):
//! - [`Identity::mint`] signs a fresh cap for a service until an expiry (the exposer).
//! - [`Cap::attenuate`] appends a narrower service and/or shorter expiry (any holder, no secret).
//! - delegation is just [`Cap::attenuate`] by a third party: hand the narrowed token onward, and the
//!   exposer still verifies the whole chain without ever seeing the delegation.
//! - [`Identity::verify`] checks a presented cap against this identity for a [`Request`] (service + now).
//!
//! parse-don't-validate: [`Cap::parse`] yields a `Cap` only from a link that decodes and whose signature
//! chain checks against the embedded root. Whether it further *grants* a given request is answered by
//! [`Identity::verify`], which returns the peer identity it is rooted at only when every check passes.

use core::time::Duration;
use std::time::SystemTime;

use biscuit_auth::builder::Algorithm;
use biscuit_auth::macros::{authorizer, biscuit, block};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey};
use data_encoding::BASE32_NOPAD;

use crate::NodeId;
use crate::service::Service;

/// The `sheer:` link scheme prefixing an encoded [`Cap`]. A share-link is `sheer:<node-id>.<base32>`.
pub const SCHEME: &str = "sheer:";

/// The separator between the embedded root [`NodeId`] and the token body inside a link.
const SEPARATOR: char = '.';

/// An exposer's signing identity: the ed25519 keypair whose public half is a [`NodeId`].
///
/// This is the root of every cap it mints. Reconstructed from the exposer's persisted 32-byte secret so
/// caps survive across runs, and it is the same key the transport binds under, so the [`NodeId`] a cap
/// roots at *is* the node peers dial. Holds secret key material, so it never derives `Debug`/`Clone`; its
/// bytes are wiped by [`biscuit_auth`] on drop.
pub struct Identity {
    root: KeyPair,
}

impl Identity {
    /// Build the signing identity from a raw 32-byte ed25519 secret (the persisted node secret).
    ///
    /// The one place a secret enters the cap layer. The public half equals this node's [`NodeId`] key,
    /// so a cap minted here verifies against the identity peers already reach.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, CapError> {
        let private = PrivateKey::from_bytes(secret, Algorithm::Ed25519).map_err(CapError::Key)?;
        Ok(Self {
            root: KeyPair::from(&private),
        })
    }

    /// This identity's [`NodeId`]: the public key a cap roots at and peers dial.
    pub fn node_id(&self) -> NodeId {
        node_id_of(&self.root)
    }

    /// Mint a fresh cap granting `service` until `expiry`, signed by this identity.
    ///
    /// The root grant. The holder may narrow it further offline with [`Cap::attenuate`]; they can never
    /// broaden it, so this is the widest the cap will ever be.
    pub fn mint(&self, service: &Service, expiry: SystemTime) -> Result<Cap, CapError> {
        let token = biscuit!(
            r#"
            check if service($s), $s == {service};
            check if time($t), $t <= {expiry};
            "#,
            service = service.as_str(),
            expiry = expiry,
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.node_id(),
            token,
        })
    }

    /// Verify a presented cap grants `request` against this identity, returning the identity it roots at.
    ///
    /// Grants iff the cap is rooted at this node's key AND every check in the chain passes for the
    /// request: the service matches and the token is unexpired at `request.now`. A foreign root, a
    /// service mismatch, an expired token, or a token narrowed past the request is a denial. Returns this
    /// node's [`NodeId`] on success so a caller can log which identity authorized the grant.
    pub fn verify(&self, cap: &Cap, request: &Request) -> Result<NodeId, CapError> {
        if cap.root != self.node_id() {
            return Err(CapError::ForeignRoot);
        }
        let authorizer = authorizer!(
            r#"
            time({now});
            service({service});
            allow if true;
            "#,
            now = request.now,
            service = request.service.as_str(),
        )
        .build(&cap.token)
        .map_err(CapError::Authorize)?;
        let mut authorizer = authorizer;
        authorizer.authorize().map_err(CapError::Denied)?;
        Ok(cap.root)
    }
}

/// A capability: a token decoded and signature-verified against the root [`NodeId`] embedded in its link.
///
/// Holding a `Cap` proves the bytes were a biscuit that chains to `root`; whether it *grants* a specific
/// request (right service, unexpired) is a separate question answered by [`Identity::verify`].
pub struct Cap {
    root: NodeId,
    token: Biscuit,
}

impl Cap {
    /// Decode a cap from a `sheer:<node-id>.<base32>` link.
    ///
    /// parse-don't-validate at the wire edge: rejects a bad scheme, a malformed [`NodeId`], bad base32,
    /// or bytes whose signature chain does not check against the embedded root. It does NOT evaluate the
    /// caveats (service, expiry); that is [`Identity::verify`]'s job at connect time.
    pub fn parse(link: &str) -> Result<Self, CapError> {
        let body = link.strip_prefix(SCHEME).ok_or(CapError::Scheme)?;
        let (root, encoded) = body.split_once(SEPARATOR).ok_or(CapError::Malformed)?;
        let root = root.parse::<NodeId>().map_err(|_| CapError::Malformed)?;
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(|_| CapError::Encoding)?;
        let public = root_key(root)?;
        // Decoding with the embedded root verifies the signature chain back to it; a token that does not
        // chain to the NodeId it claims is rejected here, before any caveat is ever considered.
        let token = Biscuit::from(&bytes, public).map_err(|_| CapError::Malformed)?;
        Ok(Self { root, token })
    }

    /// The identity this cap is rooted at: the [`NodeId`] a connector should dial and the exposer must be
    /// to verify it.
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// Encode this cap as a `sheer:<node-id>.<base32>` share-link.
    pub fn link(&self) -> Result<String, CapError> {
        let bytes = self.token.to_vec().map_err(CapError::Encode)?;
        Ok(format!(
            "{SCHEME}{}{SEPARATOR}{}",
            self.root,
            BASE32_NOPAD.encode(&bytes).to_lowercase()
        ))
    }

    /// Narrow this cap, offline, by appending a block that adds a tighter service and/or expiry check.
    ///
    /// Monotone by construction: [`biscuit_auth`] only lets a block ADD checks, so the result is always
    /// the same grant or narrower, never broader. Any holder can do this with no secret and no network,
    /// which is exactly what makes delegation work: a third party narrows and hands the token onward, and
    /// the exposer still verifies the whole chain. At least one of `service`/`shorten` must be given, or
    /// this is a no-op and returns [`CapError::EmptyAttenuation`].
    pub fn attenuate(
        &self,
        service: Option<&Service>,
        shorten: Option<SystemTime>,
    ) -> Result<Self, CapError> {
        let token = match (service, shorten) {
            (None, None) => return Err(CapError::EmptyAttenuation),
            (Some(service), None) => self.token.append(block!(
                r#"check if service($s), $s == {service};"#,
                service = service.as_str(),
            )),
            (None, Some(expiry)) => self.token.append(block!(
                r#"check if time($t), $t <= {expiry};"#,
                expiry = expiry,
            )),
            (Some(service), Some(expiry)) => self.token.append(block!(
                r#"
                check if service($s), $s == {service};
                check if time($t), $t <= {expiry};
                "#,
                service = service.as_str(),
                expiry = expiry,
            )),
        }
        .map_err(CapError::Attenuate)?;
        Ok(Self {
            root: self.root,
            token,
        })
    }
}

/// What a presented cap is asked to grant: a service, at a moment in time.
///
/// Built at the verify boundary so `verify` receives an already-valid request. `now` is normally the
/// wall clock; it is a field so a test can pin a moment and prove expiry.
pub struct Request {
    /// The service the connector is asking to reach.
    pub service: Service,
    /// The moment to evaluate expiry against.
    pub now: SystemTime,
}

impl Request {
    /// A request for `service` evaluated at the current wall-clock time.
    pub fn now(service: Service) -> Self {
        Self {
            service,
            now: SystemTime::now(),
        }
    }
}

/// An expiry `duration` from now, for [`Identity::mint`]. A convenience so callers pass `2h` not an
/// absolute instant; a duration so large it would overflow the clock saturates to a century out rather
/// than panicking, which is expiry enough for any real grant.
pub fn expires_in(duration: Duration) -> SystemTime {
    let now = SystemTime::now();
    now.checked_add(duration).unwrap_or_else(|| now + CENTURY)
}

/// A hundred years, the saturating ceiling for [`expires_in`]. Far enough out to be "does not expire" in
/// practice, near enough that `SystemTime` arithmetic never overflows.
const CENTURY: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// The [`NodeId`] whose key is this keypair's public half.
fn node_id_of(root: &KeyPair) -> NodeId {
    let mut bytes = [0u8; NodeId::KEY_LEN];
    // biscuit's PublicKey serializes to exactly 32 ed25519 bytes; the copy pins that into a NodeId key.
    bytes.copy_from_slice(&root.public().to_bytes());
    NodeId::new(bifrost_core::CryptoKind::Ed25519, bytes)
}

/// The biscuit root public key for a [`NodeId`]: the same ed25519 key, read as a verifier root.
fn root_key(node: NodeId) -> Result<PublicKey, CapError> {
    PublicKey::from_bytes(node.key(), Algorithm::Ed25519).map_err(CapError::Key)
}

/// Why a capability operation failed.
///
/// The failure modes a caller must distinguish: a malformed link, a token that does not chain to the
/// expected root, and a token that chains but whose checks deny the request. The underlying
/// [`biscuit_auth`] cause is carried by reference in the source chain, never stringified away.
#[derive(Debug, thiserror::Error)]
pub enum CapError {
    /// The link did not start with the `sheer:` scheme.
    #[error("not a sheer link")]
    Scheme,
    /// The link body was not valid base32.
    #[error("invalid base32 in link")]
    Encoding,
    /// The link's node id, structure, or signature chain was not well formed.
    #[error("malformed capability")]
    Malformed,
    /// A raw ed25519 key was not valid.
    #[error("invalid key")]
    Key(#[source] biscuit_auth::error::Format),
    /// Minting the token failed.
    #[error("mint capability")]
    Mint(#[source] biscuit_auth::error::Token),
    /// Encoding the token to bytes failed.
    #[error("encode capability")]
    Encode(#[source] biscuit_auth::error::Token),
    /// Appending an attenuation block failed.
    #[error("attenuate capability")]
    Attenuate(#[source] biscuit_auth::error::Token),
    /// An attenuation was requested that narrows nothing.
    #[error("attenuation narrows nothing")]
    EmptyAttenuation,
    /// The token did not chain back to the expected root identity.
    #[error("capability is not rooted at this identity")]
    ForeignRoot,
    /// Building the authorizer for the request failed.
    #[error("authorize capability")]
    Authorize(#[source] biscuit_auth::error::Token),
    /// The token chained to the root, but its checks denied the request (wrong service or expired).
    #[error("capability does not grant this request")]
    Denied(#[source] biscuit_auth::error::Token),
}
