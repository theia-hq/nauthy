//! The capability primitive: a `sheer` bearer token, offline-verifiable, rooted at an exposer's own
//! identity, with no central authority.
//!
//! A [`Cap`] is a [biscuit](biscuit_auth): an ed25519-signed, datalog-attenuable token. Its root key is
//! the exposer's [`VerifyKey`] key, so verification asks one question, "does this token chain back to the
//! key I am?", answered with pure pubkey identity and no PKI, registry, or server.
//!
//! A cap carries two kinds of check, both *monotone*: appending a block can only ever ADD checks, never
//! remove one, so every operation below either holds the grant the same or narrows it, and broadening is
//! impossible by construction (the crypto, not our code, enforces this).
//! - a **service** check (`check if service($s), $s == "ssh"`): the token is usable only for that service.
//! - an **expiry** check (`check if time($t), $t <= <expiry>`): the token is usable only until that time.
//!
//! A `sheer` link is `sheer:<node-id>.<base32-biscuit>`: it carries the exposer's [`VerifyKey`] (its public
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
use biscuit_auth::macros::{authorizer, biscuit, block, fact};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::VerifyKey;
use crate::service::Service;
use crate::signed::Signed;

/// The `sheer:` link scheme prefixing an encoded [`Cap`]. A share-link is `sheer:<node-id>.<base32>`.
pub const SCHEME: &str = "sheer:";

/// The separator between the embedded root [`VerifyKey`] and the token body inside a link.
const SEPARATOR: char = '.';

/// The maximum encoded token length [`Cap::parse`] accepts (~8 KiB decoded). A capability is a small
/// token, so this is generous; it bounds the base32 decode and the O(blocks) signature-chain work, which
/// run before any trust check, so an oversized link cannot burn a verifier's CPU un-refused.
const MAX_ENCODED_LEN: usize = 13_200;

/// The maximum number of blocks [`Cap::parse`] accepts: the authority block plus a bounded delegation
/// chain. Verification is O(blocks) and a legitimate chain is short, so a many-block token is refused.
const MAX_BLOCKS: usize = 16;

/// An exposer's signing identity: the ed25519 keypair whose public half is a [`VerifyKey`].
///
/// This is the root of every cap it mints. Reconstructed from the exposer's persisted 32-byte secret so
/// caps survive across runs, and it is the same key the transport binds under, so the [`VerifyKey`] a cap
/// roots at *is* the node peers dial. Holds secret key material, so it never derives `Debug`/`Clone`; its
/// bytes are wiped by [`biscuit_auth`] on drop.
pub struct Identity {
    root: KeyPair,
    /// The same ed25519 secret as `root`, as a raw signer for detached signatures over documents (the
    /// roster). Derived from the same 32-byte seed at construction, so its public half equals
    /// [`node_id`](Self::node_id): a roster this signs verifies against the same key a cap roots at.
    signing: SigningKey,
}

impl Identity {
    /// Build the signing identity from a raw 32-byte ed25519 secret (the persisted node secret).
    ///
    /// The one place a secret enters the cap layer. The public half equals this node's [`VerifyKey`] key,
    /// so a cap minted here verifies against the identity peers already reach.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, CapError> {
        let private = PrivateKey::from_bytes(secret, Algorithm::Ed25519).map_err(CapError::Key)?;
        Ok(Self {
            root: KeyPair::from(&private),
            signing: SigningKey::from_bytes(secret),
        })
    }

    /// This identity's [`VerifyKey`]: the public key a cap roots at and peers dial.
    pub fn node_id(&self) -> VerifyKey {
        node_id_of(&self.root)
    }

    /// Sign an opaque document with this identity's ed25519 key, producing a self-verifying blob. The signer
    /// is THIS identity, never a courier that later serves it: only this secret can produce a signature that
    /// verifies against this identity's [`VerifyKey`], so any node may hold and relay the blob and none can
    /// forge it. Reuses the same key that mints caps (no new secret material), as a plain detached ed25519
    /// signature over the caller's bytes: a signed document, not a capability. The bytes are OPAQUE here (a
    /// consumer canonicalizes and parses its own payload); this only proves who signed them.
    pub fn sign_document(&self, bytes: &[u8]) -> Signed {
        let signature = self.signing.sign(bytes);
        Signed::from_parts(bytes.to_vec(), self.node_id(), signature.to_bytes())
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

    /// Mint a membership badge for the device `bound_to`, granting [`Service::membership`] until `expiry`.
    ///
    /// A device badge, not a service slip: it asserts "the bearer is one of my devices", which a
    /// [`Family`](crate::Gate::Family) gate honors as whole-node admission. It is BOUND to `bound_to`, so it
    /// grants only when the *proven* dialer is that device: a badge observed in flight and replayed from a
    /// DIFFERENT key verifies against no one. That is the binding's real job: it defends the short-lived
    /// SELF-SIGNED badge a signet holder mints per dial against cross-key replay. It does NOT harden a
    /// badge that travels beside its own device seed (as the provisioned authkey does: whoever steals that
    /// blob already holds the seed, so binding buys nothing there). Only the signet (this identity) can mint
    /// one, since minting needs the root secret; a delegated slip can never be attenuated into a membership
    /// badge (attenuation only adds checks, [`Cap::attenuate`]).
    pub fn mint_member(&self, bound_to: VerifyKey, expiry: SystemTime) -> Result<Cap, CapError> {
        // Membership is a STRUCTURAL fact in the authority block, not a service name. `member(true)` is
        // asserted here and checked by the gate's `allow if member(true)` query ([`Cap::verify_member_at_root`]).
        // Because biscuit only trusts facts from the authority block (origin 0), a fact added in an
        // attenuation block is NEVER visible to that query, so a delegated service slip can never be
        // widened into membership, enforced by the crypto, not by a reserved name. And `Identity::mint`
        // (the unbound, public mint) structurally cannot emit `member`, so there is no way to mint an
        // unbound whole-node badge: the "reserved service" footgun is unrepresentable. The badge stays
        // bound to `bound_to`, so only the proven device it names may present it.
        let token = biscuit!(
            r#"
            member(true);
            check if time($t), $t <= {expiry};
            check if bound_device($d), $d == {bound};
            "#,
            expiry = expiry,
            bound = bound_to.to_string(),
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
    /// node's [`VerifyKey`] on success so a caller can log which identity authorized the grant.
    pub fn verify(&self, cap: &Cap, request: &Request) -> Result<VerifyKey, CapError> {
        cap.verify_at_root(request, self.node_id())
    }
}

impl Cap {
    /// Verify this cap grants `request` and is rooted at `root`, returning the root identity on success.
    ///
    /// Verification is pure public-key: a cap's signature chain is checked against its embedded root at
    /// [`Cap::parse`], so granting a request only needs the root to match `root` and every caveat to pass.
    /// No secret is involved, which is what lets a node gate on a root it merely TRUSTS rather than owns: a
    /// CI runner accepts caps rooted at YOUR key without ever holding your secret, so a compromised runner
    /// can never mint new access (see [`crate::Gate`]). [`Identity::verify`] is the self-rooted special case.
    pub fn verify_at_root(
        &self,
        request: &Request,
        root: VerifyKey,
    ) -> Result<VerifyKey, CapError> {
        if self.root != root {
            return Err(CapError::ForeignRoot);
        }
        let mut builder = authorizer!(
            r#"
            time({now});
            service({service});
            allow if true;
            "#,
            now = request.now,
            service = request.service.as_str(),
        );
        // Inject the proven dialer as a `bound_device` fact so a device-bound membership badge (see
        // [`Identity::mint_member`]) grants only when the peer IS the bound device. An unbound cap (a slip,
        // or a badge with no binding block) carries no `bound_device` check and is unaffected: monotone, so
        // presenting the extra fact can never broaden a grant.
        if let Some(peer) = request.bound_device {
            builder = builder
                .fact(fact!(r#"bound_device({peer})"#, peer = peer.to_string()))
                .map_err(CapError::Authorize)?;
        }
        let mut authorizer = builder.build(&self.token).map_err(CapError::Authorize)?;
        authorizer.authorize().map_err(CapError::Denied)?;
        Ok(self.root)
    }

    /// Verify this cap is a MEMBERSHIP badge rooted at `root`: it carries the `member(true)` authority fact
    /// (see [`Identity::mint_member`]) and its device binding + expiry hold for the proven `peer` at `now`.
    /// Returns the root on success.
    ///
    /// This is the membership question, distinct from the service question ([`Cap::verify_at_root`]): it
    /// provides NO service fact and admits on `allow if member(true)`. Because that query runs at DEFAULT
    /// scope, only a `member` fact in the token's AUTHORITY block satisfies it: a `member` fact forged into
    /// an attenuation block lives at a higher origin, is untrusted, and never grants (biscuit's own trust
    /// semantics). So a delegated service slip (no `member` fact) can never pass here, and a service slip
    /// can never be widened into membership. A membership badge carries no service check, so honoring it is
    /// whole-node admission.
    pub fn verify_member_at_root(
        &self,
        now: SystemTime,
        peer: VerifyKey,
        root: VerifyKey,
    ) -> Result<VerifyKey, CapError> {
        if self.root != root {
            return Err(CapError::ForeignRoot);
        }
        let mut authorizer = authorizer!(
            r#"
            time({now});
            bound_device({peer});
            allow if member(true);
            "#,
            now = now,
            peer = peer.to_string(),
        )
        .build(&self.token)
        .map_err(CapError::Authorize)?;
        authorizer.authorize().map_err(CapError::Denied)?;
        Ok(self.root)
    }
}

/// A capability: a token decoded and signature-verified against the root [`VerifyKey`] embedded in its link.
///
/// Holding a `Cap` proves the bytes were a biscuit that chains to `root`; whether it *grants* a specific
/// request (right service, unexpired) is a separate question answered by [`Identity::verify`].
pub struct Cap {
    root: VerifyKey,
    token: Biscuit,
}

impl Cap {
    /// Decode a cap from a `sheer:<node-id>.<base32>` link.
    ///
    /// parse-don't-validate at the wire edge: rejects a bad scheme, a malformed [`VerifyKey`], bad base32,
    /// or bytes whose signature chain does not check against the embedded root. It does NOT evaluate the
    /// caveats (service, expiry); that is [`Identity::verify`]'s job at connect time.
    pub fn parse(link: &str) -> Result<Self, CapError> {
        let body = link.strip_prefix(SCHEME).ok_or(CapError::Scheme)?;
        let (root, encoded) = body.split_once(SEPARATOR).ok_or(CapError::Malformed)?;
        // Bound the token size BEFORE the expensive work: base32-decoding a huge body, and then the
        // O(blocks) signature-chain verification, both run before any trust check, so an untrusted peer
        // could otherwise burn CPU with an oversized or many-block link (a foreign token is parsed here,
        // then refused later against the trusted root: too late). A real cap is small; this is generous.
        if encoded.len() > MAX_ENCODED_LEN {
            return Err(CapError::TooLarge);
        }
        let root = root.parse::<VerifyKey>().map_err(|_| CapError::Malformed)?;
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(|_| CapError::Encoding)?;
        let public = root_key(root)?;
        // Decoding with the embedded root verifies the signature chain back to it; a token that does not
        // chain to the VerifyKey it claims is rejected here, before any caveat is ever considered.
        let token = Biscuit::from(&bytes, public).map_err(|_| CapError::Malformed)?;
        // A well-formed but deeply-attenuated token is still a DoS via O(blocks) work; a legitimate
        // delegation chain is short, so bound the block count too.
        if token.block_count() > MAX_BLOCKS {
            return Err(CapError::TooLarge);
        }
        Ok(Self { root, token })
    }

    /// The identity this cap is rooted at: the [`VerifyKey`] a connector should dial and the exposer must be
    /// to verify it.
    pub fn root(&self) -> VerifyKey {
        self.root
    }

    /// This cap's revocation identifiers, one per block (the authority block first, the narrowest last).
    /// Each is a pure, offline function of the block's signature. Recording one in a
    /// [`Denylist`](crate::Denylist) revokes that token and every token attenuated from it (all of which
    /// carry that block, hence that id).
    pub fn revocation_ids(&self) -> Vec<Vec<u8>> {
        self.token.revocation_identifiers()
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

    /// Seal this cap so it can no longer be attenuated.
    ///
    /// A sealed cap still verifies, but no further block can be appended, so it cannot be narrowed and
    /// handed onward. This is the honest "non-delegable" grant: the recipient may use it but may not
    /// re-share a tightened copy. An unsealed cap (the default from [`Identity::mint`]) stays open to
    /// attenuation and delegation.
    pub fn seal(&self) -> Result<Self, CapError> {
        Ok(Self {
            root: self.root,
            token: self.token.seal().map_err(CapError::Seal)?,
        })
    }

    /// Narrow this cap, offline, by appending a block that adds a tighter service and/or expiry check.
    ///
    /// Monotone by construction: [`biscuit_auth`] only lets a block ADD checks, so the result is always
    /// the same grant or narrower, never broader. Any holder can do this with no secret and no network,
    /// which is exactly what makes delegation work: a third party narrows and hands the token onward, and
    /// the exposer still verifies the whole chain. A sealed cap (see [`Cap::seal`]) rejects this with
    /// [`CapError::Attenuate`]. At least one of `service`/`shorten` must be given, or this is a no-op and
    /// returns [`CapError::EmptyAttenuation`].
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

#[cfg(test)]
impl Identity {
    /// Test-only: forge a would-be membership badge with `member(true)` in an ATTENUATION block instead of
    /// the authority block, exactly what an attacker would attempt. The authority block carries the SAME
    /// device-binding and expiry checks as a real [`mint_member`](Identity::mint_member) badge, so the only
    /// variable is the origin of the `member` fact. The gate must refuse it: an appended fact is untrusted
    /// origin, so `allow if member(true)` (default scope) never sees it. This is the prosecutable proof
    /// that membership is unforgeable even against a hand-crafted token (the public [`Cap::attenuate`] can
    /// only append checks, never facts, so this reaches past the API on purpose).
    pub(crate) fn mint_forged_member(
        &self,
        bound_to: VerifyKey,
        expiry: SystemTime,
    ) -> Result<Cap, CapError> {
        let token = biscuit!(
            r#"
            check if time($t), $t <= {expiry};
            check if bound_device($d), $d == {bound};
            "#,
            expiry = expiry,
            bound = bound_to.to_string(),
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        let token = token
            .append(block!(r#"member(true);"#))
            .map_err(CapError::Attenuate)?;
        Ok(Cap {
            root: self.node_id(),
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
    /// The proven identity of the dialer, when known. A device-bound membership badge (see
    /// [`Identity::mint_member`]) grants only when this matches the badge's bound device; `None`, or a cap
    /// with no binding, skips the check.
    pub bound_device: Option<VerifyKey>,
}

impl Request {
    /// A request for `service` evaluated at the current wall-clock time, with no bound dialer.
    pub fn now(service: Service) -> Self {
        Self {
            service,
            now: SystemTime::now(),
            bound_device: None,
        }
    }

    /// Bind this request to the proven dialer `peer`, so a device-bound badge admits only that device. The
    /// gate sets this from the identity the transport handshake proved.
    pub fn bound_to(mut self, peer: VerifyKey) -> Self {
        self.bound_device = Some(peer);
        self
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

/// The [`VerifyKey`] that is this keypair's public half.
fn node_id_of(root: &KeyPair) -> VerifyKey {
    let mut bytes = [0u8; VerifyKey::LEN];
    // biscuit's PublicKey serializes to exactly 32 ed25519 bytes; the copy pins that into a VerifyKey.
    bytes.copy_from_slice(&root.public().to_bytes());
    VerifyKey::new(bytes)
}

/// The biscuit root public key for a [`VerifyKey`]: the same ed25519 key, read as a verifier root.
fn root_key(node: VerifyKey) -> Result<PublicKey, CapError> {
    PublicKey::from_bytes(node.bytes(), Algorithm::Ed25519).map_err(CapError::Key)
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
    /// The token exceeded the size or block-count bound; refused before verification to cap the work an
    /// untrusted peer can force.
    #[error("capability is too large")]
    TooLarge,
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
    /// Appending an attenuation block failed (for instance, the cap is sealed).
    #[error("attenuate capability")]
    Attenuate(#[source] biscuit_auth::error::Token),
    /// Sealing the token failed.
    #[error("seal capability")]
    Seal(#[source] biscuit_auth::error::Token),
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
