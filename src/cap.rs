//! The capability primitive: a bearer token, offline-verifiable, rooted at an issuer's own
//! identity, with no central authority.
//!
//! A [`Cap`] is a [biscuit](biscuit_auth): an ed25519-signed, datalog-attenuable token. Its root key is
//! the issuer's [`VerifyKey`] key, so verification asks one question, "does this token chain back to the
//! key I am?", answered with pure pubkey identity and no PKI, registry, or server.
//!
//! A cap carries two kinds of check, both *monotone*: appending a block can only ever ADD checks, never
//! remove one, so every operation below either holds the grant the same or narrows it, and broadening is
//! impossible by construction (the crypto, not our code, enforces this).
//! - a **service** check (`check if service($s), $s == "ssh"`): the token is usable only for that service.
//! - an **expiry** check (`check if time($t), $t <= <expiry>`): the token is usable only until that time.
//!
//! Beside that expiry check, every mint also emits an `expires_at(<date>)` AUTHORITY FACT carrying the
//! same instant, because a check can be evaluated but never read: a holder could not answer "when does my
//! own badge die" from the token it is holding. The fact is ADVISORY, for display and for a holder's own
//! pre-dial refusal ([`Cap::expiry`]); the CHECK remains the sole enforcement and no authorization path
//! here reads the fact.
//!
//! A link is `<key>.<token>`: it carries the issuer's [`VerifyKey`] (its public identity, never a
//! secret) beside the base32 token, so any holder can decode, attenuate, and hand it off
//! entirely offline, and a dialer learns which node to dial from the link alone.
//!
//! The lifecycle, all offline except the initial mint (which needs only the issuer's own secret, still
//! no network):
//! - [`Identity::mint`] signs a fresh cap for a service until an expiry (the issuer).
//! - [`Cap::attenuate`] appends a narrower service and/or shorter expiry (any holder, no secret).
//! - delegation is just [`Cap::attenuate`] by a third party: hand the narrowed token onward, and the
//!   issuer still verifies the whole chain without ever seeing the delegation.
//! - [`Identity::verify`] checks a presented cap against this identity for a [`Request`] (service + now).
//!
//! parse-don't-validate: [`Cap::parse`] yields a `Cap` only from a link that decodes and whose signature
//! chain checks against the embedded root. Whether it further *grants* a given request is answered by
//! [`Identity::verify`], which returns the peer identity it is rooted at only when every check passes.

use core::time::Duration;
use std::time::SystemTime;

use biscuit_auth::builder::{
    Algorithm, Binary, Check, CheckKind, Expression, Op, Predicate, Rule, Term,
};
use biscuit_auth::macros::{authorizer, biscuit, block, fact};
use biscuit_auth::{
    Authorizer, AuthorizerBuilder, AuthorizerLimits, Biscuit, KeyPair, PrivateKey, PublicKey, error,
};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::VerifyKey;
use crate::link::Link;
use crate::revocations::RevocationId;
use crate::service::Service;
use crate::signed::Signed;

/// The separator between the embedded root [`VerifyKey`] and the token body inside a link.
const SEPARATOR: char = '.';

/// The maximum encoded token length [`Cap::parse`] accepts (~8 KiB decoded). A capability is a small
/// token, so this is generous; it bounds the base32 decode and the O(blocks) signature-chain work, which
/// run before any trust check, so an oversized link cannot burn a verifier's CPU un-refused. This is the
/// TRUE cap on the pre-trust verify work: it bounds the byte length, and so the number of blocks that can
/// possibly fit.
const MAX_ENCODED_LEN: usize = 13_200;

/// The maximum number of blocks [`Cap::parse`] accepts: the authority block plus a bounded delegation
/// chain. A legitimate chain is short, so a many-block token is refused. This is a secondary structural
/// sanity bound checked AFTER verification; the actual pre-trust CPU cap is [`MAX_ENCODED_LEN`], which
/// bounds the bytes (hence the blocks) before the O(blocks) signature check runs.
const MAX_BLOCKS: usize = 16;

/// The datalog evaluation budget every verification runs under.
///
/// Set EXPLICITLY because biscuit's default `max_time` is one millisecond, and that one is a WALL-CLOCK
/// budget: a merely busy host blows through it mid-evaluation and the call fails, which turned a valid
/// capability into a refusal whenever the machine was loaded. That is an availability defect, and a lying
/// one, since the holder is told their authority failed when nothing about it was ever decided.
///
/// The time budget is LARGE enough that host load never trips it: a real cap is a handful of facts over
/// at most [`MAX_BLOCKS`] blocks and evaluates in microseconds, so a second is three orders of magnitude
/// of headroom, far past the tens of milliseconds a loaded scheduler can steal from a thread mid-run.
///
/// It is NOT a ceiling on hostile work, and nothing here should be read as one. biscuit samples the clock
/// only at ITERATION boundaries, and one iteration runs every rule to completion, so a single rule whose
/// body joins `k` predicates over `F` facts walks all `F^k` tuples uninterrupted: `max_time` bounds the
/// NUMBER of iterations times the cost of one, and the cost of one is unbounded. A token carrying ~40
/// facts and one 4-way rule (1.6 KB, 2 blocks, well inside [`MAX_ENCODED_LEN`] and [`MAX_BLOCKS`]) burns
/// seconds of one thread under this one-second budget. So the clock is a BACKSTOP for a legitimate token
/// on a starved host, nothing more.
///
/// The anti-abuse work is done by bounds that hold without a clock. The two DETERMINISTIC caps refuse a
/// token that would generate more than `max_facts` facts or need more than `max_iterations` rule passes
/// identically on every host at every load, where a clock-based refusal is noise; they are biscuit's own
/// defaults, spelled out here so an upstream default change cannot silently move nauthy's bound.
/// [`MAX_ENCODED_LEN`] and [`MAX_BLOCKS`] bound the parse and signature-chain work before evaluation
/// starts. And [`bound_evaluation_cost`] answers what none of the others reach, structurally and before
/// `run()`: it caps `F` and `k`, and it refuses a CLOSURE, whose nested evaluation is not sampled even
/// at an iteration boundary because it never leaves the one expression it lives in.
pub(crate) const AUTHORIZER_LIMITS: AuthorizerLimits = AuthorizerLimits {
    max_facts: 1_000,
    max_iterations: 100,
    max_time: Duration::from_secs(1),
};

/// The most facts an evaluation may start from: the token's own authority facts plus the ones nauthy's
/// authorizer program injects. This crate AUTHORED every legitimate token, so the real number is known
/// and small: at most `authority_bound` + `expires_at` + `member` from the authority block (three, and no
/// mint emits all three), plus `time` + `service` + `bound_device` + `foreign_member` from the verify
/// programs (at most three of the four on any one path). Six, so sixteen is double headroom for a grant
/// shape we have not minted yet, and still leaves the worst case tiny (see [`MAX_JOIN_ARITY`]).
const MAX_TOKEN_FACTS: usize = 16;

/// The widest join a check body may ask for. Every check this crate emits joins ONE predicate
/// (`check if service($s), $s == ...`) except the authority-bound slip's, which joins two
/// (`check if authority_bound($x), foreign_member($x)`), so two is exactly the grammar and not a guess.
///
/// With [`MAX_TOKEN_FACTS`] this is the whole structural guarantee: evaluation cost is `O(F^k)` in the
/// fact count `F` and the body arity `k`, so bounding BOTH pins the worst case at `16^2` = 256 candidate
/// tuples per query. Bounding either alone does nothing: eight facts under a 25-predicate body is `8^25`,
/// and 640 facts under a 2-predicate body is 409,600.
const MAX_JOIN_ARITY: usize = 2;

/// Domain-separation tag prepended to a document's bytes before signing (and required on verify), so a
/// document signature can never double as a biscuit authority-block signature (the confused-deputy forgery,
/// F1: a victim who signs attacker-influenced bytes must not thereby emit a valid biscuit block signature).
///
/// ESSENTIAL INVARIANT: the tag's FIRST byte must be one that cannot begin a valid biscuit
/// authority-block signing payload of ANY supported biscuit version. Today this holds two ways at once:
/// - a biscuit v1 signing payload begins with `\0` (`\0BLOCK\0...`); ours begins with `n` (0x6e), so the
///   signed message `TAG || bytes` can never equal a v1 payload.
/// - a biscuit v0 signing payload begins with the block protobuf, whose first byte must be a valid protobuf
///   field key (`(field << 3) | wire_type`, wire_type in {0,1,2,5}). `n` = 0x6e is field 13 wire-type 6,
///   which is not a legal protobuf wire type, so a would-be v0 forgery cannot both begin with the tag and
///   parse as a block: it dies at block deserialization.
///
/// Changing this tag (a future rename, a version bump) is therefore a DELIBERATE re-check of that property,
/// not a free edit. The `-v1` suffix IS the on-wire signed-document version. See the two-version forgery
/// regression tests in `cap_tests`. `pub(crate)` so `signed.rs` verifies over the exact same constant.
pub(crate) const SIGNED_DOCUMENT_CONTEXT: &[u8] = b"nauthy-signed-document-v1\0";

/// An issuer's signing identity: the ed25519 keypair whose public half is a [`VerifyKey`].
///
/// This is the root of every cap it mints. Reconstructed from the issuer's persisted 32-byte secret so
/// caps survive across runs, and it is the same key the transport binds under, so the [`VerifyKey`] a cap
/// roots at *is* the node peers dial. Holds secret key material, so it never derives `Debug`/`Clone`; its
/// bytes are wiped by [`biscuit_auth`] on drop.
///
/// nauthy authorizes PROVEN identities; it does not provision them. An identity is any 32-byte ed25519
/// secret ([`from_secret`](Self::from_secret)), generated fresh ([`generate`](Self::generate) /
/// [`from_rng`](Self::from_rng)) or supplied by your identity layer. Deriving many device secrets from one
/// root seed (HD-style, so one person's devices share an authority) is that identity layer's job, not
/// nauthy's: nauthy mints a device badge for whatever [`VerifyKey`] you name in `bound_to`, and where that
/// device's secret comes from is above the auth layer.
pub struct Identity {
    root: KeyPair,
    /// The same ed25519 secret as `root`, as a raw signer for detached signatures over documents (the
    /// roster). Derived from the same 32-byte seed at construction, so its public half equals
    /// [`verifying_key`](Self::verifying_key): a roster this signs verifies against the same key a cap roots
    /// at.
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

    /// Generate a fresh identity from `rng`. Runtime- and OS-free: bring any CSPRNG. The 32 secret bytes are
    /// zeroized off the stack after the keypair is built; where a device's seed comes from (random here, or
    /// derived per device by your identity layer) is above nauthy, see the type docs.
    pub fn from_rng<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, CapError> {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let identity = Self::from_secret(&secret);
        secret.zeroize();
        identity
    }

    /// Generate a fresh identity from the operating system CSPRNG. The dead-simple getting-started path.
    #[cfg(feature = "os-rng")]
    pub fn generate() -> Result<Self, CapError> {
        Self::from_rng(&mut rand_core::OsRng)
    }

    /// This identity's [`VerifyKey`]: the public key a cap roots at and peers dial.
    pub fn verifying_key(&self) -> VerifyKey {
        verifying_key_of(&self.root)
    }

    /// Sign an opaque document with this identity's ed25519 key, producing a self-verifying blob. The signer
    /// is THIS identity, never a holder that later relays it: only this secret can produce a signature that
    /// verifies against this identity's [`VerifyKey`], so any node may hold and relay the blob and none can
    /// forge it. Reuses the same key that mints caps (no new secret material), as a plain detached ed25519
    /// signature over the caller's bytes: a signed document, not a capability. The bytes are OPAQUE here (a
    /// consumer canonicalizes and parses its own payload); this only proves who signed them.
    pub fn sign_document(&self, bytes: &[u8]) -> Signed {
        // Sign TAG || bytes, never the caller's bytes verbatim: the domain-separation tag makes a document
        // signature impossible to reuse as a biscuit authority-block signature (F1). The tag is a
        // signing-time prefix only; the Signed envelope still carries the OPAQUE `bytes`, so the wire
        // framing is unchanged. See SIGNED_DOCUMENT_CONTEXT.
        let mut message = SIGNED_DOCUMENT_CONTEXT.to_vec();
        message.extend_from_slice(bytes);
        let signature = self.signing.sign(&message);
        Signed::from_parts(bytes.to_vec(), self.verifying_key(), signature.to_bytes())
    }

    /// Mint a fresh cap granting `service` until `expiry`, signed by this identity.
    ///
    /// The root grant. The holder may narrow it further offline with [`Cap::attenuate`]; they can never
    /// broaden it, so this is the widest the cap will ever be.
    pub fn mint(&self, service: &Service, expiry: SystemTime) -> Result<Cap, CapError> {
        // `expires_at` is the advisory, READABLE twin of the expiry check: the same instant, as a fact, so
        // a holder can see its own deadline without authorizing anything. The check still enforces it, and
        // only the check does. See [`Cap::expiry`].
        let token = biscuit!(
            r#"
            expires_at({expiry});
            check if service($s), $s == {service};
            check if time($t), $t <= {expiry};
            "#,
            service = service.as_str(),
            expiry = expiry,
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.verifying_key(),
            token,
        })
    }

    /// Mint a membership badge for the device `bound_to`, granting whole-node membership until `expiry`.
    ///
    /// A device badge, not a service slip: it asserts "the bearer is one of my devices", which a
    /// [`Rooted`](crate::Gate::Rooted) gate honors as whole-node admission. It is BOUND to `bound_to`, so it
    /// grants only when the *proven* dialer is that device: a badge observed in flight and replayed from a
    /// DIFFERENT key verifies against no one. That is the binding's real job: it defends the short-lived
    /// SELF-SIGNED badge an authority holder mints per dial against cross-key replay. It does NOT harden a
    /// badge that travels beside its own device seed (as a device seed provisioned alongside its badge does:
    /// whoever steals that blob already holds the seed, so binding buys nothing there). Only the authority
    /// (this identity) can mint one, since minting needs the root secret; a delegated slip can never be
    /// attenuated into a membership badge (attenuation only adds checks, [`Cap::attenuate`]).
    pub fn mint_member(&self, bound_to: VerifyKey, expiry: SystemTime) -> Result<Cap, CapError> {
        // Membership is a STRUCTURAL fact in the authority block, not a service name. `member(true)` is
        // asserted here and checked by the gate's `allow if member(true)` query
        // ([`Cap::verify_member_at_root_without_revocation`]). Because biscuit only trusts facts from the
        // authority block (origin 0), a fact added in an attenuation block is NEVER visible to that query,
        // so a delegated service slip can never be widened into membership, enforced by the crypto, not by a
        // reserved name. And `Identity::mint` (the unbound, public mint) structurally cannot emit `member`,
        // so there is no way to mint an unbound whole-node badge: the "reserved service" footgun is
        // unrepresentable. The badge stays bound to `bound_to`, so only the proven device it names may
        // present it.
        //
        // `expires_at` rides along as the advisory, READABLE twin of the expiry check (see
        // [`Cap::expiry`]), so the badged device can answer when its own badge dies. Advisory only: the
        // check is what expires this badge, here and at every gate.
        let token = biscuit!(
            r#"
            member(true);
            expires_at({expiry});
            check if time($t), $t <= {expiry};
            check if bound_device($d), $d == {bound};
            "#,
            expiry = expiry,
            bound = bound_to.to_string(),
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.verifying_key(),
            token,
        })
    }

    /// Mint a device-bound service slip granting `service` until `expiry`, usable only by the proven device
    /// `bound_to`.
    ///
    /// The standing-access primitive for an outsider's single device. Like [`Identity::mint`] it grants a
    /// named SERVICE (never `member`, so it is per-service access, never whole-node admission), but it
    /// carries the same `check if bound_device` binding a membership badge does (see
    /// [`Identity::mint_member`]). So a copy observed in flight and replayed from a DIFFERENT key verifies
    /// against no one, and a slip presented with no proven dialer (`request.bound_device` is `None`) grants
    /// nothing: theft-resistant, inert unless the presenter IS the bound device. It needs no new verify
    /// path, [`Cap::verify_at_root_without_revocation`] already injects the proven dialer as `bound_device`,
    /// so the binding check falls out of the existing service verification. Only the authority (this
    /// identity) can mint one (minting needs the root secret), and attenuation only ADDS checks, so a
    /// device-bound slip can never be widened into an unbound slip or a badge.
    pub fn mint_bound(
        &self,
        service: &Service,
        bound_to: VerifyKey,
        expiry: SystemTime,
    ) -> Result<Cap, CapError> {
        // `expires_at`: the advisory, readable twin of the expiry check (see [`Cap::expiry`]).
        let token = biscuit!(
            r#"
            expires_at({expiry});
            check if service($s), $s == {service};
            check if time($t), $t <= {expiry};
            check if bound_device($d), $d == {bound};
            "#,
            service = service.as_str(),
            expiry = expiry,
            bound = bound_to.to_string(),
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.verifying_key(),
            token,
        })
    }

    /// Mint a service slip granting `service` until `expiry`, usable only by a device that proves membership
    /// under the foreign authority `foreign_root` (a whole team, not one device).
    ///
    /// The standing-access-to-a-team primitive: issue ONCE to a PERSON (their authority `X`), and every
    /// device that authority vouches for may use it, at their discretion. `X` is pinned as a CONSTANT
    /// authority fact (`authority_bound(X)`), so it is trusted transitively (this authority asserted it) and
    /// can NEVER be overridden by a presenter. Inert alone: it carries `check if authority_bound($x),
    /// foreign_member($x)`, a check no plain verification injects, so it FAILS
    /// [`verify_at_root_without_revocation`](Cap::verify_at_root_without_revocation) and grants nothing
    /// unless the gate's two-cap flow first proves membership under `X` (see
    /// [`Cap::verify_authority_bound_at_root_without_revocation`]). Only the authority (this identity) can
    /// mint one; attenuation only ADDS checks, so it can never be widened.
    pub fn mint_authority_slip(
        &self,
        service: &Service,
        foreign_root: VerifyKey,
        expiry: SystemTime,
    ) -> Result<Cap, CapError> {
        // `expires_at`: the advisory, readable twin of the expiry check (see [`Cap::expiry`]).
        let token = biscuit!(
            r#"
            authority_bound({root});
            expires_at({expiry});
            check if service($s), $s == {service};
            check if time($t), $t <= {expiry};
            check if authority_bound($x), foreign_member($x);
            "#,
            root = foreign_root.to_string(),
            service = service.as_str(),
            expiry = expiry,
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.verifying_key(),
            token,
        })
    }

    /// Verify a presented cap grants `request` against this identity, returning the identity it roots at.
    ///
    /// Grants iff the cap is rooted at this node's key AND every check in the chain passes for the
    /// request: the service matches and the token is unexpired at `request.now`. A foreign root, a
    /// service mismatch, an expired token, or a token narrowed past the request is a denial;
    /// [`CapError::Undecided`] is NOT one, it means the evaluation never finished and the question stands
    /// unanswered. Returns this node's [`VerifyKey`] on success so a caller can log which identity
    /// authorized the grant.
    ///
    /// This does NOT consult a denylist: it is the headline self-rooted offline-verify path, pure public
    /// key against your own root. To authorize a live connection use [`Gate::admit_witnessed`](crate::Gate),
    /// which is the admission API and does check revocation.
    pub fn verify(&self, cap: &Cap, request: &Request) -> Result<VerifyKey, CapError> {
        cap.verify_at_root_without_revocation(request, self.verifying_key())
    }
}

impl Cap {
    /// Verify this cap grants `request` and is rooted at `root`, returning the root identity on success.
    ///
    /// SUB-CHECK, NOT the admission API. This OMITS revocation: it verifies the signature chain and the
    /// caveats but does NOT consult any [`Revocations`](crate::Revocations) store. To authorize a connection
    /// use [`Gate::admit_witnessed`](crate::Gate), which is the admission API and does check revocation.
    /// Public because pure offline pubkey verification against a root you trust (with your own out-of-band
    /// revocation) is a legitimate sovereign use.
    ///
    /// Verification is pure public-key: a cap's signature chain is checked against its embedded root at
    /// [`Cap::parse`], so granting a request only needs the root to match `root` and every caveat to pass.
    /// No secret is involved, which is what lets a node gate on a root it merely TRUSTS rather than owns: a
    /// CI runner accepts caps rooted at YOUR key without ever holding your secret, so a compromised runner
    /// can never mint new access (see [`crate::Gate`]). [`Identity::verify`] is the self-rooted special case.
    pub fn verify_at_root_without_revocation(
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
        self.authorize_under_budget(builder)?;
        Ok(self.root)
    }

    /// Verify this cap is a MEMBERSHIP badge rooted at `root`: it carries the `member(true)` authority fact
    /// (see [`Identity::mint_member`]) and its device binding + expiry hold for the proven `peer` at `now`.
    /// Returns the root on success.
    ///
    /// SUB-CHECK, NOT the admission API. This OMITS revocation: it verifies the signature chain and the
    /// caveats but does NOT consult any [`Revocations`](crate::Revocations) store. To authorize a connection
    /// use [`Gate::admit_witnessed`](crate::Gate), which is the admission API and does check revocation.
    /// Public because pure offline pubkey verification against a root you trust (with your own out-of-band
    /// revocation) is a legitimate sovereign use.
    ///
    /// This is the membership question, distinct from the service question
    /// ([`Cap::verify_at_root_without_revocation`]): it provides NO service fact and admits on `allow if
    /// member(true)`. Because that query runs at DEFAULT scope, only a `member` fact in the token's
    /// AUTHORITY block satisfies it: a `member` fact forged into an attenuation block lives at a higher
    /// origin, is untrusted, and never grants (biscuit's own trust semantics). So a delegated service slip
    /// (no `member` fact) can never pass here, and a service slip can never be widened into membership. A
    /// membership badge carries no service check, so honoring it is whole-node admission.
    pub fn verify_member_at_root_without_revocation(
        &self,
        now: SystemTime,
        peer: VerifyKey,
        root: VerifyKey,
    ) -> Result<VerifyKey, CapError> {
        if self.root != root {
            return Err(CapError::ForeignRoot);
        }
        self.authorize_under_budget(authorizer!(
            r#"
            time({now});
            bound_device({peer});
            allow if member(true);
            "#,
            now = now,
            peer = peer.to_string(),
        ))?;
        Ok(self.root)
    }

    /// Verify this cap is a valid AUTHORITY-BOUND slip rooted at `root` for `request`, returning the FOREIGN
    /// authority root `X` it names. Grants (and returns `X`) iff: the cap roots at `root`, its service
    /// matches, it is unexpired at `request.now`, and it carries an `authority_bound(X)` AUTHORITY fact. The
    /// gate then verifies a membership badge at the RETURNED `X` (never a presenter-supplied root) before
    /// admitting.
    ///
    /// SUB-CHECK, NOT the admission API. This OMITS revocation: it verifies the signature chain and the
    /// caveats but does NOT consult any [`Revocations`](crate::Revocations) store. To authorize a connection
    /// use [`Gate::admit_foreign_witnessed`](crate::Gate), which is the admission API and does check
    /// revocation. Public because pure offline pubkey verification against a root you trust (with your own
    /// out-of-band revocation) is a legitimate sovereign use.
    ///
    /// `X` is read from the authority block ONLY (biscuit `query` sees origin-0 facts, never attenuation
    /// blocks), so an `authority_bound` fact forged into a delegation block is invisible: the bound
    /// authority is exactly the one THIS authority signed. A plain slip or a membership badge carries no
    /// `authority_bound` fact, so this returns [`CapError::NotAuthorityBound`] for them: this method is the
    /// sole detector AND extractor.
    pub fn verify_authority_bound_at_root_without_revocation(
        &self,
        request: &Request,
        root: VerifyKey,
    ) -> Result<VerifyKey, CapError> {
        if self.root != root {
            return Err(CapError::ForeignRoot);
        }
        // Read the pinned foreign root from the authority block (origin-0 only, so an attenuation-block
        // `authority_bound` is invisible). A missing fact is a clean "not this kind".
        let x_text = self
            .authority_bound_text()?
            .ok_or(CapError::NotAuthorityBound)?;
        let x = x_text
            .parse::<VerifyKey>()
            .map_err(|_| CapError::Malformed)?;
        // Authorize the slip's service + expiry checks AND satisfy its `foreign_member($x)` check by
        // injecting the authority it named. This is what makes it authorize HERE and NOWHERE else; the gate
        // still ANDs an independent badge check under `x` before it admits, so this method never admits on
        // its own.
        self.authorize_under_budget(authorizer!(
            r#"
            time({now});
            service({service});
            foreign_member({root});
            allow if true;
            "#,
            now = request.now,
            service = request.service.as_str(),
            root = x.to_string(),
        ))?;
        Ok(x)
    }

    /// When the issuing authority set this cap to expire, from its `expires_at` AUTHORITY fact. `None` for
    /// a cap that carries none.
    ///
    /// ADVISORY, for DISPLAY and for a holder's own pre-dial refusal. The expiry CHECK is the SOLE
    /// enforcement and nothing on an authorization path may consult this instead: the check is datalog
    /// evaluated over the WHOLE chain at the moment of the request, this is one fact read out of one
    /// block. Substituting the fact for the check would silently drop every narrowing an attenuation block
    /// added and move the decision off the engine that is the actual gate. This answers a holder's
    /// question about its own credential ("when does my badge die", so it can warn, print a date, or
    /// decline to dial); it answers no one else's, and it admits nothing.
    ///
    /// Reads origin-0 facts only, the same wall [`authority_bound_root`](Self::authority_bound_root)
    /// stands behind: `query`, not `query_all`, so an `expires_at` forged into an attenuation block is
    /// invisible and the instant returned is the one THIS authority signed. That also makes it an UPPER
    /// BOUND on the effective grant, since an attenuation can only shorten the life further and is unread
    /// here: this never reports EARLIER than the token really allows, so a refusal built on it can never
    /// turn away a cap the gate would have admitted. A mint writes the fact and the check from one
    /// `SystemTime` and biscuit dates are whole seconds, so the two cannot disagree.
    ///
    /// `None` means the token carries no such fact (a cap minted before the fact existed, whose expiry
    /// lives only in its check), NOT that it never expires: a surface renders that as unknown. Reading a
    /// fact evaluates no check, so a DEAD cap still reports when it died, which is exactly when its holder
    /// needs to be told. A signed date past what `SystemTime` can hold is
    /// [`UnreadableExpiry`](CapError::UnreadableExpiry), never a panic.
    pub fn expiry(&self) -> Result<Option<SystemTime>, CapError> {
        // Built through the budgeted path, not `Biscuit::authorizer`: a query runs the same datalog engine
        // under the same limits, so an unbudgeted one here would fail on a busy host exactly as an
        // unbudgeted authorization did. The program is empty: this reads a fact, it rules on nothing.
        let mut authorizer = self.budgeted_authorizer(AuthorizerBuilder::new())?;
        // Read as raw seconds, not `SystemTime`: biscuit's conversion panics on a date past the clock's
        // range, and a hostile ROOT signs whatever `expires_at` it likes into a link it hands out.
        let rows: Vec<(DateSecs,)> = authorizer
            .query("expiry($t) <- expires_at($t)")
            .map_err(CapError::from_evaluation)?;
        rows.into_iter()
            .next()
            .map(|(DateSecs(secs),)| date_at(secs).ok_or(CapError::UnreadableExpiry))
            .transpose()
    }

    /// The last instant this cap can grant anything, read from the time checks of EVERY block: the
    /// earliest bound any of them sets, so a holder's narrower attenuation wins over the authority's.
    ///
    /// Unlike [`expiry`](Self::expiry), which reads the one fact the authority signed and is only an upper
    /// bound, this reads what the engine enforces: past the instant returned, at least one check denies,
    /// so a caller that stops honouring the cap there never ends a grant the gate would still admit. It
    /// still admits nothing on its own; the checks remain the gate.
    ///
    /// Three answers, kept apart by type:
    /// - `Ok(Some(t))`: every check that reads the clock is `check if time($t), $t <= <date>`, and `t` is
    ///   the earliest such date. Every mint and [`attenuate`](Self::attenuate) writes exactly that shape.
    /// - `Ok(None)`: no check in any block reads the clock, so time alone never ends this cap. A token
    ///   signed by its root with no expiry at all reads this way.
    /// - `Err(`[`UnreadableExpiry`](CapError::UnreadableExpiry)`)`: some check reads the clock in a shape
    ///   this crate never writes (another comparison, another predicate joined in, an alternative that
    ///   can pass without the clock, or a `check all` / `reject if`), or bounds it by a date past what
    ///   `SystemTime` can hold (biscuit dates are any `u64`). Its expiry cannot be read, and a
    ///   caller treats that as expired. Refusing here rather than guessing is safe for the same reason
    ///   the evaluation-cost whitelist is: this crate authored the grammar, so only a token it could not
    ///   have minted or narrowed is refused. A token too complex to load at all is an error too
    ///   ([`TooComplex`](CapError::TooComplex)), and reads the same way.
    ///
    /// A check reads the clock when a query's body names the `time` predicate, the only fact that carries
    /// the request's clock. Checks that do not (service, device binding, membership) set no bound.
    pub fn valid_until(&self) -> Result<Option<SystemTime>, CapError> {
        let authorizer = self.budgeted_authorizer(AuthorizerBuilder::new())?;
        let (_facts, _rules, checks, _policies) = authorizer.dump();
        checks.iter().filter_map(clock_bound).try_fold(
            None,
            |earliest: Option<SystemTime>, bound| {
                let bound = bound?;
                Ok(Some(earliest.map_or(bound, |held| held.min(bound))))
            },
        )
    }

    /// Whether this cap is an AUTHORITY-BOUND slip: it carries an `authority_bound` fact in its AUTHORITY
    /// block.
    ///
    /// A cheap, offline, root-free check the DIALER uses to decide whether to attach a foreign membership
    /// badge beside a presented slip: a plain, bearer, or device-bound slip is NOT authority-bound, so the
    /// dialer attaches no badge and never leaks its own device-to-authority linkage on a non-authority dial.
    /// Reads origin-0 facts only (see the private `authority_bound_text`), so an attenuation-block fact
    /// never reads as authority-bound.
    ///
    /// A HINT, so a read that fails (including an [`Undecided`](CapError::Undecided) one) reads as "not
    /// authority-bound": the dialer attaches no badge and leaks nothing, which is the safe direction for
    /// this question. A caller that must not lose that distinction reads
    /// [`authority_bound_root`](Self::authority_bound_root), which returns the typed cause instead.
    pub fn is_authority_bound(&self) -> bool {
        matches!(self.authority_bound_text(), Ok(Some(_)))
    }

    /// The foreign authority key `X` this cap's `authority_bound` AUTHORITY fact pins, as a typed
    /// [`VerifyKey`], if any. `None` for a plain, bearer, or device-bound slip (no such fact). Reads
    /// origin-0 facts only, so an attenuation-block fact is invisible: the pinned authority is exactly the
    /// one this authority signed.
    ///
    /// The typed, offline, root-free extractor a DIALER uses to decide whether its own foreign membership
    /// badge can ever help: a badge for an authority you are not under never verifies at that authority's
    /// gate, so a dialer attaches the co-presented badge ONLY when `X` equals the authority its own badge
    /// roots under. Distinct from
    /// [`verify_authority_bound_at_root_without_revocation`](Self::verify_authority_bound_at_root_without_revocation),
    /// which is the GATE's path (it needs the root and a request, and gates admission); this is a pure read
    /// of the pinned authority.
    pub fn authority_bound_root(&self) -> Result<Option<VerifyKey>, CapError> {
        self.authority_bound_text()?
            .map(|x| x.parse::<VerifyKey>().map_err(|_| CapError::Malformed))
            .transpose()
    }

    /// The encoded foreign authority key this cap's `authority_bound` AUTHORITY fact pins, if any. Reads
    /// origin-0 facts only: `query` (not `query_all`) defaults its rule scope to the authority block, so an
    /// `authority_bound` fact forged into an attenuation block is invisible and the bound authority is
    /// exactly the one this authority signed. `None` for a plain slip or a membership badge (no such fact).
    /// No root or secret: a pure offline read of the token's own authority block.
    fn authority_bound_text(&self) -> Result<Option<String>, CapError> {
        // Built through the budgeted path, not `Biscuit::authorizer`: a query runs the same datalog engine
        // under the same limits, so an unbudgeted one here would fail on a busy host exactly as an
        // unbudgeted authorization did. The program is empty: this reads a fact, it rules on nothing.
        let mut authorizer = self.budgeted_authorizer(AuthorizerBuilder::new())?;
        let rows: Vec<(String,)> = authorizer
            .query("bound($x) <- authority_bound($x)")
            .map_err(CapError::from_evaluation)?;
        Ok(rows.into_iter().next().map(|(x,)| x))
    }

    /// Whether this cap is a MEMBERSHIP badge by what its issuer signed: its AUTHORITY block carries
    /// `member(true)`. Reads origin-0 facts only, the same wall as `authority_bound_text`, and asks nothing
    /// about the peer, the time, or any added block.
    ///
    /// This is the question a path that must never admit a member asks, and it is deliberately not
    /// [`verify_member_at_root_without_revocation`](Self::verify_member_at_root_without_revocation): that
    /// one supplies no `service` fact, so a holder who narrows a badge to one service with
    /// [`attenuate`](Self::attenuate) makes it fail there while it still passes the service question. The
    /// badge is still a badge, and this read still sees it.
    pub(crate) fn is_member_badge(&self) -> Result<bool, CapError> {
        let mut authorizer = self.budgeted_authorizer(AuthorizerBuilder::new())?;
        let rows: Vec<(bool,)> = authorizer
            .query("badge(true) <- member(true)")
            .map_err(CapError::from_evaluation)?;
        Ok(!rows.is_empty())
    }

    /// Evaluate `program` against this token under [`AUTHORIZER_LIMITS`] and rule on its policies.
    ///
    /// The only place a cap RULES on datalog (the others run it to READ one authority fact:
    /// `authority_bound_text` and [`expiry`](Cap::expiry)), so the budget cannot be forgotten at a verify
    /// site and the timeout-versus-denial split is decided once, in [`CapError::from_evaluation`], rather
    /// than at each caller.
    fn authorize_under_budget(&self, program: AuthorizerBuilder) -> Result<(), CapError> {
        let mut authorizer = self.budgeted_authorizer(program)?;
        authorizer.authorize().map_err(CapError::from_evaluation)?;
        Ok(())
    }

    /// A datalog engine over this token running `program`, under [`AUTHORIZER_LIMITS`].
    ///
    /// The ONE place an authorizer is built, because the budget belongs to the BUILDER: biscuit stores the
    /// limits on the authorizer and applies them to every later `authorize` and `query`, so a site that
    /// built its own would silently evaluate on the one-millisecond default no matter what it passed later.
    /// It is also the one place the token's SHAPE is bounded ([`bound_evaluation_cost`]), for the same
    /// reason: every path that runs the engine on a presented token comes through here, so no verify site
    /// and no fact read can forget it.
    pub(crate) fn budgeted_authorizer(
        &self,
        program: AuthorizerBuilder,
    ) -> Result<Authorizer, CapError> {
        let authorizer = program
            .set_limits(AUTHORIZER_LIMITS)
            .build(&self.token)
            .map_err(CapError::Authorize)?;
        // `build` LOADS the token into the world but evaluates nothing, so this is the last moment before
        // any join runs and the only one where refusing is still free.
        bound_evaluation_cost(&authorizer)?;
        Ok(authorizer)
    }
}

/// A capability: a token decoded and signature-verified against the root [`VerifyKey`] embedded in its link.
///
/// Holding a `Cap` proves the bytes were a biscuit that chains to `root`; whether it *grants* a specific
/// request (right service, unexpired) is a separate question answered by [`Identity::verify`]. Cloneable
/// because a cap is share material, not a secret: every holder of the link can parse one, and cloning it
/// lets [`Link`] carry the parsed token beside its text.
#[derive(Clone)]
pub struct Cap {
    root: VerifyKey,
    token: Biscuit,
}

impl Cap {
    /// Decode a cap from its `<key>.<token>` link text.
    ///
    /// parse-don't-validate at the wire edge: rejects text that is not `<key>.<token>`, a malformed [`VerifyKey`], bad base32,
    /// or bytes whose signature chain does not check against the embedded root. It does NOT evaluate the
    /// caveats (service, expiry); that is [`Identity::verify`]'s job at connect time.
    pub fn parse(link: &str) -> Result<Self, CapError> {
        let (root, encoded) = link.split_once(SEPARATOR).ok_or(CapError::Malformed)?;
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
        let token = Biscuit::from(&bytes, public).map_err(|_| CapError::Unverified)?;
        // A well-formed but deeply-attenuated token is still a DoS via O(blocks) work; a legitimate
        // delegation chain is short, so bound the block count too.
        if token.block_count() > MAX_BLOCKS {
            return Err(CapError::TooLarge);
        }
        Ok(Self { root, token })
    }

    /// The identity this cap is rooted at: the [`VerifyKey`] a dialer should dial and the issuer must be to
    /// verify it.
    pub fn root(&self) -> VerifyKey {
        self.root
    }

    /// This cap's revocation identifiers, one per block (the authority block first, the narrowest last).
    /// Each is a pure, offline function of the block's signature. Recording one in a
    /// [`Revocations`](crate::Revocations) store revokes that token and every token attenuated from it (all
    /// of which carry that block, hence that id).
    pub fn revocation_ids(&self) -> Vec<RevocationId> {
        self.token
            .revocation_identifiers()
            .into_iter()
            .map(RevocationId::from_bytes)
            .collect()
    }

    /// This cap's ROOT revocation id: the authority-block id (the first of
    /// [`revocation_ids`](Self::revocation_ids)) that every cap attenuated or delegated from it inherits.
    /// Recording it in a [`Revocations`](crate::Revocations) store revokes this cap AND its whole delegation
    /// tree in one entry, whereas recording the narrowest id revokes only this leaf. `None` only for a token
    /// with no blocks, which a well-formed biscuit never is.
    pub fn root_revocation_id(&self) -> Option<RevocationId> {
        self.revocation_ids().into_iter().next()
    }

    /// Encode this cap as a [`Link`]: the shareable `<key>.<token>` form.
    pub fn link(&self) -> Result<Link, CapError> {
        Link::of(self.clone())
    }

    /// The encoded `<key>.<token>` text. The one raw-form encoder ([`Link::of`] calls it), so
    /// the text and the token can never drift apart.
    pub(crate) fn link_text(&self) -> Result<String, CapError> {
        let bytes = self.token.to_vec().map_err(CapError::Encode)?;
        Ok(format!(
            "{}{SEPARATOR}{}",
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
    /// the issuer still verifies the whole chain. A sealed cap (see [`Cap::seal`]) rejects this with
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
            root: self.verifying_key(),
            token,
        })
    }

    /// Test-only: mint a membership badge the way this crate did BEFORE the advisory `expires_at` fact
    /// existed, with the expiry living ONLY in the check. Two things ride on it: a badge minted by an older
    /// version reads [`Cap::expiry`] as `None` (the case every surface must render as unknown), and the
    /// accessor is proved to read the FACT, never the check, since here the check carries an expiry the
    /// accessor cannot see.
    pub(crate) fn mint_member_without_expires_at(
        &self,
        bound_to: VerifyKey,
        expiry: SystemTime,
    ) -> Result<Cap, CapError> {
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
            root: self.verifying_key(),
            token,
        })
    }

    /// Test-only: the same pre-fact badge with an `expires_at` FORGED into an attenuation block, which is
    /// what a holder would append to make a dead badge display as alive. [`Cap::expiry`] must still read
    /// `None`: `query` sees origin-0 facts only. The forgery is pinned in the pre-fact form ON PURPOSE,
    /// because it is the form that cannot pass by luck. With a genuine authority fact present as well, a
    /// regression to `query_all` would return TWO rows and the assertion could still happen to pick the
    /// honest one; with none, the wall either holds and the read is `None`, or it does not and the
    /// attacker's instant comes straight back. Reaches past the public API on purpose ([`Cap::attenuate`]
    /// appends only CHECKS, never facts).
    pub(crate) fn mint_member_with_forged_expires_at(
        &self,
        bound_to: VerifyKey,
        expiry: SystemTime,
        forged: SystemTime,
    ) -> Result<Cap, CapError> {
        let Cap { root, token } = self.mint_member_without_expires_at(bound_to, expiry)?;
        let token = token
            .append(block!(r#"expires_at({forged});"#, forged = forged))
            .map_err(CapError::Attenuate)?;
        Ok(Cap { root, token })
    }

    /// Test-only: a slip whose authority signed no expiry at all, neither the fact nor the check. No mint
    /// here writes one; it is the legitimate "never expires by time" a root may still sign by hand, and
    /// [`Cap::valid_until`] must tell it apart from an expiry it cannot read.
    pub(crate) fn mint_without_expiry(&self, service: &Service) -> Result<Cap, CapError> {
        let token = biscuit!(
            r#"check if service($s), $s == {service};"#,
            service = service.as_str(),
        )
        .build(&self.root)
        .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.verifying_key(),
            token,
        })
    }

    /// Test-only: a slip for `service` whose root signed `expires_at` and its clock check at `secs` past
    /// the epoch, as raw seconds. A mint takes a `SystemTime` and so cannot write a date past the clock's
    /// range, but a hostile root signs any `u64` date by hand into a link it hands out.
    pub(crate) fn mint_with_raw_expiry(
        &self,
        service: &Service,
        secs: u64,
    ) -> Result<Cap, CapError> {
        let token = Biscuit::builder()
            .code_with_params(
                r#"expires_at({expiry}); check if service($s), $s == {service};
                check if time($t), $t <= {expiry};"#,
                std::collections::HashMap::from([
                    ("expiry".to_owned(), Term::Date(secs)),
                    ("service".to_owned(), Term::Str(service.as_str().to_owned())),
                ]),
                std::collections::HashMap::new(),
            )
            .map_err(CapError::Mint)?
            .build(&self.root)
            .map_err(CapError::Mint)?;
        Ok(Cap {
            root: self.verifying_key(),
            token,
        })
    }

    /// Test-only: mint a real authority-bound slip naming `real_root` in the AUTHORITY block, then append a
    /// second `authority_bound(forged_root)` fact in an ATTENUATION block, exactly what an attacker would
    /// attempt to redirect the bound authority to one THEY control.
    /// [`Cap::verify_authority_bound_at_root_without_revocation`] must still return `real_root`: `query`
    /// reads origin-0 facts only, so an appended `authority_bound` is untrusted origin and invisible.
    /// Reaches past the public API on purpose (the public [`Cap::attenuate`] can only append CHECKS, never
    /// facts), the prosecutable proof that the bound authority is exactly the one this authority signed.
    pub(crate) fn mint_authority_slip_with_forged_binding(
        &self,
        service: &Service,
        real_root: VerifyKey,
        forged_root: VerifyKey,
        expiry: SystemTime,
    ) -> Result<Cap, CapError> {
        let Cap { root, token } = self.mint_authority_slip(service, real_root, expiry)?;
        let token = token
            .append(block!(
                r#"authority_bound({forged});"#,
                forged = forged_root.to_string(),
            ))
            .map_err(CapError::Attenuate)?;
        Ok(Cap { root, token })
    }
}

#[cfg(test)]
impl Cap {
    /// Test-only: append `source` as a raw datalog block, the way a hostile holder attenuates a token
    /// the authority really signed. Reaches past [`Cap::attenuate`] on purpose, and that is the attack:
    /// attenuation here appends only this crate's own fixed checks, while a holder appends whatever
    /// datalog they like with biscuit's own block builder, needing no secret and no network.
    pub(crate) fn attenuate_with_raw_datalog(&self, source: &str) -> Result<Self, CapError> {
        let block = biscuit_auth::builder::BlockBuilder::new()
            .code(source)
            .map_err(CapError::Attenuate)?;
        let token = self.token.append(block).map_err(CapError::Attenuate)?;
        Ok(Self {
            root: self.root,
            token,
        })
    }

    /// Test-only: append `check if time($t), $t <= <secs>` with the date as raw seconds, the one clock
    /// shape this crate writes but at a date a `SystemTime` cannot hold. A holder writes it with biscuit's
    /// public builder; datalog text cannot, since it spells dates as RFC 3339.
    pub(crate) fn attenuate_with_raw_clock_bound(&self, secs: u64) -> Result<Self, CapError> {
        let block = biscuit_auth::builder::BlockBuilder::new()
            .code_with_params(
                "check if time($t), $t <= {bound};",
                std::collections::HashMap::from([("bound".to_owned(), Term::Date(secs))]),
                std::collections::HashMap::new(),
            )
            .map_err(CapError::Attenuate)?;
        let token = self.token.append(block).map_err(CapError::Attenuate)?;
        Ok(Self {
            root: self.root,
            token,
        })
    }

    /// Test-only: the JOIN BOMB, `facts` facts under ONE rule whose body joins `arity` of them, so the
    /// engine walks `facts ^ arity` candidate tuples in a single uninterrupted `apply`.
    ///
    /// The rule's expression is unsatisfiable, so the join DERIVES NOTHING and `max_facts` never trips:
    /// the entire cost is the walk, which is exactly the cost no wall-clock budget can bound (biscuit
    /// samples the clock only between iterations). The result is a small, well-formed, signature-valid
    /// token that passes [`MAX_ENCODED_LEN`] and [`MAX_BLOCKS`] with room to spare, which is why the bound
    /// it must trip is a structural one.
    pub(crate) fn attenuate_with_join_bomb(
        &self,
        facts: usize,
        arity: usize,
    ) -> Result<Self, CapError> {
        let mut source = String::new();
        for fact in 0..facts {
            source.push_str(&format!("bomb({fact});\n"));
        }
        let join = (0..arity)
            .map(|slot| format!("bomb($v{slot})"))
            .collect::<Vec<_>>()
            .join(", ");
        source.push_str(&format!("burn($v0) <- {join}, $v0 < 0;\n"));
        self.attenuate_with_raw_datalog(&source)
    }

    /// Test-only: the CLOSURE BOMB, ONE check whose expression nests `.all()` closures `depth` deep (at
    /// least one) over an eight-element array, so the innermost comparison runs `8 ^ depth` times.
    ///
    /// Worse than the join bomb in two ways. The whole nest lives inside ONE expression, which biscuit
    /// walks recursively and never interrupts, not even at the iteration boundary where it samples its
    /// clock. And the innermost body is always TRUE, so the check PASSES: an unguarded host burns the
    /// entire nest and then admits the peer, spending the cost with no refusal to point at. On every
    /// dimension the join bound measures it is a legitimate token: one fact, no rule, a one-predicate
    /// body, and around a kilobyte of link.
    pub(crate) fn attenuate_with_closure_bomb(&self, depth: usize) -> Result<Self, CapError> {
        // Eight elements per level, each level evaluating the next once per element. The body of the
        // innermost closure compares the deepest bound variable, so every level is really walked.
        let mut expression = format!("$v{} >= 0", depth.saturating_sub(1));
        for level in (0..depth).rev() {
            expression = format!("[0, 1, 2, 3, 4, 5, 6, 7].all($v{level} -> {expression})");
        }
        // Hung off `service`, the fact every service verification injects, so the check is reached and
        // the nest is evaluated on the ordinary presented-token path.
        self.attenuate_with_raw_datalog(&format!("check if service($s), {expression};\n"))
    }
}

/// What a presented cap is asked to grant: a service, at a moment in time.
///
/// Built at the verify boundary so `verify` receives an already-valid request. `now` is normally the
/// wall clock; it is a field so a test can pin a moment and prove expiry.
pub struct Request {
    /// The service the dialer is asking to reach.
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

    /// An expiry `duration` from now, for [`Identity::mint`]. A convenience so callers pass `2h` not an
    /// absolute instant; a duration so large it would overflow the clock saturates to a century out rather
    /// than panicking, which is expiry enough for any real grant.
    pub fn expires_in(duration: Duration) -> SystemTime {
        let now = SystemTime::now();
        now.checked_add(duration).unwrap_or_else(|| now + CENTURY)
    }
}

/// A hundred years, the saturating ceiling for [`Request::expires_in`]. Far enough out to be "does not
/// expire" in practice, near enough that `SystemTime` arithmetic never overflows.
const CENTURY: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// The [`VerifyKey`] that is this keypair's public half.
fn verifying_key_of(root: &KeyPair) -> VerifyKey {
    let mut bytes = [0u8; VerifyKey::LEN];
    // biscuit's PublicKey serializes to exactly 32 ed25519 bytes; the copy pins that into a VerifyKey.
    bytes.copy_from_slice(&root.public().to_bytes());
    VerifyKey::new(bytes)
}

/// The biscuit root public key for a [`VerifyKey`]: the same ed25519 key, read as a verifier root.
fn root_key(node: VerifyKey) -> Result<PublicKey, CapError> {
    PublicKey::from_bytes(node.bytes(), Algorithm::Ed25519).map_err(CapError::Key)
}

/// Refuse a loaded-but-not-yet-evaluated token before it can ask for work no budget would interrupt.
///
/// THE CONTRACT: inspect the FULL SHAPE of a presented token before evaluating it, and refuse anything
/// this crate could not itself have minted or narrowed. The shape is read against nauthy's OWN emission
/// grammar, which this crate authors and can therefore enumerate exactly, so the bound holds without
/// knowing anything about how biscuit evaluates.
///
/// THE BOUND THE CLOCK CANNOT GIVE (see [`AUTHORIZER_LIMITS`]). biscuit samples its limits only BETWEEN
/// iterations, and one iteration runs every rule to completion, so a single query runs as long as it
/// likes. Two dimensions of the token decide how long, both readable before anything runs:
/// - the JOIN. A body of arity `k` over `F` facts walks `O(F^k)` candidate tuples, so bounding `F` and
///   `k` pins the worst case. Reading them is `O(F)`, not `O(F^k)`: the 64-fact, 4-way token in
///   `cap_tests` is refused in tens of microseconds and evaluates for nine seconds without this.
/// - the EXPRESSION. A closure (`.all()`, `.any()`, and the lazy `&&`, `||`, `try_or`) runs its body
///   once per element of its operand, recursively, INSIDE one expression, so a nest `d` deep over an
///   eight-element operand is `8^d` evaluations that no iteration boundary ever interrupts. The 1.3 KB
///   token in `cap_tests` nests six deep and, without this bound, burns hundreds of milliseconds and is
///   then GRANTED: the cost is paid and the peer admitted, which is worse than a refusal and invisible
///   to the join bound, whose every dimension such a token matches (one fact, no rule, a one-predicate
///   body).
///
/// A WHITELIST, which is only honest because this crate AUTHORED the grammar. A legitimate token is a
/// handful of authority facts, ZERO rules (no mint emits one, and [`Cap::attenuate`] appends only
/// checks), checks whose bodies join at most [`MAX_JOIN_ARITY`] predicates, and check expressions that
/// are one comparison against a literal. No mint and no attenuation writes a closure of ANY kind, so the
/// honest bound on closures is zero: refusing the operator outright has no headroom number to get wrong
/// and refuses the wide-but-shallow closure a depth budget would admit. So the bound refuses every token
/// nauthy could not have minted or narrowed and refuses nothing it could: a full [`MAX_BLOCKS`]-deep
/// delegation chain passes, because attenuation adds checks, never facts, rules, or operators. A refusal
/// here is DETERMINISTIC, a property of the token that reads the same on every host at every load, which
/// is what keeps it a denial and not an [`Undecided`](CapError::Undecided).
///
/// THE WHITELIST IS ENUMERATED, NEVER SAMPLED. Every node on the path from the loaded program to an
/// operator is destructured or matched EXHAUSTIVELY here, and the suite does the same over biscuit's
/// operators, so a release that adds a dimension to a rule or a kind of operator STOPS THE BUILD until
/// someone decides what it costs. That is the whole defence: a whitelist over someone else's grammar is
/// only as good as its coverage, and reading `body` while leaving `expressions` unread is exactly how a
/// token that carries no rule and joins one predicate still burned a thread. Drift in nauthy's own
/// grammar fails the other way, closed and loud: a mint that began emitting a closure would have its
/// own tokens refused at the first verify, which the suite catches on every shape this crate mints.
///
/// `dump` is the typed read, not `dump_code`, and its internal unwraps cannot fire on an authorizer
/// `build` returned: `build` converts every block's facts, rules, and checks out of the block's symbols
/// and RE-INTERNS them into the authorizer's own table, fallibly, before it returns, so a token with a
/// dangling symbol has already failed as [`Authorize`](CapError::Authorize) and every id `dump` resolves
/// was inserted by the conversion that put it there. This runs before `run()`, so no derived fact is in
/// the world yet either. The policies are this crate's own program rather than the token's, so they are
/// not attacker-influenced and not bounded here.
fn bound_evaluation_cost(authorizer: &Authorizer) -> Result<(), CapError> {
    let (facts, rules, checks, _policies) = authorizer.dump();
    let beyond_the_grammar = facts.len() > MAX_TOKEN_FACTS
        || !rules.is_empty()
        || checks
            .iter()
            // `kind` picks how a check quantifies its queries (one, all, reject), which chooses an
            // answer and never an amount of work. Destructured rather than read by field so a field
            // biscuit adds to a check cannot arrive unconsidered.
            .flat_map(|Check { queries, kind: _ }| queries)
            .any(query_beyond_the_grammar);
    if beyond_the_grammar {
        return Err(CapError::TooComplex);
    }
    Ok(())
}

/// Whether one check query asks for work no mint or attenuation here ever writes: a join wider than
/// [`MAX_JOIN_ARITY`] predicates, or an expression that opens a closure.
fn query_beyond_the_grammar(query: &Rule) -> bool {
    // Destructured, never read by field, because the omission IS the bug class: the unread member of
    // this struct is the dimension the next bomb rides. The rest cost nothing to walk: `head` names the
    // predicate a match would derive, `parameters` and `scope_parameters` are builder-time
    // substitutions already applied in a token read off the wire, and `scopes` only narrows which
    // origins a body may see. None of them adds a tuple or an evaluation.
    let Rule {
        head: _,
        body,
        expressions,
        parameters: _,
        scopes: _,
        scope_parameters: _,
    } = query;
    body.len() > MAX_JOIN_ARITY
        || expressions
            .iter()
            .any(|Expression { ops }| ops.iter().any(opens_a_closure))
}

/// Whether this operator IS a closure: a body biscuit evaluates once per element of the operand beside
/// it (`.all()`, `.any()`) or defers and may evaluate later (`&&`, `||`, `try_or`). Every lazy operator
/// biscuit offers compiles to a closure operand, so refusing the closure refuses the whole family, and
/// the suite proves that operator by operator against real tokens.
///
/// Nesting needs no recursion here: a closure appears either at the top of an expression or inside
/// another closure, so the OUTERMOST closure of any nest is always among the ops this scans.
///
/// EXHAUSTIVE on purpose. A biscuit release that adds a kind of operator stops this crate compiling
/// until someone decides what that operator costs, rather than admitting it by falling through.
fn opens_a_closure(op: &Op) -> bool {
    match op {
        Op::Closure(..) => true,
        // A value and a unary or binary operator each consume operands that are already evaluated, so
        // one application is one step over what the token already carries.
        Op::Value(_) | Op::Unary(_) | Op::Binary(_) => false,
    }
}

/// The latest instant `check` can pass at, or `None` when it does not read the clock at all.
///
/// A check passes when ANY of its queries does, so a check of several recognized time queries is bounded
/// by the latest of them. A check that reads the clock in any other shape is unreadable, including one
/// whose other query could pass with no clock at all, since that alternative makes the bound a guess.
fn clock_bound(check: &Check) -> Option<Result<SystemTime, CapError>> {
    let Check { queries, kind } = check;
    if !queries.iter().any(reads_the_clock) {
        return None;
    }
    if *kind != CheckKind::One {
        return Some(Err(CapError::UnreadableExpiry));
    }
    let bound = queries
        .iter()
        .map(|query| time_at_most(query).ok_or(CapError::UnreadableExpiry))
        .try_fold(SystemTime::UNIX_EPOCH, |latest, date| Ok(latest.max(date?)));
    Some(bound)
}

/// Whether a check query joins the `time` fact, the only fact that carries the request's clock.
fn reads_the_clock(query: &Rule) -> bool {
    query
        .body
        .iter()
        .any(|Predicate { name, .. }| name == "time")
}

/// The date `query` bounds the clock by, when it is exactly `time($t), $t <= <date>`: the one shape every
/// mint and attenuation writes. `None` for any other shape.
fn time_at_most(query: &Rule) -> Option<SystemTime> {
    // The one predicate is `time`: the caller only asks about a query that joins it.
    let [Predicate { name: _, terms }] = query.body.as_slice() else {
        return None;
    };
    let ([Term::Variable(bound)], [Expression { ops }]) =
        (terms.as_slice(), query.expressions.as_slice())
    else {
        return None;
    };
    let [
        Op::Value(Term::Variable(compared)),
        Op::Value(Term::Date(secs)),
        Op::Binary(Binary::LessOrEqual),
    ] = ops.as_slice()
    else {
        return None;
    };
    // The compared variable must be the clock itself: biscuit accepts a comparison over a variable the
    // body never binds, and that one bounds nothing.
    // A date the clock cannot hold is unreadable, not a panic: `Term::Date` is any `u64` off the wire, and
    // one past `SystemTime`'s range would overflow the std `Add`, which panics, on a token the gate admits.
    (bound == compared).then_some(*secs).and_then(date_at)
}

/// The instant `secs` seconds past the unix epoch, or `None` when `SystemTime` cannot hold it.
///
/// The ONE conversion from a biscuit date to a `SystemTime` in this crate. biscuit's own
/// `TryFrom<Term> for SystemTime` adds unchecked, and a holder writes any `u64` date into a block, so
/// every date read off a token comes through here and an out-of-range one fails closed.
fn date_at(secs: u64) -> Option<SystemTime> {
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// A biscuit date as its raw seconds, so a query reads it without biscuit's unchecked conversion.
struct DateSecs(u64);

impl TryFrom<Term> for DateSecs {
    type Error = error::Token;

    fn try_from(term: Term) -> Result<Self, Self::Error> {
        match term {
            Term::Date(secs) => Ok(Self(secs)),
            other => Err(error::Token::ConversionError(format!(
                "expected a date, got {other:?}"
            ))),
        }
    }
}

/// Why a capability operation failed.
///
/// The failure modes a caller must distinguish: a malformed link, a token that does not chain to the
/// expected root, and a token that chains but whose checks deny the request. The underlying
/// [`biscuit_auth`] cause is carried by reference in the source chain, never stringified away.
///
/// Non-exhaustive, on the argument `bifrost::Refusal` and `bifrost_wire::Error` both took on
/// 2026-09-20: hardening a capability model ADDS causes, `TooComplex` being the third this week, and
/// a downstream match that silently inherits a new one is the failure this type exists to prevent.
/// Adding the attribute is free while the enum is already breaking and costs a release train the day
/// it is deferred. Every consumer outside this crate already carries a catch-all, so nothing breaks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CapError {
    /// The token exceeded the size or block-count bound; refused before verification to cap the work an
    /// untrusted peer can force.
    #[error("capability is too large")]
    TooLarge,
    /// The token's datalog is a shape this crate never emits: too many facts, a rule (there are none in a
    /// legitimate token), a check body joining more predicates than any mint or attenuation writes, or a
    /// check expression carrying a closure (`.all()`, `.any()`, `&&`, `||`, `try_or`), of which this
    /// crate writes none. Refused before evaluation to cap the work an untrusted peer can force, which no
    /// wall-clock budget can bound (see `bound_evaluation_cost`). A property of the token, so it is a
    /// denial and not an [`Undecided`](Self::Undecided): the same token reads the same way on every host.
    #[error("capability is too complex to evaluate")]
    TooComplex,
    /// The link body was not valid base32.
    #[error("invalid base32 in link")]
    Encoding,
    /// The link was structurally broken before any signature check: not `<key>.<token>` (a missing
    /// separator, or anything written before the key), or a node-id /
    /// authority-fact key that is not a well-formed [`VerifyKey`]. Distinct from [`Unverified`](Self::Unverified),
    /// a signature-chain failure, because a structural break is a malformed input, not a security event.
    #[error("not a link: expected <key>.<token>")]
    Malformed,
    /// The token decoded but its signature chain did not verify against the embedded root: tampered,
    /// truncated mid-chain, or never signed by the key it claims. A security-relevant failure, kept distinct
    /// from [`Malformed`](Self::Malformed).
    #[error("capability signature chain does not verify")]
    Unverified,
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
    /// The token chained to the root, but its checks denied the request (wrong service or expired), or its
    /// evaluation exceeded a DETERMINISTIC budget (too many facts, too many rule passes). Every cause here
    /// is a property of the token itself: the same token answers the same way on every host, at every load.
    /// A wall-clock timeout is NOT one of them, see [`Undecided`](Self::Undecided).
    #[error("capability does not grant this request")]
    Denied(#[source] biscuit_auth::error::Token),
    /// The token is not an authority-bound slip: it carries no `authority_bound` authority fact, so it names
    /// no foreign authority. A clean "not this kind", distinct from [`Denied`](Self::Denied); the gate
    /// treats both as "not admitted on the authority-bound arm".
    #[error("capability is not an authority-bound slip")]
    NotAuthorityBound,
    /// Evaluation ran out of its [`AUTHORIZER_LIMITS`] wall-clock budget, so the request was NOT DECIDED.
    ///
    /// NOT a denial, and the distinction is the whole point of the variant: the host ran out of time, which
    /// says nothing whatever about the holder's authority. It is a TRANSIENT local condition (a loaded
    /// machine, a descheduled thread), so a caller reports it as "try again", never as "you are not
    /// authorized", and never records it as a failed authorization attempt. Fail-closed all the same:
    /// nothing is admitted on an answer that was never computed.
    #[error("capability evaluation ran out of time")]
    Undecided,
    /// A check reads the clock in a shape this crate never writes, or a date the clock cannot hold, so
    /// when the cap stops granting cannot be read. From [`Cap::valid_until`], whose callers treat it as
    /// already expired, and from [`Cap::expiry`] for an `expires_at` date past the clock's range.
    #[error("capability expiry cannot be read")]
    UnreadableExpiry,
}

impl CapError {
    /// Classify a failure from biscuit's datalog engine.
    ///
    /// The ONE place an evaluation failure becomes a nauthy error, so a timeout cannot be folded back into
    /// a denial by a call site that stopped thinking about it. A wall-clock
    /// [`Timeout`](biscuit_auth::error::RunLimit::Timeout) is [`Undecided`](Self::Undecided); everything
    /// else, the deterministic fact and iteration limits included, is a genuine [`Denied`](Self::Denied),
    /// because it is reproducible from the token alone.
    pub(crate) fn from_evaluation(failure: error::Token) -> Self {
        match failure {
            error::Token::RunLimit(error::RunLimit::Timeout) => CapError::Undecided,
            denial => CapError::Denied(denial),
        }
    }
}
