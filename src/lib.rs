//! nauthy: control-plane-free authorization. Given a peer identity that a transport has already proven,
//! decide whether it may connect, with no server, no PKI, and no registry.
//!
//! Authorization here is policy on *proven* identities, not crypto: a transport handshake has already
//! proven the peer holds the private key behind its [`VerifyKey`], so the question is only whether that
//! identity is permitted. nauthy sits above the transport and never reaches out itself, so it is usable
//! wherever a peer can be named by an ed25519 key.
//!
//! Two policies:
//! - [`Gate::Open`] permits any peer.
//! - [`Gate::Rooted`] permits a peer that *presents a signed token* ([`Cap`]) rooted at a trusted authority
//!   (a [`VerifyKey`] you own). One key you own authorizes both your own devices and anyone you delegate to,
//!   offline and revocably: the thing `authorized_keys` cannot do.
//!
//! One authority signs four grant shapes, verified offline against it:
//! - a **membership badge** ([`Identity::mint_member`]): whole-node admission, bound to one device;
//! - a **device-bound slip** ([`Identity::mint_bound`]): one service, bound to one device;
//! - an **authority-bound slip** ([`Identity::mint_authority_slip`]): one service, open to every device a
//!   foreign authority vouches for;
//! - an **unbound slip** ([`Identity::mint`]): one service, bearer, delegable by attenuation.
//!
//! A bound grant is theft-resistant and non-delegable; a bearer grant is delegable and short-lived.
//! Attenuation only ADDS checks, so a slip can never be widened into a badge, nor a narrower link
//! broadened back.
//!
//! The token is a [biscuit](biscuit_auth): an ed25519-signed, datalog-attenuable capability. nauthy never
//! hand-rolls crypto; it wraps a vetted library behind a small parse-don't-validate [`Cap`] type, adds a
//! signed membership claim, and revokes offline through a [`Revocations`] store (the batteries-included one
//! is [`FileDenylist`]).
//!
//! # Identities: authorized, not provisioned
//!
//! nauthy authorizes PROVEN identities; it does not provision them. An identity is any 32-byte ed25519
//! secret ([`Identity::from_secret`]), generated fresh ([`Identity::generate`] / [`Identity::from_rng`]) or
//! supplied by your identity layer. Deriving many device secrets from one root seed (HD-style, so one
//! person's devices share an authority) is that identity layer's job, not nauthy's: nauthy mints a device
//! badge for whatever [`VerifyKey`] you name in `bound_to`, and where that device's secret comes from is
//! above the auth layer.
//!
//! # Security preconditions (the offline-verify TCB)
//!
//! Offline verification trusts what it cannot check. A consumer MUST uphold all of:
//! - **The peer is TRANSPORT-PROVEN.** [`Gate::admit`] takes a [`ProvenPeer`], minted only from a completed
//!   handshake; a key from an unauthenticated hello voids every device binding. The type marks this seam
//!   loudly but cannot enforce it (nauthy has no transport), so the proof is the caller's contract.
//! - **The secret stays secret AND never signs hostile bytes.** [`Identity::sign_document`] domain-separates
//!   its signatures so a document signature can never be reused as a biscuit block signature.
//! - **The revocation store is DURABLE and never reset-to-empty.** A restart on ephemeral storage
//!   resurrects every revoked cap (an absent [`FileDenylist`] file is an empty set). A monotone high-water
//!   mark is out of scope; durable storage is the precondition.
//! - **The local clock is roughly right, or expiries are short.** Expiry is checked against the local clock;
//!   a badly-wrong clock widens or voids a grant's window.

mod cap;
mod gate;
mod key;
mod revocations;
mod service;
mod signed;

#[cfg(test)]
mod cap_tests;
#[cfg(test)]
mod gate_tests;
#[cfg(test)]
mod revocations_tests;
#[cfg(test)]
mod signed_tests;

pub use crate::cap::{Cap, CapError, Identity, Request, SCHEME};
pub use crate::gate::{Admission, Admitted, Decision, Gate, ProvenPeer, Refusal};
pub use crate::key::{KeyParseError, VerifyKey};
#[cfg(feature = "tokio-fs")]
pub use crate::revocations::{DenylistError, FileDenylist};
pub use crate::revocations::{RevocationId, RevocationIdParseError, Revocations};
pub use crate::service::{Service, ServiceParseError};
pub use crate::signed::{SignError, Signed};
