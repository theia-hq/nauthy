//! nauthy: control-plane-free authorization. Given a peer identity that a transport has already proven,
//! decide whether it may connect, with no server, no PKI, and no registry.
//!
//! Authorization here is policy on *proven* identities, not crypto: a transport handshake has already
//! proven the peer holds the private key behind its [`VerifyKey`], so the question is only whether that
//! identity is permitted. nauthy sits above the transport and never reaches out itself, so it is usable
//! wherever a peer can be named by an ed25519 key, theia or not.
//!
//! Two policies:
//! - [`Gate::Open`] permits any peer.
//! - [`Gate::Family`] permits a peer that *presents a signed token* ([`Cap`]) rooted at a trusted signet
//!   (a `NodeId` you own). One key you own authorizes both your own devices and anyone you delegate to,
//!   offline and revocably: the thing `authorized_keys` cannot do.
//!
//! One signet signs four grant shapes, verified offline against it:
//! - a **membership badge** ([`Identity::mint_member`]): whole-node admission, bound to one device;
//! - a **device-bound slip** ([`Identity::mint_bound`]): one service, bound to one device;
//! - a **signet-bound slip** ([`Identity::mint_signet_slip`]): one service, open to every device a foreign
//!   signet vouches for;
//! - an **unbound slip** ([`Identity::mint`]): one service, bearer, delegable by attenuation.
//!
//! A bound grant is theft-resistant and non-delegable; a bearer grant is delegable and short-lived.
//! Attenuation only ADDS checks, so a slip can never be widened into a badge, nor a narrower link
//! broadened back.
//!
//! The token is a [biscuit](biscuit_auth): an ed25519-signed, datalog-attenuable capability. nauthy never
//! hand-rolls crypto; it wraps a vetted library behind a small parse-don't-validate [`Cap`] type, adds a
//! signed membership claim, and revokes offline via a node-local [`Denylist`].

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

pub use crate::cap::{Cap, CapError, Identity, Request, SCHEME, expires_in};
pub use crate::gate::{Admitted, Decision, Gate, Refusal};
pub use crate::key::{KeyParseError, VerifyKey};
pub use crate::revocations::{Denylist, DenylistError, RevocationId, RevocationIdParseError};
pub use crate::service::{Service, ServiceParseError};
pub use crate::signed::{SignError, Signed};
