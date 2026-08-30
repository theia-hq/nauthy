//! nauthy: control-plane-free authorization. Given a peer identity that a transport has already proven,
//! decide whether it may connect, with no server, no PKI, and no registry.
//!
//! Authorization here is policy on *proven* identities, not crypto: a transport handshake has already
//! proven the peer holds the private key behind its [`NodeId`], so the question is only whether that
//! identity is permitted. nauthy sits above the transport and never reaches out itself, so it is usable
//! wherever a peer can be named by an ed25519 key, theia or not.
//!
//! Two policies:
//! - [`Gate::Open`] permits any peer.
//! - [`Gate::Family`] permits a peer that *presents a signed token* ([`Cap`]) rooted at a trusted signet,
//!   granting either MEMBERSHIP (a whole-node `member(true)` badge) or the requested SERVICE (a delegated
//!   slip). One key you own authorizes both your own devices and anyone you delegate to, offline and
//!   revocably: the thing `authorized_keys` cannot do.
//!
//! The token is a [biscuit](biscuit_auth): an ed25519-signed, datalog-attenuable capability. nauthy never
//! hand-rolls crypto; it wraps a vetted library behind a small parse-don't-validate [`Cap`] type, adds a
//! signed membership claim, and revokes offline via a node-local [`Denylist`].

mod cap;
mod gate;
mod revocations;
mod service;

#[cfg(test)]
mod cap_tests;
#[cfg(test)]
mod gate_tests;

pub use bifrost_core::NodeId;

pub use crate::cap::{Cap, CapError, Identity, Request, SCHEME, expires_in};
pub use crate::gate::{Admitted, Decision, Gate, Refusal};
pub use crate::revocations::{Denylist, DenylistError};
pub use crate::service::{Service, ServiceParseError};
