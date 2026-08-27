//! nauthy: the authorization gate. Given a peer identity that the transport has already proven, decide
//! whether it may connect.
//!
//! Authorization here is policy on *proven* identities, not crypto: a bifrost transport handshake has
//! already proven the peer holds the private key behind its [`NodeId`], so the question is only whether
//! that identity is permitted. nauthy sits ABOVE bifrost, so reach stays policy-free.
//!
//! Four policies, floor to profound:
//! - [`Gate::Open`] permits any peer that reached the key.
//! - [`Gate::Strict`] permits a fixed allowlist of node ids.
//! - [`Gate::Paired`] permits a persisted, consent-grown approved set (see [`Approvals`]).
//! - [`Gate::Cap`] permits a peer that *presents a capability* ([`Cap`]) which verifies against this
//!   node's own identity for the requested service. This is the wedge: a bearer token the exposer mints,
//!   the holder can narrow and hand off offline, and the exposer verifies with no central authority.
//!
//! The first three answer `authorized_keys`; the fourth is the thing `authorized_keys` cannot do. It is
//! built on [`biscuit-auth`](biscuit_auth), an ed25519-signed, datalog-attenuable token: nauthy never
//! hand-rolls crypto, it wraps a vetted library behind a small parse-don't-validate [`Cap`] type.

mod approvals;
mod cap;
mod gate;
mod service;

#[cfg(test)]
mod cap_tests;
#[cfg(test)]
mod gate_tests;

pub use bifrost_core::NodeId;

pub use crate::approvals::{Approvals, ApprovalsError};
pub use crate::cap::{Cap, CapError, Identity, Request, SCHEME, expires_in};
pub use crate::gate::{Decision, Gate, Refusal};
pub use crate::service::{Service, ServiceParseError};
