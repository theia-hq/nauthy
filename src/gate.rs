//! The authorization gate: the policy that decides whether a proven peer may connect.

use crate::approvals::Approvals;
use crate::cap::{Cap, Identity, Request};
use crate::{NodeId, Service};

/// An authorization policy over proven peer identities.
///
/// The transport has already proven the peer holds the key behind its [`NodeId`]; a `Gate` decides
/// whether that identity, or a capability it presents, is permitted. The first three variants gate on
/// *who* the peer is (allowlist-style); [`Gate::Cap`] gates on *what token* the peer presents, which is
/// the wedge: authority travels in a bearer capability, not in a list of keys to keep in sync.
pub enum Gate {
    /// Permit any peer that reached the key.
    Open,
    /// Permit only peers on a fixed allowlist.
    Strict(std::collections::HashSet<NodeId>),
    /// Permit only peers in a persisted, consent-grown approved set.
    Paired(Approvals),
    /// Permit a peer iff it presents a [`Cap`] that verifies against this node's own identity for the
    /// requested service and is unexpired. No allowlist, no server: the exposer holds only its own
    /// secret, and every grant it ever issued verifies offline against it.
    Cap(Identity),
}

impl Gate {
    /// Decide whether a peer presenting an optional capability may reach `service`.
    ///
    /// The identity-gated variants ([`Open`](Gate::Open), [`Strict`](Gate::Strict),
    /// [`Paired`](Gate::Paired)) ignore any presented cap and rule on `peer` alone. [`Cap`](Gate::Cap)
    /// ignores `peer` (the token, not the dialer, carries the authority) and requires a cap that verifies
    /// for `service`; a missing or non-granting cap is refused with a reason.
    pub fn admit(&self, peer: NodeId, presented: Option<&Cap>, service: &Service) -> Decision {
        match self {
            Gate::Open => Decision::Admit,
            Gate::Strict(allowed) => Decision::from(allowed.contains(&peer)),
            Gate::Paired(approvals) => Decision::from(approvals.keys().contains(&peer)),
            Gate::Cap(identity) => admit_cap(identity, presented, service),
        }
    }

    /// Whether this gate decides on a presented capability rather than on the dialer's identity. The
    /// connect path needs a cap only for a [`Cap`](Gate::Cap) gate, so a `false` here means "no token
    /// required".
    pub fn wants_capability(&self) -> bool {
        matches!(self, Gate::Cap(_))
    }
}

/// Verify a presented cap for the requested service against the exposer's identity.
fn admit_cap(identity: &Identity, presented: Option<&Cap>, service: &Service) -> Decision {
    let Some(cap) = presented else {
        return Decision::Refuse(Refusal::Missing);
    };
    let request = Request::now(Service::clone(service));
    match identity.verify(cap, &request) {
        Ok(_) => Decision::Admit,
        Err(_) => Decision::Refuse(Refusal::NotGranted),
    }
}

/// The gate's ruling on a connection attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// The peer may connect.
    Admit,
    /// The peer may not connect, with why.
    Refuse(Refusal),
}

impl Decision {
    /// Whether the decision admits the peer.
    pub fn is_admitted(&self) -> bool {
        matches!(self, Decision::Admit)
    }
}

impl From<bool> for Decision {
    /// An identity-list check reduces to admit-or-refuse; a `false` is a plain not-permitted refusal.
    fn from(permitted: bool) -> Self {
        if permitted {
            Decision::Admit
        } else {
            Decision::Refuse(Refusal::NotPermitted)
        }
    }
}

/// Why a connection was refused, distinct reasons a caller reports differently.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peer's identity was not on the allowlist or approved set.
    NotPermitted,
    /// A capability gate required a token and none was presented.
    Missing,
    /// A capability was presented but did not grant the request (foreign root, wrong service, expired).
    NotGranted,
}
