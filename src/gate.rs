//! The authorization gate: the policy that decides whether a proven peer may connect.

use crate::cap::{Cap, Request, verify_at_root};
use crate::revocations::Denylist;
use crate::{NodeId, Service};

/// An authorization policy over proven peer identities.
///
/// A caller that has already PROVEN a peer's identity (a transport handshake proves the peer holds the key
/// behind its [`NodeId`]) asks a `Gate` whether that peer may reach a service. nauthy stays above any
/// transport: a gate decides on *identities and tokens*, never on how the peer was reached, so it is usable
/// wherever a peer can be named by an ed25519 key.
///
/// - [`Gate::Open`] admits anyone.
/// - [`Gate::Strict`] admits a fixed allowlist of keys: the signet-less floor, naming who may connect.
/// - [`Gate::Family`] admits a peer that presents a signed token rooted at a trusted signet: a MEMBERSHIP
///   badge (a [`Cap`] granting [`Service::membership`], whole-node, "this device is mine") OR a delegated
///   SLIP (a [`Cap`] granting the requested service, "this friend may reach this service"). One signature,
///   two meanings, verified offline against one key, revocable by the [`Denylist`]. This is the wedge:
///   trust is a single key you own, not a list of keys to keep in sync.
pub enum Gate {
    /// Admit any peer.
    Open,
    /// Admit only peers whose key is on this allowlist.
    Strict(std::collections::HashSet<NodeId>),
    /// Admit a peer that presents a signed token rooted at the trusted signet [`NodeId`], unexpired and
    /// not on the revocation [`Denylist`], granting either MEMBERSHIP (a badge for
    /// [`Service::membership`], admitting to the whole node) or the requested SERVICE (a delegated slip).
    /// The owner's own devices carry a badge their signet signed once; a delegated friend carries a
    /// service slip; both root at the same signet and are honored here. Only the signet can mint a badge,
    /// so a delegated slip can never be attenuated into one. The denylist is boxed to keep the enum small
    /// (clippy's `large_enum_variant`).
    Family(NodeId, Box<Denylist>),
}

impl Gate {
    /// Decide whether a peer presenting an optional capability may reach `service`.
    ///
    /// The identity gates ([`Open`](Gate::Open), [`Strict`](Gate::Strict)) ignore any presented token and
    /// rule on `peer` alone. [`Family`](Gate::Family) rules on the presented token, not the dialer (the
    /// token, not who carries it, is the authority): it admits a membership badge or a slip for `service`,
    /// rooted at the trusted signet; a missing, non-granting, or revoked token is refused with a reason.
    pub fn admit(&self, peer: NodeId, presented: Option<&Cap>, service: &Service) -> Decision {
        match self {
            Gate::Open => Decision::Admit,
            Gate::Strict(allowed) => Decision::from(allowed.contains(&peer)),
            Gate::Family(root, denylist) => admit_family(*root, denylist, presented, service, peer),
        }
    }

    /// Whether this gate decides on a presented token rather than the dialer's identity alone. The connect
    /// path presents a token only for a [`Family`](Gate::Family) gate, so `false` means "no token required".
    pub fn wants_capability(&self) -> bool {
        matches!(self, Gate::Family(..))
    }

    /// Like [`admit`](Gate::admit) but yields an [`Admitted`] witness on success. The witness has no
    /// public constructor, so a service handler that requires one (e.g. a keyless shell) CANNOT be reached
    /// without a gate having permitted the peer: "authorize before serve" becomes a compile-time
    /// precondition, not a statement order a refactor could quietly drop.
    pub fn admit_witnessed(
        &self,
        peer: NodeId,
        presented: Option<&Cap>,
        service: &Service,
    ) -> Result<Admitted, Refusal> {
        match self.admit(peer, presented, service) {
            Decision::Admit => Ok(Admitted(())),
            Decision::Refuse(refusal) => Err(refusal),
        }
    }
}

/// Proof that a [`Gate`] admitted a connection.
///
/// An opaque witness with no public constructor: the only way to obtain one is [`Gate::admit_witnessed`]
/// returning `Ok`. A service handler that takes an `Admitted` therefore cannot be called without a gate
/// having permitted the peer, so "authorize before serve" is enforced by the type system, not by the order
/// of statements. It carries nothing; it exists only to be un-forgeable outside nauthy.
#[derive(Debug, Clone, Copy)]
pub struct Admitted(());

/// Admit a peer that presents a token rooted at the signet `root`, unrevoked, granting membership OR the
/// requested `service`. One signature, two meanings: a device carries a badge (the reserved membership
/// service, whole-node), a delegated friend carries a slip (the requested service); either authorizes.
fn admit_family(
    root: NodeId,
    denylist: &Denylist,
    presented: Option<&Cap>,
    service: &Service,
    peer: NodeId,
) -> Decision {
    let Some(cap) = presented else {
        return Decision::Refuse(Refusal::Missing);
    };
    if !grants(cap, root, &Service::membership(), peer) && !grants(cap, root, service, peer) {
        return Decision::Refuse(Refusal::NotGranted);
    }
    // Granted, but a revoked token is still refused: the offline recall a bare TTL cannot give. Checked
    // after the grant so a token that never granted (foreign root, wrong service) reports NotGranted.
    if denylist.is_revoked(cap) {
        return Decision::Refuse(Refusal::Revoked);
    }
    Decision::Admit
}

/// Whether `cap` grants `service` rooted at `root` for the proven dialer `peer`, evaluated now. The `peer`
/// is bound into the request so a device-bound membership badge admits only its device; an unbound cap
/// ignores it.
fn grants(cap: &Cap, root: NodeId, service: &Service, peer: NodeId) -> bool {
    verify_at_root(
        cap,
        &Request::now(Service::clone(service)).bound_to(peer),
        root,
    )
    .is_ok()
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
    /// The peer's identity was not on the allowlist.
    NotPermitted,
    /// A [`Family`](Gate::Family) gate required a token and none was presented.
    Missing,
    /// A token was presented but did not grant the request (foreign root, neither membership nor the
    /// requested service, or expired).
    NotGranted,
    /// A capability verified and granted the request, but has been revoked.
    Revoked,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            Refusal::NotPermitted => "not permitted",
            Refusal::Missing => "no capability presented",
            Refusal::NotGranted => "capability does not grant this request",
            Refusal::Revoked => "capability has been revoked",
        };
        f.write_str(reason)
    }
}
