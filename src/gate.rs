//! The authorization gate: the policy that decides whether a proven peer may connect.

use std::time::SystemTime;

use crate::cap::{Cap, Request};
use crate::revocations::Revocations;
use crate::{Service, VerifyKey};

/// An authorization policy over proven peer identities.
///
/// A caller that has already PROVEN a peer's identity (a transport handshake proves the peer holds the key
/// behind its [`VerifyKey`], see [`ProvenPeer`]) asks a `Gate` whether that peer may reach a service. nauthy
/// stays above any transport: a gate decides on *identities and tokens*, never on how the peer was reached,
/// so it is usable wherever a peer can be named by an ed25519 key.
///
/// - [`Gate::Open`] admits anyone (the one deliberate opt-out; nothing to prove).
/// - [`Gate::Rooted`] admits a peer that presents a signed token rooted at a trusted authority: a MEMBERSHIP
///   badge (a whole-node `member` cap, "this device is mine") OR a delegated SLIP (a [`Cap`] granting the
///   requested service, "this friend may reach this service"). One signature, two meanings, verified
///   offline against one key, revocable by a [`Revocations`] store. This is the wedge: trust is a single
///   key you own, not a list of keys to keep in sync, which is why there is no allowlist gate. An
///   authority-rooted membership badge IS the allowlist, and a better one: delegatable, attenuable,
///   revocable, no sync.
pub enum Gate {
    /// Admit any peer.
    Open,
    /// Admit a peer that presents a signed token rooted at the trusted authority [`VerifyKey`], unexpired
    /// and not recalled by the [`Revocations`] store, granting either MEMBERSHIP (a whole-node `member`
    /// badge) or the requested SERVICE (a delegated slip). The owner's own devices carry a badge their
    /// authority signed once; a delegated friend carries a service slip; both root at the same authority and
    /// are honored here. Only the authority can mint a badge, so a delegated slip can never be attenuated
    /// into one. The revocation oracle is boxed as a trait object so a consumer can back it with any store
    /// (a file, Redis, a database, a gossip set) and `Gate` stays one concrete type with no revocation type
    /// parameter to thread. The box is `Send + Sync` so a `Gate` can be shared across async tasks (a server
    /// hands one gate to every connection); a custom [`Revocations`] impl stored in a gate must be too.
    Rooted(VerifyKey, Box<dyn Revocations + Send + Sync>),
}

impl Gate {
    /// Build a [`Rooted`](Gate::Rooted) gate trusting `authority`, refusing any presented token the
    /// `revocations` store recalls.
    ///
    /// The constructor for the boxed variant, so a caller never hand-writes the `Box::new(revocations)`.
    /// The caller brings whatever revocation store it keeps (the batteries-included
    /// [`FileDenylist`](crate::FileDenylist), or its own [`Revocations`] impl over a database or gossip
    /// set); building an [`Open`](Gate::Open) gate is the caller's own choice, so it is built at the call
    /// site, not here. `Send + Sync` so the built gate can be shared across async tasks.
    pub fn rooted(
        authority: VerifyKey,
        revocations: impl Revocations + Send + Sync + 'static,
    ) -> Gate {
        Gate::Rooted(authority, Box::new(revocations))
    }

    /// Decide whether a peer presenting an optional capability may reach `service`.
    ///
    /// The plain admission path: a membership badge, a plain slip, or a device-bound slip. One optional cap,
    /// no positional ambiguity. [`Open`](Gate::Open) admits unconditionally. [`Rooted`](Gate::Rooted) rules
    /// on the presented token, not the dialer (the token, not who carries it, is the authority, but
    /// device-bound so only the named device may present it): it admits a membership badge or a slip for
    /// `service`, rooted at the trusted authority; a missing, non-granting, or revoked token is refused with
    /// a reason. An authority-bound slip handed here correctly refuses [`NotGranted`](Refusal::NotGranted)
    /// (it is inert alone); the two-token AND is [`admit_foreign`](Gate::admit_foreign).
    pub fn admit(&self, peer: ProvenPeer, presented: Option<&Cap>, service: &Service) -> Decision {
        match self {
            Gate::Open => Decision::Admit,
            Gate::Rooted(root, revocations) => {
                admit_plain(*root, revocations.as_ref(), presented, service, peer.key())
            }
        }
    }

    /// Decide whether a peer may reach `service` on the AUTHORITY-BOUND two-token AND: a `slip` this gate's
    /// authority signed naming a FOREIGN authority `X`, AND a membership `badge` that verifies under that
    /// `X`. Both caps are REQUIRED and NAMED, so there is no positional ambiguity and neither can be omitted
    /// by mistake.
    ///
    /// `X` comes from the SLIP (never the badge); the proven `peer` is bound into both checks. The slip is
    /// inert on the plain path ([`admit`](Gate::admit)), so this method is the only way a foreign member is
    /// admitted. [`Open`](Gate::Open) admits unconditionally.
    pub fn admit_foreign(
        &self,
        peer: ProvenPeer,
        slip: &Cap,
        badge: &Cap,
        service: &Service,
    ) -> Decision {
        match self {
            Gate::Open => Decision::Admit,
            Gate::Rooted(root, revocations) => admit_authority_bound(
                *root,
                revocations.as_ref(),
                slip,
                badge,
                service,
                peer.key(),
            ),
        }
    }

    /// Whether this gate decides on a presented token rather than the dialer's identity alone. The connect
    /// path presents a token only for a [`Rooted`](Gate::Rooted) gate, so `false` means "no token required".
    pub fn wants_capability(&self) -> bool {
        matches!(self, Gate::Rooted(..))
    }

    /// Like [`admit`](Gate::admit) but yields an [`Admitted`] witness on success. The witness has no
    /// public constructor, so a service handler that requires one (e.g. a keyless shell) CANNOT be reached
    /// without a gate having permitted the peer: "authorize before serve" becomes a compile-time
    /// precondition, not a statement order a refactor could quietly drop.
    pub fn admit_witnessed(
        &self,
        peer: ProvenPeer,
        presented: Option<&Cap>,
        service: &Service,
    ) -> Result<Admitted, Refusal> {
        match self {
            // A public node proves nothing about a peer, so it cannot have admitted a MEMBER: the kind is
            // `Slip` (fail-closed). `is_member()` is therefore false on an open node, exactly as a caller
            // layering a member-only ceiling must see it. A default-to-`Member` here would be a trust break.
            Gate::Open => Ok(Admitted {
                peer: peer.key(),
                kind: Admission::Slip,
            }),
            // A rooted gate DID rule on a token. Re-read the same member-vs-grant distinction the ruling
            // used (`is_member` before `grants`, `admit_plain`): a whole-node membership badge is `Member`,
            // a per-service delegated slip is `Slip`. Any other outcome is a refusal, never a witness.
            // `is_member` is checked first, so a badge is `Member` even where it would also grant.
            Gate::Rooted(root, revocations) => {
                match admit_plain(*root, revocations.as_ref(), presented, service, peer.key()) {
                    Decision::Admit => {
                        let kind = match presented {
                            Some(cap) if is_member(cap, *root, peer.key()) => Admission::Member,
                            _ => Admission::Slip,
                        };
                        Ok(Admitted {
                            peer: peer.key(),
                            kind,
                        })
                    }
                    Decision::Refuse(refusal) => Err(refusal),
                }
            }
        }
    }

    /// Like [`admit_foreign`](Gate::admit_foreign) but yields an [`Admitted`] witness on success. The
    /// admission is always [`Admission::Slip`], NEVER [`Member`](Admission::Member): a foreign-authority
    /// member deliberately collapses to `Slip` (fail-closed), because a member of a FOREIGN authority is not
    /// a whole-node member of THIS node, so owner-only lifecycle verbs stay closed to them.
    pub fn admit_foreign_witnessed(
        &self,
        peer: ProvenPeer,
        slip: &Cap,
        badge: &Cap,
        service: &Service,
    ) -> Result<Admitted, Refusal> {
        match self {
            Gate::Open => Ok(Admitted {
                peer: peer.key(),
                kind: Admission::Slip,
            }),
            Gate::Rooted(root, revocations) => {
                match admit_authority_bound(
                    *root,
                    revocations.as_ref(),
                    slip,
                    badge,
                    service,
                    peer.key(),
                ) {
                    Decision::Admit => Ok(Admitted {
                        peer: peer.key(),
                        kind: Admission::Slip,
                    }),
                    Decision::Refuse(refusal) => Err(refusal),
                }
            }
        }
    }
}

/// A peer identity a transport handshake has PROVEN the peer holds the secret for.
///
/// nauthy cannot check this, and every device binding rests on it: [`Gate::admit`] takes a `ProvenPeer`,
/// never a bare [`VerifyKey`], so the one precondition a caller MUST uphold is NAMED and LOCALIZED at a
/// single, greppable, loudly-documented seam rather than scattered. This is a WELL-MARKED PRECONDITION
/// enforced by contract at that seam, NOT a guarantee proven by the type system: nauthy has no transport to
/// check, so a caller can still construct a `ProvenPeer` from an unproven key. The transport-proof audit is
/// therefore not optional. What the type buys over a bare `VerifyKey` is that the F2 mistake (gating on a
/// key read from an unauthenticated hello) can no longer be made SILENTLY, and is trivial to audit for.
///
/// Unlike [`Admitted`] (a single-use witness, `!Copy`), a `ProvenPeer` is a reusable FACT (`Copy`): one
/// proven peer may open many streams, and [`Gate::admit`] re-evaluates the token, binding, and revocation
/// fresh on every call, so copying it copies only a public key plus the assertion, never an authorization.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ProvenPeer(VerifyKey);

impl ProvenPeer {
    /// Assert that a COMPLETED transport handshake proved the peer holds the secret behind `key`. Call
    /// this ONLY from the code that finished the handshake, with the key the handshake proved, NEVER with
    /// a key from a request header, a self-reported hello, or any unauthenticated claim. Everything
    /// device-bound (`mint_member`, `mint_bound`, the two-token AND) is void if this contract is broken.
    pub fn from_handshake(key: VerifyKey) -> Self {
        Self(key)
    }

    /// The proven identity.
    pub fn key(&self) -> VerifyKey {
        let Self(key) = self;
        *key
    }
}

/// Proof that a [`Gate`] admitted a connection, naming WHO was admitted and by WHAT KIND of authority.
///
/// An opaque witness with no public constructor: the only way to obtain one is [`Gate::admit_witnessed`]
/// (or [`Gate::admit_foreign_witnessed`]) returning `Ok`. A service handler that takes an `Admitted`
/// therefore cannot be called without a gate having permitted the peer, so "authorize before serve" is
/// enforced by the type system, not by the order of statements. The gate mints exactly one per ruling;
/// there is no other way to make one, so a handler that receives it can trust it without re-checking.
///
/// It is deliberately neither `Copy` nor `Clone` (asserted below, `admitted_is_single_use`): a witness is a
/// SINGLE-USE, per-stream proof. A consumer takes it BY VALUE, so minting one witness
/// authorizes exactly one serve; it cannot be duplicated and replayed onto a second stream the gate never
/// ruled on. It now carries the verified [`peer`](Admitted::peer) and the [`kind`](Admitted::kind) of
/// admission, so a handler MAY layer a finer per-request policy on the gate's floor (an owner-only lifecycle
/// verb reads [`is_member`](Admitted::is_member)); the single-use guarantee still relies on admit and serve
/// sharing one stream frame (never hoist the admit above a per-stream loop), but single-use consumption
/// removes the accidental-reuse footgun by construction. Adding a `Clone` derive here re-arms that replay,
/// so the negative-trait assertion below is a fail-if-you-try guard, not documentation.
#[derive(Debug)]
#[must_use = "an Admitted witness proves a gate ran; serve the one stream it authorized"]
pub struct Admitted {
    peer: VerifyKey,
    kind: Admission,
}

impl Admitted {
    /// The verified identity the gate admitted. The transport handshake proved this key before the gate
    /// ruled, so it is an un-forgeable fact, not a claim the peer made.
    pub fn peer(&self) -> VerifyKey {
        self.peer
    }

    /// By WHAT authority this peer was admitted: a whole-node [`Member`](Admission::Member) badge or a
    /// per-service [`Slip`](Admission::Slip). A handler layering an owner-only ceiling reads this.
    pub fn kind(&self) -> Admission {
        self.kind
    }

    /// Whether this peer was admitted as a whole-node MEMBER (a `member(true)` badge), not via a per-service
    /// slip. False on a public node, where nothing about the peer is proven (the kind is [`Slip`]). A
    /// lifecycle verb that only an owner device may trigger gates on this.
    ///
    /// [`Slip`]: Admission::Slip
    pub fn is_member(&self) -> bool {
        matches!(self.kind, Admission::Member)
    }
}

/// The AUTHORITY a [`Gate`] admitted a peer under: the two meanings a rooted token can carry.
///
/// A whole-node membership badge and a per-service slip are one signature verified against one authority,
/// but they mean different things (a whole-node member and a per-service slip mean different things, so a
/// handler that must tell an owner device from a delegated friend reads the kind off the witness), so the
/// distinction is on the witness, not just "admitted or not". It carries no data and is a plain `Copy` tag,
/// unlike [`Admitted`] itself, whose absence of `Copy`/`Clone` is the single-use guarantee; distinguishing
/// the two is deliberate (the witness is single-use, its kind is a fact you may read as often as you like).
///
/// A foreign-authority member deliberately collapses to [`Slip`](Admission::Slip): a foreign member never
/// reads as a whole-node member of THIS node (fail-closed). A stranger who needs to distinguish "delegated
/// bearer" from "foreign-authority member" on the witness cannot in this release.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Admission {
    /// Admitted via a whole-node membership badge (`member(true)`): an owner's own device.
    Member,
    /// Admitted via a per-service capability grant (a delegated slip), a foreign-authority membership, or an
    /// open gate where nothing about the peer is proven. The fail-closed kind: any admission that is not
    /// provably a whole-node member of THIS node is `Slip`.
    Slip,
}

// `Admitted` is a SINGLE-USE witness: cloning or copying it would let a caller replay one gate ruling onto a
// second stream the gate never admitted (a shell re-served to an unadmitted peer). This assertion fails to
// compile if anyone adds a `Clone` or `Copy` derive, so the invariant is enforced by the compiler, not by a
// reviewer remembering it. `Admission` (the read-only kind tag) may be `Copy`; only the witness may not.
#[cfg(test)]
static_assertions::assert_not_impl_any!(Admitted: Clone, Copy);

/// The plain admission path: a peer that presents a token rooted at the authority `root`, unrevoked,
/// granting membership OR the requested `service`. One signature, two meanings: a device carries a
/// MEMBERSHIP badge (a `member(true)` authority fact, whole-node), a delegated friend carries a SLIP (a
/// check for the requested service); either authorizes. The two are distinct questions (membership is not a
/// service name), so a slip can never be widened into whole-node admission (see
/// [`Cap::verify_member_at_root_without_revocation`]). An authority-bound slip is inert here (its
/// `foreign_member` check is unsatisfied on the plain path); the two-token AND is `admit_authority_bound`.
fn admit_plain(
    root: VerifyKey,
    revocations: &dyn Revocations,
    presented: Option<&Cap>,
    service: &Service,
    peer: VerifyKey,
) -> Decision {
    let Some(cap) = presented else {
        return Decision::Refuse(Refusal::Missing);
    };
    if is_member(cap, root, peer) || grants(cap, root, service, peer) {
        return revoked_or_admit(revocations, cap);
    }
    Decision::Refuse(Refusal::NotGranted)
}

/// The authority-bound two-token AND: `slip` is a slip rooted at `root` naming a FOREIGN authority `X`; the
/// presenter must ALSO prove membership under `X` with `badge`. `X` comes from the SLIP (never the badge);
/// the proven `peer` (the transport-proven dialer) is bound into both checks.
fn admit_authority_bound(
    root: VerifyKey,
    revocations: &dyn Revocations,
    slip: &Cap,
    badge: &Cap,
    service: &Service,
    peer: VerifyKey,
) -> Decision {
    let request = Request::now(Service::clone(service)).bound_to(peer);
    if let Ok(x) = slip.verify_authority_bound_at_root_without_revocation(&request, root) {
        // `X` is the authority the slip named, fed straight into the badge's root check. There is no path
        // that reads a badge-supplied root: `verify_member_at_root_without_revocation` only compares the
        // badge's own root AGAINST this `x`, so a badge under the wrong root fails `ForeignRoot`. The badge
        // is device-bound, so a stolen slip+badge replayed from a different key fails the bound-device check.
        let member_under_x = badge
            .verify_member_at_root_without_revocation(SystemTime::now(), peer, x)
            .is_ok();
        if member_under_x {
            return revoked_or_admit(revocations, slip);
        }
    }
    Decision::Refuse(Refusal::NotGranted)
}

/// A granted cap that is revoked is still refused; else admit. The revocation store governs the SLIP (rooted
/// at `root`); an authority-bound slip's foreign badge (rooted at `X`) is out of this node's revocation
/// authority. A foreign authority is the party that revokes a lost DEVICE in its own set; this node's only
/// lever over a foreign member is revoking the whole SLIP (all-or-nothing), inherent to cross-authority
/// trust. Checked after the grant so a token that never granted (foreign root, wrong service) reports
/// `NotGranted`, not `Revoked`.
fn revoked_or_admit(revocations: &dyn Revocations, cap: &Cap) -> Decision {
    if revocations.is_revoked(cap) {
        return Decision::Refuse(Refusal::Revoked);
    }
    Decision::Admit
}

/// Whether `cap` is a MEMBERSHIP badge rooted at `root` for the proven dialer `peer`, evaluated now: it
/// carries the `member(true)` authority fact and its device binding holds for `peer`. Whole-node.
fn is_member(cap: &Cap, root: VerifyKey, peer: VerifyKey) -> bool {
    cap.verify_member_at_root_without_revocation(SystemTime::now(), peer, root)
        .is_ok()
}

/// Whether `cap` grants `service` rooted at `root` for the proven dialer `peer`, evaluated now. The `peer`
/// is bound into the request so a device-bound cap admits only its device; an unbound slip ignores it.
fn grants(cap: &Cap, root: VerifyKey, service: &Service, peer: VerifyKey) -> bool {
    cap.verify_at_root_without_revocation(
        &Request::now(Service::clone(service)).bound_to(peer),
        root,
    )
    .is_ok()
}

/// The gate's ruling on a connection attempt.
#[must_use = "an authorization Decision must be acted on; dropping it fails open"]
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

/// Why a connection was refused, distinct reasons a caller reports differently.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A [`Rooted`](Gate::Rooted) gate required a token and none was presented.
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
            Refusal::Missing => "no capability presented",
            Refusal::NotGranted => "capability does not grant this request",
            Refusal::Revoked => "capability has been revoked",
        };
        f.write_str(reason)
    }
}
