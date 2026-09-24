//! The authorization gate: the policy that decides whether a proven peer may connect.

use std::sync::Arc;
use std::time::SystemTime;

use crate::cap::{Cap, CapError, Request};
use crate::revocations::{RevocationId, Revocations};
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
/// - [`Gate::Anchored`] trusts two authorities: a pin it reads afresh on every admission, ruled exactly as
///   a rooted gate rules on its authority, and this machine's own key, which admits only the service slips
///   this machine recorded issuing and never a member. A machine with no pin admits no member at all.
///
/// A rooted or anchored gate can also witness a proven key that presents nothing ([`Gate::proven`]); the
/// witness carries no authority and reaches only a handler built for it.
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
    /// Admit a peer that presents a token rooted at the pin the [`Anchor`] reads now, ruled as
    /// [`Rooted`](Gate::Rooted) rules, or a service slip rooted at this machine's own key that this machine
    /// recorded issuing. Built only by [`Gate::anchored`].
    Anchored(Anchor),
}

/// Where an anchored gate reads its pin: the root key it trusts for membership and delegated slips.
///
/// Asked on EVERY admission, never once at construction, so a pin written while the gate is serving is
/// trusted at the next connection with no restart. An impl that reads a file must read it fail-closed: a pin
/// it cannot read is `None`, which admits no member, never a pin kept from an earlier read that may since
/// have been replaced. A pin equal to the gate's own key is no pin (see [`Gate::anchored`]).
pub trait PinSource: Send + Sync {
    /// The pinned root key as it stands now, or `None` when this machine trusts no root.
    fn current(&self) -> Option<VerifyKey>;
}

/// A shared source answers as the source it shares, so one instance can back the gate and any other reader
/// that must agree with it on the pin.
impl<P: PinSource + ?Sized> PinSource for Arc<P> {
    fn current(&self) -> Option<VerifyKey> {
        P::current(self)
    }
}

/// The ids this machine recorded when it signed a service slip with its own key.
///
/// An anchored gate admits a slip rooted at its own key only when the slip's
/// [`root_revocation_id`](Cap::root_revocation_id) is here. A copy of the key mints slips whose ids were
/// never recorded, since every mint yields a fresh id even for the same service and lifetime, so a stolen
/// key cannot mint access to this machine. An impl that cannot read its record must answer `false`.
pub trait IssuedIds: Send + Sync {
    /// Whether this machine recorded issuing the slip whose root revocation id is `id`.
    fn is_issued(&self, id: &RevocationId) -> bool;
}

/// What an [`Anchored`](Gate::Anchored) gate trusts: a live pin, this machine's own key, the revocation
/// store, and the record of slips the own key issued.
///
/// The fields are private and [`Gate::anchored`] is the only way to build one, so every anchored gate
/// carries all four and none can be swapped out after the fact.
pub struct Anchor {
    root: Box<dyn PinSource>,
    own: VerifyKey,
    revocations: Box<dyn Revocations + Send + Sync>,
    issued: Box<dyn IssuedIds>,
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

    /// Build an [`Anchored`](Gate::Anchored) gate: `root` names the pin, read on every admission; `own` is
    /// this machine's own key; `revocations` recalls tokens and device keys on both paths; `issued` is the
    /// record of slips `own` signed.
    ///
    /// A token rooted at the pin is ruled exactly as a [`Rooted`](Gate::Rooted) gate rules on its authority.
    /// A token rooted at `own` is admitted only as a service slip: a membership badge `own` signed is
    /// refused, since a machine's own key may not make members, and a slip is admitted only when `issued`
    /// holds its root revocation id. A pin equal to `own` anchors nothing, so a source that reports this
    /// machine's own key cannot turn the own key into a root.
    pub fn anchored(
        root: impl PinSource + 'static,
        own: VerifyKey,
        revocations: impl Revocations + Send + Sync + 'static,
        issued: impl IssuedIds + 'static,
    ) -> Gate {
        Gate::Anchored(Anchor {
            root: Box::new(root),
            own,
            revocations: Box::new(revocations),
            issued: Box::new(issued),
        })
    }

    /// Decide whether a peer presenting an optional capability may reach `service`.
    ///
    /// The plain admission path: a membership badge, a plain slip, or a device-bound slip. One optional cap,
    /// no positional ambiguity. [`Open`](Gate::Open) admits unconditionally. [`Rooted`](Gate::Rooted) rules
    /// on the presented token, not the dialer (the token, not who carries it, is the authority, but
    /// device-bound so only the named device may present it): it admits a membership badge or a slip for
    /// `service`, rooted at the trusted authority; a missing, non-granting, or revoked token is refused with
    /// a reason, a peer whose own key the store revokes ([`is_revoked_peer`](Revocations::is_revoked_peer))
    /// is refused as [`Revoked`](Refusal::Revoked) before any token is read, and a token whose evaluation ran out of time is refused as
    /// [`Undecided`](Refusal::Undecided), which is not an answer about the peer. An authority-bound slip
    /// handed here correctly refuses [`NotGranted`](Refusal::NotGranted) (it is inert alone); the two-token
    /// AND is [`admit_foreign`](Gate::admit_foreign).
    pub fn admit(&self, peer: ProvenPeer, presented: Option<&Cap>, service: &Service) -> Decision {
        match self {
            Gate::Open => Decision::Admit,
            Gate::Rooted(root, revocations) => {
                admit_plain(*root, revocations.as_ref(), presented, service, peer.key())
            }
            Gate::Anchored(anchor) => match anchor.admit(presented, service, peer.key()) {
                Ok(_) => Decision::Admit,
                Err(refusal) => Decision::Refuse(refusal),
            },
        }
    }

    /// Decide whether a peer may reach `service` on the AUTHORITY-BOUND two-token AND: a `slip` this gate's
    /// authority signed naming a FOREIGN authority `X`, AND a membership `badge` that verifies under that
    /// `X`. Both caps are REQUIRED and NAMED, so there is no positional ambiguity and neither can be omitted
    /// by mistake.
    ///
    /// `X` comes from the SLIP (never the badge); the proven `peer` is bound into both checks. The slip is
    /// inert on the plain path ([`admit`](Gate::admit)), so this method is the only way a foreign member is
    /// admitted. The revocation store is asked about BOTH tokens, so a store that disables `X`'s root key
    /// refuses every one of `X`'s devices here. [`Open`](Gate::Open) admits unconditionally.
    ///
    /// The store is asked BEFORE either token is verified, so anyone holding one genuine cap rooted at
    /// `X` can pair it with a slip of their own and learn from the refusal whether this node disabled
    /// `X`: [`Revoked`](Refusal::Revoked) against [`NotGranted`](Refusal::NotGranted). A consumer that puts
    /// refusals on a wire must send those two as one. Timing still separates them, since a disabled root
    /// skips the verify, and no reordering removes that without paying the verify for every recalled
    /// token; the residual is small, because a thief holding `X`'s key learns the same by trying to connect.
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
            Gate::Anchored(anchor) => anchor.admit_foreign(slip, badge, service, peer.key()),
        }
    }

    /// Whether this gate decides on a presented token rather than the dialer's identity alone. `false` means
    /// "no token required", so a caller may skip proving the peer and presenting a token. A
    /// [`Rooted`](Gate::Rooted) and an [`Anchored`](Gate::Anchored) gate both rule on tokens bound to a
    /// proven peer, so both answer `true`, and a caller that records admissions to cut them on a later
    /// revocation records theirs.
    pub fn wants_capability(&self) -> bool {
        // Exhaustive, with no wildcard: a new variant fails to compile here until someone decides whether
        // it rules on tokens, rather than inheriting "no token required" and switching off peer proof.
        match self {
            Gate::Open => false,
            Gate::Rooted(..) | Gate::Anchored(..) => true,
        }
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
            // The origin is `Open`: no token was verified, so a downstream `Never` ceiling must refuse it.
            Gate::Open => Ok(Admitted {
                peer: peer.key(),
                kind: Admission::Slip,
                origin: Origin::Open,
            }),
            // A rooted gate DID rule on a token. Re-read the same member-vs-grant distinction the ruling
            // used (`is_member` before `grants`, `admit_plain`): a whole-node membership badge is `Member`,
            // a per-service delegated slip is `Slip`. Any other outcome is a refusal, never a witness.
            // `is_member` is checked first, so a badge is `Member` even where it would also grant.
            Gate::Rooted(root, revocations) => {
                match admit_plain(*root, revocations.as_ref(), presented, service, peer.key()) {
                    Decision::Admit => Ok(Admitted {
                        peer: peer.key(),
                        kind: admitted_kind(presented, *root, peer.key()),
                        origin: Origin::Rooted,
                    }),
                    Decision::Refuse(refusal) => Err(refusal),
                }
            }
            // A token rooted at the pin reads its kind exactly as a rooted gate does. One rooted at the own
            // key is a `Slip` and never a `Member`: the own-key path never admits a membership badge, so
            // nothing it admitted may pass an owner-only check. Both are `Rooted` in origin, since each
            // verified against one of the gate's own authorities.
            Gate::Anchored(anchor) => {
                let kind = match anchor.admit(presented, service, peer.key())? {
                    Authority::Pin(pin) => admitted_kind(presented, pin, peer.key()),
                    Authority::Own => Admission::Slip,
                };
                Ok(Admitted {
                    peer: peer.key(),
                    kind,
                    origin: Origin::Rooted,
                })
            }
        }
    }

    /// Witness a transport-proven key that presents no token: an [`Origin::Proven`] admission, which carries
    /// no authority at all.
    ///
    /// For a service that answers a peer by its key alone and grants it nothing, such as one that tells a
    /// device what this node already holds for that same key. The witness proves only that the transport
    /// proved the key and that the revocation store does not revoke it, so a consumer serves it only to a
    /// handler that accepts [`Proven`](Origin::Proven), and every rooted-only reader refuses it (see
    /// [`Admitted::peer_verified`]). Its kind is [`Slip`](Admission::Slip), so it is never a member.
    ///
    /// An [`Open`](Gate::Open) gate refuses as [`NotGranted`](Refusal::NotGranted): it is the profile a peer
    /// that only announced its key is admitted under, so its caller proved nothing a `Proven` witness could
    /// stand on. A rooted or anchored gate refuses as [`Revoked`](Refusal::Revoked) a key its store revokes,
    /// and that key's sign twin: the negated point, which anyone holding the revoked secret can prove by
    /// signing with the negated scalar. That is all revoking a key closes here. A key the store does not
    /// revoke is witnessed, so a revoked holder can still reach this path under any fresh key, and under a
    /// torsion twin (the key plus a small-order point) wherever the transport admits one; the store matches
    /// exact bytes, so refusing that twin is the transport's job. A handler that accepts this witness looks a
    /// key up by its exact bytes, never through a form that folds the sign, such as its X25519 conversion.
    pub fn proven(&self, peer: ProvenPeer) -> Result<Admitted, Refusal> {
        let revocations = match self {
            Gate::Open => return Err(Refusal::NotGranted),
            Gate::Rooted(_, revocations) => revocations.as_ref(),
            Gate::Anchored(anchor) => anchor.revocations.as_ref(),
        };
        let key = peer.key();
        if revocations.is_revoked_peer(&key)
            || sign_twin(key).is_some_and(|twin| revocations.is_revoked_peer(&twin))
        {
            return Err(Refusal::Revoked);
        }
        Ok(Admitted {
            peer: key,
            kind: Admission::Slip,
            origin: Origin::Proven,
        })
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
                origin: Origin::Open,
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
                        origin: Origin::Rooted,
                    }),
                    Decision::Refuse(refusal) => Err(refusal),
                }
            }
            Gate::Anchored(anchor) => {
                match anchor.admit_foreign(slip, badge, service, peer.key()) {
                    Decision::Admit => Ok(Admitted {
                        peer: peer.key(),
                        kind: Admission::Slip,
                        origin: Origin::Rooted,
                    }),
                    Decision::Refuse(refusal) => Err(refusal),
                }
            }
        }
    }
}

/// Which of an anchored gate's two authorities a token roots at.
#[derive(Clone, Copy)]
enum Authority {
    /// The pin, as the gate read it for this admission.
    Pin(VerifyKey),
    /// This machine's own key.
    Own,
}

impl Anchor {
    /// The pin as it stands now. A pin equal to the own key is no pin: the own key's tokens are ruled only on
    /// the own-key path, whatever the source reports.
    fn pin(&self) -> Option<VerifyKey> {
        self.root.current().filter(|pin| *pin != self.own)
    }

    /// Which authority `cap` roots at, against the pin read now, or `None` for a token rooted at neither.
    ///
    /// The pin is asked first. Since [`pin`](Self::pin) is never the own key, the two answers cannot
    /// overlap, and a pin that did equal the own key would reach membership only through this order, which
    /// is why the filter is the guard.
    fn authority_of(&self, cap: &Cap) -> Option<Authority> {
        let root = cap.root();
        if self.pin() == Some(root) {
            return Some(Authority::Pin(root));
        }
        if root == self.own {
            return Some(Authority::Own);
        }
        None
    }

    /// The plain path on an anchored gate, naming the authority that admitted on success.
    fn admit(
        &self,
        presented: Option<&Cap>,
        service: &Service,
        peer: VerifyKey,
    ) -> Result<Authority, Refusal> {
        let revocations = self.revocations.as_ref();
        if revocations.is_revoked_peer(&peer) {
            return Err(Refusal::Revoked);
        }
        let Some(cap) = presented else {
            return Err(Refusal::Missing);
        };
        let Some(authority) = self.authority_of(cap) else {
            return Err(Refusal::NotGranted);
        };
        let decision = match authority {
            Authority::Pin(pin) => admit_token(pin, revocations, cap, service, peer),
            Authority::Own => self.admit_own(cap, service, peer),
        };
        match decision {
            Decision::Admit => Ok(authority),
            Decision::Refuse(refusal) => Err(refusal),
        }
    }

    /// A token rooted at this machine's own key, on the plain path: never a membership badge, however its
    /// holder narrowed it (see [`member_badge`]), a slip for `service`, unrevoked on both reads, and recorded
    /// as issued.
    fn admit_own(&self, cap: &Cap, service: &Service, peer: VerifyKey) -> Decision {
        let revocations = self.revocations.as_ref();
        // The first read, before any datalog, for the reason `admit_plain` gives.
        if revocations.is_revoked(cap) {
            return Decision::Refuse(Refusal::Revoked);
        }
        if let Err(refusal) = member_badge(cap).refuse_member() {
            return Decision::Refuse(refusal);
        }
        match grant(cap, self.own, service, peer).decide(revocations, cap) {
            Decision::Admit => self.recorded(cap),
            refused => refused,
        }
    }

    /// The two-token path on an anchored gate. A slip rooted at the pin is ruled as a rooted gate rules it.
    /// A slip rooted at the own key must also be no membership badge (see [`member_badge`]), may not name the own key as its authority, and
    /// must be recorded as issued.
    fn admit_foreign(
        &self,
        slip: &Cap,
        badge: &Cap,
        service: &Service,
        peer: VerifyKey,
    ) -> Decision {
        let revocations = self.revocations.as_ref();
        if pair_is_revoked(revocations, peer, slip, badge) {
            return Decision::Refuse(Refusal::Revoked);
        }
        match self.authority_of(slip) {
            Some(Authority::Pin(pin)) => {
                verify_pair(pin, revocations, slip, badge, service, peer, None)
            }
            Some(Authority::Own) => {
                if let Err(refusal) = member_badge(slip).refuse_member() {
                    return Decision::Refuse(refusal);
                }
                // The own key as the slip's authority would let anyone holding a copy of it badge any key
                // they like into the fleet the slip names, so it is refused before the badge is read.
                match verify_pair(
                    self.own,
                    revocations,
                    slip,
                    badge,
                    service,
                    peer,
                    Some(self.own),
                ) {
                    Decision::Admit => self.recorded(slip),
                    refused => refused,
                }
            }
            None => Decision::Refuse(Refusal::NotGranted),
        }
    }

    /// Admit `cap` only if this machine recorded issuing it.
    fn recorded(&self, cap: &Cap) -> Decision {
        if is_recorded(self.issued.as_ref(), cap.root_revocation_id()) {
            return Decision::Admit;
        }
        Decision::Refuse(Refusal::NotGranted)
    }
}

/// Whether a token with root revocation id `root_id` is in `issued`. A token with no root id was never
/// recorded, since there is nothing to record it by, so it is never issued.
pub(crate) fn is_recorded(issued: &dyn IssuedIds, root_id: Option<RevocationId>) -> bool {
    match root_id {
        Some(id) => issued.is_issued(&id),
        None => false,
    }
}

/// A peer identity a transport handshake has PROVEN the peer holds the secret for.
///
/// nauthy cannot check this, and every device binding rests on it: [`Gate::admit`] takes a `ProvenPeer`,
/// never a bare [`VerifyKey`], so the one precondition a caller MUST uphold is NAMED and LOCALIZED at a
/// single, greppable, loudly-documented place rather than scattered. This is a WELL-MARKED PRECONDITION
/// enforced by contract there, NOT a guarantee proven by the type system: nauthy has no transport to
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
/// An opaque witness with no public constructor: the only ways to obtain one are [`Gate::admit_witnessed`]
/// or [`Gate::admit_foreign_witnessed`] returning `Ok` (a token ruling), and [`Gate::proven`] returning
/// `Ok` (a proven key, no token ruled on). A service handler that takes an `Admitted` therefore cannot be
/// called without a gate having run, so "authorize before serve" is enforced by the type system, not by the
/// order of statements. The gate mints exactly one per ruling or proven-key witness; there is no other way
/// to make one. A handler that receives it can trust that a gate ran, and nothing more: it MUST read
/// [`origin`](Admitted::origin) (or [`peer_verified`](Admitted::peer_verified)) before resting anything on
/// the peer's standing, because a [`Proven`](Origin::Proven) witness carries none.
///
/// It is deliberately neither `Copy` nor `Clone` (asserted below, `admitted_is_single_use`): a witness is a
/// SINGLE-USE, per-stream proof. A consumer takes it BY VALUE, so minting one witness
/// authorizes exactly one serve; it cannot be duplicated and replayed onto a second stream the gate never
/// ruled on. It now carries the admitted [`peer`](Admitted::peer), the [`kind`](Admitted::kind) of
/// admission, and the private [`origin`](Admitted::origin), so a handler MAY layer a finer per-request policy
/// on the gate's floor (an owner-only lifecycle verb reads [`is_member`](Admitted::is_member); an engine whose
/// safety precondition is a root-verified peer reads [`origin`](Admitted::origin)); the single-use guarantee
/// still relies on admit and serve sharing one stream frame (never hoist the admit above a per-stream loop),
/// but single-use consumption removes the accidental-reuse footgun by construction. Adding a `Clone` derive
/// here re-arms that replay, so the negative-trait assertion below is a fail-if-you-try guard, not
/// documentation.
#[derive(Debug)]
#[must_use = "an Admitted witness proves a gate ran; serve the one stream it authorized"]
pub struct Admitted {
    peer: VerifyKey,
    kind: Admission,
    /// How this witness was minted: a rooted token ruling, an open-gate admit, or a proven key with no
    /// token. Module-private: the mints in this file are the only writers, and
    /// [`origin`](Admitted::origin) is the only reader.
    origin: Origin,
}

impl Admitted {
    /// The identity the gate admitted: on a [`Rooted`](Origin::Rooted) or [`Proven`](Origin::Proven)
    /// admission the transport proved this key before the gate ruled; on an [`Open`](Origin::Open)
    /// admission it is the key the peer announced. A caller that needs a token-verified peer reads
    /// [`peer_verified`](Self::peer_verified).
    pub fn peer(&self) -> VerifyKey {
        self.peer
    }

    /// The peer, only when a token rooted at the gate's authority admitted it: `Some` on a
    /// [`Rooted`](Origin::Rooted) admission, `None` on an [`Open`](Origin::Open) or a
    /// [`Proven`](Origin::Proven) one.
    ///
    /// The rooted-only reading. A proven key is a real key but holds no standing here, so a reader that
    /// rests anything on the peer's authority must see nothing rather than a key it could mistake for one.
    pub fn peer_verified(&self) -> Option<VerifyKey> {
        // Exhaustive, with no wildcard: a new origin must be ruled on here, never read as rooted.
        match self.origin {
            Origin::Rooted => Some(self.peer),
            Origin::Open | Origin::Proven => None,
        }
    }

    /// The key a later revocation of this admission is checked against: `Some` on a
    /// [`Rooted`](Origin::Rooted) or [`Proven`](Origin::Proven) admission, whose key the transport proved,
    /// `None` on an [`Open`](Origin::Open) one, whose key was only announced.
    ///
    /// A caller that cuts a live session when its peer's key is revoked records this key when it admits
    /// the stream. A proven admission ruled on no token, so this key is the only thing a cut can find it
    /// by: a caller that records only the tokens it ruled on keeps nothing for it.
    pub fn revocable_peer(&self) -> Option<VerifyKey> {
        // Exhaustive, with no wildcard: a new origin must decide whether its key can be revoked.
        match self.origin {
            Origin::Rooted | Origin::Proven => Some(self.peer),
            Origin::Open => None,
        }
    }

    /// By WHAT authority this peer was admitted: a whole-node [`Member`](Admission::Member) badge or a
    /// per-service [`Slip`](Admission::Slip). A handler layering an owner-only ceiling reads this.
    pub fn kind(&self) -> Admission {
        self.kind
    }

    /// How this peer was admitted: under a ROOTED token ruling, an [`Open`](Origin::Open) gate, or as a
    /// [`Proven`](Origin::Proven) key with no token. Exposed as the enum, never a bool, so a future origin
    /// breaks every match site and forces a decision there instead of silently reading as one of these.
    /// An anchored gate's own-key admissions are `Rooted`; the authority that signed a slip is not an
    /// origin. A downstream ceiling that needs a verified peer refuses everything that is not
    /// [`Rooted`](Origin::Rooted) (fail-closed).
    pub fn origin(&self) -> Origin {
        self.origin
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

/// How a [`Gate`] minted an [`Admitted`] witness: by ruling on a rooted token, by an open gate that ruled
/// on nothing, or by witnessing a proven key that presented nothing.
///
/// The distinction is a downstream handler's safety precondition, not an admission decision: an engine whose
/// safety rests on a root-verified peer (a keyless shell) must refuse an open-minted witness even when its
/// route reached the engine, so the origin travels ON the witness rather than in a side channel. It is a
/// plain tag (no data), and it is exposed as the enum so a future variant forces every match site to decide
/// rather than defaulting into one of these. An anchored gate's own-key admissions are `Rooted`; the
/// authority that signed a slip is not an origin.
///
/// [`Open`](Origin::Open) is the fail-closed read for anything keyless: nothing about the peer was verified,
/// so only a handler that would serve an unauthenticated stranger may accept it.
///
/// The three origins are three disjoint classes of handler, and a consumer that sorts its handlers by what
/// they accept keeps them disjoint:
/// - a handler that needs a verified peer accepts [`Rooted`](Origin::Rooted) only;
/// - a handler that would serve a stranger accepts [`Open`](Origin::Open) and `Rooted`;
/// - a handler built for a proven key with no standing accepts [`Proven`](Origin::Proven) only, and no other
///   class accepts `Proven`.
///
/// So a `Proven` witness never reaches a handler that trusts its peer, and never one that trusts nothing
/// about it either, since the second would then serve the proven key everything it serves a stranger.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Origin {
    /// Admitted after a token rooted at the gate's authority verified (a membership badge or a delegated
    /// service slip), or through the two-token foreign-authority AND. The gate's authority is its pin or, on
    /// an anchored gate, its own key.
    Rooted,
    /// Admitted by an [`Open`](Gate::Open) gate: no token was presented or verified, so nothing about the
    /// peer is proven.
    Open,
    /// Witnessed by [`Gate::proven`]: the transport proved the key and the revocation store does not revoke
    /// it, and no token was presented. It carries no authority, and only a handler built for a proven key
    /// accepts it.
    Proven,
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

/// The sign twin of `key`: the negated point, which the holder of `key`'s secret proves by signing with the
/// negated scalar. `None` for bytes that are not a curve point, which no transport proves.
///
/// Only [`Gate::proven`] asks about it. Every other path admits on a token, and a token either binds the
/// exact key bytes, which the twin does not match, or binds no key, which any fresh key can carry as well.
fn sign_twin(key: VerifyKey) -> Option<VerifyKey> {
    let point = ed25519_dalek::VerifyingKey::from_bytes(key.bytes())
        .ok()?
        .to_edwards();
    Some(VerifyKey::new(
        ed25519_dalek::VerifyingKey::from(-point).to_bytes(),
    ))
}

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
    if revocations.is_revoked_peer(&peer) {
        return Decision::Refuse(Refusal::Revoked);
    }
    let Some(cap) = presented else {
        return Decision::Refuse(Refusal::Missing);
    };
    admit_token(root, revocations, cap, service, peer)
}

/// One presented token on the plain path, rooted at `root`: the rooted gate's ruling once the peer's own key
/// and the presence of a token are settled. An anchored gate rules on a token rooted at its pin through this
/// same function.
fn admit_token(
    root: VerifyKey,
    revocations: &dyn Revocations,
    cap: &Cap,
    service: &Service,
    peer: VerifyKey,
) -> Decision {
    // Revocation FIRST, before any datalog runs. It is a pure offline read of the token's own block
    // signatures plus a set lookup ([`Cap::revocation_ids`]), and it is INDEPENDENT of whether the token
    // grants, so asking it earlier only decides sooner: a revoked token is refused either way, and a token
    // that is not revoked still faces the whole verify. What it buys is that a revoked but persistent
    // holder stops making this node pay for an evaluation it was always going to discard, which is the one
    // lever the design keeps against a former insider. The post-grant check below stays: it is what refuses
    // a token revoked between these two answers.
    if revocations.is_revoked(cap) {
        return Decision::Refuse(Refusal::Revoked);
    }
    membership(cap, root, peer)
        .or_else(|| grant(cap, root, service, peer))
        .decide(revocations, cap)
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
    // Revocation first, for the reason `admit_plain` gives, and on BOTH tokens. The slip is this node's
    // grant; the badge roots at the foreign `X`, and asking about it is what lets a store that disables
    // root keys refuse `X`'s devices here. `Cap::parse` authenticated the badge's root, so it cannot be
    // claimed. See `revoked_or_admit` for which powers this does and does not give the node. The peer's own
    // key is asked before either token, as on the plain path.
    if pair_is_revoked(revocations, peer, slip, badge) {
        return Decision::Refuse(Refusal::Revoked);
    }
    verify_pair(root, revocations, slip, badge, service, peer, None)
}

/// The first revocation read on the two-token path: the peer's own key, then both tokens.
fn pair_is_revoked(
    revocations: &dyn Revocations,
    peer: VerifyKey,
    slip: &Cap,
    badge: &Cap,
) -> bool {
    revocations.is_revoked_peer(&peer)
        || revocations.is_revoked(slip)
        || revocations.is_revoked(badge)
}

/// The two-token AND once the first read has passed: the slip at `root` names `X`, the badge proves the
/// peer a member under `X`, and the second read finds neither token recalled. `refused_authority` is an `X`
/// this gate never accepts from a slip, refused before the badge is read.
fn verify_pair(
    root: VerifyKey,
    revocations: &dyn Revocations,
    slip: &Cap,
    badge: &Cap,
    service: &Service,
    peer: VerifyKey,
    refused_authority: Option<VerifyKey>,
) -> Decision {
    let request = Request::now(Service::clone(service)).bound_to(peer);
    let checked = match slip.verify_authority_bound_at_root_without_revocation(&request, root) {
        Ok(x) if refused_authority == Some(x) => Checked::NotGranted,
        // `X` is the authority the slip named, fed straight into the badge's root check. There is no path
        // that reads a badge-supplied root: `verify_member_at_root_without_revocation` only compares the
        // badge's own root AGAINST this `x`, so a badge under the wrong root fails `ForeignRoot`. The badge
        // is device-bound, so a stolen slip+badge replayed from a different key fails the bound-device check.
        Ok(x) => Checked::from(badge.verify_member_at_root_without_revocation(
            SystemTime::now(),
            peer,
            x,
        )),
        // A slip that did not verify is classified by the same rule every other check uses, so an undecided
        // slip evaluation is never reported as a refusal of an authority nothing ruled on.
        Err(error) => Checked::from(Err(error)),
    };
    // The second read, on both tokens as the first was: a root disabled while the pair was being evaluated
    // is refused now rather than on the next connection.
    match checked.decide(revocations, slip) {
        Decision::Admit if revocations.is_revoked(badge) => Decision::Refuse(Refusal::Revoked),
        decision => decision,
    }
}

/// A granted cap that is revoked is still refused; else admit.
///
/// On the authority-bound path the store is consulted on BOTH tokens, the foreign badge included. Three
/// powers over a foreign member stay distinct:
/// - this node may DISABLE THE FOREIGN ROOT: a store keyed on root keys (see [`Latch`](crate::Latch))
///   refuses every badge `X` signed, so every one of `X`'s devices at once;
/// - this node may REVOKE THE WHOLE SLIP it issued, cutting every device of `X` off from that grant;
/// - a lost DEVICE of `X` stays `X`'s to revoke, in `X`'s own set: its badge carries `X`'s revocation
///   ids, which this node never recorded, and `X` can re-badge the device under new ones.
///
/// Asking about the badge is deny-only: an id this node never recorded never matches, and a store that
/// refuses a foreign badge for its own reasons can only over-deny.
///
/// The SECOND of the two revocation reads, and the one that catches a token recalled while its own
/// evaluation was running; the admit paths ask first, before they pay for the verify. The authority-bound
/// path asks this about its slip and then asks the same of its badge.
fn revoked_or_admit(revocations: &dyn Revocations, cap: &Cap) -> Decision {
    if revocations.is_revoked(cap) {
        return Decision::Refuse(Refusal::Revoked);
    }
    Decision::Admit
}

/// What the MEMBERSHIP question answers for `cap` at `root` and the proven dialer `peer`, evaluated now: it
/// grants when the cap carries the `member(true)` authority fact and its device binding holds for `peer`.
/// Whole-node.
fn membership(cap: &Cap, root: VerifyKey, peer: VerifyKey) -> Checked {
    Checked::from(cap.verify_member_at_root_without_revocation(SystemTime::now(), peer, root))
}

/// Whether `cap` is a membership badge by what its issuer signed, for a path that must never admit one:
/// [`Granted`](Checked::Granted) when its authority block carries `member(true)`, whatever the peer, the
/// time, or any block a holder added.
///
/// Not [`membership`]: that asks whether the badge admits `peer` now, with no `service` fact, so a holder
/// who narrows a badge to one service makes it answer "no" there while it still grants that service. A read
/// that failed cleanly has not shown the cap is no badge, so it reads as one; one that ran out of budget
/// stays [`Undecided`](Checked::Undecided).
fn member_badge(cap: &Cap) -> Checked {
    match cap.is_member_badge() {
        Ok(true) => Checked::Granted,
        Ok(false) => Checked::NotGranted,
        Err(error) => match Checked::from(Err(error)) {
            Checked::Undecided => Checked::Undecided,
            Checked::Granted | Checked::NotGranted => Checked::Granted,
        },
    }
}

/// The kind an admission on the plain path carries, for a token rooted at `root`: `Member` for a membership
/// badge, `Slip` otherwise.
///
/// Fail-closed on anything but a plain grant: an undecided re-read is not proof of membership, so the
/// witness is a per-service `Slip`, never an owner device.
fn admitted_kind(presented: Option<&Cap>, root: VerifyKey, peer: VerifyKey) -> Admission {
    match presented {
        Some(cap) if membership(cap, root, peer).grants() => Admission::Member,
        _ => Admission::Slip,
    }
}

/// What the SERVICE question answers for `cap` at `root` and the proven dialer `peer`, evaluated now: it
/// grants when the cap grants `service`. The `peer` is bound into the request so a device-bound cap admits
/// only its device; an unbound slip ignores it.
fn grant(cap: &Cap, root: VerifyKey, service: &Service, peer: VerifyKey) -> Checked {
    Checked::from(cap.verify_at_root_without_revocation(
        &Request::now(Service::clone(service)).bound_to(peer),
        root,
    ))
}

/// What one capability check answered.
///
/// Three states, not a bool, because "did not grant" and "was never decided" are different facts about the
/// world and only one of them is about the holder: a token that fails its checks says the peer has no such
/// authority, while an evaluation that ran out of its wall-clock budget says only that this host was busy.
/// Collapsing the second into the first is what made a loaded machine report a valid capability as
/// unauthorized, so the distinction is carried in the type from the check all the way to the [`Refusal`].
pub(crate) enum Checked {
    /// The cap verified: this question grants.
    Granted,
    /// The cap verified cleanly and does not grant: a foreign root, the wrong service, expired, or the
    /// wrong device. An answer ABOUT the holder, reproducible on any host.
    NotGranted,
    /// The evaluation never finished (see [`CapError::Undecided`]), so nothing was decided about the
    /// holder. Transient, and about this host rather than about the peer.
    Undecided,
}

impl Checked {
    /// The gate ruling this answer yields, refusing a revoked cap even where the check granted.
    ///
    /// The ONE place an answer becomes a [`Decision`], so a new [`Checked`] state cannot be folded into a
    /// denial by a caller that forgot it existed.
    pub(crate) fn decide(self, revocations: &dyn Revocations, cap: &Cap) -> Decision {
        match self {
            Checked::Granted => revoked_or_admit(revocations, cap),
            Checked::NotGranted => Decision::Refuse(Refusal::NotGranted),
            Checked::Undecided => Decision::Refuse(Refusal::Undecided),
        }
    }

    /// Whether this answer GRANTS. For a caller that needs only the affirmative, where "no" and "not
    /// decided" are equally not a grant: reading the kind off an admission witness, which fails closed.
    pub(crate) fn grants(self) -> bool {
        matches!(self, Checked::Granted)
    }

    /// Read as the answer to "is this a member cap", on a path that must never admit one: a member is
    /// refused as [`NotGranted`](Refusal::NotGranted), an undecided answer is refused as
    /// [`Undecided`](Refusal::Undecided) rather than passed on, and only a clean "not a member" continues.
    pub(crate) fn refuse_member(self) -> Result<(), Refusal> {
        match self {
            Checked::Granted => Err(Refusal::NotGranted),
            Checked::NotGranted => Ok(()),
            Checked::Undecided => Err(Refusal::Undecided),
        }
    }

    /// This answer, or the next question's when this one did not grant. A cap admits on EITHER membership
    /// or the requested service, so the second question is asked only when the first did not grant.
    ///
    /// An UNDECIDED answer survives a later "no": the host was too busy to rule on one of the two, so the
    /// pair cannot honestly report "not authorized". It still yields to a later GRANT, because an
    /// affirmative answer is a real one and needs no help from the question that stalled.
    pub(crate) fn or_else(self, next: impl FnOnce() -> Checked) -> Checked {
        match self {
            Checked::Granted => Checked::Granted,
            Checked::NotGranted => next(),
            Checked::Undecided => match next() {
                Checked::Granted => Checked::Granted,
                Checked::NotGranted | Checked::Undecided => Checked::Undecided,
            },
        }
    }
}

impl From<Result<VerifyKey, CapError>> for Checked {
    /// Classify one capability verification. [`CapError::Undecided`] is the ONLY cause that is not an
    /// answer about the holder; every other error is a genuine "this cap does not grant that".
    fn from(verified: Result<VerifyKey, CapError>) -> Self {
        // EXHAUSTIVE, with no wildcard, and that is the point of the arm list below.
        //
        // `Err(_) => NotGranted` stood here until 2026-09-20 and it is the shape that once let a
        // whole verb dial as a stranger for months: a cause added upstream inherits whatever the
        // fall-through happened to be, silently, and here the fall-through is a DENIAL. `Undecided`
        // exists precisely because "I could not decide" must never read as "you are not authorized",
        // so a new cause landing in that arm by default is the exact lie this type is shaped around.
        //
        // `CapError` is now non-exhaustive, but that only forces a catch-all OUTSIDE this crate. In
        // here the compiler still checks the list, so adding a variant breaks this match and someone
        // has to rule on it. That is the guard. A reviewer who restores the wildcard to make it build
        // has thrown it away.
        match verified {
            Ok(_) => Checked::Granted,
            // Not an answer about the holder: the evaluation never finished, or was refused before
            // it began because its shape could have burned the host.
            Err(CapError::Undecided) => Checked::Undecided,
            // Answers about the token or the holder, every one of which is a genuine "no".
            Err(
                CapError::TooLarge
                | CapError::TooComplex
                | CapError::Encoding
                | CapError::Malformed
                | CapError::MalformedAuthority
                | CapError::Unverified
                | CapError::Key(_)
                | CapError::Mint(_)
                | CapError::Encode(_)
                | CapError::Attenuate(_)
                | CapError::Seal(_)
                | CapError::EmptyAttenuation
                | CapError::ForeignRoot
                | CapError::Authorize(_)
                | CapError::Denied(_)
                | CapError::NotAuthorityBound
                | CapError::UnreadableExpiry,
            ) => Checked::NotGranted,
        }
    }
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
///
/// Three of them ANSWER the question ([`Missing`](Self::Missing), [`NotGranted`](Self::NotGranted),
/// [`Revoked`](Self::Revoked)); [`Undecided`](Self::Undecided) reports that the question was never
/// answered. A caller that renders a refusal, to its own logs or to a peer, must keep that split.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A [`Rooted`](Gate::Rooted) or [`Anchored`](Gate::Anchored) gate required a token and none was
    /// presented.
    Missing,
    /// A token was presented but did not grant the request (foreign root, neither membership nor the
    /// requested service, or expired).
    NotGranted,
    /// The capability presented has been revoked. Asked before the grant, so a revoked token reports this
    /// whether or not it would also have granted: the recall is the answer, and a store lookup is cheaper
    /// than the verify it replaces.
    Revoked,
    /// Authorization was NOT DECIDED: the capability's evaluation ran out of its wall-clock budget (see
    /// [`CapError::Undecided`]), so nothing about the holder's authority was established.
    ///
    /// The odd one out, and deliberately so. The other three are ANSWERS about the peer, stable on any
    /// host; this one is a transient local condition (a loaded machine, a descheduled thread) and says
    /// nothing about the token. The connection is still refused, because nothing may be admitted on an
    /// answer that was never computed, but it is not an authorization outcome:
    /// - a HOST that logs or reports a refusal renders this as a retryable local failure, and does not
    ///   count it as a failed authorization attempt;
    /// - a consumer that puts a refusal ON THE WIRE must NOT send the peer the uniform not-admitted
    ///   refusal it sends for the other three. Telling a dialer they lack authority when this host merely
    ///   ran out of time is a lie, and it is one the dialer acts on (it will stop retrying and go looking
    ///   for a token it already has). It belongs on whatever transient/unavailable refusal that wire
    ///   already carries.
    Undecided,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            Refusal::Missing => "no capability presented",
            Refusal::NotGranted => "capability does not grant this request",
            Refusal::Revoked => "capability has been revoked",
            Refusal::Undecided => "authorization did not finish in time, try again",
        };
        f.write_str(reason)
    }
}

impl core::error::Error for Refusal {}
