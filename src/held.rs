//! Held slips: grants this machine's own key signed and keeps itself, so their holder reaches a service by
//! its proven key alone and presents nothing.
//!
//! A slip handed to its holder is a link the holder must keep and present. A held slip is the same signed
//! grant kept by its issuer instead: an anchored gate (see [`Gate::anchored`](crate::Gate::anchored))
//! admits a proven key for a service when this machine holds a slip it signed for that key, or for a
//! foreign authority that key proves membership under. The gate rules on the signed slip, never on a
//! list entry: a line a local writer adds without the key grants nothing, a revoked slip stays revoked
//! however its record is restored, and its end is the end its issuer signed.
//!
//! The work splits by what can change. What a slip's bytes fix (its signer, its holder, its service, that
//! it is no membership badge) is settled ONCE, by [`HeldSlip::verify`], and an index of verified facts
//! ([`HeldSlips`]) is all that is kept, never the parsed slip. What time and the revocation store can
//! change (the end, the slip's ids, the foreign badge a root row needs) the gate asks on every admission.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use crate::cap::{Cap, CapError, Request};
use crate::gate::Checked;
use crate::revocations::RevocationId;
use crate::{Service, VerifyKey};

/// Who a held slip admits: the one device it is bound to, or every device a foreign authority vouches
/// for. Read from the facts the slip's issuer signed ([`Identity::mint_bound`](crate::Identity::mint_bound)
/// and [`Identity::mint_authority_slip`](crate::Identity::mint_authority_slip)), never from a record kept
/// beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Holder {
    /// The proven device whose key this is.
    Device(VerifyKey),
    /// Any proven device presenting a live membership badge under this foreign authority key.
    Root(VerifyKey),
}

/// The facts of a slip this machine's own key signed and holds, verified once by [`HeldSlip::verify`].
///
/// Its fields are private and `verify` is its only constructor, so a value of this type is a slip that
/// passed every check that its signed bytes can settle: it was signed by `anchor`, it is no membership
/// badge, it is exactly as its issuer signed it (one block), it names one holder, and it granted
/// `service` at the moment it was verified. The slip itself is not kept, so a value costs a few hundred
/// bytes rather than a parsed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldSlip {
    holder: Holder,
    service: Service,
    until: SystemTime,
    id: RevocationId,
    anchor: VerifyKey,
}

impl HeldSlip {
    /// Verify `slip` as a grant this machine, `own`, holds for `service`, evaluated at `now`.
    ///
    /// Refuses, in order:
    /// - a membership badge, by what its issuer signed and however a holder narrowed it: the own key never
    ///   makes a member, here as on the gate's own-key path;
    /// - a slip signed by any key but `own`;
    /// - a slip whose holder facts cannot be read, or that names two holders;
    /// - a slip a holder narrowed (more than one block), and a bearer slip that names no holder: neither
    ///   is a grant this machine signed for one holder to keep;
    /// - a slip whose holder is not a well-formed key, and a root slip naming `own` itself as its
    ///   authority, since anyone holding a copy of that key could badge any device under it;
    /// - a slip that does not grant `service` to its own holder at `now` (the wrong service, ended, or a
    ///   device binding that disagrees with the device it names);
    /// - a slip whose end cannot be read, and one that never ends.
    ///
    /// The checks that settle what a valid own-key slip is are the ones the gate's own-key path runs on a
    /// presented slip, through the same code, so the two cannot drift. The holder is the slip's own
    /// `device_bound` or `authority_bound` fact, and the end is [`Cap::valid_until`], the earliest bound
    /// any check sets, never the advisory [`Cap::expiry`].
    pub fn verify(
        slip: &Cap,
        service: &Service,
        now: SystemTime,
        own: VerifyKey,
    ) -> Result<Self, HeldSlipError> {
        let read = OwnSlip::read(slip, own)?;
        // An integer read, so it runs before anything evaluates the slip as a grant.
        if slip.block_count() != 1 {
            return Err(HeldSlipError::Narrowed);
        }
        let (holder, until) = read.held(service, now)?;
        let id = slip.root_revocation_id().ok_or(HeldSlipError::NoId)?;
        Ok(Self {
            holder,
            service: Service::clone(service),
            until,
            id,
            anchor: own,
        })
    }

    /// Who this slip admits.
    pub fn holder(&self) -> Holder {
        self.holder
    }

    /// The service this slip was verified for.
    pub fn service(&self) -> &Service {
        &self.service
    }

    /// The last instant this slip grants anything, as its issuer signed it.
    pub fn until(&self) -> SystemTime {
        self.until
    }

    /// This slip's revocation id. Recording it in the gate's store refuses the slip on the next admission.
    pub fn id(&self) -> &RevocationId {
        &self.id
    }

    /// The key that signed this slip: the machine that holds it.
    pub fn anchor(&self) -> VerifyKey {
        self.anchor
    }
}

/// An index of [`HeldSlip`]s for one machine's own key: what an anchored gate asks when a proven key
/// presents no token rooted at it.
///
/// It records the key its slips were verified under, accepts no slip verified under another, and the gate
/// admits nothing from an index whose key is not its own. A consumer builds one off the admission path,
/// feeds it the slips it keeps, and hands it to the gate whole through a [`HeldSource`], so a rebuild
/// never stalls an admission and a gate never reads a half-built index.
///
/// It holds one slip per holder and service, and does not choose between two: inserting a second one
/// displaces the first and hands it back. A displaced slip still verifies, and it governs any index built
/// without the later one, so leaving a slip out of an index does not end it. Revoking its
/// [`id`](HeldSlip::id) does.
#[derive(Debug, Clone)]
pub struct HeldSlips {
    own: VerifyKey,
    services: HashMap<Service, Rows>,
}

/// The held slips for one service, by the key each is looked up under.
#[derive(Debug, Clone, Default)]
struct Rows {
    /// Device slips, by the device key a proven peer must be.
    devices: HashMap<VerifyKey, HeldSlip>,
    /// Root slips, by the foreign authority a presented badge must chain to.
    roots: HashMap<VerifyKey, HeldSlip>,
}

impl HeldSlips {
    /// An empty index for slips signed by `own`, this machine's key.
    pub fn new(own: VerifyKey) -> Self {
        Self {
            own,
            services: HashMap::new(),
        }
    }

    /// The key every slip here was verified under.
    pub fn own(&self) -> VerifyKey {
        self.own
    }

    /// Hold `slip`, returning the slip it displaced for the same holder and service, if any, as
    /// [`HashMap::insert`] does, so a caller never loses one without seeing it. Refuses a slip verified
    /// under a key other than this index's as [`OtherKey`](HeldSlipError::OtherKey).
    pub fn insert(&mut self, slip: HeldSlip) -> Result<Option<HeldSlip>, HeldSlipError> {
        if slip.anchor != self.own {
            return Err(HeldSlipError::OtherKey);
        }
        let rows = self.services.entry(slip.service.clone()).or_default();
        let (by_key, key) = match slip.holder {
            Holder::Device(device) => (&mut rows.devices, device),
            Holder::Root(root) => (&mut rows.roots, root),
        };
        Ok(by_key.insert(key, slip))
    }

    /// Every slip held, in no order: how a consumer asks which of its slips the index already holds, by
    /// [`id`](HeldSlip::id), before it verifies the rest. Read-only, so [`HeldSlip::verify`] stays the
    /// only way a slip enters.
    pub fn iter(&self) -> impl Iterator<Item = &HeldSlip> {
        self.services
            .values()
            .flat_map(|rows| rows.devices.values().chain(rows.roots.values()))
    }

    /// Keep only the slips `keep` answers `true` for: how a consumer carries verified slips into a rebuilt
    /// index without verifying them again, matching each by its [`id`](HeldSlip::id).
    pub fn retain(&mut self, mut keep: impl FnMut(&HeldSlip) -> bool) {
        for rows in self.services.values_mut() {
            rows.devices.retain(|_, slip| keep(slip));
            rows.roots.retain(|_, slip| keep(slip));
        }
        self.services
            .retain(|_, rows| !(rows.devices.is_empty() && rows.roots.is_empty()));
    }

    /// How many slips are held.
    pub fn len(&self) -> usize {
        self.services
            .values()
            .map(|rows| rows.devices.len() + rows.roots.len())
            .sum()
    }

    /// Whether no slip is held.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// The device slip held for `device` on `service`.
    pub(crate) fn device_row(&self, service: &Service, device: &VerifyKey) -> Option<&HeldSlip> {
        self.services.get(service)?.devices.get(device)
    }

    /// The root slip held for the foreign authority `root` on `service`. The one place a root row is
    /// selected, by the authority a verified badge chains to and nothing else.
    pub(crate) fn root_row(&self, service: &Service, root: &VerifyKey) -> Option<&HeldSlip> {
        self.services.get(service)?.roots.get(root)
    }
}

/// Where an anchored gate reads its held slips.
///
/// Asked on EVERY admission that reaches the held slips, so an index swapped in while the gate is serving
/// is read at the next connection with no restart. `None` holds nothing, and admits no one on a held
/// slip: a source answers `None` until its first index is built and whenever the slips it keeps cannot be
/// read, never an index kept from an earlier read whose slips may since have been revoked or removed.
pub trait HeldSource: Send + Sync {
    /// The held slips as they stand now, or `None` when there are none to read.
    fn current(&self) -> Option<Arc<HeldSlips>>;
}

/// A shared source answers as the source it shares, so one instance can back the gate and the consumer
/// that rebuilds it.
impl<H: HeldSource + ?Sized> HeldSource for Arc<H> {
    fn current(&self) -> Option<Arc<HeldSlips>> {
        H::current(self)
    }
}

/// The held grant an anchored gate admitted on, carried by the [`Admitted`](crate::Admitted) witness so
/// whatever records the admission records what the gate ruled on rather than what the peer presented.
#[derive(Debug)]
pub struct HeldGrant {
    slips: Vec<HeldSlip>,
    badge: Option<HeldBadge>,
}

impl HeldGrant {
    /// A grant on a device slip.
    pub(crate) fn device(slip: HeldSlip) -> Self {
        Self {
            slips: vec![slip],
            badge: None,
        }
    }

    /// A grant on a root slip and the badge that proved the peer a member under its authority.
    pub(crate) fn root(slip: HeldSlip, badge: HeldBadge) -> Self {
        Self {
            slips: vec![slip],
            badge: Some(badge),
        }
    }

    /// The held slips that admitted the peer, each with its id, end, and the key that signed it.
    pub fn slips(&self) -> &[HeldSlip] {
        &self.slips
    }

    /// For a root slip, the badge that proved the peer a member under its authority; `None` for a device
    /// slip.
    pub fn badge(&self) -> Option<&HeldBadge> {
        self.badge.as_ref()
    }
}

/// The facts of a presented membership badge a root slip was admitted beside.
#[derive(Debug)]
pub struct HeldBadge {
    root: VerifyKey,
    ids: Vec<RevocationId>,
    until: Option<SystemTime>,
}

impl HeldBadge {
    /// The facts of `badge`, verified for `peer` at `now` under its own root, or the error that refused
    /// it. Verified at the root it chains to before any held slip is looked up, so a badge under an
    /// authority this machine holds a slip for and one under any other cost the same to refuse.
    pub(crate) fn verify(badge: &Cap, peer: VerifyKey, now: SystemTime) -> Result<Self, CapError> {
        let root = badge.root();
        badge.verify_member_at_root_without_revocation(now, peer, root)?;
        // A badge whose end cannot be read is ended: whatever records the admission could not say when.
        let until = badge.valid_until()?;
        Ok(Self {
            root,
            ids: badge.revocation_ids(),
            until,
        })
    }

    /// The foreign authority the badge chains to.
    pub fn root(&self) -> VerifyKey {
        self.root
    }

    /// The badge's revocation ids, one per block.
    pub fn ids(&self) -> &[RevocationId] {
        &self.ids
    }

    /// The last instant the badge grants anything, or `None` when no check in it reads the clock.
    pub fn until(&self) -> Option<SystemTime> {
        self.until
    }
}

/// A slip rooted at this machine's own key, read once: whom its authority block names, before anything
/// verifies it as a grant.
///
/// The one ruling on what a valid own-key slip is. [`HeldSlip::verify`], the gate's plain own-key path
/// and its two-token own-key path each start from [`read`](Self::read) and finish through the same
/// verify, so no two of them can disagree about a slip both would rule on. They differ only in whom the
/// slip must admit: the holder it names, the peer presenting it, or the members of the authority it names.
pub(crate) struct OwnSlip<'a> {
    slip: &'a Cap,
    own: VerifyKey,
    holder: Named,
    until: Result<Option<SystemTime>, CapError>,
}

/// The holder a slip's authority block names, as the text its issuer signed. Parsed only by a path that
/// uses the key.
enum Named {
    Device(String),
    Root(String),
    Nobody,
}

impl<'a> OwnSlip<'a> {
    /// Read `slip` as a grant `own` signed: refused as a membership badge, as another key's, or as naming
    /// two holders. One pass over the slip's authority block (see [`Cap::authority_facts`]).
    pub(crate) fn read(slip: &'a Cap, own: VerifyKey) -> Result<Self, HeldSlipError> {
        // First, before anything reads the slip as a grant: the own key never makes a member, and a badge
        // its holder narrowed to one service is still a badge. A read that failed cleanly has not shown the
        // slip is no badge, so it reads as one; one that ran out of budget is not decided.
        let facts = match slip.authority_facts() {
            Ok(facts) if facts.member => return Err(HeldSlipError::MemberBadge),
            Ok(facts) => facts,
            Err(error) => {
                return Err(match Checked::from(Err(error)) {
                    Checked::Undecided => HeldSlipError::Denied(CapError::Undecided),
                    Checked::Granted | Checked::NotGranted => HeldSlipError::MemberBadge,
                });
            }
        };
        if slip.root() != own {
            return Err(HeldSlipError::OtherKey);
        }
        // Two holders are refused: no mint writes both, and either reading would be a guess.
        let holder = match (facts.device, facts.authority) {
            (Some(device), None) => Named::Device(device),
            (None, Some(root)) => Named::Root(root),
            (None, None) => Named::Nobody,
            (Some(_), Some(_)) => return Err(HeldSlipError::TwoHolders),
        };
        Ok(Self {
            slip,
            own,
            holder,
            until: facts.until,
        })
    }

    /// Rule on the slip as one this machine holds for `service` at `now`: bound to the device it names, or
    /// admitting the members of the foreign authority it names. Returns its holder and its signed end.
    pub(crate) fn held(
        self,
        service: &Service,
        now: SystemTime,
    ) -> Result<(Holder, SystemTime), HeldSlipError> {
        let (holder, bound_device, authority) = match &self.holder {
            Named::Device(device) => {
                let device = parse_holder(device)?;
                (Holder::Device(device), Some(device), None)
            }
            Named::Root(root) => {
                let root = self.authority(root)?;
                (Holder::Root(root), None, Some(root))
            }
            Named::Nobody => return Err(HeldSlipError::Bearer),
        };
        let request = Request {
            service: Service::clone(service),
            now,
            bound_device,
        };
        let until = self.verify(&request, authority)?;
        Ok((holder, until.ok_or(HeldSlipError::Endless)?))
    }

    /// Rule on the slip as `peer` presents it alone, on the plain path, for `service` at `now`.
    ///
    /// A root slip is refused before anything verifies it: it is inert alone, and admits only beside a
    /// badge, on the two-token path. Any other slip is bound to the peer presenting it, never to the
    /// device it names, so its own binding check refuses anyone but that device. The named device is not
    /// even parsed: nothing here reads it.
    pub(crate) fn presented(self, service: &Service, now: SystemTime, peer: VerifyKey) -> Checked {
        match self.holder {
            Named::Root(_) => return Checked::NotGranted,
            Named::Device(_) | Named::Nobody => {}
        }
        let request = Request {
            service: Service::clone(service),
            now,
            bound_device: Some(peer),
        };
        match self.verify(&request, None) {
            Ok(_) => Checked::Granted,
            Err(refused) => refused.checked(),
        }
    }

    /// Rule on the slip as `peer` presents it beside a badge, on the two-token path, for `service` at
    /// `now`: it must name a foreign authority, which is returned for the badge to be verified under. Any
    /// other slip is not granted here.
    pub(crate) fn foreign(
        self,
        service: &Service,
        now: SystemTime,
        peer: VerifyKey,
    ) -> Result<VerifyKey, Checked> {
        let Named::Root(root) = &self.holder else {
            return Err(Checked::NotGranted);
        };
        let authority = self.authority(root).map_err(HeldSlipError::checked)?;
        let request = Request {
            service: Service::clone(service),
            now,
            bound_device: Some(peer),
        };
        self.verify(&request, Some(authority))
            .map_err(HeldSlipError::checked)?;
        Ok(authority)
    }

    /// The foreign authority `text` names, refused when it is the own key: anyone holding a copy of that
    /// key could badge any device they like under it.
    fn authority(&self, text: &str) -> Result<VerifyKey, HeldSlipError> {
        let authority = parse_holder(text)?;
        if authority == self.own {
            return Err(HeldSlipError::OwnRoot);
        }
        Ok(authority)
    }

    /// The verify every path ends in: the slip grants `request` at the own key, under the foreign
    /// `authority` when it names one, and its end can be read. Returns that end.
    fn verify(
        self,
        request: &Request,
        authority: Option<VerifyKey>,
    ) -> Result<Option<SystemTime>, HeldSlipError> {
        match authority {
            Some(authority) => self
                .slip
                .verify_bound_to_authority(request, self.own, authority),
            None => self
                .slip
                .verify_at_root_without_revocation(request, self.own),
        }
        .map_err(HeldSlipError::Denied)?;
        // A slip whose end cannot be read is refused on every path, presented or held: whatever cuts an
        // admission when its grant ends could not say when.
        self.until.map_err(HeldSlipError::Denied)
    }
}

/// A holder key as its issuer signed it, refused when it is not a well-formed key.
fn parse_holder(text: &str) -> Result<VerifyKey, HeldSlipError> {
    text.parse::<VerifyKey>()
        .map_err(|_| HeldSlipError::Denied(CapError::MalformedAuthority))
}

/// Why a slip is not one this machine can hold, or not one it may hold in this index.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HeldSlipError {
    /// The slip is a membership badge by what its issuer signed. The own key never makes a member.
    #[error("slip is a membership badge")]
    MemberBadge,
    /// The slip was signed by, or verified under, a key other than the one holding it.
    #[error("slip is not signed by this key")]
    OtherKey,
    /// The slip names both a device and a foreign authority as its holder.
    #[error("slip names two holders")]
    TwoHolders,
    /// The slip is a root slip naming the key that signed it as its foreign authority.
    #[error("slip names its own signer as its authority")]
    OwnRoot,
    /// The slip did not verify for the service at the moment asked, or its end cannot be read. The cause
    /// is the capability error; an [`Undecided`](CapError::Undecided) one means the host ran out of time
    /// and the slip may verify when asked again.
    #[error("slip does not verify")]
    Denied(#[source] CapError),
    /// A holder added a block to the slip. A held slip is kept exactly as its issuer signed it.
    #[error("slip was narrowed by a holder")]
    Narrowed,
    /// The slip names no holder: a bearer slip, which admits whoever presents it and is never held.
    #[error("slip names no holder")]
    Bearer,
    /// No check in the slip reads the clock, so it never ends.
    #[error("slip never ends")]
    Endless,
    /// The slip carries no revocation id, so nothing could ever revoke it.
    #[error("slip has no revocation id")]
    NoId,
}

impl HeldSlipError {
    /// The gate's answer for a slip refused here: not decided when the host ran out of time, otherwise not
    /// granted.
    pub(crate) fn checked(self) -> Checked {
        match self {
            HeldSlipError::Denied(error) => Checked::from(Err(error)),
            HeldSlipError::MemberBadge
            | HeldSlipError::OtherKey
            | HeldSlipError::TwoHolders
            | HeldSlipError::OwnRoot
            | HeldSlipError::Narrowed
            | HeldSlipError::Bearer
            | HeldSlipError::Endless
            | HeldSlipError::NoId => Checked::NotGranted,
        }
    }
}
