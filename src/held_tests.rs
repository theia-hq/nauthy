//! Held slips: the verify that admits a slip into an index, and the anchored gate's branch that admits a
//! proven key on one.

use core::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use crate::cap::{Cap, CapError, Identity, Request};
use crate::gate::{Admission, Decision, Gate, IssuedIds, Origin, PinSource, ProvenPeer, Refusal};
use crate::held::{HeldSlip, HeldSlipError, HeldSlips, HeldSource, Holder};
use crate::revocations::{RevocationId, Revocations};
use crate::{Service, VerifyKey};

// This machine is `OWN` and trusts the pin `PIN`. A friend's authority is `FRIEND`, whose device is
// `DEVICE`; `STRANGER` holds nothing here; `ELSEWHERE` is another machine with slips of its own.
const PIN: u8 = 1;
const FRIEND: u8 = 2;
const OWN: u8 = 3;
const DEVICE: u8 = 4;
const STRANGER: u8 = 5;
const ELSEWHERE: u8 = 7;

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
}

fn key(seed: u8) -> VerifyKey {
    identity(seed).verifying_key()
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

fn proven(seed: u8) -> ProvenPeer {
    ProvenPeer::from_handshake(key(seed))
}

fn hour() -> SystemTime {
    Request::expires_in(Duration::from_secs(3600))
}

fn ago(secs: u64) -> SystemTime {
    SystemTime::now() - Duration::from_secs(secs)
}

/// The own key's slip for `svc`, bound to `device`.
fn device_slip(device: u8, svc: &str) -> Cap {
    identity(OWN)
        .mint_bound(&service(svc), key(device), hour())
        .expect("mint a device slip")
}

/// The own key's slip for `svc`, for every device `authority` badges.
fn root_slip(authority: u8, svc: &str) -> Cap {
    identity(OWN)
        .mint_authority_slip(&service(svc), key(authority), hour())
        .expect("mint a root slip")
}

/// `authority`'s membership badge for `device`, ending at `expiry`.
fn badge_until(authority: u8, device: u8, expiry: SystemTime) -> Cap {
    identity(authority)
        .mint_member(key(device), expiry)
        .expect("mint a badge")
}

fn badge(authority: u8, device: u8) -> Cap {
    badge_until(authority, device, hour())
}

/// Verify `slip` as `OWN` holds it, for `svc`, now.
fn held(slip: &Cap, svc: &str) -> Result<HeldSlip, HeldSlipError> {
    HeldSlip::verify(slip, &service(svc), SystemTime::now(), key(OWN))
}

/// An index for `OWN` holding `slips`, each verified for `svc` now.
fn index(slips: &[&Cap], svc: &str) -> HeldSlips {
    let mut index = HeldSlips::new(key(OWN));
    for slip in slips {
        index
            .insert(held(slip, svc).expect("a slip this machine holds"))
            .expect("verified under the index's key");
    }
    index
}

/// A pin that never moves.
struct Pin;

impl PinSource for Pin {
    fn current(&self) -> Option<VerifyKey> {
        Some(key(PIN))
    }
}

/// The record of slips the own key issued, by root revocation id.
struct Issued(Vec<RevocationId>);

impl IssuedIds for Issued {
    fn is_issued(&self, id: &RevocationId) -> bool {
        self.0.contains(id)
    }
}

/// A revocation store a test writes into while a gate holds it, keyed on ids and keys alike, answering a
/// cap and a held slip's facts by one rule.
#[derive(Clone, Default)]
struct Store(Arc<Mutex<Recalled>>);

#[derive(Default)]
struct Recalled {
    ids: HashSet<RevocationId>,
    keys: HashSet<VerifyKey>,
}

impl Store {
    fn revoke_id(&self, id: RevocationId) {
        self.0.lock().expect("store lock").ids.insert(id);
    }

    fn revoke_key(&self, key: VerifyKey) {
        self.0.lock().expect("store lock").keys.insert(key);
    }
}

impl Revocations for Store {
    fn is_revoked_ids(&self, root: &VerifyKey, ids: &[RevocationId]) -> bool {
        let recalled = self.0.lock().expect("store lock");
        recalled.keys.contains(root) || ids.iter().any(|id| recalled.ids.contains(id))
    }

    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.0.lock().expect("store lock").keys.contains(peer)
    }
}

/// Held slips a test swaps while a gate holds the source, as a consumer swaps in a rebuilt index.
#[derive(Clone, Default)]
struct Swap(Arc<RwLock<Option<Arc<HeldSlips>>>>);

impl Swap {
    fn holding(index: HeldSlips) -> Self {
        Self(Arc::new(RwLock::new(Some(Arc::new(index)))))
    }
}

impl HeldSource for Swap {
    fn current(&self) -> Option<Arc<HeldSlips>> {
        self.0.read().expect("swap lock").clone()
    }
}

/// An anchored gate at `OWN` over `store`, recording `issued`, holding what `held` holds.
fn gate_issuing(
    store: impl Revocations + Send + Sync + 'static,
    issued: &[&Cap],
    held: Swap,
) -> Gate {
    Gate::anchored(
        Pin,
        key(OWN),
        store,
        Issued(
            issued
                .iter()
                .filter_map(|cap| cap.root_revocation_id())
                .collect(),
        ),
        held,
    )
}

fn gate(store: impl Revocations + Send + Sync + 'static, held: Swap) -> Gate {
    gate_issuing(store, &[], held)
}

fn ssh() -> Service {
    service("ssh")
}

#[test]
fn a_held_slip_admits_its_key_with_nothing_presented() {
    let gate = gate(
        Store::default(),
        Swap::holding(index(&[&device_slip(DEVICE, "ssh")], "ssh")),
    );

    let admitted = gate
        .admit_witnessed(proven(DEVICE), None, &ssh())
        .expect("the held slip admits its device");
    assert_eq!(admitted.kind(), Admission::Slip);
    assert_eq!(admitted.peer(), key(DEVICE));
    assert_eq!(gate.admit(proven(DEVICE), None, &ssh()), Decision::Admit);
}

#[test]
fn a_revoked_peer_is_refused_before_any_held_row() {
    let store = Store::default();
    store.revoke_key(key(DEVICE));
    let gate = gate(
        store,
        Swap::holding(index(&[&device_slip(DEVICE, "ssh")], "ssh")),
    );

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Revoked)
    ));
}

#[test]
fn a_held_slip_whose_id_is_revoked_admits_nothing() {
    let slip = device_slip(DEVICE, "ssh");
    let store = Store::default();
    store.revoke_id(slip.root_revocation_id().expect("a slip has an id"));
    let gate = gate(store, Swap::holding(index(&[&slip], "ssh")));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
}

#[test]
fn a_held_admission_is_never_a_member_or_proven() {
    let gate = gate(
        Store::default(),
        Swap::holding(index(
            &[&device_slip(DEVICE, "ssh"), &root_slip(FRIEND, "ssh")],
            "ssh",
        )),
    );

    let on_device = gate
        .admit_witnessed(proven(DEVICE), None, &ssh())
        .expect("a device slip admits");
    let on_root = gate
        .admit_witnessed(proven(STRANGER), Some(&badge(FRIEND, STRANGER)), &ssh())
        .expect("a root slip admits a device its authority badges");
    for admitted in [on_device, on_root] {
        assert_eq!(admitted.kind(), Admission::Slip);
        assert!(!admitted.is_member());
        assert_eq!(admitted.origin(), Origin::Rooted);
        assert!(admitted.peer_verified().is_some());
    }
}

#[test]
fn a_member_badge_never_becomes_a_held_slip() {
    // Everything a held device slip carries, a device fact and one service, on a token that is also a
    // membership badge. Only the membership question tells it from a device slip.
    let badge = identity(OWN)
        .mint_member_naming_device(&ssh(), key(DEVICE), hour())
        .expect("sign the token");

    assert!(matches!(
        held(&badge, "ssh"),
        Err(HeldSlipError::MemberBadge)
    ));
}

#[test]
fn a_held_slip_bound_to_another_key_admits_no_one() {
    let gate = gate(
        Store::default(),
        Swap::holding(index(&[&device_slip(DEVICE, "ssh")], "ssh")),
    );

    assert!(matches!(
        gate.admit_witnessed(proven(STRANGER), None, &ssh()),
        Err(Refusal::Missing)
    ));
}

#[test]
fn a_held_slip_for_another_service_admits_nothing() {
    let slip = device_slip(DEVICE, "ssh");
    let gate = gate(Store::default(), Swap::holding(index(&[&slip], "ssh")));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &service("web")),
        Err(Refusal::Missing)
    ));
    assert!(matches!(held(&slip, "web"), Err(HeldSlipError::Denied(_))));
}

#[test]
fn a_root_row_needs_a_live_badge_bound_to_the_peer() {
    let gate = gate(
        Store::default(),
        Swap::holding(index(&[&root_slip(FRIEND, "ssh")], "ssh")),
    );

    assert!(
        gate.admit_witnessed(proven(DEVICE), Some(&badge(FRIEND, DEVICE)), &ssh())
            .is_ok(),
        "the fixture admits: a live badge under the slip's authority, bound to the peer"
    );
    let lapsed = badge_until(FRIEND, DEVICE, ago(60));
    let bound_elsewhere = badge(FRIEND, STRANGER);
    let other_authority = badge(ELSEWHERE, DEVICE);
    for presented in [&lapsed, &bound_elsewhere, &other_authority] {
        assert!(matches!(
            gate.admit_witnessed(proven(DEVICE), Some(presented), &ssh()),
            Err(Refusal::NotGranted)
        ));
    }
    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
}

#[test]
fn a_revoked_root_refuses_its_root_rows_at_once() {
    let store = Store::default();
    let gate = gate(
        store.clone(),
        Swap::holding(index(&[&root_slip(FRIEND, "ssh")], "ssh")),
    );
    let badge = badge(FRIEND, DEVICE);
    assert!(
        gate.admit_witnessed(proven(DEVICE), Some(&badge), &ssh())
            .is_ok()
    );

    store.revoke_key(key(FRIEND));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), Some(&badge), &ssh()),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn a_held_miss_is_the_refusal_of_no_token() {
    // A slip absent, revoked, or ended: the gate answers each exactly as it answers a peer that holds
    // nothing here, so no refusal tells a peer what this machine holds.
    let live = device_slip(DEVICE, "ssh");
    let revoked = device_slip(STRANGER, "ssh");
    let ended = identity(OWN)
        .mint_bound(&ssh(), key(ELSEWHERE), ago(60))
        .expect("mint a slip that has ended");
    let mut held_slips = index(&[&live, &revoked], "ssh");
    held_slips
        .insert(
            HeldSlip::verify(&ended, &ssh(), ago(120), key(OWN))
                .expect("the slip granted when it was verified"),
        )
        .expect("verified under the index's key");
    let store = Store::default();
    store.revoke_id(revoked.root_revocation_id().expect("a slip has an id"));
    let holding = gate(store, Swap::holding(held_slips));
    let empty = gate(Store::default(), Swap::default());
    let unrelated = identity(ELSEWHERE)
        .mint(&ssh(), hour())
        .expect("mint a token rooted elsewhere");

    for peer in [STRANGER, ELSEWHERE, PIN] {
        for presented in [None, Some(&unrelated)] {
            let miss = empty
                .admit_witnessed(proven(peer), presented, &ssh())
                .expect_err("nothing is held");
            assert_eq!(
                holding
                    .admit_witnessed(proven(peer), presented, &ssh())
                    .expect_err("a revoked, ended, or absent slip admits no one"),
                miss
            );
        }
    }
}

#[test]
fn the_witness_carries_the_held_grant() {
    let device = device_slip(DEVICE, "ssh");
    let root = root_slip(FRIEND, "ssh");
    let gate = gate(
        Store::default(),
        Swap::holding(index(&[&device, &root], "ssh")),
    );

    let admitted = gate
        .admit_witnessed(proven(DEVICE), None, &ssh())
        .expect("a device slip admits");
    let grant = admitted.held().expect("a held admission carries its grant");
    let [slip] = grant.slips() else {
        panic!("one slip admitted the peer");
    };
    assert_eq!(Some(slip.id()), device.root_revocation_id().as_ref());
    assert_eq!(Some(slip.until()), device.valid_until().expect("readable"));
    assert_eq!(slip.anchor(), key(OWN));
    assert_eq!(slip.holder(), Holder::Device(key(DEVICE)));
    assert!(grant.badge().is_none());

    let presented = badge(FRIEND, STRANGER);
    let admitted = gate
        .admit_witnessed(proven(STRANGER), Some(&presented), &ssh())
        .expect("a root slip admits");
    let grant = admitted.held().expect("a held admission carries its grant");
    let [slip] = grant.slips() else {
        panic!("one slip admitted the peer");
    };
    assert_eq!(Some(slip.id()), root.root_revocation_id().as_ref());
    assert_eq!(slip.anchor(), key(OWN));
    assert_eq!(slip.holder(), Holder::Root(key(FRIEND)));
    let badge = grant.badge().expect("a root slip carries its badge");
    assert_eq!(badge.root(), key(FRIEND));
    assert_eq!(badge.ids(), presented.revocation_ids().as_slice());
    assert_eq!(badge.until(), presented.valid_until().expect("readable"));

    let presented_here = gate_issuing(Store::default(), &[&device], Swap::default())
        .admit_witnessed(proven(DEVICE), Some(&device), &ssh())
        .expect("the same slip, presented and recorded, admits");
    assert!(presented_here.held().is_none());
}

#[test]
fn a_revoked_held_slip_is_refused_with_no_reload() {
    let slip = device_slip(DEVICE, "ssh");
    let store = Store::default();
    let gate = gate(store.clone(), Swap::holding(index(&[&slip], "ssh")));
    assert!(gate.admit_witnessed(proven(DEVICE), None, &ssh()).is_ok());

    // Written beside the slips, never into them: the index the gate holds is the one it held before.
    store.revoke_id(slip.root_revocation_id().expect("a slip has an id"));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
}

#[test]
fn the_verify_refuses_an_own_key_member_badge() {
    let badge = identity(OWN)
        .mint_member(key(DEVICE), hour())
        .expect("mint a badge");
    let narrowed = badge
        .attenuate(Some(&ssh()), None)
        .expect("a holder narrows an unsealed badge");

    for badge in [&badge, &narrowed] {
        assert!(matches!(
            held(badge, "ssh"),
            Err(HeldSlipError::MemberBadge)
        ));
    }
}

#[test]
fn an_index_built_under_another_key_admits_nothing() {
    let theirs = identity(ELSEWHERE)
        .mint_bound(&ssh(), key(DEVICE), hour())
        .expect("mint a slip elsewhere");
    let mut elsewhere = HeldSlips::new(key(ELSEWHERE));
    elsewhere
        .insert(
            HeldSlip::verify(&theirs, &ssh(), SystemTime::now(), key(ELSEWHERE))
                .expect("that machine holds its own slip"),
        )
        .expect("verified under that index's key");
    let gate = gate(Store::default(), Swap::holding(elsewhere.clone()));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
    assert!(matches!(
        elsewhere.insert(held(&device_slip(DEVICE, "ssh"), "ssh").expect("ours")),
        Err(HeldSlipError::OtherKey)
    ));
    assert!(matches!(held(&theirs, "ssh"), Err(HeldSlipError::OtherKey)));
}

#[test]
fn the_held_end_is_the_signed_end() {
    // The advisory fact claims ten hours; the check the issuer signed ends at one.
    let slip = identity(OWN)
        .mint_bound_advertising(
            &ssh(),
            key(DEVICE),
            hour(),
            ago(0) + Duration::from_secs(36_000),
        )
        .expect("sign the slip");
    let held = held(&slip, "ssh").expect("the slip grants now");
    assert_eq!(Some(held.until()), slip.valid_until().expect("readable"));

    let ended = identity(OWN)
        .mint_bound_advertising(
            &ssh(),
            key(DEVICE),
            ago(60),
            ago(0) + Duration::from_secs(36_000),
        )
        .expect("sign the slip");
    let mut index = HeldSlips::new(key(OWN));
    index
        .insert(HeldSlip::verify(&ended, &ssh(), ago(120), key(OWN)).expect("it granted then"))
        .expect("verified under the index's key");
    let gate = gate(Store::default(), Swap::holding(index));
    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
}

#[test]
fn the_gates_own_key_slip_path_calls_the_held_verify() {
    // A slip naming two holders carries no binding check, so its datalog grants whoever presents it, and
    // a path that asked only the datalog would admit it. The held verify refuses two holders, and the
    // gate's own-key path, ruling through the same code, refuses it presented and recorded.
    let slip = identity(OWN)
        .mint_naming_two_holders(&ssh(), key(DEVICE), key(FRIEND), hour())
        .expect("sign the slip");
    let gate = gate_issuing(Store::default(), &[&slip], Swap::default());

    assert!(matches!(held(&slip, "ssh"), Err(HeldSlipError::TwoHolders)));
    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), Some(&slip), &ssh()),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn an_own_key_slip_whose_end_cannot_be_read_is_refused_presented() {
    // A clock bound past what a `SystemTime` can hold passes the datalog. Its end cannot be read, so the
    // gate refuses it presented, as whatever cuts the admission at its end would.
    let slip = device_slip(DEVICE, "ssh");
    let far = slip
        .attenuate_with_raw_clock_bound(u64::MAX)
        .expect("a holder appends a block");
    let gate = gate_issuing(Store::default(), &[&slip], Swap::default());

    assert!(
        gate.admit_witnessed(proven(DEVICE), Some(&slip), &ssh())
            .is_ok(),
        "the fixture admits the slip as its issuer signed it"
    );
    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), Some(&far), &ssh()),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn an_own_key_device_slip_presented_by_another_key_admits_no_one() {
    // A device slip is share material: a copy reaches anyone. Presented, it is bound to whoever presents
    // it, and its own binding check admits only the device it names.
    let slip = device_slip(DEVICE, "ssh");
    let gate = gate_issuing(Store::default(), &[&slip], Swap::default());

    assert!(
        gate.admit_witnessed(proven(DEVICE), Some(&slip), &ssh())
            .is_ok(),
        "the fixture admits the device the slip names"
    );
    assert!(matches!(
        gate.admit_witnessed(proven(STRANGER), Some(&slip), &ssh()),
        Err(Refusal::NotGranted)
    ));
    assert_eq!(
        gate.admit(proven(STRANGER), Some(&slip), &ssh()),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn an_own_key_root_slip_presented_alone_admits_no_one() {
    // A root slip admits only beside a badge under the authority it names. Presented alone it admits no
    // one, recorded or not, whoever presents it.
    let slip = root_slip(FRIEND, "ssh");
    let gate = gate_issuing(Store::default(), &[&slip], Swap::default());

    assert_eq!(
        gate.admit_foreign(proven(DEVICE), &slip, &badge(FRIEND, DEVICE), &ssh()),
        Decision::Admit,
        "the fixture admits the slip beside a badge under its authority"
    );
    for peer in [DEVICE, FRIEND, STRANGER] {
        assert!(matches!(
            gate.admit_witnessed(proven(peer), Some(&slip), &ssh()),
            Err(Refusal::NotGranted)
        ));
    }
}

#[test]
fn a_holder_appended_to_a_bearer_slip_names_no_one_presented() {
    // Anyone holding a bearer slip can append a block with biscuit's own builder. A holder fact in that
    // block must stay invisible: the slip still names no one, so the presented path rules on it as the
    // bearer slip its issuer signed. Read as a device, it would name the appender; read as a root, it
    // would refuse here; read as both, it would refuse as naming two holders.
    let bearer = identity(OWN)
        .mint(&ssh(), hour())
        .expect("mint a bearer slip");
    let gate = gate_issuing(Store::default(), &[&bearer], Swap::default());
    let device = format!("device_bound(\"{}\");", key(STRANGER));
    let authority = format!("authority_bound(\"{}\");", key(FRIEND));

    for appended in [&device, &authority, &format!("{device}\n{authority}")] {
        let slip = bearer
            .attenuate_with_raw_datalog(appended)
            .expect("append a holder fact");
        let facts = slip.authority_facts().expect("read the authority block");
        assert_eq!(facts.device, None, "{appended}");
        assert_eq!(facts.authority, None, "{appended}");
        for peer in [STRANGER, DEVICE] {
            assert_eq!(
                gate.admit(proven(peer), Some(&slip), &ssh()),
                Decision::Admit,
                "{appended}"
            );
        }
    }
}

#[test]
fn a_holder_appended_to_a_device_slip_does_not_rebind_it() {
    // The binding check joins the dialer a verify injects to the holder the authority block names. A
    // check there sees only that block's facts and the verifier's, so a holder appended in a later block
    // never satisfies it, and neither does the injected fact's own name appended by hand.
    let slip = device_slip(DEVICE, "ssh");
    let gate = gate_issuing(Store::default(), &[&slip], Swap::default());

    for appended in [
        format!("device_bound(\"{}\");", key(STRANGER)),
        format!("bound_device(\"{}\");", key(STRANGER)),
    ] {
        let rebound = slip
            .attenuate_with_raw_datalog(&appended)
            .expect("append a holder fact");
        assert_eq!(
            rebound.authority_facts().expect("read").device,
            Some(key(DEVICE).to_string()),
            "{appended}"
        );
        assert_eq!(
            gate.admit(proven(DEVICE), Some(&rebound), &ssh()),
            Decision::Admit,
            "the fixture admits the device the slip names: {appended}"
        );
        assert!(
            matches!(
                gate.admit_witnessed(proven(STRANGER), Some(&rebound), &ssh()),
                Err(Refusal::NotGranted)
            ),
            "{appended}"
        );
    }
}

#[test]
fn a_slip_naming_a_malformed_device_is_never_held() {
    let slip = identity(OWN)
        .mint_bound_naming(&ssh(), "not a key", hour())
        .expect("sign the slip");

    assert!(matches!(
        held(&slip, "ssh"),
        Err(HeldSlipError::Denied(CapError::MalformedAuthority))
    ));
}

#[test]
fn an_own_key_slip_naming_a_malformed_device_admits_no_one_presented() {
    // The presented path never parses the device a slip names: it binds the slip to the peer presenting
    // it. A named device that is not a key never equals a proven peer, so the slip's own binding check
    // refuses everyone, recorded or not. A mint that drops that check, or a path that trusts the named
    // fact, turns this red.
    let named = identity(OWN)
        .mint_bound_naming(&ssh(), &key(DEVICE).to_string(), hour())
        .expect("sign the slip");
    let malformed = identity(OWN)
        .mint_bound_naming(&ssh(), "not a key", hour())
        .expect("sign the slip");
    let gate = gate_issuing(Store::default(), &[&named, &malformed], Swap::default());

    assert!(
        gate.admit_witnessed(proven(DEVICE), Some(&named), &ssh())
            .is_ok(),
        "the fixture admits a recorded slip naming a well-formed device"
    );
    for peer in [DEVICE, FRIEND, OWN, PIN, STRANGER] {
        assert!(matches!(
            gate.admit_witnessed(proven(peer), Some(&malformed), &ssh()),
            Err(Refusal::NotGranted)
        ));
        assert_eq!(
            gate.admit(proven(peer), Some(&malformed), &ssh()),
            Decision::Refuse(Refusal::NotGranted)
        );
    }
}

#[test]
fn a_narrowed_slip_is_never_held() {
    let narrowed = device_slip(DEVICE, "ssh")
        .attenuate(None, Some(hour()))
        .expect("a holder narrows a slip");

    assert!(matches!(
        held(&narrowed, "ssh"),
        Err(HeldSlipError::Narrowed)
    ));
}

#[test]
fn a_bearer_slip_is_never_held() {
    let bearer = identity(OWN)
        .mint(&ssh(), hour())
        .expect("mint a bearer slip");

    assert!(matches!(held(&bearer, "ssh"), Err(HeldSlipError::Bearer)));
}

#[test]
fn a_root_slip_naming_this_key_is_never_held() {
    assert!(matches!(
        held(&root_slip(OWN, "ssh"), "ssh"),
        Err(HeldSlipError::OwnRoot)
    ));
}

#[test]
fn a_slip_naming_two_holders_is_never_held() {
    let slip = identity(OWN)
        .mint_naming_two_holders(&ssh(), key(DEVICE), key(FRIEND), hour())
        .expect("sign the slip");

    assert!(matches!(held(&slip, "ssh"), Err(HeldSlipError::TwoHolders)));
}

#[test]
fn a_second_slip_for_a_key_and_service_displaces_the_first_and_hands_it_back() {
    // The index keeps the last slip inserted for a holder and service, and returns the one it displaced,
    // which still verifies: only revoking it ends it.
    let earlier = device_slip(DEVICE, "ssh");
    let later = identity(OWN)
        .mint_bound(&ssh(), key(DEVICE), ago(60))
        .expect("mint a slip that has ended");
    let mut index = index(&[&earlier], "ssh");
    let displaced = index
        .insert(HeldSlip::verify(&later, &ssh(), ago(120), key(OWN)).expect("it granted then"))
        .expect("verified under the index's key")
        .expect("the earlier slip is displaced");
    assert_eq!(Some(displaced.id()), earlier.root_revocation_id().as_ref());
    assert_eq!(index.len(), 1);
    let gate = gate(Store::default(), Swap::holding(index));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
}

#[test]
fn a_token_rooted_here_is_ruled_alone_and_never_falls_to_a_held_slip() {
    // The device holds a live slip, and presents a token rooted at this machine that was never recorded
    // as issued. The presented token is ruled on and refused; the held slip is not asked.
    let unrecorded = identity(OWN).mint(&ssh(), hour()).expect("mint a slip");
    let gate = gate(
        Store::default(),
        Swap::holding(index(&[&device_slip(DEVICE, "ssh")], "ssh")),
    );

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), Some(&unrecorded), &ssh()),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn a_device_slip_admits_beside_a_foreign_badge() {
    // A device of any authority presents its badge on every dial. A device slip admits by key, and the
    // grant it carries is the slip alone: the badge anchors nothing here.
    let gate = gate(
        Store::default(),
        Swap::holding(index(&[&device_slip(DEVICE, "ssh")], "ssh")),
    );

    let admitted = gate
        .admit_witnessed(proven(DEVICE), Some(&badge(FRIEND, DEVICE)), &ssh())
        .expect("the device slip admits");
    let grant = admitted.held().expect("a held admission carries its grant");
    assert_eq!(grant.slips().len(), 1);
    assert!(grant.badge().is_none());
}

#[test]
fn a_device_slip_admits_beside_a_revoked_or_misbound_foreign_badge() {
    // The peer would be admitted presenting nothing, so a foreign badge beside it, revoked or bound to
    // another device, neither refuses it nor rides on the grant.
    let revoked = badge(FRIEND, DEVICE);
    let misbound = badge(FRIEND, STRANGER);
    let store = Store::default();
    store.revoke_id(revoked.root_revocation_id().expect("a badge has an id"));
    let gate = gate(
        store,
        Swap::holding(index(&[&device_slip(DEVICE, "ssh")], "ssh")),
    );

    for presented in [&revoked, &misbound] {
        let admitted = gate
            .admit_witnessed(proven(DEVICE), Some(presented), &ssh())
            .expect("the device slip admits");
        let grant = admitted.held().expect("a held admission carries its grant");
        assert_eq!(grant.slips().len(), 1);
        assert!(grant.badge().is_none());
    }
}

#[test]
fn an_index_lists_every_slip_it_holds() {
    let device = device_slip(DEVICE, "ssh");
    let root = root_slip(FRIEND, "web");
    let mut index = index(&[&device], "ssh");
    index
        .insert(held(&root, "web").expect("a slip this machine holds"))
        .expect("verified under the index's key");

    let ids: HashSet<_> = index.iter().map(|slip| slip.id().clone()).collect();
    let expected: HashSet<_> = [&device, &root]
        .iter()
        .filter_map(|slip| slip.root_revocation_id())
        .collect();
    assert_eq!(index.iter().count(), 2);
    assert_eq!(ids, expected);
}

#[test]
fn an_arc_forwards_is_revoked_ids() {
    let slip = device_slip(DEVICE, "ssh");
    let store = Store::default();
    let gate = gate(
        Arc::new(store.clone()),
        Swap::holding(index(&[&slip], "ssh")),
    );
    assert!(gate.admit_witnessed(proven(DEVICE), None, &ssh()).is_ok());

    store.revoke_id(slip.root_revocation_id().expect("a slip has an id"));

    assert!(matches!(
        gate.admit_witnessed(proven(DEVICE), None, &ssh()),
        Err(Refusal::Missing)
    ));
}
