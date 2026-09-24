//! Gate policy: the variants and their admit/refuse rulings.

use core::time::Duration;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use biscuit_auth::builder::Algorithm;
use biscuit_auth::macros::biscuit;
use biscuit_auth::{KeyPair, PrivateKey};
use data_encoding::BASE32_NOPAD;

use crate::cap::{Cap, CapError, Identity, Request};
use crate::disabled_roots::{DisabledRoots, Latch};
use crate::gate::{
    Admission, Checked, Decision, Gate, IssuedIds, Origin, PinSource, ProvenPeer, Refusal,
    is_recorded,
};
use crate::revocations::{FileDenylist, RevocationId};
use crate::service::Service;
use crate::{STAT_DEBOUNCE, VerifyKey};

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
}

/// A rooted gate trusting `seed`'s authority, with an empty (no-file) revocation denylist.
fn rooted_gate(seed: u8) -> Gate {
    Gate::rooted(
        identity(seed).verifying_key(),
        FileDenylist::empty(PathBuf::new()),
    )
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

fn hour() -> SystemTime {
    Request::expires_in(Duration::from_secs(3600))
}

/// The proven-peer wrapper the admit surface takes: a transport handshake proved this key (see
/// `ProvenPeer`). In tests the "handshake" is our own deterministic key.
fn proven(key: VerifyKey) -> ProvenPeer {
    ProvenPeer::from_handshake(key)
}

/// A device-bound membership badge minted by `seed`'s authority for `device` (see `Identity::mint_member`).
fn bound_badge(seed: u8, device: VerifyKey) -> Cap {
    identity(seed)
        .mint_member(device, hour())
        .expect("mint bound badge")
}

/// A delegated slip minted by `seed`'s authority for `svc`.
fn slip(seed: u8, svc: &str) -> Cap {
    identity(seed)
        .mint(&service(svc), hour())
        .expect("mint slip")
}

fn some_peer() -> VerifyKey {
    identity(9).verifying_key()
}

#[test]
fn a_witness_carries_the_origin_that_minted_it() {
    // An open gate rules on nothing, so its witness is `Origin::Open`; a rooted gate verified a token, so
    // its witness is `Origin::Rooted`. A downstream `Never` ceiling reads this to refuse an open witness,
    // which is why it is the enum and not a bool: a third origin must break every match site.
    let opened = Gate::Open
        .admit_witnessed(proven(some_peer()), None, &service("ssh"))
        .expect("an open gate admits anyone");
    assert_eq!(opened.origin(), Origin::Open);

    let gate = rooted_gate(1);
    let slipped = gate
        .admit_witnessed(proven(some_peer()), Some(&slip(1, "ssh")), &service("ssh"))
        .expect("a delegated slip admits its service");
    assert_eq!(slipped.origin(), Origin::Rooted);

    // The two-token foreign-authority AND is a rooted ruling too: both leaves verified against a root.
    let hire_device = identity(4).verifying_key();
    let foreign = gate
        .admit_foreign_witnessed(
            proven(hire_device),
            &authority_slip(2, "ssh"),
            &foreign_badge(2, hire_device),
            &service("ssh"),
        )
        .expect("slip + valid badge under X admits");
    assert_eq!(foreign.origin(), Origin::Rooted);
}

#[test]
fn open_admits_anyone() {
    let gate = Gate::Open;
    assert_eq!(
        gate.admit(proven(some_peer()), None, &service("ssh")),
        Decision::Admit
    );
    assert!(!gate.wants_capability());
}

#[test]
fn rooted_refuses_when_no_token_is_presented() {
    let gate = rooted_gate(1);
    assert_eq!(
        gate.admit(proven(some_peer()), None, &service("ssh")),
        Decision::Refuse(Refusal::Missing)
    );
    assert!(gate.wants_capability());
}

#[test]
fn rooted_admits_a_bound_badge_only_from_its_device() {
    // A device-bound badge (mint_member) is non-transferable: the rooted gate admits it whole-node ONLY when
    // the proven dialer is the bound device. The same badge presented by any other key is refused, so a
    // leaked badge blob is useless without the matching device secret. This is the production admit() path
    // (peer threaded through), not just verify().
    let gate = rooted_gate(1);
    let device = identity(4).verifying_key();
    let badge = bound_badge(1, device);

    assert_eq!(
        gate.admit(proven(device), Some(&badge), &service("ssh")),
        Decision::Admit,
        "the bound device is admitted whole-node"
    );
    let stranger = identity(7).verifying_key();
    assert_eq!(
        gate.admit(proven(stranger), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "the same badge from a foreign dialer is refused"
    );
}

#[test]
fn rooted_admits_a_delegated_slip_only_for_its_service() {
    // A friend carries a slip for ssh: admitted for ssh, refused for a service the slip does not grant.
    // Membership (whole-node) and delegation (one service) are the two meanings of one signature.
    let gate = rooted_gate(1);
    let ssh = slip(1, "ssh");
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&ssh), &service("ssh")),
        Decision::Admit
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&ssh), &service("web")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn rooted_refuses_a_token_from_a_foreign_authority() {
    // A badge or slip minted by a different authority is refused: the gate trusts exactly one key.
    let gate = rooted_gate(1);
    assert_eq!(
        gate.admit(
            proven(some_peer()),
            Some(&bound_badge(2, some_peer())),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&slip(2, "ssh")), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn a_revoked_token_and_its_delegations_are_refused_across_a_reload() {
    let authority = identity(1);
    let granted = authority.mint(&service("ssh"), hour()).expect("mint");
    // A third party narrows and re-shares the same grant: a delegation carrying the same root block.
    let delegated = granted
        .attenuate(Some(&service("ssh")), None)
        .expect("attenuate");

    let path = std::env::temp_dir().join(format!("nauthy-revoke-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    {
        let mut denylist = FileDenylist::load(path.clone()).await.expect("load");
        denylist.revoke(&granted).await.expect("revoke");
    }
    // Reload from disk: revocation must survive a restart, which a bare TTL cannot give.
    let denylist = FileDenylist::load(path.clone()).await.expect("reload");
    let gate = Gate::rooted(authority.verifying_key(), denylist);

    assert_eq!(
        gate.admit(proven(some_peer()), Some(&granted), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // The delegation carries the revoked root block, so it is refused too.
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&delegated), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // A different, unrevoked grant from the same authority is still admitted.
    let other = authority.mint(&service("ssh"), hour()).expect("mint");
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&other), &service("ssh")),
        Decision::Admit
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rooted_can_trust_a_foreign_authority_the_ci_model() {
    // A CI runner is provisioned to trust the OWNER's authority: it admits tokens rooted at that key without
    // ever holding its secret, so a compromised runner can mint no access. The owner's device badge is
    // admitted; a stranger's token is refused.
    let owner = identity(5);
    let gate = Gate::rooted(owner.verifying_key(), FileDenylist::empty(PathBuf::new()));
    let owned = owner.mint_member(some_peer(), hour()).expect("mint");
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&owned), &service("ssh")),
        Decision::Admit
    );
    let stranger = identity(6).mint(&service("ssh"), hour()).expect("mint");
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&stranger), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn revocation_goes_live_without_reconstructing_the_denylist() {
    // A long-running issuer holds ONE FileDenylist; a revocation in a SEPARATE process writes the revoked id
    // to the file. The running gate must honor it on the next check (within one stat-debounce window), not
    // at the next restart. Here the same live denylist, never reloaded or reconstructed, refuses a cap after
    // a separate handle revokes it, because is_revoked re-reads the file when its mtime changed.
    let authority = identity(1);
    let granted = authority.mint(&service("ssh"), hour()).expect("mint");
    let path = std::env::temp_dir().join(format!("nauthy-live-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));

    // The running issuer's denylist: loaded once, empty (file absent).
    let live = FileDenylist::load(path.clone()).await.expect("load");
    assert!(!live.is_revoked(&granted), "unrevoked at first");

    // A separate process revokes the cap by writing the file.
    {
        let mut revoker = FileDenylist::load(path.clone()).await.expect("load");
        revoker.revoke(&granted).await.expect("revoke");
    }

    // Wait past the stat debounce so the next check restats the file; a blocking sleep is fine here (a
    // current-thread test with nothing else to run). Instant-based elapsed() advances in real time.
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));

    // Without any reload/reconstruction, the running denylist now refuses it: live revocation.
    assert!(
        live.is_revoked(&granted),
        "revocation must go live without a restart"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_deleted_denylist_file_does_not_un_revoke() {
    // Fail closed: deleting the backing file is NOT "the denylist is empty". A running issuer that revoked
    // a cap must keep refusing it even if the file disappears (a botched cleanup, or a local attacker who
    // `rm`s it to un-revoke a lost device). The last-known set stands until a real file replaces it.
    let authority = identity(1);
    let granted = authority.mint(&service("ssh"), hour()).expect("mint");
    let path = std::env::temp_dir().join(format!("nauthy-delete-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));

    let mut live = FileDenylist::load(path.clone()).await.expect("load");
    live.revoke(&granted).await.expect("revoke");
    assert!(live.is_revoked(&granted), "revoked after the write");

    // Delete the file out from under the running denylist.
    std::fs::remove_file(&path).expect("remove");

    assert!(
        live.is_revoked(&granted),
        "a deleted denylist file must not silently un-revoke a recalled cap"
    );
    let _ = std::fs::remove_file(&path);
}

// The authority-bound admit matrix: work (`rooted_gate(1)`) issues a slip bound to the hire's authority `X`
// (`identity(2)`). The hire's device (`identity(4)`) proves membership under `X` with a badge `X` signed,
// bound to that device. The gate admits ONLY when the slip AND a valid badge under `X` (bound to the proven
// dialer) are both present, the two-token AND (`Gate::admit_foreign`).

/// Work's slip for `svc`, bound to the authority of `authority_seed`.
fn authority_slip(authority_seed: u8, svc: &str) -> Cap {
    identity(1)
        .mint_authority_slip(
            &service(svc),
            identity(authority_seed).verifying_key(),
            hour(),
        )
        .expect("mint authority slip")
}

/// A membership badge minted by `authority_seed`'s authority for `device`: the hire's own device badge under
/// their authority. Bound to `device`, so only the proven dialer that IS `device` may present it.
fn foreign_badge(authority_seed: u8, device: VerifyKey) -> Cap {
    identity(authority_seed)
        .mint_member(device, hour())
        .expect("mint foreign badge")
}

#[test]
fn authority_slip_with_a_valid_foreign_badge_admits_as_a_slip() {
    // The acceptance case: the authority-bound slip (work signed, naming authority `X`) AND the hire
    // device's badge under `X`, bound to the proven dialer. Both leaves hold, so the AND admits. The
    // admission is `Slip`, NEVER `Member`: a foreign authority's member is not a whole-node member of THIS
    // node.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "ssh");
    let badge = foreign_badge(2, hire_device);
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &badge, &service("ssh")),
        Decision::Admit,
        "slip + valid badge under X, bound to the proven dialer, admits"
    );
    let admitted = gate
        .admit_foreign_witnessed(proven(hire_device), &slip, &badge, &service("ssh"))
        .expect("witnessed admission");
    assert_eq!(
        admitted.kind(),
        Admission::Slip,
        "a foreign-authority admission is a Slip, never a whole-node Member"
    );
    assert!(
        !admitted.is_member(),
        "a foreign member is not a whole-node member"
    );
}

#[test]
fn an_authority_slip_alone_on_the_plain_path_is_refused() {
    // The slip is inert on the plain path (its foreign_member check is unsatisfied there), so presenting it
    // to plain `admit` with no badge refuses NotGranted. The two-token AND is the only path that admits it.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "ssh");
    assert_eq!(
        gate.admit(proven(hire_device), Some(&slip), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "an authority slip with no membership badge is refused on the plain path"
    );
}

#[test]
fn a_foreign_badge_on_the_plain_path_does_not_admit() {
    // A foreign-authority membership badge presented on the plain path (as the sole grant) does not admit:
    // it roots at the foreign authority X, not this gate's authority, so both is_member and grants fail
    // against this root and it is refused NotGranted. The badge-with-no-slip case is now unrepresentable on
    // the AND: `admit_foreign` REQUIRES both a slip and a badge, so a badge can never be presented alone.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let badge = foreign_badge(2, hire_device);
    assert_eq!(
        gate.admit(proven(hire_device), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "a foreign badge on the plain path does not admit"
    );
}

#[test]
fn an_authority_slip_with_a_wrong_root_badge_is_refused() {
    // The badge's root is checked AGAINST the `X` the SLIP names (never a badge-supplied root): a badge
    // under a different authority `Y` fails ForeignRoot, so `member_under_x` is false.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "ssh"); // bound to authority X = identity(2)
    let wrong_badge = foreign_badge(3, hire_device); // badge under authority Y = identity(3)
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &wrong_badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "a badge under the wrong authority cannot satisfy the AND"
    );
}

#[test]
fn an_authority_slip_with_a_badge_for_another_device_is_refused() {
    // The badge under `X` is bound to a DIFFERENT device than the proven dialer, so its bound_device check
    // fails: a stolen slip+badge replayed from another key never admits.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let other_device = identity(8).verifying_key();
    let slip = authority_slip(2, "ssh");
    let badge_for_other = foreign_badge(2, other_device);
    assert_eq!(
        gate.admit_foreign(
            proven(hire_device),
            &slip,
            &badge_for_other,
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted),
        "a badge bound to a different device than the proven dialer is refused"
    );
}

#[test]
fn an_authority_slip_for_the_wrong_service_is_refused() {
    // The slip grants `web`, but the dial is for `ssh`: the slip's service check fails inside
    // verify_authority_bound_at_root_without_revocation, so it never names its authority and the AND cannot
    // even begin.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "web");
    let badge = foreign_badge(2, hire_device);
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "an authority slip for the wrong service is refused even with a valid badge"
    );
}

#[test]
fn an_authority_slip_with_an_expired_badge_is_refused() {
    // The badge under `X` is expired at wall-clock now, so its expiry check fails and the AND cannot hold,
    // even though the slip and the authority root are correct.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "ssh");
    let expired_badge = identity(2)
        .mint_member(hire_device, SystemTime::UNIX_EPOCH)
        .expect("mint an already-expired badge");
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &expired_badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "an expired foreign badge cannot satisfy the authority-bound AND"
    );
}

#[test]
fn an_authority_slip_with_a_non_member_cap_as_the_badge_is_refused() {
    // The badge slot is a plain service slip under `X`, NOT a membership badge (no `member(true)` fact), so
    // verify_member_at_root_without_revocation refuses it: only a real membership badge proves membership.
    let gate = rooted_gate(1);
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "ssh");
    let not_a_badge = identity(2)
        .mint(&service("ssh"), hour())
        .expect("mint a plain slip under X");
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &not_a_badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "a non-membership cap as the badge cannot satisfy the authority-bound AND"
    );
}

#[tokio::test]
async fn a_revoked_authority_slip_is_refused_even_with_a_valid_badge() {
    // Revoke-the-slip kills the WHOLE foreign authority's access: record the slip's revocation id in work's
    // denylist, and the authority-bound arm refuses `Revoked` even though the badge under `X` still
    // verifies. The badge (rooted at `X`) is NOT work's to revoke; revoking the slip is how work cuts the
    // person off.
    let work = identity(1);
    let hire_device = identity(4).verifying_key();
    let slip = work
        .mint_authority_slip(&service("ssh"), identity(2).verifying_key(), hour())
        .expect("mint authority slip");
    let badge = foreign_badge(2, hire_device);

    let path = std::env::temp_dir().join(format!("nauthy-authority-revoke-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    let mut denylist = FileDenylist::load(path.clone()).await.expect("load");
    denylist.revoke(&slip).await.expect("revoke the slip");
    let gate = Gate::rooted(work.verifying_key(), denylist);

    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &badge, &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "a revoked authority slip is refused even when the foreign badge still verifies"
    );
    let _ = std::fs::remove_file(&path);
}

/// A rooted gate at `gate_seed` whose oracle disables `disabled_seed`'s root key over an empty denylist, and
/// the latch file backing it (the caller removes it).
async fn gate_disabling(gate_seed: u8, disabled_seed: u8, tag: &str) -> (Gate, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "nauthy-gate-disabled-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    let mut disabled = DisabledRoots::load(path.clone()).await.expect("load");
    disabled
        .disable(identity(disabled_seed).verifying_key())
        .await
        .expect("disable");
    let oracle = Latch::new(disabled, FileDenylist::empty(PathBuf::new()));
    (
        Gate::rooted(identity(gate_seed).verifying_key(), oracle),
        path,
    )
}

#[tokio::test]
async fn a_disabled_root_refuses_the_foreign_badge_on_the_two_token_path() {
    // Work issued a slip naming the hire's authority `X`, then disabled `X`. The slip is work's own and
    // clean, so only the question about the BADGE can refuse, and it must: every device `X` badged is
    // out. The control is the same pair at a gate that disabled some other root, which admits.
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "ssh");
    let badge = foreign_badge(2, hire_device);

    let (gate, path) = gate_disabling(1, 2, "foreign").await;
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &badge, &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "a badge rooted at a disabled authority is refused though the slip is clean"
    );
    assert!(
        matches!(
            gate.admit_foreign_witnessed(proven(hire_device), &slip, &badge, &service("ssh")),
            Err(Refusal::Revoked)
        ),
        "the witnessed path shares the refusal"
    );
    let _ = std::fs::remove_file(&path);

    let (control, path) = gate_disabling(1, 3, "foreign-control").await;
    assert_eq!(
        control.admit_foreign(proven(hire_device), &slip, &badge, &service("ssh")),
        Decision::Admit,
        "the same pair admits where its root is not disabled"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_disabled_foreign_root_is_refused_before_the_pair_is_evaluated() {
    // The badge is asked with the slip, BEFORE the verify, as `admit_plain` asks its one token. The slip is
    // for `web` and the request is `ssh`, so the pair would also have failed; the recall is the answer
    // reached first. Ask about the badge after the verify instead and this reports `NotGranted`.
    let hire_device = identity(4).verifying_key();
    let slip = authority_slip(2, "web");
    let badge = foreign_badge(2, hire_device);

    let (gate, path) = gate_disabling(1, 2, "foreign-order").await;
    assert_eq!(
        gate.admit_foreign(proven(hire_device), &slip, &badge, &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "a disabled foreign root is refused without running the pair's checks"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_disabled_root_refuses_its_own_badge_on_the_plain_path() {
    // The gate's own authority disabled: the badge it once signed for this device no longer admits.
    let device = identity(4).verifying_key();
    let badge = bound_badge(1, device);

    let (gate, path) = gate_disabling(1, 1, "plain").await;
    assert_eq!(
        gate.admit(proven(device), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "a badge rooted at a disabled key is refused on the plain path"
    );
    let _ = std::fs::remove_file(&path);
}

/// An oracle that disables one root only from its SECOND question about that root: a disable that lands
/// while the pair is being evaluated, between the gate's two revocation reads.
struct DisabledMidEvaluation {
    root: VerifyKey,
    asked: core::sync::atomic::AtomicU32,
}

impl crate::revocations::Revocations for DisabledMidEvaluation {
    fn is_revoked(&self, cap: &Cap) -> bool {
        if cap.root() != self.root {
            return false;
        }
        self.asked
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            >= 1
    }
}

#[test]
fn a_foreign_root_disabled_during_evaluation_is_refused_on_the_second_read() {
    // The first read passes the badge; the root is disabled while the pair verifies. The second read must
    // ask about the badge again, as it asks about the slip, or this admission lands on a dead root.
    let hire_device = identity(4).verifying_key();
    let gate = Gate::rooted(
        identity(1).verifying_key(),
        DisabledMidEvaluation {
            root: identity(2).verifying_key(),
            asked: core::sync::atomic::AtomicU32::new(0),
        },
    );
    assert_eq!(
        gate.admit_foreign(
            proven(hire_device),
            &authority_slip(2, "ssh"),
            &foreign_badge(2, hire_device),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked),
        "a root disabled between the two reads is refused"
    );
}

#[test]
fn an_undecided_check_refuses_as_undecided_never_as_a_denial() {
    // A check that ran out of its evaluation budget decided NOTHING about the holder, so the gate must not
    // report the refusal every non-granting token gets: the peer would read "you are not authorized" from a
    // host that was merely busy. The connection is still refused, because nothing may be admitted on an
    // answer that was never computed.
    let denylist = FileDenylist::empty(PathBuf::new());
    let cap = slip(1, "ssh");
    assert_eq!(
        Checked::from(Err(CapError::Undecided)).decide(&denylist, &cap),
        Decision::Refuse(Refusal::Undecided)
    );
    assert_eq!(
        Checked::from(Err(CapError::ForeignRoot)).decide(&denylist, &cap),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn an_undecided_check_survives_the_other_questions_refusal() {
    // A cap admits on EITHER membership or the requested service, so a stalled membership check paired with
    // a plain "no" from the service check is still not an answer: reporting `NotGranted` there would hide
    // the stall behind the other question. A real GRANT does override it, since that answer needs no help
    // from the question that stalled.
    let denylist = FileDenylist::empty(PathBuf::new());
    let cap = slip(1, "ssh");
    assert_eq!(
        Checked::Undecided
            .or_else(|| Checked::NotGranted)
            .decide(&denylist, &cap),
        Decision::Refuse(Refusal::Undecided)
    );
    assert_eq!(
        Checked::Undecided
            .or_else(|| Checked::Granted)
            .decide(&denylist, &cap),
        Decision::Admit
    );
}

#[tokio::test]
async fn a_revoked_token_is_refused_before_its_grant_is_evaluated() {
    // The order this holds, and the only way to observe it from outside. Revocation is a set lookup over
    // the token's own block signatures, independent of whether the token grants, so it is asked BEFORE the
    // datalog: a revoked but persistent holder can no longer make this node pay for an evaluation it was
    // always going to throw away. A revoked token that would ALSO have failed its checks (this one is for
    // `web`, asked for `ssh`) reports the answer reached FIRST. Ask the store after the verify instead and
    // the same token reports `NotGranted`.
    let authority = identity(1);
    let revoked = authority
        .mint(&service("web"), hour())
        .expect("mint a slip for another service");

    let path = std::env::temp_dir().join(format!("nauthy-revoke-order-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    let mut denylist = FileDenylist::load(path.clone()).await.expect("load");
    denylist.revoke(&revoked).await.expect("revoke");
    let gate = Gate::rooted(authority.verifying_key(), denylist);

    assert_eq!(
        gate.admit(proven(some_peer()), Some(&revoked), &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "the recall is the answer, and it is reached without running the token's checks"
    );
    let _ = std::fs::remove_file(&path);
}

/// A store that revokes one device key and no token, and counts every question it is asked about a cap, so
/// a test can see that the peer was refused before any presented token was read.
struct RevokedKey {
    key: VerifyKey,
    caps_asked: core::sync::atomic::AtomicU32,
}

impl RevokedKey {
    fn new(key: VerifyKey) -> Self {
        Self {
            key,
            caps_asked: core::sync::atomic::AtomicU32::new(0),
        }
    }

    fn caps_asked(&self) -> u32 {
        self.caps_asked.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl crate::revocations::Revocations for RevokedKey {
    fn is_revoked(&self, _cap: &Cap) -> bool {
        self.caps_asked
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        false
    }

    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        *peer == self.key
    }
}

#[test]
fn a_revoked_peer_key_is_refused_before_any_cap() {
    // A device whose key is revoked is refused on every entry point, whatever it presents: a valid badge
    // bound to it, nothing at all, or a valid foreign pair. The refusal comes before the store is asked
    // about any token, so nothing presented is read. A device whose key is not revoked is still admitted.
    let device = identity(4).verifying_key();
    let store = std::sync::Arc::new(RevokedKey::new(device));
    let gate = Gate::rooted(identity(1).verifying_key(), std::sync::Arc::clone(&store));

    assert_eq!(
        gate.admit(
            proven(device),
            Some(&bound_badge(1, device)),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked),
        "a valid badge does not carry a revoked device key"
    );
    assert_eq!(
        gate.admit(proven(device), None, &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "the key is refused before the gate looks for a token"
    );
    assert!(matches!(
        gate.admit_witnessed(
            proven(device),
            Some(&bound_badge(1, device)),
            &service("ssh")
        ),
        Err(Refusal::Revoked)
    ));
    assert_eq!(
        gate.admit_foreign(
            proven(device),
            &authority_slip(2, "ssh"),
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked),
        "the two-token path asks about the key before either token"
    );
    assert!(matches!(
        gate.admit_foreign_witnessed(
            proven(device),
            &authority_slip(2, "ssh"),
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Err(Refusal::Revoked)
    ));
    assert_eq!(store.caps_asked(), 0, "no presented token was read");

    let sibling = identity(5).verifying_key();
    assert_eq!(
        gate.admit(
            proven(sibling),
            Some(&bound_badge(1, sibling)),
            &service("ssh")
        ),
        Decision::Admit,
        "a device whose key is not revoked is admitted"
    );
}

#[tokio::test]
async fn a_latch_forwards_is_revoked_peer() {
    // `is_revoked_peer` is a provided method, so a `Latch` that did not forward it would answer the default
    // and admit a revoked device through the store it wraps.
    let path = std::env::temp_dir().join(format!("nauthy-latch-peer-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    let disabled = DisabledRoots::load(path.clone()).await.expect("load");
    let device = identity(4).verifying_key();
    let gate = Gate::rooted(
        identity(1).verifying_key(),
        Latch::new(disabled, RevokedKey::new(device)),
    );

    assert_eq!(
        gate.admit(
            proven(device),
            Some(&bound_badge(1, device)),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked),
        "the latch passes the key question to its inner store"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_arc_forwards_is_revoked_peer() {
    // One store shared behind an `Arc` answers the key question as the store itself does.
    let device = identity(4).verifying_key();
    let gate = Gate::rooted(
        identity(1).verifying_key(),
        std::sync::Arc::new(RevokedKey::new(device)),
    );

    assert_eq!(
        gate.admit(
            proven(device),
            Some(&bound_badge(1, device)),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked),
        "the Arc passes the key question to the store it shares"
    );
}

#[test]
fn a_store_that_keeps_no_keys_revokes_no_peer() {
    // The default: a store written before the key question existed, answering only about tokens, revokes
    // no device key, so its gate admits exactly what it admitted before.
    let device = identity(4).verifying_key();
    let gate = rooted_gate(1);

    assert_eq!(
        gate.admit(
            proven(device),
            Some(&bound_badge(1, device)),
            &service("ssh")
        ),
        Decision::Admit
    );
}

// The anchored gate: this machine's own key is `identity(OWN)`, its pin (when it has one) is `identity(PIN)`.
// A device of a foreign fleet is `identity(4)` under the fleet authority `identity(2)`.

const OWN: u8 = 3;
const PIN: u8 = 1;

fn own_key() -> VerifyKey {
    identity(OWN).verifying_key()
}

/// A pin that never changes.
struct FixedPin(Option<VerifyKey>);

impl PinSource for FixedPin {
    fn current(&self) -> Option<VerifyKey> {
        self.0
    }
}

/// A pin a test can move while a gate holds it, as another process rewrites a pin file under a serving
/// gate. The lock is shared by every clone, so the test and the gate see one value.
#[derive(Clone)]
struct MovablePin(Arc<RwLock<Option<VerifyKey>>>);

impl MovablePin {
    fn new(pin: Option<VerifyKey>) -> Self {
        Self(Arc::new(RwLock::new(pin)))
    }

    fn set(&self, pin: Option<VerifyKey>) {
        *self.0.write().expect("pin lock") = pin;
    }
}

impl PinSource for MovablePin {
    fn current(&self) -> Option<VerifyKey> {
        *self.0.read().expect("pin lock")
    }
}

/// The record of slips the own key issued, by root revocation id.
struct Ledger(Vec<RevocationId>);

impl Ledger {
    fn of(caps: &[&Cap]) -> Self {
        Self(
            caps.iter()
                .filter_map(|cap| cap.root_revocation_id())
                .collect(),
        )
    }
}

impl IssuedIds for Ledger {
    fn is_issued(&self, id: &RevocationId) -> bool {
        self.0.contains(id)
    }
}

/// A store that recalls every id of the caps it was given.
struct RecalledIds(Vec<RevocationId>);

impl crate::revocations::Revocations for RecalledIds {
    fn is_revoked(&self, cap: &Cap) -> bool {
        cap.revocation_ids().iter().any(|id| self.0.contains(id))
    }
}

/// An anchored gate at `OWN` with the pin `pin`, an empty denylist, and `issued` recorded as issued.
fn anchored_gate(pin: Option<u8>, issued: &[&Cap]) -> Gate {
    Gate::anchored(
        FixedPin(pin.map(|seed| identity(seed).verifying_key())),
        own_key(),
        FileDenylist::empty(PathBuf::new()),
        Ledger::of(issued),
    )
}

/// The own key's fleet slip for `svc`: any device `authority_seed` badges may reach it.
fn own_fleet_slip(authority_seed: u8, svc: &str) -> Cap {
    identity(OWN)
        .mint_authority_slip(
            &service(svc),
            identity(authority_seed).verifying_key(),
            hour(),
        )
        .expect("mint own fleet slip")
}

/// A token no mint in this crate writes, signed by `signer_seed`: a membership fact AND an authority-bound
/// fact naming `authority_seed`, with no service check, so it passes both the membership question and the
/// authority-bound slip check. Anyone holding the key can sign one.
fn member_fleet_slip(signer_seed: u8, authority_seed: u8) -> Cap {
    let private =
        PrivateKey::from_bytes(&[signer_seed; 32], Algorithm::Ed25519).expect("valid secret");
    let token = biscuit!(
        r#"
        member(true);
        authority_bound({x});
        check if time($t), $t <= {expiry};
        "#,
        x = identity(authority_seed).verifying_key().to_string(),
        expiry = hour(),
    )
    .build(&KeyPair::from(&private))
    .expect("sign");
    let bytes = token.to_vec().expect("encode");
    Cap::parse(&format!(
        "{}.{}",
        identity(signer_seed).verifying_key(),
        BASE32_NOPAD.encode(&bytes).to_lowercase()
    ))
    .expect("parse")
}

#[test]
fn a_member_cap_rooted_at_own_is_refused() {
    // The own key never makes a member. Its badge is refused even when recorded as issued, and never
    // collapsed to a slip, though a badge has no service check and so would pass as one.
    let device = identity(4).verifying_key();
    let badge = bound_badge(OWN, device);
    let gate = anchored_gate(Some(PIN), &[&badge]);

    assert_eq!(
        gate.admit(proven(device), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert!(matches!(
        gate.admit_witnessed(proven(device), Some(&badge), &service("ssh")),
        Err(Refusal::NotGranted)
    ));

    // On the two-token path: a recorded token that is both a member cap and a fleet slip, with a valid
    // badge from that fleet. Every other check passes, so only the membership refusal stops it.
    let slip = member_fleet_slip(OWN, 2);
    let gate = anchored_gate(Some(PIN), &[&slip]);
    let fleet_badge = foreign_badge(2, device);
    assert_eq!(
        gate.admit_foreign(proven(device), &slip, &fleet_badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert!(matches!(
        gate.admit_foreign_witnessed(proven(device), &slip, &fleet_badge, &service("ssh")),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn a_narrowed_member_cap_rooted_at_own_is_refused() {
    // Narrowing a badge to one service adds a service check the membership question cannot satisfy, since
    // it supplies no service fact, while the service question still passes it. The badge is still a badge:
    // refused on both paths, whatever service its holder picked.
    let device = identity(4).verifying_key();
    let badge = bound_badge(OWN, device);
    let narrowed = badge
        .attenuate(Some(&service("ssh")), None)
        .expect("a holder narrows an unsealed badge");
    let gate = anchored_gate(Some(PIN), &[&badge]);

    assert_eq!(
        gate.admit(proven(device), Some(&narrowed), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert!(matches!(
        gate.admit_witnessed(proven(device), Some(&narrowed), &service("ssh")),
        Err(Refusal::NotGranted)
    ));
    // With no pin, the own key is the only authority, and it still makes no member.
    let pinless = anchored_gate(None, &[&badge]);
    assert_eq!(
        pinless.admit(proven(device), Some(&narrowed), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );

    // On the two-token path: the recorded member fleet slip, narrowed to the service it is presented for.
    let slip = member_fleet_slip(OWN, 2);
    let narrowed = slip
        .attenuate(Some(&service("ssh")), None)
        .expect("a holder narrows the slip");
    let gate = anchored_gate(Some(PIN), &[&slip]);
    let fleet_badge = foreign_badge(2, device);
    assert_eq!(
        gate.admit_foreign(proven(device), &narrowed, &fleet_badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert!(matches!(
        gate.admit_foreign_witnessed(proven(device), &narrowed, &fleet_badge, &service("ssh")),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn a_member_fact_in_an_added_block_does_not_make_a_badge() {
    // The badge read sees the authority block only, so a slip a holder appends `member(true)` to is still
    // a slip, and an own slip that is recorded still admits its service.
    let slip = slip(OWN, "ssh");
    let appended = slip
        .attenuate_with_raw_datalog("member(true);")
        .expect("append a fact");
    assert!(!appended.is_member_badge().expect("read"));
    assert!(
        bound_badge(OWN, some_peer())
            .is_member_badge()
            .expect("read")
    );
    let gate = anchored_gate(Some(PIN), &[&slip]);
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&appended), &service("ssh")),
        Decision::Admit
    );
}

#[test]
fn an_undecided_membership_refuses_the_own_key_path_as_undecided() {
    // The own-key path refuses a member cap, so a membership question that never finished cannot let the
    // cap through to the slip check: it may be a member. It is refused, and as `Undecided`, since nothing
    // was decided about the holder.
    assert_eq!(Checked::Granted.refuse_member(), Err(Refusal::NotGranted));
    assert_eq!(Checked::Undecided.refuse_member(), Err(Refusal::Undecided));
    assert_eq!(Checked::NotGranted.refuse_member(), Ok(()));
}

#[test]
fn a_self_anchor_admission_is_never_a_member() {
    let slip = slip(OWN, "ssh");
    let gate = anchored_gate(Some(PIN), &[&slip]);

    let admitted = gate
        .admit_witnessed(proven(some_peer()), Some(&slip), &service("ssh"))
        .expect("a recorded own slip admits its service");
    assert!(!admitted.is_member());
    assert_eq!(admitted.kind(), Admission::Slip);
}

#[test]
fn a_self_slip_absent_from_the_ledger_is_refused() {
    // A copy of the own key mints a slip for the same service and lifetime. Its id is fresh, so it is not
    // the one recorded, and it is refused; the recorded slip is admitted.
    let expiry = hour();
    let issued = identity(OWN)
        .mint(&service("ssh"), expiry)
        .expect("mint issued");
    let copied = identity(OWN)
        .mint(&service("ssh"), expiry)
        .expect("mint copied");
    let gate = anchored_gate(Some(PIN), &[&issued]);

    assert_eq!(
        gate.admit(proven(some_peer()), Some(&copied), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&issued), &service("ssh")),
        Decision::Admit
    );
}

/// A record that holds every id.
struct EveryId;

impl IssuedIds for EveryId {
    fn is_issued(&self, _id: &RevocationId) -> bool {
        true
    }
}

#[test]
fn a_self_slip_with_no_root_id_is_refused() {
    // A well-formed token always has a root id, so no presented cap reaches this; the rule is asked
    // directly. With nothing to look up, the token was never recorded, even by a record that holds all.
    assert!(!is_recorded(&EveryId, None));
    assert!(is_recorded(&EveryId, slip(OWN, "ssh").root_revocation_id()));
}

#[test]
fn a_revoked_self_slip_is_refused() {
    let issued = slip(OWN, "ssh");
    let gate = Gate::anchored(
        FixedPin(Some(identity(PIN).verifying_key())),
        own_key(),
        RecalledIds(issued.revocation_ids()),
        Ledger::of(&[&issued]),
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&issued), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );

    // Asked before the verify: a recalled slip for `web` asked for `ssh` reports the recall, not the miss.
    let web = slip(OWN, "web");
    let gate = Gate::anchored(
        FixedPin(None),
        own_key(),
        RecalledIds(web.revocation_ids()),
        Ledger::of(&[&web]),
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&web), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );

    // And asked again after it: a recall that lands while the slip verifies is refused now.
    let gate = Gate::anchored(
        FixedPin(None),
        own_key(),
        DisabledMidEvaluation {
            root: own_key(),
            asked: core::sync::atomic::AtomicU32::new(0),
        },
        Ledger::of(&[&issued]),
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&issued), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
}

/// An anchored gate at `OWN` pinned to `PIN`, whose oracle disables `disabled_seed`'s root key, and the
/// latch file backing it (the caller removes it).
async fn anchored_gate_disabling(disabled_seed: u8, issued: &[&Cap], tag: &str) -> (Gate, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "nauthy-anchored-disabled-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    let mut disabled = DisabledRoots::load(path.clone()).await.expect("load");
    disabled
        .disable(identity(disabled_seed).verifying_key())
        .await
        .expect("disable");
    let gate = Gate::anchored(
        FixedPin(Some(identity(PIN).verifying_key())),
        own_key(),
        Latch::new(disabled, FileDenylist::empty(PathBuf::new())),
        Ledger::of(issued),
    );
    (gate, path)
}

#[tokio::test]
async fn a_latched_own_key_refuses_every_self_slip() {
    let ssh = slip(OWN, "ssh");
    let web = slip(OWN, "web");
    let (gate, path) = anchored_gate_disabling(OWN, &[&ssh, &web], "own").await;

    assert_eq!(
        gate.admit(proven(some_peer()), Some(&ssh), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    assert_eq!(
        gate.admit(proven(some_peer()), Some(&web), &service("web")),
        Decision::Refuse(Refusal::Revoked)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_pinless_gate_admits_no_member() {
    // With no pin, the own key is the only authority, and it makes no members: its badge is refused, and a
    // badge from any other key roots at nothing this gate trusts.
    let device = identity(4).verifying_key();
    let own_badge = bound_badge(OWN, device);
    let other_badge = bound_badge(PIN, device);
    let gate = anchored_gate(None, &[&own_badge, &other_badge]);

    for badge in [&own_badge, &other_badge] {
        assert_eq!(
            gate.admit(proven(device), Some(badge), &service("ssh")),
            Decision::Refuse(Refusal::NotGranted)
        );
        assert!(
            gate.admit_witnessed(proven(device), Some(badge), &service("ssh"))
                .is_err()
        );
    }
}

#[test]
fn a_pin_equal_to_own_anchors_nothing() {
    // A source that reports this machine's own key does not make the own key a root: its badge is still
    // refused, and its recorded slip is still admitted only as a slip.
    let device = identity(4).verifying_key();
    let badge = bound_badge(OWN, device);
    let ssh = slip(OWN, "ssh");
    let gate = Gate::anchored(
        FixedPin(Some(own_key())),
        own_key(),
        FileDenylist::empty(PathBuf::new()),
        Ledger::of(&[&badge, &ssh]),
    );

    assert_eq!(
        gate.admit(proven(device), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    let admitted = gate
        .admit_witnessed(proven(device), Some(&ssh), &service("ssh"))
        .expect("a recorded own slip admits its service");
    assert!(!admitted.is_member());
}

#[test]
fn a_pin_written_later_is_trusted_at_the_next_admission() {
    // The pin is read on every admission, so a pin written while the gate serves is trusted at the next
    // connection, and one removed stops being trusted at the next.
    let device = identity(4).verifying_key();
    let badge = bound_badge(PIN, device);
    let pin = MovablePin::new(None);
    let gate = Gate::anchored(
        pin.clone(),
        own_key(),
        FileDenylist::empty(PathBuf::new()),
        Ledger(Vec::new()),
    );

    assert_eq!(
        gate.admit(proven(device), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "no pin yet"
    );
    pin.set(Some(identity(PIN).verifying_key()));
    let admitted = gate
        .admit_witnessed(proven(device), Some(&badge), &service("ssh"))
        .expect("the new pin's badge admits");
    assert!(admitted.is_member());
    pin.set(None);
    assert_eq!(
        gate.admit(proven(device), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "the pin is gone"
    );
}

#[test]
fn a_token_rooted_at_the_pin_is_ruled_as_a_rooted_gate_rules_it() {
    // A badge is a member, a slip admits its service only, a fleet slip admits its fleet's device, and a
    // recalled token is refused, none of it needing the own key's record.
    let device = identity(4).verifying_key();
    let gate = anchored_gate(Some(PIN), &[]);

    let member = gate
        .admit_witnessed(
            proven(device),
            Some(&bound_badge(PIN, device)),
            &service("ssh"),
        )
        .expect("the pin's badge admits");
    assert!(member.is_member());
    assert_eq!(member.origin(), Origin::Rooted);

    let slipped = gate
        .admit_witnessed(proven(device), Some(&slip(PIN, "ssh")), &service("ssh"))
        .expect("the pin's slip admits its service");
    assert_eq!(slipped.kind(), Admission::Slip);
    assert_eq!(
        gate.admit(proven(device), Some(&slip(PIN, "ssh")), &service("web")),
        Decision::Refuse(Refusal::NotGranted)
    );

    assert_eq!(
        gate.admit_foreign(
            proven(device),
            &authority_slip(2, "ssh"),
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Decision::Admit
    );

    let recalled = slip(PIN, "ssh");
    let gate = Gate::anchored(
        FixedPin(Some(identity(PIN).verifying_key())),
        own_key(),
        RecalledIds(recalled.revocation_ids()),
        Ledger(Vec::new()),
    );
    assert_eq!(
        gate.admit(proven(device), Some(&recalled), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
}

#[test]
fn a_node_signed_fleet_slip_admits_a_device_of_that_fleet() {
    let device = identity(4).verifying_key();
    let slip = own_fleet_slip(2, "ssh");
    let badge = foreign_badge(2, device);
    let gate = anchored_gate(Some(PIN), &[&slip]);

    assert_eq!(
        gate.admit_foreign(proven(device), &slip, &badge, &service("ssh")),
        Decision::Admit
    );
    let admitted = gate
        .admit_foreign_witnessed(proven(device), &slip, &badge, &service("ssh"))
        .expect("a recorded fleet slip admits the fleet's device");
    assert_eq!(admitted.kind(), Admission::Slip);

    // With no pin at all: the own key's slips do not depend on a root.
    let gate = anchored_gate(None, &[&slip]);
    assert_eq!(
        gate.admit_foreign(proven(device), &slip, &badge, &service("ssh")),
        Decision::Admit
    );
}

#[test]
fn a_node_signed_fleet_slip_absent_from_the_ledger_is_refused() {
    let device = identity(4).verifying_key();
    let gate = anchored_gate(Some(PIN), &[]);

    assert_eq!(
        gate.admit_foreign(
            proven(device),
            &own_fleet_slip(2, "ssh"),
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn a_foreign_slip_naming_own_as_authority_is_refused() {
    // A recorded fleet slip naming the own key as its fleet. Anyone holding a copy of the own key can
    // badge a key of their choosing under it, so the slip is refused before any badge is read.
    let thief = identity(7).verifying_key();
    let slip = own_fleet_slip(OWN, "ssh");
    let badge = bound_badge(OWN, thief);
    let gate = anchored_gate(Some(PIN), &[&slip]);

    assert_eq!(
        gate.admit_foreign(proven(thief), &slip, &badge, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn a_latched_fleet_refuses_a_node_signed_fleet_slip() {
    // A disabled fleet authority refuses its devices on the own key's fleet slip, asked before the pair
    // verifies (this slip is for `web`, asked for `ssh`, so a late read would report the miss) and again
    // after it.
    let device = identity(4).verifying_key();
    let web = own_fleet_slip(2, "web");
    let ssh = own_fleet_slip(2, "ssh");
    let (gate, path) = anchored_gate_disabling(2, &[&web, &ssh], "fleet").await;

    assert_eq!(
        gate.admit_foreign(
            proven(device),
            &web,
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked)
    );
    let _ = std::fs::remove_file(&path);

    let gate = Gate::anchored(
        FixedPin(None),
        own_key(),
        DisabledMidEvaluation {
            root: identity(2).verifying_key(),
            asked: core::sync::atomic::AtomicU32::new(0),
        },
        Ledger::of(&[&ssh]),
    );
    assert_eq!(
        gate.admit_foreign(
            proven(device),
            &ssh,
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::Revoked)
    );
}

#[test]
fn a_cap_rooted_elsewhere_never_takes_the_self_anchor_path() {
    // A stranger's slip roots at neither the pin nor the own key. Its id is in the record, so only the
    // choice of path can refuse it.
    let stranger = slip(5, "ssh");
    let stranger_fleet = identity(5)
        .mint_authority_slip(&service("ssh"), identity(2).verifying_key(), hour())
        .expect("mint stranger fleet slip");
    let gate = anchored_gate(Some(PIN), &[&stranger, &stranger_fleet]);
    let device = identity(4).verifying_key();

    assert_eq!(
        gate.admit(proven(device), Some(&stranger), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert_eq!(
        gate.admit_foreign(
            proven(device),
            &stranger_fleet,
            &foreign_badge(2, device),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn an_anchored_gate_wants_a_capability() {
    let gate = anchored_gate(Some(PIN), &[]);
    assert!(gate.wants_capability());
    assert_eq!(
        gate.admit(proven(some_peer()), None, &service("ssh")),
        Decision::Refuse(Refusal::Missing)
    );
}

#[test]
fn a_self_anchored_admission_is_origin_rooted() {
    // A handler that serves only verified peers reads the origin. The own key is one of the gate's
    // authorities, so its admissions are `Rooted`, on both paths.
    let device = identity(4).verifying_key();
    let ssh = slip(OWN, "ssh");
    let fleet = own_fleet_slip(2, "ssh");
    let gate = anchored_gate(Some(PIN), &[&ssh, &fleet]);

    let plain = gate
        .admit_witnessed(proven(device), Some(&ssh), &service("ssh"))
        .expect("a recorded own slip admits");
    assert_eq!(plain.origin(), Origin::Rooted);
    let foreign = gate
        .admit_foreign_witnessed(
            proven(device),
            &fleet,
            &foreign_badge(2, device),
            &service("ssh"),
        )
        .expect("a recorded fleet slip admits");
    assert_eq!(foreign.origin(), Origin::Rooted);
}

#[test]
fn an_anchored_gate_refuses_a_revoked_peer_key_before_any_cap() {
    // On every entry point and on both authorities, the device's own key is asked before any token.
    let device = identity(4).verifying_key();
    let own_slip = slip(OWN, "ssh");
    let fleet = own_fleet_slip(2, "ssh");
    let store = Arc::new(RevokedKey::new(device));
    let gate = Gate::anchored(
        FixedPin(Some(identity(PIN).verifying_key())),
        own_key(),
        Arc::clone(&store),
        Ledger::of(&[&own_slip, &fleet]),
    );

    for presented in [Some(&own_slip), Some(&bound_badge(PIN, device)), None] {
        assert_eq!(
            gate.admit(proven(device), presented, &service("ssh")),
            Decision::Refuse(Refusal::Revoked)
        );
        assert!(matches!(
            gate.admit_witnessed(proven(device), presented, &service("ssh")),
            Err(Refusal::Revoked)
        ));
    }
    for slip in [&fleet, &authority_slip(2, "ssh")] {
        assert_eq!(
            gate.admit_foreign(
                proven(device),
                slip,
                &foreign_badge(2, device),
                &service("ssh")
            ),
            Decision::Refuse(Refusal::Revoked)
        );
        assert!(matches!(
            gate.admit_foreign_witnessed(
                proven(device),
                slip,
                &foreign_badge(2, device),
                &service("ssh")
            ),
            Err(Refusal::Revoked)
        ));
    }
    assert_eq!(store.caps_asked(), 0, "no presented token was read");

    let sibling = identity(5).verifying_key();
    assert_eq!(
        gate.admit(proven(sibling), Some(&own_slip), &service("ssh")),
        Decision::Admit,
        "a device whose key is not revoked is admitted"
    );
}

#[tokio::test]
async fn a_latch_forwards_is_revoked_peer_on_an_anchored_gate() {
    let path =
        std::env::temp_dir().join(format!("nauthy-anchored-latch-peer-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(crate::revocations::witness_path(&path));
    let disabled = DisabledRoots::load(path.clone()).await.expect("load");
    let device = identity(4).verifying_key();
    let own_slip = slip(OWN, "ssh");
    let gate = Gate::anchored(
        FixedPin(None),
        own_key(),
        Latch::new(disabled, RevokedKey::new(device)),
        Ledger::of(&[&own_slip]),
    );

    assert_eq!(
        gate.admit(proven(device), Some(&own_slip), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pin_source_for_arc_reads_through() {
    // One source shared behind an `Arc` answers as the source does now, so a gate and any other reader
    // holding the same `Arc` agree on the pin.
    let pin = Arc::new(MovablePin::new(None));
    let shared: Arc<MovablePin> = Arc::clone(&pin);
    assert_eq!(PinSource::current(&shared), None);
    pin.set(Some(own_key()));
    assert_eq!(PinSource::current(&shared), Some(own_key()));

    let device = identity(4).verifying_key();
    let gate = Gate::anchored(
        Arc::clone(&pin),
        own_key(),
        FileDenylist::empty(PathBuf::new()),
        Ledger(Vec::new()),
    );
    pin.set(Some(identity(PIN).verifying_key()));
    assert_eq!(
        gate.admit(
            proven(device),
            Some(&bound_badge(PIN, device)),
            &service("ssh")
        ),
        Decision::Admit
    );
}

#[test]
fn gate_proven_refuses_an_announced_peer() {
    // An open gate is where a peer that only announced its key is admitted. It proved nothing, so it has no
    // key to witness, and a `Proven` witness minted there would give an announced key a proven one's reach.
    assert!(matches!(
        Gate::Open.proven(proven(some_peer())),
        Err(Refusal::NotGranted)
    ));
}

#[test]
fn a_proven_witness_carries_its_own_origin_on_every_gate_that_mints_one() {
    // No token was presented, so the origin is never `Rooted`: a `Rooted` witness would reach every
    // handler that needs a verified peer, a keyless shell among them.
    for gate in [rooted_gate(1), anchored_gate(Some(PIN), &[])] {
        let witness = gate
            .proven(proven(some_peer()))
            .expect("an unrevoked proven key is witnessed");
        assert_eq!(witness.origin(), Origin::Proven);
        assert_eq!(witness.peer(), some_peer());
    }
}

#[test]
fn a_proven_witness_is_never_a_member() {
    // The kind stays infallible, and fail-closed: a key with no token is no owner device.
    let witness = rooted_gate(1)
        .proven(proven(some_peer()))
        .expect("an unrevoked proven key is witnessed");
    assert_eq!(witness.kind(), Admission::Slip);
    assert!(!witness.is_member());
}

#[test]
fn gate_proven_refuses_a_revoked_peer_key_on_a_rooted_gate() {
    let device = identity(4).verifying_key();
    let gate = Gate::rooted(identity(1).verifying_key(), RevokedKey::new(device));
    assert!(matches!(gate.proven(proven(device)), Err(Refusal::Revoked)));
    let sibling = identity(5).verifying_key();
    assert!(
        gate.proven(proven(sibling)).is_ok(),
        "an unrevoked key is witnessed"
    );
}

#[test]
fn gate_proven_refuses_a_revoked_peer_key_on_an_anchored_gate() {
    let device = identity(4).verifying_key();
    let gate = Gate::anchored(
        FixedPin(Some(identity(PIN).verifying_key())),
        own_key(),
        RevokedKey::new(device),
        Ledger(Vec::new()),
    );
    assert!(matches!(gate.proven(proven(device)), Err(Refusal::Revoked)));
    let sibling = identity(5).verifying_key();
    assert!(
        gate.proven(proven(sibling)).is_ok(),
        "an unrevoked key is witnessed"
    );
}

/// The sign twin of `key`, derived from the encoding rather than the curve: negating an ed25519 point
/// negates its x, which flips only the sign bit its compressed form carries in the top bit of the last byte.
fn sign_twin(key: VerifyKey) -> VerifyKey {
    let mut bytes = *key.bytes();
    bytes[31] ^= 0x80;
    VerifyKey::new(bytes)
}

#[test]
fn gate_proven_refuses_the_sign_twin_of_a_revoked_peer_key() {
    // The holder of a revoked key's secret proves its negation by signing with the negated scalar, so the
    // twin is refused as the key is, on both gates that mint a proven witness.
    let device = identity(4).verifying_key();
    let twin = sign_twin(device);
    assert_ne!(twin, device);
    assert!(
        ed25519_dalek::VerifyingKey::from_bytes(twin.bytes()).is_ok(),
        "the twin is a valid key a transport can prove"
    );
    let rooted = Gate::rooted(identity(1).verifying_key(), RevokedKey::new(device));
    let anchored = Gate::anchored(
        FixedPin(Some(identity(PIN).verifying_key())),
        own_key(),
        RevokedKey::new(device),
        Ledger(Vec::new()),
    );
    for gate in [&rooted, &anchored] {
        assert!(matches!(gate.proven(proven(twin)), Err(Refusal::Revoked)));
        let sibling = identity(5).verifying_key();
        assert!(
            gate.proven(proven(sibling)).is_ok(),
            "an unrevoked key is witnessed"
        );
    }
}

#[test]
fn only_a_rooted_witness_has_a_verified_peer() {
    let gate = rooted_gate(1);
    let rooted = gate
        .admit_witnessed(proven(some_peer()), Some(&slip(1, "ssh")), &service("ssh"))
        .expect("a delegated slip admits its service");
    assert_eq!(rooted.peer_verified(), Some(some_peer()));

    let proven_only = gate
        .proven(proven(some_peer()))
        .expect("an unrevoked proven key is witnessed");
    assert_eq!(
        proven_only.peer_verified(),
        None,
        "a proven key holds no standing"
    );

    let opened = Gate::Open
        .admit_witnessed(proven(some_peer()), None, &service("ssh"))
        .expect("an open gate admits anyone");
    assert_eq!(
        opened.peer_verified(),
        None,
        "an announced key is not verified"
    );
}

#[test]
fn a_proven_witness_names_the_key_a_revocation_cuts() {
    // A proven admission ruled on no token, so its key is all a live cut can find it by. A rooted one is
    // cut by its key too; an open one's key was only announced, so there is nothing to revoke.
    let gate = rooted_gate(1);
    let proven_only = gate
        .proven(proven(some_peer()))
        .expect("an unrevoked proven key is witnessed");
    assert_eq!(proven_only.revocable_peer(), Some(some_peer()));

    let rooted = gate
        .admit_witnessed(proven(some_peer()), Some(&slip(1, "ssh")), &service("ssh"))
        .expect("a delegated slip admits its service");
    assert_eq!(rooted.revocable_peer(), Some(some_peer()));

    let opened = Gate::Open
        .admit_witnessed(proven(some_peer()), None, &service("ssh"))
        .expect("an open gate admits anyone");
    assert_eq!(opened.revocable_peer(), None);
}
