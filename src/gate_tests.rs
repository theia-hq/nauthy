//! Gate policy: the variants and their admit/refuse rulings.

use core::time::Duration;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::VerifyKey;
use crate::cap::{Cap, CapError, Identity, Request};
use crate::disabled_roots::{DisabledRoots, Latch};
use crate::gate::{Admission, Checked, Decision, Gate, Origin, ProvenPeer, Refusal};
use crate::revocations::{FileDenylist, STAT_DEBOUNCE};
use crate::service::Service;

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
