//! Gate policy: the three variants and their admit/refuse rulings.

use core::time::Duration;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::VerifyKey;
use crate::cap::{Cap, Identity, expires_in};
use crate::gate::{Admission, Decision, Gate, Refusal};
use crate::revocations::Denylist;
use crate::service::Service;

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
}

/// A family gate trusting `seed`'s signet, with an empty (no-file) revocation denylist.
fn family_gate(seed: u8) -> Gate {
    Gate::family(identity(seed).node_id(), Denylist::empty(PathBuf::new()))
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

fn hour() -> SystemTime {
    expires_in(Duration::from_secs(3600))
}

/// A device-bound membership badge minted by `seed`'s signet for `device` (see `Identity::mint_member`).
fn bound_badge(seed: u8, device: VerifyKey) -> Cap {
    identity(seed)
        .mint_member(device, hour())
        .expect("mint bound badge")
}

/// A delegated slip minted by `seed`'s signet for `svc`.
fn slip(seed: u8, svc: &str) -> Cap {
    identity(seed)
        .mint(&service(svc), hour())
        .expect("mint slip")
}

fn some_peer() -> VerifyKey {
    identity(9).node_id()
}

#[test]
fn open_admits_anyone() {
    let gate = Gate::Open;
    assert_eq!(
        gate.admit(some_peer(), None, None, &service("ssh")),
        Decision::Admit
    );
    assert!(!gate.wants_capability());
}

#[test]
fn family_refuses_when_no_token_is_presented() {
    let gate = family_gate(1);
    assert_eq!(
        gate.admit(some_peer(), None, None, &service("ssh")),
        Decision::Refuse(Refusal::Missing)
    );
    assert!(gate.wants_capability());
}

#[test]
fn family_admits_a_bound_badge_only_from_its_device() {
    // A device-bound badge (mint_member) is non-transferable: the family gate admits it whole-node ONLY when
    // the proven dialer is the bound device. The same badge presented by any other key is refused, so a
    // leaked badge blob is useless without the matching device secret. This is the production admit() path
    // (peer threaded through), not just verify().
    let gate = family_gate(1);
    let device = identity(4).node_id();
    let badge = bound_badge(1, device);

    assert_eq!(
        gate.admit(device, Some(&badge), None, &service("ssh")),
        Decision::Admit,
        "the bound device is admitted whole-node"
    );
    let stranger = identity(7).node_id();
    assert_eq!(
        gate.admit(stranger, Some(&badge), None, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "the same badge from a foreign dialer is refused"
    );
}

#[test]
fn family_admits_a_delegated_slip_only_for_its_service() {
    // A friend carries a slip for ssh: admitted for ssh, refused for a service the slip does not grant.
    // Membership (whole-node) and delegation (one service) are the two meanings of one signature.
    let gate = family_gate(1);
    let ssh = slip(1, "ssh");
    assert_eq!(
        gate.admit(some_peer(), Some(&ssh), None, &service("ssh")),
        Decision::Admit
    );
    assert_eq!(
        gate.admit(some_peer(), Some(&ssh), None, &service("web")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn family_refuses_a_token_from_a_foreign_signet() {
    // A badge or slip minted by a different signet is refused: the gate trusts exactly one key.
    let gate = family_gate(1);
    assert_eq!(
        gate.admit(
            some_peer(),
            Some(&bound_badge(2, some_peer())),
            None,
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert_eq!(
        gate.admit(some_peer(), Some(&slip(2, "ssh")), None, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn a_revoked_token_and_its_delegations_are_refused_across_a_reload() {
    let signet = identity(1);
    let granted = signet.mint(&service("ssh"), hour()).expect("mint");
    // A third party narrows and re-shares the same grant: a delegation carrying the same root block.
    let delegated = granted
        .attenuate(Some(&service("ssh")), None)
        .expect("attenuate");

    let path = std::env::temp_dir().join(format!("nauthy-revoke-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let mut denylist = Denylist::load(path.clone()).await.expect("load");
        denylist.revoke(&granted).await.expect("revoke");
    }
    // Reload from disk: revocation must survive a restart, which a bare TTL cannot give.
    let denylist = Denylist::load(path.clone()).await.expect("reload");
    let gate = Gate::Family(signet.node_id(), Box::new(denylist));

    assert_eq!(
        gate.admit(some_peer(), Some(&granted), None, &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // The delegation carries the revoked root block, so it is refused too.
    assert_eq!(
        gate.admit(some_peer(), Some(&delegated), None, &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // A different, unrevoked grant from the same signet is still admitted.
    let other = signet.mint(&service("ssh"), hour()).expect("mint");
    assert_eq!(
        gate.admit(some_peer(), Some(&other), None, &service("ssh")),
        Decision::Admit
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn family_can_trust_a_foreign_signet_the_ci_model() {
    // A CI runner is provisioned to trust the OWNER's signet: it admits tokens rooted at that key without
    // ever holding its secret, so a compromised runner can mint no access. The owner's device badge is
    // admitted; a stranger's token is refused.
    let owner = identity(5);
    let gate = Gate::Family(owner.node_id(), Box::new(Denylist::empty(PathBuf::new())));
    let owned = owner.mint_member(some_peer(), hour()).expect("mint");
    assert_eq!(
        gate.admit(some_peer(), Some(&owned), None, &service("ssh")),
        Decision::Admit
    );
    let stranger = identity(6).mint(&service("ssh"), hour()).expect("mint");
    assert_eq!(
        gate.admit(some_peer(), Some(&stranger), None, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn revocation_goes_live_without_reconstructing_the_denylist() {
    // Blocker 3: a long-running exposer holds ONE Denylist; a revocation in a SEPARATE process writes the
    // revoked id to the file. The running gate must honor it on the next check, not at the next
    // restart. Here the same live Denylist -- never reloaded or reconstructed -- refuses a cap after a
    // separate handle revokes it, because is_revoked re-reads the file when its mtime changed.
    let signet = identity(1);
    let granted = signet.mint(&service("ssh"), hour()).expect("mint");
    let path = std::env::temp_dir().join(format!("nauthy-live-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);

    // The running exposer's denylist: loaded once, empty (file absent).
    let live = Denylist::load(path.clone()).await.expect("load");
    assert!(!live.is_revoked(&granted), "unrevoked at first");

    // A separate process revokes the cap by writing the file.
    {
        let mut revoker = Denylist::load(path.clone()).await.expect("load");
        revoker.revoke(&granted).await.expect("revoke");
    }

    // Without any reload/reconstruction, the running denylist now refuses it -- live revocation.
    assert!(
        live.is_revoked(&granted),
        "revocation must go live without a restart"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_deleted_denylist_file_does_not_un_revoke() {
    // Fail closed: deleting the backing file is NOT "the denylist is empty". A running exposer that revoked
    // a cap must keep refusing it even if the file disappears (a botched cleanup, or a local attacker who
    // `rm`s it to un-revoke a lost device). The last-known set stands until a real file replaces it.
    let signet = identity(1);
    let granted = signet.mint(&service("ssh"), hour()).expect("mint");
    let path = std::env::temp_dir().join(format!("nauthy-delete-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut live = Denylist::load(path.clone()).await.expect("load");
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

// The signet-bound admit matrix (delib-42): work (`family_gate(1)`) issues a slip bound to the hire's fleet
// `X` (`identity(2)`). The hire's device (`identity(4)`) proves membership under `X` with a badge `X` signed,
// bound to that device. The gate admits ONLY when the slip AND a valid badge under `X` (bound to the proven
// dialer) are both present, the two-token AND.

/// Work's slip for `svc`, bound to the fleet of `fleet_seed`'s signet.
fn signet_slip(fleet_seed: u8, svc: &str) -> Cap {
    identity(1)
        .mint_signet_slip(&service(svc), identity(fleet_seed).node_id(), hour())
        .expect("mint signet slip")
}

/// A membership badge minted by `fleet_seed`'s signet for `device`: the hire's own device badge under their
/// fleet. Bound to `device`, so only the proven dialer that IS `device` may present it.
fn foreign_badge(fleet_seed: u8, device: VerifyKey) -> Cap {
    identity(fleet_seed)
        .mint_member(device, hour())
        .expect("mint foreign badge")
}

#[test]
fn signet_slip_with_a_valid_foreign_badge_admits_as_a_slip() {
    // The acceptance case: slot 1 = the signet-bound slip (work signed, naming fleet `X`), slot 2 = the
    // hire device's badge under `X`, bound to the proven dialer. Both leaves hold, so the AND admits. The
    // admission is `Slip`, NEVER `Member`: a foreign fleet's member is not a whole-node member of THIS node.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let slip = signet_slip(2, "ssh");
    let badge = foreign_badge(2, hire_device);
    assert_eq!(
        gate.admit(hire_device, Some(&slip), Some(&badge), &service("ssh")),
        Decision::Admit,
        "slip + valid badge under X, bound to the proven dialer, admits"
    );
    let admitted = gate
        .admit_witnessed(hire_device, Some(&slip), Some(&badge), &service("ssh"))
        .expect("witnessed admission");
    assert_eq!(
        admitted.kind(),
        Admission::Slip,
        "a foreign-fleet admission is a Slip, never a whole-node Member"
    );
    assert!(
        !admitted.is_member(),
        "a foreign member is not a whole-node member"
    );
}

#[test]
fn a_signet_slip_alone_is_refused() {
    // Slot 2 empty: the slip is inert on the plain path (its fleet_member check is unsatisfied) and the
    // signet-bound arm has no badge to verify, so `member_under_x` is false. No badge, no admission.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let slip = signet_slip(2, "ssh");
    assert_eq!(
        gate.admit(hire_device, Some(&slip), None, &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "a signet slip with no membership badge is refused"
    );
}

#[test]
fn a_foreign_badge_alone_is_refused_as_missing() {
    // Slot 1 empty: no grant presented at all. The gate refuses `Missing` before it ever looks at slot 2, so
    // a badge under `X` with no slip cannot admit (a foreign member is not a member of THIS node).
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let badge = foreign_badge(2, hire_device);
    assert_eq!(
        gate.admit(hire_device, None, Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::Missing),
        "a foreign badge with no slip in slot 1 is Missing"
    );
}

#[test]
fn a_signet_slip_with_a_wrong_root_badge_is_refused() {
    // The badge's root is checked AGAINST the `X` the SLIP names (never a badge-supplied root): a badge
    // under a different fleet `Y` fails `verify_member_at_root`'s ForeignRoot, so `member_under_x` is false.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let slip = signet_slip(2, "ssh"); // bound to fleet X = identity(2)
    let wrong_badge = foreign_badge(3, hire_device); // badge under fleet Y = identity(3)
    assert_eq!(
        gate.admit(
            hire_device,
            Some(&slip),
            Some(&wrong_badge),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted),
        "a badge under the wrong fleet cannot satisfy the AND"
    );
}

#[test]
fn a_signet_slip_with_a_badge_for_another_device_is_refused() {
    // The badge under `X` is bound to a DIFFERENT device than the proven dialer, so its bound_device check
    // fails: a stolen slip+badge replayed from another key never admits.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let other_device = identity(8).node_id();
    let slip = signet_slip(2, "ssh");
    let badge_for_other = foreign_badge(2, other_device);
    assert_eq!(
        gate.admit(
            hire_device,
            Some(&slip),
            Some(&badge_for_other),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted),
        "a badge bound to a different device than the proven dialer is refused"
    );
}

#[test]
fn a_signet_slip_for_the_wrong_service_is_refused() {
    // The slip grants `web`, but the dial is for `ssh`: the slip's service check fails inside
    // verify_signet_bound_at_root, so it never names its fleet and the AND cannot even begin.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let slip = signet_slip(2, "web");
    let badge = foreign_badge(2, hire_device);
    assert_eq!(
        gate.admit(hire_device, Some(&slip), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted),
        "a signet slip for the wrong service is refused even with a valid badge"
    );
}

#[test]
fn a_signet_slip_with_an_expired_badge_is_refused() {
    // The slot-2 badge under `X` is expired at wall-clock now, so its expiry check fails and the AND cannot
    // hold, even though the slip and the fleet root are correct.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let slip = signet_slip(2, "ssh");
    let expired_badge = identity(2)
        .mint_member(hire_device, SystemTime::UNIX_EPOCH)
        .expect("mint an already-expired badge");
    assert_eq!(
        gate.admit(
            hire_device,
            Some(&slip),
            Some(&expired_badge),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted),
        "an expired fleet badge cannot satisfy the signet-bound AND"
    );
}

#[test]
fn a_signet_slip_with_a_non_member_cap_in_slot_two_is_refused() {
    // Slot 2 is a plain service slip under `X`, NOT a membership badge (no `member(true)` fact), so
    // verify_member_at_root refuses it: only a real fleet membership badge proves membership.
    let gate = family_gate(1);
    let hire_device = identity(4).node_id();
    let slip = signet_slip(2, "ssh");
    let not_a_badge = identity(2)
        .mint(&service("ssh"), hour())
        .expect("mint a plain slip under X");
    assert_eq!(
        gate.admit(
            hire_device,
            Some(&slip),
            Some(&not_a_badge),
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted),
        "a non-membership cap in slot 2 cannot satisfy the signet-bound AND"
    );
}

#[tokio::test]
async fn a_revoked_signet_slip_is_refused_even_with_a_valid_badge() {
    // Revoke-the-slip kills the WHOLE fleet's access: record the slip's root revocation id in work's
    // denylist, and the signet-bound arm refuses `Revoked` even though the badge under `X` still verifies.
    // The badge (rooted at `X`) is NOT work's to revoke; revoking the slip is how work cuts the person off.
    let work = identity(1);
    let hire_device = identity(4).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), identity(2).node_id(), hour())
        .expect("mint signet slip");
    let badge = foreign_badge(2, hire_device);

    let path = std::env::temp_dir().join(format!("nauthy-signet-revoke-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut denylist = Denylist::load(path.clone()).await.expect("load");
    denylist.revoke(&slip).await.expect("revoke the slip");
    let gate = Gate::Family(work.node_id(), Box::new(denylist));

    assert_eq!(
        gate.admit(hire_device, Some(&slip), Some(&badge), &service("ssh")),
        Decision::Refuse(Refusal::Revoked),
        "a revoked signet slip is refused even when the fleet badge still verifies"
    );
    let _ = std::fs::remove_file(&path);
}
