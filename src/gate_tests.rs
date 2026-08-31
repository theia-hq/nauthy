//! Gate policy: the three variants and their admit/refuse rulings.

use core::time::Duration;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::VerifyKey;
use crate::cap::{Cap, Identity, expires_in};
use crate::gate::{Decision, Gate, Refusal};
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
        gate.admit(some_peer(), None, &service("ssh")),
        Decision::Admit
    );
    assert!(!gate.wants_capability());
}

#[test]
fn family_refuses_when_no_token_is_presented() {
    let gate = family_gate(1);
    assert_eq!(
        gate.admit(some_peer(), None, &service("ssh")),
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
        gate.admit(device, Some(&badge), &service("ssh")),
        Decision::Admit,
        "the bound device is admitted whole-node"
    );
    let stranger = identity(7).node_id();
    assert_eq!(
        gate.admit(stranger, Some(&badge), &service("ssh")),
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
        gate.admit(some_peer(), Some(&ssh), &service("ssh")),
        Decision::Admit
    );
    assert_eq!(
        gate.admit(some_peer(), Some(&ssh), &service("web")),
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
            &service("ssh")
        ),
        Decision::Refuse(Refusal::NotGranted)
    );
    assert_eq!(
        gate.admit(some_peer(), Some(&slip(2, "ssh")), &service("ssh")),
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
        gate.admit(some_peer(), Some(&granted), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // The delegation carries the revoked root block, so it is refused too.
    assert_eq!(
        gate.admit(some_peer(), Some(&delegated), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // A different, unrevoked grant from the same signet is still admitted.
    let other = signet.mint(&service("ssh"), hour()).expect("mint");
    assert_eq!(
        gate.admit(some_peer(), Some(&other), &service("ssh")),
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
        gate.admit(some_peer(), Some(&owned), &service("ssh")),
        Decision::Admit
    );
    let stranger = identity(6).mint(&service("ssh"), hour()).expect("mint");
    assert_eq!(
        gate.admit(some_peer(), Some(&stranger), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn revocation_goes_live_without_reconstructing_the_denylist() {
    // Blocker 3: a long-running exposer holds ONE Denylist; a `tightbeam revoke` in a SEPARATE process
    // writes the revoked id to the file. The running gate must honor it on the next check, not at the next
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
