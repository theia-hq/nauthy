//! Gate policy: the three variants and their admit/refuse rulings.

use core::time::Duration;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::NodeId;
use crate::cap::{Cap, Identity, expires_in};
use crate::gate::{Decision, Gate, Refusal};
use crate::revocations::Denylist;
use crate::service::Service;

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
}

/// A family gate trusting `seed`'s signet, with an empty (no-file) revocation denylist.
fn family_gate(seed: u8) -> Gate {
    Gate::Family(
        identity(seed).node_id(),
        Box::new(Denylist::empty(PathBuf::new())),
    )
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

fn hour() -> SystemTime {
    expires_in(Duration::from_secs(3600))
}

/// A membership badge minted by `seed`'s signet: a cap granting the reserved membership service.
fn badge(seed: u8) -> Cap {
    identity(seed)
        .mint(&Service::membership(), hour())
        .expect("mint badge")
}

/// A delegated slip minted by `seed`'s signet for `svc`.
fn slip(seed: u8, svc: &str) -> Cap {
    identity(seed)
        .mint(&service(svc), hour())
        .expect("mint slip")
}

fn some_peer() -> NodeId {
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
fn strict_admits_only_the_allowlist() {
    let peer = some_peer();
    let gate = Gate::Strict(HashSet::from([peer]));
    assert_eq!(gate.admit(peer, None, &service("ssh")), Decision::Admit);
    let stranger = identity(3).node_id();
    assert_eq!(
        gate.admit(stranger, None, &service("ssh")),
        Decision::Refuse(Refusal::NotPermitted)
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
fn family_admits_a_membership_badge_to_any_service_regardless_of_dialer() {
    // A device presents its badge and is admitted whole-node (any service asked). The dialer's own key is
    // irrelevant: the token, not who carries it, is the authority.
    let gate = family_gate(1);
    let badge = badge(1);
    let stranger = identity(7).node_id();
    assert_eq!(
        gate.admit(stranger, Some(&badge), &service("ssh")),
        Decision::Admit
    );
    assert_eq!(
        gate.admit(stranger, Some(&badge), &service("web")),
        Decision::Admit
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
        gate.admit(some_peer(), Some(&badge(2)), &service("ssh")),
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
    let owned = owner.mint(&Service::membership(), hour()).expect("mint");
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
