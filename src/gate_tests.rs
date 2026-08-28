//! Gate policy: the four variants and their admit/refuse rulings.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::NodeId;
use crate::cap::Identity;
use crate::gate::{Decision, Gate, Refusal};
use crate::revocations::Denylist;
use crate::service::Service;

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
}

/// A cap gate with an empty (no-file) revocation denylist, for tests that do not exercise revocation.
fn cap_gate(seed: u8) -> Gate {
    Gate::Cap(identity(seed), Box::new(Denylist::empty(PathBuf::new())))
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
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
    let allowed = HashSet::from([peer]);
    let gate = Gate::Strict(allowed);
    assert_eq!(gate.admit(peer, None, &service("ssh")), Decision::Admit);
    let stranger = identity(3).node_id();
    assert_eq!(
        gate.admit(stranger, None, &service("ssh")),
        Decision::Refuse(Refusal::NotPermitted)
    );
}

#[test]
fn cap_gate_refuses_when_no_cap_is_presented() {
    let gate = cap_gate(1);
    assert_eq!(
        gate.admit(some_peer(), None, &service("ssh")),
        Decision::Refuse(Refusal::Missing)
    );
    assert!(gate.wants_capability());
}

#[test]
fn cap_gate_admits_a_valid_cap_regardless_of_the_dialer() {
    let exposer = identity(1);
    let cap = exposer
        .mint(
            &service("ssh"),
            crate::cap::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint");
    let gate = cap_gate(1);
    // The dialer is a stranger; the token, not the dialer, carries the authority.
    let stranger = identity(7).node_id();
    assert_eq!(
        gate.admit(stranger, Some(&cap), &service("ssh")),
        Decision::Admit
    );
}

#[test]
fn cap_gate_refuses_a_wrong_service_cap() {
    let exposer = identity(1);
    let cap = exposer
        .mint(
            &service("ssh"),
            crate::cap::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint");
    let gate = cap_gate(1);
    assert_eq!(
        gate.admit(some_peer(), Some(&cap), &service("web")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[test]
fn cap_gate_refuses_a_foreign_rooted_cap() {
    let other = identity(2);
    let cap = other
        .mint(
            &service("ssh"),
            crate::cap::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint");
    let gate = cap_gate(1);
    assert_eq!(
        gate.admit(some_peer(), Some(&cap), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}

#[tokio::test]
async fn a_revoked_cap_and_its_delegations_are_refused_across_a_reload() {
    let exposer = identity(1);
    let hour = || crate::cap::expires_in(core::time::Duration::from_secs(3600));
    let cap = exposer.mint(&service("ssh"), hour()).expect("mint");
    // A third party narrows and re-shares the same grant: a delegation carrying the same root block.
    let delegated = cap
        .attenuate(Some(&service("ssh")), None)
        .expect("attenuate");

    let path = std::env::temp_dir().join(format!("nauthy-revoke-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let mut denylist = Denylist::load(path.clone()).await.expect("load");
        denylist.revoke(&cap).await.expect("revoke");
    }
    // Reload from disk: revocation must survive a restart, which a bare TTL cannot give.
    let denylist = Denylist::load(path.clone()).await.expect("reload");
    let gate = Gate::Cap(identity(1), Box::new(denylist));

    assert_eq!(
        gate.admit(some_peer(), Some(&cap), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // The delegation carries the revoked root block, so it is refused too.
    assert_eq!(
        gate.admit(some_peer(), Some(&delegated), &service("ssh")),
        Decision::Refuse(Refusal::Revoked)
    );
    // A different, unrevoked grant from the same identity is still admitted.
    let other = exposer
        .mint(
            &service("ssh"),
            crate::cap::expires_in(core::time::Duration::from_secs(7200)),
        )
        .expect("mint");
    assert_eq!(
        gate.admit(some_peer(), Some(&other), &service("ssh")),
        Decision::Admit
    );
    let _ = std::fs::remove_file(&path);
}
