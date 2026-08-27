//! Gate policy: the four variants and their admit/refuse rulings.

use std::collections::HashSet;

use crate::NodeId;
use crate::cap::Identity;
use crate::gate::{Decision, Gate, Refusal};
use crate::service::Service;

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
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
    let gate = Gate::Cap(identity(1));
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
    let gate = Gate::Cap(identity(1));
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
    let gate = Gate::Cap(identity(1));
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
    let gate = Gate::Cap(identity(1));
    assert_eq!(
        gate.admit(some_peer(), Some(&cap), &service("ssh")),
        Decision::Refuse(Refusal::NotGranted)
    );
}
