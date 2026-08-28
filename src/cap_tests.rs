//! The capability ACL matrix: mint, attenuate, delegate, expire, wrong-service, and the load-bearing
//! proof that broadening is impossible by construction.

use core::time::Duration;
use std::time::SystemTime;

use crate::cap::{Cap, CapError, Identity, Request};
use crate::service::Service;

/// A deterministic identity for tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("32-byte secret is a valid ed25519 key")
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

fn at(offset_secs: i64) -> SystemTime {
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    if offset_secs >= 0 {
        base + Duration::from_secs(offset_secs as u64)
    } else {
        base - Duration::from_secs(offset_secs.unsigned_abs())
    }
}

fn request(name: &str, now_secs: i64) -> Request {
    Request {
        service: service(name),
        now: at(now_secs),
    }
}

#[test]
fn minted_cap_grants_its_service_before_expiry() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    assert!(exposer.verify(&cap, &request("ssh", 0)).is_ok());
}

#[test]
fn minted_cap_denies_a_different_service() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    let denied = exposer.verify(&cap, &request("web", 0));
    assert!(matches!(denied, Err(CapError::Denied(_))));
}

#[test]
fn expired_cap_is_denied() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    let denied = exposer.verify(&cap, &request("ssh", 7200));
    assert!(matches!(denied, Err(CapError::Denied(_))));
}

#[test]
fn cap_does_not_verify_against_a_different_identity() {
    let exposer = identity(1);
    let other = identity(2);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    let foreign = other.verify(&cap, &request("ssh", 0));
    assert!(matches!(foreign, Err(CapError::ForeignRoot)));
}

#[test]
fn the_membership_constant_is_a_valid_service_name() {
    // membership() builds the Service directly from the constant; pin that the constant parses so the
    // infallible constructor can never yield a malformed service name.
    let parsed: Service = Service::MEMBERSHIP
        .parse()
        .expect("membership name is valid");
    assert_eq!(parsed, Service::membership());
    assert_eq!(Service::membership().as_str(), "theia:member");
}

#[test]
fn a_membership_badge_is_a_cap_for_the_reserved_service() {
    // A membership badge is a cap minted for the reserved `theia:member` service: the signet stamps a
    // device as its own. It verifies AS membership (a family gate honors that as whole-node admission), but
    // is not itself a grant to any named service -- membership is a distinct claim from a delegated cap.
    let signet = identity(1);
    let badge = signet
        .mint(&Service::membership(), at(3600))
        .expect("mint membership badge");
    assert!(
        signet.verify(&badge, &request("theia:member", 0)).is_ok(),
        "a badge grants the membership service"
    );
    assert!(
        matches!(
            signet.verify(&badge, &request("ssh", 0)),
            Err(CapError::Denied(_))
        ),
        "a membership badge is not itself an ssh grant"
    );
}

#[test]
fn a_link_round_trips_and_carries_the_root() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    let link = cap.link().expect("encode");
    assert!(link.starts_with("sheer:"));
    let parsed = Cap::parse(&link).expect("parse");
    assert_eq!(parsed.root(), exposer.node_id());
    assert!(exposer.verify(&parsed, &request("ssh", 0)).is_ok());
}

#[test]
fn a_tampered_link_is_rejected() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    let link = cap.link().expect("encode");
    // Flip a character in the token body; the signature chain must no longer check against the root.
    let mut chars: Vec<char> = link.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    let tampered: String = chars.into_iter().collect();
    assert!(matches!(
        Cap::parse(&tampered),
        Err(CapError::Malformed | CapError::Encoding)
    ));
}

#[test]
fn attenuation_narrows_expiry_and_is_enforced() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    // Holder narrows the hour down to a minute, offline, with no secret.
    let tighter = cap.attenuate(None, Some(at(60))).expect("attenuate");
    // Still valid within the shorter window.
    assert!(exposer.verify(&tighter, &request("ssh", 30)).is_ok());
    // Denied past the shorter window even though the original hour has not elapsed.
    let denied = exposer.verify(&tighter, &request("ssh", 120));
    assert!(matches!(denied, Err(CapError::Denied(_))));
}

#[test]
fn attenuation_narrows_service_and_is_enforced() {
    let exposer = identity(1);
    // Mint a cap unpinned to a service by granting a wildcard-wide window: mint pins a service, so to
    // test service-narrowing we mint for "ssh" and narrow to "ssh" (a no-op narrow that still verifies),
    // then prove a narrow to a DIFFERENT service makes the original service unreachable.
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    let to_web = cap
        .attenuate(Some(&service("web")), None)
        .expect("attenuate");
    // The added `service == web` check plus the minted `service == ssh` check can never both hold, so no
    // request is grantable: neither ssh (fails the web check) nor web (fails the ssh check).
    assert!(exposer.verify(&to_web, &request("ssh", 0)).is_err());
    assert!(exposer.verify(&to_web, &request("web", 0)).is_err());
}

#[test]
fn a_third_party_delegates_a_narrowed_cap_without_the_exposer() {
    let exposer = identity(1);
    // Exposer mints and hands off a link; from here the exposer never participates.
    let link = exposer
        .mint(&service("ssh"), at(3600))
        .expect("mint")
        .link()
        .expect("encode");

    // Holder parses, narrows the expiry, re-links, hands to a third party.
    let holder_cap = Cap::parse(&link).expect("holder parse");
    let handed = holder_cap
        .attenuate(None, Some(at(600)))
        .expect("holder narrows")
        .link()
        .expect("holder re-encodes");

    // Third party parses the handed link and uses it directly. No exposer in the loop for any of this.
    let third_party_cap = Cap::parse(&handed).expect("third-party parse");

    // Exposer, seeing the token for the first time at connect, verifies the whole chain offline.
    assert!(
        exposer
            .verify(&third_party_cap, &request("ssh", 60))
            .is_ok()
    );
    // And the third party's narrower expiry binds them too.
    assert!(
        exposer
            .verify(&third_party_cap, &request("ssh", 700))
            .is_err()
    );
}

#[test]
fn broadening_is_impossible_by_construction() {
    let exposer = identity(1);
    // A cap narrowed to a minute cannot be re-widened back to the original hour: appending a looser
    // expiry only ADDS a check, and the minute check still trips past 60s.
    let minute = exposer
        .mint(&service("ssh"), at(3600))
        .expect("mint")
        .attenuate(None, Some(at(60)))
        .expect("narrow to a minute");
    let attempt_widen = minute
        .attenuate(None, Some(at(3600)))
        .expect("append a looser expiry");
    // Past the minute but within the hour: still denied, because the minute check remains in the chain.
    let denied = exposer.verify(&attempt_widen, &request("ssh", 120));
    assert!(matches!(denied, Err(CapError::Denied(_))));
}

#[test]
fn attenuating_nothing_is_an_error() {
    let exposer = identity(1);
    let cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    assert!(matches!(
        cap.attenuate(None, None),
        Err(CapError::EmptyAttenuation)
    ));
}

#[test]
fn a_sealed_cap_verifies_but_cannot_be_attenuated() {
    let exposer = identity(1);
    let sealed = exposer
        .mint(&service("ssh"), at(3600))
        .expect("mint")
        .seal()
        .expect("seal");
    // A sealed cap still grants normally.
    assert!(exposer.verify(&sealed, &request("ssh", 0)).is_ok());
    // But it cannot be narrowed and handed onward: delegation is refused by construction.
    assert!(matches!(
        sealed.attenuate(None, Some(at(60))),
        Err(CapError::Attenuate(_))
    ));
}

#[test]
fn a_non_sheer_link_is_rejected() {
    assert!(matches!(
        Cap::parse("https://example.com"),
        Err(CapError::Scheme)
    ));
}
