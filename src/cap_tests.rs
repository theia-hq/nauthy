//! The capability ACL matrix: mint, attenuate, delegate, expire, wrong-service, and the load-bearing
//! proof that broadening is impossible by construction.

use core::time::Duration;
use std::time::SystemTime;

use crate::VerifyKey;
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
        bound_device: None,
    }
}

/// A request carrying the proven dialer, for verifying device-bound membership badges.
fn bound_request(name: &str, now_secs: i64, peer: VerifyKey) -> Request {
    request(name, now_secs).bound_to(peer)
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
fn a_bound_membership_badge_admits_only_its_device() {
    // mint_member stamps a device as the signet's own: a `member(true)` authority fact, bound to the
    // device. The membership question grants when the proven dialer IS that device, and no one else -- a
    // badge replayed from a different key verifies against no one, non-transferable by construction.
    let signet = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let stranger: VerifyKey = identity(3).node_id();
    let badge = signet
        .mint_member(device, at(3600))
        .expect("mint bound badge");

    assert!(
        badge
            .verify_member_at_root(at(0), device, signet.node_id())
            .is_ok(),
        "the bound device's badge grants membership"
    );
    assert!(
        matches!(
            badge.verify_member_at_root(at(0), stranger, signet.node_id()),
            Err(CapError::Denied(_))
        ),
        "a bound badge does not grant a foreign device"
    );
}

#[test]
fn a_service_slip_is_not_membership() {
    // A delegated service slip carries a service check, NOT the `member(true)` authority fact, so the
    // membership question refuses it: a friend's ssh slip can never read as whole-node admission.
    let signet = identity(1);
    let peer: VerifyKey = identity(4).node_id();
    let slip = signet.mint(&service("ssh"), at(3600)).expect("mint slip");
    assert!(
        matches!(
            slip.verify_member_at_root(at(0), peer, signet.node_id()),
            Err(CapError::Denied(_))
        ),
        "a service slip must not grant membership"
    );
}

#[test]
fn an_appended_member_fact_does_not_grant_membership() {
    // The origin wall -- the load-bearing proof. `mint_forged_member` builds a badge whose authority block
    // has the SAME device-binding + expiry as a real one, but asserts `member(true)` in an ATTENUATION
    // block. The only variable is the fact's origin. The gate refuses the forged badge (appended fact is
    // untrusted, so `allow if member(true)` never sees it) yet admits the real one -- so membership is
    // unforgeable by a delegated holder, enforced by biscuit's origin trust, not by our prose.
    let signet = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let forged = signet
        .mint_forged_member(device, at(3600))
        .expect("forge a member fact in an attenuation block");
    assert!(
        matches!(
            forged.verify_member_at_root(at(0), device, signet.node_id()),
            Err(CapError::Denied(_))
        ),
        "member(true) in an attenuation block must not grant -- origin wall"
    );
    // Same shape, same device, `member(true)` in the AUTHORITY block: this DOES grant. Isolates origin as
    // the sole cause of the refusal above.
    let real = signet
        .mint_member(device, at(3600))
        .expect("mint real badge");
    assert!(
        real.verify_member_at_root(at(0), device, signet.node_id())
            .is_ok()
    );
}

#[test]
fn an_unbound_cap_ignores_the_bound_device_fact() {
    // A plain slip carries no binding block, so injecting a bound_device fact is monotone and cannot change
    // its grant: an ordinary ssh slip still grants regardless of which dialer presents it.
    let exposer = identity(1);
    let anyone: VerifyKey = identity(9).node_id();
    let slip = exposer.mint(&service("ssh"), at(3600)).expect("mint slip");
    assert!(
        exposer
            .verify(&slip, &bound_request("ssh", 0, anyone))
            .is_ok()
    );
}

#[test]
fn a_device_bound_slip_admits_only_its_device() {
    // A device-bound SERVICE slip grants its service to the proven bound device and to no one else: a copy
    // replayed from a different key verifies against no one. Standing per-service access that cannot be
    // stolen -- distinct from an unbound slip, which any presenter may use.
    let exposer = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let stranger: VerifyKey = identity(3).node_id();
    let slip = exposer
        .mint_bound(&service("ssh"), device, at(3600))
        .expect("mint bound slip");

    assert!(
        exposer
            .verify(&slip, &bound_request("ssh", 0, device))
            .is_ok(),
        "the bound device reaches the service"
    );
    assert!(
        matches!(
            exposer.verify(&slip, &bound_request("ssh", 0, stranger)),
            Err(CapError::Denied(_))
        ),
        "a stranger presenting a stolen copy is refused"
    );
    // The service check still binds: the bound device cannot use the slip for a different service.
    assert!(
        matches!(
            exposer.verify(&slip, &bound_request("web", 0, device)),
            Err(CapError::Denied(_))
        ),
        "the slip stays pinned to its service"
    );
}

#[test]
fn a_device_bound_slip_denies_when_no_dialer_is_proven() {
    // Presented with no proven dialer (no bound_device fact injected), the binding check cannot be
    // satisfied, so the slip grants nothing: the binding FAILS CLOSED, it never degrades to an unbound slip.
    let exposer = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let slip = exposer
        .mint_bound(&service("ssh"), device, at(3600))
        .expect("mint bound slip");
    assert!(
        matches!(
            exposer.verify(&slip, &request("ssh", 0)),
            Err(CapError::Denied(_))
        ),
        "a bound slip with no proven dialer is denied"
    );
}

#[test]
fn a_device_bound_slip_is_not_membership() {
    // Like any service slip, a device-bound slip names a service, not the `member(true)` authority fact, so
    // the membership question refuses it: per-service access never reads as whole-node admission, even bound.
    let exposer = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let slip = exposer
        .mint_bound(&service("ssh"), device, at(3600))
        .expect("mint bound slip");
    assert!(
        matches!(
            slip.verify_member_at_root(at(0), device, exposer.node_id()),
            Err(CapError::Denied(_))
        ),
        "a device-bound service slip must not grant membership"
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

#[test]
fn an_oversized_link_is_refused_before_decoding() {
    // A body past the size bound is rejected before the base32 decode + signature verification, so an
    // untrusted peer cannot force that work with a huge link (the availability DoS the red-team found).
    let root = identity(1).node_id();
    let huge = format!("sheer:{root}.{}", "a".repeat(20_000));
    assert!(matches!(Cap::parse(&huge), Err(CapError::TooLarge)));
}

#[test]
fn a_signet_slip_names_its_fleet_for_the_right_service_unexpired() {
    // mint_signet_slip binds a slip to a whole FLEET `X` (the hire's signet). verify_signet_bound_at_root
    // returns that pinned `X` when the service matches and the slip is unexpired: the fleet the gate must
    // then check a badge under.
    let work = identity(1);
    let hire_signet: VerifyKey = identity(2).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), hire_signet, at(3600))
        .expect("mint signet slip");
    let extracted = slip
        .verify_signet_bound_at_root(&request("ssh", 0), work.node_id())
        .expect("a valid signet slip names its fleet");
    assert_eq!(
        extracted, hire_signet,
        "the returned fleet is the one the authority block pinned"
    );
}

#[test]
fn signet_bound_fleet_reads_the_pinned_fleet_offline() {
    // The dialer-side, root-free extractor: a signet slip reads back its pinned fleet `X` with no root or
    // request, while a plain slip and a membership badge (no `signet_bound` fact) read `None`. This is what
    // lets a dialer attach its fleet badge (slot 2) ONLY when the slip pins the fleet it is a member of.
    let work = identity(1);
    let hire_signet: VerifyKey = identity(2).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), hire_signet, at(3600))
        .expect("mint signet slip");
    assert_eq!(
        slip.signet_bound_fleet().expect("reads the pinned fleet"),
        Some(hire_signet),
        "a signet slip reads back the exact fleet its authority block pinned"
    );

    let plain = work
        .mint(&service("ssh"), at(3600))
        .expect("mint a plain slip");
    assert_eq!(
        plain.signet_bound_fleet().expect("reads no pinned fleet"),
        None,
        "a plain slip pins no fleet, so the dialer attaches no fleet badge"
    );
}

#[test]
fn a_signet_slip_is_inert_on_the_plain_path() {
    // The load-bearing "slip alone denies" guard: a signet-bound slip carries an extra
    // `check if signet_bound($x), fleet_member($x)` that NO plain verification injects, so verify_at_root
    // (the gate's plain path) can never satisfy it. Without this, a signet slip would admit with no badge.
    let work = identity(1);
    let hire_signet: VerifyKey = identity(2).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), hire_signet, at(3600))
        .expect("mint signet slip");
    assert!(
        work.verify(&slip, &request("ssh", 0)).is_err(),
        "a signet slip must grant nothing on the plain verify path (inert alone)"
    );
}

#[test]
fn a_signet_slip_is_denied_for_the_wrong_service_or_when_expired() {
    let work = identity(1);
    let hire_signet: VerifyKey = identity(2).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), hire_signet, at(3600))
        .expect("mint signet slip");
    assert!(
        matches!(
            slip.verify_signet_bound_at_root(&request("web", 0), work.node_id()),
            Err(CapError::Denied(_))
        ),
        "a signet slip refuses the wrong service"
    );
    assert!(
        matches!(
            slip.verify_signet_bound_at_root(&request("ssh", 7200), work.node_id()),
            Err(CapError::Denied(_))
        ),
        "an expired signet slip is denied"
    );
}

#[test]
fn verify_signet_bound_rejects_a_foreign_root() {
    let work = identity(1);
    let other = identity(5);
    let hire_signet: VerifyKey = identity(2).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), hire_signet, at(3600))
        .expect("mint signet slip");
    assert!(
        matches!(
            slip.verify_signet_bound_at_root(&request("ssh", 0), other.node_id()),
            Err(CapError::ForeignRoot)
        ),
        "a signet slip rooted at work does not verify against another root"
    );
}

#[test]
fn a_plain_cap_is_not_a_signet_slip() {
    // A plain slip, a device-bound slip, and a membership badge carry no `signet_bound` fact, so the
    // detector returns NotSignetBound for each: this method is the sole detector of the signet-bound kind.
    let work = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let plain = work.mint(&service("ssh"), at(3600)).expect("mint plain");
    let bound = work
        .mint_bound(&service("ssh"), device, at(3600))
        .expect("mint bound");
    let badge = work.mint_member(device, at(3600)).expect("mint badge");
    for cap in [&plain, &bound, &badge] {
        assert!(
            matches!(
                cap.verify_signet_bound_at_root(&request("ssh", 0), work.node_id()),
                Err(CapError::NotSignetBound)
            ),
            "a cap with no signet_bound authority fact is NotSignetBound"
        );
    }
}

#[test]
fn is_signet_bound_detects_the_kind_offline_with_no_root() {
    // The DIALER's cheap, root-free discriminator: a signet slip reads as signet-bound; a plain slip, a
    // device-bound slip, and a membership badge do NOT, so the dialer attaches a fleet badge (slot 2) beside
    // ONLY a signet slip and never leaks its device->signet linkage on a plain/bearer/device dial.
    let work = identity(1);
    let device: VerifyKey = identity(2).node_id();
    let fleet: VerifyKey = identity(2).node_id();
    let slip = work
        .mint_signet_slip(&service("ssh"), fleet, at(3600))
        .expect("mint signet slip");
    assert!(slip.is_signet_bound(), "a signet slip is signet-bound");

    for cap in [
        work.mint(&service("ssh"), at(3600)).expect("plain"),
        work.mint_bound(&service("ssh"), device, at(3600))
            .expect("bound"),
        work.mint_member(device, at(3600)).expect("badge"),
    ] {
        assert!(
            !cap.is_signet_bound(),
            "a plain slip, device-bound slip, or membership badge is NOT signet-bound"
        );
    }
}

#[test]
fn a_forged_binding_block_cannot_redirect_the_fleet() {
    // The origin wall for the fleet key: a real slip names `X` in the authority block, then an appended
    // `signet_bound(Y)` attenuation block tries to redirect it to a fleet the attacker controls. `query`
    // reads origin-0 facts only, so the returned fleet is still `X`, never `Y`: the bound fleet is exactly
    // the one this signet signed, enforced by biscuit's origin trust (mirrors the forged-member wall).
    let work = identity(1);
    let real_fleet: VerifyKey = identity(2).node_id();
    let attacker_fleet: VerifyKey = identity(3).node_id();
    let forged = work
        .mint_signet_slip_with_forged_binding(&service("ssh"), real_fleet, attacker_fleet, at(3600))
        .expect("forge a second signet_bound fact in an attenuation block");
    let extracted = forged
        .verify_signet_bound_at_root(&request("ssh", 0), work.node_id())
        .expect("the slip still verifies on its authority checks");
    assert_eq!(
        extracted, real_fleet,
        "an appended signet_bound fact must not redirect the fleet -- origin wall"
    );
    assert_ne!(
        extracted, attacker_fleet,
        "the attacker's fleet is never returned"
    );
}

#[test]
fn a_many_block_cap_is_refused_at_parse() {
    // A deeply-attenuated token is O(blocks) to verify; a legitimate delegation chain is short, so one
    // past the block bound is refused at parse rather than burning CPU.
    let exposer = identity(1);
    let mut cap = exposer.mint(&service("ssh"), at(3600)).expect("mint");
    for _ in 0..20 {
        cap = cap.attenuate(None, Some(at(3600))).expect("attenuate");
    }
    let link = cap.link().expect("encode");
    assert!(matches!(Cap::parse(&link), Err(CapError::TooLarge)));
}
