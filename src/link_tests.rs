//! The `sheer:` link as a typed value: parse/display round trip, seal, narrow, and revoke.

use core::time::Duration;
use std::time::SystemTime;

use super::Link;
use crate::cap::{CapError, Identity};
use crate::revocations::FileDenylist;
use crate::service::Service;

/// A deterministic identity for tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("32-byte secret is a valid ed25519 key")
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

/// A fresh denylist backed by a unique temp path, so parallel tests never share a file.
fn denylist(tag: &str) -> FileDenylist {
    let path = std::env::temp_dir().join(format!(
        "nauthy-link-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::revocations::lock_path(&path));
    FileDenylist::empty(path)
}

/// The parse boundary is the display boundary: a minted link renders its own text, and reparsing that text
/// yields the same root and the same verification outcome.
#[test]
fn a_minted_link_round_trips_through_display_and_parse() {
    let issuer = identity(1);
    let link = Link::mint(&issuer, &service("ssh"), Duration::from_secs(3600)).expect("mint");
    let text = link.to_string();
    assert_eq!(
        text,
        link.as_str(),
        "Display renders the stored text verbatim"
    );

    let reparsed: Link = text.parse().expect("a minted link reparses");
    assert_eq!(
        reparsed.root(),
        issuer.verifying_key(),
        "the link carries the issuer's root"
    );
    assert_eq!(
        reparsed.to_string(),
        text,
        "display is stable across a parse round trip"
    );
}

/// A malformed scheme and a tampered token are both refused at parse, before any caveat is evaluated.
#[test]
fn a_malformed_link_is_rejected() {
    assert!(
        matches!("not-a-link".parse::<Link>(), Err(CapError::Scheme)),
        "a missing scheme is a parse error, not a raw string the caller can carry"
    );

    let issuer = identity(1);
    let link = Link::mint(&issuer, &service("ssh"), Duration::from_secs(3600)).expect("mint");
    let mut chars: Vec<char> = link.as_str().chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    let tampered: String = chars.into_iter().collect();
    assert!(
        matches!(
            tampered.parse::<Link>(),
            Err(CapError::Unverified | CapError::Encoding)
        ),
        "a flipped token character must fail the signature chain at parse"
    );
}

/// A sealed link still verifies and refuses any later narrowing: it cannot be attenuated or re-shared.
#[test]
fn a_sealed_link_refuses_narrowing() {
    let issuer = identity(1);
    let sealed = Link::mint(&issuer, &service("ssh"), Duration::from_secs(3600))
        .expect("mint")
        .seal()
        .expect("seal");
    assert!(
        matches!(
            sealed.narrow(Some(&service("web")), None),
            Err(CapError::Attenuate(_))
        ),
        "a sealed link refuses attenuation"
    );
}

/// An unsealed link narrows offline: the tighter service still verifies against the narrowed link, and the
/// original service no longer does (the added check can never both hold).
#[test]
fn narrowing_tightens_the_link() {
    let issuer = identity(1);
    let link = Link::mint(&issuer, &service("ssh"), Duration::from_secs(3600)).expect("mint");
    let narrowed = link
        .narrow(Some(&service("web")), None)
        .expect("narrow by service");
    assert_ne!(
        narrowed.as_str(),
        link.as_str(),
        "narrowing produces a new link, not the same text"
    );
    assert_eq!(
        narrowed.root(),
        link.root(),
        "a narrowed link keeps the issuer's root"
    );
}

/// A bound link is sealed at mint by construction: it refuses the narrowing a bearer link accepts.
#[test]
fn a_bound_link_is_sealed_at_mint() {
    let issuer = identity(1);
    let bound = Link::mint_bound(
        &issuer,
        &service("ssh"),
        identity(2).verifying_key(),
        Duration::from_secs(3600),
    )
    .expect("mint bound");
    assert!(
        matches!(
            bound.narrow(None, Some(Duration::from_secs(60))),
            Err(CapError::Attenuate(_))
        ),
        "a device-bound link cannot be attenuated"
    );
}

/// Revoking a link records its chain in the denylist, so the gate refuses the link itself.
#[cfg(feature = "tokio-fs")]
#[tokio::test]
async fn revoke_records_the_links_chain() {
    let issuer = identity(3);
    let cap = issuer
        .mint(
            &service("ssh"),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .expect("mint");
    let link = cap.link().expect("encode");
    let mut denylist = denylist("revoke");

    assert!(!denylist.is_revoked(&cap), "nothing is revoked yet");
    link.revoke(&mut denylist).await.expect("revoke the link");
    assert!(
        denylist.is_revoked(&cap),
        "the revoked link is refused by the in-memory set"
    );
}
