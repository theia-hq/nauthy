//! The denylist's two revocation reaches: a narrowest-block [`revoke`](Denylist::revoke) that kills one
//! leaf, and a root-block [`revoke_root`](Denylist::revoke_root) that kills a grant and every cap descended
//! from it.

use core::time::Duration;
use std::time::SystemTime;

use crate::cap::Identity;
use crate::revocations::Denylist;
use crate::service::Service;

/// A deterministic identity for tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("32-byte secret is a valid ed25519 key")
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

/// An expiry far enough out that nothing under test expires.
fn far_expiry() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_secs(3600)
}

/// A fresh denylist backed by a unique temp path, so parallel tests never share a file.
fn denylist(tag: &str) -> Denylist {
    let path = std::env::temp_dir().join(format!(
        "nauthy-denylist-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    Denylist::empty(path)
}

#[tokio::test]
async fn revoke_root_refuses_the_root_cap_and_a_child_delegated_from_it() {
    // A root grant, and a child a holder attenuated (delegated) from it. Both carry the root's authority
    // block, hence its revocation id, so revoking the root must refuse BOTH in one entry.
    let exposer = identity(1);
    let root = exposer.mint(&service("ssh"), far_expiry()).expect("mint");
    let child = root
        .attenuate(None, Some(far_expiry()))
        .expect("holder narrows and re-shares");

    let mut denylist = denylist("revoke-root");
    denylist.revoke_root(&root).await.expect("revoke the root");

    assert!(
        denylist.is_revoked(&root),
        "revoke_root refuses the root cap itself"
    );
    assert!(
        denylist.is_revoked(&child),
        "revoke_root refuses a child delegated from the root, because the child inherits the root's block"
    );
}

#[tokio::test]
async fn plain_revoke_refuses_only_the_leaf_not_its_parent() {
    // Contrast: plain `revoke` records only the narrowest block. Revoking the CHILD leaf refuses that leaf
    // but leaves its parent (the wider grant it was narrowed from) still granting.
    let exposer = identity(1);
    let parent = exposer.mint(&service("ssh"), far_expiry()).expect("mint");
    let child = parent
        .attenuate(None, Some(far_expiry()))
        .expect("holder narrows");

    let mut denylist = denylist("revoke-leaf");
    denylist.revoke(&child).await.expect("revoke the leaf");

    assert!(
        denylist.is_revoked(&child),
        "plain revoke refuses the exact leaf it was given"
    );
    assert!(
        !denylist.is_revoked(&parent),
        "plain revoke leaves the parent grant intact: only the narrowest block was recorded"
    );
}
