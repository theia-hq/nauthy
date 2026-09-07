//! The denylist's two revocation reaches: a narrowest-block [`revoke`](FileDenylist::revoke) that kills one
//! leaf, and a root-block [`revoke_root`](FileDenylist::revoke_root) that kills a grant and every cap
//! descended from it.

use core::time::Duration;
use std::time::SystemTime;

use crate::cap::Identity;
use crate::revocations::FileDenylist;
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
fn denylist(tag: &str) -> FileDenylist {
    let path = std::env::temp_dir().join(format!(
        "nauthy-denylist-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    FileDenylist::empty(path)
}

#[tokio::test]
async fn revoke_root_refuses_the_root_cap_and_a_child_delegated_from_it() {
    // A root grant, and a child a holder attenuated (delegated) from it. Both carry the root's authority
    // block, hence its revocation id, so revoking the root must refuse BOTH in one entry.
    let issuer = identity(1);
    let root = issuer.mint(&service("ssh"), far_expiry()).expect("mint");
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
    let issuer = identity(1);
    let parent = issuer.mint(&service("ssh"), far_expiry()).expect("mint");
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

#[cfg(unix)]
#[tokio::test]
async fn a_persisted_denylist_is_owner_only() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    // The consumer owns and provisions the store dir; nauthy no longer creates it, so the test makes the
    // parent itself (0700 here) before persisting. The denylist records who this issuer recalled: a co-tenant
    // local user must not be able to read the FILE, which is what this asserts.
    let dir = std::env::temp_dir().join(format!(
        "nauthy-denylist-perms-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .expect("provision the store dir the consumer owns");
    let path = dir.join("revoked");

    let mut denylist = FileDenylist::empty(path.clone());
    let cap = identity(7)
        .mint(&service("ssh"), far_expiry())
        .expect("mint");
    denylist
        .revoke_root(&cap)
        .await
        .expect("revoke persists the denylist into the provisioned store dir");

    let file_mode = std::fs::metadata(&path)
        .expect("stat the denylist")
        .permissions()
        .mode();
    assert_eq!(
        file_mode & 0o777,
        0o600,
        "the denylist is written 0600 (owner read/write only) via its 0600 temp, never world-readable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
