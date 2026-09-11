//! The denylist's two revocation reaches: a narrowest-block [`revoke`](FileDenylist::revoke) that kills one
//! leaf, and a root-block [`revoke_root`](FileDenylist::revoke_root) that kills a grant and every cap
//! descended from it.

use core::time::Duration;
use std::time::SystemTime;

use crate::cap::Identity;
use crate::revocations::{FileDenylist, RevocationId};
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

/// The M2 race at its smallest: a writer replaces the path between the loader's open and its read. The
/// loaded ids and the freshness stamp must both come from the one opened handle, so the loader reports the
/// handle's bytes with the handle's `(mtime, len)`, never the old ids wearing the replacement's stamp
/// (which would make every later refresh skip and freeze a revocation until the next edit).
#[tokio::test]
async fn load_pairs_ids_and_stamp_from_one_handle() {
    let path = std::env::temp_dir().join(format!(
        "nauthy-denylist-race-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, "00\n").expect("write the first generation");
    let mut handle = tokio::fs::File::open(&path)
        .await
        .expect("open the first generation");

    // Replace the path with a different inode after the open: a truncating in-place write would be seen
    // through the still-open handle, so write a sibling and rename it over the path. The replacement is a
    // different LENGTH too, so the stamp differs even on a filesystem with coarse mtime ticks.
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, "ffff\n").expect("write the replacement generation");
    std::fs::rename(&replacement, &path).expect("rename the replacement over the path");

    let old = RevocationId::from_hex("00").expect("valid hex");
    let fresh = RevocationId::from_hex("ffff").expect("valid hex");
    let (ids, stamp) = crate::revocations::read_ids_from(&mut handle)
        .await
        .expect("read from the opened handle");
    assert!(
        ids.contains(&old),
        "the loaded set is the handle's ids, not the replacement path's"
    );
    assert!(
        !ids.contains(&fresh),
        "the replacement's ids are not loaded"
    );

    let held = handle.metadata().await.expect("stat the opened handle");
    assert_eq!(
        stamp,
        Some((held.modified().expect("mtime"), held.len())),
        "the stamp describes the same inode as the ids"
    );
    let replaced = std::fs::metadata(&path).expect("stat the replacement path");
    assert_ne!(
        stamp,
        Some((replaced.modified().expect("mtime"), replaced.len())),
        "the stamp is not the replacement path's"
    );

    let _ = std::fs::remove_file(&path);
}

/// The M2 race at its smallest on the WRITE side: a revoke must adopt the stamp of the bytes it wrote, taken
/// from the handle that wrote them, never the `(mtime, len)` of a path a second writer can replace. `persist`
/// funnels every write and every stamp through `write_and_stamp`, so this drives that seam with the
/// replacement landing between the open and the write: a stamp read from the path would describe the
/// replacement and make the next refresh skip the replacement's revocation until the next edit.
#[tokio::test]
async fn revoke_stamps_the_handle_it_wrote_not_a_replacement_path() {
    let path = std::env::temp_dir().join(format!(
        "nauthy-denylist-write-race-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&tmp);

    // The path already holds a foreign generation, and the replacement lands with a different LENGTH than
    // the body written through the handle, so the two stamps differ even on a filesystem with coarse mtime
    // ticks.
    std::fs::write(&path, "00\n").expect("write the foreign generation");
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .expect("open the handle the body is written through");

    // Replace the path after the handle is open and before the body is written: a stamp read from the path
    // would wear this replacement's freshness instead of the handle's.
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, "ffffaaaa\n").expect("write the replacement generation");
    std::fs::rename(&replacement, &path).expect("rename the replacement over the path");

    let stamp = crate::revocations::write_and_stamp(&mut file, b"aabbcc\n")
        .await
        .expect("write the body and stamp the handle");

    let held = file.metadata().await.expect("stat the written handle");
    assert_eq!(
        stamp,
        Some((held.modified().expect("mtime"), held.len())),
        "the adopted stamp describes the inode that received the bytes"
    );
    let foreign = std::fs::metadata(&path).expect("stat the replacement path");
    assert_ne!(
        stamp,
        Some((foreign.modified().expect("mtime"), foreign.len())),
        "the adopted stamp is not the replacement path's"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&tmp);
}
