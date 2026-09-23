//! A file's stamp, and the rule every live reader re-reads by.

use core::time::Duration;
use std::path::PathBuf;

use crate::FileStamp;

/// A unique temp path per test, so parallel tests never share a file.
fn scratch(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nauthy-stamp-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn stamp(path: &PathBuf) -> FileStamp {
    let meta = std::fs::metadata(path).expect("stat the file");
    FileStamp::of(&meta).expect("this platform reports an mtime")
}

/// A reader that never got a stamp, or whose stat got none, knows nothing about whether the file moved.
/// Treating two absent stamps as a match would freeze a reader on a platform that reports no mtime at the
/// first set it read, and every later revocation would be skipped.
#[test]
fn a_missing_stamp_is_never_unchanged() {
    let path = scratch("missing");
    std::fs::write(&path, "00\n").expect("write the file");
    let held = stamp(&path);

    assert!(
        !FileStamp::unchanged(None, None),
        "no stamp on either side re-reads"
    );
    assert!(
        !FileStamp::unchanged(Some(held), None),
        "a stat that reports no stamp re-reads"
    );
    assert!(
        !FileStamp::unchanged(None, Some(held)),
        "a reader holding no stamp re-reads"
    );

    let _ = std::fs::remove_file(&path);
}

/// The one case a reader may skip the read: the stat it just took matches the one it read at.
#[test]
fn an_untouched_file_is_unchanged() {
    let path = scratch("untouched");
    std::fs::write(&path, "00\n").expect("write the file");

    assert!(FileStamp::unchanged(Some(stamp(&path)), Some(stamp(&path))));

    let _ = std::fs::remove_file(&path);
}

/// A same-length replacement renamed into place, carrying the old file's mtime, is still a new generation.
/// Every writer in this crate replaces by rename, so a stamp of length and mtime alone would miss a
/// rewrite that kept both, and inside one coarse ctime tick (HFS+ records whole seconds) only the inode
/// sees it.
#[cfg(unix)]
#[test]
fn a_same_length_replacement_with_the_old_mtime_changes_the_stamp() {
    let path = scratch("replaced");
    let sibling = path.with_extension("next");
    std::fs::write(&path, "00\n").expect("write the first generation");
    let mtime = std::fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .expect("read the first generation's mtime");
    let before = stamp(&path);

    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&sibling, "ff\n").expect("write the second generation");
    std::fs::File::options()
        .write(true)
        .open(&sibling)
        .and_then(|file| file.set_modified(mtime))
        .expect("carry the old mtime onto the second generation");
    std::fs::rename(&sibling, &path).expect("rename the second generation into place");

    let after = stamp(&path);
    assert_ne!(
        before.ino(),
        after.ino(),
        "a replacement renamed into place is a different inode"
    );
    // The replacement's ctime differs here too, but on a filesystem with a coarse clock it need not. Blank
    // it on both sides so the inode alone has to tell the two generations apart.
    assert_ne!(
        before.without_ctime(),
        after.without_ctime(),
        "a replacement is seen through its inode however the length, mtime and ctime line up"
    );

    let _ = std::fs::remove_file(&path);
}

/// An in-place rewrite to the same length whose mtime is set back by hand keeps the inode, the length and
/// the mtime. The ctime is the one field it cannot set back.
#[cfg(unix)]
#[test]
fn an_mtime_set_back_by_hand_changes_the_stamp() {
    let path = scratch("backdated");
    std::fs::write(&path, "00\n").expect("write the file");
    let mtime = std::fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .expect("read the mtime");
    let before = stamp(&path);

    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&path, "ff\n").expect("rewrite the file in place, same length");
    std::fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|file| file.set_modified(mtime))
        .expect("set the mtime back");

    assert_ne!(
        before,
        stamp(&path),
        "a backdated rewrite is seen through its ctime"
    );

    let _ = std::fs::remove_file(&path);
}

/// Stamps on this thread report no mtime until this is dropped.
struct NoMtime;

impl NoMtime {
    fn on() -> Self {
        crate::stamp::NO_MTIME.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for NoMtime {
    fn drop(&mut self) {
        crate::stamp::NO_MTIME.with(|flag| flag.set(false));
    }
}

/// A denylist that holds no stamp and stats a file whose platform reports none must read it. Skipping
/// would leave a revocation written by another process unseen for as long as the process runs.
#[cfg(feature = "tokio-fs")]
#[tokio::test]
async fn a_denylist_reads_a_file_that_reports_no_stamp() {
    let path = scratch("denylist-unstamped");
    let _ = std::fs::remove_file(&path);
    let denylist = crate::FileDenylist::load(path.clone())
        .await
        .expect("an absent denylist loads empty");
    let id = crate::RevocationId::from_hex("aabb").expect("valid hex");
    std::fs::write(&path, "aabb\n").expect("another process revokes");

    let unstamped = NoMtime::on();
    assert!(
        denylist.is_revoked_any([&id]),
        "a revocation behind a missing stamp is read"
    );
    drop(unstamped);

    let _ = std::fs::remove_file(&path);
}

/// The same rule for the disabled-roots latch: a missing stamp re-reads, so a root disabled by another
/// process is refused on the next check.
#[cfg(feature = "tokio-fs")]
#[test]
fn a_latch_reads_a_file_that_reports_no_stamp() {
    let path = scratch("latch-unstamped");
    let _ = std::fs::remove_file(&path);
    let latch = crate::DisabledRoots::open_for_repair(path.clone());
    let root = crate::Identity::from_secret(&[7; 32])
        .expect("valid ed25519 secret")
        .verifying_key();
    std::fs::write(&path, format!("{root}\n")).expect("another process disables the root");

    let unstamped = NoMtime::on();
    assert!(
        latch.is_disabled(root),
        "a root disabled behind a missing stamp is read"
    );
    drop(unstamped);

    let _ = std::fs::remove_file(&path);
}
