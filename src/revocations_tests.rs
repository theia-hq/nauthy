//! The denylist: one grow-only file of revoked ids and keys, what each kind refuses, the lock a write
//! takes (the caller's, never a second), and the witness that refuses a file shorter than it was.

use core::time::Duration;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, mpsc};
use std::time::SystemTime;

use crate::cap::{Cap, Identity};
use crate::revocations::{
    Denylist, DenylistError, Exclusive, Revocation, RevocationId, Revocations, witness_path,
};
use crate::service::Service;
use crate::{STAT_DEBOUNCE, VerifyKey};

/// A deterministic identity for tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("32-byte secret is a valid ed25519 key")
}

fn key(seed: u8) -> VerifyKey {
    identity(seed).verifying_key()
}

fn service(name: &str) -> Service {
    name.parse().expect("valid service name")
}

/// An expiry far enough out that nothing under test expires.
fn far_expiry() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_secs(3600)
}

/// A slip rooted at `seed`'s authority.
fn cap_rooted_at(seed: u8) -> Cap {
    identity(seed)
        .mint(&service("ssh"), far_expiry())
        .expect("mint")
}

/// A distinct id per `n`, as a cap's chain would carry one.
fn id(n: u8) -> RevocationId {
    RevocationId::from_bytes(vec![n; 64])
}

/// A caller's own lock guard: the test holds no real lock, which is the point where a test shows that the
/// write takes none of its own.
struct Held;

impl Exclusive for Held {}

/// A unique denylist path per test and thread, cleared of anything a prior run left.
fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nauthy-denylist-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    cleanup(&path);
    path
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(witness_path(path));
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::revocations::lock_path(path));
}

fn id_line(id: &RevocationId) -> String {
    format!("id {}\n", id.to_hex())
}

fn key_line(key: &VerifyKey) -> String {
    format!("key {key}\n")
}

/// Replace the file with `bytes` through a sibling renamed over it, so it has a new inode a refresh cannot
/// mistake for the one it read, then wait past the stat debounce.
fn rewrite(path: &Path, bytes: impl AsRef<[u8]>) {
    let next = path.with_extension("next");
    std::fs::write(&next, bytes).expect("write the next generation");
    std::fs::rename(&next, path).expect("rename it over the denylist");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));
}

/// Run `task` on its own thread and report whether it finished within a few seconds. A task that
/// deadlocks or blocks forever is left behind; the test fails on its `None` rather than hanging.
fn finishes<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(task());
    });
    finished.recv_timeout(Duration::from_secs(5)).ok()
}

fn witness(path: &Path) -> String {
    std::fs::read_to_string(witness_path(path)).expect("read the witness")
}

// A gate shares its oracle across every connection task, so the store must cross threads.
static_assertions::assert_impl_all!(Denylist: Send, Sync);

#[test]
fn ids_and_keys_share_one_file_and_one_witness() {
    let dir = std::env::temp_dir().join(format!(
        "nauthy-denylist-one-file-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("provision the store dir");
    let path = dir.join("revoked");

    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Id(id(1)), Revocation::Key(key(1))])
        .expect("revoke an id and a key");

    assert_eq!(
        std::fs::read_to_string(&path).expect("read the denylist"),
        format!("{}{}", id_line(&id(1)), key_line(&key(1))),
        "one file, an id line and a key line"
    );
    assert_eq!(witness(&path), "2\n", "one witness counts both kinds");
    let names = std::fs::read_dir(&dir)
        .expect("list the store dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from(["revoked".into(), "revoked.written".into()]),
        "no second store, witness or lock beside it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_revoked_key_is_refused_as_a_peer_and_as_a_root() {
    let path = scratch("key-both");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke a key");

    assert!(denylist.is_revoked_peer(&key(1)), "refused as a peer");
    assert!(
        denylist.is_revoked(&cap_rooted_at(1)),
        "refused as the root of a cap"
    );
    assert!(
        !denylist.is_revoked_peer(&key(2)),
        "another peer is not over-denied"
    );
    assert!(
        !denylist.is_revoked(&cap_rooted_at(2)),
        "a cap rooted anywhere else is not over-denied"
    );
    cleanup(&path);
}

#[test]
fn a_revoked_id_and_a_revoked_key_each_refuse_on_their_own() {
    // Either kind refuses: a clean root with a recalled chain, and a revoked root with a clean chain.
    let path = scratch("either");
    let recalled = cap_rooted_at(2);
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(
            &Held,
            [
                Revocation::Key(key(1)),
                Revocation::Id(recalled.root_revocation_id().expect("an authority block")),
            ],
        )
        .expect("revoke");

    assert!(
        denylist.is_revoked(&cap_rooted_at(1)),
        "revoked root, clean chain"
    );
    assert!(denylist.is_revoked(&recalled), "clean root, recalled chain");
    assert!(!denylist.is_revoked(&cap_rooted_at(3)), "neither");
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_write_under_a_callers_guard_takes_no_lock() {
    let path = scratch("caller-guard");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke under the caller's guard");
    assert!(
        !crate::revocations::lock_path(&path).exists(),
        "no lock file is made when none existed"
    );

    // Another descriptor in this process holds the store's own flock. A write that flocked its sibling
    // under the caller's guard would block here (or fail) instead of returning.
    let other = Denylist::for_repair(path.clone());
    let flock = other.lock().expect("take the store's own lock");
    let writer = Denylist::for_repair(path.clone());
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(writer.revoke(&Held, [Revocation::Key(key(2))]).is_ok());
    });
    let result = finished.recv_timeout(Duration::from_secs(5));
    drop(flock);
    assert_eq!(
        result,
        Ok(true),
        "the write returns under a flock it never takes"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn two_self_locked_writers_both_survive() {
    // Both load the absent file before either writes, so each is missing the other's entry. The store's
    // own lock must serialize them, and the write must re-read under it, or the second rename drops the
    // first entry.
    let path = scratch("self-locked");
    let barrier = Arc::new(Barrier::new(2));
    let writers = [Revocation::Key(key(1)), Revocation::Id(id(1))].map(|entry| {
        let (path, barrier) = (path.clone(), Arc::clone(&barrier));
        std::thread::spawn(move || {
            let denylist = Denylist::load(path).expect("load");
            barrier.wait();
            let held = denylist.lock().expect("lock");
            denylist.revoke(&held, [entry]).expect("revoke");
        })
    });
    for writer in writers {
        writer.join().expect("the writer finishes");
    }

    let fresh = Denylist::load(path.clone()).expect("fresh load");
    assert!(fresh.is_revoked_key(&key(1)), "the key writer's entry");
    assert!(fresh.is_revoked_any([&id(1)]), "the id writer's entry");
    cleanup(&path);
}

#[test]
fn a_write_restores_an_entry_the_file_lost() {
    // The store holds `key(1)`; the file is cut to omit it. A write of an entry both already hold must
    // still put it back, not fire only for an entry new to memory.
    let path = scratch("restore");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(&Held, [Revocation::Id(id(1)), Revocation::Key(key(1))])
        .expect("revoke");
    rewrite(&path, id_line(&id(1)));

    denylist
        .revoke(&Held, [Revocation::Id(id(1))])
        .expect("revoke again");

    let text = std::fs::read_to_string(&path).expect("read the denylist");
    assert!(text.contains(&key_line(&key(1))), "the lost key is back");
    assert!(text.contains(&id_line(&id(1))), "the id stays");
    cleanup(&path);
}

#[test]
fn a_repeat_revoke_does_not_rewrite() {
    let path = scratch("repeat");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke");
    let before = crate::FileStamp::of(&std::fs::metadata(&path).expect("stat"));

    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke again");

    let after = crate::FileStamp::of(&std::fs::metadata(&path).expect("stat"));
    assert!(before.is_some(), "the platform stamps the file");
    assert_eq!(
        before, after,
        "an entry the file holds is not written again"
    );
    cleanup(&path);
}

#[test]
fn a_repeat_revoke_restores_a_deleted_file() {
    // The other side of not rewriting: a file that lost the entry, deletion included, is written.
    let path = scratch("repeat-deleted");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke");
    std::fs::remove_file(&path).expect("delete the denylist");

    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke again");

    let fresh = Denylist::load(path.clone()).expect("fresh load");
    assert!(fresh.is_revoked_key(&key(1)), "the file is back");
    cleanup(&path);
}

#[test]
fn a_shorter_file_than_its_witness_is_lost_for_either_kind() {
    let path = scratch("lost-kind");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Id(id(1)), Revocation::Key(key(1))])
        .expect("revoke");

    std::fs::write(&path, id_line(&id(1))).expect("cut the key line");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Lost {
                expected: 2,
                found: 1,
                ..
            })
        ),
        "a lost key is a loss"
    );

    std::fs::write(&path, key_line(&key(1))).expect("restore the key, cut the id line");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Lost {
                expected: 2,
                found: 1,
                ..
            })
        ),
        "a lost id is a loss"
    );
    cleanup(&path);
}

#[test]
fn a_refresh_never_drops_an_id_or_a_key() {
    let path = scratch("refresh-union");
    Denylist::for_repair(path.clone())
        .revoke(
            &Held,
            [
                Revocation::Id(id(1)),
                Revocation::Key(key(1)),
                Revocation::Id(id(2)),
            ],
        )
        .expect("revoke");
    let denylist = Denylist::load(path.clone()).expect("load");
    assert!(denylist.is_revoked_key(&key(1)), "held before the rewrite");

    rewrite(&path, id_line(&id(2)));

    assert!(
        denylist.is_revoked_any([&id(1)]),
        "an id dropped from the file stays revoked"
    );
    assert!(
        denylist.is_revoked_key(&key(1)),
        "a key dropped from the file stays revoked"
    );
    cleanup(&path);
}

#[test]
fn one_bad_line_hides_neither_kind() {
    let path = scratch("bad-line");
    let denylist = Denylist::load(path.clone()).expect("load the absent file");
    rewrite(
        &path,
        format!("{}garbage\n{}", id_line(&id(1)), key_line(&key(1))),
    );

    assert!(
        denylist.is_revoked_any([&id(1)]),
        "the id before the bad line"
    );
    assert!(
        denylist.is_revoked_key(&key(1)),
        "the key after the bad line"
    );
    assert_eq!(denylist.malformed_line(), Some(2), "the bad line is named");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Parse { line: 2 })
        ),
        "a load refuses it, naming the line"
    );
    cleanup(&path);
}

#[test]
fn a_bad_line_is_carried_and_not_counted() {
    // The bad line may be an entry this version cannot read, so a write keeps it rather than dropping
    // what might be a revocation, and the witness counts entries only.
    let path = scratch("carried");
    std::fs::write(&path, format!("{}ed02future\n", id_line(&id(1)))).expect("poison the file");
    let denylist = Denylist::for_repair(path.clone());

    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke writes anyway");

    assert_eq!(
        std::fs::read_to_string(&path).expect("read the denylist"),
        format!("{}{}ed02future\n", id_line(&id(1)), key_line(&key(1))),
        "the sorted entries, then the carried line"
    );
    assert_eq!(witness(&path), "2\n", "the carried line is not counted");
    assert_eq!(
        denylist.malformed_line(),
        Some(3),
        "the carried line is named where it now sits"
    );
    cleanup(&path);
}

#[test]
fn deleting_a_carried_bad_line_does_not_trip_lost() {
    let path = scratch("bad-line-repair");
    std::fs::write(&path, format!("{}garbage\n", key_line(&key(1)))).expect("poison the file");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(2))])
        .expect("revoke carries the bad line");

    std::fs::write(&path, format!("{}{}", key_line(&key(1)), key_line(&key(2))))
        .expect("repair the bad line");
    assert!(
        Denylist::load(path.clone()).is_ok(),
        "a repaired file with every entry loads"
    );
    cleanup(&path);
}

#[test]
fn an_oversized_file_refuses_load_and_is_ignored_live() {
    let path = scratch("oversized");
    std::fs::write(&path, id_line(&id(1))).expect("write the denylist");
    let denylist = Denylist::load(path.clone()).expect("load");
    assert!(denylist.is_revoked_any([&id(1)]), "held before");

    rewrite(
        &path,
        format!("{}{}", key_line(&key(1)), "\n".repeat((4 << 20) + 1)),
    );

    assert!(denylist.is_revoked_any([&id(1)]), "what was held stays");
    assert!(
        !denylist.is_revoked_key(&key(1)),
        "an oversized file is not read on the admit path"
    );
    assert!(
        matches!(Denylist::load(path.clone()), Err(DenylistError::TooLarge)),
        "an oversized file is refused at load"
    );
    assert!(
        matches!(
            denylist.revoke(&Held, [Revocation::Key(key(2))]),
            Err(DenylistError::TooLarge)
        ),
        "and a write refuses rather than replace what it cannot read"
    );
    cleanup(&path);
}

#[test]
fn an_absent_denylist_refuses_nothing() {
    let path = scratch("absent");
    let denylist = Denylist::load(path.clone()).expect("load");
    assert!(!denylist.is_revoked_key(&key(1)), "no file, no key");
    assert!(!denylist.is_revoked(&cap_rooted_at(1)), "no file, no cap");
    cleanup(&path);
}

#[test]
fn an_entry_written_by_another_instance_is_seen() {
    // Live: the first check after load always stats, so no sleep is needed to see this write.
    let path = scratch("live");
    let running = Denylist::load(path.clone()).expect("load");
    assert!(!running.is_revoked_peer(&key(1)), "nothing yet");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("another process revokes");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));

    assert!(
        running.is_revoked_peer(&key(1)),
        "a key another process revoked is refused without a restart"
    );
    cleanup(&path);
}

#[test]
fn a_write_is_seen_by_the_instance_that_wrote_it_at_once() {
    // A writer shares its instance with a gate through `&self`, so the gate sees the write without
    // waiting for a refresh.
    let path = scratch("own-write");
    let denylist = Denylist::load(path.clone()).expect("load");
    assert!(!denylist.is_revoked_key(&key(1)), "arms the debounce");
    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke");
    assert!(denylist.is_revoked_key(&key(1)), "seen inside the debounce");
    cleanup(&path);
}

#[test]
fn deleting_the_file_keeps_the_last_known_set() {
    let path = scratch("deleted-live");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(&Held, [Revocation::Id(id(1)), Revocation::Key(key(1))])
        .expect("revoke");
    std::fs::remove_file(&path).expect("delete the denylist");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));

    assert!(denylist.is_revoked_any([&id(1)]), "the id stays revoked");
    assert!(denylist.is_revoked_key(&key(1)), "the key stays revoked");
    cleanup(&path);
}

#[test]
fn a_deleted_or_emptied_denylist_is_lost_at_load() {
    let path = scratch("deleted");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke");

    std::fs::write(&path, "").expect("truncate the denylist");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Lost {
                expected: 1,
                found: 0,
                ..
            })
        ),
        "an emptied denylist that was written before refuses to load"
    );
    std::fs::remove_file(&path).expect("delete the denylist");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Lost {
                expected: 1,
                found: 0,
                ..
            })
        ),
        "a deleted denylist beside its witness refuses to load"
    );
    cleanup(&path);
}

#[test]
fn the_lost_message_names_the_way_out() {
    let path = scratch("message");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke");
    std::fs::remove_file(&path).expect("lose the file");

    let Err(error) = Denylist::load(path.clone()) else {
        panic!("a lost denylist must not load");
    };
    let message = error.to_string();
    assert!(
        message.contains(&path.display().to_string()),
        "names the file"
    );
    assert!(
        message.contains(&witness_path(&path).display().to_string()),
        "names the witness to remove"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn removing_the_witness_accepts_the_loss_at_load() {
    // The one way to shrink the set on purpose: remove the witness and load again. The load reads the file
    // as it stands, and the lock is never involved.
    let path = scratch("accept");
    let denylist = Denylist::for_repair(path.clone());
    let held = denylist.lock().expect("lock");
    denylist
        .revoke(&held, [Revocation::Id(id(1)), Revocation::Id(id(2))])
        .expect("revoke");
    drop(held);
    std::fs::write(&path, id_line(&id(1))).expect("lose one id");

    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Lost {
                expected: 2,
                found: 1,
                ..
            })
        ),
        "a shorter file beside its witness refuses to load"
    );
    std::fs::remove_file(witness_path(&path)).expect("accept the loss");

    let loaded = Denylist::load(path.clone()).expect("loads the file as it stands");
    assert!(loaded.is_revoked_any([&id(1)]), "the id the file names");
    assert!(
        !loaded.is_revoked_any([&id(2)]),
        "the id the file left out is un-revoked"
    );
    assert!(
        crate::revocations::lock_path(&path).exists(),
        "the lock was never touched"
    );
    cleanup(&path);
}

#[test]
fn only_a_full_reapply_clears_lost() {
    let path = scratch("reapply");
    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(1)), Revocation::Key(key(2))])
        .expect("revoke");
    std::fs::remove_file(&path).expect("lose the file");

    let repair = Denylist::for_repair(path.clone());
    repair
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("re-apply one");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Lost {
                expected: 2,
                found: 1,
                ..
            })
        ),
        "a partial repair does not quietly un-revoke the rest"
    );

    repair
        .revoke(&Held, [Revocation::Key(key(2))])
        .expect("re-apply the other");
    let repaired = Denylist::load(path.clone()).expect("a full repair loads");
    assert!(repaired.is_revoked_key(&key(1)) && repaired.is_revoked_key(&key(2)));
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_stranded_lock_is_not_a_witness() {
    // A self-locking write that failed after taking the lock leaves `<path>.lock` and nothing else.
    // Nothing was ever durably recorded, so the absent file loads as the empty set.
    let path = scratch("stranded-lock");
    std::fs::write(crate::revocations::lock_path(&path), "").expect("strand a lock");
    let loaded = Denylist::load(path.clone());
    assert!(
        matches!(loaded, Ok(ref denylist) if !denylist.is_revoked_key(&key(1))),
        "a lock alone proves nothing was written"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_failed_write_leaves_the_witness_untouched() {
    // The witness moves only after the body is durably in place. A rename over a non-empty directory
    // fails, so the body never lands, and the witness must not claim it did.
    let path = scratch("failed-write");
    std::fs::create_dir_all(path.join("occupied")).expect("make the target unrenamable");
    let written = crate::revocations::write_atomically(&path, b"x\n", 3);
    assert!(written.is_err(), "the rename over a directory fails");
    assert!(
        !witness_path(&path).exists(),
        "a failed write leaves no witness"
    );
    let _ = std::fs::remove_dir_all(&path);
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_persisted_denylist_is_owner_only() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    // The consumer owns and provisions the store dir; nauthy does not create it. The denylist records who
    // this issuer recalled, so a co-tenant local user must not be able to read the FILE.
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

    Denylist::for_repair(path.clone())
        .revoke(&Held, [Revocation::Key(key(7))])
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

#[cfg(unix)]
#[test]
fn a_same_length_replacement_with_the_old_mtime_is_still_seen() {
    // Every key line is the same length, so {K1, K2} and {K1, K3} are the same size. A replacement renamed
    // in with the old mtime put back would pass an `(mtime, len)` stamp unseen; the inode gives it away.
    let path = scratch("swap");
    std::fs::write(&path, format!("{}{}", key_line(&key(1)), key_line(&key(2))))
        .expect("write the denylist");
    let denylist = Denylist::load(path.clone()).expect("load");
    assert!(
        denylist.is_revoked_key(&key(1)),
        "the first check stats the file"
    );
    let mtime = std::fs::metadata(&path)
        .expect("stat the denylist")
        .modified()
        .expect("mtime");

    let swap = path.with_extension("swap");
    std::fs::write(&swap, format!("{}{}", key_line(&key(1)), key_line(&key(3))))
        .expect("write the replacement");
    std::fs::File::options()
        .write(true)
        .open(&swap)
        .expect("open the replacement")
        .set_modified(mtime)
        .expect("put the old mtime back");
    std::fs::rename(&swap, &path).expect("rename the replacement in");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));

    assert!(
        denylist.is_revoked_key(&key(3)),
        "a same-length, same-mtime replacement is read"
    );
    cleanup(&path);
}

/// The race at its smallest: a writer replaces the path between the loader's open and its read. The
/// loaded entries and the freshness stamp must both come from the one opened handle, so the loader reports
/// the handle's bytes with the handle's stamp, never the old entries wearing the replacement's stamp
/// (which would make every later refresh skip and freeze a revocation until the next edit).
#[test]
fn load_pairs_ids_and_stamp_from_one_handle() {
    let path = scratch("race");
    std::fs::write(&path, "id 00\n").expect("write the first generation");
    let mut handle = std::fs::File::open(&path).expect("open the first generation");

    // Replace the path with a different inode after the open: a truncating in-place write would be seen
    // through the still-open handle, so write a sibling and rename it over the path. The replacement is a
    // different LENGTH too, so the stamp differs even on a filesystem with coarse mtime ticks.
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, "id ffff\n").expect("write the replacement generation");
    std::fs::rename(&replacement, &path).expect("rename the replacement over the path");

    let old = RevocationId::from_hex("00").expect("valid hex");
    let fresh = RevocationId::from_hex("ffff").expect("valid hex");
    let (entries, stamp) =
        crate::revocations::read_entries_from(&mut handle).expect("read from the opened handle");
    assert!(
        entries.ids.contains(&old),
        "the loaded set is the handle's ids, not the replacement path's"
    );
    assert!(
        !entries.ids.contains(&fresh),
        "the replacement's ids are not loaded"
    );

    let held = handle.metadata().expect("stat the opened handle");
    assert_eq!(
        stamp,
        crate::FileStamp::of(&held),
        "the stamp describes the same inode as the ids"
    );
    let replaced = std::fs::metadata(&path).expect("stat the replacement path");
    assert_ne!(
        stamp,
        crate::FileStamp::of(&replaced),
        "the stamp is not the replacement path's"
    );
    cleanup(&path);
}

/// The same race on the WRITE side: a revoke must adopt the stamp of the bytes it wrote, taken from the
/// handle that wrote them, never the stamp of a path a second writer can replace. Every write and every
/// stamp funnels through `write_and_stamp`, so this drives that path with the replacement landing between
/// the open and the write: a stamp read from the path would describe the replacement and make the next
/// refresh skip the replacement's revocation until the next edit.
#[test]
fn revoke_stamps_the_handle_it_wrote_not_a_replacement_path() {
    let path = scratch("write-race");
    let tmp = crate::revocations::temp_path(&path);
    let _ = std::fs::remove_file(&tmp);

    // The path already holds a foreign generation, and the replacement lands with a different LENGTH than
    // the body written through the handle, so the two stamps differ even on a filesystem with coarse mtime
    // ticks.
    std::fs::write(&path, "id 00\n").expect("write the foreign generation");
    let mut file =
        std::fs::File::create(&tmp).expect("open the handle the body is written through");

    // Replace the path after the handle is open and before the body is written: a stamp read from the path
    // would wear this replacement's freshness instead of the handle's.
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, "id ffffaaaa\n").expect("write the replacement generation");
    std::fs::rename(&replacement, &path).expect("rename the replacement over the path");

    let stamp = crate::revocations::write_and_stamp(&mut file, b"aabbcc\n")
        .expect("write the body and stamp the handle");

    // The length is the bytes this handle wrote, so it can only be the handle's own body. The exact
    // mtime is not asserted: a stat can race the write's mtime visibility on some filesystems, and
    // the security property here is which bytes the stamp describes, never the clock tick.
    assert_eq!(
        stamp.map(|stamp| stamp.len),
        Some(7),
        "the adopted stamp carries the bytes the handle wrote, not a replacement's length"
    );
    let foreign = std::fs::metadata(&path).expect("stat the replacement path");
    assert_ne!(
        stamp,
        crate::FileStamp::of(&foreign),
        "the adopted stamp is not the replacement path's"
    );
    cleanup(&path);
    let _ = std::fs::remove_file(&tmp);
}

/// Each write gets its own temp sibling: a fixed `<denylist>.tmp` name would let two writers share one
/// temp, so one could truncate the other's in-flight body.
#[test]
fn each_write_gets_a_unique_temp_sibling() {
    let path = PathBuf::from("/tmp/nauthy-denylist-temp");
    let first = crate::revocations::temp_path(&path);
    let second = crate::revocations::temp_path(&path);
    assert_ne!(first, second, "two writes never share one temp path");
    assert_eq!(
        first.parent(),
        path.parent(),
        "the temp is a sibling in the denylist's dir"
    );
    assert_eq!(
        second.parent(),
        path.parent(),
        "the temp is a sibling in the denylist's dir"
    );
}

#[test]
fn a_root_id_refuses_the_grant_and_its_delegations() {
    // A root grant, and a child a holder attenuated (delegated) from it. Both carry the root's authority
    // block, hence its revocation id, so recording that id refuses BOTH in one entry.
    let root = cap_rooted_at(1);
    let child = root
        .attenuate(None, Some(far_expiry()))
        .expect("holder narrows and re-shares");
    let path = scratch("root-id");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(
            &Held,
            [Revocation::Id(
                root.root_revocation_id().expect("an authority block"),
            )],
        )
        .expect("revoke the root id");

    assert!(denylist.is_revoked(&root), "the root cap itself");
    assert!(
        denylist.is_revoked(&child),
        "a child delegated from the root, because it inherits the root's block"
    );
    cleanup(&path);
}

#[test]
fn the_id_query_matches_a_kept_chain_after_the_cap_is_gone() {
    // A reader that kept a cap's ids and dropped the cap asks the same question `is_revoked` does. Zero
    // ids, an unrevoked chain, and a chain holding the revoked leaf, from the ids alone.
    let parent = cap_rooted_at(1);
    let child = parent
        .attenuate(None, Some(far_expiry()))
        .expect("holder narrows");
    let (parent_ids, child_ids) = (parent.revocation_ids(), child.revocation_ids());
    drop((parent, child));

    let path = scratch("id-query");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(
            &Held,
            [Revocation::Id(
                child_ids.last().expect("a chain has a block").clone(),
            )],
        )
        .expect("revoke the leaf");

    assert!(!denylist.is_revoked_any(&[]), "no ids, nothing revoked");
    assert!(
        !denylist.is_revoked_any(&parent_ids),
        "the parent's chain does not carry the leaf"
    );
    assert!(
        denylist.is_revoked_any(&child_ids),
        "the child's kept chain carries the revoked leaf"
    );
    cleanup(&path);
}

#[test]
fn a_shared_store_answers_as_the_store_it_shares() {
    // One instance behind an `Arc` backs a gate and a second reader; a revoke through it is seen by both.
    let cap = cap_rooted_at(1);
    let path = scratch("shared");
    let denylist = Denylist::for_repair(path.clone());
    denylist
        .revoke(
            &Held,
            [
                Revocation::Id(cap.root_revocation_id().expect("an authority block")),
                Revocation::Key(key(4)),
            ],
        )
        .expect("revoke");
    let shared = Arc::new(denylist);
    let oracle: &dyn Revocations = &shared;
    assert!(oracle.is_revoked(&cap), "the shared store refuses a cap");
    assert!(oracle.is_revoked_peer(&key(4)), "and a peer");
    assert!(!oracle.is_revoked(&cap_rooted_at(2)), "and nothing else");
    cleanup(&path);
}

#[test]
fn eight_threads_through_one_instance_all_survive() {
    // One instance shared by eight writers under one guard: nothing but the per-file write slot orders
    // their read-merge-writes, and unordered the smaller body lands last under a larger witness.
    for round in 0..20 {
        let path = scratch(&format!("eight-{round}"));
        let denylist = Arc::new(Denylist::for_repair(path.clone()));
        let barrier = Arc::new(Barrier::new(8));
        let writers = (0..8)
            .map(|n| {
                let (denylist, barrier) = (Arc::clone(&denylist), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    denylist
                        .revoke(&Held, [Revocation::Id(id(n))])
                        .expect("revoke");
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().expect("the writer finishes");
        }

        let fresh = Denylist::load(path.clone()).expect("every Ok write is on disk, none lost");
        assert!(
            (0..8).all(|n| fresh.is_revoked_any([&id(n)])),
            "round {round}: every writer's id is on disk"
        );
        cleanup(&path);
    }
}

#[test]
fn one_guard_over_two_instances_loses_no_revocation() {
    // Two instances over one file, one guard: both return `Ok`, so both entries must be on disk. Per
    // instance ordering alone lets one rename land over the other.
    for round in 0..50 {
        let path = scratch(&format!("two-instances-{round}"));
        let (first, second) = (
            Denylist::load(path.clone()).expect("load"),
            Denylist::load(path.clone()).expect("load"),
        );
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                first
                    .revoke(&Held, [Revocation::Id(id(1))])
                    .expect("revoke");
            });
            scope.spawn(|| {
                barrier.wait();
                second
                    .revoke(&Held, [Revocation::Id(id(2))])
                    .expect("revoke");
            });
        });

        let fresh = Denylist::load(path.clone()).expect("fresh load");
        assert!(
            fresh.is_revoked_any([&id(1)]) && fresh.is_revoked_any([&id(2)]),
            "round {round}: both Ok revocations are on disk"
        );
        cleanup(&path);
    }
}

#[cfg(unix)]
#[test]
fn a_lock_for_one_file_is_refused_on_another() {
    let dir = std::env::temp_dir().join(format!(
        "nauthy-denylist-wrong-lock-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("provision the store dir");
    let (this, other) = (dir.join("revoked"), dir.join("other"));
    let denylist = Denylist::for_repair(this.clone());

    let foreign = Denylist::for_repair(other)
        .lock()
        .expect("lock the other file");
    assert!(
        matches!(
            denylist.revoke(&foreign, [Revocation::Key(key(1))]),
            Err(DenylistError::WrongLock { .. })
        ),
        "a guard for another file is refused"
    );
    assert!(!this.exists(), "and nothing was written");
    assert!(
        denylist.is_revoked_key(&key(1)),
        "the entry still refuses in this process"
    );
    drop(foreign);

    // The same file through another spelling of its directory is the same file.
    std::fs::create_dir_all(dir.join("sub")).expect("make a subdirectory to climb out of");
    let own = Denylist::for_repair(dir.join("sub").join("..").join("revoked"))
        .lock()
        .expect("lock this file");
    denylist
        .revoke(&own, [Revocation::Key(key(1))])
        .expect("a guard for this file is accepted");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_iterator_that_asks_the_store_deadlocks_neither_a_write_nor_a_check() {
    // A caller that filters what it revokes, or what it asks about, through the store itself. Consumed
    // under the store's lock, either iterator re-locks it on the same thread and every check hangs.
    let path = scratch("reentrant");
    let denylist = Arc::new(Denylist::for_repair(path.clone()));
    denylist
        .revoke(&Held, [Revocation::Key(key(1))])
        .expect("revoke");

    let writer = Arc::clone(&denylist);
    let wrote = finishes(move || {
        let keys = [key(1), key(2)];
        writer
            .revoke(
                &Held,
                keys.iter()
                    .filter(|key| !writer.is_revoked_key(key))
                    .copied()
                    .map(Revocation::Key),
            )
            .is_ok()
    });
    assert_eq!(
        wrote,
        Some(true),
        "a write whose entries ask the store returns"
    );

    let reader = Arc::clone(&denylist);
    let asked = finishes(move || {
        let ids = [id(1), id(2)];
        reader.is_revoked_any(ids.iter().filter(|_| !reader.is_revoked_key(&key(9))))
    });
    assert_eq!(
        asked,
        Some(false),
        "a check whose ids ask the store returns"
    );
    assert!(
        denylist.is_revoked_key(&key(2)),
        "and the filtered write landed"
    );
    cleanup(&path);
}

#[test]
fn a_line_that_is_not_utf8_hides_nothing() {
    let path = scratch("not-utf8");
    let denylist = Denylist::load(path.clone()).expect("load the absent file");
    let mut body = id_line(&id(1)).into_bytes();
    body.extend_from_slice(b"\xff\xfe\n");
    body.extend_from_slice(key_line(&key(1)).as_bytes());
    rewrite(&path, &body);

    assert!(
        denylist.is_revoked_any([&id(1)]),
        "the id before the bad bytes"
    );
    assert!(
        denylist.is_revoked_key(&key(1)),
        "the key after the bad bytes"
    );
    assert_eq!(denylist.malformed_line(), Some(2), "the bad line is named");
    assert!(
        matches!(
            Denylist::load(path.clone()),
            Err(DenylistError::Parse { line: 2 })
        ),
        "a load refuses it, naming the line"
    );

    denylist
        .revoke(&Held, [Revocation::Key(key(2))])
        .expect("a write past the bad bytes");
    let written = std::fs::read(&path).expect("read the denylist");
    assert!(
        written.ends_with(b"\xff\xfe\n"),
        "the bad line is carried byte for byte"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_fifo_over_the_file_wedges_neither_a_check_nor_a_load() {
    let path = scratch("fifo");
    let denylist = Arc::new(Denylist::for_repair(path.clone()));
    denylist
        .revoke(&Held, [Revocation::Id(id(1))])
        .expect("revoke");
    let fifo = path.with_extension("fifo");
    make_fifo(&fifo);
    rewrite_with(&fifo, &path);

    let reader = Arc::clone(&denylist);
    assert_eq!(
        finishes(move || reader.is_revoked_any([&id(1)])),
        Some(true),
        "a check returns, and keeps what it held"
    );
    let loading = path.clone();
    assert!(
        matches!(
            finishes(move || Denylist::load(loading)),
            Some(Err(DenylistError::Io(_)))
        ),
        "a load returns, refusing what is not a regular file"
    );
    let _ = std::fs::remove_file(&path);
    cleanup(&path);
}

/// Make a FIFO at `path`, replacing whatever was there.
#[cfg(unix)]
fn make_fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;

    let _ = std::fs::remove_file(path);
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no interior nul");
    // SAFETY: `name` is a valid nul-terminated path for the duration of the call; `mkfifo` only creates a
    // directory entry and touches no memory of ours.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// Rename `from` over `path` and wait past the stat debounce.
#[cfg(unix)]
fn rewrite_with(from: &Path, path: &Path) {
    std::fs::rename(from, path).expect("rename over the denylist");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));
}

#[test]
fn a_write_that_would_cross_the_cap_is_refused() {
    // Fill the file to within one line of its cap. An `Ok` that grew it past the cap would leave a file
    // the next load refuses.
    let path = scratch("cap");
    let line_len = id_line(&id(0)).len();
    let lines = (4 << 20) / line_len;
    let body = (0..lines)
        .map(|n| {
            let n = u32::try_from(n).expect("fits");
            let mut bytes = vec![0_u8; 64];
            bytes[..4].copy_from_slice(&n.to_be_bytes());
            id_line(&RevocationId::from_bytes(bytes))
        })
        .collect::<String>();
    std::fs::write(&path, &body).expect("fill the denylist");
    let denylist = Denylist::load(path.clone()).expect("a file at the cap loads");

    assert!(
        matches!(
            denylist.revoke(&Held, [Revocation::Key(key(1))]),
            Err(DenylistError::TooLarge)
        ),
        "a write past the cap is refused"
    );
    assert_eq!(
        std::fs::metadata(&path).expect("stat").len(),
        u64::try_from(body.len()).expect("fits"),
        "and the file is untouched"
    );
    assert!(
        Denylist::load(path.clone()).is_ok(),
        "so the next load still reads it"
    );
    cleanup(&path);
}

#[test]
fn a_repeat_revoke_raises_a_lagging_witness() {
    // A crash between the body's rename and the witness leaves the witness behind the file. A later write
    // of an entry the file holds must still raise it, or a restore that drops that entry loads clean.
    let path = scratch("lagging");
    std::fs::write(
        &path,
        format!("{}{}{}", id_line(&id(1)), id_line(&id(2)), id_line(&id(3))),
    )
    .expect("write three entries");
    std::fs::write(witness_path(&path), "2\n").expect("a witness one write behind");

    Denylist::load(path.clone())
        .expect("load")
        .revoke(&Held, [Revocation::Id(id(3))])
        .expect("revoke an entry the file holds");

    assert_eq!(witness(&path), "3\n", "the witness catches up");
    cleanup(&path);
}

#[test]
fn an_unbounded_witness_is_refused() {
    // A witness is a count and a newline. One padded without bound is not read to its end.
    let path = scratch("long-witness");
    std::fs::write(&path, id_line(&id(1))).expect("write the denylist");
    std::fs::write(witness_path(&path), format!("1{}", " ".repeat(4096))).expect("pad the witness");
    assert!(
        matches!(Denylist::load(path.clone()), Err(DenylistError::Io(_))),
        "an overlong witness is refused, not trusted"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_planted_temp_name_is_not_followed() {
    let path = scratch("planted");
    let victim = path.with_extension("victim");
    std::fs::write(&victim, "untouched\n").expect("write the victim");
    let planted = path.with_extension("planted");
    let _ = std::fs::remove_file(&planted);
    std::os::unix::fs::symlink(&victim, &planted).expect("plant a symlink");

    assert!(
        crate::revocations::open_tmp(&planted).is_err(),
        "an existing temp name is not opened"
    );
    assert_eq!(
        std::fs::read_to_string(&victim).expect("read the victim"),
        "untouched\n",
        "and what it points at is not truncated"
    );
    let _ = std::fs::remove_file(&planted);
    let _ = std::fs::remove_file(&victim);
    cleanup(&path);
}

/// A fresh, empty directory unique to this test and thread.
fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nauthy-denylist-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("provision the store dir");
    dir
}

#[test]
fn two_spellings_of_one_file_share_one_writer_slot() {
    // One file reached by two names: through a `..`, and, where the filesystem folds them, in another
    // case or another Unicode normalization. Keyed by name, the two instances get two slots, write at once
    // under one guard, and one `Ok` revocation is lost with no `Lost`.
    let dir = scratch_dir("spellings");
    std::fs::create_dir_all(dir.join("sub")).expect("make a subdirectory to climb out of");
    let pairs = [
        (
            dir.join("revoked"),
            dir.join("sub").join("..").join("revoked"),
        ),
        (dir.join("deny"), dir.join("DENY")),
        (dir.join("caf\u{e9}"), dir.join("cafe\u{301}")),
    ];
    for (first, second) in pairs {
        std::fs::write(&first, "").expect("create the file by its first name");
        let one_file = second.exists();
        cleanup(&first);
        if !one_file {
            // This filesystem keeps the two names apart: two files, two denylists, nothing shared.
            continue;
        }
        for round in 0..30 {
            let (a, b) = (
                Denylist::load(first.clone()).expect("load"),
                Denylist::load(second.clone()).expect("load"),
            );
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    a.revoke(&Held, [Revocation::Id(id(1))]).expect("revoke");
                });
                scope.spawn(|| {
                    barrier.wait();
                    b.revoke(&Held, [Revocation::Id(id(2))]).expect("revoke");
                });
            });
            let fresh = Denylist::load(first.clone()).expect("fresh load");
            assert!(
                fresh.is_revoked_any([&id(1)]) && fresh.is_revoked_any([&id(2)]),
                "{} and {}, round {round}: both Ok revocations are on disk",
                first.display(),
                second.display()
            );
            cleanup(&first);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_lock_is_refused_once_its_directory_is_replaced() {
    // The guard names the same path, but the directory at that path is a new one, whose writers take the
    // new `.lock`. The old lock excludes none of them.
    let dir = scratch_dir("replaced-dir");
    let path = dir.join("revoked");
    let denylist = Denylist::for_repair(path.clone());
    let held = denylist.lock().expect("lock");
    let moved = dir.with_extension("old");
    let _ = std::fs::remove_dir_all(&moved);
    std::fs::rename(&dir, &moved).expect("move the store dir away");
    std::fs::create_dir_all(&dir).expect("recreate it");
    let _ = Denylist::for_repair(path.clone())
        .lock()
        .expect("another writer locks the new directory's lock file");

    assert!(
        matches!(
            denylist.revoke(&held, [Revocation::Key(key(1))]),
            Err(DenylistError::WrongLock { .. })
        ),
        "a guard on the replaced lock file is refused"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&moved);
}

#[cfg(unix)]
#[test]
fn a_fifo_at_the_lock_path_does_not_wedge_lock() {
    let path = scratch("lock-fifo");
    make_fifo(&crate::revocations::lock_path(&path));
    let locking = path.clone();
    assert!(
        matches!(
            finishes(move || Denylist::for_repair(locking).lock().map(drop)),
            Some(Err(DenylistError::Io(_)))
        ),
        "lock returns, refusing what is not a regular file"
    );
    cleanup(&path);
}
