//! The disabled-roots latch: what it reads, that it only ever grows, and the oracle it composes into.

use core::time::Duration;
use std::path::PathBuf;

use crate::VerifyKey;
use crate::cap::{Cap, Identity, Request};
use crate::disabled_roots::{DisabledRoots, DisabledRootsError, Latch};
use crate::revocations::{FileDenylist, Revocations, STAT_DEBOUNCE, witness_path};
use crate::service::Service;

fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).expect("valid ed25519 secret")
}

fn root(seed: u8) -> VerifyKey {
    identity(seed).verifying_key()
}

/// A slip rooted at `seed`'s authority.
fn cap_rooted_at(seed: u8) -> Cap {
    identity(seed)
        .mint(
            &"ssh".parse::<Service>().expect("valid service"),
            Request::expires_in(Duration::from_secs(3600)),
        )
        .expect("mint")
}

/// A unique latch path per test and thread, cleared of any file and lock a prior run left.
fn latch_path(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nauthy-disabled-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    cleanup(&path);
    path
}

/// The file body a writer would leave for `roots`, one key per line.
fn body(roots: &[VerifyKey]) -> String {
    roots.iter().map(|root| format!("{root}\n")).collect()
}

/// Rewrite the file in place and wait past the stat debounce, so the next check re-reads it.
fn rewrite(path: &PathBuf, text: &str) {
    std::fs::write(path, text).expect("rewrite the latch");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));
}

fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(witness_path(path));
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::revocations::lock_path(path));
}

#[tokio::test]
async fn an_absent_latch_disables_nothing() {
    let path = latch_path("absent");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert!(!latch.is_disabled(root(1)), "no file, no disabled root");
    cleanup(&path);
}

#[tokio::test]
async fn a_loaded_latch_disables_exactly_the_roots_it_names() {
    let path = latch_path("names");
    std::fs::write(&path, body(&[root(1), root(2)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert!(latch.is_disabled(root(1)), "the first named root");
    assert!(latch.is_disabled(root(2)), "the second named root");
    assert!(!latch.is_disabled(root(3)), "a root the file never named");
    cleanup(&path);
}

#[tokio::test]
async fn a_malformed_latch_refuses_to_load() {
    // Fail closed at the edge: a caller never starts on a set it could only partly read.
    let path = latch_path("malformed");
    std::fs::write(&path, format!("{}not-a-key\n", body(&[root(1)]))).expect("write the latch");
    let loaded = DisabledRoots::load(path.clone()).await;
    assert!(
        matches!(loaded, Err(DisabledRootsError::Parse { line: 2, .. })),
        "one bad line fails the whole load, and the error names it"
    );
    cleanup(&path);
}

#[tokio::test]
async fn a_refresh_never_shrinks_the_set() {
    // The latch's defining difference from the denylist. A file rewritten SHORTER is either a mistake or
    // an attempt to revive a root, and a running process must refuse the dropped root either way.
    let path = latch_path("shrink");
    std::fs::write(&path, body(&[root(1), root(2)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert!(latch.is_disabled(root(2)), "held before the rewrite");

    rewrite(&path, &body(&[root(1)]));

    assert!(
        latch.is_disabled(root(2)),
        "a root dropped from the file stays disabled"
    );
    assert!(latch.is_disabled(root(1)), "the root still named stays too");
    cleanup(&path);
}

#[tokio::test]
async fn a_parse_error_keeps_the_last_known_set() {
    let path = latch_path("corrupt");
    std::fs::write(&path, body(&[root(1)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert!(latch.is_disabled(root(1)), "held before the corruption");

    rewrite(&path, "garbage\n");

    assert!(
        latch.is_disabled(root(1)),
        "a corrupted file keeps every root already read"
    );
    cleanup(&path);
}

#[tokio::test]
async fn deleting_the_latch_keeps_the_last_known_set() {
    let path = latch_path("delete");
    std::fs::write(&path, body(&[root(1)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert!(latch.is_disabled(root(1)), "held before the deletion");

    std::fs::remove_file(&path).expect("delete the latch");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));

    assert!(
        latch.is_disabled(root(1)),
        "a deleted file does not re-enable a root in a running process"
    );
    cleanup(&path);
}

#[tokio::test]
async fn a_root_appended_by_another_writer_is_seen() {
    // Live: the first check after load always stats, so no sleep is needed to see this write.
    let path = latch_path("append");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    let mut other = DisabledRoots::load(path.clone())
        .await
        .expect("load another");
    other
        .disable(root(1))
        .await
        .expect("the other writer disables");

    assert!(
        latch.is_disabled(root(1)),
        "a root another process disabled is honored without a restart"
    );
    cleanup(&path);
}

#[tokio::test]
async fn the_file_is_one_key_per_line_in_its_string_form() {
    let path = latch_path("format");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");

    let text = std::fs::read_to_string(&path).expect("read the latch back");
    assert_eq!(
        text,
        format!("{}\n", root(1)),
        "the root, in the form its authority is named by"
    );
    cleanup(&path);
}

#[tokio::test]
async fn two_writers_disabling_different_roots_both_survive_on_disk() {
    // Both load the absent file before either writes, so each is missing the other's root. The union under
    // the lock must keep both, or the second rename would re-enable the first root for every later load.
    let path = latch_path("merge");
    let mut first = DisabledRoots::load(path.clone()).await.expect("load first");
    let mut second = DisabledRoots::load(path.clone())
        .await
        .expect("load second");
    first.disable(root(1)).await.expect("first disables");
    second.disable(root(2)).await.expect("second disables");

    let fresh = DisabledRoots::load(path.clone()).await.expect("fresh load");
    assert!(
        fresh.is_disabled(root(1)),
        "the first writer's root is on disk"
    );
    assert!(
        fresh.is_disabled(root(2)),
        "the second writer's root is on disk"
    );
    cleanup(&path);
}

#[tokio::test]
async fn disabling_again_restores_a_file_a_deletion_lost() {
    // The limit this narrows: a process that STARTS after a deletion trusts every root again. Applying the
    // disable again must put the file back, even though this instance already holds the root.
    let path = latch_path("restore");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");
    std::fs::remove_file(&path).expect("delete the latch");

    latch.disable(root(1)).await.expect("disable again");

    let fresh = DisabledRoots::load(path.clone()).await.expect("fresh load");
    assert!(
        fresh.is_disabled(root(1)),
        "a repeated disable rewrites the file"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn a_persisted_latch_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = latch_path("perms");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");

    let mode = std::fs::metadata(&path)
        .expect("stat the latch")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the latch is written 0600");
    cleanup(&path);
}

#[tokio::test]
async fn the_latch_refuses_a_disabled_root_and_only_that_root() {
    let path = latch_path("oracle");
    let mut disabled = DisabledRoots::load(path.clone()).await.expect("load");
    disabled.disable(root(1)).await.expect("disable");
    let latch = Latch::new(disabled, FileDenylist::empty(PathBuf::new()));

    assert!(
        latch.is_revoked(&cap_rooted_at(1)),
        "a cap rooted at the disabled key"
    );
    assert!(
        !latch.is_revoked(&cap_rooted_at(2)),
        "a cap rooted anywhere else is not over-denied"
    );
    cleanup(&path);
}

#[tokio::test]
async fn the_latch_still_asks_the_inner_store() {
    // Either answer refuses: a clean root with a revoked chain, and a disabled root with a clean chain.
    let latch_file = latch_path("union-latch");
    let deny_file = latch_path("union-deny");
    let mut disabled = DisabledRoots::load(latch_file.clone()).await.expect("load");
    disabled.disable(root(1)).await.expect("disable");
    let revoked = cap_rooted_at(2);
    let mut denylist = FileDenylist::load(deny_file.clone())
        .await
        .expect("load the denylist");
    denylist.revoke(&revoked).await.expect("revoke");
    let latch = Latch::new(disabled, denylist);

    assert!(
        latch.is_revoked(&cap_rooted_at(1)),
        "disabled root, clean chain"
    );
    assert!(latch.is_revoked(&revoked), "clean root, revoked chain");
    assert!(!latch.is_revoked(&cap_rooted_at(3)), "neither");
    cleanup(&latch_file);
    cleanup(&deny_file);
}

// A gate shares its oracle across every connection task, so the composed store must cross threads.
static_assertions::assert_impl_all!(Latch<FileDenylist>: Send, Sync);

#[tokio::test]
async fn one_bad_line_does_not_hide_the_keys_after_it() {
    // A running latch unions every valid line, so a typo or a torn append cannot freeze it at the set it
    // held before, and the bad line is reported rather than silently skipped.
    let path = latch_path("poison");
    std::fs::write(&path, body(&[root(1)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert_eq!(latch.malformed_line(), None, "a clean file reports nothing");

    rewrite(
        &path,
        &format!("{}garbage\n{}", body(&[root(1)]), body(&[root(2)])),
    );

    assert!(
        latch.is_disabled(root(2)),
        "a key after a bad line is still disabled"
    );
    assert_eq!(latch.malformed_line(), Some(2), "the bad line is named");
    cleanup(&path);
}

#[tokio::test]
async fn disable_still_writes_past_a_bad_line_and_keeps_it() {
    // The bad line may be a key form this version cannot read, so a rewrite carries it over verbatim
    // rather than dropping what might be a disabled root.
    let path = latch_path("poison-write");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    std::fs::write(&path, format!("{}bf02future\n", body(&[root(1)]))).expect("poison the latch");

    latch.disable(root(2)).await.expect("disable writes anyway");

    let text = std::fs::read_to_string(&path).expect("read the latch back");
    assert!(
        text.contains(&root(1).to_string()),
        "the key already there stays"
    );
    assert!(text.contains(&root(2).to_string()), "the new key lands");
    assert!(text.contains("bf02future"), "the unreadable line is kept");
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn a_latch_written_before_and_now_missing_or_empty_refuses_to_load() {
    // The witness records that a durable write left one key, so an absent or empty file beside it was
    // lost, not emptied: a crash, a truncation, or a careless delete. Loading it would trust the root again.
    let path = latch_path("lost");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");

    std::fs::write(&path, "").expect("truncate the latch");
    assert!(
        matches!(
            DisabledRoots::load(path.clone()).await,
            Err(DisabledRootsError::Lost {
                expected: 1,
                found: 0,
                ..
            })
        ),
        "an empty file that was written before is lost"
    );

    std::fs::remove_file(&path).expect("delete the latch");
    assert!(
        matches!(
            DisabledRoots::load(path.clone()).await,
            Err(DisabledRootsError::Lost {
                expected: 1,
                found: 0,
                ..
            })
        ),
        "an absent file that was written before is lost"
    );
    cleanup(&path);
}

#[tokio::test]
async fn an_oversized_latch_is_refused_at_load_and_ignored_while_running() {
    let path = latch_path("oversized");
    std::fs::write(&path, body(&[root(1)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");

    let huge = format!("{}{}", body(&[root(2)]), "\n".repeat(2 << 20));
    rewrite(&path, &huge);

    assert!(latch.is_disabled(root(1)), "what was held stays");
    assert!(
        !latch.is_disabled(root(2)),
        "an oversized file is not read on the admit path"
    );
    assert!(
        matches!(
            DisabledRoots::load(path.clone()).await,
            Err(DisabledRootsError::TooLarge)
        ),
        "an oversized file is refused at load"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn a_same_length_replacement_with_the_old_mtime_is_still_seen() {
    // Every key line is the same length, so {R1, R2} and {R1, R3} are the same size. A replacement renamed
    // in with the old mtime put back would pass an `(mtime, len)` stamp unseen; the inode gives it away.
    let path = latch_path("swap");
    std::fs::write(&path, body(&[root(1), root(2)])).expect("write the latch");
    let latch = DisabledRoots::load(path.clone()).await.expect("load");
    assert!(latch.is_disabled(root(1)), "the first check stats the file");
    let mtime = std::fs::metadata(&path)
        .expect("stat the latch")
        .modified()
        .expect("mtime");

    let swap = path.with_extension("swap");
    std::fs::write(&swap, body(&[root(1), root(3)])).expect("write the replacement");
    std::fs::File::options()
        .write(true)
        .open(&swap)
        .expect("open the replacement")
        .set_modified(mtime)
        .expect("put the old mtime back");
    std::fs::rename(&swap, &path).expect("rename the replacement in");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));

    assert!(
        latch.is_disabled(root(3)),
        "a same-length, same-mtime replacement is read"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn a_stranded_lock_is_not_a_witness() {
    // A first write that failed after taking the lock leaves `<path>.lock` and nothing else. Nothing was
    // ever durably recorded, so the absent file loads as the empty set rather than refusing forever.
    let path = latch_path("stranded-lock");
    std::fs::write(crate::revocations::lock_path(&path), "").expect("strand a lock");
    let loaded = DisabledRoots::load(path.clone()).await;
    assert!(
        matches!(loaded, Ok(ref latch) if !latch.is_disabled(root(1))),
        "a lock alone proves nothing was written"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn a_failed_write_leaves_the_witness_untouched() {
    // The witness moves only after the body is durably in place. A rename over a non-empty directory
    // fails, so the body never lands, and the witness must not claim it did.
    let path = latch_path("failed-write");
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
#[tokio::test]
async fn a_truncated_latch_is_lost_at_load() {
    // Not only the empty file: any file shorter than its high-water mark lost keys, and loading it would
    // trust those roots at the next start.
    let path = latch_path("truncated");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    for seed in 1..=3 {
        latch.disable(root(seed)).await.expect("disable");
    }
    std::fs::write(&path, body(&[root(1)])).expect("truncate to one root");
    assert!(
        matches!(
            DisabledRoots::load(path.clone()).await,
            Err(DisabledRootsError::Lost {
                expected: 3,
                found: 1,
                ..
            })
        ),
        "a file below its high-water mark is lost"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn only_a_full_reapply_clears_lost() {
    let path = latch_path("reapply");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");
    latch.disable(root(2)).await.expect("disable");
    std::fs::remove_file(&path).expect("lose the file");

    let mut repair = DisabledRoots::open_for_repair(path.clone());
    repair.disable(root(1)).await.expect("re-apply one");
    assert!(
        matches!(
            DisabledRoots::load(path.clone()).await,
            Err(DisabledRootsError::Lost {
                expected: 2,
                found: 1,
                ..
            })
        ),
        "a partial repair does not quietly trust the rest"
    );

    repair.disable(root(2)).await.expect("re-apply the other");
    let repaired = DisabledRoots::load(path.clone())
        .await
        .expect("a full repair loads");
    assert!(repaired.is_disabled(root(1)) && repaired.is_disabled(root(2)));
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn removing_the_witness_accepts_the_loss() {
    // The documented way out when nothing can be restored: the lock stays, and is never involved.
    let path = latch_path("accept");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");
    std::fs::remove_file(&path).expect("lose the file");
    std::fs::remove_file(witness_path(&path)).expect("accept the loss");

    let loaded = DisabledRoots::load(path.clone())
        .await
        .expect("loads empty");
    assert!(
        !loaded.is_disabled(root(1)),
        "the lost root is trusted again"
    );
    assert!(
        crate::revocations::lock_path(&path).exists(),
        "the lock was never touched"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn the_lost_message_names_the_way_out() {
    let path = latch_path("message");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    latch.disable(root(1)).await.expect("disable");
    std::fs::remove_file(&path).expect("lose the file");

    let Err(error) = DisabledRoots::load(path.clone()).await else {
        panic!("a lost latch must not load");
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
#[tokio::test]
async fn deleting_a_carried_bad_line_does_not_trip_lost() {
    // The witness counts keys, not lines, so an operator who repairs a bad line that a write carried over
    // is not told a root went missing.
    let path = latch_path("bad-line-repair");
    let mut latch = DisabledRoots::load(path.clone()).await.expect("load");
    std::fs::write(&path, format!("{}garbage\n", body(&[root(1)]))).expect("poison the latch");
    latch
        .disable(root(2))
        .await
        .expect("disable carries the bad line");

    std::fs::write(&path, body(&[root(1), root(2)])).expect("repair the bad line");
    assert!(
        DisabledRoots::load(path.clone()).await.is_ok(),
        "a repaired file with every key loads"
    );
    cleanup(&path);
}

#[tokio::test]
async fn the_latch_lends_its_one_instance_to_a_reader_that_kept_roots() {
    // A reader holding a root it kept, not a cap, reaches the same instance the gate asks, so a root
    // disabled through that instance is seen by both with no second load.
    let path = latch_path("lend");
    let disabled = DisabledRoots::load(path.clone()).await.expect("load");
    let latch = Latch::new(disabled, FileDenylist::empty(PathBuf::new()));
    assert!(
        !latch.disabled().is_disabled(root(1)),
        "nothing disabled yet"
    );
    // Disabled through a second writer on the same file, then seen through the lent instance.
    let mut writer = DisabledRoots::open_for_repair(path.clone());
    writer.disable(root(1)).await.expect("disable");
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(20));
    assert!(
        latch.disabled().is_disabled(root(1)),
        "the lent instance sees it"
    );
    assert!(
        latch.is_revoked(&cap_rooted_at(1)),
        "and so does the gate's oracle"
    );
    cleanup(&path);
}
