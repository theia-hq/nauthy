#!/bin/sh
# durable-write-gate.sh -- a store write that returned Ok survives a power cut.
#
# THE RULE. Every persisted store in this crate (the revocation denylist, the disabled-roots latch) is
# replaced through ONE function, `replace_durably` in src/revocations.rs: write a temp sibling, fsync
# it, rename it over the target, fsync the parent directory. No other site may rename a file into place;
# the store body and its `.written` witness both go through it.
#
# WHY IT IS LOAD-BEARING. Without the file fsync, a power cut after the caller saw Ok can leave the
# renamed name pointing at blocks never written, which reads back empty or as garbage. Without the
# directory fsync, the rename itself can be lost and the old body comes back. Either one un-revokes a
# cap or re-trusts a disabled root, silently, after an operator was told it was done.
#
# WHY A GATE AND NOT A TEST. No test can hold this. A test cannot cut the power between the write and
# writeback, and every read in the same boot sees the page cache whether or not anything reached the
# disk, so a test passes identically with the fsyncs deleted. A test that passes either way reports the
# protection as covered, which is worse than none. STYLE.md's answer for a guard no test can reach is a
# mechanical gate over the source, which is this file.
#
# WHAT IT CHECKS.
#   1. `write_and_stamp` calls `sync_all()` on the handle it wrote.
#   2. `replace_durably` renames and then calls `sync_parent`.
#   3. `sync_parent` calls `sync_all()` on the opened directory.
#   4. No `rename(` appears in non-test source outside `replace_durably`.
#
# Held to its own rule: delete any one fsync, or add a rename elsewhere, and watch this fail.

set -eu

ROOT="${1:-.}"
cd "$ROOT"

FILE="src/revocations.rs"

# Print the body of `fn $1` in $FILE, from its signature to the brace that closes it.
body_of() {
  awk -v pat="(^|[^A-Za-z0-9_])fn[[:space:]]+$1[^A-Za-z0-9_]" '
    start == 0 && $0 ~ pat { start = 1 }
    start {
      print
      line = $0
      opens = gsub(/[{]/, "{", line)
      closes = gsub(/[}]/, "}", line)
      depth += opens - closes
      if (opens > 0) { entered = 1 }
      if (entered && depth <= 0) { exit }
    }
  ' "$FILE"
}

fail=0
require() {
  fn=$1
  pattern=$2
  why=$3
  body=$(body_of "$fn")
  if [ -z "$body" ]; then
    printf 'durable-write-gate: FAIL -- no `fn %s` in %s.\n' "$fn" "$FILE" >&2
    fail=1
    return
  fi
  if ! printf '%s\n' "$body" | grep -qE "$pattern"; then
    printf 'durable-write-gate: FAIL -- `fn %s` in %s no longer %s.\n' "$fn" "$FILE" "$why" >&2
    fail=1
  fi
}

require write_and_stamp 'sync_all\(\)' 'fsyncs the handle it wrote'
require replace_durably 'sync_parent\(' 'fsyncs the directory after the rename'
require sync_parent 'sync_all\(\)' 'fsyncs the directory it opened'

# Every rename in non-test source must be the one inside replace_durably.
allowed=$(body_of replace_durably | grep -cE 'rename\(' || true)
total=$(find src -name '*.rs' -not -name '*_tests.rs' -exec grep -hE 'rename\(' {} + | grep -cvE '^[[:space:]]*//' || true)
if [ "$total" -ne "$allowed" ]; then
  printf 'durable-write-gate: FAIL -- %s rename call(s) in src, %s inside `replace_durably`.\n' \
    "$total" "$allowed" >&2
  printf 'A store replaced anywhere else skips the fsyncs that make an Ok survive a power cut.\n' >&2
  fail=1
fi

[ "$fail" -eq 0 ] || exit 1
printf 'durable-write-gate: ok\n'
