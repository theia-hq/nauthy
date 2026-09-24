#!/bin/sh
# layering-gate fixture: exercise check 4 of scripts/layering-gate.sh on throwaway git trees, so a
# regression in the layer table, the dependent walk, the word boundary, the path handling or the
# self-exemption fails HERE instead of passing silently in CI. Each case builds a temp repo whose
# root manifest names one layer of the table, carries a copy of the gate, plants one file, and
# asserts the exit code plus a substring of the output. The layers are read from the gate's own
# table by row number, so this file names none of them.
# Dependency-free: POSIX sh + git + awk + grep + sed.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
gate="$here/../layering-gate.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# Which rows depend on each row, directly or not, as the dependency graph stands. Row numbers
# follow the table's order, lowest layer first.
expected_above() {
  case "$1" in
    1) echo "4 5 6 7" ;;
    2) echo "3 4 5 6 7" ;;
    3) echo "4 5 6 7" ;;
    4) echo "5 6 7" ;;
    5) echo "6 7" ;;
    6) echo "7" ;;
    7) echo "" ;;
  esac
}

rows=$(grep -E '^layer [a-z]+ +\| [a-z ]+\|[a-z ]*$' "$gate")
row_count=$(printf '%s\n' "$rows" | grep -c . || true)

# words_of ROW -- every word of that row; first_word_of ROW -- the one a manifest names.
words_of() { printf '%s\n' "$rows" | sed -n "${1}p" | awk -F'|' '{ print $2 }' | xargs; }
first_word_of() { words_of "$1" | awk '{ print $1 }'; }

# mkrepo CASE ROW [ws] -- a git repo whose root manifest identifies as ROW: a root [package]
# named for it, or with `ws`, a virtual workspace whose member carries that name.
mkrepo() {
  repo="$tmp/$1"
  name=$(first_word_of "$2")
  mkdir -p "$repo/scripts" "$repo/src"
  if [ "${3:-}" = ws ]; then
    mkdir -p "$repo/crates/m/src"
    printf '[workspace]\nresolver = "3"\nmembers = [\n    "crates/m",\n]\n' > "$repo/Cargo.toml"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2024"\n' "$name" > "$repo/crates/m/Cargo.toml"
    printf '//! fixture\n' > "$repo/crates/m/src/lib.rs"
  else
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2024"\n' "$name" > "$repo/Cargo.toml"
  fi
  printf '//! fixture\n' > "$repo/src/lib.rs"
  cp "$gate" "$repo/scripts/layering-gate.sh"
  git -C "$repo" init -q
}

# plant CASE PATH TEXT -- write TEXT to PATH in the case's repo and track it.
plant() {
  mkdir -p "$(dirname "$tmp/$1/$2")"
  printf '%s\n' "$3" >> "$tmp/$1/$2"
}

# expect CASE WANT_EXIT NEEDLE LABEL [untracked] -- track the case's files (unless told not to),
# run the gate on its repo and check it.
expect() {
  [ "${5:-}" = untracked ] || git -C "$tmp/$1" add -A
  set +e
  out=$(cd "$tmp/$1" && sh scripts/layering-gate.sh . 2>&1)
  code=$?
  set -e
  if [ "$code" -eq "$2" ] && printf '%s\n' "$out" | grep -qF -- "$3"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    printf 'FAIL  %s: want exit %s with "%s", got exit %s:\n%s\n\n' "$4" "$2" "$3" "$code" "$out"
  fi
}

if [ "$row_count" -ne 7 ]; then
  printf 'FAIL  the gate has %s layer rows; this fixture encodes 7. Update expected_above.\n' "$row_count"
  exit 1
fi

# Every layer computes the forbidden set its dependents give it, and a word from any other row
# fails exactly when that row depends on it.
r=1
while [ "$r" -le 7 ]; do
  kind=""
  [ "$r" -eq 5 ] && kind=ws
  want=""
  for a in $(expected_above "$r"); do want="$want $(words_of "$a")"; done
  want=$(printf '%s\n' $want | sort -u | tr '\n' ' ' | sed 's/ $//')
  mkrepo "set-$r" "$r" "$kind"
  expect "set-$r" 0 "forbids: ${want:-(nothing)}" "row $r computes its forbidden set"
  m=1
  while [ "$m" -le 7 ]; do
    if [ "$m" -ne "$r" ]; then
      mkrepo "word-$r-$m" "$r" "$kind"
      plant "word-$r-$m" src/lib.rs "//! see $(first_word_of "$m") here"
      case " $(expected_above "$r") " in
        *" $m "*) expect "word-$r-$m" 1 "src/lib.rs:2:" "row $r refuses a word of row $m, which depends on it" ;;
        *) expect "word-$r-$m" 0 "OK" "row $r allows a word of row $m, which does not depend on it" ;;
      esac
    fi
    m=$((m + 1))
  done
  r=$((r + 1))
done

top=$(first_word_of 6)
last=$(first_word_of 7)
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
capital() { printf '%s%s' "$(upper "$(printf '%s' "$1" | cut -c1)")" "$(printf '%s' "$1" | cut -c2-)"; }

# A tracked path with a space is read, not split.
mkrepo space 1
plant space "a b/x.md" "made for $top"
expect space 1 "a b/x.md:1:" "a path with a space is scanned"

# An underscore or a hyphen is a boundary, so an env var or a suffixed crate name is caught.
mkrepo underscore 1
plant underscore src/lib.rs "const V: &str = \"$(printf '%s' "$top" | tr '[:lower:]' '[:upper:]')_HOME\";"
expect underscore 1 "src/lib.rs:2:" "an uppercase word before an underscore is caught"
mkrepo hyphen 1
plant hyphen src/lib.rs "//! a $(first_word_of 4)-handler crate"
expect hyphen 1 "src/lib.rs:2:" "a word before a hyphen is caught"

# A word is caught as one hump of an identifier, in every casing a name takes.
for ident in "$(capital "$top")Link" "my$(capital "$top")" "$(capital "$last")Client" "$(upper "$top")2" \
    "${top}Link"; do
  mkrepo "hump-$ident" 1
  plant "hump-$ident" src/lib.rs "struct $ident;"
  expect "hump-$ident" 1 "src/lib.rs:2:" "a word inside the identifier $ident is caught"
done
# A word run into lowercase letters is prose, not a name.
mkrepo prose 1
plant prose src/lib.rs "//! a ${top}ing sound"
expect prose 0 "OK" "a word run into lowercase letters is allowed"

# A tracked path is checked like a line: a file named for a dependent fails with no hit inside it.
mkrepo path 1
plant path "src/$top.rs" "//! fixture"
expect path 1 "src/$top.rs" "a file named for a dependent is caught"
mkrepo pathcap 1
plant pathcap "docs/$(capital "$last")-notes.md" "notes"
expect pathcap 1 "docs/$(capital "$last")-notes.md" "a capitalised word in a path is caught"

# A git read that fails fails the gate instead of reporting a clean scan.
mkrepo broken 1
git -C "$tmp/broken" add -A
printf 'junk' > "$tmp/broken/.git/index"
expect broken 1 "git grep failed" "a failed git grep fails the gate" untracked
mkrepo unreadable 1
plant unreadable notes.md "notes"
git -C "$tmp/unreadable" add -A
chmod 000 "$tmp/unreadable/notes.md"
if [ -r "$tmp/unreadable/notes.md" ]; then
  printf 'skip  an unreadable file cannot be made here (running as root)\n'
else
  expect unreadable 1 "git grep failed" "a file git grep cannot read fails the gate" untracked
fi
chmod 644 "$tmp/unreadable/notes.md"

# The gate checks its own comments: only a table row is exempt, and only in the gate.
mkrepo self 1
plant self scripts/layering-gate.sh "# as $top does it"
expect self 1 "scripts/layering-gate.sh:" "a comment in the gate itself is checked"
mkrepo rowcopy 1
printf '%s\n' "$rows" | sed -n 6p > "$tmp/rowcopy/notes.md"
expect rowcopy 1 "notes.md:1:" "a table row outside the gate is not exempt"

# A CHANGELOG at any depth may keep history.
mkrepo changelog 1
plant changelog CHANGELOG.md "- dropped the $top prefix"
plant changelog crates/x/CHANGELOG.md "- dropped the $top prefix"
expect changelog 0 "OK" "a CHANGELOG may name a dependent"

# A repo the table does not know fails loud instead of checking nothing.
mkrepo unknown 1
sed 's/^name = .*/name = "unlisted"/' "$tmp/unknown/Cargo.toml" > "$tmp/unknown/Cargo.toml.new"
mv "$tmp/unknown/Cargo.toml.new" "$tmp/unknown/Cargo.toml"
expect unknown 1 "no LAYERS row" "an unlisted root package fails"

printf 'layering-gate fixture: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
