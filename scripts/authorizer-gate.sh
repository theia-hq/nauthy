#!/bin/sh
# authorizer-gate.sh -- datalog never runs on a budget nobody set.
#
# THE RULE (STYLE.md "A guard's test must fail when the guard is removed"). Every biscuit
# `Authorizer` in this crate is built by `Cap::budgeted_authorizer` in src/cap.rs, which sets
# `AUTHORIZER_LIMITS` on the BUILDER before it builds. No other site may construct one.
#
# WHY THE BUDGET IS LOAD-BEARING. biscuit stores the limits on the authorizer, so they are fixed at
# BUILD time and apply to every later `authorize` and `query`; a site that builds its own gets the
# library default of ONE MILLISECOND of wall clock no matter what it passes afterwards. A loaded host
# then runs out of clock mid-evaluation, and the evaluator reports that as a failure to prove the
# policy: a VALID capability refused, its holder told the authority did not grant, when in truth
# nothing was decided. Load is attacker-suppliable, so that is a denial an attacker can manufacture.
# Routing every evaluation through one budgeted builder is what keeps "out of time" distinguishable
# from "not authorized".
#
# WHY A GATE AND NOT A TEST. No test can hold this. The deterministic limits (`max_facts`,
# `max_iterations`) deliberately match the library's own defaults, so the ONLY observable difference
# between the funnel and a bypass is wall clock, and a test that can tell 1 ms from 1 s is precisely
# the clock race the budget exists to prevent. A test that passes either way is worse than no test: it
# reports the protection as covered. Swapping one budgeted call for the shorthand leaves the whole
# suite green, which is how this invariant sat held by a comment alone. STYLE.md's answer for a guard
# no test can reach is a mechanical gate over the source, which is this file.
#
# WHAT IT CHECKS. Every `*.rs` in the tree, for the two spellings that materialize an `Authorizer`:
#
#   .authorizer(              `Biscuit::authorizer()`, the shorthand that builds on biscuit's
#                             unbudgeted defaults. Forbidden EVERYWHERE, including inside the funnel:
#                             the funnel has no use for it, so the one exempt region is not a place to
#                             hide it.
#   .build(&<expr naming a token>)
#                             `AuthorizerBuilder::build(&self, token: &Biscuit)`. Permitted only in
#                             the funnel's own body, which is where it belongs.
#
# WHY NOT A BARE `.build(`. The other thing spelled `.build(` here is `BiscuitBuilder::build(&self,
# root: &KeyPair)`, which MINTS a token (six call sites, all `.build(&self.root)`). Matching the bare
# word would fire on every one of them on day one, and a gate that cries wolf gets disabled. The two
# are told apart by their arguments, which is not a coincidence of today's naming but a consequence of
# their signatures: one consumes the `&Biscuit` being authorized, spelled for its role (`token`) or
# its type (`biscuit`); the other consumes signing key material, spelled `root` or `keypair` and never
# either word.
#
# THE EXCEPTION IS NAMED, NOT PATTERN-MATCHED. The exempt region is found by locating
# `fn budgeted_authorizer` in src/cap.rs and following its braces to the end of its body, so the
# exemption is tied to that function by NAME and moves with it. A predicate shaped to dodge the
# funnel's text instead (say, ignoring `set_limits` lines) would exempt any site that copied the
# spelling. If the funnel is renamed or moved, the anchor is gone and this gate FAILS rather than
# silently exempting nothing: losing the funnel is the thing it is watching for.
#
# ESCAPE HATCH. None, deliberately. An allow-marker is a pattern-dodge with a comment on it, and the
# whole point is that there is exactly ONE place an authorizer is built. A site that genuinely needs a
# second one is a design change, which is a conversation, not a suppression.
#
# Dependency-free: POSIX sh + grep + awk. Run from a repo root (or pass a root path):
#   sh scripts/authorizer-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"
cd "$ROOT"

FUNNEL_FILE="src/cap.rs"
FUNNEL_FN="budgeted_authorizer"

# `Biscuit::authorizer()`: the unbudgeted shorthand. No exception, anywhere.
SHORTHAND='\.authorizer\('
# `AuthorizerBuilder::build(&token)`: legal only inside the funnel. The argument is matched, not the
# bare `.build(`, so the six `.build(&self.root)` MINT calls never match (see the header).
BUILD_WITH_TOKEN='\.build\(&[^)]*([Tt]oken|[Bb]iscuit)'

# ---------------------------------------------------------------------------------------
# Locate the funnel's body: the line declaring `fn <FUNNEL_FN>(` through the line that closes it.
# Brace-counted from the first `{` after the declaration, because the signature wraps across lines
# (`pub(crate) fn budgeted_authorizer(\n &self,\n ...\n) -> Result<..> {`) so the opening brace is not
# on the declaring line. Emits "START END"; END is 0 if the body never closes, START 0 if the
# function is not there at all. Both are failures, handled below.
# ---------------------------------------------------------------------------------------
range=$(awk -v pat="(^|[^A-Za-z0-9_])fn[[:space:]]+${FUNNEL_FN}[^A-Za-z0-9_]" '
  start == 0 && $0 ~ pat { start = NR }
  start > 0 {
    line = $0
    opens = gsub(/[{]/, "{", line)
    closes = gsub(/[}]/, "}", line)
    depth += opens - closes
    if (opens > 0) { entered = 1 }
    if (entered && depth <= 0) { print start, NR; done = 1; exit }
  }
  END { if (!done) { print start + 0, 0 } }
' "$FUNNEL_FILE")

funnel_start=${range% *}
funnel_end=${range#* }

if [ "$funnel_start" -eq 0 ]; then
  printf 'authorizer-gate: FAIL -- no `fn %s` in %s.\n' "$FUNNEL_FN" "$FUNNEL_FILE" >&2
  printf 'The one budgeted authorizer is gone or renamed, so nothing funnels the datalog budget.\n' >&2
  exit 1
fi
if [ "$funnel_end" -eq 0 ]; then
  printf 'authorizer-gate: FAIL -- the body of `fn %s` in %s does not close.\n' \
    "$FUNNEL_FN" "$FUNNEL_FILE" >&2
  exit 1
fi

files=$(find . -name '*.rs' -not -path '*/target/*' -not -path '*/_archived/*' | sort)

fail=0
hits=0
scanned=0

for f in $files; do
  [ -f "$f" ] || continue
  scanned=$((scanned + 1))

  found=$(grep -nE "$SHORTHAND" "$f" 2>/dev/null || true)

  builds=$(grep -nE "$BUILD_WITH_TOKEN" "$f" 2>/dev/null || true)
  # Inside the funnel's own body, the builder call is the funnel doing its job.
  if [ "$f" = "./$FUNNEL_FILE" ] && [ -n "$builds" ]; then
    builds=$(printf '%s\n' "$builds" \
      | awk -F: -v s="$funnel_start" -v e="$funnel_end" 'NF && ($1 < s || $1 > e)')
  fi

  found=$(printf '%s\n%s\n' "$found" "$builds" | grep -v '^$' | sort -t: -k1,1n -u || true)
  [ -n "$found" ] || continue

  printf 'UNBUDGETED %s\n' "$f"
  printf '%s\n' "$found" | sed 's/^/        /'
  hits=$((hits + $(printf '%s\n' "$found" | grep -c .)))
  fail=1
done

if [ "$fail" -ne 0 ]; then
  printf '\nauthorizer-gate: FAIL -- %s authorizer(s) built outside Cap::%s.\n' "$hits" "$FUNNEL_FN" >&2
  printf 'Route it through Cap::%s. biscuit fixes the limits at build time, so an authorizer built\n' \
    "$FUNNEL_FN" >&2
  printf 'anywhere else evaluates on the 1 ms default and a busy host reads as a denial.\n' >&2
  exit 1
fi
printf 'authorizer-gate: OK -- %s file(s) clean; the only authorizer is Cap::%s (%s:%s-%s).\n' \
  "$scanned" "$FUNNEL_FN" "$FUNNEL_FILE" "$funnel_start" "$funnel_end"
