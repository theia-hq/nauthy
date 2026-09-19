# Changelog

All notable changes to nauthy, newest first.

## v0.3.1

A holder can read when its own grant dies, and the budget funnel is enforced.

### Added
- **`Cap::expiry()`.** A holder could not answer when its own grant expires. The instant lived only
  inside a datalog CHECK, and checks are not facts: a query runs rules over the fact set and can
  never bind a variable to a comparison bound, so no origin-0 read could reach it. The four mints
  now emit an `expires_at` AUTHORITY fact beside the check they already write, from the same
  binding; biscuit dates are whole seconds, so the two cannot disagree. **Advisory only.** The check
  remains the sole enforcement, and an attenuation can only shorten the life while being invisible
  to an origin-0 read, so the value is an UPPER BOUND: a caller refusing early on it can never turn
  away a grant this authority would have admitted. `None` means no fact, never "does not expire".

### Changed
- **`scripts/authorizer-gate.sh` enforces the budget funnel.** Every datalog evaluation must run on
  the explicit budget set on the builder, because the library default is one millisecond of WALL
  CLOCK and a loaded host then reads a timeout as a denial rather than as "undecided". The funnel
  landed in v0.3.0 and nothing enforced it: swapping a budgeted authorizer for the unbudgeted
  default leaves the whole suite green. No test can hold it, since only the time limit differs from
  the defaults and a test that distinguishes one millisecond from one second is the clock race the
  fix exists to prevent. The gate is verified by introducing the violation it forbids, and it is the
  only thing in the crate that can see that violation.

## v0.3.0

A busy host no longer refuses a valid capability.

### Fixed
- **BREAKING: a refusal can now mean "not now".** Every capability check ran on the underlying datalog
  engine's default budget of one millisecond of WALL CLOCK, so a merely loaded host failed the evaluation
  and the failure was read as a denial: the holder was told their authority did not grant, when nothing
  about their authority had been decided. Checks now run under an explicit one-second budget, and an
  evaluation that still runs out of time reports the new `CapError::Undecided` and `Refusal::Undecided`
  instead of a denial. Both are new public variants, so a `match` on either enum must handle them.
  Treat one as transient and retry; never record it as a failed authorization. The deterministic caps
  (facts, rule passes) are unchanged and still refuse a hostile token identically on every host, which is
  what actually bounds the work. A refusal is still a refusal: nothing is admitted on an answer that was
  never computed.

## v0.2.1

A `Link` you can hold by value, and the parsed capability it already carried is now readable.

### Changed
- **`Link` is pointer-sized to hold and exposes its parsed `Cap`.** The cap is boxed inside the link, so a
  `Link` moves by value without dragging a whole token along, and `Link::cap()` hands back the cap the link
  was parsed or minted from, so a consumer that needs its root or its revocation ids reads them instead of
  re-decoding and re-verifying the text. No API removed.

## v0.2.0

A typed `sheer:` link, an admission witness that names its origin, and a denylist that holds under
concurrent writers.

### New
- **`Link`**, the typed `sheer:` link: `Link::mint`, `Link::mint_bound`, `Link::mint_signet`, `Link::seal`,
  `Link::narrow`, and `Link::revoke`, with `FromStr` validating the signature chain at the wire edge.
- **`Admitted::origin()`**, exposing an `Origin` (`Rooted` or `Open`) on the admission witness, so a
  handler can refuse an open-gate admission even when its route reached it.
- **`Refusal` implements `Error`**, so a refusal threads through a typed error chain.
- **`DESIGN.md`**, the why/compromise/factored-in rationale for each major design choice, linked from the
  README.

### Changed
- **`FileDenylist` no longer creates its parent directory.** Provisioning the directory the denylist lives
  in, and its permissions, is the consumer's responsibility; `FileDenylist` writes only its own file,
  owner-only (`0600` on Unix). A consumer that relied on `persist` creating the directory must now create
  it beforehand.

### Fixed
- **Concurrent revocations no longer drop one.** `FileDenylist` writers take an exclusive lock on a sibling
  `<path>.lock`, re-read under it, and write the union, so two processes revoking different ids both keep
  them; the rewrite is atomic (a unique temp file, then a rename).
- **Live reload spots a same-tick change.** The freshness stamp is `(mtime, len)`, so a revocation written
  within one coarse mtime tick is still picked up.

## v0.1.0

The first standalone release: generic capability vocabulary, an offline keygen path, a runtime-free core,
and one coordinated wire/format bump. Tokens and denylist files are not interoperable with any earlier
theia-internal build.

### Changed
- **BREAKING: tokens and denylist files are not interoperable with any earlier theia-internal build.** The
  datalog predicates were renamed (`signet_bound` to `authority_bound`, `fleet_member` to `foreign_member`),
  `sign_document` is now domain-separated, and the denylist file encoding changed from base32 to lowercase
  hex. Regenerate issued tokens and denylist files.
- **BREAKING: the denylist migration is required, not advisory.** An earlier base32 denylist file does not
  load under this release (it fails closed). One-time convert the file base32 to hex, or re-revoke to
  rebuild it; do not rely on the load failure to catch it.
- **Vocabulary genericized.** `Gate::Family` to `Gate::Rooted` (`Gate::family` to `Gate::rooted`);
  `Identity::node_id` to `Identity::verifying_key`; `Identity::mint_signet_slip` to
  `Identity::mint_authority_slip`; `Cap::is_signet_bound` to `Cap::is_authority_bound`;
  `Cap::signet_bound_fleet` to `Cap::authority_bound_root`; `CapError::NotSignetBound` to
  `CapError::NotAuthorityBound`; `Denylist` to `FileDenylist`.
- **`Gate::admit` split by grant shape.** `admit(peer, presented, service)` takes one optional cap; the
  two-token authority-bound AND is now `admit_foreign(peer, slip, badge, service)`, both caps required and
  named. The witnessed forms follow. `admit` now takes a `ProvenPeer`, never a bare `VerifyKey`.
- **Offline verify renamed `verify_*_at_root_without_revocation`,** so it is impossible to miss that these
  skip revocation; `Gate::admit_witnessed` is the admission API. `expires_in` is now `Request::expires_in`.

### New
- **`Identity::generate` / `Identity::from_rng`.** Mint a fresh identity from the OS CSPRNG (`os-rng`
  feature, on by default) or any caller-supplied CSPRNG; the secret bytes are zeroized after use.
- **`Revocations` trait and a runtime-free core.** The gate consults a synchronous `Revocations` oracle, so
  a consumer can back revocation with any store. `FileDenylist` sits behind the `tokio-fs` feature (on by
  default); `--no-default-features` builds the core (trait, `Gate`, `Cap`, `Identity`) with no async runtime.
- **`ProvenPeer`.** A named, greppable point for the one precondition offline auth cannot check: the peer is
  transport-proven. `Gate::admit` takes it instead of a bare key.
- **`sign_document` is domain-separated** with a fixed context tag, so a document signature can never be
  reused as a biscuit block signature.
- **`Decision` is `#[must_use]`** (a dropped authorization decision fails open), and `Admission` is now
  exported so a caller can match `Admitted::kind`.
- **`CapError::Unverified`** splits a signature-chain-verify failure out from the structural
  `CapError::Malformed`.
