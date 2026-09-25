# Changelog

All notable changes to nauthy, newest first.

## v0.10.0

### Breaking
- **A key that is not a usable ed25519 key is refused wherever it enters:** key text (and so a link, a
  pinned authority, or a line of a `DisabledRoots` file) and the signer of a signed blob. A usable key is
  the canonical encoding of a prime-order point. A point off the curve, a non-canonical encoding, a
  small-order point, or a point with a torsion component is refused, and `KeyError` names which.
  `[1u8; 32]` has a torsion component and is refused; the key the seed `[7; 32]` binds prints as
  `ed015jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwa`.
- **`VerifyKey::new` is gone.** `VerifyKey::try_new(bytes)` checks the bytes and returns
  `Result<VerifyKey, KeyError>`.
- **`KeyParseError` is `#[non_exhaustive]` and gains `Key`.** A `match` on it needs a wildcard arm.
- **`SignError` gains `Signer`:** `Signed::decode` refuses a blob whose signer is not a usable key.
  `SignError` is not `#[non_exhaustive]`, so a `match` on it without a wildcard arm no longer compiles.

### Added
- **`KeyError` names the check a key failed:** `NotOnCurve`, `NotCanonical`, `SmallOrder`, or
  `HasTorsion`. It is `#[non_exhaustive]`.

## v0.9.0

### Breaking
- **A link is `<key>.<token>`, with no scheme.** `SCHEME` and `CapError::Scheme` are gone. A link
  carries the authority's key, one `.`, and the token; anything before the key fails to parse as
  `Malformed`, whose message is now "not a link: expected <key>.<token>". An application that shows
  links to people adds and strips its own prefix at its edge.
- **Key text starts with `ed01`**, named for the ed25519 suite. The tag is read in any case. `[1u8; 32]`
  prints as `ed01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq`.
- **Key and token text is ASCII.** Non-ASCII input is refused before decoding, and case is folded with
  ASCII rules only, so no text has a second spelling.

### Added
- **`CapError::MalformedAuthority`**: a capability that pins an authority key that is not a key. Before,
  this reported as a malformed link.

### Fixed
- **`Gate::proven` also refuses a revoked key's sign twin.** Revoking key A closes A and -A; the rustdoc
  now says what a revocation does and does not close.
- **A link with a second `.` is refused as `Malformed`** before any decoding.

## v0.8.0

### Breaking
- **A link is `swoosh:<key>.<token>`.** `SCHEME` is `"swoosh:"`, and a `sheer:` link no longer parses,
  even with a valid token. Re-mint or re-print any stored link.
- **`Origin` has a new variant, `Proven`.** `Origin` is not `#[non_exhaustive]`, so a `match` on it
  without a wildcard arm no longer compiles. Decide at each match site whether that handler accepts a
  proven key with no standing (most should not).

### Added
- **A gate can witness a proven key that presents nothing.** `Gate::proven(peer)` returns an `Admitted`
  whose origin is `Origin::Proven`, for a service that answers a device by its key alone and grants it
  nothing.
  - The witness carries no authority: its kind is `Slip`, so it is never a member, and
    `Admitted::peer_verified` returns `None`.
  - An open gate refuses as `NotGranted`, since its peers proved nothing. A rooted or anchored gate
    refuses a key its store revokes as `Revoked`.
- **`Admitted::revocable_peer`** names the key a later revocation is checked against: the peer's key on
  a `Rooted` or `Proven` admission, `None` on an `Open` one. Record it when you admit a stream if you cut
  live sessions on revocation; a proven admission ruled on no token, so this key is the only handle.

## v0.7.0

### Breaking
- **`Gate` has a new variant, `Anchored`.** `Gate` is not `#[non_exhaustive]`, so a `match` on it
  without a wildcard arm no longer compiles. Add an arm for `Gate::Anchored`. Code that only builds a
  gate and calls its methods is unaffected.

### Added
- **A machine can trust its own key for the service grants it issued.** `Gate::anchored` takes four
  things: a `PinSource`, the machine's own key, a revocation store, and an `IssuedIds` record.
  - The pin is read on every admission, so a root written while the gate serves is trusted at the next
    connection. A token rooted at the pin is ruled exactly as `Gate::rooted` rules. With no pin, no
    token admits a member.
  - A token rooted at the own key is admitted only as a service slip, and only when `IssuedIds` holds
    its root revocation id. Record that id when you mint. A copy of the key mints slips with fresh ids,
    so it cannot mint access. A membership badge the own key signed is refused, even one narrowed to a
    single service, and so is a fleet slip that names the own key as its authority.
  - A pin equal to the own key is no pin.

  Its admissions carry `Origin::Rooted`, and one made under the own key is never a member.
  `PinSource` is implemented for `Arc<P>`. `Gate::wants_capability` answers `true` for an anchored gate.
- **A revocation store can revoke a device's key.** `Revocations::is_revoked_peer` is asked about the
  transport-proven peer before any token is read. A `true` refuses that device whatever it presents,
  including a token minted for it later. It has a default that answers `false`, so an existing store
  keeps its behavior. `Latch` and the `Arc` impl pass the question to the store they wrap. A wrapper of
  your own must do the same, or it answers `false`.
- **`FileStamp` and `STAT_DEBOUNCE` are public**, for a store of your own that reloads a file another
  process writes. `FileStamp::of` stamps a file's metadata (length, mtime and, on unix, inode and
  ctime). `FileStamp::unchanged` compares two stamps. Stat at most once per `STAT_DEBOUNCE`. Both build
  without the `tokio-fs` feature.

### Fixed
- **A file whose platform reports no mtime is now re-read.** `FileDenylist` and `DisabledRoots` held
  no stamp for such a file and compared a missing stamp to a missing stamp as "unchanged", so a
  revocation or a disabled root written by another process was never seen. A missing stamp now always
  means "re-read". A missing or unreadable file still keeps the last set read.

## v0.6.0

### Added
- **`Cap::valid_until` returns the instant a cap's whole chain stops granting.** `Cap::expiry` reads
  only the expiry the authority signed, and a holder who narrows a cap before passing it on can set an
  earlier one that `expiry` never sees. `valid_until` reads the clock checks of every block and returns
  the earliest. `Ok(None)` means nothing in the chain reads the clock. The new
  `CapError::UnreadableExpiry` means a clock check has a shape nauthy never writes; treat that cap as
  expired. The gate denies such a cap.

### Fixed
- **A date past the clock's range no longer panics.** A biscuit date can be any `u64`. A holder could
  append a check dated `u64::MAX` to a slip, and reading its expiry panicked, which in a server ends the
  process. `expiry` and `valid_until` now convert through one checked addition, and a date out of range
  reads as `UnreadableExpiry`.

## v0.5.0

### Breaking
- **Two error enums changed.** `DenylistError` has a new `Lost` variant, and
  `DenylistError` and `DisabledRootsError` are now `#[non_exhaustive]`. A `match` on either needs a
  wildcard arm. Code that only passes the error on with `?` is unaffected. Future variants will not
  break it again.

### Added
- **A node can stop trusting a root key.** `DisabledRoots` is a file of root keys, one `bf01` key per
  line. `Latch` wraps any `Revocations` store and refuses every cap whose root is on that list. A
  denylist can only name grants a key has already signed. This list names the key, so it also refuses
  whatever the key signs later.

  The list only grows. A running process keeps every key it has read, even if the file is rewritten
  shorter, corrupted, or deleted. A line that is not a key does not hide the keys around it, and
  `malformed_line` reports it. Nothing in the API removes a key. The limit: a process that starts after
  both the file and its `.written` witness are gone trusts those roots again. Keep them in a directory
  only the node's user can write.

- **`FileDenylist::is_revoked_any`** answers whether any of a set of revocation ids is revoked, in one
  read. A server that remembers the ids of the caps it admitted can ask, while a session is live, whether
  any of them has since been revoked.
- **`Revocations` is implemented for `Arc<R>`**, so one store can be shared by the gate and by code
  that checks live sessions.

### Fixed
- **A revocation could vanish in a power cut after `revoke` returned.** The file is now flushed to
  disk before it replaces the old one, and so is its directory. A running denylist no longer swaps its
  set for an empty file.
- **A lost or truncated store no longer loads as if nothing were revoked.** Each successful write now
  records how many entries it left in a `<path>.written` file beside the store. `load` refuses a store
  that holds fewer, a missing file included, with `Lost`. The error names three ways out:
  - restore the file;
  - write everything again, through `FileDenylist::empty` or `DisabledRoots::open_for_repair` (this
    clears `Lost` only once every missing entry is back);
  - delete the `.written` file, which accepts the loss.

  Never delete the `.lock` file: writers use it to take turns. A store last written by an earlier
  version has no `.written` file, and gets this protection from its next write.

### Changed
- **The authority-bound check now asks the revocation store about the foreign badge too.** Before,
  it asked only about the slip. With `Latch`, disabling a foreign authority's root refuses all of that
  authority's devices at once. A store keyed on revocation ids is unaffected. A custom store now sees
  foreign badges, and refusing one can only deny, never admit.

## v0.4.0

A token should not be able to name its own cost.

### Fixed
- **A presented capability could pin a verifying thread for as long as it liked.** Measured, not
  argued: a 1.5 KB two-block token burned 1.4 seconds under a one-second budget, and a 1.9 KB one
  burned 9.4 seconds.

  The wall clock could not stop it, and the code's own comment claiming otherwise was wrong. The
  datalog engine samples its fact, iteration and time limits only BETWEEN evaluation passes, while a
  single pass runs to completion, so one expensive join inside one pass is bounded by nothing.

  The bound is structural and runs before evaluation, which is the only place a bound can work: a
  presented token is refused if it carries more facts than nauthy mints, any rule at all, or a check
  wider than nauthy writes. That is sound because nauthy authored its own grammar, so the whitelist
  IS the grammar. It costs 52 microseconds against the 9.4 seconds it guards, and a legitimate slip
  is unchanged at 60.

- **A second bomb walked through that fix, and this one was admitted rather than refused.** A
  legitimate slip and a nested-closure token are identical on every dimension the first bound
  reads, and differ only in whether a check carries a closure, which the bound never looked at.
  Cost is 8^depth on a token growing about 92 bytes per level: at depth 6 the host burned 489
  milliseconds and then GRANTED. Nothing was refused, so nothing logged a refusal.

  nauthy emits no closures anywhere, so the bound is to refuse any, rather than to permit some
  depth. A whitelist over our own grammar has no headroom number that can be set wrong.

  The contract is now stated at the guard: inspect the full shape of a presented token before
  evaluating it, and refuse anything this crate could not itself have minted. It is held by the
  compiler rather than by a comment. The biscuit rule and check types are destructured with no rest
  pattern and its operator type is matched exhaustively, so a release that adds a field or an
  operator stops the build until someone decides what it costs.

- **Revocation is consulted before verification.** A revoked but persistent holder previously spent
  the host's evaluation budget first and was refused afterwards.

### Changed
- **`CapError` is `#[non_exhaustive]` and gains `TooComplex`.** Hardening a capability model adds
  causes, and a consumer that silently inherits a new one is the failure this type exists to
  prevent. Inside the crate, the one place a verification result becomes a decision no longer
  carries a wildcard: a new cause breaks that match until someone rules on it, because the
  fall-through there was a DENIAL, and "I could not decide" must never read as "you are not
  authorized".

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
