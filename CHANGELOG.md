# Changelog

All notable changes to nauthy, newest first.

## Unreleased

### Changed
- **`FileDenylist` no longer creates its parent directory.** Provisioning the directory the denylist lives
  in, and its permissions, is the consumer's responsibility; `FileDenylist` writes only its own file,
  owner-only (`0600` on Unix). A consumer that relied on `persist` creating the directory must now create
  it beforehand.

### Added
- **`Link`**, the typed `sheer:` link: `Link::mint`, `Link::mint_bound`, `Link::mint_signet`, `Link::seal`,
  `Link::narrow`, and `Link::revoke`, with `FromStr` validating the signature chain at the wire edge.
- **`Admitted::origin()`**, exposing an `Origin` (`Rooted` or `Open`) on the admission witness, so a
  handler can refuse an open-gate admission even when its route reached it.
- **`Refusal` implements `Error`**, so a refusal threads through a typed error chain.
- **`DESIGN.md`**, the why/compromise/factored-in rationale for each major design choice, linked from the
  README.

### Fixed
- **Concurrent revocations no longer drop one.** `FileDenylist` writers take an exclusive lock on a sibling
  `<path>.lock`, re-read under it, and write the union, so two processes revoking different ids both keep
  them; the rewrite is atomic (a unique temp file, then a rename).
- **Live reload spots a same-tick change.** The freshness stamp is `(mtime, len)`, so a revocation written
  within one coarse mtime tick is still picked up.

## 0.1.0

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
