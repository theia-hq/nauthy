# Changelog

All notable changes to nauthy, newest first.

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
- **`ProvenPeer`.** A named, greppable seam for the one precondition offline auth cannot check: the peer is
  transport-proven. `Gate::admit` takes it instead of a bare key.
- **`sign_document` is domain-separated** with a fixed context tag, so a document signature can never be
  reused as a biscuit block signature.
- **`Decision` is `#[must_use]`** (a dropped authorization decision fails open), and `Admission` is now
  exported so a caller can match `Admitted::kind`.
- **`CapError::Unverified`** splits a signature-chain-verify failure out from the structural
  `CapError::Malformed`.
