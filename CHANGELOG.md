# Changelog

All notable changes to nauthy, newest first.

## Unreleased

### New
- **`Identity::mint_bound`** a device-bound service slip: grants one service, usable only by the proven
  device it names. A copy replayed from another key verifies against no one, and it cannot be attenuated
  into an unbound slip or a badge. Standing, theft-resistant, non-delegable.
- **`Identity::mint_signet_slip`** a signet-bound service slip: grants one service to every device a
  foreign signet vouches for. The foreign root is pinned as a constant fact the presenter cannot
  override; the gate admits only after proving membership under that signet, a two-cap flow
  (`Cap::verify_signet_bound_at_root`). Revoking the one slip cuts the whole fleet.
- **Root revocation.** `Denylist::revoke_root` refuses a grant and every narrower link delegated from it,
  in one entry; `Cap::root_revocation_id` recovers the id to key it on. `Denylist::revoke` still refuses
  a single link.
- **`RevocationId`** the revocation-id newtype a denylist entry is stored under, parsed at the boundary
  (`from_hex` / `from_bytes`). `Cap::revocation_ids` reads the ids a link carries and `Denylist::revoke_id`
  refuses one directly, so an issuer can persist revocations and re-apply them by id.
- **`Admitted` names the peer and the admission kind.** The gate's admit witness now carries who was
  admitted and by what authority, `Admission::Member` (a device under this signet) or `Admission::Slip` (a
  delegated capability); `Admitted::is_member` reads it, fail-closed to `Slip` on anything not provably a
  member. A handler can gate on the identity behind an admitted stream.
- **`Signed`, a generic signed-document primitive.** `Identity::sign_document` signs any opaque payload
  with the identity's ed25519 key, and `Signed::verify` roots it at the key you trust. The bytes are
  opaque here, so a consumer canonicalizes and parses its own document; the earlier roster-specific payload
  is gone.
