# nauthy

Capability tokens you can revoke with no server, rooted at one ed25519 key you hold. Mint a grant to
reach a service, narrow it, hand it on, or revoke it; every grant carries an expiry and a revocation id.
Verification is offline against that key, with no PKI and no control plane.

The one thing that sets nauthy apart: a grant roots at the **same ed25519 key a peer already dials you
at**. Where that key is your transport identity (iroh, libp2p, Noise, any ed25519 p2p), authorization
collapses into the key the handshake already proved. There is no second identity to manage, nothing to
phone home to, and verification is local arithmetic against one public key. For a peer who already proved a
transport key, a separate identity layer plus a second signature on every use would be pure overhead;
nauthy spends neither.

```rust
match gate.admit(peer, presented, &service) {
    Decision::Admit => serve(peer).await,
    Decision::Refuse(why) => reject(why),
}
```

> Experimental. The token core is stable; the surrounding API may still change before 1.0.

## Install

```sh
cargo add nauthy --git https://github.com/theia-hq/nauthy --branch main
```

The defaults (`fs`, `os-rng`) give you the file-backed revocation store and one-line key generation. For
a build with no file access, take the core alone:

```toml
nauthy = { git = "https://github.com/theia-hq/nauthy", branch = "main", default-features = false }
```

The core (`Gate`, `Cap`, `Identity`, the `Revocations` trait) reads no file and needs no async runtime.
Without the defaults you lose `Denylist` (bring your own `Revocations`) and `Identity::generate` (use
`Identity::from_rng` with any CSPRNG you supply).

This page describes the default branch; the released docs are at the newest tag.

## What you verify, and the one precondition

You verify a presented token offline against one key you hold. No server is ever contacted. The whole
check is: does this token chain back to my key, and do its checks pass right now.

nauthy authorizes an identity; it does not authenticate one. It rests on **one precondition it cannot
check itself**: that a transport handshake has already proven the peer holds the private key behind its
public key. That is what `ProvenPeer::from_handshake` marks. It is a well-marked contract at a single
point you audit, not a guarantee the type system proves: nauthy has no transport to check, so you must
call it only from the code that finished the handshake, with the key the handshake proved.

## The grants

One key signs four token shapes, plus one policy that needs no token. Each answers one question, and
every grant carries an expiry and a revocation id:

| Grant | Question | Bound to | Delegable |
| ----- | -------- | -------- | --------- |
| open gate (`Gate::Open`) | anyone who reached me | nothing | n/a |
| membership badge (`Identity::mint_member`) | is this device mine? (whole node) | one device | no |
| device-bound slip (`Identity::mint_bound`) | may this device reach this service? | one device | no |
| authority-bound slip (`Identity::mint_authority_slip`) | may any device a named authority vouches for reach this service? | that authority | no |
| bearer slip (`Identity::mint`) | may whoever holds this link reach this service? | nothing | yes |

The law the crypto enforces: a **bound** grant is theft-resistant and non-delegable, because a copy
replayed from a different key verifies against no one. A **bearer** grant is delegable and should be
short-lived, because whoever holds an unexpired copy can use it. Narrowing a token only ever ADDS checks,
so a slip can never be widened into a badge, and a narrowed link can never be broadened back.

## From zero: generate, mint, narrow, verify, revoke

```rust
use core::time::Duration;
use std::sync::Arc;

use nauthy::{
    Cap, Decision, Denylist, Gate, Identity, ProvenPeer, Refusal, Request, Revocation, Service,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. One key is your whole trust root. Generate a fresh ed25519 identity
    //    (or load a persisted 32-byte secret with `Identity::from_secret`).
    let authority = Identity::generate()?;

    // 2. Mint a grant: reach the "ssh" service, good for one hour.
    let ssh: Service = "ssh".parse()?;
    let cap = authority.mint(&ssh, Request::expires_in(Duration::from_secs(3600)))?;

    // 3. Hand it out as a link. A holder can narrow it further, offline, with no secret.
    let link = cap.link()?;
    let narrowed = link.narrow(None, Some(Duration::from_secs(600)))?;

    // The transport handshake proved which key the peer holds; mark that fact here.
    // (In a real service this key comes from your transport, not a fresh identity.)
    let peer = ProvenPeer::from_handshake(Identity::generate()?.verifying_key());

    // 4. On your node, decide whether the peer may connect. The gate trusts one key: yours,
    //    and shares the denylist you revoke through. The link arrives as text; parse it
    //    back into the cap the gate rules on.
    let denylist = Arc::new(Denylist::load("caps.deny".into())?);
    let gate = Gate::rooted(authority.verifying_key(), Arc::clone(&denylist));
    let presented = Cap::parse(narrowed.as_str())?;
    match gate.admit(peer, Some(&presented), &ssh) {
        Decision::Admit => println!("admitted"),
        Decision::Refuse(why) => println!("refused: {why}"),
    }

    // 5. Revoke the whole grant: record its root id, so the cap and every link
    //    narrowed from it are refused from now on, offline. A write takes the lock.
    let guard = denylist.lock()?;
    denylist.revoke(&guard, cap.root_revocation_id().map(Revocation::Id))?;
    drop(guard);

    // The gate reads the same denylist, so it refuses the narrowed link at once.
    assert!(matches!(
        gate.admit(peer, Some(&presented), &ssh),
        Decision::Refuse(Refusal::Revoked),
    ));
    Ok(())
}
```

For a compile-time proof that a service handler cannot run without a ruling, use `admit_witnessed`, which
returns an `Admitted` witness (single-use, no public constructor) instead of a plain `Decision`. The
witness carries the proven peer, the admission kind, and its origin (`Origin::Rooted`, `Origin::Open` or
`Origin::Proven`), so a handler can refuse an open-gate admission even when its route reached it. A
handler that takes an `Admitted` cannot be reached without a gate having permitted the peer.

`gate.proven(peer)` witnesses a proven key that presents nothing, for a service that answers a device by
its key alone. The witness is `Origin::Proven` and carries no authority: its kind is `Slip`,
`peer_verified()` is `None`, and only a handler built for proven keys should accept it. A key the store
revokes is refused, and so is every peer of an open gate, which proved nothing. `revocable_peer()` names
the key to record if you cut live sessions on a later revocation.

## A machine that signs its own grants

`Gate::rooted` trusts one key for good. `Gate::anchored` is for a machine that holds a key of its own
beside the root it trusts:

```rust
let gate = Gate::anchored(pin, own.verifying_key(), denylist, issued);
```

- `pin` is a `PinSource`, asked on every admission, so a root written while the gate serves is trusted at
  the next connection. A token rooted at it is ruled exactly as `Gate::rooted` rules. With no pin, no
  token admits a member.
- A token rooted at `own` is admitted only as a service slip, and only when `issued` (an `IssuedIds`)
  holds its `root_revocation_id`. Record that id when you mint. A copy of the key mints slips with fresh
  ids, so it cannot mint access. A membership badge `own` signed is refused, and so is an authority-bound
  slip that names `own` as its authority.
- A pin equal to `own` is no pin.

Its admissions carry `Origin::Rooted`; one made under `own` is never a member. `PinSource` is implemented
for `Arc<P>`, so the gate and any other reader can share one source.

A link is `<key>.<token>`: it carries the authority's public key beside the token, so a holder can
decode and narrow it entirely offline, and a dialer learns which node to reach from the link alone. The
`Link` type owns that text; parsing validates the signature chain at the wire edge.

## Revocation

A token verifies offline, so there is no server to ask "is this revoked?". Instead the issuer keeps a
denylist, and the gate refuses any token or device that matches it. This survives a restart, which a
short expiry cannot: an expiry ages a leaked token out eventually but cannot recall it now.

`Denylist` keeps that list in one file, one entry per line:

```text
id <hex>
key <ed01...>
```

- An `id` refuses every token whose chain carries it. `link.revoke(&denylist, &guard)` records a link's
  narrowest id: it refuses that link and anything narrowed from it, not the grant it was narrowed from.
  Recording `cap.root_revocation_id()` as a `Revocation::Id` refuses the grant and every link narrowed
  from it.
- A `key` refuses that device whatever it presents, and every token rooted at that key, past and future.

```rust
let denylist = Denylist::load("caps.deny".into())?;
let guard = denylist.lock()?;
link.revoke(&denylist, &guard)?; // this link and its narrowings
denylist.revoke(&guard, cap.root_revocation_id().map(Revocation::Id))?; // the whole grant
denylist.revoke(&guard, [Revocation::Key(lost_device)])?; // a device, for good
```

A write needs a lock that excludes every other writer of the file, in every process. `denylist.lock()`
takes the store's own (unix only). A program that already serializes its writers implements `Exclusive`
on its own guard and passes that instead. A write re-reads the file and writes the union, so two writers
never drop each other's entries.

The file only grows. A running store checks it at connect time, so a revocation another process writes
takes effect on the next connection without a restart; a file that shrinks or disappears un-revokes
nothing. `Denylist::load` refuses a file holding fewer entries than its `<path>.written` witness records.
Revocation does not evict a session already in progress; short expiry backs it up.

When a load or a write refuses, `DenylistError` says why; each variant's docs name the fix.

A store of your own can revoke a device's key too. `Revocations::is_revoked_peer` is asked about the
transport-proven dialer before any token is read, and a `true` refuses that device whatever it presents,
including a token minted for it later. It defaults to `false`, so a store that keeps only token ids
needs nothing new. `Arc` passes the question on to the store it shares; a wrapper of your own must do
the same, or it answers the default.

To reload live as `Denylist` does, use `FileStamp::of`: it takes a file's metadata and returns its
stamp (length, mtime and, on unix, inode and ctime). Stat at most once per `STAT_DEBOUNCE` and re-read
when the stamp differs from the one you read at. `of` returns `None` when the platform reports no mtime.
Treat that as "re-read", never as "unchanged". What a missing file means stays your store's decision:
`Denylist` keeps every entry it holds, because deleting a denylist must never un-revoke.

## The boundaries: what you bring

nauthy is the authorization layer, and no more. Three things are yours:

- **A transport-proven peer.** You call `ProvenPeer::from_handshake` from the code that finished the
  handshake. nauthy consumes the proof; it does not perform the handshake.
- **A revocation store.** Use `Denylist`, or implement the `Revocations` trait (one required method)
  over whatever you keep (a database, Redis, a gossip set). The gate consults it synchronously.
- **Where secrets come from.** An identity is any 32-byte ed25519 secret. Deriving many device secrets
  from one root seed (so one person's devices share an authority) is your identity layer's job; nauthy
  mints a badge for whatever key you name.

nauthy brings the grant vocabulary, offline verification, device binding against replay, the single-use
`Admitted` witness, and the shipped revocation store.

## Three things people build with this

- **Agentic-AI permissioning.** Mint a short bearer slip per task, scoped to the one service the agent
  may reach; revoke it when the task ends.
- **Licensing.** Mint one device-bound slip per customer machine. A copied license file verifies against
  no other key.
- **Membership badges.** Mint one badge per device you own; the gate admits every member with no
  per-service step.

## Recipes

Two patterns you build on nauthy's own primitives.

**An authority directory on `sign_document`.** `Identity::sign_document` signs opaque bytes with the same
key that mints tokens, producing a self-verifying blob. Publish records (a name-to-key mapping, a roster,
a config) that any node may relay and only the authority can forge; a reader verifies each against the
key it trusts before parsing.

```rust
let signed = authority.sign_document(record_bytes);
let wire = signed.encode();                       // serve or gossip this
// on the reader:
let payload = Signed::decode(&wire)?.verify(authority.verifying_key())?;
```

**An audit index on `root_revocation_id`.** A control-plane-free system has no queryable "who has access
now". If you need one, build it: at mint time record `cap.root_revocation_id()` beside the grantee. Later
you can list outstanding grants, and revoke one by its id alone, without still holding the token.

```rust
if let Some(root_id) = cap.root_revocation_id() {
    index.insert("alice", root_id.to_hex());          // your directory
}
// later, revoke by that id:
let root_id = RevocationId::from_hex(&index["alice"])?;
denylist.revoke(&denylist.lock()?, [Revocation::Id(root_id)])?;
```

## The limits

- **A refusal can mean "not now".** If this host is too loaded to finish evaluating a token, the gate
  refuses with `Refusal::Undecided`. That is a transient local condition and says nothing about the
  holder, so retry it, do not count it as a failed authorization, and if you put refusals on a wire, do
  not send it as the same "not admitted" the other refusals send.
- **A bearer slip is a bearer token.** Whoever holds an unexpired, un-revoked one gets that service until
  it expires or you revoke it. Keep bearer slips short-lived; prefer a bound grant where you can.
- **Revocation is node-local.** Revoking on one node does not reach others. An owner running several
  nodes revokes on each. Keep the denylist file and its `<path>.written` witness on durable storage: a
  restart that finds both gone loads an empty list and resurrects every revoked token and key.
- **An authority-bound slip cannot single out one device** of the foreign authority it names; it sees
  only that authority, never its individual devices. When a device leaves that authority, revoke the slip
  or let it expire. Keep these short-lived.
- **No queryable source of truth.** There is no central "who has access right now"; you revoke by id
  after the fact, and see outstanding grants only if you keep the audit index above. This is the trade:
  auditability for zero infrastructure. If you must answer "who has access" from a central authority for
  compliance, nauthy is the wrong tool.
- **The clock matters.** Expiry is checked against the local clock; a badly-wrong clock widens or voids a
  grant's window.

## nauthy and UCAN, and why the fusion

nauthy sits in the same niche as [UCAN](https://github.com/ucan-wg/spec): offline-verifiable, attenuable,
delegable capability tokens with no control plane. Over UCAN, nauthy roots at the transport key rather
than a separate DID identity layer (UCAN recommends per-context keys that do NOT move between contexts);
its device binding falls out of the transport proof rather than a second signature on every use; and it
is one small Rust dependency, not a spec ecosystem. Over [DPoP (RFC 9449)](https://www.rfc-editor.org/info/rfc9449),
which standardizes the same replay defense, nauthy needs no OAuth server and binds to the key the
transport already proved rather than a fresh one.

Own what they have that nauthy does not: UCAN has cross-language libraries, spec governance, and adopters;
DPoP is a finalized IETF standard in broad production use. The token core under nauthy is
[Eclipse Biscuit](https://www.biscuitsec.org), which gives full datalog where nauthy gives five fixed
shapes (an illegal state you cannot represent beats an expressive one you can misconfigure), and has been
through external security review nauthy has not. If you are not already a pubkey-transport system, or you
need central mutable policy, reach for those.

nauthy is deliberately none of those. It is not a policy engine, not a workload-identity server, and not a
relationship store. It is the zero-infrastructure, capability side of that fork, for systems where your
key is already your identity, and it stays there.

The reasoning behind each of these choices (why it is the way it is, what it costs, and what was weighed)
is in [DESIGN.md](DESIGN.md).

## The name

*nauthy* is *auth* with a wink at *naughty*: the doorkeeper that waves your own in and turns the naughty
away.

## License

MIT OR Apache-2.0.
