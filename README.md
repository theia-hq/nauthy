# nauthy

Offline capability tokens rooted at one key you hold. Mint a grant to reach a service, narrow it, hand
it on, revoke it, all verified against your key with no server, no PKI, and no control plane.

The one thing that sets nauthy apart: a grant roots at the **same ed25519 key a peer already dials you
at**. Where that key is your transport identity (iroh, libp2p, Noise, any ed25519 p2p), authorization
collapses into the key the handshake already proved. There is no second identity to manage, nothing to
phone home to, and verification is local arithmetic against one public key.

```rust
match gate.admit(peer, presented, &service) {
    Decision::Admit => serve(peer).await,
    Decision::Refuse(why) => reject(why),
}
```

> Experimental. The token core is stable; the surrounding API may still change before 1.0.

## Install

```sh
cargo add nauthy
```

The defaults (`tokio-fs`, `os-rng`) give you the shipped file-backed revocation store and one-line key
generation. For a build with no async runtime at all, take the core alone:

```toml
nauthy = { version = "0.1", default-features = false }
```

The core (`Gate`, `Cap`, `Identity`, the `Revocations` trait) needs no runtime. `--no-default-features`
drops `FileDenylist` (bring your own `Revocations`) and `Identity::generate` (use `Identity::from_rng`
with any CSPRNG you supply).

## What you verify, and the one precondition

You verify a presented token offline against one key you hold. No server is ever contacted. The whole
check is: does this token chain back to my key, and do its checks pass right now.

nauthy authorizes an identity; it does not authenticate one. It rests on **one precondition it cannot
check itself**: that a transport handshake has already proven the peer holds the private key behind its
public key. That is what `ProvenPeer::from_handshake` marks. It is a well-marked contract at a single
seam you audit, not a guarantee the type system proves: nauthy has no transport to check, so you must
call it only from the code that finished the handshake, with the key the handshake proved. Every
device-bound grant rests on that one call being honest.

## The grants

One key signs four token shapes, plus one policy that needs no token. Each answers one question:

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

use nauthy::{Cap, Decision, FileDenylist, Gate, Identity, ProvenPeer, Refusal, Request, Service};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. One key is your whole trust root. Generate a fresh ed25519 identity
    //    (or load a persisted 32-byte secret with `Identity::from_secret`).
    let authority = Identity::generate()?;

    // 2. Mint a grant: reach the "ssh" service, good for one hour.
    let ssh: Service = "ssh".parse()?;
    let cap = authority.mint(&ssh, Request::expires_in(Duration::from_secs(3600)))?;

    // 3. Hand it out as a link. A holder can narrow it further, offline, with no secret.
    let link = cap.link()?;
    let narrowed =
        Cap::parse(&link)?.attenuate(None, Some(Request::expires_in(Duration::from_secs(600))))?;

    // The transport handshake proved which key the peer holds; mark that fact here.
    // (In a real service this key comes from your transport, not a fresh identity.)
    let peer = ProvenPeer::from_handshake(Identity::generate()?.verifying_key());

    // 4. On your node, decide whether the peer may connect. The gate trusts one key: yours.
    let gate = Gate::rooted(authority.verifying_key(), FileDenylist::load("caps.deny".into()).await?);
    match gate.admit(peer, Some(&narrowed), &ssh) {
        Decision::Admit => println!("admitted"),
        Decision::Refuse(why) => println!("refused: {why}"),
    }

    // 5. Revoke the whole grant. Records the root id, so the cap and every link
    //    narrowed from it are refused from now on, offline.
    let mut denylist = FileDenylist::empty("caps.deny".into());
    denylist.revoke_root(&cap).await?;

    // A gate reading the same denylist now refuses the narrowed link with Refusal::Revoked.
    let gate = Gate::rooted(authority.verifying_key(), FileDenylist::load("caps.deny".into()).await?);
    assert!(matches!(
        gate.admit(peer, Some(&narrowed), &ssh),
        Decision::Refuse(Refusal::Revoked),
    ));
    Ok(())
}
```

For a compile-time proof that a service handler cannot run without a ruling, use `admit_witnessed`, which
returns an `Admitted` witness (single-use, no public constructor) instead of a plain `Decision`. A
handler that takes an `Admitted` cannot be reached without a gate having permitted the peer.

A link is `sheer:<key>.<token>`: it carries the authority's public key beside the token, so a holder can
decode and narrow it entirely offline, and a dialer learns which node to reach from the link alone.

## Revocation

A token verifies offline, so there is no server to ask "is this revoked?". Instead the issuer keeps a set
of revoked ids, and the gate refuses any presented token whose chain includes one. This survives a
restart, which a short expiry cannot: an expiry ages a leaked token out eventually but cannot recall it
now.

- `revoke` records a token's narrowest id: refuses that exact link, but not the grants it was narrowed
  from.
- `revoke_root` records the authority-block id every descendant inherits: refuses the grant and its whole
  delegation tree in one entry.

The shipped `FileDenylist` is a set of ids on disk, checked at connect time and fails closed. It reloads
live when the file changes, so a revocation written by another process takes effect on the next
connection without a restart. Revocation does not evict a session already in progress; short expiry backs
it up.

## The seams: what you bring

nauthy is the authorization layer, and no more. Three seams are yours:

- **A transport-proven peer.** You call `ProvenPeer::from_handshake` from the code that finished the
  handshake. nauthy consumes the proof; it does not perform the handshake.
- **A revocation store.** Use the shipped `FileDenylist`, or implement the one-method `Revocations` trait
  over whatever you keep (a database, Redis, a gossip set). The gate consults it synchronously.
- **Where secrets come from.** An identity is any 32-byte ed25519 secret. Deriving many device secrets
  from one root seed (so one person's devices share an authority) is your identity layer's job; nauthy
  mints a badge for whatever key you name.

nauthy brings the grant vocabulary, offline verification, device binding against replay, the single-use
`Admitted` witness, and the shipped revocation store.

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
let root_id = cap.root_revocation_id().expect("a minted cap has an authority block");
index.insert("alice", root_id.to_hex());          // your directory
// later, revoke by that id:
denylist.revoke_id(RevocationId::from_hex(&index["alice"])?).await?;
```

## The honest limits

- **A bearer slip is a bearer token.** Whoever holds an unexpired, un-revoked one gets that service until
  it expires or you revoke it. Keep bearer slips short-lived; prefer a bound grant where you can.
- **Revocation is node-local.** Revoking on one node does not reach others. An owner running several
  nodes revokes on each. The `FileDenylist` file must live on durable storage: a restart on ephemeral
  storage resurrects every revoked token.
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
shapes, and has been through external security review nauthy has not. If you are not already a
pubkey-transport system, or you need central mutable policy, reach for those.

nauthy is deliberately none of those. It is not a policy engine, not a workload-identity server, and not a
relationship store. It is the zero-infrastructure, capability side of that fork, for systems where your
key is already your identity, and it stays there.

## The name

*nauthy* is *auth* with a wink at *naughty*: the doorkeeper that waves your own in and turns the naughty
away.

## License

MIT OR Apache-2.0.
