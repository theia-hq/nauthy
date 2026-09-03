# nauthy

Decide whether an already-authenticated peer may connect. You hand it a peer's public key (which the
transport has already proven) and a policy, and it returns admit or refuse. Trust roots at a single key
you own: your own devices and anyone you delegate to are admitted by tokens that verify against that
key, offline, with no server, no PKI, and no allowlist to keep in sync. Everyone else, nauthy turns away.

**The name.** *nauthy* is *auth* with a wink at *naughty*: the doorkeeper that waves your own in and
turns the naughty away.

The capabilities are [biscuit](https://www.biscuitsec.org) tokens; nauthy wraps them behind a small,
misuse-resistant API rather than hand-rolling crypto.

```rust
use nauthy::{Gate, Decision};

match gate.admit(peer_id, presented_cap, &service) {
    Decision::Admit => serve(peer_id).await,
    Decision::Refuse(why) => reject(why),
}
```

> Experimental. The capability layer is v1; revocation is a node-local denylist plus short expiry (see
> below).

## The gate

A `Gate` is the policy a node applies to an inbound peer the transport has already authenticated. Two
variants:

- `Gate::Open` admits any peer that reached the key: the one deliberate opt-out.
- `Gate::Family(signet)` admits a peer that presents a token rooted at a **signet**, a `NodeId` you own.
  Everyone else is turned away.

The signet is a single key you own, not a list of keys to keep in sync. Verification asks one question:
does this token chain back to the signet I trust? It is answered on the node, offline. No PKI, no
registry, no server.

Build a family gate with `Gate::family(signet, denylist)`; `Gate::Open` is the constructor for the open
variant.

## The grants

One signet signs every grant. Each is a `Cap` (a token) verified offline against that signet. There are
four shapes, for four questions:

- **Membership badge** (`Identity::mint_member`) answers "this device is mine." Bound to one device's
  key, it admits that device to the whole node, every service. This is how your own machines get in.
- **Device-bound slip** (`Identity::mint_bound`) answers "this one device may reach this one service."
  Bound to the device's key, so a copy is inert for anyone else, and it cannot be delegated. Standing
  access for a single machine.
- **Signet-bound slip** (`Identity::mint_signet_slip`) answers "every device in this person's fleet may
  reach this one service." It pins a foreign signet you name, so every device that signet vouches for,
  now or later, may use it. Theft-resistant, non-delegable. Issue it once to admit a whole person.
- **Unbound slip** (`Identity::mint`) answers "whoever holds this link may reach this one service." A
  bearer token: anyone with a copy may present it. It carries no binding, so a holder can narrow it and
  pass it on. Short expiry is its revocation story.

The law the crypto enforces: a **bound** grant (device or signet) is theft-resistant and cannot be
widened or delegated; a **bearer** grant can be narrowed and delegated but should be short-lived.
Attenuation only ever ADDS checks, so a slip can never be widened into a badge, and a narrower link can
never be broadened back.

The root key of every grant is the **signet's own `NodeId`**, so verification asks one question: "does
this token chain back to the signet I trust?" A share-link is `sheer:<node-id>.<base32-token>`: it
carries the signet's public `NodeId` beside the token, so a holder can decode and narrow it offline, and
a connector learns which node to dial from the link alone.

- **mint** (signet): `Identity::from_secret(&secret)?.mint(&service, expiry)` signs a bearer service
  slip. `mint_member`, `mint_bound`, and `mint_signet_slip` sign the bound forms above.
- **attenuate** (any holder, offline): `cap.attenuate(Some(&service), Some(shorter_expiry))` appends a
  narrower check. Monotone by construction: a block can only ADD checks, so broadening is impossible.
- **delegate** (any holder, offline): attenuate, then hand the narrower link onward. The signet verifies
  the whole chain without ever seeing the delegation. Only a bearer slip is delegable; a bound one is
  inert for anyone but the device or fleet it names.
- **verify** (signet): the gate grants iff the cap roots at this signet, its binding holds for the proven
  dialer, the service matches, and the token is unexpired.

```rust
use core::time::Duration;
use nauthy::{Cap, Identity, Request, Service, expires_in};

let signet = Identity::from_secret(&secret)?;
let cap = signet.mint(&"ssh".parse::<Service>()?, expires_in(Duration::from_secs(3600)))?;
let link = cap.link()?; // sheer:bf01….<token>  -> hand this out

// a holder narrows it, offline, before delegating
let tighter = Cap::parse(&link)?.attenuate(None, Some(expires_in(Duration::from_secs(600))))?;

// the signet verifies a presented cap at connect time
signet.verify(&Cap::parse(&tighter.link()?)?, &Request::now("ssh".parse()?))?;
```

## Revocation

A `Family` gate consults a node-local **denylist**. Revoking a grant appends its id to a file the node
reads; from then on the grant is refused, offline, with no server to ask. `Denylist::revoke` refuses one
link; `Denylist::revoke_root` refuses a grant and every narrower link delegated from it, in one entry.

Revocation is checked at connect time and fails closed: a new connection presenting a revoked grant is
turned away. It does not evict a session already in progress. Short expiry backs it up, a grant that
outlives its use expires on its own; revoking a broad grant before it expires is the denylist's job.

Because the denylist is node-local, an owner running several nodes revokes on each; a revoke on one
does not reach the others.

A signet-bound slip carries one limit worth naming. A gate keys its denylist on grant ids and the
signet a slip pins, never on the fleet's individual devices, which it never sees. So when a device
leaves that fleet (lost or stolen), the fleet's owner can drop it on their side, but a node that
granted the whole fleet cannot tell that one device apart: it stays admitted until the signet-bound
slip itself is revoked or expires. Keep signet-bound slips short-lived so a stray device ages out.

## License

MIT OR Apache-2.0.
