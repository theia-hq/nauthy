# nauthy

Decide whether an already-authenticated peer may connect. You hand it a peer's public key (which the
transport has already proven) and a policy, and it returns admit or refuse. Trust roots at a single key
you own: your own devices and anyone you delegate to are admitted by tokens that verify against that
key, offline, with no server, no PKI, and no allowlist to keep in sync.

**The name.** nauthy is the authorization layer: it holds the gate and says who gets in. The name is
*auth* with a wink at *naughty*. Uh huh, nauthy nauthy: the part that turns peers away.

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

A `Gate` is the policy a server applies to an inbound, already-authenticated peer. Two variants:

- `Open` permits any peer that reached the key: the one deliberate opt-out.
- `Family(signet)` permits a peer that presents a signed token rooted at a trusted **signet** (a
  `NodeId` you own). One signature carries two meanings: a **membership badge** ("this is my device",
  admitting the whole node) or a **service slip** ("this friend may reach this service"). Both root at
  the same signet and are verified offline against it.

The signet is a single key you own, not a list of keys to keep in sync. A membership badge *is* the
allowlist, and a better one: delegatable, attenuable, revocable, with nothing to synchronize. That is
the thing a plain allowlist cannot do.

## The capability (`sheer`)

A `Cap` is a bearer token that carries its own grant, verifiable offline. It is a
[biscuit](https://www.biscuitsec.org): an ed25519-signed, datalog-attenuable token. nauthy does not
hand-roll crypto; it wraps biscuit behind a small parse-don't-validate `Cap`.

The root key of a cap is the **signet's own `NodeId`**, so verification asks one question: "does this
token chain back to the signet I trust?" No PKI, no registry, no server.

- **mint** (signet): `Identity::from_secret(&secret)?.mint(&service, expiry)` signs a fresh service
  slip. `mint_member(device, expiry)` instead signs a membership badge bound to a specific device.
- **attenuate** (any holder, offline): `cap.attenuate(Some(&service), Some(shorter_expiry))` appends a
  narrower check. Monotone by construction: a block can only ADD checks, so broadening is impossible,
  and a service slip can never be widened into a membership badge.
- **delegate** (any holder, offline): attenuate, then hand the narrower link onward. The signet verifies
  the whole chain without ever seeing the delegation.
- **verify** (signet): `identity.verify(&cap, &request)` grants iff the cap roots at this signet, the
  service matches, and the token is unexpired.

A share-link is `sheer:<node-id>.<base32-biscuit>`: it carries the signet's public `NodeId` alongside
the token, so a holder can decode and narrow it offline, and a connector learns which node to dial from
the link alone.

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

A `Family` gate consults a node-local **denylist**: `tightbeam revoke` (or the equivalent) appends a
token to a file the next server run reads, and a listed grant is refused offline, with no server to ask.
Short expiry backs it up: a cap that outlives its usefulness expires on its own. Revoking a broad grant
before it expires is the denylist's job.

## License

MIT OR Apache-2.0.
