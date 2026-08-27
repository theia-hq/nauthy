# nauthy

Authorization for the theia overlay: given a peer identity the transport has already proven, decide
whether it may connect. It sits above [bifrost](https://github.com/theia-hq/bifrost), so reach stays
policy-free and authorization is policy on proven identities.

> Experimental. The capability layer is v1; short-expiry is the only revocation story (see below).

## The gate

A `Gate` is the policy a server applies to an inbound, already-authenticated peer. Four variants, floor
to profound:

- `Open` permits any peer that reached the key.
- `Strict(set)` permits a fixed allowlist of node ids (`authorized_keys`).
- `Paired(approvals)` permits a persisted, consent-grown approved set.
- `Cap(identity)` permits a peer that presents a **capability** which verifies against this node's own
  identity for the requested service.

The first three gate on *who* the peer is. The fourth gates on *what token* the peer presents, and it is
the thing an allowlist cannot do: attenuate, expire, and delegate a grant, with no central authority.

## The capability (`sheer`)

A `Cap` is a bearer token that carries its own grant, verifiable offline. It is a
[biscuit](https://www.biscuitsec.org): an ed25519-signed, datalog-attenuable token. nauthy does not
hand-roll crypto; it wraps biscuit behind a small parse-don't-validate `Cap`.

The root key of a cap is the **exposer's own `NodeId`**, so verification asks one question: "does this
token chain back to the key I am?" No PKI, no registry, no server.

- **mint** (exposer): `Identity::from_secret(&secret)?.mint(&service, expiry)` signs a fresh cap.
- **attenuate** (any holder, offline): `cap.attenuate(Some(&service), Some(shorter_expiry))` appends a
  narrower check. Monotone by construction: a block can only ADD checks, so broadening is impossible.
- **delegate** (any holder, offline): attenuate, then hand the narrower link onward. The exposer verifies
  the whole chain without ever seeing the delegation.
- **verify** (exposer): `identity.verify(&cap, &request)` grants iff the cap roots at this identity, the
  service matches, and the token is unexpired.

A share-link is `sheer:<node-id>.<base32-biscuit>`: it carries the exposer's public `NodeId` alongside
the token, so a holder can decode and narrow it offline, and a connector learns which node to dial from
the link alone.

```rust
use core::time::Duration;
use nauthy::{Cap, Identity, Request, Service, expires_in};

let exposer = Identity::from_secret(&secret)?;
let cap = exposer.mint(&"ssh".parse::<Service>()?, expires_in(Duration::from_secs(3600)))?;
let link = cap.link()?; // sheer:bf01….<token>  -> hand this out

// a holder narrows it, offline, before delegating
let tighter = Cap::parse(&link)?.attenuate(None, Some(expires_in(Duration::from_secs(600))))?;

// the exposer verifies a presented cap at connect time
exposer.verify(&Cap::parse(&tighter.link()?)?, &Request::now("ssh".parse()?))?;
```

## Revocation

**Open, not built.** Biscuits do not revoke cleanly. The v1 answer is **short expiry only**: the expiry
check *is* the revocation story. A revocation-hint channel or short-expiry-plus-refresh is a later design
point, logged, not built.

## License

MIT OR Apache-2.0.
