# Why nauthy is shaped this way

nauthy makes a handful of deliberate choices, each one trading breadth for a sharp fit to a single job:
authorize a peer who already holds an ed25519 key, offline, with no server. This doc records each choice:
why it is the way it is, what it costs, and what was weighed against it. If a choice looks narrow, that is
the point; here is the reasoning so you can judge whether the fit is yours.

## Rooting a grant at the transport key

**Why.** A grant roots at the same ed25519 key a peer already dials you at. Where that key is the peer's
transport identity, the transport handshake has already proven the peer holds it, so authorization needs
no second identity to manage and no per-use signature to check. The proof you already have is the proof
the grant rests on.

**The compromise.** The payoff exists only where the peer HAS a proven transport key. Drop nauthy into a
system with no such key (a browser session, a wallet, a workload with no p2p handshake) and the fusion
buys nothing: you are left with a curated token layer and must supply the binding some other way.

**Factored in.** The strongest capability systems keep authorization identity separate from transport
identity on purpose: they recommend per-context keys that do not move between contexts, so a leak in one
place cannot travel. nauthy takes the opposite bet for one specific reader, the pubkey-transport peer, for
whom a separate identity layer plus a second signature on every use is pure overhead. This is a divergence
made with eyes open, not an omission.

## Five fixed grant shapes, not a policy language

**Why.** One key signs four token shapes plus one policy that needs no token, and each answers exactly one
question ("is this device mine", "may this device reach this service", and so on). The crypto enforces the
law: a bound grant replayed from another key verifies against no one, and narrowing only ever adds checks.
An illegal state you cannot represent beats an expressive one you can misconfigure. There is no attribute
to set wrong and no rule to get subtly backwards.

**The compromise.** Policy that does not fit one of the five shapes has no home here. There is no attribute
matching, no rule language, no escape hatch for the case the menu did not anticipate.

**Factored in.** The token core underneath is a full datalog engine, so arbitrary policy is technically in
reach. nauthy chose NOT to expose it, and to surface only the shapes it can make correct by construction.
A system that genuinely needs arbitrary, mutable policy wants a policy engine, which is a different tool
with a different cost. nauthy is the side of that fork where the shapes are fixed and therefore safe.

## Node-local revocation, not a published status list

**Why.** A token verifies offline, so there is no status server to ask "is this revoked". Instead the
issuer keeps a set of revoked ids, and the gate refuses any presented token whose chain includes one. This
is zero infrastructure: a set on disk, checked at connect time, failing closed. It survives a restart,
which a short expiry cannot.

**The compromise.** Revoking on one node does not reach others. An owner running several nodes revokes on
each. There is no canonical, signed, published status list a third party can fetch and trust.

**Factored in.** Revocation is an interface, not a fixed store: the gate consults a one-method `Revocations`
trait, so the set can live behind anything a consumer supplies, including a set shared across their own
deployment. nauthy ships the node-local floor and leaves distribution to the consumer, rather than baking
in a network to propagate revocations: the trait is the extension point, not a promise of one.

## Bearer slips alongside bound slips

**Why.** A bound slip is theft-resistant and non-delegable: a copy replayed from a different key verifies
against no one, so it is the shape to prefer. A bearer slip is delegable and carries no such binding, for
the case where the holder cannot prove a key of their own. Both are first-class and typed, so which one you
minted is visible at the call site, not buried in configuration.

**The compromise.** A bearer slip is a bearer token. Whoever holds an unexpired, un-revoked copy gets the
service until it expires or you revoke it. That is the price of delegability.

**Factored in.** The two shapes are kept distinct in the type system precisely so the trade is a choice you
make on purpose. The guidance follows from the shape: keep bearer slips short-lived, and prefer a bound
grant wherever the holder can prove a key.

## No queryable "who has access right now"

**Why.** The only way to answer "who has access right now" authoritatively is a control plane that every
grant passes through, and that control plane is the infrastructure nauthy exists to avoid. Grants are
minted and narrowed offline, by holders, with no secret and no call home, so no single place ever sees them
all.

**The compromise.** You cannot ask a source of truth. You revoke by id after the fact, and you see
outstanding grants only if you record them yourself as you mint them.

**Factored in.** This is the trade stated plainly: auditability for zero infrastructure. Each grant exposes
a stable `root_revocation_id`, so a consumer who needs an index can build one (record the id beside the
grantee at mint time, list and revoke by it later) without nauthy growing a control plane. If you must
answer "who has access" from a central authority for compliance, that requirement points at a different
tool, and nauthy says so.

## Expiry against the local clock

**Why.** Expiry with no server means checking a grant's window against the local clock. It is the simplest
thing that ages a leaked token out eventually with no coordination between parties.

**The compromise.** A badly-wrong clock widens or voids a grant's window. There is no trusted time source to
correct it.

**Factored in.** Expiry is a backstop, not the primary control. Revocation is the mechanism that recalls a
token now; expiry is what limits the damage of one you have not yet revoked. That is why the guidance is to
keep bearer expiries short: a short window makes clock drift a small error rather than a large one.

## One small Rust dependency, not a spec ecosystem

**Why.** nauthy is one dependency you can read end to end, with the correctness batteries a first-time
implementer tends to get wrong already in the box: device binding, a single-use admission witness that makes
"authorize before serve" a compile-time precondition, and a shipped revocation store. You adopt a library,
not a specification and a build-it-yourself checklist.

**The compromise.** There are no cross-language libraries, no independent specification, and no governance
process. It is a single implementation, and this thin layer over the token core has not been through
external security review.

**Factored in.** The token core underneath HAS been through external security review, with real advisories
found and fixed, so the cryptographic substrate is not unproven. The maturity gap is this layer's own age
and review depth, which is a real cost to weigh, and one that narrows with time and use rather than with more
code.

## The honest bottom line

On the narrow job it is built for (attenuable, revocable capability tokens rooted at a transport key,
verified offline, with zero server, as one small Rust dependency) nauthy matches or beats the alternatives
for that specific reader. The nearest peer in that niche, [UCAN](https://github.com/ucan-wg/spec), is a
mature, multi-language, governed ecosystem, and where you are not already a pubkey-transport system it is
the safer reach; the README says as much. What separates them here is not a missing feature: the capability
work is matched on both sides. The remaining gap is maturity, external audit depth, and adopters, and none
of those close by writing more code. They close by the library being used, reviewed, and trusted over time.
That is the honest state, stated so you can price it yourself.
