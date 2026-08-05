# Proposal 0012 — The live-auth session context must not be combinable by XOR

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §8.1
**Supersedes:** nothing
**Corrects:** §8.1's claim that no single party can bias the derived context

> **Applied as drafted.** The strengthened claim replaced the original rather than sitting
> alongside it: the old sentence bounded the guarantee to a *single* party, and the construction
> now holds against any coalition short of the whole session, so leaving both would have
> understated it.

---

## Problem

§8.1 combines participants' nonces with XOR:

```
context_id = Hash(nonce_1 ⊕ nonce_2 ⊕ ... ⊕ nonce_n, channel_metadata)
```

and then claims, on the strength of the commit-before-reveal structure, that *"no single party
can precompute a pseudonym in advance or bias the final context toward one they've already
prepared a replay against."*

That claim is false as written. XOR is its own inverse, so a participant who can contribute a
value equal to another's cancels both — and the commitment step does not stop them, because
nothing in §8.1 requires commitments to be distinct or bound to whoever posted them.

### The attack

1. Commitments are broadcast in step 1 with no stated ordering, so Mallory can wait and see
   Alice's `commit_A`.
2. Mallory posts `commit_M = commit_A`, an exact copy.
3. Alice reveals `(nonce_A, blinding_A)` in step 2.
4. Mallory replays the identical pair. It is a valid opening of the commitment she posted, so
   nothing in the protocol rejects it.
5. `nonce_A ⊕ nonce_M = 0`.

At n = 2 the result is `context_id = Hash(0, channel_metadata)` — fully determined before the
session begins, since `channel_metadata` comes from the channel handshake. Mallory prepares her
pseudonym and proof in advance against a context she knew all along, which is exactly the
precomputation §8.1 says is impossible.

At n > 2 she cancels any single participant she chooses, reducing the context's entropy to the
remaining contributions and targeting a specific victim while she does it.

The damage is not confined to §8. §10.4 reuses this primitive as *"public randomness Skiora
cannot bias"* for verifiably-random replay-witness selection, so a biasable context is a
biasable witness draw.

### Why "reject duplicate commitments" is the wrong fix

It is the obvious repair and it does block the attack above, but only through an argument thin
enough to be worth refusing.

Cancelling requires committing to `nonce_A` before learning it. Re-blinding — posting a
distinct `Hash(nonce_A, blinding_M)` — needs `nonce_A` at commit time, which Mallory does not
have. So copying the commitment verbatim is her only route, and rejecting duplicates closes it.

But that reasoning rests entirely on the commitment scheme being binding and non-malleable, and
on nobody later adding a feature that reopens the door: a participant who rejoins after a
dropped connection, a retry that re-posts a commitment, a relayed session that legitimately
carries the same value twice. The security of the construction should not depend on a check
that a plausible future change quietly invalidates.

The real defect is the combiner. A group operation where one party can contribute another's
inverse is fragile whatever guards surround it.

## Decision

Replace XOR with a hash over every contribution, length-framed and in canonical order.

Once the combiner is not cancellable, copying a commitment gains nothing: the duplicated nonce
appears twice in the input, and the result still depends on the honest contribution nobody can
predict. Forcing a chosen `context_id` becomes a hash inversion rather than an arithmetic
identity, and that holds even against n−1 colluding participants.

Duplicate commitments are still rejected, but as a hygiene check rather than as the thing
carrying the security. That is the point of the change: after it, the check can be removed by
mistake without breaking the protocol.

Contributions are ordered by the nonce values themselves, so no participant identifier is
needed — which matters here, since participants are anonymous to each other by construction and
introducing an identifier to fix a nonce-combination bug would be a poor trade.

---

## Replacement text

### §8.1 — Step 1

> **Step 1 — every participant posts a commitment:**
> ```
> commit_i = Hash("nymora/v0/live-auth/commitment", nonce_i, blinding_i)   for i = 1..n
> ```
>
> Each field is length-framed before hashing, so the boundary between `nonce_i` and
> `blinding_i` cannot be moved. Two participants posting an identical commitment is a protocol
> violation and the session must abort — not because the derivation below depends on it, which
> it deliberately does not, but because a participant contributing nothing new has no honest
> reason to.

### §8.1 — Step 3

> **Step 3 — the shared context is derived from all contributions together:**
> ```
> context_id = Hash(
>   "nymora/v0/live-auth/context",
>   n,
>   nonce_(1) ‖ nonce_(2) ‖ … ‖ nonce_(n),    -- ascending lexicographic order,
>                                             -- each length-framed
>   channel_metadata
> )
> ```
>
> **The combination is a hash, not XOR, and that is load-bearing.** XOR is its own inverse, so a
> participant able to contribute a value equal to another's cancels both — and at n = 2 that
> yields a context of `Hash(0, channel_metadata)`, known before the session starts. Under a hash
> the same move produces a duplicated input field and no advantage: the result still depends on
> a contribution the attacker cannot predict, and forcing a chosen value requires inverting the
> hash rather than solving an equation. This holds against n−1 colluding participants, not
> merely against one.
>
> Sorting the nonces makes the input canonical without any participant identifier, which suits a
> setting where participants are anonymous to each other. The count `n` is absorbed so that a
> session of one size cannot be reinterpreted as one of another.

### §8.1 — the paragraph following step 5

> Because `context_id` depends on nonces contributed by *every* participant, all commit before
> any reveal, and the contributions are combined by a hash rather than a cancellable operation,
> no coalition short of the whole session can precompute a pseudonym in advance or bias the
> final context toward one they have already prepared a replay against. This scales as O(n) —
> one proof per participant, checked once against a single shared value — rather than the O(n²)
> exchanges a pairwise-only design would require for every participant to mutually authenticate
> with every other. At n=2, the mechanism reduces to ordinary two-party mutual authentication
> with no special-casing required.

### §8.1 — sequence diagram note

The diagram's third note currently reads
`context_id = Hash(nonce_alice ⊕ nonce_bob ⊕ nonce_charlie, channel_metadata)`. Replace with:

> `context_id = Hash(sorted framed nonces, channel_metadata)`<br/>— computed independently,
> identically, by all three

---

## Consequences

**Gained:** the biasing claim §8.1 makes becomes true, and true against a stronger adversary
than the original text considered — any n−1 participants rather than a single one.

**Gained:** §10.4's verifiably-random witness selection inherits an unbiasable context. It cited
this primitive for a property the primitive did not have.

**Paid:** hashing n framed values instead of one XOR fold. Negligible, and none of it is in a
circuit — `context_id` is computed in the clear by every participant, and only the pseudonym
derived from it enters a proof.

**Paid:** contributions must be sorted before hashing, so the derivation is no longer
order-free in the way an XOR fold is. Every participant sees the same set, so this is a local
sort rather than an agreement problem.

**Unchanged:** the commit-reveal structure, the pseudonym derivation, the per-participant
proofs, and the `channel_metadata` anti-relay caveat — which remains the honest limit of this
mechanism and is untouched by this proposal.

## Note for implementers

`Domain::LiveAuthCommitment` and `Domain::LiveAuthContext` already exist in `nymora-core`'s
registry and are the tags the replacement text names. Neither construction is implemented yet,
so nothing in `nymora-crypto` changes today; §8.1 was specified before the code reached it.

The framing convention is the one `Hasher` already applies — a `u64` little-endian length before
each field. An implementation should build both values through that type rather than hashing by
hand, so this construction inherits the same discipline as the rest.

## Open question

**Should the reveal step have a deadline?** This proposal removes the attacker's ability to bias
the context, but not their ability to withhold. A participant who sees every reveal and then
declines to send their own forces an abort, and can repeat it — a denial of service that costs
them nothing and is indistinguishable from a dropped connection. §8.1 specifies no timeout and
no penalty. That is a liveness question rather than a soundness one, which is why it is not
settled here, but it belongs with whoever implements the state machine.
