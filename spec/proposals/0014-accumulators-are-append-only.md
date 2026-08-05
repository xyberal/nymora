# Proposal 0014 — Accumulators are append-only

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §5.2
**Supersedes:** nothing

> **Decided in session and applied directly.** This records a property the design already
> relies on rather than changing behaviour; it is written down because the word "accumulator"
> invites the opposite assumption and nothing currently corrects it.

---

## Problem

Nothing in §5.2 says whether a leaf can be removed, and every mechanism that might have removed
one turns out not to:

- **Migration (§9.3)** consumes the old leaf by publishing a migration nullifier. The leaf stays
  in the tree; what changes is that its nullifier is now spent.
- **Revocation (§11)** maintains a separate revocation-set root. A revoked credential's leaf is
  not withdrawn from the membership accumulator.
- **Dissolution (§12)** freezes roots rather than emptying them.

So the structure is append-only in practice, and no reader can tell from the specification. That
matters in two directions. An implementer who assumes deletion builds a materially more complex
tree — one supporting removal, with the witness-invalidation and root-history consequences that
follow — for a capability nothing uses. An implementer who assumes append-only builds the simple
thing and has no text to point at when asked why.

## Decision

§5.2 states that accumulators are append-only, and states the two consequences that follow.

### Membership is not "the leaf is present"

Since leaves are never withdrawn, presence in the accumulator is necessary but not sufficient.
A credential is current when its leaf is present **and** its migration nullifier is unspent
(§9.3) **and** it is absent from the revocation set (§11). That is already how the protocol
behaves; append-onlyness is what makes it the only possible reading.

### Depth is sized for lifetime members, not live ones

A tree of depth `d` holds `2^d` leaves and never reclaims one. An agora's capacity is therefore
consumed by every credential it has *ever* issued, including migrated predecessors and revoked
members — and planned migration (§9.3) is expected to be routine, so the gap between live
membership and consumed capacity grows with device churn rather than with recruitment.

This is a sizing note rather than a limitation. It needs saying because the intuitive reckoning
— "depth 32 gives four billion members" — is wrong by however many device migrations the agora
sees over its life.

---

## Replacement text

### §5.2 — after the no-size paragraph

> **Accumulators are append-only.** A leaf is added when a credential is admitted and is never
> removed or modified. Nothing in the protocol withdraws one: planned migration (§9.3) consumes
> the old leaf by spending its migration nullifier rather than deleting it, revocation (§11)
> maintains a separate revocation-set root, and dissolution (§12) freezes roots rather than
> emptying them.
>
> Two consequences follow, and both are easy to get wrong in the opposite direction.
>
> First, **presence in the accumulator does not by itself mean a credential is current.** A
> credential is current when its leaf is present, its migration nullifier is unspent (§9.3), and
> it is absent from the revocation set (§11). A verifier checking only inclusion accepts
> superseded and revoked credentials.
>
> Second, **depth must be sized for every credential the agora will ever issue**, not for its
> live membership. Migrated predecessors and revoked members consume capacity permanently, and
> since planned migration is the expected path for a routine device change, consumption tracks
> device churn rather than recruitment.

---

## Consequences

**Gained:** an implementer builds the simpler structure with a reason to point at, and a
verifier that checks inclusion alone is now visibly wrong rather than arguably sufficient.

**Gained:** §10.1's append-only transparency log now describes an append-only underlying
structure. The root sequence it publishes is a chain of extensions, which is the property an
auditor checking append-onlyness is actually checking.

**Paid:** nothing at the protocol level. This describes existing behaviour.

**Named, not solved:** the capacity ceiling. An agora that exhausts its depth has no mechanism
to grow — re-rooting at a greater depth would reissue every witness and is not specified. Worth
knowing before choosing a depth, and worth a proposal if any agora ever approaches one.

## Note for implementers

Task 2.4 builds the tree against this decision: leaves are appended left to right, so the
occupied region is always a prefix and the remainder is empty subtrees whose hashes can be
precomputed per level.

Removal being absent from the API is not merely an omission — it is the decision. A future
`remove` would invalidate the reasoning above and needs a proposal, not a patch.
