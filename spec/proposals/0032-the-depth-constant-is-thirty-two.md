# Proposal 0032 — The depth constant is thirty-two

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §5.2
**Applies:** the value [proposal 0030](0030-accumulator-depth-is-a-protocol-constant.md)
deferred. 0030 settled *who* chooses the depth (no one — it is a network-wide protocol
constant); this pins *what* it is, on the measurement 0030 named as its evidence.

---

## Problem

Proposal 0030 deferred the depth constant's numeric value to measured constraint
counts. The counts exist (`measure/`, reproducible): an in-circuit Merkle inclusion
path costs a flat **243 constraints per level**, linear across every depth measured,
with no fixed overhead worth naming. The question is no longer open-ended — it is an
asymmetry to price:

- **Under-provisioning is terminal.** §5.2: a full class admits no further leaf and,
  because migration consumes capacity, permits no routine device change either. No
  mechanism compacts or re-accumulates; the escape is a protocol-version event.
  Capacity consumption tracks device churn, not recruitment, so a class's lifetime
  demand is a multiple of its membership that nobody can bound at creation.
- **Over-provisioning is linear.** Each extra level costs 243 constraints per
  inclusion path and one 32-byte sibling per witness.

There is also a closing window. Today the constant binds nothing but text — no real
circuit exists, no proof has ever circulated — so pinning it is free. The real circuit
is built *at* this depth; once proofs exist, the depth is part of the one proof shape
§6.5 standardizes, and revising it becomes a protocol-version event. The cheapest
moment to decide is now, and the moment is brief.

## Decision

**The network-wide accumulator depth is 32.**

Priced honestly, against the statement that will actually contain it. The routine
statement carries three paths at this depth — class membership, revocation absence,
migration-spend absence. Depth 32 puts the depth-dependent cost at roughly 23,000
constraints; depth 16 would save about 11,700 of them. Against a statement that also
verifies an embedded-curve certificate (6,238 constraints) and derives its
commitments and nullifiers, the saving is real but modest — on the order of a quarter
of the statement — and it is bought with 65,536 leaves per class, a ceiling a
five-thousand-member class with routine device churn exhausts within its founders'
tenure. The asymmetry decides: a linear, bounded, per-proof cost against a terminal,
unbounded, per-class risk.

Depth 32 is also the value §5.2's own arithmetic has anchored on since before 0030
existed: roughly four billion leaves per class, at thirty-two siblings per witness —
capacity comfortably beyond any class this protocol's social mechanics (vouching,
quorums, per-agora trust) could plausibly assemble, with migration churn included.
Independent accumulator-based designs settled on the same value under the same
asymmetry.

## Alternatives rejected

- **16 or 24.** The savings are 3,888 and 1,944 constraints per path respectively;
  the capacities are 65 thousand and 16.7 million leaves. 24 is probably enough for
  any class — "probably enough" is exactly the wager §5.2 forbids, for a saving that
  does not change what device can produce the proof.
- **40 or larger.** 2<sup>32</sup> already exceeds plausible lifetime demand by
  orders of magnitude; further levels are constraints spent on capacity nothing can
  consume. 64 additionally sits on the edge of the u64 position index and its
  capacity arithmetic for no benefit at all.
- **Defer to the proving-system choice, as 0030's text sketched.** The per-level cost
  is linear in the price of one 2-to-1 hash for any plausible arithmetization, so a
  different proving system rescales every alternative identically and cannot reorder
  them. Waiting buys no information that bears on the choice — and spends the window
  in which the choice is free.

## Consequences

- §5.2 states the value; its sizing argument becomes the record of why 32, rather
  than advice about choosing.
- The one-line pin the implementation promised lands: `nymora-circuits` carries
  `PROTOCOL_DEPTH = 32`. The const generics remain the mechanism — tests and
  conformance vectors continue to exercise small trees, which 0030 already holds
  harmless ("the constant binds deployments, not the algebra").
- The real circuit is built at depth 32. Revising the value hereafter requires a new
  proposal, and once proofs circulate, a protocol version.
