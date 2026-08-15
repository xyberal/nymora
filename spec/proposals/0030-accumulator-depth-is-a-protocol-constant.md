# Proposal 0030 — Accumulator depth is a protocol constant

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §5.2, §6.5
**Supersedes:** nothing

> **Found by reading the layers against each other.** The specification, the circuit
> layer, and the accumulator crate answered "who chooses the depth?" three different
> ways, and the disagreement would have been settled silently — by whichever answer the
> real circuit hard-coded first — if it were not settled deliberately here.

---

## Problem

Three layers held three positions on accumulator depth:

- **§5.2** addressed its sizing advice to the founder: "size depth generously at
  creation… there is no second chance later." Depth as a per-agora parameter, chosen
  when the agora is created.
- **`nymora-circuits`** asserted the opposite in its doc comments: `DEPTH` is a value
  the real circuit fixes *network-wide*, because a per-agora depth is a per-agora proof
  shape — exactly the fingerprinting §6.5 exists to prevent.
- **`nymora-accumulator`** is agnostic: depth is a const generic on `Tree` and
  `Witness`, a property of each instance, with no opinion about who picks it.

These cannot all be normative. The membership path is *inside* the standardized
circuit: its length is the depth, and a circuit is a fixed shape. If the founder
genuinely chooses, every agora with a distinct depth has a distinct proof — size,
structure, verification key — and an attestation bundle fingerprints its group by
shape alone, undoing what the tag mechanism (§6.4) and the one-circuit rule (§6.5)
exist to provide. If the circuit fixes one value, §5.2's advice is addressed to
someone with no decision to make.

## Decision

**Accumulator depth is a single network-wide protocol constant. Its numeric value is
deferred until the real circuit is implemented; its scope is settled now.**

The scope question and the value question separate cleanly, and only the value needs
information that does not exist yet:

- **Scope — decidable today, on arguments already in the specification.** First, the
  fingerprinting argument above: one circuit means one depth, and §6.5's one-circuit
  rule is not negotiable. Second, §5.2's own exhaustion argument undermines founder
  choice from the other side: exhaustion is terminal for the class, so the only safe
  choice is always "generous" — a parameter whose correct value is known in advance is
  not a parameter, and offering it to founders offers only the ability to get it
  wrong, permanently. The choice adds a foot-gun and a fingerprint and nothing else.
- **Value — deferred to measured constraint counts.** In-circuit cost is linear in
  depth (one hash-and-select per level), and the right ceiling depends on the
  constraint budget of the chosen proof system and hash — precisely the measurements
  proposal 0001 already defers to. The value is pinned at protocol-version
  standardization, alongside the circuit it parameterizes. §5.2's arithmetic stands as
  the anchor for that decision: depth 32 accommodates roughly four billion leaves at
  thirty-two siblings per witness.

## Alternatives rejected

- **Per-agora depth, as §5.2 had it.** Dead on the fingerprinting requirement alone;
  see above.
- **A small menu of standardized depths** (say 16 / 24 / 32, one circuit each). Proof
  shape then discloses the bucket — a coarse group-size classifier attached to every
  attestation bundle. A weaker leak than a per-agora shape, but §6.5's requirement is
  that shape reveal *nothing*, and a three-way partition of all agoras is not nothing.
- **Per-agora trees padded to a maximum inside one circuit.** The circuit verifies
  every path at the maximum depth; shorter trees pad their witnesses. Proof shape is
  uniform, but nothing is gained: proving cost is set by the circuit's shape, so every
  agora pays the maximum regardless, and the effective capacity ceiling is the maximum
  too — at which point the smaller tree is complexity with no property attached.
  Padding is the correct *implementation* answer to a different question (variable
  occupancy inside one fixed-depth tree), and it is already how a sparse tree works.

## Consequences

- §5.2 states that depth is a protocol constant fixed network-wide at
  protocol-version standardization, and addresses its sizing argument to that
  decision rather than to founders. The capacity facts are unchanged: consumption is
  permanent, tracks device churn, and exhaustion is terminal for the class.
- §6.5 names depth as part of the proof shape its one-circuit rule holds constant.
- **No code changes beyond doc comments.** The const generic `DEPTH` that runs
  through `nymora-accumulator`, `nymora-circuits`, and `nymora-protocol` is the
  implementation mechanism for a constant the protocol pins per version — the
  generics stay, and the doc comments in `nymora-circuits` now cite this proposal for
  the position they already held. The conformance vectors exercise the construction at
  small test depths, which is unaffected: the constant binds deployments, not the
  algebra.
- Whoever implements the real circuit inherits one decision (the number), not two
  (the number and its scope). Proposal 0001's measurement discipline applies.
