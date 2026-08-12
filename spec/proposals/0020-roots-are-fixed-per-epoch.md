# Proposal 0020 — Roots are fixed per epoch; mutations land at boundaries

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §5.2, §5.3, §7, §9.3 (generalizes a rule §9.3 already states)
**Supersedes:** nothing

> **Decided in session and applied directly.** Phase 5's operator state forced the blank:
> §7 serves `root_at_epoch` — singular — while §5.2's accumulator gains leaves whenever a
> vouch session finalizes, and the specification never says which root a mid-epoch proof
> is checked against or what happens to it when the tree moves an hour later. §9.3 already
> answers the question for the two exclusion roots ("exclusion roots are fixed per
> epoch"); this proposal extends the same rule to the class accumulators, because leaving
> the two families on different clocks was an oversight rather than a design.

---

## Problem

An accumulator that moves mid-epoch breaks three things at once:

- **Honest proofs stop verifying minutes after they are cut.** A proof is checked against
  a root; if an admission moves the root while the proof is in flight, the proof fails
  against the new root through no fault of the prover, and every verifier needs a window
  of "recent enough" roots — a window the specification never defines.
- **`root_at_epoch` stops being well-defined.** §7 serves one root per epoch per class.
  If the tree moved during the epoch, an attestation from early in the epoch and one from
  late in it were cut against different roots, and no single served value verifies both.
- **A per-epoch root *history* within the epoch is an admission counter.** Serving every
  intermediate root would repair verification at the cost of publishing how many
  admissions happened and when — exactly the occupancy information §5.2 withholds "at any
  point".

## Decision

**Every root any proof is checked against is fixed for the whole epoch.** Concretely:

- The class accumulators, the revocation-set root, and the migration-spend root are
  snapshotted at each epoch boundary; the snapshot is the epoch's one canonical root set.
- Admissions (§5.3 finalize) and migration spends (§9.3) **stage** during the epoch and
  land at the next boundary. A member admitted in epoch *e* is present in the class root
  — and can first act — at *e + 1*.
- Revocation is not an exception but the rule's sharpest form: §11 advances the epoch
  immediately, so a revocation lands at a boundary too — one it forces into existence.
  Its effect is immediate *because* the boundary moved, not because the root moved
  mid-epoch.

## Consequences

**Gained:** `root_at_epoch` is singular and total — one snapshot per epoch answers every
historical verification. A member's witnesses (inclusion and the two absences) are valid
for exactly an epoch, refreshed on the boundary broadcast rather than raced against
concurrent admissions. "Current roots" never changes under a prover mid-flight. The
within-epoch admission cadence stays unpublished.

**Paid:** admission latency — a newly vouched member waits for the boundary before first
acting. §9.1 already prices epochs at roughly a day and §11 already lets any event that
cannot wait force a boundary, so the wait is bounded and, where it matters, collapsible.

**Unchanged:** §9.3's window for a superseded device (that rule was already stated in
these terms); append-onlyness (§5.2, proposal 0014); the proof statement — the chain of
§9.1 takes the epoch's roots as public inputs exactly as before.
