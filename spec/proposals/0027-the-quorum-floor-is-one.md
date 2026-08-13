# Proposal 0027 — The quorum floor is one

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §4.3, §5.3
**Supersedes:** nothing

> **Found by the pre-publication re-read.** §4.3 says the governance quorum "start[s] at
> 1 in the founding state … and raised as thresholds are", and nowhere contemplates
> zero — but nothing enforced that. The policy decision accepted zero for both numbers
> it carries, and execution compares approvals against the quorum with `>=`, which zero
> satisfies vacuously.

---

## Problem

`Decision::Policy` carries the complete new state — an admission threshold for one class
and the agora's governance quorum — and validated neither. Two consequences, one of them
severe:

- **A zero governance quorum makes every subsequent execution vacuously approved.** Once
  a single policy proposal carrying `governance_quorum: 0` executes, `execute` succeeds
  on any proposal with an empty approval set. The operator raises proposals itself
  (`propose` is its own method), so from that moment the operator alone can raise and
  execute anything the quorum machine decides — revocation of any member (§11) and
  dissolution of the agora (§12) included. The quorum machine exists precisely to
  withhold those from any single party.
- **A zero admission threshold admits on no attestation at all.** `finalize` compares
  the session's nullifier count against the threshold; zero passes an empty session,
  and the vouching requirement (§5.3) evaporates for that class.

The mitigation that does exist is real but insufficient: approving members recompute the
subject from the served content (proposal 0021), so a zero must be knowingly approved by
the current quorum — it cannot be smuggled under a subject that claims otherwise. But
the engine is the reference a conformant Skiora wraps, and an invariant this load-bearing
cannot rest on every member of every future group reading two integers correctly. The
founding path had the same hole: a class configured with a zero threshold at creation
was accepted without complaint.

## Decision

**One is the floor, enforced at every point where the numbers enter.**

- `create` refuses a founding configuration in which any class's admission threshold is
  zero — the same self-consistency validation that already refuses an unconfigured
  voucher class, with the same error (`Malformed`: a deterministic property of the
  caller's own input, not hidden state).
- `propose` refuses a policy decision naming a zero admission threshold or a zero
  governance quorum, also as `Malformed`. The refusal is at *raise*, not at execute: a
  proposal that could never validly execute must not open and gather approvals — the
  same shape as exhaustion refusing at session start (§5.2) rather than after
  attestations were collected. Since `propose` is the proposals map's only write path,
  the floor holds at execution by induction, with no second check to drift.

`Malformed` rather than the uniform `Rejected` is deliberate and consistent with the
error discipline: `Rejected` protects information about state, and a zero in the
caller's own input discloses nothing the caller did not already hold.

## Consequences

- §4.3 states the floor and its reason; §5.3's *k* is explicitly ≥ 1.
- The founding state is unchanged: quorum 1, threshold 1 remain the legitimate §4.1
  minimum — the floor forbids zero, not smallness. What smallness costs is already
  §15's small-group territory.
- Tests pin both entry points: a zero-threshold founding is refused, and both zero-
  carrying policy proposals refuse at raise.
- Rejected alternative: flooring at `execute`. It leaves a doomed proposal open all
  epoch collecting approvals, and it re-checks at a second site what a single write
  path can guarantee at one.
