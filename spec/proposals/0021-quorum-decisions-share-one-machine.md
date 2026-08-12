# Proposal 0021 — Quorum decisions share one machine and one action; subjects carry the kind

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §4.3, §11, §12
**Supersedes:** nothing

> **Decided in session and applied directly.** Phase 5's state machines forced the blank:
> §4.3 gives policy changes an approval mechanism (the policy-approval nullifier), but §11
> says only that revocation requires a quorum and §12 that dissolution collects
> member-proof confirmations — neither says what an approval *is*, what its nullifier
> derives over, or what stops an approval collected for one decision being presented
> toward another.

---

## Problem

A revocation, a dissolution, and a policy change are the same shape — *k current members
approved subject X* — but specifying each in isolation invites two failure modes:

- **Three bespoke approval flows.** Each is a fresh chance to get nullifier distinctness,
  quorum freshness, or non-disclosure wrong, and §6.5's uniform-shape argument cuts
  against inventing per-decision proof variants: every new action variant is a new clause
  the one standardized circuit must carry.
- **Cross-kind replay.** If approvals for different decision kinds accumulate under
  identifiers drawn from one namespace, an approval harvested for an innocuous policy
  tweak could be counted toward a revocation — the approving member proved "I approve
  subject X" without X's *kind* being bound by anything.

There is also a subtler gap: §4.3's `proposal/{id}` is issued by Skiora, and nothing binds
the identifier to the proposal's *content*. A Skiora that shows different content to
different members under one identifier collects a quorum for something nobody approved.

## Decision

**One quorum machine, one action, domain-separated subjects.**

1. Every quorum decision — policy change (§4.3), revocation (§11), dissolution (§12) — is
   approved with the **policy-approval action** of §9.1's chain: nullifier
   `Hash(sk_cred, subject_id, agora_id)`. No new action variants; §6.5's action set stays
   closed.
2. The **subject identifier** is derived, not issued:

   ```
   subject_id = Hash(kind_tag; agora_id, epoch_raised, approving_class,
                     canonical_decision_content, nonce)
   ```

   under one of three domain tags — `nymora/v0/proposal/policy`,
   `nymora/v0/proposal/revocation`, `nymora/v0/proposal/dissolution`. The kind lives in
   the tag, so subjects of different kinds cannot collide and an approval nullifier for
   one kind is unforgeable as another — the same argument that keeps a migration
   certificate from standing in for an epoch certificate (§9.1).
3. **Members recompute the subject before approving.** Skiora serves the decision
   content, the approving class, the raising epoch, and the nonce; an honest member
   derives `subject_id` locally and approves only on a match. Divergent content under one
   identifier is caught by the recomputation; one content under two identifiers splits
   the approvals and meets quorum with neither.
4. The **nonce** is fresh per raise, so a re-raised proposal (§4.3 requires re-raising
   after expiry) is a new subject and inherits no approvals. The raising **epoch** is
   absorbed for the same quorum-freshness rule that expires the proposal.
5. §12's flow maps onto the machine without residue: *initiate* is propose, *confirm* is
   approve, *execute* is the threshold-met execution. §11's revocation executes by
   inserting the leaf into the revocation set and advancing the epoch immediately, as
   §11 already requires.

The quorum an execution requires is agora policy — a `governance_quorum` value set by the
same policy-change mechanism, starting at 1 in the founding state (§4.1's unavoidable
window) and raised as §4.3 raises thresholds.

## Consequences

**Gained:** revocation and dissolution have a specified approval mechanism at all; one
audited implementation of distinctness, expiry, and non-disclosure serves all three
kinds; subject identifiers bind content, closing the divergent-content quorum attack; the
circuit's action set does not grow.

**Paid:** the subject derivation is protocol rather than an operator convenience — every
implementation must produce identical bytes, and the three domain tags are permanent
registry entries.

**Unchanged:** the policy-approval nullifier's derivation and key (§4.3 — `sk_cred`, by
proposal 0005's window rule, since approvals are counted); proposal expiry at the epoch
boundary and on early advance (§4.3, §11); the non-disclosure of approval counts before
execution.
