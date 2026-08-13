# Proposal 0028 — Numeric credential attributes are deferred

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §2, §5.1, §9.3, §15
**Supersedes:** nothing

> **Found by the pre-publication read-through, twice.** §5.1 defined the credential as an
> attribute-bearing object (BBS+-style, hidden `tier` / `vouch_count` / `tenure_start`),
> while §9.1's normative leaf — `Commit(pk_root, sk_cred, r_root, agora_id)` — commits no
> attribute, and §9.3 promised an attribute carry-over no migration proof establishes.
> The independent implementation audit rediscovered the same contradiction without
> knowing it was already on file: it is the first thing a serious reviewer finds.

---

## Problem

The specification told two incompatible stories about what a credential *is*:

- **§5.1**: an attribute-bearing signature object carrying hidden numeric state —
  `tier`, `vouch_count`, `tenure_start` — with zero-knowledge range predicates
  ("tier ≥ 2", "tenure ≥ 6 months") and an optional evaluation service hiding the
  policy constants themselves.
- **§9.1**: a leaf commitment over key material and nothing else. The standardized
  circuit opens that leaf; no attribute exists anywhere in the statement, the witness,
  the accumulator, or the implementation.

Only one of these can be the credential the circuit proves things about, and everything
downstream of §9.1 — the vectors, the stub statement, the migration proof, the entire
phase 4–5 implementation — is built on the leaf. §5.1's object was a design intention
that predates the key-hierarchy work and was never reconciled with it. §9.3 inherited
the confusion: "tenure, vouch count, tier — carry over to the new leaf" describes a
transfer of state the leaf does not hold.

## Decision

**The credential of this protocol version is §9.1's leaf, and §5.1 now says so.
Numeric hidden attributes are deferred to a later protocol version.**

Two things make the deferral honest rather than a loss:

- **Tier survives, restructured: tier is class membership.** Each tier and eligibility
  rule is its own policy class with its own accumulator (§5.2), and "tier ≥ 2" is proven
  as membership in the Tier2 class root. This is not a weaker encoding of the attribute
  — for the one predicate the protocol currently needs, it is the *stronger* one: a
  class-membership proof discloses only the class it was proven against, so the
  non-comparability requirement §5.1 states ("never relative ordering against any other
  credential") holds because there is no number to compare, rather than resting on a
  range-proof construction hiding one.
- **What is genuinely deferred is expressive admission policy** — vouch-count and
  tenure predicates, and policies over them. Until a later version adds them, policies
  express what class membership can: thresholds of attestations by eligible classes
  (§5.3).

**Why deferral is a protocol-version event and not a feature flag.** Attributes live in
the leaf, and the leaf is what the one standardized circuit opens (§6.5). Adding them
changes the commitment's arity, every stored credential, every witness, and the circuit
itself — the same class of change as re-accumulation, which §5.2 already names a
protocol-version event. A reintroduction must also re-establish, inside its own design,
every property this section requires: non-comparability across credentials, no ordering
oracle, and carry-over across migration proven in zero knowledge alongside §9.3's
existing clauses. None of that is free, which is exactly why recording the deferral
beats pretending the attributes exist.

## Consequences

- §2's vocabulary and §5.1 describe the credential as it is: the §9.1 leaf, with tier
  as class membership and a marked deferral for numeric attributes.
- §9.3's carry-over sentence states what migration actually preserves — the class the
  consumed leaf occupied, and the `sk_cred` lineage — with attributes joining when they
  exist.
- §15's lost-device and key-leak costs read "standing" rather than enumerating
  attributes the version does not have.
- No code changes beyond one doc comment: the implementation already is the deferred
  version. The conformance vectors pin the attribute-free leaf and are untouched.
- The circuit work of phase 6 sizes against the attribute-free statement. Whoever
  reintroduces attributes owns the constraint-count consequences (proposal 0001's
  measurement discipline applies).
