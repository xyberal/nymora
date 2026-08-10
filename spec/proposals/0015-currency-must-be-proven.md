# Proposal 0015 — Currency must be proven, not presumed

**Status:** **Proposed**
**Affects:** §5.2, §7, §8.3, §9.1, §9.3, §10.1, §11
**Depends on:** 0014, which removed deletion as an enforcement mechanism and thereby exposed
this; 0008 and 0013, whose leaf and nullifier constructions the repair builds on
**Corrects:** §11's claim that revocation ends write capability at once, and
`nymora-crypto`'s migration nullifier, which diverges from §9.1 as written

---

## Problem

§5.2 defines what it means for a credential to be current: its leaf is present, its
migration nullifier is unspent (§9.3), and it is absent from the revocation set (§11). The
routine proof statement (§9.1) establishes exactly one of the three — inclusion — and no
mechanism anywhere establishes the other two. §5.2 even names the resulting failure — *"a
verifier checking only inclusion accepts superseded and revoked credentials"* — and then
every verifier in the design checks only inclusion, because inclusion is all the statement
proves.

### A revoked credential keeps writing

Under 0014 the accumulator is append-only: revocation adds an entry to a separate
revocation set and removes nothing. The revoked member's leaf is still in the tree. They
still hold `sk_root`, and certification is purely local (§9.1), so they certify a fresh
epoch key for the new epoch without asking anyone. Their routine proofs still verify
against the current root, and Skiora cannot refuse them, because it cannot tell which
credential produced a proof — §2.1, working exactly as designed.

What revocation actually removes today is the tag-key broadcast: **read** access. §11's
sentence — *"Write capability ends at once: the credential leaves the accumulator, and no
valid proof can be produced against the new root"* — was true before 0014 and is false
now. It is the load-bearing sentence of the section, and §10's "feeding timely revocation"
and §15's "prompt revocation" mitigation both lean on it.

### A migrated-away device keeps writing

After a planned migration, the old device still holds `sk_root_old`, `sk_cred`, and
`r_root_old`, and its consumed-but-present leaf still verifies. Authorship nullifiers
derive from `sk_epoch`, so nothing the old device publishes collides with the successor.
The count contexts are protected — `sk_cred` is shared across the lineage, so vouching and
policy nullifiers collide with the successor's — but attestation is not a count. A phone
handed back to a repair shop after a routine upgrade can author group-attributed content
indefinitely.

### Skiora cannot check at the door

Both failures have the same shape: the party positioned to enforce currency cannot
identify the credential, and the party who can identify it (the holder) is the adversary.
Unlinkability is not the bug — it is the design's central property. The conclusion is
forced: **the currency check has to travel inside the proof**, as a statement the holder
proves about public per-epoch state.

### The migration nullifier cannot be spent twice, and must be

§9.1 already specifies that migration derives its nullifier from `sk_cred` *"over the
identifier of the session, proposal, or leaf they consume."* The code diverges:
`nullifier::migration` absorbs only the key and the agora, so the value is **constant
across a credential's entire lineage**. The first planned migration spends it; the second
— the member's next routine device change, years later — produces the identical value and
is indistinguishable from a double-spend. As implemented, a credential can migrate exactly
once, ever.

Under this proposal the defect would be worse than a blocked migration: the successor's own
routine proofs must show its migration nullifier *unspent*, and with a lineage-constant
derivation that check fails the moment the first migration completes — bricking the
successor entirely. Binding the consumed leaf into the derivation fixes both: each leaf has
its own spend, the anti-Sybil property (§9.3: one successor per leaf) is preserved per
leaf, and a lineage migrates as many times as devices change.

## Decision

The routine proof statement gains a **currency component**: two non-membership clauses,
proven against two per-epoch published roots.

1. The credential's leaf is absent from the **revocation set**.
2. The credential's migration nullifier, `Hash(sk_cred, leaf, agora_id)`, is absent from
   the **migration-spend set**.

Both sets are keyed accumulators supporting non-membership witnesses — a sparse Merkle
tree or an indexed (sorted) Merkle tree. That is a different structure from §5.2's
positional append-only accumulator, which cannot express non-membership at all. The choice
between sparse and indexed is a constraint-cost question and is fixed with the proving
system, on the same fault line that leaves the algebraic hash provisional; what is fixed
now is the interface: keyed insertion, per-epoch published roots, non-membership
witnesses.

Three rules complete the mechanism:

- **The exclusion roots are public inputs**, alongside the accumulator root. A verifier —
  Skiora, or a member checking a live-auth proof (§8) — accepts a routine proof only
  against the current epoch's three roots. Historical verification is untouched: an
  attestation from epoch *e* verifies against epoch *e*'s roots, which is §11's claim 1
  working as stated.
- **Exclusion roots are fixed at epoch boundaries.** Revocation still takes effect
  immediately, because revocation advances the epoch immediately (§11) and the new epoch's
  revocation root carries the new entry. A consumed leaf enters the migration-spend set at
  the next boundary, so a superseded device retains write capability for at most the
  remainder of the epoch — the same bound a compromised `sk_epoch` already carries (§9.1),
  and migration, unlike revocation, is the member's own cooperative act.
- **The sets are served to members whole**, member-gated like roots (§7), and
  non-membership witnesses are computed locally. This is not a convenience: a witness
  request naming a specific leaf would tell Skiora exactly which credential is about to
  act — the linkage §2.1 forbids. Serving the whole set is affordable because its
  cardinality tracks revocations and migrations, never membership or content volume.

One revocation entry excludes a leaf from every policy class at once, since the clause is
over the leaf value itself rather than over any class's tree.

### Alternatives refused

**A per-epoch rebuilt "current members" root** — Skiora re-issues a tree containing only
current leaves each epoch, and proofs verify against it. Fails structurally: a migration is
verified in zero knowledge precisely so Skiora never learns which leaf it consumed, so
Skiora cannot omit superseded leaves from any tree it builds. It repairs only the
revocation half, re-keys the meaning of `root_at_epoch` everywhere, and contradicts
nothing-is-deleted for no gain the exclusion sets don't deliver.

**A per-epoch liveness token distributed like `K_tag_e`** — routine proofs require
knowledge of a per-epoch secret that revoked members stop receiving. Fails twice: it is a
shared secret, so any single current member restores a revoked member's write capability
by leaking it (§15 already flags this blast-radius shape for `K_tag_e`); and ABE gating
cannot distinguish a superseded old device from its successor, since the old credential
still satisfies every attribute the broadcast is gated on.

**Accepting the gap** — revocation that ends read but not write is not the §11 the rest of
the design leans on, and §1's adversary explicitly includes a compromised member whose
standing the group must be able to end. Not acceptable, and refusing it in writing is the
point of this section.

---

## Replacement text

### §9.1 — the routine proof statement (replaces the existing block)

> ```
> ∃ sk_epoch, sk_cred, r_root, pk_epoch, epoch_cert, merkle_path, exclusion_witnesses such that:
>   epoch_cert verifies as a valid signature over pk_epoch, by some pk_root committed in Root_tier2
>   ∧ sk_cred and r_root together open that credential's committed leaf
>   ∧ that leaf is absent from the revocation set at the current epoch (§11)
>   ∧ Hash(sk_cred, leaf, agora_id) is absent from the migration-spend set (§9.3)
>   ∧ the action's own output is correctly derived (below)
> ```
>
> The revocation-set root and migration-spend root are public inputs alongside the
> accumulator root; a verifier accepts a routine proof only against the current epoch's
> three roots. The two non-membership clauses are what make §5.2's definition of a current
> credential a proven fact rather than a verifier's unaided obligation.

### §9.3 — the consuming nullifier, named (added where the old leaf's consumption is described)

> The nullifier consuming the old leaf is `Hash(sk_cred, leaf_old, agora_id)` under its own
> domain. It is bound to the specific leaf being consumed, not only to the credential:
> `sk_cred` carries across the lineage deliberately (above), so a derivation over the key
> alone would be constant for the credential's life — spent once at the first migration and
> colliding at every subsequent one. Binding the leaf gives each migration its own spend
> while preserving the property that one leaf admits one successor.

### §11 — the asymmetry paragraph (replaces it, superseding the interim note)

> **Revocation is asymmetric in effect, and both sides are closed deliberately.** Write
> capability ends because every routine proof must show the credential's leaf absent from
> the revocation set at the current epoch (§9.1); the leaf itself never leaves the
> accumulator (§5.2), and does not need to. Read capability ends through the tag-key
> broadcast: a revoked member already holds the current epoch's `K_tag_e` and the content
> keys gated alongside it (§6.4), and those are replaced only at an epoch boundary —

(the paragraph then continues with the existing early-advance text unchanged)

### §11 — new paragraph, following the asymmetry paragraph

> The revocation set and the migration-spend set (§9.3) are served to members whole,
> member-gated like roots (§7), and non-membership witnesses are computed locally by each
> Persora. A witness request naming a specific leaf would disclose to Skiora exactly which
> credential is about to act; serving the full set is what keeps the request anonymous, and
> is affordable because both sets grow with revocations and migrations, never with
> membership or content.

### §5.2 — appended to the "presence does not by itself mean current" paragraph

> All three conditions are established inside every routine proof (§9.1): inclusion by the
> membership path, the other two by non-membership proofs against the revocation-set and
> migration-spend roots. An implementation verifying inclusion alone is nonconformant, not
> merely weaker.

### §10.1 — the on-log list, revocation bullet extended

> - the revocation-set root (§11) and the migration-spend root (§9.3) — the two exclusion
>   roots every routine proof proves non-membership against — so exclusion state is
>   publicly consistent and cannot be forked per member;

### §8.3 — appended to the revocation-staleness paragraph

> Concretely, offline verification checks proofs against the cached exclusion roots (§9.1),
> so "as of my last sync" is precisely the epoch of the cached roots.

---

## Consequences

**Gained:** revocation actually revokes and migration actually supersedes. §11's two-claims
split becomes real — permanence of past attestation, currency checked separately — instead
of the first claim quietly covering both.

**Gained:** §8.4's "currently-valid credential" claim becomes true. Today a live-auth proof
from a revoked member verifies; under this statement it cannot.

**Gained:** a credential lineage can migrate more than once, which the implemented
derivation silently forbade.

**Paid:** every routine proof grows by two non-membership paths. With an indexed tree this
is two membership paths plus range comparisons per proof — real constraint cost, priced
when the proving system is chosen, and the reason the structure choice is deferred to that
decision rather than made here.

**Paid:** a second accumulator structure (keyed, with non-membership witnesses) joins the
positional one in `nymora-accumulator`.

**Paid:** the migration-spend set's root becomes public where the spent set was previously
Skiora-private state. The root reveals nothing per entry, but its insertion cadence on the
transparency log reveals migration frequency — an event class §16.3 already treats as
observable, since every migration also appends a visible successor leaf.

**Not addressed:** how the group identifies which leaf to revoke without identity — a §11
governance question, entangled with the revocation-status index contradiction (review
finding F2), and untouched here. Also untouched: 0009/0010, and the stale duplicate proof
statements in §5.3/§6.5 (review finding F6), which should be corrected to reference §9.1's
statement rather than restating it.

## Note for implementers

**`nymora-crypto/src/nullifier.rs`** — `migration` currently diverges from §9.1's already
normative text ("over the identifier of the … leaf they consume"): it absorbs only the key
and the agora. The signature becomes
`migration(key: &CredentialKey, leaf: &Commitment, agora: &AgoraId)`, absorbing key, leaf,
agora in that order. This is a conformance fix to existing spec text and may land ahead of
the rest of this proposal. The `nullifier/migration` conformance vectors move; the family
is provisional, so vectors are expected to move, but the new values must be cross-checked
against an independent implementation per the vectors README.

**`nymora-accumulator`** — the exclusion sets need a keyed structure with non-membership
witnesses; the existing positional tree cannot provide one. The structure lands with the
proving system. What can land earlier is the interface and its constraints, mirroring the
existing crate discipline: no occupancy reporting beyond what the served-whole model
already discloses to members, and domain-separated leaf hashing distinct from the
positional tree's tags.

**`nymora-ports`** — `Slot::CachedRoot` is keyed by `{policy_class, epoch}`; the exclusion
roots are per-agora, not per-class, so caching them for §8.3 requires new slot variants
(e.g. `CachedRevocationRoot(Epoch)`, `CachedMigrationSpendRoot(Epoch)`) when offline
verification is implemented. The integrity note on `CachedRoot` applies to them with full
force: a tampered cached exclusion root makes a revoked credential verify offline.

**Circuit** — public inputs grow by two roots. The two non-membership witnesses are private
witnesses, like the membership path.
