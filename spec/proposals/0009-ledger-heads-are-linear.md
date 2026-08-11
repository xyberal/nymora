# Proposal 0009 — Make the ledger head a linear resource

**Status:** **Closed — superseded by 0010**, which defers the mechanism this repairs
**Affects:** §9.3, §10.3, §10.4
**Depends on:** 0008, which is what exposes the gap — see below
**Corrects:** §10.3's claim that head-pinning makes the ledger "non-forkable"

> **Closed without application, not discarded.** Proposal 0010 deferred §10.2–§10.4, and
> this construction went with them — as their reintroduction prerequisite: §10.4's closing
> note names linear-head registration as what makes one-chain-per-credential hold by
> induction if the ledger returns, with entries carrying self-verifying action artifacts
> rather than signatures and the member as the verifier. The open recovery question below
> closed with the deferral, and 0010 records why it was never answerable: recoverability
> from durable secrets and unlinkability against durable secrets are the same statement
> with opposite signs.

---

## Problem

§10.3 already anticipates the attack this proposal closes. It opens by naming it — *"a rogue
Persora could keep two sets of books — a clean 'show' ledger and a real hidden one"* — and
answers with three layers: Skiora refuses any action not carrying its ledger entry, pins one
head per credential and rejects entries that do not extend it, and checkpoints those pinned
heads to the transparency log so a rogue Skiora cannot secretly permit a fork.

That is sound within an epoch. The gap is at the boundary, and it has two halves.

### The handle's derivation is unspecified, and 0008 makes it load-bearing

§10.4 has the pinning handle rotate per epoch, unlinkably, so Skiora cannot stitch a
credential's activity into one thread. The specification never says how the handle is
derived — which was harmless until 0008 established that a credential can hold more than one
`sk_epoch` in a single epoch, since certification is purely local and invisible.

If the handle derives from the epoch key, a member with two epoch keys presents two handles.
Skiora pins two heads, neither of which forks, and accepts both. Head-pinning does not fail
loudly; it succeeds twice.

### Rotation removes the check that would catch truncation

Because handles are unlinkable across epochs — the property §10.4 exists to provide — nothing
verifies that a new epoch's chain continues the previous one. A member may start a fresh chain
at any boundary and later present a consistent but partial history, dropping whatever they
prefer a replay witness not to see.

### Why proving continuity is not enough

The obvious repair is to require a proof, at registration, that the new chain's first entry
extends the head pinned in the previous epoch. It does not work, because continuity is a
property *of a chain* while the attack is about the *number of chains*. A proof about one
chain cannot establish that no other exists:

```
epoch 7   register H_a → chain A (clean)      register H_b → chain B (real)
epoch 8   register H_c, continues A  ✓        register H_d, continues B  ✓
```

Both chains are continuous. The proof is satisfied twice, and the member still keeps two sets
of books.

## Decision

Registering a handle **consumes** the previous head rather than merely referencing it. Each
registration spends exactly one unspent pinned head and produces exactly one new head.

Uniqueness then follows by induction rather than by enforcement:

- **Base.** A credential is admitted with one chain, anchored to its accumulator leaf. One
  head exists.
- **Step.** Each registration consumes one head and produces one. The count is invariant.
- **Therefore.** Two registrations in an epoch would require two unspent heads. There is one.

Chain multiplicity cannot be created at a boundary, only inherited, and there is nothing to
inherit it from. Within an epoch §10.3 already applies unchanged, since entries extend the
pinned head rather than creating a new one.

This is the same construction as the migration nullifier (§9.3): consume the predecessor so
that exactly one successor can exist. The head becomes a linear resource — spent and reissued
once per epoch — rather than a label Skiora looks up.

### The handle needs no secret at all

Consuming the predecessor makes the handle's derivation irrelevant to uniqueness, which is
what allows the privacy-preferring choice. The handle is **random**, generated fresh at each
registration, and reveals nothing to anyone — including an adversary holding the credential's
own key material.

The alternative considered was a handle derived from `sk_cred` plus a per-epoch registration
nullifier to enforce one-per-epoch. It is simpler — a hash and a duplicate check, against a
set-membership proof — but it leaks: an adversary holding `sk_cred` recomputes every past
registration nullifier and learns which epochs the member was active in. Since pinned heads
are checkpointed to a public log (§10.3), that is a timeline reconstructible from public data,
which is the activity graph §10.4 exists to prevent. The proving cost is the better thing to
spend.

### What the registration proves

In zero knowledge, at each epoch boundary:

```
∃ prev_head, prev_handle, chain_entry such that:
  prev_head is in Skiora's pinned-head set and is unspent
  ∧ chain_entry.prev_hash = prev_head
  ∧ new_head = Hash(chain_entry)
```

revealing only `new_head` and the fresh random handle. Skiora marks the consumed head spent.
The unspent-set membership proof is the new machinery this requires; everything else is
already present.

### Migration carries the head forward

§10.2 states that a member's next device after migration can replay their own ledger, so the
chain must survive the credential change. The successor credential inherits the unspent head,
proven alongside the migration itself (§9.3) — the same proof that already shows the successor
leaf commits to the same `sk_cred`.

Without this, migration either breaks the chain or mints a second one, which would reintroduce
exactly the multiplicity this proposal removes. Path 2 (lost or seized device) does not carry
it, consistent with that path producing a structurally new credential.

### Skiora is not newly trusted

Tracking which heads are spent is Skiora's job, and a rogue Skiora could honour a double-spend
— the same exposure §10.3 already identifies for head-pinning, and closed the same way: pinned
heads, and now their spent status, are checkpointed to the transparency log (§10.1). The three
layers stand unchanged.

---

## Replacement text

### §10.3 — the head-pinning bullet, second sentence replaced

> Skiora pins the latest committed ledger head for each credential (identified only by an
> unlinkable per-epoch handle — §10.4). Within an epoch it accepts only entries extending the
> single head it last recorded, so a divergent second chain references a `prev_hash` Skiora
> does not recognize as current and is rejected.
>
> Across an epoch boundary the handle rotates and cannot be linked to its predecessor, so
> extension is not something Skiora can check by lookup. Registering a handle therefore
> **consumes** a head rather than referencing one: the member proves in zero knowledge that the
> new chain extends some unspent head in the pinned set, and Skiora marks that head spent. Each
> registration spends one and produces one, so a credential admitted with a single head can
> never hold two — chain multiplicity cannot be created at a boundary, only inherited, and
> there is nothing to inherit it from.

### §10.3 — the layer summary, second line replaced

> - **Skiora head-pinning** → a client cannot keep secret books, fork within an epoch, or
>   start a second chain across one.

### §10.4 — the handle bullet, sentence added

> The handle is freshly random at each registration and derived from no key material. It need
> not be, because uniqueness comes from consuming the previous head (§10.3) rather than from
> the handle's derivation — which means the handle leaks nothing even to an adversary holding
> the credential's own secrets. A handle derived from a durable secret would have been simpler,
> and would have let anyone holding that secret reconstruct the member's activity timeline from
> the public checkpoints, which is precisely what this section exists to prevent.

### §9.3 — path 1, after the `sk_cred` carry-forward paragraph

> The successor credential also inherits the old credential's unspent ledger head, proven in
> the same step. §10.2's guarantee that a member's next device can replay their own history
> depends on the chain surviving migration; a successor that started a fresh chain would either
> break that replay or create a second chain, which §10.3 exists to make impossible. Path 2
> does not carry the head, consistent with the structurally new credential it produces.

---

## Consequences

**Gained:** "one chain per credential" becomes a structural property rather than an assumption
holding only within an epoch. §10.3's non-forkable claim becomes true as stated.

**Gained:** the handle stops being a place where a secret could leak, because it stops being
derived from one.

**Paid:** an unspent-head set and a membership proof over it. This is the real cost — a second
accumulator alongside the credential one, and a proof obligation at every epoch boundary a
member is active in. It is paid only by active members, since an inactive member registers no
handle.

**Paid:** a member who loses their chain state without losing their credential cannot register
a successor handle and is effectively unable to act until they recover it. This wants an
explicit answer and does not have one — see below.

**Unchanged:** the three-layer trust structure, ledger contents remaining holder-only, and the
replay-witness mechanism.

## Note for implementers

`Domain::LedgerHeadHandle` exists in `nymora-core`'s registry, described as the handle under
which Skiora pins a head. Under this proposal the handle is random rather than derived, so that
tag is unused unless it is repurposed for the consumed-head proof's transcript. Leave it in
place; removing a tag renumbers nothing but does churn the registry, and a use is likely.

Nothing here is implementable before the accumulator exists, and the unspent-head set is a
second instance of it — worth knowing when that work is specified, since it argues for the
accumulator being generic over what it holds rather than specialised to credentials.

## Open question

**Ledger state loss without credential loss.** The chain is holder-only, so a member whose
device is intact but whose ledger state is corrupted or partially restored cannot prove
continuity and cannot register a new handle. Under §9.3 that is not a lost device, so path 2's
revoke-and-re-vouch is a heavy remedy for what may be a backup failure. Options include
allowing a quorum-authorised head reset, treating it as path 2 regardless, or having the member
prove continuity against the transparency log's checkpoints instead of local state. The last
looks most promising and least specified.
