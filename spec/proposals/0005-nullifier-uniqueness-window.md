# Proposal 0005 — Match every nullifier's key lifetime to the window it guards

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §4.3, §5.3, §9.1, §9.3
**Depends on:** 0006 (defer corroboration). If corroboration returns, this proposal must be
reconsidered — see the alternative at the end.
**Relationship to 0001 and 0003:** independent of 0001. The migration key is software-held
under either custody model, for the reason 0003 established about `r_root`.

> **Applied as drafted, with two additions.** §9.1's key-hierarchy diagram and §9.3's path-1
> key generation both had to name `sk_migrate` — the latter to state that it is carried over
> rather than regenerated, which is the whole point of the change and was not visible in the
> flow as written.

> **Revised.** An earlier draft recommended a durable nullifier key for *every* context,
> accepting retroactive attribution of the whole content graph as the price. That draft
> treated corroboration as fixed. With corroboration deferred (0006), three of the four
> contexts fit inside an epoch and only migration needs a durable key — a far smaller
> exposure. The earlier recommendation is superseded by this one.

---

## Problem

§9.1 states the nullifier for routine proofs as:

```
nullifier = Hash(sk_epoch, message_hash, agora_id)
```

A deterministic nullifier enforces "at most once" only for as long as the key producing it
lives. Derive the same context under a fresh key and the result is an unrelated value the
verifier has no way to recognise as a repeat — and the verifier has nothing else to fall back
on, because it never learns which member acted. Nullifier equality is the entire mechanism.

**The lifetime of the key is therefore the window over which "once" is enforced.** With
`sk_epoch` that window is one epoch, while every object being guarded currently outlasts one.

| Guarded object | Accepts actions until | Failure with an epoch-scoped key |
|---|---|---|
| Credential leaf (§9.3) | It is consumed — no bound exists | **One successor credential per epoch.** Migrate, wait for rollover, migrate again from the same leaf; each successor carries the original tenure, vouch count, and tier |
| Policy proposal (§4.3) | Activated — no stated expiry | Approve once per epoch; a k-of-n threshold falls to one member and `k` rollovers |
| Vouch session (§5.3) | Finalized — no stated bound | A session spanning a rollover lets one voucher satisfy the threshold alone |

The first is the most damaging and the least fixable. §9.3 names the migration nullifier as
the sole mechanism consuming the old leaf, so an epoch-scoped one turns a single admitted
credential into as many as its holder has patience for — and every quorum in the protocol
rests on credentials being countable.

## Decision

Two different fixes, because the three contexts are not alike.

**Bound the windows that can be bounded.** A vouch session must finalize within the epoch it
opened; a policy proposal expires at the end of the epoch in which it was raised. Both are
internal, short-lived by nature, and re-raisable. With the window inside one epoch, the
epoch-scoped nullifier is exactly right and nothing further is needed.

**Give migration a durable key.** A credential leaf sits in the accumulator indefinitely and
there is no window to shrink. `sk_migrate` is generated at credential creation, independently
per agora, committed in the leaf, never rotated, and used for one purpose: deriving the
migration nullifier.

```
leaf = Commit(pk_root, sk_migrate, r_root)
```

The commitment is what makes durability enforceable rather than merely requested: the circuit
proves the migration nullifier derives from the same `sk_migrate` the leaf commits to, so a
member who invents a fresh one has no leaf containing it and cannot produce a proof.

### Migration carries the key forward

If `sk_migrate` were regenerated on each migration, migration would launder its own
nullifier: migrate, then migrate again from the successor, indefinitely. So the successor
leaf commits to the **same** `sk_migrate`, proven in zero knowledge as part of the existing
migration proof.

Path 2 (lost, stolen, or seized device) cannot carry it — the old key is unreachable, which
is that path's premise. Uniqueness resets there, gated by the quorum revocation and
re-vouching §11 and §5.3 already require. "Obtain a quorum" is the correct price for
resetting a nullifier.

### Why not derive it from `sk_root`

`sk_root` is durable and already authorizes migration, so it looks like the natural source.
It cannot be: the migration nullifier is recomputed inside the circuit, making its seed a
witness on every migration proof, and `sk_root` is non-exportable by §9.2. This is the third
value to hit that wall after `r_root` and the epoch witness set, and the rule is worth
stating once — **anything the circuit recomputes must be exportable, and therefore cannot be
hardware-held.**

## What this costs

Very little, which is the point of the narrowed scope.

`sk_migrate` produces exactly one value per credential per agora. An adversary holding it can
compute that credential's migration nullifier — which tells them a particular leaf was
consumed, and is useful only if they already know which leaf to ask about. It does not
attribute content, because content nullifiers remain epoch-scoped.

§9.1's forward-secrecy claim therefore survives essentially intact. The one honest caveat:
an adversary holding `sk_migrate` across a migration can confirm that two leaves belong to
the same credential lineage. That is one linkage event per migration, not a content graph.

---

## Replacement text

### §4.3 — new sentence after the approval flow

> A proposal expires at the end of the epoch in which it was raised, and must be re-raised to
> continue. This is not an administrative convenience: approvals are counted by nullifier,
> nullifiers are scoped to an epoch key (§9.1), and a proposal outliving that key could be
> approved a second time by the same credential under its successor.

### §5.3 — new sentence after the session flow

> A vouch session must finalize within the epoch in which it was opened; one that does not is
> abandoned rather than carried over. As with policy proposals (§4.3), the threshold is
> counted by nullifier, and a session spanning an epoch boundary would let a single credential
> attest twice under two keys.

### §9.1 — new paragraph, after the epoch-key paragraph added by 0004

> **Nullifier keys are scoped to the window they guard.** A nullifier enforces "at most once"
> only for the lifetime of the key that produced it, and the verifier has no other handle on
> identity to fall back on. Vouching (§5.3), policy approval (§4.3), and authorship (§6.1)
> guard objects that live within a single epoch, and use `sk_epoch` accordingly.
>
> Migration is the exception. A credential leaf remains in the accumulator indefinitely, so
> its consuming nullifier must remain valid indefinitely. Each credential therefore carries
> `sk_migrate`, generated at creation, committed in its leaf, never rotated, and used for no
> other purpose. Like `r_root` it is a witness the circuit recomputes against, so it is
> exported on every migration proof and held in software rather than hardware.

### §9.1 — leaf commitment

> ```
> leaf = Commit(pk_root, sk_migrate, r_root)
> ```

### §9.1 — "What this bounds", closing sentence added

> Attribution is bounded with it, with one exception. `sk_migrate` is durable by necessity,
> so an adversary holding it can confirm that two leaves belong to the same credential
> lineage across a migration. That is a single linkage per migration; it does not extend to
> content, whose nullifiers expire with the epoch key that produced them.

### §9.3 — path 1, after the migration-nullifier sentence

> The successor leaf commits to the **same** `sk_migrate` as the leaf it replaces, proven in
> zero knowledge alongside the migration itself. Were a fresh key generated instead, each
> migration would launder the nullifier consuming the previous leaf, and a member could spawn
> successor credentials without limit — every one of them carrying the tenure, vouch count,
> and tier of the original. Path 2 cannot preserve `sk_migrate`, since it presumes the old key
> is unreachable; uniqueness resets there, gated by the quorum revocation that path already
> requires.

---

## Consequences

**Gained:** credentials become countable, which every quorum in the protocol assumes.
Admission thresholds cannot be met by one patient member, proposals cannot be approved twice,
and a credential has exactly one successor.

**Paid:** governance and admission acquire a deadline. A proposal or vouch session that does
not complete within its epoch must be restarted. This couples epoch length to how long
group decisions realistically take — see the open question.

**Paid:** one field in the leaf and one witness in the migration circuit.

**Not paid:** retroactive attribution of content. That was the price of the earlier draft,
and deferring corroboration (0006) removes the need for it.

## The alternative, if corroboration returns

Corroboration accepts actions indefinitely on objects that circulate publicly. Restoring
§6.3 restores that combination, and with it the need for a durable key covering content
nullifiers — reinstating retroactive attribution of the content graph as an accepted cost.
The earlier draft of this proposal, preserved in version control, is that design.

A middle path exists and should be considered first: reintroduce corroboration with a bounded
acceptance window (a message may be corroborated only during the epoch it was authored, or
the one following). That keeps epoch-scoped content nullifiers. Its cost is that late
corroboration becomes impossible and that accepting the following epoch requires members to
retain the previous epoch key one epoch longer, weakening the deletion requirement in 0004.

## Note for implementers

`nymora-crypto` takes an opaque `NullifierKey` for all four derivations and deliberately
provides no conversion from `EpochSecretKey`. Applying this proposal splits that: three
contexts take a key derived from `sk_epoch`, and `migration` takes `sk_migrate`. Making
those distinct types would keep the distinction enforced by the compiler rather than by
convention. `commit()` gains a `sk_migrate` argument.

## Open question

**Epoch length is unspecified, and this proposal gives it a floor.** An epoch must be long
enough for a vouch session and a policy proposal to complete comfortably within it, or
governance becomes unreliable. It must be short enough for the forward secrecy in §9.1 to
mean anything. The specification currently gives neither bound, and this is the first
requirement that constrains the choice from below.
