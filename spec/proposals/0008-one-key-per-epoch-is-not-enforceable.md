# Proposal 0008 — Define when an epoch ends, and stop counting on the epoch key

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §4.3, §5.3, §9.1

> **Applied as drafted, with one addition.** §9.1's "nullifier keys are scoped to the window
> they guard" paragraph — added by 0005 — listed vouching, policy approval, and authorship as
> epoch-scoped. Three of those move here, so the paragraph was rewritten to introduce
> authorship alone rather than left contradicting the text below it.
>
> **Amendment — the application was incomplete, and was finished later.** A review found four
> places in §9.1 that this proposal's decision invalidated and that the original application
> did not reach. They are corrections to this proposal's own application, not new decisions;
> every one follows from the text above.
>
> 1. The paragraph introducing the routine-proof statement still read *"Every ordinary proof —
>    vouching, authoring content, corroborating, live authentication — uses `sk_epoch`"*, and
>    the statement's nullifier line still read `Hash(sk_epoch, message_hash, agora_id)`. For
>    vouching both the key and the context were wrong, two paragraphs after the text saying so.
>    This was the most consequential miss: the statement block is what a circuit implementer
>    transcribes, and it contradicted the decision it was supposed to follow.
> 2. That statement's witness list omitted `sk_cred`, although the leaf it opens commits to it
>    — `Commit(pk_root, sk_cred, r_root)`. A statement naming only `r_root` cannot open that
>    leaf. The list is now correct and says why.
> 3. The `r_root` paragraph still named the two-argument leaf `Commit(pk_root, r_root)`. The
>    same stale expression had propagated into `nymora-core`'s `Domain::Commitment` and
>    `Commitment` doc comments, and was corrected there too.
> 4. The certification-by-use paragraph claimed a seized dormant device *"yields nothing that
>    can recompute even the previous epoch's nullifiers."* That was true when 0007 wrote it and
>    false once this proposal made three nullifier contexts durable: such a device still holds
>    `sk_cred` and `r_root`. The claim is now bounded to authorship, with the governance
>    exposure stated rather than implied.
>
> Item 4 is why this amendment exists rather than a fresh proposal. The failure mode is not
> that a decision was wrong; it is that a decision's consequences were applied where the
> proposal pointed and not where they also reached. A proposal that changes what a key *is*
> touches every claim resting on what that key *was*.
**Answers:** the open question left by 0007 — who decides an epoch has ended
**Corrects:** the rationale 0005 gave for epoch-bounding proposals and vouch sessions, and
renames the durable key it introduced

---

## Problem

0007 left one question open: deletion of an epoch key is triggered by the epoch ending, but
the engine has no clock by design, and a device clock can be wrong or manipulated. Working
that through answered it — and exposed a second problem that the first was hiding.

### Part 1: what "ended" means

The two failure modes are not symmetric.

| | Consequence | Recoverable? |
|---|---|---|
| Recognised **late** | The key outlives its window; forward secrecy degrades by exactly the lateness | **No** |
| Recognised **early** | The member certifies a new key next time they act | Yes — one prompt |

An asymmetry that sharp settles the design: fail toward early.

### Part 2: nothing binds a credential to one epoch key per epoch

0007 established that certification is purely local — `epoch_cert` never leaves the device,
there is no counterparty, and nothing is published. That is what makes lazy rollover work.
It also means nothing limits how many epoch keys a credential holds in a single epoch:

```
Mallory certifies pk_epoch_a for epoch 7 → approves proposal P → nullifier N_a
Mallory certifies pk_epoch_b for epoch 7 → approves proposal P → nullifier N_b ≠ N_a
```

Both certificates are valid signatures over their payloads by the `pk_root` committed in her
leaf. Both proofs verify. Two approvals, one credential, **within one epoch**.

The verifier cannot detect this. `pk_epoch` is a private witness (§9.1) and making it public
would reintroduce exactly the same-epoch cross-post linkability that §9.1 keeps it private to
avoid. There is no per-credential public marker to collide against.

**This invalidates the reasoning in 0005.** That proposal confined policy proposals and vouch
sessions to a single epoch so their nullifiers would stay comparable — sound only if a
credential has one epoch key per epoch, which the specification never states and nothing
enforces. Migration is unaffected: 0005 keyed it on a durable secret, which is the fix this
proposal generalises.

**Client-side enforcement cannot close it.** The obvious remedy — a monotonic counter
refusing to sign a second certificate for the same epoch — fails against the adversary that
matters. The member is the attacker here, they control the device, and anything enforced
below the verifier is advisory to them.

## Decision

### 1. An epoch ends at whichever signal arrives first

Deletion fires on the earlier of: the transparency log (§10.1) publishing an advance, or the
local clock reaching the agora's maximum interval (§9.1). A manipulated clock can then only
cause *earlier* deletion, which is safe; a stalled or withheld log cannot hold a key open past
the interval.

The engine is not given a clock. The host delivers epoch-end as an **event**, and the
whichever-first policy is the host's.

An offline member is not locked out. Deletion removes the old key; it does not prevent
certifying a new one. A member out of contact certifies against the last epoch they know
about and risks rejection if the agora has since advanced, which degrades gracefully and is
consistent with §15's position on connectivity-dependent freshness.

### 2. Counted nullifiers key on the credential, not the epoch

`sk_migrate` is renamed **`sk_cred`** and extended: vouching (§5.3), policy approval (§4.3),
and migration (§9.3) all derive their nullifiers from it. It remains generated at credential
creation, independent per agora (§5.1), committed in the leaf, and never rotated.

```
leaf = Commit(pk_root, sk_cred, r_root)
```

Uniqueness then holds regardless of how many epoch keys a credential certifies, because the
count no longer depends on the epoch key at all.

**Authorship (§6.1) stays on `sk_epoch`.** It is the one context whose objects are public, so
it is the one place a durable key would let an adversary sweep published bundles and attribute
content retroactively — the exposure 0005 and 0006 worked to avoid. Its uniqueness is also the
least load-bearing: with corroboration deferred (0006), the replay §6.1 cites the nullifier
for is already prevented by the proof's Fiat-Shamir binding to `message_hash`.

**The additional exposure is close to nil.** §10.2's receipt ledger already records *every*
action a credential takes, on the device, per agora. An adversary who compromises the device
already holds the member's complete governance history for that agora; deriving these
nullifiers from `sk_cred` gives them nothing further. The only adversary it assists is one
holding `sk_cred` but not the ledger — an odd combination, since both live in the same
storage.

### 3. Epoch-bounded governance survives, for different reasons

§4.3 and §5.3 keep their expiry rules. The justification changes: they no longer exist to keep
nullifiers comparable, but to bound governance latency and to keep quorum arithmetic fresh
across membership changes — the same reason 0007 gives for a forced advance expiring them.

---

## Replacement text

### §9.1 — the deletion paragraph, sentence appended

> An epoch ends at whichever comes first: the transparency log publishing an advance (§10.1),
> or the agora's maximum interval elapsing on the local clock. Failing toward the earlier
> signal is deliberate — a key recognised as expired too late outlives its window and cannot
> be recovered, while one destroyed too early costs a single re-certification. A member out of
> contact may still certify a key against the last epoch they know of, and risks rejection if
> the agora has advanced.

### §9.1 — new paragraph, after the nullifier-key paragraph

> **A credential may hold more than one epoch key in an epoch, and nothing can prevent it.**
> Certification is purely local, so a member may generate and certify a second `sk_epoch` for
> the same epoch number at will. The verifier cannot detect this: `pk_epoch` is a private
> witness, and publishing it to make duplicates visible would reintroduce the same-epoch
> linkability it is kept private to prevent. Enforcement below the verifier — a monotonic
> counter in the authenticator, say — is advisory only, since the member who would exploit
> this controls the device.
>
> Any count that must be correct therefore cannot rest on the epoch key. Vouching (§5.3),
> policy approval (§4.3), and migration (§9.3) derive their nullifiers from `sk_cred`, which
> is one per credential by construction. Authorship (§6.1) continues to use `sk_epoch`: its
> objects are public, so a durable key there would permit retroactive attribution of content,
> and its uniqueness is in any case secondary to the proof's binding to `message_hash`.

### §9.1 — `sk_migrate` renamed throughout

> `sk_migrate` → `sk_cred`, with the leaf commitment becoming
> `leaf = Commit(pk_root, sk_cred, r_root)` and the description broadened from "used for no
> other purpose" to "used for every nullifier whose count must be correct."

### §4.3 — the expiry sentence, rationale replaced

> A proposal expires at the end of the epoch in which it was raised, and must be re-raised to
> continue. The reason is not nullifier comparability — approvals are counted by a nullifier
> derived from `sk_cred`, which does not rotate (§9.1) — but quorum freshness: a proposal that
> outlived the membership set it was raised under would accumulate approvals against a
> threshold that no longer describes the group. An early advance following a revocation
> expires it for the same reason (§11).

### §5.3 — the expiry sentence, rationale replaced

> A vouch session must finalize within the epoch in which it was opened; one that does not is
> abandoned rather than carried over. As with policy proposals (§4.3), this bounds how long an
> admission decision may accumulate attestations against a fixed threshold, rather than serving
> any property of the nullifier itself.

---

## Consequences

**Gained:** the counts the protocol actually depends on — admission thresholds, one approval
per credential, one successor per credential — become correct rather than contingent on an
unstated and unenforceable property.

**Gained:** epoch end is defined without giving the engine a clock, and without trusting the
device's.

**Paid:** three nullifier contexts move to a durable key. As argued above the marginal
exposure is close to nil against a device-compromising adversary, but it is not zero against
one who obtains `sk_cred` alone.

**Paid:** a member out of contact past the interval must certify optimistically and may be
rejected. Previously they could act on a still-valid key.

**Unchanged:** content nullifiers, cross-agora isolation, and the epoch structure's bound on
impersonation.

## Note for implementers

`MigrationKey` in `nymora-core` becomes `CredentialKey`. In `nymora-crypto`, `vouch` and
`policy` take it in place of `EpochSecretKey`; `attestation` keeps `EpochSecretKey`;
`migration` is unchanged but for the type name. `commit()`'s parameter is renamed. Domain tags
are untouched, so no derived value changes except through the key substitution itself.

The split is worth keeping visible in the signatures: three functions taking a durable key and
one taking an epoch key is the whole of this proposal, expressed where a caller will see it.

## Open question

**Does anything else rest on one-key-per-epoch?** This proposal audits the nullifier contexts,
which is where counting happens. §10.2's receipt-ledger entries are signed with `sk_epoch`, so
a member holding two keys in one epoch could in principle maintain two chains and present
whichever suits a replay witness — the ledger is per credential, and a witness has no way to
know it has been shown all of them. That is a detection mechanism rather than a count, so it
is out of scope here, but it follows the same fault line and should be examined before §10 is
implemented.
