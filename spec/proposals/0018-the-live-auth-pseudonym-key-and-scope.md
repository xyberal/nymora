# Proposal 0018 — The live-auth pseudonym takes the epoch key and is agora-scoped

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §8.1
**Supersedes:** nothing

> **Decided in session and applied directly.** Both decisions follow from arguments already
> settled — proposal 0005's window rule and proposal 0013's refusal to rest distinctness on
> correct client behaviour, extended by 0017 — so they are recorded here for the history
> rather than drafted for a decision. Implementing the derivation (phase 4) is what forced
> the two blanks to be filled.

---

## Problem

§8.1 step 4 derives the session pseudonym as:

```
pseudonym_i = Hash(sk_i, "conversation", context_id)
```

Two things are unspecified, and an implementation cannot leave either open:

1. **Which key is `sk_i`?** The credential holds three candidate secrets (`sk_epoch`,
   `sk_cred`, `r_root`), and the choice is not cosmetic — it decides what an adversary who
   later obtains the key can retroactively attribute.
2. **Nothing scopes the value to the agora.** Every nullifier absorbs the `agora_id` by
   construction (proposals 0013, 0017), and §5.1's isolation requirement names pseudonyms
   in the same list as nullifiers. The pseudonym derivation was the one place a
   secret-derived, externally visible handle did not absorb it.

## Decision

### The key is `sk_epoch`

Proposal 0005's rule decides this: a nullifier key — and a pseudonym is the same object
without the counting duty — is scoped to the window it guards. A session pseudonym guards
continuity within one conversation (§8.2); nothing is counted across sessions, so nothing
needs a durable key. And the durable choice would be actively harmful: `pseudonym_i` is
deterministic given the key and `context_id`, both of which appear in a channel's history,
so an adversary who later obtains a durable key could recompute the pseudonym for every
recorded session the credential ever joined — retroactive *presence* attribution, precisely
the class of linkage 0005 closed for content by keeping authorship on the epoch key.

With `sk_epoch`, that exposure expires with the epoch, matching §9.1's forward-secrecy
bound: a seized dormant device can attribute presence for at most the epoch it was seized
in — and only if a certified key exists at all.

### The derivation absorbs the agora

```
pseudonym_i = Hash(sk_epoch, context_id, agora_id)
```

`context_id` looks unique enough without it — it absorbs fresh nonces from every
participant. But cross-agora distinctness must not rest on every client's randomness being
correct, which is exactly the assumption 0013 refused for commitments and 0017 refused for
session identifiers: a nonce-reuse bug, a client restored from backup replaying its
commit-reveal state, or a deterministic test fixture leaking into production can each
reproduce a context — and colluding participants can copy every other contribution across
sessions deliberately. Combined with key material wrongly shared across agoras, equal
pseudonyms in two agoras would confirm cross-agora membership to everyone in both channels
(§16.1). One absorbed field makes the distinctness structural instead.

The informal `"conversation"` literal is subsumed by the registered domain tag
(`nymora/v0/live-auth/pseudonym`), which carries the same separation bindingly — the same
treatment every other derivation already has.

---

## Replacement text

### §8.1 — step 4

> **Step 4 — each participant posts one pseudonym and proof against the shared context:**
>
> ```
> pseudonym_i = Hash(sk_epoch, context_id, agora_id)   -- under the live-auth pseudonym domain tag
> proof_i = ZK(membership ∧ pseudonym_i correctly derived)
> ```
>
> The key is the **epoch key**, by the rule that a distinctness key is scoped to the window
> it guards (§9.1): a pseudonym guards continuity within one conversation, nothing is
> counted across sessions, and a durable key would let whoever later obtains it recompute
> the pseudonym for every recorded session the credential ever joined — retroactive
> presence attribution, the same class of linkage authorship avoids by using `sk_epoch`.
> The `agora_id` is absorbed even though `context_id` incorporates every participant's
> fresh nonce: cross-agora distinctness must hold by construction rather than rest on every
> client's randomness being correct or on key material having been generated fresh per
> agora (§5.1; proposals 0013, 0017).

---

## Consequences

**Gained:** both blanks are filled by rules the design already committed to, rather than by
implementation accident. Presence attribution is bounded by the epoch, like content
attribution. Cross-agora pseudonym distinctness survives a randomness bug, colluding
participants, and a key-generation bug — any two of the three.

**Paid:** one absorbed field in the pseudonym clause of a circuit that does not yet exist,
and a session pseudonym cannot survive an epoch boundary — a conversation running past a
rollover re-derives pseudonyms when its context refreshes (§8.1 already refreshes contexts
periodically for late joiners, so the machinery exists and §8.2's continuity was always
per-context, never per-credential).

**Unchanged:** within-session Sybil detection (§8.1) — it needs determinism within one
context, which any key choice provides. The commitment and context derivations, which
carry no secrets and stay exactly as §8.1 writes them.

## Note for implementers

`live_auth::pseudonym()` in `nymora-crypto` takes the agora last, after the context it
scopes — the same convention as every nullifier derivation. It is in the algebraic family
(the circuit recomputes it), so it sits behind the provisional feature and its vector is
provisional; the commitment, context, and SAS derivations are byte-family and settled.
