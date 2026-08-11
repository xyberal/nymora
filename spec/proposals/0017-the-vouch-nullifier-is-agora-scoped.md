# Proposal 0017 — The vouch nullifier is agora-scoped

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §5.3
**Supersedes:** nothing

> **Decided in session and applied directly.** The change is one absorbed field and its
> justification is proposal 0013's existing argument rather than a new one, so it is recorded
> here for the history rather than drafted for a decision.

---

## Problem

The vouch nullifier was the only count-nullifier that did not absorb the agora:

```
nullifier = Hash(sk_cred, session_id)
```

The stated reason was that a session identifier is already unique to the agora that issued it —
so absorbing the `agora_id` alongside it would add nothing. That reasoning assumes an honest
issuer. Session identifiers are issued by Skiora, and Skiora is an adversary in this threat
model (compelled or colluding operators, §1, §16.2): two colluding Skioras can issue the *same*
`session_id` deliberately.

Under that collision, cross-agora distinctness of vouch nullifiers rests entirely on `sk_cred`
being freshly generated per agora — a client behaving correctly, which is precisely the
assumption proposal 0013 refused to rest on for commitments. Its list of the ways that
assumption fails is unchanged: a backup-and-restore feature, a "clone this credential"
convenience, a test fixture leaking into production. Any of those, combined with colluding
operators, yields equal vouch nullifiers in two agoras — confirmed cross-agora membership
linkage, the exact correlation §16 bounds.

`policy()` and `migration()` already absorb the agora. Vouching was the odd one out for a
reason that dissolves the moment the issuer is adversarial.

## Decision

The vouch nullifier absorbs the agora, after the session identifier — matching the convention
of the other derivations, which place the agora after the context they scope:

```
nullifier = Hash(sk_cred, session_id, agora_id)
```

---

## Replacement text

### §5.3 — the attestation proof statement

> Each attestation proof establishes the full membership chain of §9.1 in zero knowledge —
> that statement is normative there, and only its final clause varies by action. For vouching
> the final clause is:
>
> ```
> nullifier = Hash(sk_cred, session_id, agora_id)
> ```
>
> The nullifier derives from `sk_cred` because a threshold is a count and a count cannot rest
> on a key its holder can mint twice (§9.1). It is agora-scoped even though a session
> identifier looks unique enough without it: session identifiers are issued by Skiora, and two
> colluding Skioras can issue the same one, so cross-agora distinctness must hold by
> construction rather than rest on the issuer being honest or on key material having been
> correctly generated fresh per agora (proposal 0013).

---

## Consequences

**Gained:** cross-agora distinctness of vouch nullifiers is structural. It now survives the
two failures it previously depended on being absent — a colluding issuer and a key-generation
bug — needing both to occur *and* the property still holds.

**Paid:** one absorbed field, in a circuit that does not yet exist. The provisional
`nullifier/vouch` conformance vector moves, which is what provisional means; the new value is
cross-checked against an independent implementation as `vectors/README.md` requires.

**Unchanged:** the within-agora counting property. Distinctness inside one session never
depended on the agora field; it comes from `sk_cred` being one per credential.

## Note for implementers

`vouch()` in `nymora-crypto` takes the agora last, after `session_id` — every nullifier
derivation now ends with the agora it is scoped to, and every one absorbs it.
