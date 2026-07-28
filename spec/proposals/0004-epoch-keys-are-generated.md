# Proposal 0004 — Epoch keys are generated, not derived

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §9.1
**Supersedes:** nothing
> **Applied as drafted.** §9.3 was checked for the same defect and carries no epoch-key
> derivation wording; §5.1 already stated the rule correctly and needed no change.

**Relationship to 0001:** independent. 0001 argues that deriving epoch keys from root
material would destroy forward secrecy, but that argument sits inside a proposal deferred
until the circuit exists. The wording defect it depends on is live in the specification
today, so the correction is stated here and can be applied without waiting on 0001.

---

## Problem

§9.1 introduces the key hierarchy with:

```
sk_epoch  — freshly derived each epoch; used for routine, day-to-day operations
```

"Derived" is the wrong word, and it is wrong in a direction that quietly removes the
property the whole two-tier hierarchy exists to provide. The sentence admits three readings:

| Reading | What it means | Forward secrecy |
|---|---|---|
| **A. Generated** | `sk_epoch` is sampled fresh from the device CSPRNG each rollover | Holds |
| **B. Ratcheted** | `sk_epoch_{n+1} = KDF(sk_epoch_n)` | Holds *backwards only* — see below |
| **C. Derived from root** | `sk_epoch_n = KDF(sk_root ‖ n)` or from any long-lived seed | **Destroyed** |

Only A is safe, and the specification never says which is meant.

**Reading C destroys forward secrecy outright.** §9.1 claims that "prior epochs' keys have
already been discarded and cannot be reconstructed from the current one, so past activity
outside the compromised epoch stays unlinkable." Under C, anyone who later obtains the root
material recomputes *every* epoch key the credential has ever held, and with them every past
nullifier — retroactively linking the member's entire history in every agora. The §9.1 bound
becomes false. Against the coercion adversary of §1, who obtains the device and its holder,
this is the difference between losing one epoch and losing everything.

**Reading B is subtler and also wrong.** A ratchet is one-way in the right direction — past
keys cannot be recovered from the current one — so it survives the test above. It fails a
different one: an attacker holding `sk_epoch_n` can compute `sk_epoch_{n+1}` and every key
after it, so a single epoch compromise is no longer bounded to a single epoch. Worse, the
member's own honest rollover *re-certifies the compromised key*: they generate the next
epoch key by ratcheting, obtain `epoch_cert` for it from `sk_root`, and hand the attacker a
valid credential for the new epoch without any anomaly to detect. This contradicts §9.1's
"What this bounds" paragraph as squarely as C contradicts the sentence after it. A ratchet
also has no state-recovery story: a member restoring from backup or migrating a device
(§9.3) must land on the correct point in the chain or lose their credential, a constraint
the certificate model does not otherwise impose.

**Derivation buys nothing here.** The usual reason to derive rather than generate is to
avoid storing or transporting a key. That reason does not apply: `epoch_cert` already exists,
`sk_root` must already be reachable at rollover to sign it, and the key never leaves the
device. Derivation would trade a real security property for no operational gain.

§5.1 already states the correct rule for the multi-agora case — "all key material … and every
epoch key — is generated **freshly and independently per agora** … not derived from a shared
seed or master secret." §9.1's wording is inconsistent with the section it depends on.

## Decision

State reading A normatively, and state the deletion requirement that makes the §9.1 bound
true rather than merely asserted.

`sk_epoch` is **generated**, independently at each rollover, from the device's
cryptographically secure random source. It is never computed from `sk_root`, from `r_root`,
from a recovery seed, or from any previous epoch key. The previous epoch's key is destroyed
once rollover completes.

---

## Replacement text

### §9.1 — the tier listing

> ```
> sk_root   — committed (via its public counterpart) in the agora's accumulator; used rarely
> sk_epoch  — freshly generated each epoch and certified by sk_root; used for routine,
>             day-to-day operations
> ```

### §9.1 — new paragraph, immediately after the `epoch_cert` block

> **Epoch keys are generated, never derived.** Each epoch's `sk_epoch` is sampled
> independently from the device's cryptographically secure random source. It is never
> computed from `sk_root`, from `r_root`, from a recovery seed, or from the preceding epoch's
> key — including by a one-way ratchet. `epoch_cert` is what makes a freshly generated key
> valid; derivation is not a shortcut for that step but a defeat of it. Deriving from
> long-lived material would let anyone who later obtains that material recompute every past
> epoch key, and with them every past nullifier, retroactively linking activity that the
> epoch structure exists to keep separate; deriving from the previous epoch's key would let a
> single epoch's compromise extend to every epoch after it, silently re-certified by the
> member's own honest rollover.
>
> The corollary is a deletion requirement: once rollover completes, the previous epoch's key
> is destroyed. Forward secrecy across epochs rests on that deletion, not on the derivation
> structure — there is none.

### §9.1 — diagram label

> `sk_epoch + r_root` / *"epoch key fresh each epoch"* → *"epoch key generated fresh each
> epoch"*, and the `CERT -.-> SKE` edge label `"certifies"` is retained. No structural change;
> the diagram already shows certification rather than derivation, and is the one place the
> section states this correctly.

---

## Consequences

**Gained:** §9.1's forward-secrecy claim becomes true by construction rather than by
implication, and §9.1 stops contradicting §5.1. Implementations cannot arrive at C or B by
reading the section in good faith.

**Paid:** nothing structural — this fixes wording to match what the rest of the section
already assumes. It does close off a design an implementer might otherwise have reached for:
a member who loses their device state between rollovers cannot recompute the current epoch
key and must obtain a new one certified by `sk_root`. That is the correct behaviour, and it
is the path §9.3 already describes.

**Not settled here:** whether `sk_root` is reachable at every rollover is a custody question
belonging to §9.2 and Proposal 0001. This proposal fixes only what `sk_epoch` is; 0001
remains free to change what signs its certificate.

## Note for implementers

The reference implementation already assumes reading A. `nymora-core`'s domain registry
carries no epoch-key-derivation tag — one was written and removed for this reason — and
`nymora-crypto`'s KDF module documents epoch keys under "What this is *not* used for". If
this proposal is rejected in favour of a derivation, both must change, and the change is
protocol-breaking.
