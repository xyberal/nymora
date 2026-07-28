# Proposal 0003 — Correct the treatment of the commitment opening value `r`

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §9.1, §9.2

> **Applied as drafted, with one addition.** §9.2's Mechanism block also had the
> authenticator generating and deriving `r_root`/`r_epoch`, and its software-management
> paragraph was written around `r_epoch`. Both were corrected alongside §9.1: the
> authenticator now generates `sk_root` only, and `r_root` is named as software-held because
> it must be supplied on every proof.
**Relationship to 0001:** extracted from it. This correction is required regardless of how
the hardware-custody question in 0001 is settled, and is stated here so it can be applied
without waiting on that decision.

---

## Problem

§9.1 states that `r_epoch = KDF(r_root, epoch_number)` and that routine proofs "use
`r_epoch` as the membership-inclusion witness rather than `r_root` directly."

This is not realisable. The accumulator leaf is `Commit(pk_root, r_root)`, and proving that
leaf's membership requires **opening** that commitment, which requires `r_root` itself. A
one-way KDF output cannot open a commitment formed with its input — and that one-wayness is
the very property the derivation exists to provide. The two requirements are mutually
exclusive.

The section contradicts itself on this point directly, acknowledging the requirement one
sentence before contradicting it:

> Every proof of root-leaf membership requires `r` as a witness alongside `sk_root`

The underlying concern is legitimate: a long-lived secret should not sit in ordinary storage
carrying `sk_root`-like exposure without `sk_root`-like protection. The error is treating
`r_root` as though it carried signing authority. It does not.

## Decision

Reclassify `r_root` as what it is — a blinding value, not authority. It is supplied as the
membership-inclusion witness on every routine proof, held in ordinary OS-protected storage
alongside `sk_epoch`, and **not rotated**. The `r_epoch` derivation is removed.

|  | `sk_root` | `r_root` |
|---|---|---|
| What it authorizes | Epoch certificates, governance, migration | Nothing |
| Compromise alone permits | Permanent impersonation of the credential | Membership testing, *only* with a candidate `pk_root` |
| Required in routine proofs | No — the point of the hierarchy | Yes — unavoidable as the Merkle opening |
| Custody | Hardware (§9.2) | Software, with `sk_epoch` |

A value that must be exported on every operation cannot meaningfully be held in hardware
custody; the attempt to protect `r_root` as though it were a signing key is what produced the
contradiction.

---

## Replacement text

### §9.1 — circuit statement, `r_epoch` line replaced

> ```
> ∃ sk_epoch, r_epoch, pk_epoch, epoch_cert, merkle_path such that:
>   epoch_cert verifies as a valid signature over pk_epoch, by some pk_root committed in Root_tier2
>   ∧ r_root correctly opens that credential's committed leaf
>   ∧ nullifier = Hash(sk_epoch, message_hash, agora_id)
> ```
>
> (with `r_epoch` removed from the witness list and `r_root` added)

### §9.1 — the `r` rotation paragraph replaced in full

> **`r_root` is a blinding value, not authority, and is held in software.** Every proof of
> root-leaf membership must open `Commit(pk_root, r_root)`, which requires `r_root` itself as
> a witness. No per-epoch substitute is possible: any derivation one-way enough to protect
> `r_root` is, by construction, unable to open a commitment formed with it. `r_root` is
> therefore supplied on every routine proof, and cannot meaningfully be held in hardware
> custody — a value exported on every operation is not hardware-held in any useful sense.
>
> This is acceptable because `r_root` authorizes nothing. Its sole function is to hide
> `pk_root` from Skiora, which receives only the commitment at credential creation. An
> adversary holding `r_root` alone can forge no proof, sign no certificate, and impersonate no
> one; the value becomes useful only in combination with a candidate `pk_root`, and an
> adversary positioned to obtain both already holds the device. `r_root` is stored with
> `sk_epoch` in ordinary OS-protected storage, and is not rotated.

### §9.1 — diagram labels

> `sk_root, r_root` → `sk_root` (hardware); `r_root` moves to the software tier alongside
> `sk_epoch`.

### §9.1 — closing paragraph replaced

> Compromise of `sk_epoch` and `r_root` (the pair touched by every routine operation) is
> bounded to one epoch for impersonation purposes: `r_root` grants no authority on its own,
> and `sk_epoch` expires. Compromise of `sk_root` (touched only rarely, and ideally
> hardware-bound per §9.2) is total and permanent for that credential — which is exactly why
> it is never stored or used alongside the routine pair.

---

## Consequences

**Gained:** §9.1 becomes implementable. The witness set for routine proofs is stated
correctly, which is what the circuit (§6.5) must be built against.

**Paid:** `r_root` is a long-lived value in software storage. This is a smaller exposure than
the current text implies it is avoiding, because `r_root` conveys no capability by itself —
but it is a real value an attacker with device access obtains, and it is no longer presented
as protected.

## Note for implementers

If Proposal 0001 is later applied, its full §9.1 replacement already incorporates this
correction consistently (with `pk_proot` in place of `pk_root`). Applying 0003 first and
0001 later is safe and produces no conflict.
