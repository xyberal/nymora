# Proposal 0013 — The credential leaf commits to its agora

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §9.1
**Supersedes:** nothing

> **Decided in session and applied directly.** The change is small and its justification is
> §5.1's existing normative rule rather than a new argument, so it is recorded here for the
> history rather than drafted for a decision.

---

## Problem

§5.1 already requires this. Its second bullet reads:

> **No value derived within one agora is ever reused in, or derivable from, another.** This
> covers nullifiers, pseudonyms, **commitments**, tags, ledger entries, and any handle presented
> to a Skiora.

The leaf commitment is a commitment, and it is not compliant. §9.1 specifies

```
leaf = Commit(pk_root, sk_cred, r_root)
```

with no agora among the inputs. Two agoras given the same three values produce the same leaf.

Today they never are, because §5.1's *first* bullet requires all key material to be generated
freshly and independently per agora. So the property holds — but it holds because a client
behaves correctly, not because the construction makes it so. That is the weaker of the two
guarantees §5.1 offers, and the section asks for the stronger one in the same breath.

The same argument settled the policy class identifier in task 2.1: a value that could be shared
across agoras was bound to the agora instead, for one absorbed field.

### Why it is worth fixing even though nothing currently breaks

A leaf lives in a per-agora accumulator, so a leaf from one agora already fails a membership
proof against another's root. The repair is defence in depth, not a fix for a live break.

What it buys is that a key-generation bug stops being a cross-agora linkage bug. Reusing
material across agoras is the kind of mistake that a backup-and-restore feature, a "clone this
credential" convenience, or a test fixture leaking into production all produce naturally, and
under the present construction each of those silently yields identical leaves in two agoras.

The cost is one field element in a circuit that does not yet exist. It will never be cheaper.

## Decision

The leaf commits to its agora:

```
leaf = Commit(pk_root, sk_cred, r_root, agora_id)
```

---

## Replacement text

### §9.1 — the leaf definition

> The accumulator leaf commits to `pk_root` (a public verification key derived from `sk_root`)
> and to `sk_cred` (below), using an opening value `r_root` fixed once at credential creation,
> and is bound to the agora it belongs to:
>
> ```
> leaf = Commit(pk_root, sk_cred, r_root, agora_id)
> ```
>
> The `agora_id` is not secret to the parties who hold this leaf and adds no hiding. It is
> present so that §5.1's requirement — that no commitment derived within one agora be derivable
> from another — holds by construction rather than by a client having correctly generated fresh
> material per agora. Both are required; only one of them survives a key-generation bug.

### §9.1 — the `r_root` paragraph, first sentence

> Every proof of root-leaf membership must open `Commit(pk_root, sk_cred, r_root, agora_id)`,
> which requires `r_root` itself as a witness.

---

## Consequences

**Gained:** cross-agora leaf distinctness is structural. A credential whose key material was
duplicated into a second agora by mistake no longer produces an identical leaf there.

**Paid:** one absorbed field, and one more input the circuit must take. `agora_id` is 32 bytes
and does not fit in a single field element under an algebraic hash, so the encoding question
§16's note already raises for the attestation nullifier now also applies here — the same
encoding must be used in both places.

**Unchanged:** hiding, binding, and the opening. `agora_id` is known to everyone who could
verify this leaf, so committing to it discloses nothing that was not already available to them.

## Note for implementers

`commit()` in `nymora-crypto` takes the agora last, matching the nullifier functions, which
already place the agora after the context they scope. Its known-answer vector changes, and the
new one is cross-checked against an independent implementation rather than recorded from the
code.
