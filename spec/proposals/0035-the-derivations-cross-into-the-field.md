# Proposal 0035 — The derivations cross into the field

**Status:** Draft
**Affects:** §5.2, §6.5, §9.1, §9.3, §15
**Builds on:** [proposal 0034](0034-the-circuit-instances-are-pinned.md) (the
Poseidon instance, the certificate equation, and the reference string — whose open
question 1, the payload encodings, this proposal answers) and
[proposal 0033](0033-the-proving-system-is-plonkish-kzg-over-bls12-381.md)

---

## Problem

Proposal 0034 pinned the primitives at instance level and left one gap, named as
its open question 1: the encodings. The pinned Poseidon consumes field elements of
the BLS12-381 scalar field; the protocol's values are bytes — 32-byte identifiers
(`agora_id`, `message_hash`, session contexts), variable-length identifiers
(session, proposal, and challenge strings), 64-bit epoch numbers, and secret keys
minted from raw device entropy. Every derivation the circuit recomputes is still
specified, and implemented, over the SHA-256 stand-in with length-framed byte
absorption and per-context string domain tags — conventions that have no meaning
inside an arithmetic circuit, where there are no lengths, no bytes, and every
absorbed element costs constraints.

Until the crossing is pinned, the same value has two identities: the bytes the
protocol stores and transmits, and the field element the circuit constrains. Two
implementations could agree on every mechanism and still derive different
nullifiers. This proposal fixes the crossing once, for every value the standardized
circuit touches — and with it, the concrete form of every derivation §9.1 states
abstractly as `Hash(...)`, so the provisional primitives can retire.

## Decision

### 1. The field-entry rule

**A 32-byte identifier enters the field by little-endian interpretation with bits
254 and 255 cleared** — a 254-bit truncation, guaranteed below the field order
(2²⁵⁴ < r). One rule for every fixed-width identifier: `agora_id`,
`message_hash`, the live-auth `context_id`. The two discarded bits cost nothing
that matters: collision resistance of a 254-bit identifier space is not the
protocol's weakest link by dozens of orders of magnitude.

**A variable-length identifier is first compressed by the byte family** — SHA-256
under the new domain tag `nymora/v0/action-context`, length-framed as always —
**and the digest enters by the same rule.** This covers the session, proposal, and
challenge identifiers, which are opaque bytes the protocol never interprets. The
byte family is where framing lives; the field never sees a length.

**An epoch number enters as itself**: the u64 injected directly into the field.

**A field element leaves as its canonical 32-byte little-endian representation.**
Every 32-byte protocol value that names a field element — nullifiers, commitments,
roots, openings — carries exactly this encoding on the wire and in storage; a
non-canonical representation does not name a value.

**Secret keys are minted below their moduli by truncation.** `sk_cred` and
`r_root` are field elements: 32 bytes of fresh entropy with bits 254–255 cleared.
`sk_epoch` and `sk_root` are Jubjub scalars: 32 bytes of fresh entropy with the
top five bits cleared (2²⁵¹ is below the Jubjub subgroup order). Truncation
samples uniformly from a fixed power-of-two subset of the scalar field — not from
the whole field, and deliberately so: the alternative, wide reduction, needs twice
the entropy material to avoid modular bias, and what these keys need is
unpredictability, which 251 uniform bits provide beyond challenge. The dividend is
structural: §9.1's canonicity clause — one key, one representation, one nullifier
stream — is satisfied by construction, because a truncated key's canonical bytes
are the bytes it was minted from.

### 2. One action derivation, with the tag absorbed

The action clause — the only line of §9.1's chain that varies — derives one way
for all five actions:

```
output = Poseidon(ACTION, tag, key, context, agora_id)

tag:      0 authorship   1 vouch   2 policy approval   3 live-auth   4 verification
key:      sk_epoch for tags 0 and 3;  sk_cred for tags 1 and 2
context:  the action's identifier, entered by the field rule of decision 1
```

For verification access (tag 4) the statement constrains the public output to the
zero constant — access derives nothing (proposal 0019), and a constrained zero is
how "nothing" keeps the one proof shape §6.5 requires: every ordinary proof
carries the same public inputs, always.

Absorbing the tag is what replaces the per-context string domains. A vouch
nullifier and a policy nullifier over colliding identifier bytes still differ,
because 1 ≠ 2 inside the hash; an authorship proof cannot be replayed as a vouch,
because the tag is constrained by the statement, not labeled alongside it. The
separation that used to live in `nymora/v0/nullifier/*` tags now lives one element
deep in a single derivation — in-band, arithmetic, and checked by the circuit
itself. The four retired string domains remain registered and reserved: the
registry is permanent, and an unregistered name is a name that can be quietly
reclaimed.

The migration spend is deliberately **not** an action — it is a clause of both
statements, keyed by the leaf it consumes:

```
spend = Poseidon(SPEND, sk_cred, leaf, agora_id)
```

### 3. The leaf, the trees, and the signed messages

**The leaf commits to coordinates.** The circuit holds `pk_root` as a point, so
the commitment absorbs its affine coordinates rather than a compressed encoding it
would have to pay to decompress:

```
leaf = Poseidon(LEAF, pk_root.x, pk_root.y, sk_cred, r_root, agora_id)
```

**The positional accumulator folds the untagged 2-to-1 hash**: an interior node is
`Poseidon(left, right)`, and the leaf enters the fold as itself. The
leaf-versus-node domain tags retire; what replaces them is stronger than a label.
The pinned sponge writes the input length into the capacity element before
absorbing anything, so a 2-element node, a 3-element gap leaf, and a 5-element
credential leaf are computed by structurally disjoint functions — the Merkle
second-preimage substitution the old tags blocked is blocked by arity, in
arithmetic the circuit already performs.

**The exclusion sets are gap trees.** A set holds its keys truncated to 253 bits —
the ordering domain in-circuit comparison is sound over (the field's bit length
minus two) — sorted, with sentinels 0 and 2²⁵³−1 closing the ends. Consecutive
pairs are the gaps; each gap is a leaf `Poseidon(GAP, low, high)` in a positional
tree of the protocol depth (§5.2). Absence of key `t` is a **positive** statement:
inclusion of a gap with `low < t < high`, both comparisons strict and in-statement.
A present key can never satisfy it — its own truncation is what some gap boundary
holds — so soundness is unconditional. What truncation risks is only availability:
two distinct keys colliding in 253 bits (probability ~2⁻²⁵³) would leave the later
one unable to prove its own absence, an outcome the protocol survives and an
adversary cannot exploit. Non-membership witnesses shrink from 256 sibling hashes
to a depth-32 path with two boundary values.

**The signed messages are field-element sequences.** The certificate payloads
compress by the pinned hash, and the compression *is* the canonical signed
message — §9.1's length-framed byte layout retires:

```
m_epoch     = Poseidon(EPOCH_CERT, agora_id, epoch, pk_epoch.x, pk_epoch.y)
m_migration = Poseidon(MIGRATION_CERT, agora_id, pk_root_new.x, pk_root_new.y)
```

Everything the byte layout guaranteed survives the move: the domain leads, the
agora is inside the signed message, the two certificate kinds cannot collide
(distinct domains), and no boundary is movable (there are no boundaries — every
input is one field element, arity-pinned). The signature itself is the §9.1
equation over `m`, with the deterministic nonce derived as
`k = reduce(Poseidon(NONCE, sk, m))`.

### 4. The numeric domain registry

The field domains, permanent alongside the string registry:

```
1 LEAF   2 GAP   3 ACTION   4 EPOCH_CERT   5 MIGRATION_CERT   6 SPEND   7 NONCE
```

Zero is never a domain — it is the padding and empty-subtree value. Two
derivations are deliberately untagged and pinned by arity instead: the 2-to-1
accumulator node, and the transcript challenge `e = Poseidon(R.x, R.y, PK.x,
PK.y, m)`, whose five-element shape §9.1 states as an equation.

### What retires

The SHA-256 algebraic stand-in, the provisional Ed25519 certificate scheme, the
256-level sparse exclusion tree, the certificate byte encodings, and the two
features that fenced them (`provisional-algebraic-hash`,
`provisional-signature`). The wire widths do not move: keys 32 bytes, signatures
64, every derived value 32 — proposal 0034's continuity promise, kept. The stub
prover remains — a statement evaluator is still the right test backend — but from
this change on it evaluates the real primitives, so what it proves in the clear is
byte-for-byte what the circuit proves in zero knowledge.

## Alternatives rejected

**Wide-reduction hash-to-field for identifiers.** Uniformity over the full field
is the right tool where distributions must be indistinguishable from uniform;
identifiers need collision resistance, which truncation preserves at 254 bits.
Truncation is also auditable by eye — clear two bits — where reduction demands
either double-width material everywhere or an expansion step with its own domain
question.

**Packing identifiers into two limbs.** Lossless, and permanently doubles the
absorption cost of every identifier in every derivation the circuit ever computes,
to avoid a 2⁻²⁵⁴ collision consideration that is already dwarfed by every other
term in the security argument.

**Keeping per-context hash domains for the five actions.** Five separately-tagged
derivations would put the action distinction outside the uniform clause — five
circuit variants of the final line, selected rather than absorbed — reopening
exactly the shape variance §6.5 forbids. One derivation with the tag as an input
keeps the clause literally uniform.

**Carrying the byte framing into the circuit.** Absorbing length-framed bytes
in-circuit means bit-decomposing every field boundary — hundreds of constraints
per field for a guarantee (injective encoding) that fixed arity plus the
length-bearing capacity element already provide for free.

## Open questions

1. **The hardware key-store contract for `m`.** A real `KeyStore` backend signs
   the compressed message, which means either computing the Poseidon compression
   behind the trait or accepting `m` precomputed by the caller. The software
   backend computes it; the trait boundary for hardware backends is decided when
   one exists (with §9.2's binding design).

2. **The committed excerpt's size.** The reference-string excerpt (proposal 0034,
   decision 3) is committed at whatever power of two covers the statements with
   headroom; the exact `k` is recorded with the excerpt's checksums when the
   custody chain lands.

## Consequences

- Every provisional conformance vector regenerates, and gains independence it
  never had: expected values are now computed by a second implementation of the
  same pinned instances (the proving stack's own CPU primitives), not by the code
  under test. The settled byte-family vectors do not move.
- The specification stops describing two hash families where the circuit sees
  one: §9.1's derivations become the equations above, and the byte family's
  remit is exactly the values no circuit recomputes.
- Nothing is published and no compatibility exists to preserve (§1's pre-release
  posture): the values change wholesale, the protocol version does not.
- The workspace loses its last cryptographic stand-in. What remains provisional
  after this change is a *wiring* fact — the proving backend lives beside the
  workspace rather than behind the `ProofSystem` trait object in production
  callers — not a cryptographic one.
