# Constraint measurement

Two specification decisions are deferred to numbers rather than argued from taste:

- **Proposal 0001** — whether the hardware-custody root key can be verified in-circuit
  directly (non-native P-256 ECDSA) or needs the two-level indirection onto an
  embedded-curve key. Its decision rule: *if the P-256 configuration is an order of
  magnitude or more above the embedded-curve configuration, measured in the
  configuration most favorable to P-256, the two-level design is applied* — a negative
  result in a favorable configuration is conclusive, where one in a weak configuration
  proves nothing.
- **Proposal 0030** — the numeric value of the network-wide accumulator depth constant,
  priced by the per-level cost of the in-circuit Merkle path.

This crate is that measurement: standalone (deliberately outside the library workspace —
it carries a proving-stack dependency tree the library must not inherit), deterministic
(`ark_std::test_rng`; every run reproduces the numbers below), and with its `Cargo.lock`
committed, because pinned dependencies are part of reproducing a measurement.

```sh
cargo run --release
```

Every constraint system is checked satisfiable against genuine witnesses (a real
signature, a real Merkle path); `MEASURE_SKIP_SAT=1` skips that replay without changing
any count.

## What is measured

R1CS constraints over the BLS12-381 scalar field — the field proposal 0033 selects
(arkworks 0.4, constraint-count optimization goal). Counts, not proving times, because
counts are platform-independent and the *ratio* carries the decision. Three cumulative
configurations:

| | configuration | contents |
|---|---|---|
| (a) | statement core | Merkle inclusion (Poseidon, depth 32) + nullifier derivation |
| (b) | embedded signature | (a) + Schnorr over a curve embedded in the field (Jubjub) |
| (c) | in-circuit P-256 | (a) + non-native ECDSA over P-256 |

Configuration (c) is favored at every choice point, so that its count is a floor for
the design family rather than an artifact of a weak implementation:

- the message hash is a public constant — no SHA-256 in circuit;
- the two scalar multiplications share doublings (Straus);
- point arithmetic is verification-style — result and slope witnessed, curve relations
  enforced by multiplication, **no in-circuit inversion** — with incomplete affine
  formulas (a production circuit pays more for completeness);
- the final `x(R′) mod n = r` check exploits P-256's `n < p < 2n`: one multiplication
  proves `x − r ∈ {0, n}` instead of a general reduction.

Configuration (b) is left *unfavored*: the generator multiplication uses the generic
variable-base gadget where a real circuit would use fixed-base windows. Overstating (b)
can only shrink the ratio the rule reads, so it cannot manufacture the conclusion.

The one unavoidable real-deployment cost that is charged to (c): the public key is a
witness (it lives inside the credential chain, never in public inputs), so curve
membership of the witnessed key is enforced.

## Results — 2026-08-15, BLS12-381 scalar field

The measurement was first taken over the BN254 scalar field (same day; in this file's
git history) and re-run on BLS12-381 when proposal 0033 selected it. As the field-size
argument predicts, the counts are identical except the embedded signature, which
shifted by 11 constraints (6,238 → 6,227; Jubjub's scalar bit-length versus Baby
Jubjub's). Every decision taken on the original numbers stands unchanged.

```
== unit costs ==
  poseidon 2-to-1 hash                                  241
  one non-native mul (P-256 base over BLS12-381)       1266

== components ==
  merkle inclusion, depth 32                           7777
  nullifier derivation                                  484
  embedded-curve schnorr verify                        6227
  non-native P-256 ECDSA verify                     2541739
      ecdsa/scalars u1, u2 (mod n)                     2872
      ecdsa/scalar bit decomposition                   1866
      ecdsa/cross-field bind of r                      2440
      ecdsa/key witness + on-curve                     3284
      ecdsa/straus double-and-add                   2527020
      ecdsa/offset removal + x-check                   4257

== configurations ==
  (a) merkle-32 + nullifier                            8261
  (b) (a) + embedded-curve signature                  14488
  (c) (a) + non-native P-256 ECDSA                  2550000

== merkle depth sensitivity ==
  depth 16: 3889   depth 20: 4861   depth 24: 5833
  depth 28: 6805   depth 32: 7777   depth 40: 9721
```

## Reading the numbers

**Proposal 0001 — the ratio is two orders of magnitude, conclusive.** The signature
increment is 6,227 constraints embedded versus 2,541,739 non-native: **408×**
(configuration ratio 176×). The rule asked for one order of magnitude in a
configuration favoring P-256; the result is two. Independent R1CS implementations of
non-native ECDSA report the same order (≈1.5M constraints), so this is the design
family's cost, not this harness's. The decision follows: **the two-level root key of
proposal 0001 is applied** — hardware P-256 keys authorize an embedded-curve signing
key outside the circuit, and the circuit verifies the embedded signature. No mobile
proving harness is needed to reach this conclusion.

A lookup-argument proving system (Plonkish) narrows the absolute gap but not the
verdict: published lookup-based ECDSA circuits remain tens of multiples above an
embedded-curve check, and §6.5's one-standardized-circuit rule prices the whole
network at whatever this check costs.

**Proposal 0030 — depth is cheap; fix the constant generously.** The Merkle path costs
a flat **243 constraints per level** (one Poseidon 2-to-1 plus the direction selects).
Depth 32 — four billion leaves per class — costs 7,777 constraints per inclusion path;
even with the real statement's three paths (membership, revocation absence, spend
absence), the depth-dependent cost stays two orders of magnitude below the embedded
signature's neighborhood and three below in-circuit P-256. Nothing in these numbers
argues for a depth below 32; halving to 16 saves under 4,000 constraints per path and
forfeits the capacity argument §5.2 calls terminal.

## What this does not measure

Proving time, memory, and proof size are proving-system- and platform-dependent and
are deliberately out of scope — they are validated on real clients once the proving
system is chosen. The counts here bound the *relative* costs that the two deferred
decisions turn on, nothing more.
