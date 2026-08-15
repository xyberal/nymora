# Proposal 0033 — The proving system is Plonkish KZG over BLS12-381

**Status:** **Proposed** — nothing below is normative until this proposal is applied
**Affects:** §5.2, §6.5, §9.1, §15
**Builds on:** [proposal 0031](0031-the-committed-root-is-proving-native.md) (the
committed root is proving-native, so the certificate scheme is fixed with the proving
field) and [proposal 0032](0032-the-depth-constant-is-thirty-two.md) (the statement's
size is now known, so the candidates can be priced against the real workload)

---

## Problem

The specification defers several bindings to "the proving system": §6.5 says
"e.g., Groth16/PLONK" where a real circuit needs the definite article; §9.1 fixes both
the epoch-certificate signature scheme and the exclusion accumulators' structure "with
the proving system (§6.5)"; and proposal 0031 left exactly one open question in this
area — the concrete proving-native signature scheme. Every one of these resolves the
moment one choice is made, and none resolves before it. The stub proof backend cannot
be replaced until it is made.

The choice is unusually entangled, which is why it was deferred until the measurements
existed: picking a proving system picks an arithmetization *and* a proving field, the
field picks the algebraic hash instance and the embedded curve, the embedded curve
picks the certificate scheme — and, because the root and epoch keys live *on* the
embedded curve, the field choice becomes a re-keying event for every credential the
moment real credentials exist. It is one decision wearing five coats, and one of them
hardens into permanence at first deployment. The decision is therefore made once, for
both the draft and what follows it, rather than provisionally.

## Requirements, from the specification itself

The candidates are not judged on generality; they are judged on what the
specification already demands:

1. **A small, fixed-size proof blob in every published bundle** (§6.5, §6.6). The
   bundle travels with content; its proof field is not amortizable and not batchable.
2. **Prover on the member's own device** (§9.1's cost accounting, §15's posture that
   members hold modest hardware). The routine statement is now sized: three
   depth-32 paths at 243 constraints per level ≈ 23,300, the embedded-curve
   certificate at 6,227, plus commitment, nullifier, and action-clause derivations —
   call it 35,000–50,000 constraints (the `measure/` harness, re-run on the
   BLS12-381 scalar field this proposal selects; reproducible). These are properties
   of the field's *size* (~255-bit scalars), not of a particular curve — the re-run
   confirmed it, matching the original BN254 numbers everywhere but an 11-constraint
   shift in the signature. A statement this small proves on a phone under any
   mainstream system; the requirement rules out nothing but waste.
3. **Verifier on the member's own device, one bundle at a time** (§7). Verification
   cost is paid at every read, unamortized.
4. **Several statements under one system, revised while a draft.** The routine chain
   and the migration statement exist today; §6.5's scope rule legitimizes a heavier
   governance circuit later. And every statement will be revised before any
   non-draft version. The setup model is priced per circuit *per revision*, not once.
5. **An embedded curve in the proving field** (proposal 0031): the certificate scheme
   must be proving-native, so the scalar field must host an efficient curve for it.
6. **A maintained Rust implementation.** The reference implementation is Rust with no
   FFI in the trust path.
7. **A security margin the protocol can hold for its lifetime.** The field is fixed
   for both phases (the re-keying event above), forgery in this protocol is invisible
   by design (see below), and a membership protocol expects to live for decades.
   Margin is priced against that horizon, not against the draft.

## Decision

**Plonkish arithmetization with KZG polynomial commitments over the BLS12-381
pairing curve, under a universal updatable structured reference string inherited from
an existing large ceremony** (the Zcash and Filecoin powers-of-tau lineages; one
honest contributor among their participants suffices, and the string covers every
circuit this protocol will ever standardize). Bound with it, because the field binds
them:

- **The in-circuit hash is Poseidon over the BLS12-381 scalar field**, in the shape
  the measurements were taken with — width 3, rate 2, α = 5 — with round counts
  re-derived for the field (expected unchanged at this size) and the parameter
  provenance pinned in the specification before vectors regenerate (open question 1).
  The accumulators of §5.2 and every commitment, nullifier, and certificate payload
  hash the circuit computes use this instance.
- **The certificate scheme is EdDSA over Jubjub with a Poseidon transcript** — the
  embedded-curve construction whose in-circuit verification measured 6,227
  constraints on this field. This closes proposal 0031's remaining open question:
  `sk_root` and `sk_epoch` are Jubjub keys, and "public counterpart" in §9.1's
  correspondence clause means this scheme's key derivation.

Two arguments decide, one per axis.

**The setup model (requirement 4) rules out per-circuit ceremonies.** A Groth16
setup is a two-phase ceremony whose circuit-specific phase must be re-run for every
circuit and every revision — a single changed constraint invalidates it. Three
circuits times a draft's revision rate is on the order of ten ceremonies, each
needing independent contributors recruited, verified, and published, each minting a
fresh "at least one participant was honest" assumption. And this protocol is the
worst possible place to accumulate such assumptions, because **a soundness failure
here is silent forever**: a currency has a turnstile — forgery shows up, at least in
principle, as inflation an auditor can hunt — but a forged anonymous member is
indistinguishable from a real one *by the protocol's own design*. There is no
aggregate to audit. A system whose failures are unobservable should minimize the
trust events it asks the world to believe in; inheriting one string that other
systems have escrowed value on for years adds none. A universal setup also keeps a
circuit revision what this repository already requires it to be: one synchronized,
reviewable change — the verification key is deterministic public preprocessing,
recomputable by anyone from the circuit source, with no external ceremony transcript
attached.

**The lifetime margin (requirement 7) picks the curve.** BLS12-381 was designed
after — and specifically in response to — the exTNFS family of attacks that eroded
the previous generation's estimates, and current analyses place it near 120 bits.
The competing field, BN254, sits near 100 post-exTNFS: not attackable in any
operational sense, but a margin whose estimate has already moved once, held for
decades, in a protocol that cannot observe its own forgeries. Because the curve
hardens at first deployment, choosing the larger margin now costs prover time
(~1.5–2×, immaterial at this statement size) and some ecosystem depth; choosing the
smaller one would cost either a planned mid-life migration — a full re-keying of
every credential, executed under shipping pressure at exactly the moment temporary
decisions ossify — or the margin itself. The single-field path is taken deliberately:
one instantiation, one audit surface, no migration event, no re-keying deadline.

**What a curve failure would and would not cost** — recorded because it shapes the
margin's pricing. If the curve's discrete logarithm ever became computable, the
exposure is *soundness, forward-only*: forged membership, vouches, approvals, and
migrations from that day on, answerable by a protocol-version event. It is **not**
retroactive exposure of members: the zero-knowledge of a properly blinded Plonkish
proof is statistical, so published bundles never become deanonymizable — not by a
curve break, not by a quantum adversary — and the identifying machinery (Poseidon
nullifiers and pseudonyms, HMAC tags, Jubjub keys) does not rest on the pairing
assumption at all. The caveat that keeps this honest: "statistical" is a property of
*correctly counted blinding*, an implementation obligation named in §15 when this
proposal is applied. The asymmetry — integrity fails forward and loudly at the
version level, anonymity does not fail — is what makes a margin acceptable to hold
at all; ~120 bits is what makes holding it comfortable.

The margin acceptance still carries a checkpoint, lighter than a migration gate:
**before any non-draft version, the curve is re-affirmed against then-current
discrete-log estimates, and any transparent system offering sub-kilobyte proofs is
evaluated** — hash-based proof sizes have been trending down, and such a system
would remove both the inherited-setup assumption and the discrete-log assumption
(including its quantum tail) in one move. If published estimates for BLS12-381 ever
fall materially, the checkpoint fires early rather than waiting for the boundary.

## Alternatives rejected

- **Groth16.** The strongest candidate on requirements 1 and 3 — smallest proofs
  (~192–256 bytes), cheapest verification, and the closest-cousin precedent:
  Semaphore is Merkle membership plus nullifiers under Groth16. But Semaphore's
  conditions are the mirror image of this protocol's: one circuit frozen for years
  (a ceremony per revision amortizes to one ceremony ever), an Ethereum-contract
  verifier where every proof byte and pairing is metered in money (nothing meters
  a phone), and an ecosystem that industrialized ceremony-running because it needed
  one per circuit version. Rejected on the setup argument above; the sub-kilobyte
  difference in bundle size buys freedom from all of it.
- **Plonkish KZG over BN254.** The near-winner, and an earlier draft of this
  proposal chose it: it was the field the `measure/` numbers were originally taken
  in, and its Rust lineage (the actively developed Axiom fork of Halo2) has the
  deepest tooling and the most production mileage — a real advantage during
  hand-written gadget construction, which is where circuit soundness is actually
  lost. Rejected because every argument for it is a draft-phase argument and
  expires, while every argument against it is a production argument and begins
  exactly when the field becomes permanent: ~100-bit margin held for decades
  (requirement 7), or else a planned curve migration with a re-keying deadline,
  executed under shipping pressure, with two field instantiations to audit instead
  of one. Measurement continuity, the other argument for it, re-purchased for a
  day's work: the harness re-run on BLS12-381 reproduced the BN254 counts to within
  11 constraints (requirement 2). The tooling gap, checked as of 2026-08, is real
  but no longer decisive — see the posture note.
- **Halo2 with IPA on the Pasta curves** (the transparent Zcash Orchard system). No
  setup at all — but the ceremony it avoids, inheritance already avoids, so the
  transparency premium is paid twice over: multi-kilobyte proofs in every published
  bundle, and single-proof verification dominated by a multi-scalar multiplication —
  batchable in principle, while §7's verifier reads one bundle at a time. Its
  soundness rests on discrete logarithms all the same.
- **STARK-family systems.** Transparent, post-quantum-leaning, fast provers — and
  proofs of 50–200 KB, which requirement 1 rules out flatly. Their small fields also
  host no reasonable embedded curve for requirement 5. The family remains the named
  candidate at the checkpoint if its proof sizes reach sub-kilobyte.
- **Folding/recursion schemes** (Nova and kin). Built to amortize long incremental
  computations; this protocol proves one small statement at a time, and folding
  stacks typically need a wrapping SNARK anyway — the decision returns unmade.

## Implementation posture (informative, dated 2026-08)

The normative decision above is system, field, hash, and scheme — not a library. For
the record at drafting time: the BLS12-381 Rust story is anchored by the Dusk
lineage — `dusk-plonk`, a pure-Rust PLONK with KZG over BLS12-381, actively
maintained (v0.20.3, February 2026) and security-audited, alongside sibling crates
for Jubjub, Poseidon, and an EdDSA-over-Jubjub-with-Poseidon scheme that is
precisely this proposal's certificate construction — with `midnight-zk`, a
Halo2-family Plonkish stack on the same curve, as an independent alternative. (For
contrast: the PSE fork of Halo2 entered maintenance mode in January 2025; the
actively developed Axiom lineage is BN254-tied; the arkworks Groth16 stack
self-describes as an academic prototype.)

Whatever the library, **the certificate-verification gadget is the highest-risk
hand-written component of the whole circuit**. The precedent to respect: in May 2026
a critical soundness flaw was disclosed in the scalar-multiplication chip of Zcash's
`halo2_gadgets` — in production for four years, patched by an emergency hard fork
that June. A curve gadget is where circuit soundness goes to die; every clause of
ours ships with negative vectors that a maliciously wrong witness must fail. The
blinding-sufficiency check named above sits on the same review list: the
retroactive-privacy claim is information-theoretic only if the implementation blinds
for every evaluation the transcript exposes.

## Open questions

1. **The Poseidon parameter provenance.** Round counts and constants for the
   BLS12-381 instance are generated deterministically; before the vectors
   regenerate, the generation procedure and its domain separation must be pinned in
   the specification, not just in code.
2. **The SRS excerpt.** The circuit's size fixes how much of the inherited string is
   needed; the excerpt, its provenance chain from the source ceremony, and its
   checksum belong in the repository alongside the verification key.

## Consequences

- §6.5's "e.g., Groth16/PLONK" becomes this system, named. §9.1's two "fixed with the
  proving system" clauses resolve: the certificate scheme is EdDSA over Jubjub with a
  Poseidon transcript, and the exclusion accumulators are keyed Poseidon structures
  over the same field. §5.2's accumulator hash is the named Poseidon instance.
- §15 gains the margin entry — ~120 bits, the forward-only failure asymmetry, the
  blinding obligation — and the pre-non-draft checkpoint with its early trigger.
- The `measure/` harness was re-run on the BLS12-381 scalar field (2026-08-15,
  satisfiability checked) as part of drafting this proposal: the per-level Merkle
  cost, the nullifier, and the non-native ECDSA count are identical to the BN254
  run; the embedded signature moved from 6,238 to 6,227; the decision ratio moved
  from 407× to 408×. The decisions those numbers justified (0031, 0032) stand
  confirmed on the field the protocol now names. When this proposal is applied,
  §9.1's cited measurements update to these values.
- The provisional hash and signature retire when the real circuit lands, and the
  conformance vectors regenerate with them — one synchronized change across
  specification, code, and vectors, as every mechanism change is.
- The real circuit is built against this system at `PROTOCOL_DEPTH = 32`, replacing
  the stub backend behind the existing `ProofSystem` boundary.
