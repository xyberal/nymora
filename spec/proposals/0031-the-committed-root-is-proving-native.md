# Proposal 0031 — The committed root is proving-native; hardware anchors its custody

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §6.5, §9.1, §9.2, §9.3, §14, §15
**Applies:** [proposal 0001](0001-two-level-root-key.md), whose decision rule its
measurement has now met. 0001 remains unedited, as every applied record does; this
proposal records how its decision maps onto a specification that moved while it waited.

---

## The measurement

Proposal 0001 deferred one question to numbers: can the hardware authenticator's own
signature (ECDSA P-256) be verified inside the standardized circuit, or must the
accumulator-committed key be proving-system-native, with hardware demoted to an anchor
above it? Its rule: a non-native cost an order of magnitude or more above the
embedded-curve alternative, *measured in the configuration most favorable to non-native
verification*, is conclusive.

The measurement exists (`measure/`, reproducible): an embedded-curve verification adds
**6,238** constraints to the statement core; non-native P-256 ECDSA adds **2,541,739**,
with every choice favoring it — message hash public, shared doublings, no in-circuit
inversion, the P-256-specific reduction shortcut. The ratio is **407×**, two orders of
magnitude where the rule asked for one, and independent implementations of the same
construction report the same order. The certificate is checked on every routine proof,
so this cost would be paid on every post, vouch, and live-authentication handshake, by
the member's own device.

The rule fires: **the two-level root key is applied.** The leaf commits a
proving-system-native protocol root; the hardware key becomes the credential's anchor,
never verified inside the standardized circuit.

## What maps directly

0001 predates the opening-value correction (0003), the agora-bound leaf (0013), the
counting key `sk_cred` (0015-era), the canonical certificate encodings, and the
attribute-free leaf (0028). Its replacement text no longer drops in; its decision does.
Applied to today's specification:

- **`sk_root` keeps its name and its every current use.** The protocol root 0001 called
  `sk_proot` is exactly the `sk_root` the specification already has: committed via
  `pk_root` in the four-value leaf, signing the canonical epoch certificate the circuit
  verifies. What changes is its stated nature — proving-system-native, software-held,
  wrapped at rest under the hardware anchor where the platform can — not its role. No
  derivation, domain tag, leaf shape, statement, vector, or line of implementation
  changes: the implementation was built against an abstract root authority
  (`nymora-ports`' `KeyStore`) whose documentation states that the two-level
  arrangement lives entirely behind it.
- **`sk_hw` enters §9.1 and §9.2** as the hardware anchor: generated inside the
  authenticator, non-exportable, binding the credential to genuine hardware at creation
  (the binding evidence §9.2's attestation tradeoff already governs), wrapping
  `sk_root` at rest and gating its use behind user presence where the platform
  supports it.
- **§6.5 states the scope rule 0001 argued**: the uniform-shape requirement targets
  externally published bundles; proofs that travel only member-to-operator may use a
  distinct shape. The implementation's migration statement already cites this
  reasoning; it becomes normative text.
- **§15 gains the honesty entry**: the committed key is software-held, and hardware
  cannot re-gate it once extracted — stated with what extraction actually permits
  (below), not the softer version.

## What is adapted, and why: migration certificates stay with `sk_root`

0001's drafted §9.3 moved migration signing to the hardware key, for a real property:
an adversary who extracts the protocol root alone cannot mint a successor credential.
That text is **not** adopted, because the protocol it was drafted against no longer
exists. Migration is anonymous now: the certificate is verified *inside* the migration
proof against the key the consumed leaf commits, precisely so that neither `pk_root`
nor the leaf is ever named in the act. A hardware-signed certificate cannot join that
chain soundly:

- The leaf does not commit `pk_hw`, so an in-circuit "the hardware signed this" clause
  quantifies over a free witness — an adversary holding the extracted root binds a
  hardware key *they* control and satisfies the clause. The binding proves possession
  of some hardware, not of *the* hardware.
- Anchoring it properly means either committing `pk_hw` in the leaf — a change to the
  commitment's arity, which proposal 0028 already names a protocol-version event — or
  having the operator pin binding evidence per leaf and check it at migration, which
  names the migrating credential and forfeits the anonymity the in-circuit design
  exists to provide.
- Verifying the hardware signature in-circuit is the 407× measurement again — rare
  here, so tolerable in isolation, but it does not remove either anchoring problem.

Hardware's contribution to migration is therefore **custody, not verification**: where
wrapping is in force, producing a migration certificate requires unwrapping `sk_root`
behind a user-presence check on the old device. What an extracted `sk_root` permits
without that check is stated in §15 with its genuine bounds: at most one hijacked
successor per leaf (the spend nullifier admits one), visible to the victim (their own
next proof fails against the spent leaf), and recoverable by quorum revocation of the
successor (§11).

A future protocol version that changes the leaf for other reasons (0028's attributes)
should revisit committing hardware evidence at the same time; the record of why it is
not done now is this section.

## Alternatives rejected

- **Accept non-native verification** (0001's own second alternative). The measurement
  is the answer: 407×, on every routine proof, against the modest hardware §15's threat
  model pushes members toward.
- **Commit `pk_hw` in the leaf now.** A protocol-version event (0028) undertaken solely
  to upgrade migration's custody story from "wrapped + presence-gated + one successor +
  visible + revocable" to "hardware-gated" — the wrong trade while the primitives are
  provisional, and it would still leave the verification cost question open.
- **Rename `sk_root` to `sk_proot`.** Pure churn across every section, derivation
  comment, vector, and identifier, buying one word of precision the three-tier table
  in §9.1 provides anyway.

## Open questions inherited from 0001, unchanged

1. **Hardware-gated governance** (dissolution requiring `sk_hw`): still open, now with
   §6.5's scope rule making a heavier governance circuit legitimate when someone takes
   it up.
2. **Binding expiry** ("hardware heartbeat"): still deferred, not rejected.
3. **The concrete proving-native signature scheme**: fixed with the proving system
   (§6.5); the provisional scheme stands in until then.

## Consequences

- §9.1 presents three tiers with the measured *why*; §9.2 describes the two-key
  backend behind the key-store surface and drops its deferral hedge; §9.3 states why
  migration certificates stay with the protocol root; §14 and §15 say what custody now
  actually claims.
- **No mechanism changes.** Wire formats, canonical encodings, statements, vectors,
  and state machines are untouched; the code changes are documentation, because the
  port boundary was designed to absorb exactly this decision.
- The key-store backends to come implement the two-key arrangement behind the existing
  trait: hardware anchor plus wrapped proving-native root, capabilities reported, the
  binding carried as opaque evidence.
