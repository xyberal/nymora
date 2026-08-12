# Proposal 0023 — The transparency log is a hash chain, not a Merkle log

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §10.1
**Supersedes:** nothing

> **Decided in session and applied directly.** Phase 5 built §10.1's log and diverged
> from its words: the section asks for "signed tree heads making the root sequence itself
> an append-only Merkle log," in the style of certificate transparency, and the
> implementation is a linear hash chain. The section also never says what key signs the
> heads. This proposal records both decisions rather than leaving them in module
> documentation.

---

## Problem

§10.1 reaches for certificate transparency by name, and CT's structure answers CT's
constraints: logs holding billions of entries, verified by lightweight third parties who
cannot hold them, so consistency between two heads must be checkable in `O(log n)` with a
Merkle consistency proof. Neither constraint is Nymora's:

- **The log grows per epoch, not per action.** Its entries are root publications,
  policy-change facts, and the freeze — an agora advancing weekly writes on the order of
  fifty entries a year. Replaying the whole log is a few hundred hash invocations,
  cheaper than verifying a single RFC 6962 consistency proof. The asymptotics that
  justify the tree never become material.
- **The auditors already hold the data.** §10.1's verifiers are members (who receive
  heads on the boundary cadence and can trivially hold the entry list) and independent
  replicas. And the attack the log exists to catch — a split view — is *equivocation*:
  two validly signed heads at the same sequence with different content. That check needs
  the heads alone; the Merkle structure buys nothing for the log's primary claim.
- **Consistency proofs are the wrong fetch pattern here.** A consistency-proof query
  names the two heads it connects, telling the operator exactly which state the asking
  member last saw — a fingerprinting signal on an identified connection, in a protocol
  that fights linkability everywhere else. The interactive service that is the Merkle
  log's headline feature is one members should not use.
- **The machinery is not free.** Tree storage, node recomputation, and consistency-proof
  verification — with RFC 6962's famously fiddly index arithmetic — would live in the
  open, allocation-disciplined crate people are asked to audit. The chain is a few dozen
  lines with a known-answer pin.

Separately, §10.1 required signed heads without saying what signs them. The member key
hierarchy is the wrong tool: those keys are private witnesses (§9.1), and a head must be
attributable to the log's operator, not to any member.

## Decision

The log is a **linear hash chain**: `head_n = Hash(head_{n-1}, entry_n)` under its own
domain tag, so every head commits to the entire history beneath it by construction.
Append-only integrity is verified by **full replay**, and auditors fetch the entry suffix
whole and uniformly — the same shape as §11's whole-set service, revealing nothing about
what the fetcher already knew. Equivocation detection is unchanged: two validly signed
heads at one sequence number are portable proof of a fork.

Heads are signed by an **operator-held log key**, distinct from all member material. The
key exists to make the log non-repudiable by its operator; it says nothing about members,
and — with pooled deployment in mind — the signing key, not any name in the entries, is
what ties heads to one log.

The structure is a point-in-time fit, not a ceiling: pooled logs across many agoras, or
third-party monitors at a scale where replay stops being cheap, are the signal to revisit
it. The signed-head format and the auditor's claims survive that upgrade unchanged; only
the commitment structure under the head would.

## Consequences

**Gained:** the smallest auditable artifact that delivers §10.1's three checks; an
auditor fetch pattern that leaks nothing about the auditor's prior state; heads
attributable to exactly the party the log holds accountable; §10.1's words match the
implementation.

**Paid:** no sublinear consistency proofs — a verifier must hold or fetch the entries
between two heads to relate them. At per-epoch growth this is cheaper than the proofs it
replaces; it becomes a real cost only in the pooled/monitor-at-scale deployments named
above, which is when this decision is revisited.

**Unchanged:** everything on and off the log (§10.1's admissible list and the
never-on-the-log rule), opt-in per agora, the gossip requirement, and the three auditor
checks — non-equivocation, append-only integrity, protocol conformance.
