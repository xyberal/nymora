# Proposal 0024 — The bulletin is a signed operator statement

**Status:** **Applied** — the sections below are now normative in the specification. The
open questions were decided at application: the statement key is **separate** from the
log-head key, and the bulletin **embeds** the latest signed log head where a log exists.
**Affects:** §9.1, §11 (the boundary-broadcast paragraph), §6.4, §10.1 (cross-reference)
**Supersedes:** nothing; subsumes §9.1's signed epoch-advance statement

> **Not blocking, but not deferrable to "someday."** Phase 5's bulletin is a plain value
> passed in-process, where authenticity is guaranteed by the function call. The moment it
> crosses a network — which is its entire purpose — the gap below opens. This is
> independent of the proving system and should land before any deployment that serves
> real members, i.e., alongside or before phase 6.

---

## Problem

The boundary bulletin (§11) is the member's entire view of the new epoch: the roots to
prove against, the exclusion sets to cut absence witnesses from, the tag key to
trial-decrypt with. Phase 5 generalized §9.1's broadcast to carry all of it — and did not
inherit the one property §9.1 had already demanded for the piece it covered: §9.1
specifies a **signed** epoch-advance statement for log-less agoras. The implementation is
behind the specification on the field the specification covered, and the specification is
behind the implementation on every field the bulletin added.

An unsigned bulletin, tampered with or forged in transit, yields:

- **False verifiers — the serious one.** A member *acting* on forged state merely fails:
  their witnesses will not verify against Skiora's true roots. A member *verifying* is
  different. Offline verification (§8.3) checks proofs against locally cached roots, and
  a proof is only as sound as the root it is verified against. Feed a verifier a bulletin
  carrying an attacker-built class root and the attacker mints valid membership proofs
  for a tree of their own construction. The zero-knowledge machinery is intact; the
  integrity anchor under it was swapped.
- **Replay defeats revocation immediacy.** §11 forces a boundary so revocation takes
  effect *now*. Replaying the previous epoch's bulletin to a targeted member keeps that
  member verifying against pre-revocation roots and sets — the revoked member stays
  acceptable to that verifier for as long as the replay holds. Revocation is only as
  immediate as bulletin delivery is authentic and fresh.
- **Per-member forks leave no evidence.** Serving different bulletins to different
  members is the split-view attack §10.1 exists to catch — but the log is opt-in, and an
  unsigned bulletin gives a suspicious member nothing portable to gossip: "the bytes I
  received" proves nothing about who produced them.
- **Tag-key substitution** — the mildest: a wrong `K_tag_e` makes the member's
  trial-decryption miss the group's content. Denial of service, not disclosure, since
  trial-decryption is local.

Channel security is not a substitute. The bulletin's delivery-cut semantics and §8.3's
offline story both assume the artifact can be cached, relayed peer-to-peer, and fetched
through infrastructure the member does not trust. That calls for **object security** —
the artifact carries its own authenticity — not a property of one hop.

## Decision

**Canonical bulletin bytes, signed by an operator-held statement key.**

1. **Encoding.** The bulletin gets a canonical byte encoding in `nymora-core`, alongside
   the certificate encodings and under the same discipline: a new domain tag leads, every
   variable-length field is length-framed, and the `agora_id` is inside the signed
   message so no-replay-across-agoras (§16.1) holds by construction rather than by key
   management. (The log's entries omit the `agora_id` because the log is *public* and
   unlabeled roots serve pooled deployment; the bulletin travels only on the member-gated
   channel, where naming the agora to its own members reveals nothing.)
2. **Signer.** An **operator statement key**, per agora, distinct from all member
   material — the same reasoning as the log-head key (proposal 0023): the signature makes
   the *operator* non-repudiable and says nothing about members. Log-less agoras need
   operator signing material for §9.1's advance statement anyway; this key is that
   material, generalized. Whether it is the same key as the log-head key where a log
   exists is left open below.
3. **Member acceptance.** A member accepts a bulletin only if the signature verifies
   under the operator statement key pinned at admission, and the epoch is strictly
   greater than the member's current epoch. Monotonicity is the freshness rule — cheap,
   since members track their epoch anyway, and sufficient, since sets arrive whole
   (§11): a member offline for several boundaries applies the latest bulletin alone and
   is current.
4. **Subsumption.** §9.1's signed epoch-advance statement is struck as a separate
   artifact: it is the degenerate bulletin. One signed object announces the boundary and
   equips the member for it; there is no window where a member knows the epoch advanced
   but cannot yet act in it.
5. **Equivocation is portable.** Two validly signed bulletins for the same epoch with
   different content are proof of a fork, carryable to anyone who holds the statement
   key — the exact analogue of the log's `equivocation` check, extended to agoras that
   declined the log. This is the property per-member authenticators (MACs) can never
   give, which is why they are rejected outright: a per-member authenticator is
   precisely the tool for undetectable per-member forking.

**The existence-hiding cost, argued rather than assumed.** A signature is a name: any
party who obtains a signed bulletin can verify it against the statement key forever — a
leaked bulletin is proof the agora exists, which is what §3 protects and why the most
existence-sensitive agoras declined the transparency log. The proposal signs anyway, for
three reasons. The bulletin travels only on the member-gated channel, so the leak
requires a member — and a member can prove the agora's existence regardless, by
describing it or by leaking any other artifact. The key is per-agora, so nothing links
one agora's bulletins to another's. And the alternative protects deniability of an
artifact by sacrificing the protocol's core integrity claim: unforgeable roots. An agora
that judges the trade differently can rotate its statement key aggressively (members
re-pin at each bulletin, since each is accepted under the key pinned before it) at the
cost of weaker long-horizon fork evidence — a policy knob, not a protocol change.

## Consequences

**Gained:** the root-authenticity anchor holds end-to-end — cached, relayed, and offline;
revocation immediacy survives transit; split-view detection extends to log-less agoras
with portable evidence; §9.1 and §11 describe one artifact instead of one-and-a-half.

**Paid:** an operator statement key to manage per agora; a signature and its verification
on every boundary (per epoch, not per action — noise); the attributability of leaked
bulletins, argued above; the wire artifact grows by one signature.

**Unchanged:** what the bulletin carries; whole-set semantics; delivery cut to remaining
members as the read-cutoff mechanism (§11); the transparency log's role where present —
the log still catches an operator who lies *uniformly*, which no signature can.

## Open questions

- **One operator key or two?** Where the log exists, the statement key and the log-head
  key could be the same material (fewer keys, and heads and bulletins become mutually
  attributable) or separate (role separation; a log key disclosed for auditing reveals
  nothing about the member-gated channel). Lean separate; decide when implementing.
- **Should the bulletin embed the latest signed log head?** Where a log exists, this lets
  a member cross-check the bulletin's roots against the public log with no extra fetch,
  binding the two artifacts. Costs a head per bulletin. Lean yes; decide when
  implementing.

## Applying this proposal requires

Canonical bulletin encoding + domain tag in `nymora-core` with vectors; a signature field
on `Bulletin` and signing in `advance_epoch`; a member-side acceptance function
(signature + monotonicity) in `nymora-protocol`; §9.1 and §11 edits; a §10.1
cross-reference for the equivocation parallel.
