# Proposal 0006 — Defer corroboration to a later protocol version

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §2, §6.3, §6.6, §14
**Supersedes:** nothing
**Prerequisite for:** 0005, whose recommendation depends on this deferral

> **Applied as drafted.** Descriptive mentions of corroboration in §9.1 and §9.2 (lists of
> the operations `sk_epoch` covers) were left in place: they point at a section that now
> declares its own deferred status, and rewriting them would churn text that becomes correct
> again if §6.3 returns.

---

## Problem

This is a scope decision rather than a defect. It is written up as a proposal because
corroboration is not an independent feature: removing it changes what the nullifier
construction must provide, and re-adding it later changes that back. That coupling needs to
be recorded somewhere a future implementer will find it.

Corroboration (§6.3) lets members independently attest to content someone else authored. It
is the only place in the protocol where an object accepts actions **indefinitely** and is
also **public**: a message can be corroborated whenever a member encounters it, and the
bundle carrying it circulates freely.

Both halves matter. Indefinite acceptance means the nullifier preventing duplicate
corroboration must stay valid indefinitely, which requires a key that outlives epochs.
Public circulation means an adversary holding that key can recompute the nullifier for every
bundle in the agora and mark which the member corroborated. Together they force the durable
nullifier key analysed in 0005, and with it the loss of retroactive unlinkability for the
entire content graph.

No other context has both properties. Vouch sessions and policy proposals accept actions for
a bounded time and are internal; migration is indefinite but concerns a single accumulator
leaf rather than a stream of public objects.

## Decision

Corroboration is deferred to a later protocol version. Authorship (§6.1) is unaffected.

§6.3 remains in the specification, marked deferred rather than deleted, so the design and
its rationale survive for whoever picks it up.

## What is lost

Independent endorsement of content. A bundle proves that a member of the agora stands behind
it; without corroboration it cannot show that *several* do. For a group whose content is
consumed outside the agora, that is a real reduction in the strength of the claim a bundle
makes.

## What is not lost

**§6.2 group-scoped reputation.** It concerns authorship, and its internal continuity
mechanism is a separate member-only construction that never leaves the agora. Neither
depends on §6.3.

**The self-corroboration property.** §6.1 and §6.3 currently share a nullifier domain so
that a member who authored a message produces the same nullifier when corroborating it. With
corroboration deferred, there is nothing to prevent; the shared domain becomes vestigial
rather than wrong.

---

## Replacement text

### §2 — vocabulary

> | **Attestation** | A zero-knowledge proof that a valid credential authored a specific
> piece of content. |

### §6.3 — section heading and opening

> ### 6.3 Corroboration — deferred
>
> **Deferred to a later protocol version (proposal 0006).** The mechanism below is
> specified but not implemented. Read the note at the end of this section before
> reintroducing it: corroboration is coupled to the nullifier construction in §9.1 and
> cannot be re-added as an isolated feature.

### §6.3 — new closing note

> **Reintroducing this section reopens the nullifier decision.** Corroboration is the only
> context in the protocol where a public object accepts actions indefinitely. That
> combination requires a nullifier key outliving epochs, and such a key lets anyone holding
> it recompute the nullifier for every published bundle and determine which the member
> corroborated — retroactively, for the life of the credential. Proposal 0005 was settled on
> the assumption that this section is deferred. Reversing that assumption reverses 0005's
> conclusion; the two must be reconsidered together.

### §6.6 — bundle format

> ```json
> {
>   "content": "<M>",
>   "tag": "<32-byte HMAC output>",
>   "attestation": {
>     "proof": "<fixed-size SNARK blob>",
>     "message_hash": "<Hash(M)>",
>     "nullifier": "<32-byte value>"
>   }
> }
> ```
>
> The `corroborations` array is absent in this version (§6.3). It is omitted rather than
> sent empty: an always-empty array would be a field every bundle carries and no bundle
> uses, and canonical serialization (§6.6) admits no ambiguity between absent and empty.

### §14 — capabilities summary

> - **Content**: Authored content carries unlinkable, message-bound attestations proving "a
> real group member stands behind this" externally, while richer authorship/reliability
> tracking and revocation status remain visible only to members internally.

---

## Consequences

**Gained:** the nullifier construction no longer needs a durable key for content, so
retroactive attribution of the content graph does not arise. See 0005.

**Paid:** bundles carry a single attestation, and the strength of what they assert is
correspondingly narrower.

**Deferred, not decided:** whether corroboration is worth its cost when it returns. That
judgement needs usage the design does not yet have — specifically, whether content is
corroborated shortly after it appears or long afterwards. If shortly, a later version could
reintroduce corroboration with a bounded acceptance window and keep epoch-scoped nullifiers,
avoiding this trade entirely.

## Note for implementers

Task 1.6 defines the wire format. The bundle should be built without a `corroborations`
field rather than with an empty one, and the format version should make its later addition a
compatible extension rather than a redefinition.
