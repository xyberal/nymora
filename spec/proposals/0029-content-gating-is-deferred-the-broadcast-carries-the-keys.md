# Proposal 0029 — Content gating is deferred; the broadcast carries the keys

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §6.4, §7, §11, §12
**Supersedes:** nothing

> **Found by the pre-publication read-through.** §6.4 said `K_tag_e` is distributed
> "via the agora's attribute-based-encryption (ABE) content-gating mechanism — the same
> mechanism used to gate tiered content generally", §11 said the boundary broadcast is
> the channel, and §12 destroyed an "ABE master key" at dissolution. No ABE mechanism is
> specified anywhere in this document, and none is implemented: the content-gating
> references were an orphaned assumption from an earlier design stage, load-bearing in
> three sections and defined in none.

---

## Problem

Tier-gated content encryption — encrypt content so that only members of sufficient
standing can decrypt it, with an attribute-based scheme deciding "sufficient" — was
assumed by early drafts as the substrate that would also deliver the tag key. The
key-hierarchy and boundary-broadcast work made that delivery story obsolete: since
proposal 0020 fixed roots per epoch and §11 generalized the boundary broadcast into the
members-only channel carrying everything an epoch fixes, `K_tag_e` (and now `K_witness_e`,
proposal 0025) ride that broadcast, and the delivery *cut* — remaining members receive
it, the revoked member does not — is the revocation mechanism.

The ABE references that remained were pure debt:

- §6.4 named a distribution mechanism that does not exist, when the mechanism that does
  exist (§11) was already doing the work one sentence away.
- §12's dissolution effects destroyed an "ABE master key" no other section defines,
  creating a phantom object in the section whose whole point is enumerating exactly what
  destruction covers.
- A reader auditing the spec finds a load-bearing mechanism with no definition — the
  same class of incoherence proposal 0028 removed from §5.1, in the content plane.

## Decision

**The boundary broadcast (§11) is the distribution channel for every per-epoch member
key. Tier-gated content encryption is deferred to a later protocol version.**

- §6.4 states the broadcast as `K_tag_e`'s channel and revocation as the delivery cut.
  Nothing about the tag construction changes — `tag = HMAC(K_tag_e, message_hash)` never
  depended on how the key travels.
- §12's effects are conditional where they always secretly were: *when* a later version
  encrypts content under agora-held keys, dissolution destroying those keys is what makes
  existing ciphertexts permanently undecryptable. In this version, dissolution's effects
  are the ones the implemented mechanisms deliver: frozen roots, refused services, a
  terminal log entry.
- What a deferral costs, stated plainly: in this version the protocol gates **standing
  and services**, not **content at rest**. Content reaching members does so over
  member-gated delivery (§7's access grant, the broadcast), and provenance and routing
  are cryptographic (§6) — but a bundle's payload is not itself encrypted to a tier by
  the protocol. Groups needing tiered confidentiality *within* the membership must wait
  for the later version or layer their own encryption above the protocol.

**Constraints on the reintroduction.** Whoever adds content gating inherits three
settled decisions it must compose with, not reopen: keys reaching members ride the
boundary broadcast and rotate at boundaries, so revocation remains the delivery cut
(§11); a member's key material must stay per-agora and non-comparable (§5.1); and if the
scheme's decryption keys are shared across members — as attribute-based constructions'
are, per attribute — each shared key joins `K_tag_e` and `K_witness_e` in §15's
shared-secret blast radius and must be argued at that standard.

## Consequences

- §6.4 and §11 agree on one channel; §7's reliance list names content delivery, not a
  gating mechanism; §12 destroys only what exists.
- Two doc comments (`TagKey`, `derive_tag_key`) now name the broadcast instead of ABE.
- No mechanism, vector, or test changed: the implementation never contained ABE, so the
  specification moved to the code, as it did in 0028.
