# Proposal 0025 — The witness service is keyed, not proof-gated

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §5.2, §11, §15
**Supersedes:** nothing

> **Decided in session and applied directly.** The phase-5 implementation served the
> current roots and inclusion witnesses ungated, justified at the time from §5.2's
> ambivalent "public (or member-visible, per §7)". The pre-publication read-through
> concluded the implementation was wrong, not the spec — and that the obvious repair,
> gating both behind a membership proof, is impossible for one of them.

---

## Problem

Two ungated endpoints each negated a stated guarantee:

- **Ungated current roots are an affiliation oracle.** A root reveals nothing on its own
  (§5.2), but a *served* root completes something: the proof-verification algorithm is
  public, so an outsider holding an attestation bundle — bundles travel externally by
  design (§6.6) — and suspecting agora X could fetch X's current roots and run the
  verifier. Proof valid → affiliation confirmed, which is precisely the capability §6.4
  spends the entire tag mechanism preventing, and the direct negation of §7's claim that
  a non-member has no path to a trustworthy root.
- **An ungated witness service is an occupancy probe.** Witness-by-position returns a
  path for an occupied position and an error for an empty one. Enumerating positions
  yields the class occupancy §5.2 withholds "at any point."

The obvious repair — gate both behind §7's access grant — works for roots and is
**impossible for witnesses**: a member's first proof of an epoch requires that epoch's
inclusion witness as a private input, and a boundary-admitted member has never proven
anything. Every proof-gated witness service has an unreachable base case. The circularity
is not incidental; it is the same one the bulletin already breaks for roots and exclusion
sets, and it points at the same resolution.

## Decision

**Current roots have no lookup endpoint.** They reach members exclusively through the
boundary broadcast (§11) — the members-only channel that already carries the exclusion
sets and `K_tag`, delivered fresh at every boundary and re-servable by the host to a
member who missed one. Historical roots remain behind §7's access grant, whose own base
case is sound: by the time a member needs history, they hold the current epoch's material
and can prove. The founder is equipped the same way — the genesis epoch's bulletin,
served at creation — so no epoch, including the first, has a differently-shaped bootstrap.

**The witness service is keyed by `K_witness_e`**, a symmetric per-epoch key with exactly
the tag key's lifecycle: derived by the operator under its own domain tag
(`nymora/v0/witness/key`), distributed in the boundary broadcast, rotated at every
boundary, withheld from a revoked member at the same cut. A witness request presents the
key; a wrong or stale key refuses identically over occupied and empty positions. The key
is derived from the same operator secret as `K_tag_e` but under a distinct domain, so
leaking one epoch key never leaks the other — the tag key resolves content, the witness
key opens a service, and their compromise stories stay separate.

What the key authenticates is deliberately minimal: that the requester was equipped for
this epoch — the property the service needs, and the most a shared key can carry. It says
nothing about who asked, which is correct: naming the asker is what the service must
never do.

## Consequences

**Gained:** §7's no-path-to-a-trustworthy-root claim is true again; the affiliation
oracle and the occupancy probe are closed; every epoch, genesis included, equips members
through one channel with one shape; a revoked member's witness service ends at exactly
the boundary that revoked them, with no separate mechanism.

**Paid:** one more shared per-epoch secret, with the shared-secret blast radius §15
already prices for `K_tag_e` — a leaked witness key permits occupancy probing for its
epoch, and nothing more (it forges no proof, resolves no tag, reads no content). And a
limit inherited rather than introduced: which member fetches which position remains
visible to the operator, as any per-position service must accept. Serving the class
*whole*, §11-style, would remove even that — and is rejected here because the leaf list
grows with total membership (the whole-set affordability argument §11 makes for exclusion
sets inverts), and a position-ordered leaf list would hand every member the admission
ordering §15's founding-asymmetry note keeps unqueryable. Keeping the fetch unlinkable on
the wire stays a transport obligation (§16.2).

**Unchanged:** what a witness *is* and when it is valid (epoch-stable, proposal 0020);
the bulletin's members-only delivery cut (§11); §7's challenge-bound access for
everything historical; the public verifiability of the transparency log, whose roots an
agora may still choose to publish (§10.1) — publishing is the agora's explicit opt-in to
existence disclosure, not a default any outsider can query.
