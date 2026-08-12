# Nymora Protocol Specification

The normative definition of the Nymora protocol — what a conformant **Skiora** (server)
and **Persora** (client) implementation must do.

| Document | Contents |
|---|---|
| [nymora-protocol.md](nymora-protocol.md) | §2–§14 — vocabulary, membership and vouching, content provenance, verification, live authentication, key hierarchy, integrity/auditability, revocation, dissolution, deployment |
| [threat-model.md](threat-model.md) | §1 — purpose and adversary model · §15 — known limitations and what the design does *not* solve |
| [proposals/](proposals) | The decision record — the argued reasoning behind every normative change |

## Proposals — how to read them

The specification above is always the current truth; `proposals/` is *why* it is that
way. Every change to a normative section is drafted as a proposal first — the problem,
the decision, the alternatives rejected and why, the consequences — and the proposal
survives, unedited, after the change lands. Read the spec to learn the protocol; read a
proposal when a section makes you ask *"why would they do it this way?"*

A proposal's **status** line says how to treat it:

- **Applied** — its content is already in the specification sections above. The proposal
  is the historical argument, not pending work.
- **Proposed** — an argued change that has not been applied. The spec text it affects
  remains authoritative and, where practical, points to the proposal.
- **Closed** — superseded. Kept, because deleting a decision record hides that the
  decision was ever different.

Proposals are never edited after the fact except for their status line: corrections land
in the specification, the code, or a new proposal — an amended record is not a record.

**Protocol version:** `0.0.0` (pre-release; the specification is a design draft and may
change incompatibly).

## How this relates to the code

This specification and the implementation are versioned **together, in the same repository
and the same commit**. A change to a mechanism should land as one change to:

1. the relevant section here,
2. the crate(s) implementing it, and
3. the conformance vectors in [`../tests/`](../tests) — the *executable* form of this
   specification.

A specification that lives apart from its implementation drifts, and for a security
protocol a drifted specification is worse than none. Protocol-level changes are recorded
in [`../CHANGELOG.md`](../CHANGELOG.md) alongside crate changes.

## Section numbers are stable identifiers

Sections are cited by number from source code and documentation (e.g. `§6.5` for the
standardized circuit, `§9.2` for hardware-backed custody). Numbering is preserved across
the split between the two documents above.

**Never renumber a section.** Append new ones, and mark superseded material as such in
place.

## Derived material

The public website presents Nymora for a general audience. It must **link** to this
specification as the canonical source rather than restate it — duplicated protocol prose
diverges, and readers cannot then tell which text is authoritative.
