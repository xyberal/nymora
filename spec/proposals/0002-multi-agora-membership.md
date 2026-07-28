# Proposal 0002 — Multi-agora membership: normative isolation, ledger scoping, correlation limits

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §2, §5.1, §9.2, §10.2, §14, §15; adds §16
**Supersedes:** nothing

> **Applied as drafted, with one addition.** §14's summary carried the same "per-Persora
> receipt ledgers" wording as the §2 glossary — a third instance of the defect this proposal
> corrects. It was updated to "per-credential" alongside the others, and §14 gained a
> multi-agora bullet.

---

## Problem

§13 states that a single Persora may hold credentials for "any number of independent
agoras." That capability is central to the design — it is what lets a person participate in
several groups without any of them learning about the others. Three things stand in the way
of implementing it correctly.

### 1. The isolation guarantee is cited but never stated

Both §9.2 and §13 refer to per-agora credential unlinkability as a requirement "already
established in §5.1." It is not. §5.1 covers credential attributes and their zero-knowledge
disclosure, and says nothing about agora scoping, key separation, or cross-agora
unlinkability.

The single property that makes multi-agora membership safe is therefore asserted twice and
defined nowhere. An implementer has no normative text to conform to, and a reviewer has
nothing to check against.

### 2. Receipt ledger scope is contradictory, and one reading breaks isolation

- §2 (glossary): "a **per-Persora** hash-chained, append-only record"
- §10.3: "Skiora pins the latest committed ledger head **for each credential** … one chain
  **per credential**"

These differ precisely when a member belongs to more than one agora. The per-Persora reading
is not merely ambiguous but actively harmful: §10.2 and §10.4 have the ledger replayed by a
**second Persora**, chosen by the member or verifiably-randomly selected. A ledger spanning
every agora would disclose to that witness the member's complete activity across all
memberships — including which agoras they belong to — undoing in one mechanism the isolation
the rest of the design maintains.

### 3. Multi-agora operational risks are unaddressed

Cryptographic isolation does not extend to the device, the network, or the authenticator.
Membership in several agoras concentrates correlation risk in ways single membership does
not, and the design currently says nothing about it: simultaneous device migrations across
agoras, traffic to several Skiora deployments from one host, authenticator-level identifiers
shared across credentials, and practical ceilings on how many memberships a device can hold.

---

## Decision

State the isolation requirement normatively where it is already cited (§5.1), correct the
ledger scope, record the authenticator-level caveats in §9.2, and add a section (§16)
covering multi-agora membership as a topic in its own right.

**On numbering.** §16 is appended rather than inserted near §5, because section numbers are
stable identifiers cited from source code (see `spec/README.md`). It lives in
`nymora-protocol.md` as mechanism, notwithstanding that §15 sits in `threat-model.md` —
numbering is global across the specification set, not per file.

---

## Replacement text

### §5.1 — append

> **Credentials are per-agora and mutually unlinkable.** A member holding credentials in
> several agoras holds a wholly separate credential in each. This is a normative requirement,
> not an implementation preference, and it is what §13's statement that one Persora may serve
> any number of agoras depends on:
>
> - All key material — the hardware anchor, the protocol root, the commitment opening value,
>   and every epoch key — is generated **freshly and independently per agora**. It is not
>   derived from a shared seed or master secret, however convenient that would be for backup:
>   a common seed would make compromise of one agora's material a compromise of all, and
>   would let an adversary holding it test membership in any agora whose identifier they can
>   name.
> - **No value derived within one agora is ever reused in, or derivable from, another.** This
>   covers nullifiers, pseudonyms, commitments, tags, ledger entries, and any handle
>   presented to a Skiora.
> - **No interface accepts or returns state spanning more than one agora.** Nothing a Persora
>   presents to any Skiora reveals that other memberships exist, how many there are, or which.
>
> The standardized circuit (§6.5) is deliberately shared across agoras; sharing a *circuit*
> is what makes proofs indistinguishable, whereas sharing a *witness* would make them
> linkable. No proof instance takes a witness from more than one agora.

### §2 — glossary entry replaced

> | **Receipt ledger** | A per-credential hash-chained, append-only record of every action one credential takes within one agora, replayable by another Persora to confirm that history is complete, consistent, and non-forged. A member holding credentials in several agoras keeps a separate, unlinked ledger for each. |

### §10.2 — append

> **One ledger per credential, never one per person.** A member in several agoras maintains a
> separate chain for each, and a replay witness sees only the chain for the agora it was
> asked about. A single ledger spanning a member's agoras would hand any witness — including
> a verifiably-randomly selected one (§10.4) — the member's full cross-agora activity, and
> with it the fact that those memberships share an owner. The witness learns that some
> credential's history is consistent; it learns nothing about any other agora, and cannot
> tell whether the member belongs to any.

### §9.2 — append to "What this does not defend against"

> **Authenticator-level identifiers can link credentials that the protocol keeps separate.**
> Per-agora key scoping isolates the keys, not necessarily the device that holds them. Two
> details deserve checking against any authenticator before it is relied upon:
>
> - **Signature counters.** WebAuthn authenticators return a counter with each assertion, and
>   some maintain it globally across all credentials rather than per credential. Two Skiora
>   deployments comparing counter values could correlate credentials held on the same
>   authenticator — exactly the cross-agora link §5.1 forbids. Prefer authenticators with
>   per-credential counters or none at all.
> - **Relying-party identifiers.** Treating each `agora_id` as its own relying-party context
>   works directly with platform key stores, where keys are scoped by an arbitrary alias. It
>   does not translate cleanly to WebAuthn/CTAP2, whose relying-party identifier must be a
>   valid domain rather than an opaque value; per-agora hardware scoping may therefore be
>   unavailable on precisely the discrete security keys this section otherwise recommends.
>   Where it cannot be enforced by the authenticator, Persora must enforce it in software and
>   should say so plainly to the member.

### §16 — new section

> ## 16. Multi-Agora Membership
>
> A person may belong to several agoras at once, holding one credential in each through a
> single Persora (§13). The agoras must remain mutually invisible: no agora, and no
> observer, should learn that a member belongs to any other. §5.1 states the credential-level
> requirement; this section covers what follows from it in practice, and where it stops.
>
> ### 16.1 What isolation covers
>
> Each membership is a self-contained cryptographic domain. Keys, accumulators, roots, epoch
> schedules, policies, tag keys, and receipt ledgers are per agora and share nothing.
> Standing in one agora confers nothing in another — a member at a high tier with long tenure
> begins any other agora as an ordinary candidate, admitted through the same vouching flow
> as anyone else (§5.3). There is no cross-agora reputation, and deliberately so: a
> transferable standing would be a linkable one.
>
> Because nullifiers are namespace-bound (§6.1) and the circuit is shared across all agoras
> (§6.5), two attestations by the same person in two agoras are, to any observer, unrelated
> artifacts of identical shape.
>
> ### 16.2 What isolation does not cover
>
> The protocol isolates cryptographic material. It does not isolate the device, the network
> stack, or the human operating them, and multiple memberships concentrate that residual
> exposure rather than merely repeating it:
>
> - **Network correlation.** Several memberships mean traffic to several Skiora deployments
>   from one host, on correlated schedules. An observer of the network — or an adversary
>   operating or compelling two of those deployments — can associate the memberships without
>   examining a single proof. Per-agora network isolation (a distinct anonymity-network
>   circuit per agora, never reused) is the practical mitigation, and for members in several
>   agoras it should be treated as a requirement rather than a refinement.
> - **Timing.** Activity that clusters across agoras — epoch rollovers performed together,
>   sessions opened in sequence, migrations run in one sitting (§16.3) — produces correlation
>   the cryptography cannot mask. Persora should avoid scheduling per-agora maintenance in
>   lockstep.
> - **The authenticator**, per §9.2's caveats on signature counters and relying-party scoping.
> - **The person.** Recruitment patterns, writing style, and availability windows are
>   unaffected by any mechanism here, and someone active in several agoras presents more
>   material to correlate. This is §15's social-leakage limitation, amplified by membership
>   count.
>
> ### 16.3 Device migration across several agoras
>
> Migration (§9.3) is per agora: one certificate, one Skiora, one accumulator update each. A
> member in several agoras performs several independent migrations, and the protocol offers
> no way to batch them — by construction, since no component has a cross-agora view.
>
> That independence is the point, and it is also the hazard. Several migrations executed in
> one sitting from one new device produce a tight cluster of credential replacements across
> otherwise unrelated Skiora deployments: a strong signal that those credentials share an
> owner, available to anyone observing more than one of them. **Migrations should therefore
> be staggered** — separated in time, and carried over distinct network paths. Persora is the
> only component positioned to help here, since it alone knows the set, and it should
> encourage staggering rather than offering a convenient migrate-everything action.
>
> The lost-device path (§9.3, Path 2) is worse in proportion. Each agora requires independent
> quorum revocation and fresh vouching, each involving other members and each generating its
> own visible activity. A member in several agoras who loses a device faces a recovery
> burden that scales linearly and cannot be consolidated. Groups should expect this, and
> members should weigh it when deciding how many memberships to hold on one device.
>
> ### 16.4 Practical ceilings
>
> Nothing limits membership count cryptographically, but two costs grow with it:
>
> - **Tag resolution** (§6.4) is proportional to the number of held agoras multiplied by the
>   number of cached epochs per agora, since an incoming tag must be tried against every
>   held key. The work is individually trivial and the growth is linear, but it is not free,
>   and the trial loop must not vary observably in duration according to which key matched.
> - **Hardware credential slots** are finite on discrete authenticators, often a few dozen
>   resident credentials. A member in many agoras may exhaust them.
>
> Persora should make the number of held memberships visible to the member, since the
> operational cost of each — migration burden, network discipline, recovery exposure — is
> borne by them and is not otherwise apparent.

### §15 — new entry

> **Multiple memberships concentrate correlation risk outside the protocol's reach.** A
> member of several agoras is cryptographically unlinked across them (§5.1, §16.1), but the
> single device, network path, authenticator, and person behind those memberships are not.
> Traffic to several Skiora deployments from one host, migrations or rollovers clustered in
> time, a shared authenticator's device-level identifiers, and consistent behavioural
> patterns are all available to an adversary observing more than one agora — and an
> adversary who operates or compels two of them needs no cryptographic break at all. Per-agora
> network isolation and staggered maintenance (§16.2, §16.3) reduce this materially but do
> not eliminate it, and the exposure grows with the number of memberships held on one device.

---

## Consequences

**Gained:** the guarantee §9.2 and §13 rely on becomes checkable text; the receipt ledger's
scope stops being contradictory, closing a cross-agora disclosure through the replay witness;
implementers get explicit direction on migration fan-out, network isolation, and
authenticator caveats that are otherwise discovered late or not at all.

**Paid:** one more normative section to maintain; §16.2 and §16.3 impose operational
discipline (staggering, per-agora circuits) that the protocol cannot enforce and that will
be inconvenient for members holding many memberships.

## Open questions

1. **Cross-agora panic wipe.** A member under duress may want to destroy all credentials at
   once. Any such action is inherently cross-agora and sits awkwardly against §5.1's
   prohibition on interfaces spanning agoras — though it is local-only and discloses nothing
   externally. Deferred.
2. **Constant-time tag resolution.** §16.4 requires the trial loop not to leak which key
   matched. Whether that must be constant-time across *all* held keys, or merely free of
   ordering that correlates with agora identity, needs settling when §6.4 is implemented.
3. **Should Persora cap memberships per authenticator** when slot exhaustion is
   foreseeable, or simply report the ceiling and let the member decide?
