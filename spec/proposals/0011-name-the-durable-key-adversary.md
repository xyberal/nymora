# Proposal 0011 — Name the durable-key adversary

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §1, §15
**Supersedes:** nothing

> **Applied as drafted.** The §15 entry sits between the hardware-custody and migration entries
> rather than at the end of the list: it is the boundary of the first, and the reason the second
> is not a complete remedy.
>
> One §9.1 claim this would otherwise have had to correct — that a seized dormant device yields
> nothing able to recompute past nullifiers — was fixed earlier, as part of completing proposal
> 0008's application. That is where it belonged: the sentence became false when 0008 made three
> nullifier contexts durable, not when this proposal named the adversary that exploits them.

---

## Problem

§1 lists device seizure and forensic extraction among the capabilities the design accounts
for, and §15 is candid about what hardware custody does and does not close. Neither says what
happens **after** the adversary loses access to the device.

That turns out to be the interesting part, because two of a credential's secrets cannot be
hardware-held at all. The rule that forces it has now appeared three times: **anything the
circuit recomputes must be exportable, and therefore cannot live in a secure element.** It
caught `r_root` (proposal 0003, which found the specified rotation unimplementable for exactly
this reason) and `sk_cred` (proposal 0008, which had to make it durable because counting
requires a key that outlives epochs). §9.1 already records both as software-held.

So §9.2's non-extractability protects `sk_root` and nothing else, and the remaining material is
- **durable** — `sk_cred` is generated once, never rotated, and carried across planned
  migration by §9.3, so it outlives the device it was created on;
- **small** — a fixed-width value that fits in a backup, a sync, a memory image, or a phone
  that was repaired, resold, or discarded after a migration;
- **still useful to an adversary who no longer has the device**, because the values derived
  from it are deterministic.

### Three proposals have rediscovered this independently

- **0005** found that a durable nullifier key lets whoever holds it recompute the nullifier for
  every published bundle and mark which the member acted on — the reason authorship keeps an
  epoch-scoped key.
- **0008** found that a durable `sk_cred` lets an adversary confirm two leaves belong to the
  same credential lineage across a migration, and recorded that consequence in §9.1.
- **0010** found that a durable-secret-derived value published to the transparency log becomes a
  permanent activity lookup, and proposed the rule in §10.1 that keeps such values off it.

Each recorded its own consequence. None named the adversary, so each analysis started over. A
capability rediscovered three times is one the threat model should enumerate.

## Decision

§1 names retention and continued use of extracted material as a capability the design accounts
for. §15 gains an entry stating what that capability actually reaches, what bounds it, and what
it costs to escape.

Nothing normative changes. This is a gap in what the design *says about itself*, not in what it
does — 0008's decision was forced, and no alternative construction avoids the exposure.

---

## Replacement text

### §1 — adversary capabilities, fourth item extended

> Nymora is designed against a spectrum of adversaries, from local law enforcement with
> subpoena power up to a resourced national security apparatus with network surveillance and
> infiltration capability. The relevant adversary capabilities the design accounts for include:
> legal compulsion of any operator; network-level surveillance and traffic correlation;
> infiltration by a genuinely-admitted member; device seizure and forensic extraction,
> **including retention and continued use of extracted material long after access to the device
> has ended**; and coercion of a member who is physically present with their device.

### §15 — new entry, following the hardware-custody entry

> **A durable credential secret keeps paying out after the device is gone.** Hardware custody
> (§9.2) covers `sk_root` and cannot cover everything: a value the circuit recomputes must be
> supplied to it as a witness, so `r_root` (§9.1) and `sk_cred` (§9.1) are software-held by
> construction rather than by choice. `sk_cred` is also never rotated and is carried to the
> successor credential on planned migration (§9.3), so it outlives the device it was generated
> on. An adversary who obtains it once — from a backup, a sync, a memory image, or a phone
> repaired, resold, or discarded after a migration — retains something that stays useful
> indefinitely, without further access.
>
> What it reaches: the nullifiers for vouching (§5.3), policy approval (§4.3), and migration
> (§9.3) are deterministic in `sk_cred`, so whoever holds it can recompute the value a given
> action *would* have produced and test whether that action was taken — backwards over the
> credential's whole history and forwards for as long as it lives. Combined with `r_root` and
> `pk_root` it also reproduces the accumulator leaf, and confirms that two leaves belong to one
> credential lineage across a migration (§9.1).
>
> What bounds it: those nullifiers are never published (§10.1), so the test requires Skiora's
> own state as well as the key — a compelled or compromised operator *in addition to* a key
> leak, not a public dataset anyone can download. `sk_cred` is per-agora (§5.1, §16.1), so one
> leak exposes one membership and says nothing about any other. And content is untouched:
> authorship nullifiers derive from the epoch key (§6.1), which is destroyed when its epoch ends
> (§9.1), which is why the published bundles remain unattributable.
>
> What it costs to escape: nothing rotates `sk_cred`, and migration deliberately preserves it,
> so a member who believes it has leaked has only §9.3's Path 2 — quorum revocation and
> re-vouching, surrendering tenure, vouch count, and tier. That is the full lost-device penalty
> paid without a lost device. Whether an agora treats a suspected key leak as grounds for it is
> a §5.3 policy judgement, and one worth making before it is needed.

---

## Consequences

**Gained:** the capability is enumerated once, where the next proposal will find it, instead of
being rediscovered from the consequence end each time.

**Gained:** the boundary of §9.2's protection is stated plainly. "Hardware-backed" reads as
covering the credential; it covers one key of three, and the reason is structural.

**Paid:** nothing. No mechanism changes.

**Not addressed:** whether `sk_cred` should be rotatable at all. It cannot be under the present
design — 0008 shows counting requires a key that outlives epochs, and §9.3 shows migration
requires one that outlives devices — but "no rotation path exists for the credential's longest
lived secret" is a fact worth stating rather than a conclusion worth resting on. If a future
proposal finds a way to rotate it without laundering the migration nullifier, this entry
narrows.

## Note for implementers

`SecretBytes` already erases on drop, redacts in `Debug`, and is deliberately not `Clone`
(`nymora-core`). Those defences target the value's presence in *this* process. They do nothing
about the copy a platform backup made, which is the path this entry describes, and which belongs
to the `SecureStorage` implementation rather than to the engine.

`Slot::CredentialKey` and `Slot::RootOpening` in `nymora-ports` are the two durable slots, and
are documented as such. A host implementing that port should treat exclusion from
platform-wide backup as a requirement for those two, not a preference.
