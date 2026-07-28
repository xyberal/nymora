# Proposal 0007 — Epoch length, lazy rollover, and event-driven advances

**Status:** **Applied** — the sections below are now normative in the specification
**Affects:** §6.4, §9.1, §11, §16.4

> **Applied as drafted.** `EpochSecretKey`'s doc comment in `nymora-core` carried the same
> defect as §9.1's deletion sentence — "discarded at epoch rollover" — and was corrected
> alongside it.
**Corrects:** the deletion sentence in §9.1 applied by 0004 — see part 1
**Answers:** the open question left by 0005 (epoch length has a floor but the specification
states neither bound)

---

## Problem

The specification never says how long an epoch is, and three separate mechanisms now depend
on the answer. Attempting to pick a number surfaced that two of the three constraints were
misread, and that one of them is not really about epoch length at all.

### What appears to constrain the choice

| Wants longer epochs | Wants shorter |
|---|---|
| Hardware user-presence prompts, one per rollover per agora (§9.1, §9.2) | Forward-secrecy granularity — compromise exposes one epoch of activity (§9.1) |
| Governance and admission must complete inside one epoch (§4.3, §5.3, per 0005) | Revocation read-latency — a revoked member keeps `K_tag_e` until the boundary (§6.4, §11) |
| Tag resolution cost, agoras × cached epochs (§16.4) | |

Taken at face value the first row and second row have no comfortable midpoint: prompts want
weeks, revocation wants hours. But the hardware constraint is an artifact of assuming
rollover is eager, and the revocation constraint is an artifact of assuming epoch boundaries
are purely scheduled. Neither assumption is stated anywhere; both are wrong.

### Rollover is triggered by use, not by the calendar

Nothing requires a member to certify a new epoch key when an epoch begins. `epoch_cert` is a
private witness that never leaves the device (§9.1), so certification is a purely local
operation with no protocol interaction, nothing published, and no counterparty. A member
needs a current epoch key only at the moment they act.

So the real cost is one prompt per *burst of activity*, not one per elapsed epoch. A member
inactive across ten epochs pays a single prompt when they next act. A member who only reads
pays none at all: resolving tags needs `K_tag_e`, which is broadcast, and verifying others'
content needs the accumulator root, neither of which touches their own key material.

The hardware constraint therefore does not scale with epoch length, and does not constrain
it.

### But lazy rollover breaks the deletion rule as currently worded

§9.1 says: *"once rollover completes, the previous epoch's key is destroyed."* That ties
deletion to rollover, and under lazy rollover an inactive member never completes one — so
they hold a live epoch key indefinitely, and the forward-secrecy window becomes *time since
last activity* rather than one epoch. A member who acts once a year carries a year-long
window on a weekly epoch.

### And revocation latency is not an epoch-length problem

§6.4 revokes tag access by ceasing to broadcast `K_tag_e`, which takes effect at the next
boundary. §11 meanwhile names "fast internal detection leading to prompt revocation" as one
of the only mitigations available once content has propagated. As written, promptness is
capped by epoch length — and the asymmetry underneath is stated nowhere:

| | When revocation takes effect |
|---|---|
| **Write** — attesting, vouching, approving | Immediately: the credential leaves the accumulator and no valid proof can be produced |
| **Read** — resolving tags, decrypting gated content | Not until the epoch turns, since the revoked member already holds `K_tag_e` |

Nothing in the design requires boundaries to be scheduled, though. If an epoch can be
advanced early, revocation can advance it, and the latency question detaches from the routine
interval entirely.

## Decision

Three parts, in the order the reasoning above establishes them.

### 1. Rollover is lazy, and deletion is not tied to it

Two triggers, deliberately separate:

| | Trigger |
|---|---|
| **Destroying** the previous epoch's key | **The clock** — when the epoch ends, whether or not a successor has been certified |
| **Generating and certifying** a new one | **Use** — when the member next needs to act |

This is strictly stronger than tying both to rollover. A member with no current activity holds
no usable epoch key at all, so a seized dormant device yields nothing that can forge a proof
and nothing that can recompute even the previous epoch's nullifiers. `sk_migrate` and `r_root`
remain, as §9.1 already describes.

### 2. Epoch length is a bounded per-agora policy

Set through the same policy-mutation mechanism as thresholds (§5.3), following the precedent
§9.3 sets for the analogous judgment — agoras with different risk profiles should not be
handed one number.

| | |
|---|---|
| **Default** | 7 days |
| **Minimum** | 24 hours |
| **Maximum** | 30 days |

The bounds are protocol facts rather than preferences. Below 24 hours, asynchronous k-of-n
governance cannot reliably complete within the epoch that 0005 confines it to. Above 30 days,
the forward-secrecy granularity in §9.1 stops meaning anything useful.

Between those, the choice is governed by one question: how often do members realistically
check in? A proposal must be raisable *and* completable inside one epoch, so the interval
must exceed the group's response time, not merely its action time.

Epoch length is mutable policy and therefore **not** part of the public parameters from which
`agora_id` is derived (§3), which are fixed at creation.

### 3. Epochs may be advanced early, and revocation advances them

The scheduled interval is a **maximum**, not a fixed tick. An agora may advance the epoch at
any time by publishing the new epoch's root (§10.1) and broadcasting the new `K_tag`; members
pick it up the next time they act, which under part 1 costs them nothing extra.

Revocation, and any other change to the membership set, advances the epoch immediately. Read
access for the revoked credential ends with the broadcast rather than with the schedule.

This closes only *future* access. Content the revoked member already resolved cannot be
un-resolved, consistent with §11's statement that there is no cryptographic undo once content
has propagated.

---

## Replacement text

### §9.1 — the deletion paragraph, replaced in full

> The corollary is a deletion requirement, and its trigger is the clock rather than the
> rollover: when an epoch ends, that epoch's key is destroyed, whether or not a successor has
> been certified. Forward secrecy across epochs rests on that deletion, not on the derivation
> structure — there is none.
>
> **Certification, by contrast, is triggered by use.** `epoch_cert` never leaves the device
> (below), so certifying a new epoch key is a purely local operation with no counterparty and
> nothing published; a member needs a current key only at the moment they act. There is
> therefore no reason to certify one at the start of every epoch, and good reason not to: a
> member with no current activity holds no usable epoch key at all, so a seized dormant device
> yields nothing that can forge a proof and nothing that can recompute even the previous
> epoch's nullifiers. Members who only read need never certify a key, since resolving tags
> uses the broadcast `K_tag_e` (§6.4) and verifying content uses the accumulator root.
>
> One consequence is worth stating for implementers: the cost of hardware-backed custody
> (§9.2) scales with a member's activity, not with elapsed time. A member inactive across ten
> epochs pays one user-presence prompt when they next act, not ten.

### §9.1 — new paragraph, epoch length

> **Epoch length is a per-agora policy, bounded by the protocol.** It is set and adjusted
> through the same policy-mutation mechanism as vouching thresholds (§5.3), because agoras
> with different risk profiles should not be handed a single interval — the same judgment §9.3
> makes about presuming a device unreachable.
>
> The default is **7 days**, the minimum **24 hours**, and the maximum **30 days**. The bounds
> are not preferences: below 24 hours, asynchronous k-of-n governance cannot reliably complete
> inside the epoch that §4.3 and §5.3 confine it to; above 30 days, the forward-secrecy
> granularity described above stops being useful. Between them the choice follows from how
> quickly members realistically respond, since a proposal must be both raised and completed
> within one epoch.
>
> The interval is a **maximum**, not a fixed tick: an epoch may be advanced early (§11), and
> is not part of the public parameters deriving `agora_id`, which are fixed at creation (§3).

### §6.4 — after the revocation sentence

> Because tag keys are broadcast per epoch, ceasing to broadcast takes effect at the next
> epoch boundary rather than immediately. An agora may advance the epoch early precisely to
> make it immediate; see §11.

### §11 — new paragraph, after the status-check scoping

> **Revocation is asymmetric in effect, and the asymmetry is closed deliberately.** Write
> capability ends at once: the credential leaves the accumulator, and no valid proof can be
> produced against the new root. Read capability would not, since a revoked member already
> holds the current epoch's `K_tag_e` and the content keys gated alongside it (§6.4), and
> those are replaced only at an epoch boundary.
>
> Revocation therefore advances the epoch immediately rather than waiting for the schedule
> (§9.1). The new `K_tag` is broadcast to the remaining members, and the revoked credential
> receives nothing further. This is what makes the "prompt revocation" named above an
> available mitigation rather than one capped by the routine epoch interval. It closes future
> access only: content already resolved cannot be un-resolved, consistent with the absence of
> any cryptographic undo.
>
> An early advance also expires any open policy proposal or vouch session (§4.3, §5.3). That
> is intended rather than incidental — the membership set has changed, so the quorum
> arithmetic has changed, and approvals cast in part by a now-revoked credential should not
> carry forward silently.

### §16.4 — tag resolution bullet, sentence added

> Early epoch advances (§11) add to the count of cached epochs beyond what the scheduled
> interval implies. The effect is small, since advances follow membership changes rather than
> content volume, but a client caching by wall-clock window rather than by epoch count will
> mis-size its cache.

---

## Consequences

**Gained:** epoch length becomes a decidable parameter, because the two constraints that
appeared irreconcilable were both artifacts of unstated assumptions. Revocation gains an
effective read cut-off. Dormant devices become materially safer than the previous wording
implied.

**Paid:** the epoch number is no longer predictable from a start time and an interval. Any
client that inferred the current epoch arithmetically must instead learn it from the
transparency log (§10.1) or the tag-key broadcast. This is the right dependency — an agora
that advances early has a reason to — but it is a real change for an implementer who assumed
a fixed tick.

**Paid:** frequent revocations mean frequent advances, so members re-certify more often in
periods of governance churn. Acceptable, and concentrated exactly when the group wants
tighter control.

## Note for implementers

`Epoch` in `nymora-core` is an opaque counter with checked increment and carries no notion of
duration, so nothing there assumes a fixed tick. `LocalReason::EpochOutOfRange` already
covers a proof presented under a stale key, which is the observable result of a member acting
after an advance they have not yet picked up.

The two triggers in part 1 belong to the host, not the engine: deletion is clock-driven and
the engine has no clock by design. `SecureStorage` (task 1.7) will need an operation the host
can call when an epoch ends, distinct from whatever certifies a new key.

## Open question

**Who decides an epoch has ended?** Part 1 makes deletion clock-driven, but the engine is
sans-io and has no clock, and a member's device clock can be wrong or manipulated. An epoch
end that a member's device recognises late leaves a key alive past its window; one it
recognises early destroys a key still in use. The transparency log (§10.1) is the authoritative
record, so the safe reading is that the log's published advance defines the end and local
clocks are only a hint — but that makes deletion depend on connectivity, which §15 already
flags as outside what cryptography alone can guarantee. Worth settling before the state
machines are written.
