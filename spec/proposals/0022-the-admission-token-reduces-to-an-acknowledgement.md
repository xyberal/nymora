# Proposal 0022 — The credential-update token reduces to an admission acknowledgement

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §5.3 (and the finalize responses quoted in §4.2)
**Supersedes:** nothing

> **Decided in session and applied directly.** Phase 5's vouch machine forced the blank:
> §5.3's `finalize` returns `{ threshold_met: true, credential_update_token }`, and the
> token is named nowhere else — not what it contains, not what accepts it, not what it
> authorizes. An implementation cannot return a value the specification never defines.

---

## Problem

The name suggests a bearer credential: something the new member presents later to
"collect" their membership. Any such design is worse than nothing here:

- **The member needs no secret from Skiora.** The credential is the member's own
  material — `sk_cred`, `r_root`, `pk_root` existed on their device before the session
  opened, and the leaf *is* their commitment, which they already hold. There is nothing
  to hand over.
- **A bearer token is a liability.** It would be a value whose theft means something,
  carried over a channel §1's adversary watches, protecting a resource — membership —
  that is actually established by the accumulator insertion itself.
- **Everything the member must *learn* is two public facts:** that admission happened,
  and where and when the leaf sits — its permanent position (for witness refresh) and the
  epoch from which it is present in the class root (proposal 0020).

## Decision

`finalize`'s successful response is an **admission acknowledgement** and nothing more:

```
POST /agora/{agora_id}/vouch/session/{id}/finalize
  → { threshold_met: true, position, active_from_epoch }
```

`credential_update_token` is struck as a concept. The acknowledgement is not secret, not
bearer, and authorizes nothing: presenting it proves nothing, and losing it costs nothing
— the same facts are recoverable by refreshing a witness for the member's own leaf.
Everything else the new member needs — the epoch's roots, exclusion sets, tag key —
arrives the way it arrives for every member: the boundary distribution (§11's broadcast
mechanism) and the member-gated services of §7.

## Consequences

**Gained:** the finalize response is fully specified; no bearer value exists to steal,
replay, or compel; admission's effect is exactly the accumulator insertion, with no
second "activation" step to get out of sync with it.

**Paid:** nothing identified — the token had no other stated role to lose.

**Unchanged:** the one-time disclosure shape of finalize (§5.3): the outcome, including
this acknowledgement, is revealed exactly once, and a failed finalize consumes the
session.
