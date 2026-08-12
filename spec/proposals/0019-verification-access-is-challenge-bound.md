# Proposal 0019 — Verification access is a challenge-bound membership proof, with no nullifier

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §7
**Supersedes:** nothing

> **Decided in session and applied directly.** Phase 4's statement types forced the blank:
> §7 gives the wire shape of policy-check (`proof_token` in, `grant_token` out) but never
> states what the proof *proves*, and an implementation cannot leave a proof statement
> implicit. The decision follows §9.1's existing structure — the membership chain with an
> action-specific final clause — so it is recorded rather than drafted for a decision.

---

## Problem

§7 restricts verification to members: obtaining a root requires proving current standing.
The endpoints are specified, the statement is not. Filling it naively either way fails:

- **A bare membership proof** — the chain of §9.1 with no final clause — is a replayable
  artifact. Anyone who observes one (a network position, a compromised log, Skiora itself
  re-presenting it elsewhere) holds a reusable "some member asked for roots" token. Every
  other proof in the design is bound to something single-use; this one would be bound to
  nothing.
- **A nullifier-bearing proof** — the pattern every other action uses — is wrong for a
  different reason: a nullifier enforces *at most once*, and access is not a count. §7's
  premise is that any current member may verify anything, any number of times. A nullifier
  over some access context would either ration verification (wrong) or be derived over a
  value so fresh it enforces nothing (pointless), while handing Skiora one more
  credential-derived artifact per lookup for no property in return.

## Decision

The verification-access proof is the full membership chain of §9.1, proven against the
verifier's own policy class, with this final clause:

```
the Fiat–Shamir challenge incorporates a Skiora-issued, single-use challenge value
```

— and no nullifier or pseudonym. Freshness comes from the challenge: Skiora issues it for
one exchange, the proof binds it the same way an authorship proof binds `message_hash`
(§6.5), and a replayed proof fails against any other challenge. Distinctness needs no
enforcement because nothing is counted.

What Skiora learns is exactly what §7 already grants it: *some* current member of the
proven class asked for roots. No pseudonym, no nullifier, no cross-request handle — two
lookups by the same member are structurally unrelated, which is strictly less than any
nullifier-bearing design would disclose.

The `grant_token` and the challenge's transport (issuance, expiry, single-use bookkeeping)
are Skiora-side session mechanics, out of scope here and specified with the wire flows
(phase 5).

---

## Replacement text

### §7 — after the consolidated round-trip block

> The membership proof in either form is the full chain of §9.1 — that statement is
> normative there, and only its final clause varies by action. For verification access the
> final clause binds a **Skiora-issued, single-use challenge** into the Fiat–Shamir
> transcript, exactly as an authorship proof binds `message_hash` (§6.5), and carries **no
> nullifier**: access is not a count, so there is nothing for a nullifier to enforce, and a
> credential-derived artifact per lookup would disclose more than the accepted baseline —
> that some current member of the class asked — for no property in return. Replay is
> closed by the challenge being single-use, not by distinctness bookkeeping.

---

## Consequences

**Gained:** the statement exists, so phase 4 can implement it; replay of an observed
access proof is closed; the disclosure floor of §7 is unchanged rather than quietly
raised.

**Paid:** verification access becomes a two-message exchange (fetch challenge, present
proof) rather than a bearer token — the cost every challenge-response design pays.
Skiora must remember issued challenges until use or expiry; that is state it already
keeps for vouch sessions.

**Unchanged:** the endpoints and their shapes in §7. The out-of-band root resolution via
the tag mechanism (§6.4). The circuit: the chain is the same one, and a final clause that
binds a public input and derives nothing is the cheapest of the action variants.
