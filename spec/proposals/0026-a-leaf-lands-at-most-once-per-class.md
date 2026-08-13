# Proposal 0026 — A leaf lands at most once per class

**Status:** **Applied** — the section below is now normative in the specification
**Affects:** §5.2
**Supersedes:** nothing

> **Found by the pre-publication re-read.** The phase-5 operator enforced every
> precondition at the door of each flow and none at the point where flows converge — the
> staging list itself. Two flows converging on the same leaf therefore staged it twice,
> and a third path could consume a spend on a staging that then refused.

---

## Problem

Three admission paths put a leaf into the staged list that lands at the boundary
(proposal 0020): founding, vouch finalize, and migration acceptance. Each checked its own
preconditions — a vouch session opens only for a pending candidate not already *landed*
in the class, a migration's successor is refused if already *landed* — but none checked
the staged list, and nothing checked at the one place all three converge.

The concrete hole: a candidate stays pending until a finalize succeeds, so two vouch
sessions may be opened for one candidate, both may gather attestations, and both may
finalize within the epoch. Each finalize staged the leaf; at the boundary the class tree
appended the same commitment twice, and the operator's position bookkeeping silently
overwrote the first position with the second.

This is **not** a counting break, and establishing that was part of the decision. Every
counted nullifier derives from `sk_cred` and is leaf-independent (§9.1), so a duplicated
leaf mints no second vote and no second vouch. Revocation is by commitment (§11), so
revoking the credential covers every copy at once. Both copies open with the same
`sk_cred`, so their migration spend is one nullifier — spending either consumes both.
What the duplicate does cost is real anyway: it permanently burns capacity that §5.2
declares terminal for the class, and it breaks the implicit invariant — one leaf per
admission decision — that the position bookkeeping and the admission acknowledgement
(proposal 0022) are written against.

A second hole shared the family: migration acceptance staged the **spend before the
admission**. A verified migration whose staging then refused — a full class is
sufficient — had already staged the spend, so the boundary consumed the old leaf while
admitting no successor: the member paid the full lost-device price (§9.3, path 2) for a
refusal that should have cost nothing.

## Decision

**The staging point enforces the invariant, because the staging point is where the flows
converge.** Staging a leaf refuses when the class already holds it — landed, or staged
for the coming boundary. Door-side checks remain as cheap early refusals; the guarantee
does not rest on them.

Two consequences of placing the check there rather than earlier:

- **Concurrent vouch sessions for one candidate remain legal.** Nothing at session start
  can know which of two open sessions will meet threshold first, and refusing the second
  *session* would disclose that a first exists — a disclosure the zero-field `attest`
  response shape exists to avoid (§5.3). The race is resolved where it becomes real:
  whichever finalize stages first wins, and the later one refuses exactly like any other
  failed finalize, consuming its session (proposal 0022).
- **The same leaf in two different classes is not a duplicate.** A member's classes share
  one commitment by construction — the founder's leaf enters every founding class (§4.1)
  — so the check is per class, not per agora.

**Migration stages the admission first, the spend second.** A staging refusal now
refuses the migration whole: the spend is never staged, the old leaf stays live, and the
member retries or accepts the class's exhaustion with their standing intact. The
verified-then-refused proof discloses nothing the member did not already publish by
submitting it.

## Consequences

- `stage_admission` gains the duplicate check and becomes the normative choke point; §5.2
  states the invariant ("added at most once per class") beside append-only.
- A duplicate staging refuses as `Rejected`, indistinguishable from every other refusal
  (§5.3's non-disclosure discipline).
- The double-finalize race and the refused-migration spend are pinned by tests: the
  second finalize refuses and exactly one seat lands; a migration into a full class
  broadcasts no spend and the predecessor still acts.
- Rejected alternative: refusing the second session at `start_vouch`. It closes only the
  vouch path (migration and founding converge on the same list), and it cannot be
  complete — sessions expire at boundaries, not at finalize, so a session-time check
  still leaves the finalize-time race. The invariant lives where the list is written.
