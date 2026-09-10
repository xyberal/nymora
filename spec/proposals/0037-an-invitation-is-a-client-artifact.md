# Proposal 0037 — An invitation is a client artifact

**Status:** **Applied** — §17.1 is now normative in the specification
**Affects:** §17.1 (new); no change to Skiora's surfaces
**Depends on:** [proposal 0036](0036-the-boundary-broadcast-is-delivered-per-member.md) (the fetch key)
**Companion:** [proposal 0038](0038-artifacts-have-a-text-armor.md) (how it travels)

> **Found designing the first native client.** The reference CLI joins an agora from
> four values typed on a command line, and bootstraps a freshly admitted member from
> the operator's loopback admin plane. Neither is available to a person with a phone.
> The protocol is complete without an invitation — admission is §5.3, and it needs none —
> but two clients that cannot read each other's invitations are two protocols to the
> people using them.

---

## Problem

A candidate can do nothing until a member tells them four things, and the protocol
says only that they are shared "out-of-band" (§3, §4): the operator's address, the
`agora_id`, the policy class to be admitted to, and the **statement key** — the trust
root every envelope is verified against (§11, proposal 0024), which must be pinned
before the first envelope is opened and never learned from the server that signs
with it.

Two further values are needed in practice and have no member-side source today:

1. **The first envelope.** A member who has just landed holds no fetch key: the fetch
   key of epoch `e` is inside epoch `e`'s body, which they could not open before they
   had a ciphertext in it. The reference flow hands them the envelope through the
   admin plane, which binds loopback on the operator's host by design. A member of a
   provider-hosted agora has no such path.
2. **The epoch interval.** The candidate must finalize within the epoch (§5.3) and will
   land at the next boundary, so the client needs to say *when*; the interval is fixed
   at founding and served nowhere on the member plane.

Every client will invent an object carrying these. If each invents its own, an
invitation from one client cannot be accepted by another.

## Decision

**An invitation is a versioned byte object with this content, produced by a member's
client and consumed by a candidate's client.** It is not a protocol message: Skiora
never sees one. Its encoding is normative so that clients interoperate; its transport
is proposal 0038's armor, or any channel that carries bytes.

```
invitation := version(1) ‖ agora_id(32) ‖ policy_class(32) ‖ statement_key(32)
            ‖ log_key(32)          -- all-zero when the agora publishes no log
            ‖ fetch_key(32)        -- the current epoch's, from the inviter's body
            ‖ epoch(8, u64 LE)     -- the epoch that fetch key belongs to
            ‖ interval(8, u64 LE)  -- the agora's epoch interval, in seconds
            ‖ valid_through(8, u64 LE)  -- last epoch at which fetch_key is served
            ‖ server(length-framed UTF-8) -- the member plane's address
version = 1
```

**The fetch key is deliberately included.** It is what lets the new member fetch their
first envelope after they land, with no operator involvement: a fetch key is served
for its window (Skiora's `bulletin_key_epochs`, default two boundaries), so an
invitation issued at epoch `e` fetches epochs `e` and `e+1` — enough to land and
receive. The inviter, a member, could hand this key over in any case; the object
grants nothing a member could not already tell the invitee.

**What that costs, stated.** The fetch key's blast radius is that the agora exists and
how many ciphertexts it publishes (0036). An invitee who never completes admission
can learn both for the window. Therefore:

- an invitation is a **members-only artifact**, to be sent over a channel the inviter
  trusts, never posted publicly, and clients present it as such;
- `valid_through` is the inviter's client's statement of the window's end, and a
  consuming client refuses an invitation past it rather than trying a dead key;
- the invitee's fetch of the first envelope is a fetch like any other: Skiora
  distinguishes nothing.

**The statement key is the trust root, and the channel is what protects it.** An
invitation is not signed: a signature by the inviter's credential would be an
authorship bundle (§6.6) over the invitation, which the invitee — not yet a member —
cannot verify (§7). The invitee trusts the statement key exactly as far as they trust
whoever handed them the invitation, which is the same trust admission already rests on
("real-world vetting happens off-system", §5.3). A client shows the statement key's
fingerprint so that it *can* be compared out of band; it does not pretend the object
proves anything.

**Interval and expiry are advisory.** They come from the inviter's client, which
learned the interval at founding (the founder) or from its own invitation (everyone
else). A client uses them for deadlines and messaging; nothing cryptographic depends
on them, and a wrong value produces a wrong clock, not a wrong proof.

## Consequences

- **Skiora is unchanged.** No route is added, and the admin plane keeps its role for
  the founder's genesis envelope, which no invitation can carry (there is no earlier
  member to issue one).
- **The reference CLI gains `persora invite`** (produce) and `persora join --invite`
  (consume), and the three-client demo's admin-bulletin hand-offs for new members are
  replaced by invitations — so the flow is exercised against the real server before any
  native client exists.
- **A member who missed the window** (two boundaries without a sync) recovers the same
  way a new member starts: a fresh fetch key from any member. Clients may present a
  "resync" object that is an invitation minus nothing — the object already is one.
- **An invitation reveals the inviter to the invitee**, socially. The protocol does
  not and cannot hide who invited whom from the invited; it hides it from the server,
  which learns nothing about invitations at all.

## Open questions

1. Whether `bulletin_key_epochs` should become a per-agora value visible to members,
   so `valid_through` is computed rather than assumed from the default. Skiora
   configuration today; a member-visible interval and window in the envelope body
   would make both fields of this object derivable. Not needed for correctness.
2. Whether a client should refuse to *produce* an invitation over a transport it
   cannot label as private (a plain clipboard copy, say). Presentation, not protocol.

## Applying this proposal requires

- §17 "Client interoperability" appended to the specification, with §17.1 stating the
  object, the members-only rule, and the trust argument above.
- `nymora-core`: an `invitation` codec (encode/decode, canonical, length-framed like
  `MigrationHandoff`), with a conformance vector.
- The reference CLI's `invite` / `join --invite`, and the demo updated to use them.
- CHANGELOG "Added".
