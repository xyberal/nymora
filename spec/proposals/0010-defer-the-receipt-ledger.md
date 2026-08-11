# Proposal 0010 — Defer the receipt ledger to a later protocol version

**Status:** **Applied** — the sections below are now marked deferred in the specification
**Affects:** §2, §10, §10.1, §10.2, §10.3, §10.4, §14
**Supersedes:** 0009, which repairs a mechanism this proposal defers
**Answers:** 0008's open question — "does anything else rest on one-key-per-epoch?"

> **Applied with three additions to the closing note, and one row updated.** Since this was
> drafted, the review that strengthened it also found that §10.2's replay verification is
> impossible as specified — entries are signed with `sk_epoch`, whose public key is never
> published and whose private key is destroyed at epoch end, so a witness holds no
> verification key for any past-epoch entry. That finding, and the shape a viable
> reintroduction takes — write-time completeness via 0009's linear heads, self-verifying
> action artifacts instead of signatures, the member as verifier, mandated third-party audit
> permanently out of reach — were added to §10.4's closing note so a reintroducer meets
> every obstacle at once. The §2 transparency-log row reads "exclusion roots" rather than
> "revocation-set root", matching 0015, which was applied first. The second open question
> below was answered by proposal 0011 before this one was decided.

---

## Problem

This began as a scope decision, like 0006, and is written up because the receipt ledger is not
an isolated feature: three subsections, one bullet on the public log, and an entire
unlinkability apparatus exist only to support it, and removing it changes what §10 claims. That
coupling needs recording where a future implementer will find it.

It has since become less of a judgement call. The first three subsections below are the original
argument — the mechanism is contradictory as specified, and both known repairs are expensive.
The fourth was added later and is the stronger one: **§10.4 cannot be implemented at all without
two primitives the design does not have.**

### The mechanism does not currently work as specified

§10.3 claims head-pinning makes a credential's ledger "*non-forkable (one chain per
credential)*". §10.4 states that Skiora "*cannot ... read chain length or cross-epoch
continuity from the heads it holds*," and presents that as the privacy property the section
exists to provide.

These are the same fact with opposite signs. §10.3 asks Skiora to enforce an invariant over
*credentials*; §10.4 guarantees Skiora cannot identify a credential. What Skiora's table is
actually keyed by is the per-epoch handle, and the map from handle to credential is precisely
what §10.4 makes uncomputable.

Two consequences follow, and the second is worse than the first:

- **Across a boundary**, a freshly rotated handle has no last-recorded head, so Skiora has
  nothing to compare a declared starting point against. A member may begin a new chain and
  later present a consistent but partial history.
- **Within an epoch**, nothing constrains handle registration at all. §10.3's parenthetical
  assumes one handle per credential per epoch; no section requires it. If handles are
  unlinkable and freely registrable, a member registers two in the same epoch and keeps two
  chains without waiting for a boundary.

So the within-epoch guarantee is not sound either. 0009 diagnosed this as a boundary problem;
it is a registration problem, and the boundary is only where it is most visible.

### Better wording cannot fix it

The ability to verify "these two handles belong to one credential" **is** the ability to
stitch a credential's epochs into a thread. Enforcement and surveillance are one capability
here. Skiora cannot be granted the first and denied the second by more careful drafting, which
is why this is a design gap rather than an editorial one.

### Both repairs are expensive, and one is disqualifying

**Derive the handle from a durable secret** (`handle_e = Hash(sk_cred, agora_id, e)`). Cheap —
the handle becomes its own nullifier, and registration adds one hash to a circuit already
running a membership proof. But handles must appear on the transparency log, or §10.1 cannot
audit whether Skiora pinned two heads under one credential. The complete set of handles is then
public, permanent, replicated, and undeletable by construction. An adversary who later obtains
`sk_cred` computes one hash per epoch and reads off a gap-free activity timeline — backwards
over the credential's whole life, and forwards forever, since §9.3 carries `sk_cred` across
migration. The only escape is path 2 revocation: the member pays the full lost-device penalty
having never lost a device.

This is not covered by 0008's rationale that a device adversary already holds the ledger. That
adversary needs access and sees a snapshot; this one needs one 32-byte value and sees
everything, from anywhere, permanently.

**Consume the previous head** (0009). Sound, but it needs an unspent-head accumulator, a
set-membership proof from every active member at every boundary, and a spend nullifier 0009
does not specify — and its privacy rests on per-epoch entropy held only by the member, which is
exactly why a member who loses chain state is locked out of their own credential. 0009 records
that as an open question. It is not answerable: recoverability from durable secrets and
unlinkability against durable secrets are the same statement with opposite signs.

### §10.4 is not implementable, and that is a stronger objection than cost

Everything above is an argument that the ledger is expensive and strained. A later review found
something firmer: **§10.4's replay-witness selection requires two primitives the design does not
have, and its own construction leaks what §5.2 forbids.**

**It cites a primitive that cannot do this job.** §10.4 says selection "uses public randomness
Skiora cannot bias (the jointly-derived-randomness primitive from §8.1)." §8.1 is a commit-reveal
among the participants of a *live session* — it needs a known participant set, all online
simultaneously, and `channel_metadata` from a live channel's handshake. Witness selection has
none of those: the candidate set is the whole anonymous membership, they are not simultaneously
online, and there is no channel. Proposal 0012 corrected a genuine bias flaw in §8.1, and did not
make it applicable here. What §10.4 needs is a public randomness beacon, which appears nowhere in
the design; the transparency log's signed tree heads are the nearest thing and Skiora produces
them, so it can grind them.

**It needs a delivery mechanism that does not exist.** The holder must send their full ledger to
the selected witness, who is anonymous by construction — the point is that they prove selection
"without revealing which member that is." §6.4's tags route content to *the agora*, resolved by
every member trying their keys; that is broadcast. §8 authenticates members already sharing a
channel. Nothing in the protocol delivers a private message to an anonymously-selected
counterparty.

**Selection leaks membership size, which §5.2 forbids without qualification.** §5.2: *"No API
surface exposes accumulator size, leaf count, or leaf listing, at any point."* §5.4 rules out
decoy padding, so occupancy is information about real members. Any mechanism that samples from
the membership has an observable response rate, and response rate × selection probability =
membership size. Selecting by leaf index makes it blatant, since most indices are empty. The
natural repair — a VRF-style lottery where each member checks `H(sk_cred, R) < t` and proves
selection in zero knowledge — removes the empty-slot problem and still leaks: the number of
respondents is binomial in the membership size, and setting `t` so that roughly one member
responds requires already knowing it. This is not a construction defect. Sampling from a set
reveals the set's size.

That lottery form also lands on the pattern 0011 has since enumerated: `H(sk_cred, R)` with
public `R` and observable selection lets anyone who later obtains `sk_cred` determine whether
that member was selected in any past round.

**The section violates its own title.** §10.4 is called "Keeping the ledger from becoming an
activity graph." It protects the ledger from Skiora and then hands it, entire, to a randomly
chosen fellow member — while §1 lists "infiltration by a genuinely-admitted member" among the
capabilities the design accounts for. The member-*chosen* witness is fine; the verifiably-random
branch exists precisely so the member cannot choose, which is what makes it unsafe.

**Two smaller errors.** §10.4 resolves witness disagreement by recomputation, "the witness whose
result does not match is the faulty one" — but if two witnesses were shown *different ledgers*,
which is the attack §10.3 exists to catch, both recompute correctly and the faulty party is the
holder. And a selected member who stays silent is indistinguishable from one never selected,
offline, or non-existent, so a rogue Persora is never audited by simply not replying.

**What this changes about the decision.** Deferring §10.2–§10.4 was a judgement about whether
the ledger earns its cost. It is now closer to a forced move: making §10.4 implementable means
specifying a randomness beacon *and* an anonymous unicast channel, then accepting a cardinality
leak the specification prohibits in absolute terms. Each of those is a larger undertaking than
the ledger itself.

### Why it keeps generating problems

Every other mechanism in Nymora works by destroying state. Epoch keys are generated fresh and
destroyed at the boundary (0004, 0007); nullifiers expire with the key that produced them;
`sk_root` is non-exportable; content is tag-routed so observers cannot accumulate correlations;
§3 hides an agora's existence. The design is subtractive throughout.

§10.2 is the one component that accumulates — a permanent, signed, growing per-member record.
It is also the one that keeps colliding with the rest, and the collisions are not coincidental.

The root difficulty is circularity: **the ledger is a record of a party's behaviour, held by
that party.** §10.3 and §10.4 are four stacked mechanisms — Skiora enforcement, head-pinning,
public checkpointing, verifiably-random witnesses — all compensating for that single fact. The
contradiction above is what that compensation costs when it meets the unlinkability the rest of
the design requires.

## Decision

§10.2, §10.3, and §10.4 are deferred to a later protocol version. They remain in the
specification, marked deferred rather than deleted, so the design and its rationale survive for
whoever picks them up.

§10.1 is retained unchanged except for the pinned-heads bullet. The transparency log addresses
a rogue *Skiora*, not a rogue member, and stands alone.

## What is lost

**Enforced completeness.** Skiora no longer refuses actions unaccompanied by a chain-extending
entry. Whether an action occurred is recorded by Skiora's nullifier sets where the action is
counted, and not at all where it is not.

**Authorship self-audit.** A member cannot establish that their credential did *not* publish
content they did not write. An application may keep a local log, but that is not a protocol
guarantee and a compromised client writes it.

**Verification-outcome integrity.** A client that lies to its user about a verification result
is no longer caught by a signed chain.

**Third-party replay**, and with it §10.4's verifiably-random witness selection.

## What is not lost

**Detection of unauthorized governance actions.** Skiora already maintains authoritative
nullifier sets for vouching (§5.3), policy approval (§4.3), and migration (§9.3), because it
needs them for duplicate detection. Those records are **client-independent**: a rogue Persora
cannot truncate, fork, or rewrite them, because it does not hold them. A member who can compute
`vouch(sk_cred, session_id)` or `policy(sk_cred, proposal_id, agora_id)` can determine whether
their credential took that action.

This covers less than the ledger and covers it more soundly. It is exactly the case §10.2's
third bullet names — a member checking that every action was one they authorized — and it works
against the adversary that bullet fails against, since the record is not in the attacker's
hands.

Exposing it as a query is **not specified here**; see the open question.

**§10.1 in full**, minus one bullet. Its three auditor guarantees — non-equivocation,
append-only integrity, protocol conformance — concern aggregate state and are untouched.

**0008.** Its finding is independent of §10: an epoch key cannot support a count regardless of
whether a ledger exists. `sk_cred` remains durable for the same reasons.

---

## Replacement text

### §2 — vocabulary, transparency log row

> | **Transparency log** | An optional, per-agora, independently-replicated append-only log of
> identity-free state commitments (roots, policy changes, revocation-set root), enabling any
> outside party to verify the machinery is run honestly without membership or identity access. |

### §2 — vocabulary, receipt ledger row

> | **Receipt ledger** | *Deferred (§10.2, proposal 0010.)* A per-credential hash-chained,
> append-only record of every action one credential takes within one agora, replayable by
> another Persora to confirm that history is complete, consistent, and non-forged. |

### §10 — opening paragraph and threat table

> The mechanisms so far protect against forged proofs and identity disclosure, but they do not,
> on their own, defend against a **rogue Skiora** that silently rewrites or forks its aggregate
> state. This section defines the layer that covers it.
>
> | Threat | Covered by |
> |---|---|
> | Rogue **Skiora** silently rewrites, rolls back, or forks aggregate state | §10.1 Per-agora transparency log |
> | Rogue **Persora** hides, denies, or forks its own action history | *Deferred* — §10.2–§10.4 (proposal 0010) |
>
> A rogue **Persora** — one that abuses its own valid credential or misrepresents its own
> history — is a separate trust boundary, addressed by the deferred sections below. Nothing
> here *prevents* a compromised client from taking a valid-but-unwanted action in the moment;
> that prevention belongs to hardware-bound authorization (§9.2) and structural server-side
> enforcement (§5.3). What this section adds is that a rogue operator cannot silently corrupt
> the shared state without public detection.

### §10.1 — "On the log", final bullet removed

The `pinned per-credential ledger heads (§10.3)` bullet is struck. The remaining four bullets
are unchanged.

### §10.1 — "Never on the log", sentence added

> **Never on the log:** nullifiers, attestation bundles, content, tags, individual membership
> commitments, or verification receipts tied to members. The line is aggregate, identity-free
> state commitments only; anything per-action or per-member stays off.
>
> The rule behind that list: **a value derived from a durable secret may be revealed to Skiora,
> but must never be published here.** Skiora sees such a value once and holds it under its own
> access controls; the log is public, permanent, replicated, and undeletable, so anything on it
> is available to every future adversary who ever obtains the key. A per-member value that is
> deterministic in a durable secret turns the log into a lookup table for that member's
> activity, retroactively and prospectively, the moment the secret leaks. This is why the
> pinned-heads bullet is struck rather than reworded, and the constraint any future
> reintroduction must satisfy.

### §10.2 — section heading and opening

> ### 10.2 Personal receipt ledger — deferred
>
> **Deferred to a later protocol version (proposal 0010).** The mechanism below is specified
> but not implemented, together with §10.3 and §10.4. Read the note at the end of §10.4 before
> reintroducing it: the ledger cannot be re-added without also settling how its pinning handle
> is derived, and the obvious derivations are not free.

### §10.3 — section heading and opening

> ### 10.3 Enforced logging and head-pinning — deferred
>
> **Deferred with §10.2 (proposal 0010).** As written this section overstates what it
> delivers: it claims one chain per credential, while §10.4 guarantees Skiora cannot identify a
> credential. See §10.4's closing note.

### §10.4 — section heading and opening

> ### 10.4 Keeping the ledger from becoming an activity graph — deferred
>
> **Deferred with §10.2 (proposal 0010).**

### §10.4 — new closing note

> **Reintroducing §10.2–§10.4 requires settling the pinning handle first.** The handle's
> derivation is unspecified in the text above, and it is load-bearing rather than incidental.
> Nothing in §10.3 limits a credential to one handle per epoch, so a member may register two and
> keep two chains without waiting for a boundary; across a boundary, rotation leaves Skiora with
> no last-recorded head to compare a new chain against. §10.3's non-forkable claim therefore
> holds at no scope as written.
>
> Wording cannot repair it. Verifying that two handles belong to one credential *is* the
> capability to link a credential's epochs, so Skiora cannot be granted the enforcement without
> the surveillance §10.4 exists to prevent. The two known repairs both carry real cost: deriving
> the handle from a durable secret makes the public log a permanent activity lookup for anyone
> who later obtains that secret (see §10.1's rule, and 0008 for why `sk_cred` is durable by
> necessity); consuming the previous head as a linear resource — proposal 0009 — works, but
> needs a second accumulator, a membership proof from every active member at every boundary, and
> leaves a member who loses chain state unable to act at all.
>
> A third direction is unexplored: a handle key that evolves one-way per epoch, deleted as it
> advances, so the published value is a function of nothing durable. It closes retroactive
> linkage without an accumulator, at the cost of proving the iteration in-circuit and of a
> recovery story for the seed.
>
> **The replay-witness mechanism needs more than a handle.** Settling the pinning question would
> still leave this section unimplementable, because it rests on two primitives the design does
> not provide. Selection needs public randomness no party can bias over an anonymous membership
> that is not simultaneously online — a beacon, not the commit-reveal of §8.1, which this section
> cites and which requires a known participant set on a live channel. Delivery needs a private
> message to a counterparty who is anonymous by construction, and §6.4's tags route to an agora
> by broadcast rather than to a member.
>
> Selection also discloses membership size. Any sampling of the membership has an observable
> response rate, and response rate against selection probability yields the count that §5.2
> withholds "at any point" — a property of sampling rather than of any particular construction,
> so it does not yield to a better one. And the full ledger goes to whoever is selected, which
> in the verifiably-random case is a member the holder did not choose and §1 allows to be an
> infiltrator.
>
> Finally, two corrections for whoever picks this up: recomputation does not resolve a
> disagreement between witnesses shown *different* ledgers — both recompute correctly, and the
> faulty party is the holder, not a witness — and a selected member who simply does not reply is
> indistinguishable from one never selected, so the check is unenforceable as described.

### §14 — capabilities summary

> - **Integrity and auditability**: An optional per-agora append-only transparency log lets any
> independent outside party verify the machinery is run honestly — non-equivocation,
> append-only integrity, and protocol conformance — without any membership or identity access.
> Detection of a rogue *client's* misbehaviour is deferred with §10.2 (proposal 0010).

### §16 and §210 — left unchanged

Descriptive mentions of ledgers in the per-agora isolation requirements (§16) are left in
place, following 0006's precedent. They point at sections that now declare their own deferred
status, they are correct if those sections return, and rewriting them would churn text that
becomes right again.

---

## Consequences

**Gained: nothing per-member touches the public log.** With pinned heads struck, §10.1 carries
only aggregate commitments. The entire risk class this proposal analyses stops existing rather
than being managed, and §10.1's exclusion list becomes trivially satisfiable instead of
something to police. An agora that opts into the log now publishes strictly less about its
members, which eases §3's existence-privacy tradeoff.

**Gained: 0009 closes.** Its unspent-head accumulator, spend nullifier, and unanswerable
recovery question all go with it.

**Gained: §10's remaining claim is true.** It currently asserts three composing layers, two of
which do not hold as specified.

**Paid: Nymora says nothing about whether a member's client behaved faithfully.** The guarantee
narrows to "a valid proof was produced by a valid member." A rogue client that vouches without
its user's knowledge corrupts the membership set, and that is a genuine group-level harm the
protocol no longer addresses directly — only through the nullifier sets Skiora already holds.

**Deferred, not decided:** whether a tamper-evident personal history is worth its cost when it
returns. That judgement wants a threat the design does not yet have evidence for — specifically
whether rogue *clients*, as distinct from rogue members and rogue operators, are a real
adversary for the deployments Nymora targets. Client integrity is also addressable outside the
protocol, by reproducible builds and platform attestation, which is where the compensating
mechanisms would not have to fight the unlinkability requirements.

## Note for implementers

**Task 1.7 is directly affected.** `SecureStorage` was accumulating requirements to hold ledger
chain state whose loss has protocol consequences. With §10.2 deferred it holds no growing chain
and has no state-loss failure mode, which is a simpler port and a smaller durability contract.

`Domain::LedgerEntry`, `Domain::LedgerHeadHandle`, and the `LedgerHash` digest newtype stay in
place, documented as reserved for a deferred mechanism. Nothing implements §10 yet, so there is
no code to remove; removing the tags would churn the registry for no gain, and a use is likely
if the sections return.

## Open questions

**Should credential self-audit be specified?** The capability described under "What is not
lost" exists implicitly — Skiora holds the nullifier sets, and a member can compute their own
nullifiers. Exposing it as a query needs its own analysis, and one detail is already clear:
it must authenticate on `sk_root`, not `sk_cred`. `sk_root` is hardware-held and
non-exportable, so a leaked `sk_cred` alone cannot unlock enumeration; gating on `sk_cred`
would hand an adversary precisely the capability §10.1's rule withholds. Coverage would extend
to vouching, policy approval, and migration — not to authorship, whose nullifier is epoch-keyed
and whose key is destroyed, and not to verification, which produces no nullifier. This wants a
proposal of its own rather than a paragraph in a deferral.

**Does the threat model have a durable-key adversary?** `threat-model.md` contains no mention
of `sk_cred`, durable key exposure, or key compromise. Three proposals in a row have now tripped
over the same gap: 0005 (retroactive attribution), 0008 (migration lineage linkage), and this
one. "An adversary obtains a durable credential secret and retains it" should be an enumerated
adversary in §15 rather than something each proposal rediscovers from scratch.
