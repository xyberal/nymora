# Proposal 0016 — Standing is checked at the action, never the artifact

**Status:** **Proposed**
**Affects:** §11, §14
**Depends on:** 0015 (Proposed) — checking currency at action time is what makes this
removal safe; if 0015 is rejected, the replacement text below overstates what remains
**Corrects:** §11's specification of a private index from attestation nullifiers to
credential status, and the scope of §11's no-author-cooperation principle

---

## Problem

§11 specifies an internal endpoint answering, for any attestation nullifier, whether the
credential behind it is currently in good standing, and states that this "requires the
Skiora to maintain a private internal index from attestation-nullifiers to current
credential status." That index cannot exist, and the reasons stack.

### Skiora cannot build it

The attestation nullifier is `Hash(sk_epoch, message_hash, agora_id)` with `sk_epoch` and
`pk_epoch` private witnesses (§9.1). Skiora has no computational path from a nullifier to a
credential — §2.1 states this as a guarantee: Skiora "never learns which credential
produced any given proof." Building the index requires exactly that knowledge, per proof,
at ingestion time. The specification asks for the negation of its own core property.

And if Skiora somehow could: an index mapping every published attestation to a credential's
standing *is* the per-member activity graph — the artifact a compelled operator would be
made to disclose, and the thing §10.4's title says the design must never assemble.

### The author cannot answer it either

The tempting repair is voluntary cooperation: the author proves in zero knowledge that a
given nullifier is theirs and that they currently satisfy the exclusion checks. It fails on
key lifetime. Producing that proof requires the `sk_epoch` that derived the nullifier, and
§9.1 destroys each epoch key when its epoch ends — deliberately, because retroactive
unattributability of published content is a stated guarantee (§15, proposal 0011: "which is
why the published bundles remain unattributable"). A cooperative scheme would have to
mandate *retaining* old epoch keys, trading away the forward secrecy the destruction
exists to provide. Cooperation can cover at most the current epoch's content, and a
"current" answer obtainable only from cooperating authors reads silence as guilt —
punishing the offline, not the compromised.

So the query's answer is not merely unavailable to Skiora; it is information the design
guarantees **nobody** can compute once an epoch closes. §6.1 already states the underlying
identity: recognition and linkability are the same property viewed from two angles. A
reliable answer to "is this bundle's author revoked?" *is* the ability to link the bundle
to a credential. There is no protocol version in which this endpoint exists and §2.1 also
holds — which is why this proposal removes it as contradictory rather than deferring it
in the 0006/0010 pattern. Deferral promises a return; nothing here can return.

### The section forecloses its own escape, for a reason that no longer applies

§11 closes by arguing that status "must be something the group determines independently of
the author's cooperation," because a refresh-based mechanism would fail exactly when it
matters. That argument is about **revocation the mechanism**, and it is correct: a revoked
author has no incentive to refresh, and one who still could would make revocation
meaningless. Under 0015 the principle is satisfied where it belongs — every routine proof
establishes currency, with no author-supplied refresh anywhere. Applied to a
*per-attestation query*, the principle proves the query impossible rather than mandating
it: there is no author-independent answer (Skiora cannot build the index) and no
author-dependent one either (the keys are gone).

## Decision

Remove the endpoint and the index from §11. Standing — §11's claim 2 — is checked at the
one place it has an answer: **the moment a credential acts**, inside every routine proof
(§9.1, proposal 0015). No action by a revoked or superseded credential verifies. No query
answers standing per past attestation, and the absence is a guarantee, not a gap: it is
what a compelled operator cannot be made to disclose, the same structural move §3 makes by
having no registry to compel.

What a member *can* establish about older content is epoch-coarse, and requires no
endpoint at all — it is computable locally from material a member already holds under
0015: the tag resolves the bundle's epoch (§6.4), the attestation itself proves a
credential was valid at that epoch, and the revocation set — served whole to members
(0015) — shows how much has changed since. "Valid then; *k* revocations since; whether
this author is among them, unknowable to anyone" is the whole truth the design permits.

---

## Replacement text

### §11 — the endpoint block, the index paragraph, and the scoping paragraph (replaced)

The two-claims framing that opens the section is unchanged. The endpoint sketch, the
"requires the Skiora to maintain a private internal index" paragraph, and the
"Scoping, by explicit design decision" paragraph are replaced with:

> The second claim is checked where it has an answer: at the moment a credential acts.
> Every routine proof establishes currency against the current epoch's roots (§9.1), so no
> action by a revoked or superseded credential verifies. There is deliberately **no
> per-attestation standing query** — no interface answers "is the author of this bundle
> currently in good standing," because no party can answer it:
>
> - **Skiora cannot.** It never learns which credential produced a proof (§2.1), and an
>   index from attestation nullifiers to credentials would *be* that knowledge — the
>   per-member activity graph a compelled operator could be made to disclose. The index's
>   nonexistence is load-bearing in the same way the registry's is (§3): what does not
>   exist cannot be compelled.
> - **The author cannot.** Re-proving authorship of a past-epoch bundle requires that
>   epoch's `sk_epoch`, destroyed when the epoch ended (§9.1). Retroactive
>   unattributability of published content is a stated guarantee (§15), and recognition
>   and linkability are the same property viewed from two angles (§6.1) — an answerable
>   standing query would be that guarantee's negation.
>
> What a member can establish about older content is epoch-coarse and computed locally,
> from material they already hold: the tag resolves the bundle's epoch *e* (§6.4); the
> attestation proves a credential was valid at *e*; the revocation set (§9.1) shows how
> many revocations have occurred since. Members weighing older content should weigh it in
> exactly those terms — *valid then, k revocations since, the author's membership among
> them unknowable* — rather than treating attestation as a claim about the present.
>
> **External scoping is unchanged:** the group's attestation remains permanent and
> unconditional — "the group vouched for this at the time" — regardless of internal
> governance since. This mirrors the group-vs-individual reputation scoping in §6.2: the
> external world receives a coarse, permanent, group-level fact; internally, the finest
> claim available is the epoch-coarse one above.

### §11 — the author-cooperation paragraph (replaced)

> **Why revocation cannot depend on author cooperation:** it does not — currency is
> established inside every routine proof (§9.1), with no author-supplied refresh anywhere.
> That placement is forced, not stylistic: a revoked or compromised author has no
> incentive to cooperate, and a mechanism they could still satisfy would make revocation
> meaningless. The same reasoning is why the per-attestation query above is removed rather
> than answered by voluntary author proofs: cooperation could at most cover the current
> epoch's content, since older epoch keys no longer exist (§9.1), and an answer obtainable
> only from cooperating authors reads silence as guilt — punishing absence, not
> compromise.

### §14 — the Content bullet (replaced)

> - **Content**: Authored content carries unlinkable, message-bound attestations proving
>   "a real group member stands behind this" externally, while richer authorship and
>   reliability tracking remains a member-only concept — and standing is enforced at the
>   moment of every action (§9.1, §11) rather than being queryable per past attestation.

---

## Consequences

**Gained:** §11 stops specifying §2.1's negation. The contradiction was not decorative —
it sat in the section implementers read to build revocation, describing an index whose
construction would have required instrumenting exactly the linkage the rest of the system
is built to prevent.

**Gained:** the compelled-operator surface shrinks by one artifact. A Skiora subpoenaed for
"the revocation status of these attestations" has nothing to produce and no index whose
existence must be denied.

**Gained:** the no-author-cooperation principle survives, rescoped to what it was always
about, and is now true twice over — revocation enforcement never needed cooperation
(0015), and the standing query that would have needed it no longer exists.

**Paid:** members lose the feature as promised — a per-attestation "current | revoked"
answer for content they are re-reading. What remains is the epoch-coarse fact. This is a
real reduction in what §11 offered, and an unreal reduction in what it could deliver: the
promised feature was never buildable, so what is lost is a promise, not a capability. The
spec is now honest about the strongest claim available.

**Not addressed:** how the group identifies which leaf to revoke without identity — the
governance and detection question, still open (0015 carries the same note). Also
untouched: 0009/0010, and §11's early-advance and asymmetry mechanics, which 0015 covers.

## Note for implementers

Nothing in the workspace implements the endpoint, so applying this proposal changes
specification text only. `LocalReason::CredentialRevoked` in `nymora-core` is unaffected —
it exists for server-side checks that reject an *action* (§11's enforcement under 0015),
never for answering a query; under 0015 most such rejections will surface locally as
`ProofInvalid` instead, and whether the variant retains a distinct use is a question for
the protocol crate when it arrives, not for this proposal.
