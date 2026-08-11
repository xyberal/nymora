# Changelog

All notable changes to the Nymora protocol library are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial workspace scaffold: `nymora-core`, `nymora-crypto`, `nymora-accumulator`,
  `nymora-circuits`, `nymora-proofs`, `nymora-protocol`, `nymora-ports` (empty placeholders).
- Self-contained CI (format, lint, test, license-header check).
- Dual licensing under `MIT OR Apache-2.0`.
- Protocol specification under `spec/` (`nymora-protocol.md` §2–§14,
  `threat-model.md` §1 and §15), versioned alongside the implementation.
- `ARCHITECTURE.md` describing the pure-engine-plus-ports model and crate graph.
- Specification §16, Multi-Agora Membership, and a normative per-agora credential isolation
  requirement in §5.1 (proposal 0002).
- Canonical signed-payload encodings for the epoch certificate (§9.1) and the migration
  certificate (§9.3), in `nymora-core` alongside the bundle format. Both certificates are
  verified inside the standardized circuit, which makes the signed bytes wire format even
  though neither certificate ever travels: a backend framing them differently would produce
  proofs no other implementation can verify, or a per-backend proof shape — the §6.5
  fingerprinting vector. Each encoding leads with its domain tag, separating the two
  certificate kinds that share a signing key, and carries the `agora_id` inside the signed
  message, so the no-replay-across-agoras requirement (§16.1) holds by construction. The
  `KeyStore` port now takes the payload types and must sign exactly their canonical bytes;
  the software stand-in streams them through the same encoder rather than restating the
  layout.
- Threat model §1, §15: an adversary who **retains extracted key material** after losing access
  to the device is now enumerated. §1 listed device seizure but said nothing about what survives
  it, and two of a credential's three secrets cannot be hardware-held at all — a value the
  circuit recomputes must be supplied to it as a witness — so §9.2's protection covers `sk_root`
  and not `r_root` or `sk_cred`. The §15 entry states what such an adversary reaches
  (recomputing any vouching, policy, or migration nullifier, in either direction, for the life
  of the credential), what bounds it (those nullifiers are unpublished, `sk_cred` is per-agora,
  and content is epoch-keyed), and that escaping it costs a Path 2 revocation — the full
  lost-device penalty without a lost device. Three prior proposals rediscovered this from the
  consequence end (proposal 0011).
- Specification §5.2: accumulators are **append-only** — no mechanism withdraws a leaf, since
  migration consumes one by nullifier (§9.3), revocation keeps a separate set (§11), and
  dissolution freezes rather than empties (§12). Two consequences are now stated: presence in
  the accumulator does not by itself mean a credential is current, and depth must be sized for
  every credential an agora will ever issue rather than for its live membership, since
  consumption tracks device churn (proposal 0014).
- Specification §9.1: an epoch ends at whichever comes first — the transparency log
  publishing an advance, or the maximum interval elapsing on the local clock. Failing toward
  the earlier signal is deliberate, since a key recognised as expired late outlives its
  window irrecoverably while one destroyed early costs a single re-certification (proposal
  0008).
- Specification §9.1: epoch length is a per-agora policy, default 7 days, bounded to
  [24 hours, 30 days] (proposal 0007).
- Specification §9.1, §11: an epoch may be advanced early, and revocation advances it
  immediately. §11 now states the revocation asymmetry it closes — write capability ends at
  once, while read capability would otherwise persist until the next tag-key broadcast, which
  had silently capped the "prompt revocation" §11 relies on (proposal 0007).

### Changed
- Specification §9.1: the credential leaf commits to its agora —
  `Commit(pk_root, sk_cred, r_root, agora_id)`. §5.1 already listed commitments among the
  values that may not be derivable across agoras, and the construction did not comply; the
  property held only because §5.1 separately requires fresh key material per agora, which is
  a client behaving correctly rather than a construction making it so (proposal 0013).
- Corroboration (§6.3) is **deferred** to a later protocol version; the external bundle
  (§6.6) carries no `corroborations` array. The section remains specified, with a note that
  reintroducing it reopens the nullifier decision below — it is not an isolated feature
  (proposal 0006).
- The personal receipt ledger and its enforcement (§10.2–§10.4) are **deferred** to a later
  protocol version, and the pinned-heads bullet leaves the transparency log, which now
  carries only aggregate, identity-free commitments. The mechanism was contradictory as
  specified — §10.3's one-chain-per-credential enforcement requires exactly the credential
  identification §10.4 makes uncomputable — and two of its three legs cannot be implemented
  at all: a replay witness holds no verification key for any past-epoch entry, since
  `pk_epoch` is never published and epoch keys are destroyed at epoch end; and
  verifiably-random witness selection needs a randomness beacon and an anonymous unicast
  channel the design does not have, then leaks membership size, which §5.2 forbids at any
  point. §10.4's closing note records every obstacle plus the shape a viable reintroduction
  takes — write-time completeness via linear head registration (proposal 0009, closed as
  its prerequisite), self-verifying action artifacts instead of signatures, the member as
  verifier — so whoever reopens the ledger starts from what can exist (proposals 0009,
  0010).

### Fixed
- Specification §5.3: the vouch nullifier is **agora-scoped** —
  `Hash(sk_cred, session_id, agora_id)`. It was the only count-nullifier that did not absorb
  the agora, on the reasoning that a session identifier is already unique to the agora that
  issued it — but session identifiers are issued by Skiora, an adversary in this threat model,
  and two colluding Skioras can issue the same one. That left cross-agora distinctness resting
  on key material having been correctly generated fresh per agora, the assumption proposal
  0013 refused to rest on for commitments; the same defence-in-depth now holds for every
  nullifier by construction. §5.3 and §6.5 also now reference §9.1's canonical proof statement
  instead of restating pre-0008/0013 forms of it that had gone stale (proposal 0017).
- Specification §11, §14: the per-attestation revocation-status endpoint is **removed as
  contradictory**, not deferred. The private index it required — attestation nullifiers to
  credential standing — is the exact knowledge §2.1 guarantees Skiora never holds, and no
  cooperative substitute exists: re-proving authorship of a past-epoch bundle needs the
  epoch key §9.1 destroys, which is §15's retroactive-unattributability guarantee working
  as stated. Standing is checked where it has an answer — at the moment a credential acts
  (§9.1) — and what a member can establish about older content is epoch-coarse and locally
  computable: valid at its epoch, so-many revocations since, the author's membership among
  them unknowable to anyone. The no-author-cooperation principle is rescoped to what it was
  always about — revocation the mechanism, which needs no cooperation — rather than
  mandating a query that has no author-independent answer and no author-dependent one
  either (proposal 0016).
- Specification §5.2, §9.1, §9.3, §10.1, §11: every routine proof must establish
  **currency**, not only inclusion — the credential's leaf absent from the revocation set
  and its migration nullifier unspent, proven as non-membership against two per-epoch
  exclusion roots served whole to members. Under the append-only accumulator a revoked
  credential's leaf never leaves the tree, certification is purely local, and Skiora cannot
  tell whose proof it is checking, so revocation had silently stopped ending write
  capability — and a migrated-away device could author indefinitely, since authorship
  nullifiers derive from the epoch key and never collide with the successor's. The
  migration nullifier now also binds the leaf it consumes, `Hash(sk_cred, leaf, agora_id)`,
  as §9.1 already required: `sk_cred` is constant across a lineage, so the key-only
  derivation the code carried was spent once at the first migration, capping every
  credential at a single device change (proposal 0015).
- Specification §8.1: the jointly-derived session context is combined with a **hash over
  length-framed, canonically ordered contributions**, not XOR. XOR is its own inverse and
  nothing required commitments to be distinct, so a participant could copy another's
  commitment, replay its opening, and cancel that contribution — at n = 2 yielding a
  `context_id` of `Hash(0, channel_metadata)`, fully determined before the session began. That
  is exactly the precomputation the section claimed to prevent. The claim now holds against any
  coalition short of the whole session rather than against a single party, and §10.4's
  verifiably-random witness selection, which cites this primitive as unbiasable randomness,
  inherits the repair (proposal 0012).
- Specification §9.1: completed proposal 0008's application, which had left four claims
  standing that its own decision invalidated. The routine-proof statement still said vouching
  used `sk_epoch` and still carried authorship's nullifier formula, two paragraphs after the
  text saying otherwise — the block a circuit implementer transcribes. Its witness list omitted
  `sk_cred`, which the leaf commits to and which is required to open it. The `r_root` paragraph
  still named the two-argument leaf `Commit(pk_root, r_root)`, as did `Domain::Commitment` and
  the `Commitment` newtype in `nymora-core`. And the claim that a seized dormant device cannot
  recompute past nullifiers, true when 0007 wrote it, is now bounded to authorship: such a
  device still holds `sk_cred` and `r_root`, which reproduce every vouching, policy-approval,
  and migration nullifier the credential ever made.
- Specification §4.3, §5.3, §9.1, §9.3: every nullifier whose **count** must be correct now
  derives from a credential's durable `sk_cred`, committed in the leaf and carried across
  planned migration — vouching thresholds, policy approvals, and the migration nullifier
  consuming a leaf. Previously all three keyed on `sk_epoch`, which cannot support a count at
  all: certification is purely local, so a member can certify a second epoch key for the same
  epoch and produce two nullifiers for one action, and the verifier cannot detect it because
  `pk_epoch` is a private witness. A member could therefore satisfy an admission threshold
  alone, approve a proposal repeatedly, or spawn successor credentials without limit — each
  inheriting the original's tenure, vouch count, and tier.

  Authorship keeps `sk_epoch`: its objects are public, so a durable key there would let an
  adversary holding it recompute nullifiers over every published bundle and attribute a
  member's content retroactively. Policy proposals and vouch sessions still expire with the
  epoch that raised them, now for quorum freshness rather than for any property of the
  nullifier (proposals 0005 and 0008).
- Specification §9.1: destroying an epoch key is triggered by the epoch **ending**, not by a
  successor being certified. Certification happens when a member next acts, so under the
  previous wording an inactive member never completed a rollover and never deleted — making
  the forward-secrecy window their activity gap rather than one epoch. A member with no
  current activity now holds no usable epoch key at all (proposal 0007).
- Specification: the receipt ledger is scoped **per credential**, not per Persora (§2, §10.2,
  §14). The per-Persora reading would have disclosed a member's full cross-agora activity to
  a ledger replay witness (proposal 0002).
- Specification §9.1: epoch keys are **generated** fresh each epoch and certified, never
  derived — not from root material, and not by a ratchet from the previous epoch's key. The
  former "freshly derived" wording admitted readings that would have destroyed the
  forward-secrecy bound the section claims. Adds the corresponding requirement to destroy the
  previous epoch's key at rollover (proposal 0004).
- Specification §9.1/§9.2: the commitment opening value `r_root` is supplied as the
  membership witness on every routine proof and held in software; the `r_epoch` rotation it
  previously specified was unimplementable, since a one-way derivation cannot open the
  commitment formed with its input (proposal 0003).
