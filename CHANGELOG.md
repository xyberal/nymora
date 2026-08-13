# Changelog

All notable changes to the Nymora protocol library are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **The workspace carries its own secret scan.** CI gains a gitleaks job over the tree
  and the full history (a secret committed and later deleted still travels with every
  clone), configured by a new `.gitleaks.toml` whose allowlist is narrow and argued per
  entry: domain-separation tags are public protocol constants that must appear verbatim,
  and the conformance vectors exist to be published — their structural safety is that
  the test harness fails on any value the code does not compute from the inputs beside
  it.
- **The bulletin is a signed operator statement** (§9.1, §10.1, §11; proposal 0024,
  applied). The boundary bulletin is meant to be cached, relayed, and fetched through
  hosts a member does not trust, so it now carries its own authenticity: a canonical
  domain-tagged digest (new `nymora/v0/bulletin` domain; agora inside the signed bytes;
  every field framed; KAT pinned by independent computation) signed by a per-agora
  **operator statement key**, distinct from member material and from the log-head key.
  Members pin the key at admission and accept with the new feature-free
  `nymora-protocol::bulletin` module — signature plus strictly-advancing epoch, so a
  replayed pre-revocation bulletin cannot hold a verifier at stale roots — behind a new
  `provisional-signature` feature so member builds opt in without the operator role.
  Two validly signed divergent bulletins for one epoch are portable fork proof
  (`bulletin_equivocation`), extending §10.1's non-equivocation to log-less agoras;
  where a log exists the bulletin embeds the latest signed head, binding the
  member-gated artifact to the public one. §9.1's separate signed epoch-advance
  statement is subsumed — it was the degenerate bulletin. Dissolution now destroys the
  statement seed with the tag secret; `Executed::Revocation` boxes its bulletin.
- **The protocol state machines, both roles** — `nymora-protocol` now carries the whole
  server side of §4–§12 behind a new `operator` feature (`AgoraState`): single-founder
  bootstrap (§4.1), vouch sessions with nullifier distinctness and zero-field
  acknowledgements (§5.3), the quorum-decision machine serving policy changes, revocations,
  and dissolutions alike (§4.3, §11, §12; proposal 0021), challenge-bound verification
  access with consumed-on-presentation challenges (§7; proposal 0019), the migration
  acceptance path with boundary-staged spends (§9.3), revocation with an immediate forced
  boundary and full expiry cascade (§11), the opt-in transparency log with hash-chained
  signed heads and pure auditor functions (§10.1; proposal 0023), and terminal
  dissolution (§12). The feature is
  off by default so the member side stays allocation-free.
- Member-side live-authentication session machine (`live_auth`): a typestate over
  commit-reveal-derive (§8.1) — no path reveals before the roster is locked, duplicate
  commitments abort before any reveal, every opening is checked, and the same machine
  serves the in-person transports of §8.3 because the transport was never its business.
- Shared quorum-decision subjects (`decision`), ungated so approving members recompute
  them: `subject_id = Hash(kind_tag; agora, epoch, approving_class, content, nonce)` under
  three new domain tags — approvals for one decision kind are unforgeable as another, and
  divergent content under one identifier is caught by recomputation (proposal 0021).
- The boundary **bulletin**: `advance_epoch` returns the new epoch's roots, both exclusion
  sets whole, and the tag key — §11's broadcast mechanism generalized, which is also what
  breaks the bootstrap circularity a bare §7 gate would create and equips a member admitted
  at that very boundary. `ExclusionSet` gained `keys()` for exactly this whole-set service.
- Specification: proposals 0020 (roots are fixed per epoch; mutations land at boundaries),
  0021 (quorum decisions share one machine and one action), 0022 (the
  `credential_update_token` reduces to an admission acknowledgement), and 0023 (the
  transparency log is a hash chain with operator-signed heads, not a Merkle log), applied
  to §4.2, §4.3, §5.2, §5.3, §10.1, §11, and §12.
- Two-agora end-to-end lifecycle test: bootstrap through dissolution across two agoras on
  software keys and stub proofs, with the negative class as explicit assertions — no
  identifier, leaf, nullifier, pseudonym, tag, tag key, subject, or root correlates, and
  one agora's dissolution is invisible in the other. This is the phase-5 milestone: the
  whole protocol above the port boundary now runs.
- Known-answer pins (independently computed) for the two new canonical byte constructions:
  quorum subjects and the transparency log's chain step.
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
- Specification §9.1: the epoch-advance signal for agoras **without a transparency log** —
  the log is opt-in, so for an agora that declines it the authoritative signal is a signed
  epoch-advance statement served by Skiora on the member-gated `K_tag_e` broadcast channel
  (§6.4), with the local-clock maximum as backstop. Previously the only specified signals
  were the log and the clock, and the clock cannot carry an early advance — leaving §11's
  revocation-triggered immediate advance with no delivery path in exactly the
  existence-sensitive, log-declining deployments most likely to need prompt revocation.
- Specification §5.2: accumulator **exhaustion is terminal** for a policy class under the
  current protocol version — no further admission and, because migration consumes capacity,
  no routine device change either. No mechanism compacts, extends, or re-accumulates a tree;
  a re-accumulation ceremony would be a protocol-version event with its own proposal. The
  actionable consequence is stated where implementers previously had to infer it: size depth
  generously at creation, where the cost is logarithmic — depth 32 is roughly four billion
  leaves at thirty-two siblings per witness.
- The credential lifecycle of §9.1–§9.3 in `nymora-protocol` — its first real module, and,
  deliberately, the only crate that *drives* the two ports: creation (root authority first,
  durable slots second, unwound on failure so a partial credential cannot exist), epoch
  certification and rollover with the §9.1 destroy-on-epoch-end sweep, and planned
  migration on both devices. Sequencing lives in the engine because the ordering carries
  the security properties — a host asked to remember the epoch-end delete would eventually
  forget it. Randomness is a parameter, not a port, extending the treatment of time: fresh
  key material arrives as a consume-once `FreshEntropy` carrying §5.1's
  never-from-a-shared-seed rule, while the epoch keypair arrives as the host's signature
  scheme produced it, since that scheme is fixed with the proving system.
- The planned-migration handoff (§9.3) as a canonical encoding in `nymora-core` — the one
  wire format that carries a secret, since moving `sk_cred` between two devices the same
  member controls is its purpose. Version-led, length-framed, strictly decoded, with the
  transport obligations (local and deliberate, never through Skiora, buffer destroyed after
  decode) stated where an implementer will look. It deliberately omits the old credential's
  hardware binding: the migration certificate fully replaces it, and the successor presents
  its own.
- Three `SecureStorage` slots: `RootPublicKey` (a witness on every routine proof, and
  `KeyStore` deliberately has no read-it-back operation), `EpochCert(Epoch)` (the epoch
  public key and root signature a routine proof takes as private witnesses — stored rather
  than re-signed per proof, since signing may sit behind a user-presence prompt), and
  `EpochCursor` (the member's own record of the last epoch it certified, which is what lets
  epoch-end cleanup sweep without the enumeration the port refuses).
- The **provisional signature** in `nymora-crypto` (`provisional-signature` feature, on by
  default): Ed25519, standing in for the in-circuit signature scheme that is fixed with the
  proving system, exactly as the algebraic hash stands in for the circuit's hash. It exists
  because the stub prover must *publicly verify* both root certificates while holding only
  `pk_root` — the moment the software key store's keyed-hash stand-ins were documented to
  end at. `SoftwareKeyStore` now signs with it, deterministically from the same per-agora
  seeds; nothing pins its sizes, which move with the scheme.
- Live-authentication derivations (§8.1, §8.3) in `nymora-crypto`: the commit-reveal
  commitment, the jointly-derived session context (count absorbed, nonces sorted and
  framed, channel metadata last), and the SAS — byte-family, settled, with permanent
  vectors — plus the session pseudonym, which the circuit recomputes and is therefore
  algebraic-family and provisional. Session sequencing (commit-before-reveal, duplicate
  abort, late-joiner refresh) is deliberately absent here: it is a phase-5 state machine.
- The keyed exclusion sets of §9.1's currency clauses in `nymora-accumulator` — the
  revocation set (§11) and the migration-spend set (§9.3) — as a provisional sparse Merkle
  tree over the key's 256 bits with **non-membership witnesses**: a keyed root, an
  `AbsenceWitness`, and allocation-free, constant-time-in-the-path `verifies_absent`. The
  real structure is fixed with the proving system; what is pinned is the shape the
  protocol builds against, which is why the module sits behind the same provisional
  feature as the positional witness. Construction (`ExclusionSet`: insert, root, witness
  serving) is operator-side behind `build`, idempotent, permanent, and — carrying §5.2's
  discipline over — reports no occupancy, since a revocation count is information about
  members. Two new permanent domain tags separate its leaves and nodes from the positional
  accumulator's, so a membership path and a non-membership path can never be confused.
- The two proof statements as types, and the proving-system boundary, in `nymora-circuits`:
  §9.1's membership chain as one witness set with the action-specific final clause as a
  variant — authorship, vouch, policy approval, live auth, verification access — so a new
  kind of proof is a new variant rather than a new shape (§6.5 made structural); the
  migration statement (§9.3) deliberately beside it, not inside it, since a migration
  proof never leaves the agora. The `ProofSystem` trait returns §6.5's single bit, must
  refuse an unsatisfiable witness at prove time, and binds every proof to exactly its
  public inputs. Behind it, for now: the **stub prover** (`stub-prover` feature, on by
  default) — a plaintext evaluator of every clause, honest in semantics (nothing is
  asserted a circuit could not prove) and loudly dishonest in disclosure (its proofs
  contain the witness, must never leave a test process, and redact themselves in `Debug`).
  Its public-input binding is an explicit transcript digest, because re-evaluation alone
  would accept an action swap the Fiat–Shamir binding must refuse.
- The per-action proof surface in `nymora-proofs`: prove and verify entry points for all
  six actions, deriving each nullifier and pseudonym from the witness rather than
  accepting one — a caller can no longer mismatch a final clause and its derivation — and
  `EpochRoots` carrying the current epoch's three roots as one value so roots from two
  epochs cannot be mixed invisibly (§9.1).
- Witness assembly in `nymora-protocol` (`load_acting_material`): everything the phase-3
  lifecycle stored, loaded back as the chain witness a proof consumes. A swept epoch
  refuses here as `Unavailable` — §9.1's destroy-on-epoch-end becoming an inability to
  prove is the forward-secrecy bound made executable, and the cross-phase tests observe it
  end to end. The Merkle and absence witnesses stay parameters: they come from Skiora,
  and fetching is I/O, which is the host's.

### Changed
- **Content gating is deferred; the broadcast carries the keys** (§6.4, §7, §11, §12;
  proposal 0029). Three sections leaned on an attribute-based-encryption content-gating
  mechanism that no section defines and nothing implements: §6.4 named it as `K_tag_e`'s
  distribution channel while §11 named the boundary broadcast, and §12 destroyed an "ABE
  master key" at dissolution. The spec now agrees with itself and the code: the boundary
  broadcast is the distribution channel for every per-epoch member key, revocation is
  the delivery cut, and tier-gated content encryption is a later-version mechanism —
  with the deferral's cost stated plainly (this version gates standing and services, not
  content at rest) and the reintroduction constrained to compose with the broadcast,
  per-agora isolation, and §15's shared-secret blast radius. Two doc comments updated;
  no mechanism changed.
- **Numeric credential attributes are deferred** (§2, §5.1, §9.3, §15; proposal 0028).
  The specification told two stories about what a credential is: §5.1's attribute-bearing
  BBS+-style object (hidden `tier`, `vouch_count`, `tenure_start`) and §9.1's leaf
  commitment over key material, which is what the circuit, the vectors, and the whole
  implementation are built on. §5.1 now states the leaf as the credential, tier as class
  membership (a class-membership proof discloses no number to compare, so
  non-comparability holds structurally), and numeric attributes as deferred to a later
  protocol version — a protocol-version event, since attributes change the leaf the one
  standardized circuit opens. §9.3's carry-over states what migration actually preserves
  (class and `sk_cred` lineage); §15's costs read "standing" rather than enumerating
  attributes this version does not have. No mechanism changed: the implementation
  already was the deferred version.
- **Pre-publication re-read, editorial pass**: the workspace `README` now states the
  actual status — complete protocol logic on a stub prover and provisional primitives,
  nothing deployable — and its crate table describes what the crates contain rather than
  what the roadmap promises (no BBS+, no Poseidon, no real circuit yet); `tests/README`
  points to where the conformance vectors actually live instead of calling itself a
  scaffold placeholder. Spec illustrations caught up with normative text: §5.2's
  `root-at-epoch` snippet now matches §7's shape, §9.3's wire block carries the
  `agora_id` the leaf commitment has always included (§9.1, proposal 0013), §11 states
  that the exclusion sets travel in the boundary broadcast with no separate lookup
  (proposal 0025's rule, stated for the sets), §10.1's auditor conformance check claims
  only what is decidable from the log artifact, and §14's dissolution bullet carries
  §4.4's not-yet-implemented caveat. Doc comments corrected in place: the self-
  corroboration guarantee is qualified to same-epoch (the key dies with its epoch),
  `Domain::TagRouting` is marked reserved-and-deliberately-unused, the migration
  statement's shape argument cites proposal 0001 rather than a §6.5 rule the spec does
  not contain, the quorum content encoding is described as it is (per-field framing),
  and the secret types and handoff format state plainly that decode-path stack residue
  is the host's to wipe. No mechanism changed.
- **Current roots and inclusion witnesses are member-only** (§5.2, §11, §15; proposal
  0025). The phase-5 `current_roots` and `witness` endpoints were ungated, and the
  pre-publication read-through showed each negated a stated guarantee: a served current
  root plus the public verifier is an affiliation oracle for external bundles (the
  confirmation §6.4 exists to prevent, and the negation of §7's no-path-to-a-root claim),
  and witness-by-position answers occupancy probes (§5.2 withholds occupancy at any
  point). `current_roots` is deleted — the boundary bulletin is a member's only source
  for current roots, with `current_bulletin` added for host re-delivery and for equipping
  the founder at genesis — and the witness service now requires the epoch's
  **witness-service key** (`K_witness_e`, new domain `nymora/v0/witness/key`), carried in
  the bulletin with exactly the tag key's lifecycle. Keyed rather than proof-gated
  because proof-gating has an unreachable base case: a member's first proof of an epoch
  requires the witness itself. A wrong or stale key refuses identically over occupied and
  empty positions.
- Specification editorial pass ahead of publication: the illustrative wire snippets and
  the §4 diagram caught up with the proposals already applied around them — §4.1 no longer
  shows `credentials/init` returning a credential id and tier (the founder's leaf is placed
  at creation, the one direct insertion), §4.3 says `execute` over a derived subject rather
  than `activate` over an issued id, §7's access flow shows the challenge-bound shapes of
  proposal 0019 instead of the struck `proof_token`/`grant_token`, and §12's dissolution
  snippet is the §4.3 quorum machine it always was in prose (proposal 0021), with the
  destruction proof conditioned on §4.4. §4.4 now carries a specified-not-yet-implemented
  status note. Spec text affected by proposed-but-unapplied proposals now points to them
  (0001 at §9.2, 0024 at §9.1 and §11). `spec/README.md` describes `proposals/` as the
  decision record it is, with the status conventions spelled out.
- §11's whole-set service is now honest in the accumulator: the exclusion-set module no
  longer claims Skiora serves absence witnesses — a witness request naming a key would
  disclose exactly which credential is about to act, so members receive the sets whole
  (`ExclusionSet::keys`) and compute witnesses locally, as §11 always specified.
- Specification §5.3, §4.2: `finalize` returns `{ threshold_met, position,
  active_from_epoch }` — the `credential_update_token` is struck as a concept (proposal
  0022), and a failed finalize consumes the session.
- Specification §5.2: every root a proof is checked against is fixed for the whole epoch;
  admissions and spends land at boundaries, and a member admitted in epoch *e* first acts
  at *e + 1* (proposal 0020).
- Specification §4.3, §11, §12: revocation and dissolution are decided through §4.3's
  quorum machine with domain-separated, content-binding subject identifiers, and the
  governance quorum is itself agora policy (proposal 0021). §11 additionally specifies the
  boundary broadcast's full contents and why the sets travel whole.
- Specification §9.1: the membership chain states `pk_epoch is the public counterpart of
  sk_epoch` explicitly. Implementing the statement types surfaced that the clause was
  implied but absent — and without it the certificate constrains nothing about the key the
  nullifier derives from, making certification decorative for exactly the operations it
  exists to authorize.
- Specification §7: the verification-access proof statement is now specified — the full
  chain with a final clause binding a Skiora-issued, single-use challenge, and **no
  nullifier**, since access is not a count and replay is closed by challenge freshness
  (proposal 0019).
- The migration handoff carries the predecessor's `r_root` and `pk_root` instead of the
  consumed leaf. The successor is the prover — it submits `credentials/migrate` — and the
  migration statement opens the old leaf, which takes the opening material; the leaf
  itself is now derived from what the handoff carries, since a derived value cannot
  disagree with the values it derives from. Layout changed in place with
  `HANDOFF_VERSION` unchanged: nothing has shipped, and the version byte exists for
  deployed formats, not drafts. `authorize_migration` no longer needs the provisional
  hash and loses its feature gate.
- Specification §8.1: the live-auth pseudonym is
  `Hash(sk_epoch, context_id, agora_id)` under its registered domain tag — the key pinned
  to the epoch tier by 0005's window rule (a durable key would permit retroactive *presence*
  attribution for every recorded session), and the agora absorbed by construction rather
  than resting on every participant's randomness being correct (proposal 0018). The
  informal `"conversation"` literal is subsumed by the domain tag.
- Specification §8.3: `short_digest` is pinned — the byte-family hash of `context_id`
  under the SAS domain tag, truncated to its first 4 bytes. Participants compare the value
  across devices, so the digest and truncation are protocol; only the rendering (digits,
  words, emoji) is the client's.
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
- `KeyStore` reports a too-small caller buffer as `ProtocolError::Malformed` rather than
  `Unavailable`, matching `SecureStorage` and the bundle codec: buffer size is a property of
  the caller's own input, not an operational condition, and retrying it cannot succeed —
  which is what `Unavailable` would imply.

### Fixed
- **The quorum floor is one** (§4.3, §5.3; proposal 0027). `Decision::Policy` accepted a
  zero governance quorum and a zero admission threshold, and execution compares approvals
  with `>=` — so one member-approved zero would have made every subsequent execution
  vacuously approved, handing the operator alone the power to raise and execute
  revocations and dissolution, and a zero threshold admitted on no attestation. Zero now
  refuses as `Malformed` at both entry points: `propose` (a proposal that could never
  validly execute must not open and gather approvals) and `create` (a zero-threshold
  founding is self-inconsistent). Both are pinned by tests; the legitimate §4.1 founding
  minimum — quorum 1, threshold 1 — is unchanged.
- **A leaf lands at most once per class** (§5.2; proposal 0026). The staged-admission
  list had no duplicate check, so two vouch sessions racing for one candidate could both
  finalize and land the same commitment twice — burning terminal capacity (§5.2) and
  silently overwriting position bookkeeping, though minting no second vote (counted
  nullifiers derive from `sk_cred` and are leaf-independent). `stage_admission` is now
  the choke point: it refuses a leaf the class already holds, landed or staged.
  Migration acceptance also staged the spend *before* the admission, so a verified
  migration whose staging then refused (a full class suffices) consumed the old leaf
  while admitting no successor — the full lost-device price for a refusal. The admission
  now stages first; a refusal costs nothing. Both pinned by tests: the second finalize
  refuses and exactly one seat lands; a migration into a full class broadcasts no spend
  and the predecessor keeps acting.
- `Witness` no longer derives `Debug`: the derived form printed the member's index — their
  position in the membership set, which the crate's own `Node` type already refuses to log
  by habit — plus every sibling on the path. The hand-written form renders only the depth,
  which is a published property of the agora.
- `agora_id::derive` debug-guards ceremony plausibility the way it already guarded the
  founding key: a threshold ceremony claiming fewer than one signer or more signers than
  parties is a caller bug, and the identifier it derives is permanent, so it is refused in
  debug builds rather than committed to and shared out-of-band.
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
