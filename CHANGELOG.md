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

### Changed
- Corroboration (§6.3) is **deferred** to a later protocol version; the external bundle
  (§6.6) carries no `corroborations` array. The section remains specified, with a note that
  reintroducing it reopens the nullifier decision below — it is not an isolated feature
  (proposal 0006).

### Added
- Specification §9.1: epoch length is a per-agora policy, default 7 days, bounded to
  [24 hours, 30 days] (proposal 0007).
- Specification §9.1, §11: an epoch may be advanced early, and revocation advances it
  immediately. §11 now states the revocation asymmetry it closes — write capability ends at
  once, while read capability would otherwise persist until the next tag-key broadcast, which
  had silently capped the "prompt revocation" §11 relies on (proposal 0007).

### Fixed
- Specification §9.1: destroying an epoch key is triggered by the epoch **ending**, not by a
  successor being certified. Certification happens when a member next acts, so under the
  previous wording an inactive member never completed a rollover and never deleted — making
  the forward-secrecy window their activity gap rather than one epoch. A member with no
  current activity now holds no usable epoch key at all (proposal 0007).
- Specification §4.3, §5.3, §9.1, §9.3: every nullifier's key lifetime now matches the
  window it guards. A nullifier enforces "at most once" only for as long as its key lives,
  and the verifier has no other handle on identity — so policy proposals and vouch sessions
  now expire with the epoch that raised them, and the credential leaf, which has no bound,
  gains a durable `sk_migrate` committed in the leaf and carried across planned migration.
  Previously a member could approve a proposal once per epoch, satisfy a vouching threshold
  alone across rollovers, or spawn one successor credential per epoch — each inheriting the
  original's tenure, vouch count, and tier (proposal 0005).
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
