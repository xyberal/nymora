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

### Fixed
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
