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
