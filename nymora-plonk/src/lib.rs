// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-plonk` — the real proving backend: both Nymora statements over Plonkish
//! KZG on BLS12-381 (proposals 0033, 0034).
//!
//! # What this crate is
//!
//! The §9.1 membership chain ([`chain`]) and the §9.3 migration statement
//! ([`migration`]) as circuits, over the pinned instances: the width-3 Poseidon of
//! §6.5, the EdDSA-over-Jubjub certificate equation of §9.1, and the gap-tree
//! exclusion structure ([`exclusion`]) that makes the currency clauses affordable.
//! [`backend::Backend`] holds the reference string and both key pairs, and refuses
//! unsatisfiable witnesses the way the `ProofSystem` contract requires.
//!
//! # Behind the boundary
//!
//! [`backend::Backend`] implements `nymora-circuits`' `ProofSystem` trait ([`system`]),
//! so the whole workspace drives these circuits through the same interface it drove
//! the stub through (proposal 0035). The workspace's own primitives are the CPU twins
//! of what the circuits constrain — same Poseidon instance, same certificate scheme,
//! same trees — and the parity suite in this crate pins the two implementations
//! against each other value for value.
//!
//! # Where the trust sits
//!
//! The proving stack is `midnight-zk` (implementation posture recorded in proposal
//! 0034, dated): the proofs layer descends from halo2 v0.3.0, the circuits layer is
//! unaudited, and this crate's per-clause negative tests and known-answer pins are
//! the mitigations 0034 mandates. Subgroup membership of witness points is
//! constrained by the point-assignment path itself (0034 open question 3: resolved —
//! the chip tracks and enforces it; the CPU-side types cannot even express an
//! off-subgroup point). The known-answer tests pin the Poseidon constants
//! transitively: any upstream instance change breaks them loudly.

pub mod backend;
pub mod chain;
pub mod domains;
mod evaluate;
pub mod exclusion;
mod gadgets;
pub mod migration;
pub mod primitives;
pub mod system;
pub mod tree;

pub use evaluate::{satisfies_chain, satisfies_migration};

/// The circuit field: the BLS12-381 scalar field (§6.5).
pub type F = midnight_curves::Fq;

/// The network-wide accumulator depth, owned by `nymora-circuits` (§5.2; proposals
/// 0030, 0032) — re-exported so the backend instantiates at the protocol's value.
pub use nymora_circuits::PROTOCOL_DEPTH;
