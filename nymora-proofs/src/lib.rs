// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-proofs` — the per-action proof surface: one prove and one verify entry point
//! for each thing a member does (§5.3, §6.1, §7, §8.1, §4.3, §9.3).
//!
//! # Why a layer above the proving system
//!
//! [`ProofSystem`] is one trait over two statements, and using it raw leaves two mistakes
//! open that this crate closes by construction:
//!
//! - **A mismatched final clause.** The action variant and its derivation must agree —
//!   a vouch clause carrying an authorship-derived nullifier is a proof that will never
//!   verify, or worse, a caller deriving the nullifier itself may derive it under the
//!   wrong key or domain. Here the prove functions *derive* the action's output from the
//!   witness and return it; no caller ever assembles an [`Action`] by hand.
//! - **A verifier checking the wrong statement.** The verify functions reconstruct the
//!   same public inputs from the same named parameters, so prover and verifier cannot
//!   drift in what they believe the proof is about.
//!
//! Everything here is pure: no ports, no storage, no I/O. Loading the witness out of a
//! member's storage is `nymora-protocol`'s job — the crate that drives the ports.
//!
//! # The three roots travel together
//!
//! A verifier accepts a routine proof only against the current epoch's three roots
//! (§9.1). [`EpochRoots`] carries them as one value so a call site cannot mix the class
//! root of one epoch with the exclusion roots of another — the mistake would otherwise be
//! invisible until proofs started failing for honest members.

#![no_std]

#[cfg(feature = "provisional-algebraic-hash")]
mod action;

#[cfg(feature = "provisional-algebraic-hash")]
pub use action::{
    prove_authorship, prove_live_auth, prove_migration, prove_policy_approval,
    prove_verification_access, prove_vouch, verify_authorship, verify_live_auth, verify_migration,
    verify_policy_approval, verify_verification_access, verify_vouch, EpochRoots,
};

#[cfg(feature = "provisional-algebraic-hash")]
pub use nymora_circuits::{Action, ChainWitness, MigrationWitness, ProofSystem};

#[cfg(test)]
extern crate std;
