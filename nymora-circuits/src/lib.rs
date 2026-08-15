// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-circuits` — the proof statements, the proving-system boundary, and (for now)
//! the stub prover.
//!
//! §6.5 requires **one standardized circuit** shared across every agora, so that proof
//! size and structure never vary — and this crate is where that circuit's statement lives
//! as types: the membership chain of §9.1 with its action-specific final clause
//! ([`statement`]), and the migration statement of §9.3 beside it. The [`ProofSystem`]
//! trait is the boundary everything above builds against; the real circuit arrives behind
//! it, and until then the [`stub`] backend evaluates the same statements in the clear.
//!
//! The statement types sit behind the provisional feature because every clause is
//! expressed over the stand-in algebraic hash and the provisional witness structures. The
//! stub additionally sits behind `stub-prover` and must never leave a test process — see
//! its module documentation for what it is honest about and what it is loudly not.

#![no_std]

/// The network-wide accumulator depth (§5.2; proposals 0030, 0032).
///
/// One value for every class in every agora, because the membership path lives inside
/// the one standardized circuit and its length is part of the proof shape §6.5 keeps
/// uniform. This constant binds deployments and the real circuit; the `DEPTH` const
/// generics running through the crates stay, so tests and conformance vectors continue
/// to exercise the algebra on small trees.
pub const PROTOCOL_DEPTH: usize = 32;

#[cfg(feature = "provisional-algebraic-hash")]
pub mod statement;
#[cfg(feature = "stub-prover")]
pub mod stub;
#[cfg(feature = "provisional-algebraic-hash")]
pub mod system;

#[cfg(feature = "provisional-algebraic-hash")]
pub use statement::{
    Action, ChainPublicInputs, ChainWitness, MigrationPublicInputs, MigrationWitness,
};
#[cfg(feature = "stub-prover")]
pub use stub::{MigrationStubProof, StubProof, StubProver};
#[cfg(feature = "provisional-algebraic-hash")]
pub use system::ProofSystem;

#[cfg(test)]
extern crate std;
