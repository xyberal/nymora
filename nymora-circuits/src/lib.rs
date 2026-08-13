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
