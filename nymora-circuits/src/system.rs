// SPDX-License-Identifier: MIT OR Apache-2.0

//! The proving-system boundary: one trait, two statements, a single-bit outcome (§6.5).
//!
//! Everything above this trait — the action API in `nymora-proofs`, witness assembly and
//! state machines in `nymora-protocol` — is written against it and never learns which
//! backend produced a proof. The stub backend (this crate, `stub-prover` feature) is the
//! stand-in implementation; the real circuit replaces it behind the same trait, and
//! nothing above recompiles differently.

use crate::statement::{ChainPublicInputs, ChainWitness, MigrationPublicInputs, MigrationWitness};
use nymora_core::ProtocolError;

/// A proving system for the two Nymora statements.
///
/// `DEPTH` is the accumulator depth the statements quantify over. The network-wide value
/// is [`PROTOCOL_DEPTH`](crate::PROTOCOL_DEPTH) — a per-agora depth would be a per-agora
/// proof shape, the §6.5 fingerprinting vector; proposal 0030 fixed the scope and 0032
/// the value — but the trait carries it generically so that tests exercise small trees.
///
/// # Soundness at both ends
///
/// [`prove`](ProofSystem::prove) must refuse a witness that does not satisfy the
/// statement against the given public inputs — a real prover *cannot* produce such a
/// proof, so a backend that emitted one anyway would let every caller above build on an
/// assertion no circuit could make (the semantic honesty rule of the stub). The refusal
/// is [`ProtocolError::Malformed`]: an unsatisfiable witness is a property of the
/// caller's own inputs, and retrying cannot succeed.
///
/// # Verification binds the public inputs
///
/// [`verify`](ProofSystem::verify) returns its single bit for exactly the supplied public
/// inputs. A proof presented against *any* altered input — another message hash, another
/// epoch's roots, another agora, a different claimed nullifier — must fail: the binding
/// §6.5 gets from the Fiat–Shamir transcript is part of this contract, however a backend
/// achieves it.
///
/// # The output is one bit
///
/// No error detail on the verify side, deliberately: every proof in this design verifies
/// to `valid: true/false` and nothing else (§6.5), and a verifier that explained *why* a
/// proof failed would be an oracle over private witness structure.
pub trait ProofSystem<const DEPTH: usize> {
    /// An ordinary proof — the membership chain with one action clause (§9.1).
    type Proof: core::fmt::Debug;
    /// A migration proof (§9.3).
    type MigrationProof: core::fmt::Debug;

    /// Proves the membership chain with the action clause in `public`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] when the witness does not satisfy the statement
    /// against these public inputs — see the trait documentation.
    fn prove(
        &self,
        witness: &ChainWitness<'_, DEPTH>,
        public: &ChainPublicInputs<'_>,
    ) -> Result<Self::Proof, ProtocolError>;

    /// Whether `proof` establishes the chain for exactly these public inputs.
    fn verify(&self, proof: &Self::Proof, public: &ChainPublicInputs<'_>) -> bool;

    /// Proves the migration statement.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] when the witness does not satisfy the statement
    /// against these public inputs — see the trait documentation.
    fn prove_migration(
        &self,
        witness: &MigrationWitness<'_, DEPTH>,
        public: &MigrationPublicInputs,
    ) -> Result<Self::MigrationProof, ProtocolError>;

    /// Whether `proof` establishes the migration statement for exactly these public
    /// inputs.
    fn verify_migration(
        &self,
        proof: &Self::MigrationProof,
        public: &MigrationPublicInputs,
    ) -> bool;
}
