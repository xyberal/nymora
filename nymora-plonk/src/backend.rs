// SPDX-License-Identifier: MIT OR Apache-2.0

//! The prover/verifier pair holding both statements' keys — the artifact that will
//! stand behind the `ProofSystem` boundary at swap time.
//!
//! # Two ways to obtain a reference string
//!
//! [`Backend::insecure_for_tests`] generates a deterministic, **insecure** local
//! string so tests and CI run offline and byte-stable; it must never ship and never
//! derive an artifact that does. Production keys derive from the inherited Filecoin
//! phase-1 string only ([`Backend::from_srs_reader`]), under the custody rule §6.5
//! states (proposal 0034).

use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::{optimal_k, prove, setup_pk, setup_vk, verify, MidnightPK, MidnightVK};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{
    chain::{ChainInstance, ChainRelation, ChainWitness},
    migration::{MigrationInstance, MigrationRelation, MigrationWitness},
};

/// Why proving was refused or a proof could not be produced.
#[derive(Debug)]
pub enum ProveError {
    /// The witness does not satisfy the statement against these public inputs —
    /// retrying cannot succeed (the `Malformed` class of the `ProofSystem` contract).
    Unsatisfiable,
    /// The backend failed for a reason other than the witness (an SRS/key mismatch,
    /// an internal synthesis error).
    Backend(midnight_proofs::plonk::Error),
}

/// The proving backend: the reference string and both statements' key pairs.
pub struct Backend<const DEPTH: usize> {
    srs: ParamsKZG<Bls12>,
    chain_vk: MidnightVK,
    chain_pk: MidnightPK<ChainRelation<DEPTH>>,
    migration_vk: MidnightVK,
    migration_pk: MidnightPK<MigrationRelation<DEPTH>>,
}

impl<const DEPTH: usize> Backend<DEPTH> {
    /// The rows (log2) the larger of the two statements needs.
    pub fn required_k() -> u32 {
        optimal_k(&ChainRelation::<DEPTH>).max(optimal_k(&MigrationRelation::<DEPTH>))
    }

    /// A backend over a deterministic, **insecure** local string. Test and CI use
    /// only — see the module documentation.
    pub fn insecure_for_tests(seed: u64) -> Self {
        let k = Self::required_k();
        let srs = ParamsKZG::<Bls12>::unsafe_setup(k, ChaCha20Rng::seed_from_u64(seed));
        Self::from_params(srs)
    }

    /// A backend over an externally supplied reference string (the inherited
    /// Filecoin excerpt, in production).
    pub fn from_params(srs: ParamsKZG<Bls12>) -> Self {
        let chain_vk = setup_vk(&srs, &ChainRelation::<DEPTH>);
        let chain_pk = setup_pk(&ChainRelation::<DEPTH>, &chain_vk);
        let migration_vk = setup_vk(&srs, &MigrationRelation::<DEPTH>);
        let migration_pk = setup_pk(&MigrationRelation::<DEPTH>, &migration_vk);
        Backend {
            srs,
            chain_vk,
            chain_pk,
            migration_vk,
            migration_pk,
        }
    }

    /// Proves the membership chain for exactly these public inputs.
    ///
    /// The witness is checked against the statement CPU-side first, so an
    /// unsatisfiable witness is refused as [`ProveError::Unsatisfiable`] rather than
    /// silently producing a proof that can never verify.
    pub fn prove_chain(
        &self,
        witness: &ChainWitness<DEPTH>,
        instance: &ChainInstance,
    ) -> Result<Vec<u8>, ProveError> {
        if !crate::satisfies_chain(witness, instance) {
            return Err(ProveError::Unsatisfiable);
        }
        let mut rng = ChaCha20Rng::from_entropy();
        prove::<ChainRelation<DEPTH>, blake2b_simd::State>(
            &self.srs,
            &self.chain_pk,
            &ChainRelation::<DEPTH>,
            instance,
            witness.clone(),
            &mut rng,
        )
        .map_err(ProveError::Backend)
    }

    /// Whether `proof` establishes the chain for exactly these public inputs.
    pub fn verify_chain(&self, proof: &[u8], instance: &ChainInstance) -> bool {
        verify::<ChainRelation<DEPTH>, blake2b_simd::State>(
            &self.srs.verifier_params(),
            &self.chain_vk,
            instance,
            None,
            proof,
        )
        .is_ok()
    }

    /// Proves the migration statement for exactly these public inputs.
    ///
    /// # Errors
    ///
    /// [`ProveError::Unsatisfiable`] when the witness does not satisfy the
    /// statement; [`ProveError::Backend`] otherwise.
    pub fn prove_migration(
        &self,
        witness: &MigrationWitness<DEPTH>,
        instance: &MigrationInstance,
    ) -> Result<Vec<u8>, ProveError> {
        if !crate::satisfies_migration(witness, instance) {
            return Err(ProveError::Unsatisfiable);
        }
        let mut rng = ChaCha20Rng::from_entropy();
        prove::<MigrationRelation<DEPTH>, blake2b_simd::State>(
            &self.srs,
            &self.migration_pk,
            &MigrationRelation::<DEPTH>,
            instance,
            witness.clone(),
            &mut rng,
        )
        .map_err(ProveError::Backend)
    }

    /// Whether `proof` establishes the migration statement for exactly these
    /// public inputs.
    pub fn verify_migration(&self, proof: &[u8], instance: &MigrationInstance) -> bool {
        verify::<MigrationRelation<DEPTH>, blake2b_simd::State>(
            &self.srs.verifier_params(),
            &self.migration_vk,
            instance,
            None,
            proof,
        )
        .is_ok()
    }
}
