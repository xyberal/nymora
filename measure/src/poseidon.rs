// SPDX-License-Identifier: MIT OR Apache-2.0

//! One Poseidon instance for every algebraic hash in the measurement.
//!
//! The counts, not the parameters, are the product here: any secure Poseidon over the
//! BN254 scalar field with t = 3 (rate 2), alpha = 5, 8 full and 57 partial rounds has
//! the same constraint shape, so the standard configuration stands in for whichever
//! instance the real circuit standardizes on.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub fn config() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(Fr::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
}

pub fn hash_native(cfg: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(cfg);
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn hash_var(
    cs: ConstraintSystemRef<Fr>,
    cfg: &PoseidonConfig<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, cfg);
    for x in inputs {
        sponge.absorb(x)?;
    }
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}
