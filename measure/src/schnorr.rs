// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration (b)'s increment: an embedded-curve Schnorr verification.
//!
//! Baby Jubjub is embedded in the BN254 scalar field, so both scalar multiplications run
//! on native field arithmetic and the challenge hash is the same Poseidon as everywhere
//! else. This is the shape the epoch certificate check (§9.1) takes if proposal 0001 is
//! applied and the in-circuit key is an embedded-curve key.
//!
//! The count is deliberately conservative (it *over*states (b)): the generator
//! multiplication uses the generic variable-base gadget, where a real circuit would use
//! fixed-base windows for `s·G`. Overcounting (b) only shrinks the (c)/(b) ratio the
//! decision rule looks at, so it cannot manufacture the conclusion.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ec::{CurveGroup, Group};
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::{EdwardsProjective, Fr as EdFr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand::Rng;

use crate::poseidon::{hash_native, hash_var};

/// Constrain: witnessed `(R, s)` verifies as a Schnorr signature under witnessed public
/// key `P` on a constant message: `s·G == R + c·P` with `c = Poseidon(R, P, m)`.
pub fn verify_circuit(
    cs: ConstraintSystemRef<Fr>,
    cfg: &PoseidonConfig<Fr>,
    rng: &mut impl Rng,
) -> Result<(), SynthesisError> {
    // Native signature over the same equation the circuit checks.
    let g = EdwardsProjective::generator();
    let d = EdFr::rand(rng);
    let p = g * d;
    let k = EdFr::rand(rng);
    let r = g * k;
    let msg = Fr::from(424242u64);

    let (ra, pa) = (r.into_affine(), p.into_affine());
    let c = hash_native(cfg, &[ra.x, ra.y, pa.x, pa.y, msg]);
    let c_scalar = EdFr::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le());
    let s = k + c_scalar * d;

    // The circuit.
    let g_var = EdwardsVar::new_constant(cs.clone(), g)?;
    let r_var = EdwardsVar::new_witness(cs.clone(), || Ok(r))?;
    let p_var = EdwardsVar::new_witness(cs.clone(), || Ok(p))?;
    let msg_var = FpVar::new_constant(cs.clone(), msg)?;

    let s_bits: Vec<Boolean<Fr>> = s
        .into_bigint()
        .to_bits_le()
        .into_iter()
        .take(EdFr::MODULUS_BIT_SIZE as usize)
        .map(|b| Boolean::new_witness(cs.clone(), || Ok(b)))
        .collect::<Result<_, _>>()?;

    let c_var = hash_var(
        cs,
        cfg,
        &[
            r_var.x.clone(),
            r_var.y.clone(),
            p_var.x.clone(),
            p_var.y.clone(),
            msg_var,
        ],
    )?;
    let c_bits = c_var.to_bits_le()?;

    let lhs = g_var.scalar_mul_le(s_bits.iter())?;
    let rhs = r_var + p_var.scalar_mul_le(c_bits.iter())?;
    lhs.enforce_equal(&rhs)
}
