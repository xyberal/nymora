// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration (a): Merkle inclusion at a given depth, plus the nullifier derivation.
//!
//! This is the irreducible core of the membership statement (§9.1): a leaf opens under a
//! public root, and the action nullifier is derived from secrets the prover holds. Both
//! circuits here take the hash as the unit of cost, so the depth sensitivity this module
//! measures is what prices proposal 0030's deferred constant.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::UniformRand;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand::Rng;

use crate::poseidon::{hash_native, hash_var};

/// Native mirror: fold a leaf up a path of `depth` random siblings, returning the root.
pub struct PathInstance {
    pub leaf: Fr,
    pub siblings: Vec<Fr>,
    /// `true` means the running value is the right child at that level.
    pub directions: Vec<bool>,
    pub root: Fr,
}

pub fn random_path(cfg: &PoseidonConfig<Fr>, depth: usize, rng: &mut impl Rng) -> PathInstance {
    let leaf = Fr::rand(rng);
    let siblings: Vec<Fr> = (0..depth).map(|_| Fr::rand(rng)).collect();
    let directions: Vec<bool> = (0..depth).map(|_| rng.gen()).collect();
    let mut cur = leaf;
    for (sib, dir) in siblings.iter().zip(&directions) {
        cur = if *dir {
            hash_native(cfg, &[*sib, cur])
        } else {
            hash_native(cfg, &[cur, *sib])
        };
    }
    PathInstance {
        leaf,
        siblings,
        directions,
        root: cur,
    }
}

/// Constrain: the witnessed leaf opens under the public root.
pub fn inclusion_circuit(
    cs: ConstraintSystemRef<Fr>,
    cfg: &PoseidonConfig<Fr>,
    inst: &PathInstance,
) -> Result<FpVar<Fr>, SynthesisError> {
    let root = FpVar::new_input(cs.clone(), || Ok(inst.root))?;
    let leaf = FpVar::new_witness(cs.clone(), || Ok(inst.leaf))?;
    let mut cur = leaf.clone();
    for (sib, dir) in inst.siblings.iter().zip(&inst.directions) {
        let sib = FpVar::new_witness(cs.clone(), || Ok(*sib))?;
        let dir = Boolean::new_witness(cs.clone(), || Ok(*dir))?;
        let left = FpVar::conditionally_select(&dir, &sib, &cur)?;
        let right = FpVar::conditionally_select(&dir, &cur, &sib)?;
        cur = hash_var(cs.clone(), cfg, &[left, right])?;
    }
    cur.enforce_equal(&root)?;
    Ok(leaf)
}

/// Constrain: the public nullifier is `Poseidon(sk, message_hash, agora)` over witnessed
/// secrets — the action-binding clause of §6.5's statement.
pub fn nullifier_circuit(
    cs: ConstraintSystemRef<Fr>,
    cfg: &PoseidonConfig<Fr>,
    rng: &mut impl Rng,
) -> Result<(), SynthesisError> {
    let sk = Fr::rand(rng);
    let message_hash = Fr::rand(rng);
    let agora = Fr::rand(rng);
    let expected = hash_native(cfg, &[sk, message_hash, agora]);

    let nullifier = FpVar::new_input(cs.clone(), || Ok(expected))?;
    let sk = FpVar::new_witness(cs.clone(), || Ok(sk))?;
    let message_hash = FpVar::new_witness(cs.clone(), || Ok(message_hash))?;
    let agora = FpVar::new_witness(cs.clone(), || Ok(agora))?;
    let derived = hash_var(cs, cfg, &[sk, message_hash, agora])?;
    derived.enforce_equal(&nullifier)
}
