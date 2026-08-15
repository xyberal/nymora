// SPDX-License-Identifier: MIT OR Apache-2.0

//! Constraint measurement for the decisions the specification defers to numbers.
//!
//! Three configurations, cumulative by design:
//!
//! - **(a)** Merkle inclusion at depth 32 plus the nullifier derivation — the
//!   irreducible core of the §9.1 membership statement;
//! - **(b)** (a) plus an embedded-curve Schnorr verification — the epoch-certificate
//!   check if proposal 0001 is applied;
//! - **(c)** (a) plus non-native P-256 ECDSA — the epoch-certificate check if the
//!   hardware key is verified in-circuit directly.
//!
//! Proposal 0001's decision rule reads the (c)-versus-(b) ratio; the Merkle depth table
//! prices the network-wide constant proposal 0030 defers. Counts are R1CS constraints
//! over the BN254 scalar field with the constraint-count optimization goal — the
//! platform-independent measure; ratios, not absolute numbers, carry the decision.
//!
//! Deterministic by construction (`ark_std::test_rng`): every run reproduces the
//! numbers in README.md. `MEASURE_SKIP_SAT=1` skips the satisfiability replay, which
//! only re-checks witness consistency and does not change any count.

mod ecdsa;
mod merkle;
mod poseidon;
mod schnorr;

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use ark_std::test_rng;

const CANONICAL_DEPTH: usize = 32;

fn measure(
    label: &str,
    check_sat: bool,
    f: impl FnOnce(ConstraintSystemRef<Fr>) -> Result<(), SynthesisError>,
) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    f(cs.clone()).expect("circuit construction");
    let n = cs.num_constraints();
    if check_sat && !cs.is_satisfied().expect("constraint evaluation") {
        panic!(
            "{label}: constraint system is unsatisfied at {:?}",
            cs.which_is_unsatisfied().expect("constraint evaluation")
        );
    }
    println!("  {label:<46} {n:>10}");
    n
}

fn main() {
    let check_sat = std::env::var("MEASURE_SKIP_SAT").is_err();
    let cfg = poseidon::config();
    let mut rng = test_rng();

    println!("constraint measurement — R1CS over the BN254 scalar field");
    println!("(counts optimized for constraints; satisfiability {})", {
        if check_sat {
            "checked"
        } else {
            "skipped"
        }
    });

    println!("\n== unit costs ==");
    measure("poseidon 2-to-1 hash", check_sat, |cs| {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let h = poseidon::hash_native(&cfg, &[a, b]);
        let h_in = FpVar::new_input(cs.clone(), || Ok(h))?;
        let a_v = FpVar::new_witness(cs.clone(), || Ok(a))?;
        let b_v = FpVar::new_witness(cs.clone(), || Ok(b))?;
        poseidon::hash_var(cs, &cfg, &[a_v, b_v])?.enforce_equal(&h_in)
    });
    measure(
        "one non-native mul (P-256 base over BN254)",
        check_sat,
        |cs| {
            use ark_secp256r1::Fq as FqP;
            let a = FqP::rand(&mut rng);
            let b = FqP::rand(&mut rng);
            let a_v = NonNativeFieldVar::<FqP, Fr>::new_witness(cs.clone(), || Ok(a))?;
            let b_v = NonNativeFieldVar::<FqP, Fr>::new_witness(cs, || Ok(b))?;
            (&a_v * &b_v).enforce_equal(&NonNativeFieldVar::constant(a * b))
        },
    );

    println!("\n== components ==");
    let merkle_32 = measure("merkle inclusion, depth 32", check_sat, |cs| {
        let inst = merkle::random_path(&cfg, CANONICAL_DEPTH, &mut rng);
        merkle::inclusion_circuit(cs, &cfg, &inst).map(|_| ())
    });
    let nullifier = measure("nullifier derivation", check_sat, |cs| {
        merkle::nullifier_circuit(cs, &cfg, &mut rng)
    });
    let schnorr = measure("embedded-curve schnorr verify", check_sat, |cs| {
        schnorr::verify_circuit(cs, &cfg, &mut rng)
    });
    println!("  non-native P-256 ECDSA verify, broken down:");
    let ecdsa = measure("non-native P-256 ECDSA verify", check_sat, |cs| {
        ecdsa::verify_circuit(cs, &mut rng)
    });

    println!("\n== configurations ==");
    let a = merkle_32 + nullifier;
    let b = a + schnorr;
    let c = a + ecdsa;
    println!("  (a) merkle-32 + nullifier                      {a:>10}");
    println!("  (b) (a) + embedded-curve signature             {b:>10}");
    println!("  (c) (a) + non-native P-256 ECDSA               {c:>10}");

    println!("\n== merkle depth sensitivity (proposal 0030) ==");
    for depth in [16usize, 20, 24, 28, 32, 40] {
        measure(
            &format!("merkle inclusion, depth {depth}"),
            check_sat,
            |cs| {
                let inst = merkle::random_path(&cfg, depth, &mut rng);
                merkle::inclusion_circuit(cs, &cfg, &inst).map(|_| ())
            },
        );
    }

    println!("\n== decision readout (proposal 0001) ==");
    println!("  signature increment (b) - (a)                  {schnorr:>10}");
    println!("  signature increment (c) - (a)                  {ecdsa:>10}");
    println!(
        "  increment ratio ((c)-(a)) / ((b)-(a))          {:>10.1}",
        ecdsa as f64 / schnorr as f64
    );
    println!(
        "  configuration ratio (c) / (b)                  {:>10.1}",
        c as f64 / b as f64
    );
    println!("  rule: an order of magnitude or more, measured with (c) favored, is conclusive.");
}
