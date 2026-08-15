// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration (c)'s increment: non-native P-256 ECDSA verification.
//!
//! Every choice here favors (c), so that a large count is conclusive rather than an
//! artifact of a weak implementation (a negative result in a weak configuration proves
//! nothing):
//!
//! - the message hash `z` is a public constant — no SHA-256 in circuit, though a real
//!   epoch certificate would need its bytes bound;
//! - the two scalar multiplications share their doublings (Straus/Shamir), the cheapest
//!   joint form without precomputation tables;
//! - point arithmetic uses incomplete affine formulas (3–4 non-native multiplications
//!   per operation), sound off the exceptional cases a random instance never hits —
//!   a production circuit would pay more for completeness;
//! - the `x(R') mod n = r` check exploits `n < p < 2n` for P-256: one multiplication
//!   proves `x − r ∈ {0, n}` instead of a general reduction.
//!
//! The one cost a real deployment could not avoid that is included: the public key is a
//! witness (it lives inside the credential chain, never in public inputs), so the curve
//! membership check is charged.
//!
//! The accumulator starts at a constant point `C` with the correction `2^len·C`
//! subtracted at the end — the standard trick to keep the incomplete formulas away from
//! the point at infinity.

use ark_bls12_381::Fr;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_secp256r1::{Affine, Config as P256, Fq as FqP, Fr as FrP, Projective};
use ark_std::rand::Rng;

type NNBase = NonNativeFieldVar<FqP, Fr>;
type NNScalar = NonNativeFieldVar<FrP, Fr>;

/// A P-256 point as two non-native base-field coordinates.
struct PointVar {
    x: NNBase,
    y: NNBase,
}

impl PointVar {
    fn witness(cs: ConstraintSystemRef<Fr>, p: &Affine) -> Result<Self, SynthesisError> {
        Ok(Self {
            x: NNBase::new_witness(cs.clone(), || Ok(p.x))?,
            y: NNBase::new_witness(cs, || Ok(p.y))?,
        })
    }

    /// Incomplete affine addition, verification-style: the result and the chord slope
    /// are witnessed, and the three curve relations are enforced by multiplication —
    /// no in-circuit inverse, and every constrained operand is freshly allocated
    /// (canonical), which both lowers the count and stays off the non-native gadget's
    /// fragile long-chain lazy-reduction path. Assumes `x1 != x2`.
    fn add(&self, other: &PointVar) -> Result<PointVar, SynthesisError> {
        let cs = self.x.cs().or(other.x.cs());
        let (x1, y1) = (self.x.value()?, self.y.value()?);
        let (x2, y2) = (other.x.value()?, other.y.value()?);
        let lam_v = (y2 - y1) * (x2 - x1).inverse().expect("distinct x");
        let x3_v = lam_v.square() - x1 - x2;
        let y3_v = lam_v * (x1 - x3_v) - y1;
        let lam = NNBase::new_witness(cs.clone(), || Ok(lam_v))?;
        let x3 = NNBase::new_witness(cs.clone(), || Ok(x3_v))?;
        let y3 = NNBase::new_witness(cs, || Ok(y3_v))?;

        // lam·(x2 − x1) = y2 − y1;  lam² = x1 + x2 + x3;  lam·(x1 − x3) = y1 + y3.
        (&lam * &(&other.x - &self.x)).enforce_equal(&(&other.y - &self.y))?;
        (&lam * &lam).enforce_equal(&(&(&self.x + &other.x) + &x3))?;
        (&lam * &(&self.x - &x3)).enforce_equal(&(&self.y + &y3))?;
        Ok(PointVar { x: x3, y: y3 })
    }

    /// Affine doubling, same verification style. Assumes `y != 0` (no small torsion on
    /// P-256 in practice).
    fn double(&self, a_var: &NNBase) -> Result<PointVar, SynthesisError> {
        let cs = self.x.cs();
        let (x1, y1) = (self.x.value()?, self.y.value()?);
        let a = <P256 as SWCurveConfig>::COEFF_A;
        let lam_v =
            (x1.square() + x1.square() + x1.square() + a) * y1.double().inverse().expect("y != 0");
        let x3_v = lam_v.square() - x1.double();
        let y3_v = lam_v * (x1 - x3_v) - y1;
        let lam = NNBase::new_witness(cs.clone(), || Ok(lam_v))?;
        let x3 = NNBase::new_witness(cs.clone(), || Ok(x3_v))?;
        let y3 = NNBase::new_witness(cs, || Ok(y3_v))?;

        // lam·2y = 3x² + a;  lam² = 2x + x3;  lam·(x − x3) = y + y3.
        let xx = &self.x * &self.x;
        (&lam * &self.y.double()?).enforce_equal(&(&(&xx.double()? + &xx) + a_var))?;
        (&lam * &lam).enforce_equal(&(&self.x.double()? + &x3))?;
        (&lam * &(&self.x - &x3)).enforce_equal(&(&self.y + &y3))?;
        Ok(PointVar { x: x3, y: y3 })
    }

    fn select(b: &Boolean<Fr>, t: &PointVar, f: &PointVar) -> Result<PointVar, SynthesisError> {
        Ok(PointVar {
            x: NNBase::conditionally_select(b, &t.x, &f.x)?,
            y: NNBase::conditionally_select(b, &t.y, &f.y)?,
        })
    }

    /// `y^2 = x^3 + ax + b` — charged because the key is a witness.
    fn enforce_on_curve(&self) -> Result<(), SynthesisError> {
        let yy = &self.y * &self.y;
        let xx = &self.x * &self.x;
        let xxx = &xx * &self.x;
        let ax = &NNBase::constant(<P256 as SWCurveConfig>::COEFF_A) * &self.x;
        let rhs = &(&xxx + &ax) + &NNBase::constant(<P256 as SWCurveConfig>::COEFF_B);
        yy.enforce_equal(&rhs)
    }
}

/// Constrain: a witnessed `(r, s)` verifies as an ECDSA signature over P-256 under a
/// witnessed public key, on a constant message hash.
pub fn verify_circuit(
    cs: ConstraintSystemRef<Fr>,
    rng: &mut impl Rng,
) -> Result<(), SynthesisError> {
    // A genuine native signature, so the whole circuit is satisfiable.
    let g = Projective::generator();
    let d = FrP::rand(rng);
    let q = g * d;
    let z = FrP::from(0x5eed_f00du64);
    let k = FrP::rand(rng);
    let big_r = (g * k).into_affine();
    let r_fq = big_r.x;
    let r_n = FrP::from_le_bytes_mod_order(&r_fq.into_bigint().to_bytes_le());
    let s = k.inverse().expect("k != 0") * (z + r_n * d);
    {
        let sinv = s.inverse().expect("s != 0");
        let check = (g * (z * sinv) + q * (r_n * sinv)).into_affine();
        assert_eq!(
            FrP::from_le_bytes_mod_order(&check.x.into_bigint().to_bytes_le()),
            r_n,
            "native ECDSA self-check"
        );
    }

    let mut prev = cs.num_constraints();
    let mark = |label: &str, cs: &ConstraintSystemRef<Fr>, prev: &mut usize| {
        let now = cs.num_constraints();
        println!("      ecdsa/{label:<30} {:>10}", now - *prev);
        *prev = now;
    };

    // Scalar side, mod n: u1 = z·s⁻¹, u2 = r·s⁻¹, with s⁻¹ witnessed and checked.
    let s_var = NNScalar::new_witness(cs.clone(), || Ok(s))?;
    let sinv_var = NNScalar::new_witness(cs.clone(), || Ok(s.inverse().expect("s != 0")))?;
    (&s_var * &sinv_var).enforce_equal(&NNScalar::one())?;
    let r_n_var = NNScalar::new_witness(cs.clone(), || Ok(r_n))?;
    let u1 = &sinv_var * &NNScalar::constant(z);
    let u2 = &sinv_var * &r_n_var;
    mark("scalars u1, u2 (mod n)", &cs, &mut prev);

    let u1_bits = u1.to_bits_le()?;
    let u2_bits = u2.to_bits_le()?;
    assert_eq!(u1_bits.len(), u2_bits.len());
    let len = u1_bits.len();
    mark("scalar bit decomposition", &cs, &mut prev);

    // Bind r across the two fields: its mod-n and mod-p witnesses agree bit for bit
    // (sound because r < n < p, up to the negligible x >= n case).
    let r_p_var = NNBase::new_witness(cs.clone(), || Ok(r_fq))?;
    let r_p_bits = r_p_var.to_bits_le()?;
    let r_n_bits = r_n_var.to_bits_le()?;
    assert_eq!(r_p_bits.len(), r_n_bits.len());
    for (a, b) in r_p_bits.iter().zip(&r_n_bits) {
        a.enforce_equal(b)?;
    }
    mark("cross-field bind of r", &cs, &mut prev);

    // The public key is inside the credential chain: witnessed, so curve membership
    // must be charged.
    let q_aff = q.into_affine();
    let q_var = PointVar::witness(cs.clone(), &q_aff)?;
    q_var.enforce_on_curve()?;
    mark("key witness + on-curve", &cs, &mut prev);

    // Straus joint double-and-add for u1·G + u2·Q, offset by C against infinity.
    // G and C are fixed, publicly known points, but they are allocated as witnesses:
    // ark 0.4's non-native constant/witness mixed arithmetic is the gadget's fragile
    // path, and the allocation overhead is a few hundred constraints against millions.
    let c_point = (g * FrP::from(0xC0FFEEu64)).into_affine();
    let g_var = PointVar::witness(cs.clone(), &g.into_affine())?;
    let a_var = NNBase::new_witness(cs.clone(), || Ok(<P256 as SWCurveConfig>::COEFF_A))?;
    let mut acc = PointVar::witness(cs.clone(), &c_point)?;
    for i in (0..len).rev() {
        acc = acc.double(&a_var)?;
        let with_g = acc.add(&g_var)?;
        acc = PointVar::select(&u1_bits[i], &with_g, &acc)?;
        let with_q = acc.add(&q_var)?;
        acc = PointVar::select(&u2_bits[i], &with_q, &acc)?;
    }
    mark("straus double-and-add", &cs, &mut prev);

    // Value-level cross-check against a native mirror of the same loop, so a witness
    // drift is reported as what it is rather than as an opaque unsatisfied constraint.
    let two_pow = FrP::from(2u64).pow([len as u64]);
    let sinv = s.inverse().expect("s != 0");
    let expected =
        (c_point.into_group() * two_pow + g * (z * sinv) + q * (r_n * sinv)).into_affine();
    assert_eq!(
        (acc.x.value()?, acc.y.value()?),
        (expected.x, expected.y),
        "straus accumulator drifted from the native mirror"
    );

    // Undo the offset, then check x(R') ≡ r (mod n) via x − r ∈ {0, n}.
    let k_corr = (c_point.into_group() * two_pow).into_affine();
    let neg_k = (-k_corr.into_group()).into_affine();
    let v = acc.add(&PointVar::witness(cs.clone(), &neg_k)?)?;
    let n_in_p = FqP::from_le_bytes_mod_order(&FrP::MODULUS.to_bytes_le());
    let d1 = &v.x - &r_p_var;
    let d2 = &d1 - &NNBase::constant(n_in_p);
    (&d1 * &d2).enforce_equal(&NNBase::zero())?;
    mark("offset removal + x-check", &cs, &mut prev);

    Ok(())
}
