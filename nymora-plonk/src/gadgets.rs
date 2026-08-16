// SPDX-License-Identifier: MIT OR Apache-2.0

//! The in-circuit building blocks both statements share: the Merkle fold, the
//! exclusion (absence) clause, and the §9.1 certificate verification.
//!
//! Every function here constrains exactly what its CPU twin in [`crate::primitives`],
//! [`crate::tree`], or [`crate::exclusion`] computes — the statement tests prove that
//! correspondence, and the negative tests prove each clause actually binds.

use midnight_circuits::{
    ecc::native::AssignedScalarOfNativeCurve,
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, BinaryInstructions,
        ControlFlowInstructions, DecompositionInstructions, EccInstructions, EqualityInstructions,
        RangeCheckInstructions,
    },
    types::{AssignedBit, AssignedNative, AssignedNativePoint},
};
use midnight_curves::JubjubExtended as Jubjub;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::ZkStdLib;
use num_bigint::BigUint;

use crate::{
    domains,
    exclusion::AbsenceWitness,
    primitives::{Signature, KEY_BITS},
    tree::Path,
    F,
};

/// An assigned authentication path.
pub struct AssignedPath {
    /// The sibling at each level.
    pub siblings: Vec<AssignedNative<F>>,
    /// The direction bit at each level.
    pub bits: Vec<AssignedBit<F>>,
}

/// Assigns a path as private witnesses.
pub fn assign_path<const DEPTH: usize>(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    path: Value<Path<DEPTH>>,
) -> Result<AssignedPath, Error> {
    let siblings = std_lib.assign_many(layouter, &path.map(|p| p.siblings).transpose_array())?;
    let bits = std_lib.assign_many(layouter, &path.map(|p| p.bits).transpose_array())?;
    Ok(AssignedPath { siblings, bits })
}

/// Folds a leaf up an assigned path — the in-circuit twin of [`Path::root`].
pub fn merkle_root(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    leaf: &AssignedNative<F>,
    path: &AssignedPath,
) -> Result<AssignedNative<F>, Error> {
    let mut current = leaf.clone();
    for (sibling, bit) in path.siblings.iter().zip(path.bits.iter()) {
        let (left, right) = std_lib.cond_swap(layouter, bit, &current, sibling)?;
        current = std_lib.poseidon(layouter, &[left, right])?;
    }
    Ok(current)
}

/// Truncates a full-field element into the exclusion ordering domain — the
/// in-circuit twin of [`crate::primitives::truncate_key`]: canonical bit
/// decomposition, low [`KEY_BITS`] bits recomposed.
fn truncate_key(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    value: &AssignedNative<F>,
) -> Result<AssignedNative<F>, Error> {
    let bits = std_lib.assigned_to_le_bits(layouter, value, None, true)?;
    std_lib.assigned_from_le_bits(layouter, &bits[..KEY_BITS as usize])
}

/// Constrains `key` absent from the exclusion set under `root` (§9.1's currency
/// clauses): some gap `(low, high)` with `low < t(key) < high` sits under the root.
pub fn assert_absent<const DEPTH: usize>(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    key: &AssignedNative<F>,
    witness: Value<AbsenceWitness<DEPTH>>,
    root: &AssignedNative<F>,
) -> Result<(), Error> {
    let low: AssignedNative<F> = std_lib.assign(layouter, witness.clone().map(|w| w.low))?;
    let high: AssignedNative<F> = std_lib.assign(layouter, witness.clone().map(|w| w.high))?;
    let path = assign_path(std_lib, layouter, witness.map(|w| w.path))?;

    // The ordering domain: the key truncates into it, and the comparison bounds
    // every operand below 2^KEY_BITS — the witness bounds' range check included.
    let t = truncate_key(std_lib, layouter, key)?;
    let below = std_lib.lower_than(layouter, &low, &t, KEY_BITS)?;
    std_lib.assert_equal_to_fixed(layouter, &below, true)?;
    let above = std_lib.lower_than(layouter, &t, &high, KEY_BITS)?;
    std_lib.assert_equal_to_fixed(layouter, &above, true)?;

    let gap_tag = gap_tag(std_lib, layouter)?;
    let gap = std_lib.poseidon(layouter, &[gap_tag, low, high])?;
    let computed = merkle_root(std_lib, layouter, &gap, &path)?;
    std_lib.assert_equal(layouter, &computed, root)
}

/// The GAP domain tag as a fixed assigned element.
fn gap_tag(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
) -> Result<AssignedNative<F>, Error> {
    std_lib.assign_fixed(layouter, domains::tag(domains::GAP))
}

/// An assigned §9.1 certificate signature.
pub struct AssignedSignature {
    /// The nonce commitment `R`.
    pub r: AssignedNativePoint<Jubjub>,
    /// The response scalar `S`.
    pub s: AssignedScalarOfNativeCurve<Jubjub>,
}

/// Assigns a signature as private witnesses. The point assignment constrains `R`
/// onto Jubjub's prime-order subgroup — the subgroup-membership clause §9.1 makes
/// part of the statement.
pub fn assign_signature(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    signature: Value<Signature>,
) -> Result<AssignedSignature, Error> {
    let r = std_lib
        .jubjub()
        .assign(layouter, signature.map(|sig| sig.r))?;
    let s = std_lib
        .jubjub()
        .assign(layouter, signature.map(|sig| sig.s))?;
    Ok(AssignedSignature { r, s })
}

/// Verifies the §9.1 equation in-circuit: `e = Poseidon(R.x, R.y, PK.x, PK.y, m)`,
/// then `S·G = R + e·PK`.
pub fn verify_certificate(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    signature: AssignedSignature,
    pk: &AssignedNativePoint<Jubjub>,
    message: &AssignedNative<F>,
) -> Result<(), Error> {
    let jubjub = std_lib.jubjub();
    let (rx, ry) = (
        jubjub.x_coordinate(&signature.r),
        jubjub.y_coordinate(&signature.r),
    );
    let (px, py) = (jubjub.x_coordinate(pk), jubjub.y_coordinate(pk));
    let e_field = std_lib.poseidon(layouter, &[rx, ry, px, py, message.clone()])?;
    let e_bytes = std_lib.assigned_to_le_bytes(layouter, &e_field, None)?;
    let e = jubjub.scalar_from_le_bytes(layouter, &e_bytes)?;

    let generator = jubjub.assign_fixed(layouter, crate::primitives::generator())?;
    let s_g = jubjub.msm(layouter, &[signature.s], &[generator])?;
    let e_pk = jubjub.msm(layouter, &[e], std::slice::from_ref(pk))?;
    let r_plus_e_pk = EccInstructions::add(jubjub, layouter, &signature.r, &e_pk)?;
    jubjub.assert_equal(layouter, &s_g, &r_plus_e_pk)
}

/// Assigns a Jubjub scalar from its canonical 32 little-endian bytes, returning both
/// its scalar form (for curve arithmetic) and its field form (for hashing), with the
/// canonicity constraint `field(bytes) < r` that gives one key exactly one hashable
/// representation. Without that constraint, a non-canonical byte witness would
/// certify under the same public key while deriving a *different* nullifier —
/// several counts from one key, the exact failure the correspondence clause exists
/// to prevent.
pub fn assign_canonical_scalar(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    bytes: Value<[u8; 32]>,
) -> Result<(AssignedScalarOfNativeCurve<Jubjub>, AssignedNative<F>), Error> {
    let assigned_bytes = std_lib.assign_many(layouter, &bytes.transpose_array())?;
    let as_field = std_lib.assigned_from_le_bytes(layouter, &assigned_bytes)?;
    let order = BigUint::parse_bytes(crate::primitives::jubjub_order_hex().as_bytes(), 16)
        .expect("the curve's stated modulus is valid hex");
    std_lib.assert_lower_than_fixed(layouter, &as_field, &order)?;
    let as_scalar = std_lib
        .jubjub()
        .scalar_from_le_bytes(layouter, &assigned_bytes)?;
    Ok((as_scalar, as_field))
}

/// Constrains `tag` to the five action tags: `(tag)(tag-1)(tag-2)(tag-3)(tag-4) = 0`.
pub fn assert_action_tag(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    tag: &AssignedNative<F>,
) -> Result<(), Error> {
    let mut product = tag.clone();
    for shift in 1..=4u64 {
        let term = std_lib.add_constant(layouter, tag, -F::from(shift))?;
        product = std_lib.mul(layouter, &product, &term, None)?;
    }
    std_lib.assert_equal_to_fixed(layouter, &product, F::from(0))
}

/// The selector bits an action tag induces: whether the derivation key is the epoch
/// key (tags 0, 3), and whether the action derives nothing (tag 4).
pub fn action_selectors(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    tag: &AssignedNative<F>,
) -> Result<(AssignedBit<F>, AssignedBit<F>), Error> {
    let is_authorship =
        std_lib.is_equal_to_fixed(layouter, tag, F::from(domains::action_tag::AUTHORSHIP))?;
    let is_live_auth =
        std_lib.is_equal_to_fixed(layouter, tag, F::from(domains::action_tag::LIVE_AUTH))?;
    let uses_epoch_key = std_lib.or(layouter, &[is_authorship, is_live_auth])?;
    let derives_nothing =
        std_lib.is_equal_to_fixed(layouter, tag, F::from(domains::action_tag::VERIFICATION))?;
    Ok((uses_epoch_key, derives_nothing))
}
