// SPDX-License-Identifier: MIT OR Apache-2.0

//! CPU-side twins of the in-circuit primitives: the pinned Poseidon instance and the
//! §9.1 certificate scheme.
//!
//! Everything here mirrors, value for value, what the circuits in [`crate::chain`] and
//! [`crate::migration`] constrain — the tests prove that correspondence end to end,
//! and the conformance vectors will pin it. The Poseidon instance is the one proposals
//! 0033/0034 fix (width 3, rate 2, α = 5, 8 full and 60 partial rounds, Grain-generated
//! constants); the known-answer tests carry its checksum so an upstream constants
//! change cannot slip past silently.

use ff::PrimeField;
use group::{Group, GroupEncoding};
use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};
use midnight_curves::{Fr as JubjubScalar, JubjubAffine, JubjubExtended, JubjubSubgroup};

use crate::{domains, F};

/// The pinned Poseidon hash over an arbitrary-length input (CPU side).
pub fn poseidon(inputs: &[F]) -> F {
    <PoseidonChip<F> as HashCPU<F, F>>::hash(inputs)
}

/// The number of bits of the exclusion sets' ordering domain: full-field keys are
/// truncated to this width before they order gaps, because the in-circuit comparison
/// is sound only below `F::NUM_BITS - 2` bits. A truncation collision can only cost
/// availability (a key unable to prove its own absence), never soundness: a present
/// key's exact truncation is what the set holds. See [`crate::exclusion`].
pub const KEY_BITS: u32 = 253;

/// Truncates a field element into the exclusion ordering domain (low `KEY_BITS` bits).
pub fn truncate_key(value: F) -> F {
    let bytes = value.to_repr();
    let mut le = [0u8; 32];
    le.copy_from_slice(bytes.as_ref());
    // Zero every bit at index >= KEY_BITS (little-endian bit order).
    for bit in KEY_BITS..256 {
        le[(bit / 8) as usize] &= !(1u8 << (bit % 8));
    }
    F::from_repr(le).expect("a 253-bit value is canonical")
}

/// The affine coordinates of a subgroup point, as circuit-field elements.
pub fn coords(point: &JubjubSubgroup) -> (F, F) {
    let extended: &JubjubExtended = point.into();
    let affine: JubjubAffine = extended.into();
    (affine.get_u(), affine.get_v())
}

/// A Jubjub scalar's canonical little-endian bytes, as the circuit hashes and
/// assigns them. The field element these bytes name is below the Jubjub group
/// order — the canonicity the circuit re-checks in-constraint, so one key has
/// exactly one hashable representation.
pub fn scalar_bytes(scalar: &JubjubScalar) -> [u8; 32] {
    scalar.to_bytes()
}

/// A Jubjub scalar's canonical representation as a circuit-field element (the value
/// the action derivation absorbs for `sk_epoch`).
pub fn scalar_as_field(scalar: &JubjubScalar) -> F {
    F::from_repr(scalar.to_bytes()).expect("the Jubjub order is below the field order")
}

/// An EdDSA signature over Jubjub with a Poseidon transcript, in the (R, S) form
/// §9.1 states: 32 bytes of compressed point, 32 bytes of scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The nonce commitment `R = k·G`.
    pub r: JubjubSubgroup,
    /// The response `S = k + e·sk`.
    pub s: JubjubScalar,
}

/// Derives the public counterpart of a signing key: `PK = sk·G`.
pub fn public_key(sk: &JubjubScalar) -> JubjubSubgroup {
    JubjubSubgroup::generator() * sk
}

/// The subgroup generator `G` the equations are stated over.
pub fn generator() -> JubjubSubgroup {
    JubjubSubgroup::generator()
}

/// The Jubjub group order as lowercase hex (no `0x`), for the in-circuit
/// canonicity bound — taken from the curve implementation, never hardcoded.
pub fn jubjub_order_hex() -> String {
    JubjubScalar::MODULUS.trim_start_matches("0x").to_string()
}

/// Reduces a field element into the Jubjub scalar field (the challenge reduction
/// §9.1 names: little-endian interpretation, then reduction).
fn reduce_to_scalar(value: F) -> JubjubScalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(value.to_repr().as_ref());
    JubjubScalar::from_bytes_wide(&wide)
}

/// Signs a payload field element under the §9.1 equation, with the deterministic
/// nonce `k = reduce(Poseidon(NONCE, sk, m))` — reproducible for vectors, immune to
/// nonce reuse, and invisible to the circuit.
pub fn sign(sk: &JubjubScalar, message: F) -> Signature {
    let k = reduce_to_scalar(poseidon(&[
        domains::tag(domains::NONCE),
        scalar_as_field(sk),
        message,
    ]));
    let r = JubjubSubgroup::generator() * k;
    let e = reduce_to_scalar(challenge(&r, &public_key(sk), message));
    Signature { r, s: k + e * sk }
}

/// The transcript challenge `e = Poseidon(R.x, R.y, PK.x, PK.y, m)` before reduction —
/// exactly the equation §9.1 pins, computed identically in and out of the circuit.
pub fn challenge(r: &JubjubSubgroup, pk: &JubjubSubgroup, message: F) -> F {
    let (rx, ry) = coords(r);
    let (px, py) = coords(pk);
    poseidon(&[rx, ry, px, py, message])
}

/// Verifies the §9.1 equation `S·G = R + e·PK` (CPU side).
pub fn verify(signature: &Signature, pk: &JubjubSubgroup, message: F) -> bool {
    let e = reduce_to_scalar(challenge(&signature.r, pk, message));
    JubjubSubgroup::generator() * signature.s == signature.r + pk * e
}

/// Encodes a signature in its 64-byte wire form: compressed `R`, then `S` — the
/// widths the provisional scheme already occupies (§9.1).
pub fn signature_bytes(signature: &Signature) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&signature.r.to_bytes());
    out[32..].copy_from_slice(&signature.s.to_bytes());
    out
}
