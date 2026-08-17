// SPDX-License-Identifier: MIT OR Apache-2.0

//! The field crossing: how protocol bytes become field elements (§6.5, proposal 0035).
//!
//! Every value the standardized circuit recomputes lives in the BLS12-381 scalar field.
//! The protocol stores and transmits 32-byte strings; this module is the one place the
//! two meet, and the rules here are normative — two implementations that disagree about
//! any of them derive different nullifiers from identical state.
//!
//! # The rules, in one place
//!
//! - **A 32-byte identifier enters by little-endian interpretation with bits 254 and
//!   255 cleared** ([`from_id`]): a 254-bit truncation, below the field order by
//!   construction. One rule for `agora_id`, `message_hash`, and the live-auth context.
//! - **A variable-length identifier is compressed by the byte family first**
//!   ([`from_context_bytes`]): SHA-256 under [`Domain::ActionContext`], then the same
//!   truncation. Framing lives in the byte family; the field never sees a length.
//! - **An epoch number enters as itself** — the u64, injected.
//! - **A field element leaves as its canonical 32-byte little-endian representation**
//!   ([`to_bytes`]). A non-canonical string does not name a value.
//! - **Secrets are minted below their moduli by truncation** ([`mint_secret`], and its
//!   Jubjub counterpart in [`crate::signature`]): what a key needs is unpredictability,
//!   which 254 uniform bits provide, and truncation makes the canonicity the circuit
//!   asserts (§9.1) true by construction — a minted key's canonical bytes are the bytes
//!   it was minted from.
//!
//! # Witness bytes decode by reduction
//!
//! [`from_witness_bytes`] is total: it interprets 32 bytes as an integer and reduces.
//! Canonical strings map to the value they name; non-canonical ones fold to *some*
//! deterministic element. That is deliberate, and safe: the values decoded this way are
//! witness material (accumulator siblings, witnessed keys) whose forgery is prevented
//! by preimage resistance, not by encoding injectivity — an adversary who controls the
//! bytes could as easily send the canonical form. Where canonicity itself is the
//! property — the epoch key, whose non-canonical twin would derive a second nullifier
//! stream — the statement checks it explicitly, and [`decode`] is the strict form.

use ff::PrimeField;
use nymora_core::{Domain, Epoch};

use crate::hash::ByteHasher;

/// One element of the proving field — the BLS12-381 scalar field (§6.5).
pub type F = bls12_381::Scalar;

/// A 32-byte identifier's field entry: little-endian, bits 254 and 255 cleared
/// (proposal 0035).
#[must_use]
pub fn from_id(bytes: &[u8; 32]) -> F {
    let mut le = *bytes;
    le[31] &= 0x3f;
    F::from_repr(le).expect("a 254-bit value is below the field order")
}

/// A variable-length identifier's field entry: byte-family compression under
/// [`Domain::ActionContext`], then the identifier rule (proposal 0035).
#[must_use]
pub fn from_context_bytes(identifier: &[u8]) -> F {
    from_id(
        &ByteHasher::new(Domain::ActionContext)
            .absorb(identifier)
            .finalize(),
    )
}

/// An epoch number's field entry: the u64, injected.
#[must_use]
pub fn from_epoch(epoch: Epoch) -> F {
    F::from(epoch.get())
}

/// The canonical wire form: 32 little-endian bytes.
#[must_use]
pub fn to_bytes(value: &F) -> [u8; 32] {
    value.to_repr()
}

/// Strict decoding: the value a canonical 32-byte string names, or `None`.
///
/// This is the check the circuit performs where canonicity is itself the property at
/// stake; see the module documentation for when to use [`from_witness_bytes`] instead.
#[must_use]
pub fn decode(bytes: &[u8; 32]) -> Option<F> {
    F::from_repr(*bytes).into()
}

/// Total decoding for witness material: little-endian interpretation, reduced.
///
/// Canonical strings map to themselves. See the module documentation for why the
/// non-injectivity is harmless where this is used.
#[must_use]
pub fn from_witness_bytes(bytes: &[u8; 32]) -> F {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    F::from_bytes_wide(&wide)
}

/// Mints a field-element secret from 32 bytes of fresh entropy: bits 254 and 255
/// cleared, giving canonical bytes for a uniformly sampled 254-bit value.
///
/// The entropy must come from the device's cryptographically secure random source and
/// be used once. Truncation rather than wide reduction is proposal 0035's deliberate
/// trade: no extra entropy material, auditable by eye, and canonical by construction.
#[must_use]
pub fn mint_secret(entropy: [u8; 32]) -> [u8; 32] {
    let mut bytes = entropy;
    bytes[31] &= 0x3f;
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_entry_is_deterministic_and_truncates() {
        let all_ones = [0xff; 32];
        let entered = from_id(&all_ones);
        // Round-trips as canonical bytes with the top two bits gone.
        let mut expected = all_ones;
        expected[31] = 0x3f;
        assert_eq!(to_bytes(&entered), expected);
        assert_eq!(from_id(&all_ones), from_id(&expected));
    }

    #[test]
    fn low_identifiers_enter_verbatim() {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        assert_eq!(from_id(&bytes), F::from(42u64));
        assert_eq!(to_bytes(&from_id(&bytes)), bytes);
    }

    #[test]
    fn context_compression_frames_its_input() {
        // The byte-family framing must reach the crossing: distinct identifiers that
        // concatenate identically must not collide.
        assert_ne!(from_context_bytes(b"ab"), from_context_bytes(b"a"));
        assert_eq!(from_context_bytes(b"x"), from_context_bytes(b"x"));
    }

    #[test]
    fn strict_decoding_rejects_what_reduction_folds() {
        // The field modulus itself: non-canonical (names no element), reduces to zero.
        let modulus: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
        ];
        assert_eq!(decode(&modulus), None);
        assert_eq!(from_witness_bytes(&modulus), F::from(0));

        let canonical = to_bytes(&F::from(7));
        assert_eq!(decode(&canonical), Some(F::from(7)));
        assert_eq!(from_witness_bytes(&canonical), F::from(7));
    }

    #[test]
    fn minted_secrets_are_canonical() {
        let minted = mint_secret([0xff; 32]);
        assert!(
            decode(&minted).is_some(),
            "a minted secret must be canonical"
        );
        assert_eq!(minted[31], 0x3f);
    }
}
