// SPDX-License-Identifier: MIT OR Apache-2.0

//! The certificate scheme: EdDSA over Jubjub with a Poseidon transcript (§9.1;
//! proposals 0033, 0034, 0035).
//!
//! This is the scheme the standardized circuit verifies in-constraint, stated in §9.1
//! as an equation and implemented here as its CPU twin:
//!
//! ```text
//! PK = sk·G                keys: scalars of Jubjub's prime-order subgroup
//! R  = k·G                 nonce k derived deterministically from (sk, m)
//! e  = Poseidon(R.x, R.y, PK.x, PK.y, m)    reduced into the Jubjub scalar field
//! S  = k + e·sk
//! signature = (R, S)       32-byte compressed point ‖ 32-byte scalar
//! verify:  S·G = R + e·PK
//! ```
//!
//! # The message is one field element
//!
//! `m` is the certificate payload compressed by the pinned hash (proposal 0035) —
//! [`epoch_cert_message`] and [`migration_cert_message`] are the two compressions, and
//! they are wire format even though no certificate travels: the circuit recomputes `m`
//! from witness values, so signer and circuit must agree to the element.
//!
//! # The deterministic nonce is an obligation
//!
//! `k = reduce(Poseidon(NONCE, sk, m))` — costing the circuit nothing (the nonce is
//! signer-local), keeping vectors byte-reproducible, and foreclosing nonce reuse, which
//! for this equation would surrender `sk` outright.
//!
//! # Subgroup membership is checked at every decoding
//!
//! Jubjub's cofactor is 8, and §9.1 states the equation over the prime-order subgroup:
//! every compressed point decoded here — public keys and nonce commitments alike — is
//! refused unless it names a subgroup point, the same boundary the circuit enforces on
//! its witnessed points. A key that decodes to a curve point *off* the subgroup
//! verifies nothing and signs nothing.

use ff::PrimeField;
use group::{Group, GroupEncoding};
use jubjub::{Fr as JubjubScalar, SubgroupPoint};
use nymora_core::{field_domain, AgoraId, Epoch};

use crate::field::{self, F};
use crate::poseidon;

/// Width of a secret signing key, in bytes: a canonical Jubjub scalar.
pub const SEED_LEN: usize = 32;

/// Width of a public verification key: a compressed subgroup point.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Width of a signature: compressed `R`, then canonical `S`.
pub const SIGNATURE_LEN: usize = 64;

/// Mints a Jubjub-scalar secret from 32 bytes of fresh entropy: the top five bits
/// cleared, giving canonical bytes for a uniformly sampled 251-bit value — below the
/// subgroup order by construction (proposal 0035), so §9.1's canonicity clause holds
/// without a check.
#[must_use]
pub fn mint_signing_secret(entropy: [u8; 32]) -> [u8; 32] {
    let mut bytes = entropy;
    bytes[31] &= 0x07;
    bytes
}

/// The affine coordinates of a subgroup point, as field elements — the form every
/// derivation absorbs points in (§9.1, proposal 0035).
#[must_use]
pub fn coordinates(point: &SubgroupPoint) -> (F, F) {
    let affine = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(*point));
    (affine.get_u(), affine.get_v())
}

/// A canonical scalar's value as a field element: the Jubjub order divides into the
/// field, so canonical scalar bytes are canonical field bytes. This is how `sk_epoch`
/// enters the action derivation (§9.1).
fn scalar_as_field(scalar: &JubjubScalar) -> F {
    field::decode(&scalar.to_bytes()).expect("the Jubjub order is below the field order")
}

/// Reduces a field element into the Jubjub scalar field — the reduction §9.1 names for
/// the challenge and the nonce.
fn reduce(value: &F) -> JubjubScalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&value.to_repr());
    JubjubScalar::from_bytes_wide(&wide)
}

/// Decodes a secret key, refusing non-canonical bytes.
fn decode_secret(sk: &[u8; SEED_LEN]) -> Option<JubjubScalar> {
    JubjubScalar::from_bytes(sk).into()
}

/// Decodes a compressed point, refusing anything off the prime-order subgroup — the
/// serialization boundary §9.1's cofactor clause is enforced at.
fn decode_point(bytes: &[u8; 32]) -> Option<SubgroupPoint> {
    SubgroupPoint::from_bytes(bytes).into()
}

/// Derives the public verification key: `PK = sk·G`, compressed.
///
/// Returns `None` for non-canonical secret bytes — the same refusal the circuit's
/// canonicity clause makes, so the CPU side cannot accept a key the statement would
/// not.
#[must_use]
pub fn public_key(sk: &[u8; SEED_LEN]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let sk = decode_secret(sk)?;
    Some((SubgroupPoint::generator() * sk).to_bytes())
}

/// The transcript challenge before reduction: `Poseidon(R.x, R.y, PK.x, PK.y, m)` —
/// deliberately untagged, pinned by its five-element arity (§9.1, proposal 0035).
fn challenge(r: &SubgroupPoint, pk: &SubgroupPoint, message: &F) -> F {
    let (rx, ry) = coordinates(r);
    let (px, py) = coordinates(pk);
    poseidon::hash(&[rx, ry, px, py, *message])
}

/// Signs a compressed message under the §9.1 equation.
///
/// Returns `None` for non-canonical secret bytes. Signing is deterministic — see the
/// module documentation for why that is an obligation rather than a convenience.
#[must_use]
pub fn sign(sk: &[u8; SEED_LEN], message: &F) -> Option<[u8; SIGNATURE_LEN]> {
    let secret = decode_secret(sk)?;
    let k = reduce(&poseidon::hash(&[
        F::from(field_domain::NONCE),
        scalar_as_field(&secret),
        *message,
    ]));
    let r = SubgroupPoint::generator() * k;
    let pk = SubgroupPoint::generator() * secret;
    let e = reduce(&challenge(&r, &pk, message));
    let s = k + e * secret;

    let mut out = [0u8; SIGNATURE_LEN];
    out[..32].copy_from_slice(&r.to_bytes());
    out[32..].copy_from_slice(&s.to_bytes());
    Some(out)
}

/// Verifies the §9.1 equation `S·G = R + e·PK`.
///
/// Returns `false` for a wrong-width, non-canonical, or off-subgroup input rather than
/// distinguishing those from an honest mismatch: every caller treats an unverifiable
/// certificate and a forged one identically, so there is nothing for the distinction
/// to inform.
#[must_use]
pub fn verify(public_key: &[u8], message: &F, signature: &[u8]) -> bool {
    let Ok(pk_bytes): Result<[u8; PUBLIC_KEY_LEN], _> = public_key.try_into() else {
        return false;
    };
    let Some(pk) = decode_point(&pk_bytes) else {
        return false;
    };
    let Ok(sig): Result<[u8; SIGNATURE_LEN], _> = signature.try_into() else {
        return false;
    };
    let Ok(r_bytes): Result<[u8; 32], _> = sig[..32].try_into() else {
        return false;
    };
    let Ok(s_bytes): Result<[u8; 32], _> = sig[32..].try_into() else {
        return false;
    };
    let Some(r) = decode_point(&r_bytes) else {
        return false;
    };
    let Some(s) = Option::<JubjubScalar>::from(JubjubScalar::from_bytes(&s_bytes)) else {
        return false;
    };

    let e = reduce(&challenge(&r, &pk, message));
    SubgroupPoint::generator() * s == r + pk * e
}

/// The epoch certificate's canonical signed message (§9.1, proposal 0035):
/// `Poseidon(EPOCH_CERT, agora, epoch, pk_epoch.x, pk_epoch.y)`.
///
/// Returns `None` where the key bytes name no subgroup point — such an encoding has no
/// coordinates and therefore no message.
#[must_use]
pub fn epoch_cert_message(agora: &AgoraId, epoch: Epoch, epoch_public_key: &[u8]) -> Option<F> {
    let key: [u8; 32] = epoch_public_key.try_into().ok()?;
    let (x, y) = coordinates(&decode_point(&key)?);
    Some(poseidon::hash(&[
        F::from(field_domain::EPOCH_CERT),
        field::from_id(agora.as_bytes()),
        field::from_epoch(epoch),
        x,
        y,
    ]))
}

/// The migration certificate's canonical signed message (§9.3, proposal 0035):
/// `Poseidon(MIGRATION_CERT, agora, pk_root_new.x, pk_root_new.y)`.
#[must_use]
pub fn migration_cert_message(agora: &AgoraId, successor_public_key: &[u8]) -> Option<F> {
    let key: [u8; 32] = successor_public_key.try_into().ok()?;
    let (x, y) = coordinates(&decode_point(&key)?);
    Some(poseidon::hash(&[
        F::from(field_domain::MIGRATION_CERT),
        field::from_id(agora.as_bytes()),
        x,
        y,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> [u8; SEED_LEN] {
        mint_signing_secret([byte; 32])
    }

    #[test]
    fn a_signature_verifies_under_its_public_key() {
        let sk = secret(0x42);
        let pk = public_key(&sk).expect("minted keys are canonical");
        let sig = sign(&sk, &F::from(7)).expect("minted keys are canonical");
        assert!(verify(&pk, &F::from(7), &sig));
    }

    /// Pins the whole scheme — curve, generator, nonce derivation, challenge, encoding
    /// — against the value the proving stack's own curve fork computes for the same
    /// key and message. If this moves, the two Jubjub implementations have diverged.
    #[test]
    fn known_answer_matches_the_circuit_stack() {
        let mut sk = [0u8; 32];
        sk[0] = 42;
        let sig = sign(&sk, &F::from(7)).expect("42 is canonical");
        let expected = "2f3143d77a2b1106956f3eec2a0b741dd869d5f12b57bfe800670598bbd51781\
                        4d83cbd41f12c0f3c52618d3fe7ae8d28589bfb34359cf919ec40da5ce66f502";
        let rendered: alloc::string::String =
            sig.iter().map(|b| alloc::format!("{b:02x}")).collect();
        assert_eq!(rendered, expected, "the certificate scheme moved");
    }

    extern crate alloc;

    #[test]
    fn signing_is_deterministic() {
        assert_eq!(sign(&secret(1), &F::from(9)), sign(&secret(1), &F::from(9)));
    }

    #[test]
    fn a_tampered_message_or_signature_is_rejected() {
        let sk = secret(0x42);
        let pk = public_key(&sk).expect("canonical");
        let sig = sign(&sk, &F::from(7)).expect("canonical");
        assert!(!verify(&pk, &F::from(8), &sig));

        let mut bent = sig;
        bent[40] ^= 0x01;
        assert!(!verify(&pk, &F::from(7), &bent));
    }

    #[test]
    fn another_key_is_rejected() {
        let sig = sign(&secret(0x42), &F::from(7)).expect("canonical");
        let other = public_key(&secret(0x43)).expect("canonical");
        assert!(!verify(&other, &F::from(7), &sig));
    }

    /// A non-canonical secret is refused at every entry, exactly as the circuit's
    /// canonicity clause refuses it — one key, one representation, one nullifier
    /// stream (§9.1).
    #[test]
    fn non_canonical_secrets_are_refused() {
        let non_canonical = [0xff; 32];
        assert_eq!(public_key(&non_canonical), None);
        assert_eq!(sign(&non_canonical, &F::from(7)), None);
        assert!(decode_secret(&mint_signing_secret([0xff; 32])).is_some());
    }

    /// Wrong widths are an honest `false`.
    #[test]
    fn wrong_width_inputs_are_rejected() {
        let sk = secret(0x42);
        let pk = public_key(&sk).expect("canonical");
        let sig = sign(&sk, &F::from(7)).expect("canonical");
        assert!(!verify(&pk[..31], &F::from(7), &sig));
        assert!(!verify(&pk, &F::from(7), &sig[..63]));
        assert!(!verify(&[], &F::from(7), &[]));
    }

    /// The serialization boundary of §9.1's cofactor clause: an encoding that decodes
    /// to a curve point *outside* the prime-order subgroup must be refused wherever a
    /// point enters.
    #[test]
    fn an_off_subgroup_point_is_refused_at_the_boundary() {
        // A point of low order: the curve has cofactor 8, and (0, -1) is its order-2
        // torsion point — a canonical encoding, on the curve, off the subgroup.
        let torsion =
            jubjub::AffinePoint::from_raw_unchecked(jubjub::Base::zero(), -jubjub::Base::one());
        let bytes = torsion.to_bytes();
        assert!(
            bool::from(jubjub::AffinePoint::from_bytes(bytes).is_some()),
            "the fixture must be a valid curve point"
        );
        assert_eq!(decode_point(&bytes), None, "an off-subgroup point decoded");

        // And therefore: no certificate message can be formed over it, and no
        // signature carrying it as R verifies.
        assert_eq!(
            epoch_cert_message(&AgoraId::from_bytes([1; 32]), Epoch::new(1), &bytes),
            None
        );
        let sk = secret(0x42);
        let pk = public_key(&sk).expect("canonical");
        let mut sig = sign(&sk, &F::from(7)).expect("canonical");
        sig[..32].copy_from_slice(&bytes);
        assert!(!verify(&pk, &F::from(7), &sig));
    }

    /// The two certificate kinds cannot collide: distinct leading domains, and the
    /// arity differs besides.
    #[test]
    fn the_two_certificate_messages_cannot_collide() {
        let agora = AgoraId::from_bytes([0x7e; 32]);
        let sk = secret(0x42);
        let pk = public_key(&sk).expect("canonical");
        let epoch = epoch_cert_message(&agora, Epoch::new(0), &pk).expect("subgroup point");
        let migration = migration_cert_message(&agora, &pk).expect("subgroup point");
        assert_ne!(epoch, migration);
    }

    #[test]
    fn every_bound_fact_changes_the_epoch_message() {
        let agora = AgoraId::from_bytes([0x7e; 32]);
        let other_agora = AgoraId::from_bytes([0x7f; 32]);
        let pk = public_key(&secret(0x42)).expect("canonical");
        let other_pk = public_key(&secret(0x43)).expect("canonical");
        let base = epoch_cert_message(&agora, Epoch::new(7), &pk).expect("subgroup point");
        assert_ne!(
            base,
            epoch_cert_message(&other_agora, Epoch::new(7), &pk).expect("subgroup point"),
            "the agora is not in the signed message"
        );
        assert_ne!(
            base,
            epoch_cert_message(&agora, Epoch::new(8), &pk).expect("subgroup point"),
            "the epoch is not in the signed message"
        );
        assert_ne!(
            base,
            epoch_cert_message(&agora, Epoch::new(7), &other_pk).expect("subgroup point"),
            "the key is not in the signed message"
        );
    }

    #[test]
    fn distinct_seeds_yield_distinct_keys() {
        assert_ne!(public_key(&secret(1)), public_key(&secret(2)));
    }
}
