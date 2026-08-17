// SPDX-License-Identifier: MIT OR Apache-2.0

//! The credential leaf commitment (§9.1, proposal 0035).
//!
//! ```text
//! leaf = Poseidon(LEAF, pk_root.x, pk_root.y, sk_cred, r_root, agora_id)
//! ```
//!
//! This is what Skiora holds in place of a member's public key. It is **hiding** —
//! Skiora learns nothing about either committed value, resting on `r_root` being
//! unpredictable — and **binding**, so a member cannot later claim a different pair
//! produced the same leaf. Every routine proof opens it (§9.1), which is why `r_root`
//! is supplied on every operation and cannot be held in hardware.
//!
//! The commitment absorbs the root key's affine **coordinates**, not its compressed
//! encoding: the circuit holds `pk_root` as a point and recomputes this hash from the
//! point it verified the certificate under, so paying to decompress in-constraint
//! would buy nothing. A compressed encoding that names no subgroup point has no
//! coordinates, and therefore no leaf — the same serialization boundary the signature
//! scheme enforces.
//!
//! Committing to `sk_cred` is what makes its durability enforceable rather than merely
//! requested: every counted proof shows its nullifier derives from the same key this
//! leaf commits to, so a member who invents a fresh one has no leaf containing it
//! (§9.3). Committing to `agora_id` is §5.1's cross-agora underivability held by
//! construction rather than by a client having generated fresh material per agora
//! (proposal 0013).

use group::GroupEncoding;
use nymora_core::{field_domain, AgoraId, Commitment, CredentialKey, RootOpening};

use crate::field::{self, F};
use crate::poseidon;
use crate::signature;

/// Commits to a credential's root public key and durable secret under an opening
/// value.
///
/// Returns `None` where `pk_root` is not the 32-byte encoding of a subgroup point —
/// such a key has no coordinates to commit to. Hiding rests entirely on `opening`
/// being unpredictable: `r_root` must be minted from the device's secure random
/// source at credential creation, and never derived, counted, or reused (§5.1).
#[must_use]
pub fn commit(
    pk_root: &[u8],
    credential_key: &CredentialKey,
    opening: &RootOpening,
    agora: &AgoraId,
) -> Option<Commitment> {
    let key: [u8; 32] = pk_root.try_into().ok()?;
    let point = Option::<jubjub::SubgroupPoint>::from(jubjub::SubgroupPoint::from_bytes(&key))?;
    let (x, y) = signature::coordinates(&point);
    Some(Commitment::from_bytes(field::to_bytes(&poseidon::hash(&[
        F::from(field_domain::LEAF),
        x,
        y,
        field::from_witness_bytes(credential_key.expose()),
        field::from_witness_bytes(opening.expose()),
        field::from_id(agora.as_bytes()),
    ]))))
}

#[cfg(test)]
mod tests {
    use super::commit;
    use crate::signature;
    use nymora_core::{AgoraId, Commitment, CredentialKey, RootOpening};

    const AGORA: AgoraId = AgoraId::from_bytes([0x99; 32]);

    fn pk() -> [u8; 32] {
        signature::public_key(&signature::mint_signing_secret([0x11; 32]))
            .expect("minted keys are canonical")
    }

    fn mk(byte: u8) -> CredentialKey {
        CredentialKey::new([byte; 32])
    }

    fn opening(byte: u8) -> RootOpening {
        RootOpening::new([byte; 32])
    }

    fn leaf(key: u8, open: u8, agora: &AgoraId) -> Commitment {
        commit(&pk(), &mk(key), &opening(open), agora).expect("pk is a subgroup point")
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(leaf(0x14, 0x22, &AGORA), leaf(0x14, 0x22, &AGORA));
    }

    /// §5.1 — identical material in two agoras must not produce the same leaf
    /// (proposal 0013).
    #[test]
    fn identical_material_in_two_agoras_does_not_collide() {
        assert_ne!(
            leaf(0x14, 0x22, &AGORA),
            leaf(0x14, 0x22, &AgoraId::from_bytes([0x9a; 32]))
        );
    }

    /// Hiding: the same key under two openings must look unrelated, or Skiora could
    /// recognise a returning member's `pk_root` across credentials.
    #[test]
    fn different_openings_hide_the_same_key() {
        assert_ne!(leaf(0x14, 0x22, &AGORA), leaf(0x14, 0x23, &AGORA));
    }

    /// Binding: a different key under the same opening must not collide.
    #[test]
    fn different_keys_do_not_collide_under_one_opening() {
        let other_pk = signature::public_key(&signature::mint_signing_secret([0x12; 32]))
            .expect("minted keys are canonical");
        assert_ne!(
            commit(&pk(), &mk(0x14), &opening(0x22), &AGORA),
            commit(&other_pk, &mk(0x14), &opening(0x22), &AGORA)
        );
    }

    /// The credential key is bound too, not just carried alongside — what stops a
    /// member presenting a leaf with one `sk_cred` and a nullifier from another.
    #[test]
    fn the_credential_key_changes_the_leaf() {
        assert_ne!(leaf(0x14, 0x22, &AGORA), leaf(0x15, 0x22, &AGORA));
    }

    /// The serialization boundary: bytes that name no subgroup point have no leaf.
    #[test]
    fn a_non_point_key_has_no_commitment() {
        assert_eq!(commit(&[0xff; 32], &mk(0x14), &opening(0x22), &AGORA), None);
        assert_eq!(commit(&[0x11; 31], &mk(0x14), &opening(0x22), &AGORA), None);
    }
}
