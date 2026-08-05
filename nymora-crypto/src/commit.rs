// SPDX-License-Identifier: MIT OR Apache-2.0

//! The credential leaf commitment (§9.1).
//!
//! ```text
//! leaf = Commit(pk_root, sk_cred, r_root, agora_id)
//! ```
//!
//! This is what Skiora holds in place of a member's public key. It is **hiding** — Skiora
//! learns nothing about either committed value — and **binding**, so a member cannot later
//! claim a different pair produced the same leaf. Every routine proof opens it (§9.1), which
//! is why `r_root` is supplied on every operation and cannot be held in hardware.
//!
//! Committing to `sk_cred` is what makes its durability enforceable rather than merely
//! requested: every proof using it shows the nullifier derives from the same key this leaf
//! commits to, so a member who invents a fresh one has no leaf containing it (§9.3).
//!
//! Committing to `agora_id` adds no hiding — everyone who could verify this leaf already knows
//! it. It is there so §5.1's requirement that no commitment be derivable across agoras holds by
//! construction rather than by a client having generated fresh material per agora
//! (proposal 0013). Both hold today; only the construction survives a key-generation bug.

use crate::algebraic::AlgebraicHasher;
use nymora_core::{AgoraId, Commitment, CredentialKey, Domain, RootOpening};

/// Commits to a credential's root public key and durable secret under an opening value.
///
/// Hiding rests entirely on `opening` being unpredictable: this is a hash commitment, so an
/// adversary who can guess the opening can confirm a guessed `pk_root` by recomputation.
/// `r_root` must therefore come from a cryptographically secure random source at credential
/// creation, and never from anything derived, counted, or reused (§5.1).
#[must_use]
pub fn commit(
    pk_root: &[u8],
    credential_key: &CredentialKey,
    opening: &RootOpening,
    agora: &AgoraId,
) -> Commitment {
    Commitment::from_bytes(
        AlgebraicHasher::new(Domain::Commitment)
            .absorb(pk_root)
            .absorb(credential_key.expose())
            .absorb(opening.expose())
            .absorb(agora.as_bytes())
            .finalize(),
    )
}

#[cfg(test)]
mod tests {
    use super::commit;
    use nymora_core::{AgoraId, CredentialKey, RootOpening};

    const PK: &[u8] = &[0x11; 32];
    const AGORA: AgoraId = AgoraId::from_bytes([0x99; 32]);

    fn mk(byte: u8) -> CredentialKey {
        CredentialKey::new([byte; 32])
    }

    fn opening(byte: u8) -> RootOpening {
        RootOpening::new([byte; 32])
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            commit(PK, &mk(0x44), &opening(0x22), &AGORA),
            commit(PK, &mk(0x44), &opening(0x22), &AGORA)
        );
    }

    /// §5.1 — identical material in two agoras must not produce the same leaf.
    ///
    /// The property held before this was absorbed, because §5.1 also requires key material to
    /// be generated freshly per agora. It held by a client behaving correctly rather than by
    /// construction, and a backup-restore, a credential-clone convenience, or a test fixture
    /// reaching production each break that assumption silently (proposal 0013).
    #[test]
    fn identical_material_in_two_agoras_does_not_collide() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22), &AGORA),
            commit(
                PK,
                &mk(0x44),
                &opening(0x22),
                &AgoraId::from_bytes([0x9a; 32])
            )
        );
    }

    /// Pins the construction, cross-checked against an independent implementation of the
    /// framing and of SHA-256 — which is what the provisional algebraic backend stands in with.
    ///
    /// This value moves when the real algebraic hash arrives, and that is expected: it pins the
    /// *shape* — field order, framing, and the domain tag — not the eventual digest.
    #[test]
    fn known_answer() {
        assert_eq!(
            commit(PK, &mk(0x44), &opening(0x22), &AGORA).as_bytes(),
            &[
                0x12, 0xab, 0x9a, 0x5b, 0x36, 0xf4, 0x99, 0x0d, 0xa9, 0x14, 0x07, 0xdd, 0x55, 0x2e,
                0x37, 0x61, 0xc4, 0x14, 0x85, 0xd5, 0xf8, 0xdd, 0xe4, 0x94, 0xad, 0x30, 0xc9, 0xbb,
                0xce, 0x21, 0x10, 0x64,
            ]
        );
    }

    /// Hiding: the same key under two openings must look unrelated.
    ///
    /// Without this, Skiora could recognise a returning member's `pk_root` across
    /// credentials, which is the linkage the commitment exists to prevent.
    #[test]
    fn different_openings_hide_the_same_key() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22), &AGORA),
            commit(PK, &mk(0x44), &opening(0x23), &AGORA)
        );
    }

    /// Binding: a different key under the same opening must not collide.
    #[test]
    fn different_keys_do_not_collide_under_one_opening() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22), &AGORA),
            commit(&[0x12; 32], &mk(0x44), &opening(0x22), &AGORA)
        );
    }

    /// The credential key is bound too, not just carried alongside.
    ///
    /// This is what stops a member from presenting a leaf with one `sk_cred` and a
    /// nullifier derived from another (§5.3, §4.3, §9.3).
    #[test]
    fn the_credential_key_changes_the_leaf() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22), &AGORA),
            commit(PK, &mk(0x45), &opening(0x22), &AGORA)
        );
    }

    /// The framing in [`crate::Hasher`] must survive into the commitment.
    ///
    /// `pk_root` is variable-length as far as this function is concerned, so an unframed
    /// encoding would let a longer key absorb the next field's leading bytes and produce a
    /// second valid opening for the same leaf — a direct break of binding.
    #[test]
    fn the_field_boundaries_are_not_malleable() {
        let long = [0x11u8; 33];
        assert_ne!(
            commit(PK, &mk(0x11), &opening(0x11), &AGORA),
            commit(&long, &mk(0x11), &opening(0x11), &AGORA)
        );
    }
}
