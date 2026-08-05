// SPDX-License-Identifier: MIT OR Apache-2.0

//! The credential leaf commitment (§9.1).
//!
//! ```text
//! leaf = Commit(pk_root, sk_cred, r_root)
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

use crate::algebraic::AlgebraicHasher;
use nymora_core::{Commitment, CredentialKey, Domain, RootOpening};

/// Commits to a credential's root public key and durable secret under an opening value.
///
/// Hiding rests entirely on `opening` being unpredictable: this is a hash commitment, so an
/// adversary who can guess the opening can confirm a guessed `pk_root` by recomputation.
/// `r_root` must therefore come from a cryptographically secure random source at credential
/// creation, and never from anything derived, counted, or reused (§5.1).
#[must_use]
pub fn commit(pk_root: &[u8], credential_key: &CredentialKey, opening: &RootOpening) -> Commitment {
    Commitment::from_bytes(
        AlgebraicHasher::new(Domain::Commitment)
            .absorb(pk_root)
            .absorb(credential_key.expose())
            .absorb(opening.expose())
            .finalize(),
    )
}

#[cfg(test)]
mod tests {
    use super::commit;
    use nymora_core::{CredentialKey, RootOpening};

    const PK: &[u8] = &[0x11; 32];

    fn mk(byte: u8) -> CredentialKey {
        CredentialKey::new([byte; 32])
    }

    fn opening(byte: u8) -> RootOpening {
        RootOpening::new([byte; 32])
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            commit(PK, &mk(0x44), &opening(0x22)),
            commit(PK, &mk(0x44), &opening(0x22))
        );
    }

    /// Hiding: the same key under two openings must look unrelated.
    ///
    /// Without this, Skiora could recognise a returning member's `pk_root` across
    /// credentials, which is the linkage the commitment exists to prevent.
    #[test]
    fn different_openings_hide_the_same_key() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22)),
            commit(PK, &mk(0x44), &opening(0x23))
        );
    }

    /// Binding: a different key under the same opening must not collide.
    #[test]
    fn different_keys_do_not_collide_under_one_opening() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22)),
            commit(&[0x12; 32], &mk(0x44), &opening(0x22))
        );
    }

    /// The credential key is bound too, not just carried alongside.
    ///
    /// This is what stops a member from presenting a leaf with one `sk_cred` and a
    /// nullifier derived from another (§5.3, §4.3, §9.3).
    #[test]
    fn the_credential_key_changes_the_leaf() {
        assert_ne!(
            commit(PK, &mk(0x44), &opening(0x22)),
            commit(PK, &mk(0x45), &opening(0x22))
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
            commit(PK, &mk(0x11), &opening(0x11)),
            commit(&long, &mk(0x11), &opening(0x11))
        );
    }
}
