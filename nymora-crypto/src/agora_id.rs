// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deriving an agora's identifier from its founding parameters (§3).
//!
//! No registry issues these. An agora computes its own identifier from material it already
//! holds, which is what removes the third party §3 is written to eliminate — anything that
//! tracked agora existence would be a single point of compulsion for metadata the design
//! exists to avoid creating.
//!
//! # Byte family, deliberately
//!
//! `agora_id` is an *input* to the attestation nullifier (§6.1), not a value the circuit
//! recomputes, so nothing here needs the algebraic hash. See the crate documentation for the
//! distinction.
//!
//! One consequence belongs with the circuit work rather than here: an algebraic hash operates
//! on field elements of fewer than 256 bits, so a 32-byte `agora_id` will not fit in one.
//! Whatever encoding the circuit adopts — splitting across two elements, or truncating —
//! must be fixed there and applied identically everywhere, for the same reason the framing in
//! [`crate::Hasher`] is.

use crate::hash::ByteHasher;
use nymora_core::{AgoraId, Domain, PublicParameters};

/// Derives an agora's identifier from its founding parameters.
///
/// Deterministic and total: the same parameters always produce the same identifier, which is
/// what lets a member who was handed an `agora_id` out-of-band confirm it against parameters
/// they are given, and what lets two implementations agree without coordinating.
///
/// # Panics
///
/// Debug builds only, if `founding_key` is shorter than 16 bytes. That is not a length the
/// protocol requires but a guard against the failure described in [`PublicParameters`]:
/// passing a name or a label here rather than key material would make the resulting
/// identifier guessable, and an agora's existence is the thing §3 protects. Real key material
/// is far longer than this floor.
#[must_use]
pub fn derive(params: &PublicParameters<'_>) -> AgoraId {
    debug_assert!(
        params.founding_key.len() >= 16,
        "founding_key looks like a label rather than key material; see PublicParameters"
    );

    AgoraId::from_bytes(
        ByteHasher::new(Domain::AgoraId)
            .absorb(&params.ceremony.encode())
            .absorb(params.founding_key)
            .finalize(),
    )
}

#[cfg(test)]
mod tests {
    use super::derive;
    use nymora_core::{CeremonyMode, PublicParameters};

    const KEY: &[u8] = &[0x7e; 32];

    fn params(ceremony: CeremonyMode, founding_key: &[u8]) -> PublicParameters<'_> {
        PublicParameters {
            ceremony,
            founding_key,
        }
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            derive(&params(CeremonyMode::SingleParty, KEY)),
            derive(&params(CeremonyMode::SingleParty, KEY))
        );
    }

    #[test]
    fn the_founding_key_changes_the_identifier() {
        assert_ne!(
            derive(&params(CeremonyMode::SingleParty, KEY)),
            derive(&params(CeremonyMode::SingleParty, &[0x7f; 32]))
        );
    }

    #[test]
    fn the_ceremony_changes_the_identifier() {
        assert_ne!(
            derive(&params(CeremonyMode::SingleParty, KEY)),
            derive(&params(
                CeremonyMode::Threshold {
                    threshold: 0,
                    parties: 0
                },
                KEY
            )),
            "the ceremony discriminant was not absorbed"
        );
    }

    /// Threshold parameters are part of the committed set, not decoration.
    #[test]
    fn the_threshold_shape_changes_the_identifier() {
        let two_of_three = CeremonyMode::Threshold {
            threshold: 2,
            parties: 3,
        };
        let three_of_two = CeremonyMode::Threshold {
            threshold: 3,
            parties: 2,
        };
        assert_ne!(
            derive(&params(two_of_three, KEY)),
            derive(&params(three_of_two, KEY)),
            "threshold and parties are interchangeable in the encoding"
        );
    }

    /// The ceremony/key boundary must not be movable.
    ///
    /// `founding_key` is variable-length, so without framing a key whose leading bytes
    /// matched a different ceremony encoding could produce a colliding identifier — and an
    /// `agora_id` collision means two distinct agoras sharing every nullifier namespace.
    #[test]
    fn the_field_boundary_is_not_malleable() {
        let mut shifted = [0u8; 33];
        shifted[1..].copy_from_slice(&[0x7e; 32]);
        assert_ne!(
            derive(&params(CeremonyMode::SingleParty, KEY)),
            derive(&params(CeremonyMode::SingleParty, &shifted))
        );
    }

    /// Pins the derivation, cross-checked against an independent implementation of the
    /// framing and of SHA-256 rather than copied from this code's output.
    ///
    /// An `agora_id` is permanent and shared out-of-band. If this value moves, every agora
    /// derived under the old construction becomes unaddressable — the identifier its members
    /// hold no longer matches the one its parameters produce. That is a version bump of the
    /// domain tag, never a fixed expectation.
    #[test]
    fn known_answer() {
        assert_eq!(
            derive(&params(CeremonyMode::SingleParty, KEY)).as_bytes(),
            &[
                0xc2, 0xdd, 0x7b, 0x5e, 0xeb, 0x10, 0xd4, 0xa7, 0x18, 0xc1, 0x0e, 0x12, 0xd9, 0x33,
                0xab, 0xdd, 0x60, 0xbb, 0xee, 0x48, 0xc2, 0x15, 0x8e, 0x88, 0xbb, 0xe6, 0xe4, 0x3f,
                0xa9, 0x3e, 0x9e, 0x6f,
            ]
        );
    }
}
