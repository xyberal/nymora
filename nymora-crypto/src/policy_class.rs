// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deriving a policy class identifier from its agora and label (§5.2).
//!
//! # Why this is derived rather than agreed
//!
//! A policy class could have been a constant — `1` for tier 2, `2` for eligible vouchers — and
//! every implementation would interoperate immediately. That is precisely what §5.1 forbids:
//! *"No value derived within one agora is ever reused in, or derivable from, another. This
//! covers … any handle presented to a Skiora."* §5.2 puts the identifier in the request path,
//! which makes it such a handle, and a shared constant would be the same bytes appearing in
//! every agora running a tier system.
//!
//! Binding it to the `agora_id` costs one absorbed field and removes the correlator.
//!
//! # Byte family
//!
//! The identifier selects *which* accumulator root a proof is checked against; the root is a
//! public input, and the identifier itself is never recomputed inside a circuit. So this is the
//! byte family, for the same reason [`crate::agora_id`] is.

use crate::hash::ByteHasher;
use nymora_core::{AgoraId, Domain, PolicyClass};

/// Derives a policy class identifier.
///
/// `label` names the class within its agora — `b"tier-2-members"`, say. It carries no entropy
/// requirement and is expected to be guessable; the `agora_id` is what makes the result
/// unguessable, and §3 keeps that confidential.
///
/// The label is absorbed as raw bytes and never interpreted, so an agora may use whatever
/// naming its policy (§5.3) settles on. Two agoras choosing the same label produce unrelated
/// identifiers.
#[must_use]
pub fn derive(agora: &AgoraId, label: &[u8]) -> PolicyClass {
    PolicyClass::from_bytes(
        ByteHasher::new(Domain::PolicyClass)
            .absorb(agora.as_bytes())
            .absorb(label)
            .finalize(),
    )
}

#[cfg(test)]
mod tests {
    use super::derive;
    use nymora_core::AgoraId;

    const AGORA: AgoraId = AgoraId::from_bytes([0x7e; 32]);
    const OTHER: AgoraId = AgoraId::from_bytes([0x7f; 32]);
    const LABEL: &[u8] = b"tier-2-members";

    #[test]
    fn is_deterministic() {
        assert_eq!(derive(&AGORA, LABEL), derive(&AGORA, LABEL));
    }

    #[test]
    fn the_label_selects_the_class() {
        assert_ne!(derive(&AGORA, LABEL), derive(&AGORA, b"tier-2-vouchers"));
    }

    /// §5.1 — the same label in two agoras must not produce the same handle.
    ///
    /// This is the property the whole derivation exists for. A shared constant would fail it,
    /// and the failure would be invisible until someone correlated two agoras' traffic.
    #[test]
    fn the_same_label_is_unrelated_across_agoras() {
        assert_ne!(derive(&AGORA, LABEL), derive(&OTHER, LABEL));
    }

    /// The agora/label boundary must not be movable.
    ///
    /// `agora_id` is fixed-width but `label` is not, so without framing a label whose leading
    /// bytes absorbed the tail of the identifier would collide with a different pairing — two
    /// distinct classes sharing one accumulator.
    #[test]
    fn the_field_boundary_is_not_malleable() {
        let mut shifted = [0u8; 33];
        shifted[1..].copy_from_slice(&[0x7e; 32]);
        assert_ne!(
            derive(&AGORA, LABEL),
            derive(&AgoraId::from_bytes([0x7e; 32]), &shifted)
        );
    }

    #[test]
    fn an_empty_label_is_representable() {
        assert_ne!(derive(&AGORA, b""), derive(&AGORA, LABEL));
    }

    /// Pins the derivation, cross-checked against an independent implementation of the framing
    /// and of SHA-256 rather than copied from this code's output.
    ///
    /// Moving this value re-addresses every accumulator in every agora: roots are fetched by
    /// policy class, so a changed identifier points at a tree that does not exist. That is a
    /// version bump of the domain tag, never a fixed expectation.
    #[test]
    fn known_answer() {
        assert_eq!(
            derive(&AGORA, LABEL).as_bytes(),
            &[
                0x5a, 0x29, 0x69, 0x20, 0xce, 0xef, 0x7b, 0xfc, 0xb2, 0xac, 0xbb, 0x9a, 0x9b, 0x59,
                0xd2, 0xaa, 0xc5, 0xd1, 0xf4, 0xa8, 0x10, 0x54, 0xa1, 0x8a, 0x95, 0x32, 0x8e, 0xef,
                0xcf, 0x76, 0x92, 0x23,
            ]
        );
    }
}
