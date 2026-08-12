// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-epoch witness-service key (§5.2, proposal 0025).
//!
//! The inclusion-witness service is the one member service that cannot be gated by a
//! membership proof: a member's first proof of an epoch requires the witness itself, and a
//! boundary-admitted member has never proven anything. Left ungated instead, the service
//! answers position probes — occupied positions return a path, empty ones an error — and
//! enumerating them yields the class occupancy §5.2 withholds at any point.
//!
//! The resolution is the tag key's shape (§6.4): a symmetric per-epoch key, derived by the
//! operator, distributed to current members in the boundary broadcast (§11), and withheld
//! from a revoked member at exactly the same cut. Holding it proves nothing about *who*
//! asked — only that the requester was equipped for this epoch, which is the property the
//! service needs and the most it can have.
//!
//! Derived under its own domain rather than sharing [`Domain::TagKey`]'s, so that leaking
//! one epoch key never leaks the other: the tag key resolves content, this key opens the
//! witness service, and their compromise stories stay separate.

use nymora_core::{AgoraId, Domain, Epoch, WitnessKey, DIGEST_LEN};

/// Derives an agora's witness-service key for one epoch.
///
/// Performed by the agora's operator, whose members receive the result through the
/// boundary broadcast (§11) rather than deriving it themselves — the input secret is not
/// member material. A member's Persora holds the broadcast key and never runs this.
#[must_use]
pub fn derive_witness_key(agora_secret: &[u8], agora: &AgoraId, epoch: Epoch) -> WitnessKey {
    let mut context = [0u8; DIGEST_LEN + 8];
    context[..DIGEST_LEN].copy_from_slice(agora.as_bytes());
    context[DIGEST_LEN..].copy_from_slice(&epoch.get().to_le_bytes());
    WitnessKey::new(crate::kdf::derive(
        Domain::WitnessKey,
        agora_secret,
        &context,
    ))
}

#[cfg(test)]
mod tests {
    use super::derive_witness_key;
    use nymora_core::{AgoraId, Epoch, TagKey};

    const SECRET: &[u8] = &[0x5a; 32];

    fn agora() -> AgoraId {
        AgoraId::from_bytes([0x0a; 32])
    }

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n)
    }

    #[test]
    fn deterministic_for_one_epoch() {
        assert_eq!(
            derive_witness_key(SECRET, &agora(), epoch(7)),
            derive_witness_key(SECRET, &agora(), epoch(7))
        );
    }

    #[test]
    fn rotates_with_the_epoch() {
        assert_ne!(
            derive_witness_key(SECRET, &agora(), epoch(7)),
            derive_witness_key(SECRET, &agora(), epoch(8))
        );
    }

    #[test]
    fn scoped_to_the_agora() {
        assert_ne!(
            derive_witness_key(SECRET, &agora(), epoch(7)),
            derive_witness_key(SECRET, &AgoraId::from_bytes([0x0b; 32]), epoch(7))
        );
    }

    /// The same secret under the tag-key domain yields an unrelated key — the two epoch
    /// keys must have separate compromise stories despite one input secret.
    #[test]
    fn distinct_from_the_tag_key() {
        let witness = derive_witness_key(SECRET, &agora(), epoch(7));
        let tag = crate::tag::derive_tag_key(SECRET, &agora(), epoch(7));
        assert_ne!(TagKey::new(*witness.expose()), tag);
    }
}
