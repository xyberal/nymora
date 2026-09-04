// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-epoch fetch key (§11, proposal 0036).
//!
//! The boundary envelope must be gated by *something*: an ungated bulletin is an
//! existence-and-size oracle to anyone who learns an agora id, and its roots are what §7
//! forbids outsiders from ever obtaining. The fetch key is a shared per-epoch secret with
//! exactly the tag key's lifecycle — derived by the operator, delivered to members inside
//! the encrypted bulletin body, presented to fetch the next envelope — whose blast radius
//! is now stated in full: a leaked or retained key reveals that the agora exists and how
//! many ciphertexts it published, and nothing behind them, which is all ciphertext.
//!
//! Derived under its own domain rather than sharing [`Domain::TagKey`]'s, so that leaking
//! one epoch key never leaks the other.

use nymora_core::{AgoraId, Domain, Epoch, FetchKey, DIGEST_LEN};

/// Derives an agora's fetch key for one epoch.
///
/// Performed by the agora's operator, whose members receive the result through the
/// boundary broadcast (§11) rather than deriving it themselves — the input secret is not
/// member material. A member's Persora holds the broadcast key and never runs this.
#[must_use]
pub fn derive_fetch_key(agora_secret: &[u8], agora: &AgoraId, epoch: Epoch) -> FetchKey {
    let mut context = [0u8; DIGEST_LEN + 8];
    context[..DIGEST_LEN].copy_from_slice(agora.as_bytes());
    context[DIGEST_LEN..].copy_from_slice(&epoch.get().to_le_bytes());
    FetchKey::new(crate::kdf::derive(Domain::FetchKey, agora_secret, &context))
}

#[cfg(test)]
mod tests {
    use super::derive_fetch_key;
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
            derive_fetch_key(SECRET, &agora(), epoch(7)),
            derive_fetch_key(SECRET, &agora(), epoch(7))
        );
    }

    #[test]
    fn rotates_with_the_epoch() {
        assert_ne!(
            derive_fetch_key(SECRET, &agora(), epoch(7)),
            derive_fetch_key(SECRET, &agora(), epoch(8))
        );
    }

    #[test]
    fn scoped_to_the_agora() {
        assert_ne!(
            derive_fetch_key(SECRET, &agora(), epoch(7)),
            derive_fetch_key(SECRET, &AgoraId::from_bytes([0x0b; 32]), epoch(7))
        );
    }

    /// The same secret under the tag-key domain yields an unrelated key — the two epoch
    /// keys must have separate compromise stories despite one input secret.
    #[test]
    fn distinct_from_the_tag_key() {
        let fetch = derive_fetch_key(SECRET, &agora(), epoch(7));
        let tag = crate::tag::derive_tag_key(SECRET, &agora(), epoch(7));
        assert_ne!(TagKey::new(*fetch.expose()), tag);
    }
}
