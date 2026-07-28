// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key derivation.
//!
//! HKDF-SHA256, with the [`Domain`] tag and a caller-supplied context as `info`, both
//! length-framed exactly as in [`crate::Hasher`].
//!
//! The extract step is skipped (no salt): every input keying material in this design is
//! already a uniformly random secret rather than a password or a Diffie–Hellman output, so
//! expansion alone is the right construction. HKDF is used in preference to a bare hash
//! because hand-rolled key derivation is a standing audit finding even where it happens to
//! be sound.
//!
//! # What this is *not* used for
//!
//! Not for producing `sk_epoch`. Deriving epoch keys from long-lived root material would
//! let anyone who later recovers that root recompute every past epoch key, and with them
//! every past nullifier — retroactively linking a member's entire history. Epoch keys are
//! generated freshly and certified, never derived — including by a ratchet from the previous
//! epoch's key, which would extend one epoch's compromise to every epoch after it. See
//! `spec/proposals/0004-epoch-keys-are-generated.md`.

use hkdf::Hkdf;
use nymora_core::{Domain, DIGEST_LEN};
use sha2::Sha256;

/// Derives a 32-byte subkey from uniformly random input keying material.
///
/// `context` distinguishes derivations within the same domain — an epoch number, an agora
/// identifier, or whatever the call site needs to vary. It is length-framed, so no choice
/// of context can impersonate a different domain.
#[must_use]
pub fn derive(domain: Domain, ikm: &[u8], context: &[u8]) -> [u8; DIGEST_LEN] {
    let tag = domain.tag().as_bytes();
    let tag_len = (tag.len() as u64).to_le_bytes();
    let context_len = (context.len() as u64).to_le_bytes();

    let mut okm = [0u8; DIGEST_LEN];
    Hkdf::<Sha256>::new(None, ikm)
        .expand_multi_info(&[&tag_len, tag, &context_len, context], &mut okm)
        // Fails only if the output length exceeds 255 * 32 bytes, which a fixed 32-byte
        // output cannot do.
        .expect("32-byte output is within HKDF-SHA256 limits");
    okm
}

#[cfg(test)]
mod tests {
    use super::derive;
    use nymora_core::Domain;

    const IKM: &[u8] = &[0x5a; 32];

    #[test]
    fn is_deterministic() {
        assert_eq!(
            derive(Domain::TagKey, IKM, b"epoch-7"),
            derive(Domain::TagKey, IKM, b"epoch-7")
        );
    }

    #[test]
    fn domain_separates() {
        assert_ne!(
            derive(Domain::TagKey, IKM, b"epoch-7"),
            derive(Domain::LedgerHeadHandle, IKM, b"epoch-7"),
            "derivations in different domains collided"
        );
    }

    #[test]
    fn context_separates() {
        assert_ne!(
            derive(Domain::TagKey, IKM, b"epoch-7"),
            derive(Domain::TagKey, IKM, b"epoch-8"),
            "per-epoch keys collided"
        );
    }

    #[test]
    fn input_key_separates() {
        assert_ne!(
            derive(Domain::TagKey, IKM, b"epoch-7"),
            derive(Domain::TagKey, &[0x5b; 32], b"epoch-7")
        );
    }

    /// Framing must hold across the domain/context boundary too, not only within it.
    #[test]
    fn framing_makes_the_info_string_unambiguous() {
        assert_ne!(
            derive(Domain::TagKey, IKM, b"epoch-7"),
            derive(Domain::TagKey, IKM, b"-7"),
            "context boundary is malleable"
        );
    }

    /// Pins the construction, cross-checked against an independent HKDF-SHA256
    /// implementation. See the equivalent test in `hash.rs` for why a failure here is
    /// protocol-breaking rather than an expectation to update.
    #[test]
    fn known_answer() {
        assert_eq!(
            derive(Domain::TagKey, IKM, b"epoch-0"),
            [
                0x85, 0xef, 0x72, 0x4f, 0xdd, 0x41, 0x69, 0x45, 0x59, 0x89, 0xcf, 0xf5, 0x2c, 0xee,
                0x8f, 0x83, 0xb9, 0xd5, 0x05, 0x86, 0x12, 0xa4, 0xe5, 0x69, 0x96, 0x39, 0xc6, 0x66,
                0x9f, 0x39, 0x66, 0x83,
            ]
        );
    }
}
