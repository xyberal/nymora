// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbox key's cryptography (§11, proposal 0036): agreement, key derivation, the
//! lookup tag, and the authenticated encryption of the boundary ciphertexts.
//!
//! # The construction
//!
//! ```text
//! inbox keypair     (sk_inbox, pk_inbox)   X25519, minted fresh per credential
//! ephemeral keypair (sk_e, pk_e)           X25519, one per boundary, derived by the
//!                                          operator from its secret (replay-exact)
//! agreed            = X25519(sk_e, pk_inbox) = X25519(sk_inbox, pk_e)
//! seal key          = HKDF(InboxSeal, agreed, pk_e ‖ pk_inbox ‖ class)
//! lookup tag        = HKDF(InboxTag,  agreed, pk_e ‖ pk_inbox ‖ class)[..8]
//! ciphertext        = ChaCha20-Poly1305(seal key, nonce 0, ad, K_body ‖ path)
//! body              = ChaCha20-Poly1305(K_body,   nonce 0, ad, canonical body)
//! ad                = Hash(BulletinBody; agora, epoch)
//! ```
//!
//! The nonce is fixed at zero because every key here is used exactly once: a seal key is
//! unique per (ephemeral, inbox, class) and the ephemeral changes every boundary; the
//! body key is unique per epoch. Reusing either with a second message would be a bug in
//! the caller's lifecycle, not a property this module can repair — the operator derives
//! both from the epoch, so a second message under one key cannot arise from honest use.
//!
//! The associated data binds every ciphertext to one agora and one epoch, so a
//! ciphertext lifted from another envelope opens to nothing.
//!
//! # What is and is not claimed
//!
//! No forward secrecy: a stolen inbox secret opens that credential's ciphertexts until
//! the credential migrates or the registration expires — inside §15's device-compromise
//! residual. The lookup tag reveals nothing: it is a KDF output under its own domain, so
//! it says nothing about the seal key, and the ephemeral half's rotation makes the same
//! member's tag unlinkable across boundaries.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use nymora_core::{
    AgoraId, BodyKey, Domain, Epoch, InboxPublicKey, InboxSecretKey, InboxTag, PolicyClass,
    ProtocolError, SecretBytes, DIGEST_LEN, INBOX_PUBLIC_KEY_LEN, INBOX_TAG_LEN,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::hash::ByteHasher;

/// Width of the authentication tag every sealed buffer carries.
pub const SEAL_TAG_LEN: usize = 16;

/// Mints an inbox secret from fresh entropy: the X25519 clamp (RFC 7748), so the stored
/// bytes are canonical for the scalar they name.
#[must_use]
pub fn mint_inbox_secret(entropy: [u8; 32]) -> [u8; 32] {
    let mut bytes = entropy;
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    bytes
}

/// The public half of an inbox secret.
#[must_use]
pub fn inbox_public_key(secret: &InboxSecretKey) -> InboxPublicKey {
    let secret = StaticSecret::from(*secret.expose());
    InboxPublicKey::from_bytes(PublicKey::from(&secret).to_bytes())
}

/// The operator's ephemeral agreement secret for one boundary (§11, proposal 0036).
///
/// Derived from the operator secret under its own domain rather than minted, so a host
/// replaying its journal reconstructs the envelope byte for byte. "Ephemeral" describes
/// its lifetime — one boundary — not its provenance.
#[must_use]
pub fn derive_ephemeral_secret(
    agora_secret: &[u8],
    agora: &AgoraId,
    epoch: Epoch,
) -> InboxSecretKey {
    InboxSecretKey::new(mint_inbox_secret(crate::kdf::derive(
        Domain::InboxEphemeral,
        agora_secret,
        &epoch_context(agora, epoch),
    )))
}

/// The per-epoch body key, `K_body_e` (§11, proposal 0036's single-body rule).
#[must_use]
pub fn derive_body_key(agora_secret: &[u8], agora: &AgoraId, epoch: Epoch) -> BodyKey {
    BodyKey::new(crate::kdf::derive(
        Domain::BodyKey,
        agora_secret,
        &epoch_context(agora, epoch),
    ))
}

fn epoch_context(agora: &AgoraId, epoch: Epoch) -> [u8; DIGEST_LEN + 8] {
    let mut context = [0u8; DIGEST_LEN + 8];
    context[..DIGEST_LEN].copy_from_slice(agora.as_bytes());
    context[DIGEST_LEN..].copy_from_slice(&epoch.get().to_le_bytes());
    context
}

/// An agreed secret between one inbox key and one ephemeral key.
#[derive(Debug)]
pub struct Agreed(SecretBytes<32>);

/// Runs the agreement. Either side may call it: the operator with its ephemeral secret
/// and the member's inbox key, the member with its inbox secret and the envelope's
/// ephemeral key.
///
/// Returns `None` for a non-contributory result (a low-order public key), which names no
/// usable secret.
#[must_use]
pub fn agree(secret: &InboxSecretKey, public: &InboxPublicKey) -> Option<Agreed> {
    let shared =
        StaticSecret::from(*secret.expose()).diffie_hellman(&PublicKey::from(*public.as_bytes()));
    if !shared.was_contributory() {
        return None;
    }
    Some(Agreed(SecretBytes::new(*shared.as_bytes())))
}

fn seal_context(
    ephemeral: &InboxPublicKey,
    inbox: &InboxPublicKey,
    class: &PolicyClass,
) -> [u8; 2 * INBOX_PUBLIC_KEY_LEN + DIGEST_LEN] {
    let mut context = [0u8; 2 * INBOX_PUBLIC_KEY_LEN + DIGEST_LEN];
    context[..INBOX_PUBLIC_KEY_LEN].copy_from_slice(ephemeral.as_bytes());
    context[INBOX_PUBLIC_KEY_LEN..2 * INBOX_PUBLIC_KEY_LEN].copy_from_slice(inbox.as_bytes());
    context[2 * INBOX_PUBLIC_KEY_LEN..].copy_from_slice(class.as_bytes());
    context
}

/// The key one member's ciphertext for one class is sealed under.
#[must_use]
pub fn seal_key(
    agreed: &Agreed,
    ephemeral: &InboxPublicKey,
    inbox: &InboxPublicKey,
    class: &PolicyClass,
) -> SecretBytes<32> {
    SecretBytes::new(crate::kdf::derive(
        Domain::InboxSeal,
        agreed.0.expose(),
        &seal_context(ephemeral, inbox, class),
    ))
}

/// The tag a member finds their ciphertext for one class by.
#[must_use]
pub fn lookup_tag(
    agreed: &Agreed,
    ephemeral: &InboxPublicKey,
    inbox: &InboxPublicKey,
    class: &PolicyClass,
) -> InboxTag {
    let derived = crate::kdf::derive(
        Domain::InboxTag,
        agreed.0.expose(),
        &seal_context(ephemeral, inbox, class),
    );
    let mut tag = [0u8; INBOX_TAG_LEN];
    tag.copy_from_slice(&derived[..INBOX_TAG_LEN]);
    InboxTag::from_bytes(tag)
}

/// The associated data binding a ciphertext to one agora and one epoch.
#[must_use]
pub fn associated_data(agora: &AgoraId, epoch: Epoch) -> [u8; DIGEST_LEN] {
    ByteHasher::new(Domain::BulletinBody)
        .absorb(agora.as_bytes())
        .absorb(&epoch.get().to_le_bytes())
        .finalize()
}

/// Encrypts `buffer` in place under a single-use key, returning the authentication tag.
#[must_use]
pub fn seal_in_place(key: &[u8; 32], associated: &[u8], buffer: &mut [u8]) -> [u8; SEAL_TAG_LEN] {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(&Nonce::default(), associated, buffer)
        // The only failure is a buffer beyond the cipher's 2^38-byte limit.
        .expect("a bulletin ciphertext is far below the AEAD's length limit");
    tag.into()
}

/// Decrypts `buffer` in place, refusing — and leaving the buffer unreadable — unless the
/// tag authenticates it under this key and associated data.
///
/// # Errors
///
/// [`ProtocolError::Malformed`]: the ciphertext, tag, key, and associated data do not
/// agree — a property of the input, deterministically visible.
pub fn open_in_place(
    key: &[u8; 32],
    associated: &[u8],
    buffer: &mut [u8],
    tag: &[u8; SEAL_TAG_LEN],
) -> Result<(), ProtocolError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(&Nonce::default(), associated, buffer, &Tag::from(*tag))
        .map_err(|_| ProtocolError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> InboxSecretKey {
        InboxSecretKey::new(mint_inbox_secret([byte; 32]))
    }

    /// RFC 7748 §6.1: the X25519 known answer, through this module's own entry points.
    #[test]
    fn x25519_known_answer() {
        let alice = InboxSecretKey::new([
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ]);
        let bob_public = InboxPublicKey::from_bytes([
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ]);
        let expected = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        assert_eq!(
            inbox_public_key(&alice).as_bytes(),
            &[
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
                0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
                0xaa, 0x9b, 0x4e, 0x6a,
            ]
        );
        let agreed = agree(&alice, &bob_public).expect("contributory");
        assert_eq!(agreed.0.expose(), &expected);
    }

    #[test]
    fn both_sides_agree_on_the_same_secret() {
        let (a, b) = (secret(1), secret(2));
        let ab = agree(&a, &inbox_public_key(&b)).unwrap();
        let ba = agree(&b, &inbox_public_key(&a)).unwrap();
        assert_eq!(ab.0, ba.0);
    }

    #[test]
    fn a_low_order_key_agrees_on_nothing() {
        assert!(agree(&secret(1), &InboxPublicKey::from_bytes([0u8; 32])).is_none());
    }

    #[test]
    fn seal_key_and_tag_bind_every_input() {
        let agreed = agree(&secret(1), &inbox_public_key(&secret(2))).unwrap();
        let e = inbox_public_key(&secret(3));
        let i = inbox_public_key(&secret(2));
        let class_a = PolicyClass::from_bytes([0xaa; 32]);
        let class_b = PolicyClass::from_bytes([0xbb; 32]);
        assert_ne!(
            seal_key(&agreed, &e, &i, &class_a),
            seal_key(&agreed, &e, &i, &class_b)
        );
        assert_ne!(
            lookup_tag(&agreed, &e, &i, &class_a),
            lookup_tag(&agreed, &e, &i, &class_b)
        );
        assert_ne!(
            seal_key(&agreed, &e, &i, &class_a).expose()[..INBOX_TAG_LEN],
            *lookup_tag(&agreed, &e, &i, &class_a).as_bytes(),
            "the tag must not be a prefix of the key"
        );
    }

    #[test]
    fn sealed_bytes_open_only_as_sealed() {
        let key = [7u8; 32];
        let ad = associated_data(&AgoraId::from_bytes([1; 32]), Epoch::new(4));
        let mut buffer = *b"the boundary body";
        let tag = seal_in_place(&key, &ad, &mut buffer);
        assert_ne!(&buffer, b"the boundary body");

        let mut copy = buffer;
        open_in_place(&key, &ad, &mut copy, &tag).expect("opens");
        assert_eq!(&copy, b"the boundary body");

        // A different epoch's associated data, a different key, a flipped byte: refused.
        let other_ad = associated_data(&AgoraId::from_bytes([1; 32]), Epoch::new(5));
        assert!(open_in_place(&key, &other_ad, &mut buffer.clone(), &tag).is_err());
        assert!(open_in_place(&[8u8; 32], &ad, &mut buffer.clone(), &tag).is_err());
        let mut flipped = buffer;
        flipped[0] ^= 1;
        assert!(open_in_place(&key, &ad, &mut flipped, &tag).is_err());
    }

    #[test]
    fn the_ephemeral_and_body_keys_rotate_with_the_epoch() {
        let agora = AgoraId::from_bytes([0x0a; 32]);
        assert_ne!(
            derive_ephemeral_secret(&[0x5a; 32], &agora, Epoch::new(1)),
            derive_ephemeral_secret(&[0x5a; 32], &agora, Epoch::new(2))
        );
        assert_ne!(
            derive_body_key(&[0x5a; 32], &agora, Epoch::new(1)),
            derive_body_key(&[0x5a; 32], &agora, Epoch::new(2))
        );
    }
}
