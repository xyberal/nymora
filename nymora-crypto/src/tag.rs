// SPDX-License-Identifier: MIT OR Apache-2.0

//! Routing tags (§6.4).
//!
//! A bundle must tell a member which agora and epoch to verify it against, without carrying
//! `agora_id` in the clear — a plaintext identifier would let any observer confirm group
//! affiliation for tagged content without breaking a single proof.
//!
//! ```text
//! tag = HMAC(K_tag_e, message_hash)
//! ```
//!
//! To anyone without the key the result is indistinguishable from random: fixed width, no
//! structure, no label, no length variation. To a member it is resolved by trying the keys
//! they hold — see [`resolve`], and the constraint that governs how.
//!
//! This is the byte family (see the crate documentation): a tag is never recomputed inside
//! a circuit, so nothing about its construction waits on the proving system.

use hmac::{Hmac, Mac};
use nymora_core::{AgoraId, Domain, Epoch, MessageHash, Tag, TagKey, DIGEST_LEN};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Derives an agora's tag key for one epoch.
///
/// Performed by the agora, whose members receive the result through attribute-based
/// encryption rather than deriving it themselves — `agora_secret` is not member material.
/// A member's Persora holds the broadcast keys and never runs this.
#[must_use]
pub fn derive_tag_key(agora_secret: &[u8], agora: &AgoraId, epoch: Epoch) -> TagKey {
    let mut context = [0u8; DIGEST_LEN + 8];
    context[..DIGEST_LEN].copy_from_slice(agora.as_bytes());
    context[DIGEST_LEN..].copy_from_slice(&epoch.get().to_le_bytes());
    TagKey::new(crate::kdf::derive(Domain::TagKey, agora_secret, &context))
}

/// Computes the routing tag for a message.
///
/// # Why the message carries no domain tag
///
/// Everything else in this crate absorbs a [`Domain`] before its inputs. This does not, and the
/// difference is deliberate rather than an omission: HMAC's separation comes from the key, and
/// `K_tag_e` is already bound to a domain, an agora, and an epoch by
/// [`derive_tag_key`]. It has exactly one consumer — this function — so a second separation on
/// the message side would guard against a collision with a use that does not exist.
///
/// Should `K_tag_e` ever acquire a second purpose, the answer is a second domain tag in its
/// derivation, not a prefix on this message. That keeps one rule rather than two.
#[must_use]
pub fn tag(key: &TagKey, message: &MessageHash) -> Tag {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.expose())
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(message.as_bytes());
    Tag::from_bytes(mac.finalize().into_bytes().into())
}

/// Finds which held key produced a tag, in time independent of the answer.
///
/// Returns the index of the first matching key, or `None`.
///
/// # Why this does not stop at the first match
///
/// §16.4 requires that the trial loop "must not vary observably in duration according to
/// which key matched." A loop that returned early would take time proportional to the
/// position of the match, and since a member's key list is ordered by agora and epoch, that
/// duration would tell an observer *which agora* a bundle belongs to — recovering exactly
/// the fact §6.4 exists to hide, without touching the cryptography at all.
///
/// So every key is tried, comparison is constant-time, and the index is selected without
/// branching. That the answer is `Some` or `None` is still observable, and must be: the
/// member has to act on it. Only *which* key matched is protected.
///
/// The cost is linear in held keys — agoras multiplied by cached epochs (§16.4) — and paid
/// in full on every bundle, including ones addressed to nobody.
#[must_use]
pub fn resolve(keys: &[TagKey], message: &MessageHash, target: &Tag) -> Option<usize> {
    resolve_with(keys.len(), target, |i| tag(&keys[i], message))
}

/// The branchless selection loop, factored out so a test can count its iterations.
fn resolve_with<F>(count: usize, target: &Tag, mut candidate: F) -> Option<usize>
where
    F: FnMut(usize) -> Tag,
{
    let mut found = Choice::from(0u8);
    let mut index = 0u64;

    for i in 0..count {
        let hit = candidate(i).as_bytes().ct_eq(target.as_bytes());
        // Keep the first match: take this index only if it matched and nothing has yet.
        let take = hit & !found;
        index = u64::conditional_select(&index, &(i as u64), take);
        found |= hit;
    }

    if bool::from(found) {
        Some(index as usize)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_tag_key, resolve, resolve_with, tag};
    use nymora_core::{AgoraId, Epoch, MessageHash, Tag, TagKey};
    use std::vec::Vec;

    fn message(byte: u8) -> MessageHash {
        MessageHash::from_bytes([byte; 32])
    }

    fn keys(count: u8) -> Vec<TagKey> {
        (0..count).map(|i| TagKey::new([i; 32])).collect()
    }

    #[test]
    fn is_deterministic() {
        let key = TagKey::new([7; 32]);
        assert_eq!(tag(&key, &message(1)), tag(&key, &message(1)));
    }

    #[test]
    fn different_keys_and_messages_separate() {
        assert_ne!(
            tag(&TagKey::new([7; 32]), &message(1)),
            tag(&TagKey::new([8; 32]), &message(1))
        );
        assert_ne!(
            tag(&TagKey::new([7; 32]), &message(1)),
            tag(&TagKey::new([7; 32]), &message(2))
        );
    }

    /// Per-agora and per-epoch isolation of the broadcast key (§5.1, §6.4).
    #[test]
    fn tag_keys_are_scoped_to_one_agora_and_epoch() {
        let secret = [0x33; 32];
        let (a, b) = (AgoraId::from_bytes([1; 32]), AgoraId::from_bytes([2; 32]));
        assert_ne!(
            derive_tag_key(&secret, &a, Epoch::ZERO),
            derive_tag_key(&secret, &b, Epoch::ZERO),
            "two agoras derived the same tag key"
        );
        assert_ne!(
            derive_tag_key(&secret, &a, Epoch::ZERO),
            derive_tag_key(&secret, &a, Epoch::new(1)),
            "an agora reused a tag key across epochs"
        );
    }

    #[test]
    fn resolves_the_matching_key() {
        let held = keys(4);
        let target = tag(&held[2], &message(1));
        assert_eq!(resolve(&held, &message(1), &target), Some(2));
    }

    #[test]
    fn reports_no_match_for_a_foreign_tag() {
        let held = keys(4);
        let target = tag(&TagKey::new([200; 32]), &message(1));
        assert_eq!(resolve(&held, &message(1), &target), None);
    }

    #[test]
    fn a_matching_key_does_not_help_a_different_message() {
        let held = keys(4);
        let target = tag(&held[2], &message(1));
        assert_eq!(resolve(&held, &message(9), &target), None);
    }

    /// Pins the construction, cross-checked against an independent HMAC-SHA256 implementation.
    ///
    /// This construction is settled — a tag never enters a circuit — so a change here is a
    /// protocol break rather than an expectation to update. It is also the break that hides
    /// best: a member computing tags differently resolves every bundle to `None`, which is
    /// indistinguishable from content simply not being addressed to them.
    #[test]
    fn known_answer() {
        assert_eq!(
            tag(
                &TagKey::new([0x07; 32]),
                &MessageHash::from_bytes([0xaa; 32])
            )
            .as_bytes(),
            &[
                0x6b, 0x05, 0x14, 0x99, 0x00, 0x9e, 0x0f, 0x5d, 0x50, 0x64, 0x48, 0x1b, 0x95, 0x23,
                0x2e, 0xd8, 0x97, 0x8a, 0xfc, 0x5e, 0x82, 0xff, 0xbf, 0xcf, 0xeb, 0x52, 0xa1, 0x0c,
                0xd1, 0xb5, 0x0f, 0x1f,
            ]
        );
    }

    /// The key carries the separation, so the derivation and the tag must be pinned together.
    #[test]
    fn known_answer_for_a_derived_key() {
        let key = derive_tag_key(&[0x5a; 32], &AgoraId::from_bytes([0x7e; 32]), Epoch::new(7));
        assert_eq!(
            key.expose(),
            &[
                0x75, 0xdc, 0x57, 0xd1, 0x1d, 0x4d, 0x1f, 0x04, 0x92, 0xf7, 0x15, 0x1b, 0xb6, 0x5f,
                0xcd, 0x34, 0x6e, 0x69, 0x86, 0xc6, 0x9d, 0xc8, 0x34, 0x29, 0xa7, 0xc3, 0xf4, 0xac,
                0xfb, 0xca, 0x60, 0x95,
            ]
        );
    }

    /// The §16.4 property, tested structurally rather than by timing.
    ///
    /// Wall-clock measurement is too noisy to assert on in a unit test, but the property
    /// that makes the loop constant-duration is that it performs the same work regardless
    /// of the answer. Counting the trials proves exactly that, deterministically: a `break`
    /// on match — the obvious optimisation, and the one a future reader will be tempted by
    /// — fails this immediately.
    #[test]
    fn every_key_is_tried_whatever_the_answer() {
        let target = Tag::from_bytes([0xaa; 32]);
        let hit = |i: usize, at: usize| {
            if i == at {
                target
            } else {
                Tag::from_bytes([0; 32])
            }
        };

        for at in [0, 3, 7] {
            let mut trials = 0;
            let found = resolve_with(8, &target, |i| {
                trials += 1;
                hit(i, at)
            });
            assert_eq!(found, Some(at));
            assert_eq!(trials, 8, "loop short-circuited on a match at index {at}");
        }

        let mut trials = 0;
        let found = resolve_with(8, &target, |_| {
            trials += 1;
            Tag::from_bytes([0; 32])
        });
        assert_eq!(found, None);
        assert_eq!(trials, 8, "a miss did less work than a hit");
    }

    /// Two keys producing the same tag is a collision, not a supported case; the first wins.
    #[test]
    fn duplicate_matches_resolve_to_the_first() {
        let target = Tag::from_bytes([0xaa; 32]);
        assert_eq!(resolve_with(4, &target, |_| target), Some(0));
    }
}
