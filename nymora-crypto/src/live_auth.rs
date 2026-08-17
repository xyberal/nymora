// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live-authentication derivations (§8.1, §8.3).
//!
//! The commit-reveal-derive mechanism: every participant commits to a fresh nonce, all
//! reveal once all have committed, and the session context is derived from every
//! contribution together — so no coalition short of the whole session can precompute a
//! pseudonym or bias the context toward one it has prepared a replay against. This module
//! is the derivations only; the *sequencing* (all commitments before any reveal, abort on
//! duplicate commitments, periodic refresh for late joiners) is a protocol state machine
//! and lives above, in `nymora-protocol`.
//!
//! # Two families in one session
//!
//! The pseudonym is recomputed **inside the circuit** — the proof statement includes
//! "`pseudonym_i` correctly derived" (§8.1) — so [`pseudonym`] is the algebraic family:
//! the uniform action derivation at its own tag (proposal 0035). Everything else here is
//! checked by peers and by people, never by a circuit: [`commitment`] is recomputed by
//! peers at reveal, [`context`] by every participant independently, and [`sas`] is read
//! aloud (§8.3). Those are byte-family, and their vectors are permanent.
//!
//! # Why the SAS truncation is pinned here
//!
//! §8.3's defense is people comparing values across devices, which only works if every
//! implementation computes the *same* value: the digest and its truncation are protocol,
//! pinned by [`SAS_LEN`] and its vector. How the bytes render — digits, words, emoji — is
//! the client's presentation and deliberately unpinned.

use crate::field::{self, F};
use crate::hash::ByteHasher;
use crate::poseidon;
use nymora_core::{
    field_domain, AgoraId, Domain, EpochSecretKey, SessionCommitment, SessionContext,
    SessionPseudonym,
};

/// Width of a session nonce and of its blinding, in bytes.
///
/// The spec leaves the widths open; interoperability does not. Both values must carry real
/// entropy from the device's secure random source — the nonce is what makes the context
/// unpredictable, and the blinding is what keeps the nonce hidden until reveal.
pub const NONCE_LEN: usize = 32;

/// Width of the short authentication string, in bytes.
///
/// 32 bits: enough that a manipulated context escapes notice with probability ~2⁻³²
/// against a one-shot attack — the SAS is confirmed once per session, so an attacker gets
/// one try — while remaining short enough to read aloud in any rendering.
pub const SAS_LEN: usize = 4;

/// A participant's commitment over their nonce and blinding (§8.1 step 1).
///
/// Posted before any participant reveals, and checked by every peer at reveal by
/// recomputing it from the revealed pair. Framing makes the nonce/blinding boundary
/// immovable, so a participant cannot reveal a different split of the same bytes.
#[must_use]
pub fn commitment(nonce: &[u8; NONCE_LEN], blinding: &[u8; NONCE_LEN]) -> SessionCommitment {
    SessionCommitment::from_bytes(
        ByteHasher::new(Domain::LiveAuthCommitment)
            .absorb(nonce)
            .absorb(blinding)
            .finalize(),
    )
}

/// The jointly-derived session context, `context_id` (§8.1 step 3).
///
/// Sorts the nonces in place — ascending byte-lexicographic — so the input is canonical
/// without any participant identifier, which suits a setting where participants are
/// anonymous to each other; every participant computes the identical value regardless of
/// arrival order. The participant count is absorbed so a session of one size cannot be
/// reinterpreted as one of another, and the combination is a hash rather than XOR so that
/// contributing a value equal to another's cancels nothing (§8.1).
///
/// `channel_metadata` should incorporate something from the underlying channel's own key
/// exchange where one exists (§8.1); it is absorbed last, as raw bytes this function never
/// interprets.
#[must_use]
pub fn context(nonces: &mut [[u8; NONCE_LEN]], channel_metadata: &[u8]) -> SessionContext {
    nonces.sort_unstable();
    let mut hasher =
        ByteHasher::new(Domain::LiveAuthContext).absorb(&(nonces.len() as u64).to_le_bytes());
    for nonce in nonces.iter() {
        hasher = hasher.absorb(nonce);
    }
    SessionContext::from_bytes(hasher.absorb(channel_metadata).finalize())
}

/// The short authentication string for a finalized context (§8.3).
///
/// The first [`SAS_LEN`] bytes of the byte-family hash of the context under its own domain
/// tag. Every participant's device computes this identically and the people present
/// confirm the values match — the one check in the protocol whose verifier is human, kept
/// deliberately independent of any transport guarantee.
#[must_use]
pub fn sas(context: &SessionContext) -> [u8; SAS_LEN] {
    let digest = ByteHasher::new(Domain::LiveAuthSas)
        .absorb(context.as_bytes())
        .finalize();
    let mut short = [0u8; SAS_LEN];
    short.copy_from_slice(&digest[..SAS_LEN]);
    short
}

/// A participant's pseudonym within one session (§8.1 step 4, proposal 0018).
///
/// Takes the **epoch key**, by 0005's rule that a distinctness key is scoped to the window
/// it guards: a pseudonym guards continuity within one conversation, nothing is counted,
/// and a durable key would let whoever later obtains it recompute the pseudonym for every
/// recorded session the credential ever joined. The agora is absorbed last, after the
/// context it scopes — the same convention and the same defence-in-depth argument as every
/// nullifier derivation (proposals 0013, 0017): distinctness across agoras must not rest
/// on every participant's randomness being correct.
///
/// The circuit recomputes this value, so it is the uniform action derivation at tag 3
/// (proposal 0035): `Poseidon(ACTION, 3, sk_epoch, context_id, agora_id)`, the context
/// entering the field by the identifier rule.
#[must_use]
pub fn pseudonym(
    key: &EpochSecretKey,
    context: &SessionContext,
    agora: &AgoraId,
) -> SessionPseudonym {
    SessionPseudonym::from_bytes(field::to_bytes(&poseidon::hash(&[
        F::from(field_domain::ACTION),
        F::from(field_domain::action_tag::LIVE_AUTH),
        field::from_witness_bytes(key.expose()),
        field::from_id(context.as_bytes()),
        field::from_id(agora.as_bytes()),
    ])))
}

#[cfg(test)]
mod tests {
    use super::{commitment, context, sas, NONCE_LEN, SAS_LEN};
    use nymora_core::SessionContext;

    #[test]
    fn a_commitment_opens_only_to_its_own_pair() {
        let base = commitment(&[0xaa; NONCE_LEN], &[0xbb; NONCE_LEN]);
        assert_eq!(base, commitment(&[0xaa; NONCE_LEN], &[0xbb; NONCE_LEN]));
        assert_ne!(base, commitment(&[0xab; NONCE_LEN], &[0xbb; NONCE_LEN]));
        assert_ne!(base, commitment(&[0xaa; NONCE_LEN], &[0xbc; NONCE_LEN]));
    }

    /// Every participant must derive the identical context, whatever order the reveals
    /// arrived in — that is what sorting is for.
    #[test]
    fn the_context_is_order_independent() {
        let mut one = [[0xcc; NONCE_LEN], [0x11; NONCE_LEN], [0x77; NONCE_LEN]];
        let mut two = [[0x11; NONCE_LEN], [0x77; NONCE_LEN], [0xcc; NONCE_LEN]];
        assert_eq!(context(&mut one, b"channel"), context(&mut two, b"channel"));
    }

    /// §8.1: a participant contributing a value equal to another's gains nothing — under a
    /// hash the duplicated field still changes the input, unlike XOR where it cancels.
    #[test]
    fn a_duplicated_nonce_does_not_cancel() {
        let mut with_duplicate = [[0x42; NONCE_LEN], [0x42; NONCE_LEN]];
        let mut without = [[0x42; NONCE_LEN]];
        assert_ne!(
            context(&mut with_duplicate, b"channel"),
            context(&mut without, b"channel"),
            "a duplicated contribution cancelled out"
        );
    }

    #[test]
    fn the_context_binds_its_channel_metadata() {
        let mut one = [[0x42; NONCE_LEN]];
        let mut two = [[0x42; NONCE_LEN]];
        assert_ne!(
            context(&mut one, b"channel-1"),
            context(&mut two, b"channel-2")
        );
    }

    #[test]
    fn the_sas_is_deterministic_and_short() {
        let context = SessionContext::from_bytes([0xdd; 32]);
        assert_eq!(sas(&context), sas(&context));
        assert_eq!(sas(&context).len(), SAS_LEN);
        assert_ne!(
            sas(&context),
            sas(&SessionContext::from_bytes([0xde; 32])),
            "two contexts rendered the same SAS"
        );
    }

    mod pseudonym {
        use super::super::pseudonym;
        use nymora_core::{AgoraId, EpochSecretKey, SessionContext};

        fn key(byte: u8) -> EpochSecretKey {
            EpochSecretKey::new([byte; 32])
        }

        fn ctx(byte: u8) -> SessionContext {
            SessionContext::from_bytes([byte; 32])
        }

        fn agora(byte: u8) -> AgoraId {
            AgoraId::from_bytes([byte; 32])
        }

        /// Within-session Sybil detection rests on this: the same credential in the same
        /// session produces the identical value, visibly.
        #[test]
        fn is_deterministic() {
            assert_eq!(
                pseudonym(&key(1), &ctx(2), &agora(3)),
                pseudonym(&key(1), &ctx(2), &agora(3))
            );
        }

        #[test]
        fn distinct_participants_are_distinct() {
            assert_ne!(
                pseudonym(&key(1), &ctx(2), &agora(3)),
                pseudonym(&key(9), &ctx(2), &agora(3))
            );
        }

        /// §8.2's boundary: continuity is per-context, so a new session means a new
        /// pseudonym even for the same key.
        #[test]
        fn a_new_context_is_a_new_pseudonym() {
            assert_ne!(
                pseudonym(&key(1), &ctx(2), &agora(3)),
                pseudonym(&key(1), &ctx(4), &agora(3))
            );
        }

        /// Proposal 0018: the same key and the same context in two agoras must differ —
        /// by construction, not because contexts happen never to repeat.
        #[test]
        fn the_same_session_shape_is_unlinkable_across_agoras() {
            assert_ne!(
                pseudonym(&key(1), &ctx(2), &agora(3)),
                pseudonym(&key(1), &ctx(2), &agora(4)),
                "one member's presence correlated across two agoras"
            );
        }
    }
}
