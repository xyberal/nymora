// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nullifier derivation.
//!
//! A nullifier is how the protocol enforces "at most once" without learning who. The
//! verifier keeps a set of seen values and rejects repeats; because the derivation is
//! deterministic, the same member acting twice in the same context produces the same value,
//! and because it is a hash of a secret, nobody can tell which member that is.
//!
//! # Anything counted takes the durable key
//!
//! The window over which "once" is enforced is the lifetime of the key that produced the
//! nullifier — derive the same context under a fresh key and the result is an unrelated
//! value the verifier cannot recognise as a repeat. Three of the four functions here exist
//! so that something can be *counted*, so all three take [`CredentialKey`] (§9.1):
//!
//! | | Key | What the count protects |
//! |---|---|---|
//! | [`vouch`] | [`CredentialKey`] | A k-of-n admission threshold (§5.3) |
//! | [`policy`] | [`CredentialKey`] | One approval per credential (§4.3) |
//! | [`migration`] | [`CredentialKey`] | One successor per credential (§9.3) |
//! | [`attestation`] | [`EpochSecretKey`] | Nothing load-bearing — see below |
//!
//! The epoch key cannot serve a count, and not because epochs are short. Certifying an
//! epoch key is purely local (§9.1), so a member can certify a *second* one for the same
//! epoch whenever they like and produce two nullifiers for one action. The verifier cannot
//! detect it: `pk_epoch` is a private witness, and publishing it to expose duplicates would
//! reintroduce the same-epoch linkability keeping it private prevents. Enforcing
//! one-key-per-epoch in the client is worthless, since the member who would exploit it owns
//! the device.
//!
//! [`attestation`] keeps the epoch key deliberately. It is the one context whose objects are
//! public, so a durable key would let anyone holding it sweep every published bundle and
//! attribute a member's content retroactively — and its uniqueness is the least load-bearing,
//! since the replay §6.1 cites it for is already prevented by the proof's binding to
//! `message_hash`.
//!
//! # Agora scoping
//!
//! Contexts that could otherwise collide across agoras absorb the [`AgoraId`], so that one
//! member's actions in two agoras are unlinkable and a nullifier from one cannot be replayed
//! into another (§5.1, §6.1).

use crate::algebraic::AlgebraicHasher;
use nymora_core::{AgoraId, CredentialKey, Domain, EpochSecretKey, MessageHash, Nullifier};

/// Scopes one vouching attestation to one admission session (§5.3).
///
/// Enforces that a single credential counts once toward a k-of-n threshold. `session_id` is
/// the opaque identifier Skiora issues at `vouch/session/start`; it is absorbed as raw bytes
/// and never interpreted here.
///
/// This nullifier is not agora-scoped: a session identifier is already unique to the agora
/// that issued it, and absorbing the `agora_id` alongside it would add nothing.
#[must_use]
pub fn vouch(key: &CredentialKey, session_id: &[u8]) -> Nullifier {
    Nullifier::from_bytes(
        AlgebraicHasher::new(Domain::NullifierVouch)
            .absorb(key.expose())
            .absorb(session_id)
            .finalize(),
    )
}

/// Binds an authorship attestation to one message within one agora (§6.1).
///
/// Corroboration (§6.3) is deferred, and would have shared this derivation: a member who
/// authored a message would produce the identical nullifier when corroborating it, making
/// self-corroboration impossible as a consequence of the shared context rather than by a
/// separate check. If corroboration returns, that property returns with it — along with the
/// key-lifetime question the module documentation describes, since a message accepts
/// corroborations indefinitely.
#[must_use]
pub fn attestation(key: &EpochSecretKey, message: &MessageHash, agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(
        AlgebraicHasher::new(Domain::NullifierAttestation)
            .absorb(key.expose())
            .absorb(message.as_bytes())
            .absorb(agora.as_bytes())
            .finalize(),
    )
}

/// Enforces one approval per credential on a policy proposal (§4.3).
///
/// `proposal_id` is the identifier under which approvals accumulate. Proposals still expire
/// with the epoch that raised them, but for quorum freshness rather than for anything to do
/// with this nullifier: a proposal outliving its membership set would accumulate approvals
/// against a threshold that no longer describes the group (§4.3).
#[must_use]
pub fn policy(key: &CredentialKey, proposal_id: &[u8], agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(
        AlgebraicHasher::new(Domain::NullifierPolicy)
            .absorb(key.expose())
            .absorb(proposal_id)
            .absorb(agora.as_bytes())
            .finalize(),
    )
}

/// Consumes a credential's old leaf during device migration (§9.3).
///
/// This is what stops a still-live old key from spawning more than one successor credential,
/// so it must remain unique for the life of the credential. A leaf sits in the accumulator
/// indefinitely, which is why migration was the first context to require the durable key —
/// the others followed once it became clear the epoch key cannot support a count at all.
#[must_use]
pub fn migration(key: &CredentialKey, agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(
        AlgebraicHasher::new(Domain::NullifierMigration)
            .absorb(key.expose())
            .absorb(agora.as_bytes())
            .finalize(),
    )
}

#[cfg(test)]
mod tests {
    use super::{attestation, migration, policy, vouch};
    use nymora_core::{AgoraId, CredentialKey, EpochSecretKey, MessageHash};

    fn epoch_key(byte: u8) -> EpochSecretKey {
        EpochSecretKey::new([byte; 32])
    }

    /// A credential key over the *same bytes* as [`epoch_key`].
    ///
    /// Deliberate: the collision test below must isolate the domain tag as the only
    /// difference between contexts. Different key bytes would make it pass trivially.
    fn cred_key(byte: u8) -> CredentialKey {
        CredentialKey::new([byte; 32])
    }

    fn agora(byte: u8) -> AgoraId {
        AgoraId::from_bytes([byte; 32])
    }

    fn message(byte: u8) -> MessageHash {
        MessageHash::from_bytes([byte; 32])
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            attestation(&epoch_key(1), &message(2), &agora(3)),
            attestation(&epoch_key(1), &message(2), &agora(3)),
            "the same member acting twice must be detectable"
        );
    }

    #[test]
    fn different_members_differ() {
        assert_ne!(
            attestation(&epoch_key(1), &message(2), &agora(3)),
            attestation(&epoch_key(9), &message(2), &agora(3))
        );
    }

    /// Per-agora isolation (§5.1): the same member, same message, two agoras.
    ///
    /// Equal values here would let an observer holding both bundles confirm that one member
    /// belongs to both agoras — the exact correlation §16 bounds.
    #[test]
    fn the_same_member_is_unlinkable_across_agoras() {
        assert_ne!(
            attestation(&epoch_key(1), &message(2), &agora(3)),
            attestation(&epoch_key(1), &message(2), &agora(4)),
            "one member's activity correlated across two agoras"
        );
    }

    /// A nullifier from one context must not be replayable in another.
    ///
    /// Every derivation absorbs the same key bytes first, so only the domain tag separates
    /// them. If two shared a tag, an approval could be replayed as a vouch, or a migration
    /// could be spent as an attestation.
    #[test]
    fn contexts_do_not_collide() {
        let (e, c, a) = (epoch_key(1), cred_key(1), agora(3));
        let all = [
            vouch(&c, b"session"),
            attestation(&e, &message(0), &a),
            policy(&c, b"session", &a),
            migration(&c, &a),
        ];
        for (i, x) in all.iter().enumerate() {
            for y in &all[i + 1..] {
                assert_ne!(x, y, "two nullifier contexts collided");
            }
        }
    }

    /// `vouch` and `policy` take caller-supplied identifiers of arbitrary length.
    #[test]
    fn identifier_boundaries_are_not_malleable() {
        assert_ne!(vouch(&cred_key(1), b"ab"), vouch(&cred_key(1), b"a"));
        assert_ne!(
            policy(&cred_key(1), b"ab", &agora(3)),
            policy(&cred_key(1), b"a", &agora(3))
        );
    }
}
