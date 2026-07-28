// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nullifier derivation.
//!
//! A nullifier is how the protocol enforces "at most once" without learning who. The
//! verifier keeps a set of seen values and rejects repeats; because the derivation is
//! deterministic, the same member acting twice in the same context produces the same value,
//! and because it is a hash of a secret, nobody can tell which member that is.
//!
//! # Uniqueness lasts exactly as long as the key
//!
//! The window over which "once" is enforced is the lifetime of the key that produced the
//! nullifier — derive the same context under a fresh key and the result is an unrelated
//! value the verifier cannot recognise as a repeat. So each function takes the key whose
//! lifetime matches the object it guards (§9.1):
//!
//! - [`vouch`], [`attestation`], and [`policy`] guard objects bounded to one epoch — a
//!   vouch session must finalize within its epoch (§5.3) and a policy proposal expires at
//!   the end of its own (§4.3) — so they take [`EpochSecretKey`].
//! - [`migration`] guards an accumulator leaf, which has no bound at all, so it takes the
//!   durable [`MigrationKey`].
//!
//! The two are distinct types rather than one, because substituting the epoch key into
//! `migration` would silently turn a permanent guarantee into a per-epoch one — and the
//! failure would not appear until a rollover, in production, as a member spawning a second
//! credential from the same leaf.
//!
//! # Agora scoping
//!
//! Contexts that could otherwise collide across agoras absorb the [`AgoraId`], so that one
//! member's actions in two agoras are unlinkable and a nullifier from one cannot be replayed
//! into another (§5.1, §6.1).

use crate::algebraic::AlgebraicHasher;
use nymora_core::{AgoraId, Domain, EpochSecretKey, MessageHash, MigrationKey, Nullifier};

/// Scopes one vouching attestation to one admission session (§5.3).
///
/// Enforces that a single credential counts once toward a k-of-n threshold. `session_id` is
/// the opaque identifier Skiora issues at `vouch/session/start`; it is absorbed as raw bytes
/// and never interpreted here.
///
/// This nullifier is not agora-scoped: a session identifier is already unique to the agora
/// that issued it, and absorbing the `agora_id` alongside it would add nothing.
#[must_use]
pub fn vouch(key: &EpochSecretKey, session_id: &[u8]) -> Nullifier {
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
/// `proposal_id` is the identifier under which approvals accumulate. This is sound only
/// because a proposal expires at the end of the epoch in which it was raised (§4.3): a
/// longer-lived proposal would outlast the key counting its approvals, and the same
/// credential could approve it again under the next epoch's key.
#[must_use]
pub fn policy(key: &EpochSecretKey, proposal_id: &[u8], agora: &AgoraId) -> Nullifier {
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
/// This is what stops a still-live old key from spawning more than one successor
/// credential, so it must remain unique for the life of the credential rather than the life
/// of an epoch — a migration nullifier that changed on rollover would permit one successor
/// per epoch, which is precisely the outcome §9.3 exists to prevent.
#[must_use]
pub fn migration(key: &MigrationKey, agora: &AgoraId) -> Nullifier {
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
    use nymora_core::{AgoraId, EpochSecretKey, MessageHash, MigrationKey};

    fn key(byte: u8) -> EpochSecretKey {
        EpochSecretKey::new([byte; 32])
    }

    /// A migration key over the *same bytes* as [`key`].
    ///
    /// Deliberate: the collision test below must isolate the domain tag as the only
    /// difference between contexts. Different key bytes would make it pass trivially.
    fn migration_key(byte: u8) -> MigrationKey {
        MigrationKey::new([byte; 32])
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
            attestation(&key(1), &message(2), &agora(3)),
            attestation(&key(1), &message(2), &agora(3)),
            "the same member acting twice must be detectable"
        );
    }

    #[test]
    fn different_members_differ() {
        assert_ne!(
            attestation(&key(1), &message(2), &agora(3)),
            attestation(&key(9), &message(2), &agora(3))
        );
    }

    /// Per-agora isolation (§5.1): the same member, same message, two agoras.
    ///
    /// Equal values here would let an observer holding both bundles confirm that one member
    /// belongs to both agoras — the exact correlation §16 bounds.
    #[test]
    fn the_same_member_is_unlinkable_across_agoras() {
        assert_ne!(
            attestation(&key(1), &message(2), &agora(3)),
            attestation(&key(1), &message(2), &agora(4)),
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
        let (k, m, a) = (key(1), migration_key(1), agora(3));
        let all = [
            vouch(&k, b"session"),
            attestation(&k, &message(0), &a),
            policy(&k, b"session", &a),
            migration(&m, &a),
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
        assert_ne!(vouch(&key(1), b"ab"), vouch(&key(1), b"a"));
        assert_ne!(
            policy(&key(1), b"ab", &agora(3)),
            policy(&key(1), b"a", &agora(3))
        );
    }
}
