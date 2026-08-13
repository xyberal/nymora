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
//! | [`migration`] | [`CredentialKey`] | One successor per leaf (§9.3) |
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
//! Every derivation absorbs the [`AgoraId`], so that one member's actions in two agoras are
//! unlinkable and a nullifier from one cannot be replayed into another (§5.1, §6.1) — by
//! construction, not because per-agora identifiers happen to be distinct or because key
//! material was correctly generated fresh per agora (proposals 0013, 0017).

use crate::algebraic::AlgebraicHasher;
use nymora_core::{
    AgoraId, Commitment, CredentialKey, Domain, EpochSecretKey, MessageHash, Nullifier,
};

/// Scopes one vouching attestation to one admission session (§5.3).
///
/// Enforces that a single credential counts once toward a k-of-n threshold. `session_id` is
/// the opaque identifier Skiora issues at `vouch/session/start`; it is absorbed as raw bytes
/// and never interpreted here.
///
/// The agora is absorbed even though a session identifier looks unique enough without it:
/// session identifiers are issued by Skiora, an adversary in this threat model, and two
/// colluding Skioras can issue the *same* one. Cross-agora distinctness must survive that and
/// a key-generation bug reusing `sk_cred` across agoras — the defence-in-depth argument of
/// proposal 0013, applied here by proposal 0017 — rather than rest on either being absent.
#[must_use]
pub fn vouch(key: &CredentialKey, session_id: &[u8], agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(
        AlgebraicHasher::new(Domain::NullifierVouch)
            .absorb(key.expose())
            .absorb(session_id)
            .absorb(agora.as_bytes())
            .finalize(),
    )
}

/// Binds an authorship attestation to one message within one agora (§6.1).
///
/// Corroboration (§6.3) is deferred, and would have shared this derivation: a member
/// corroborating a message they authored in the same epoch would reproduce the authorship
/// nullifier, making same-epoch self-corroboration visible without a separate check — and
/// only same-epoch, since the key dies with its epoch (§9.1). If corroboration returns,
/// that property and its limit return with it — along with the
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
/// This is what stops a still-live old key from spawning more than one successor from the
/// same leaf, and — under §9.1's currency clauses — what a superseded device can no longer
/// show unspent. A leaf sits in the accumulator indefinitely, which is why migration was the
/// first context to require the durable key — the others followed once it became clear the
/// epoch key cannot support a count at all.
///
/// The consumed leaf is bound in, not only the credential. `sk_cred` carries across the
/// lineage deliberately (§9.3), so a derivation over the key alone would be constant for the
/// credential's life: spent once at the first migration and colliding at every one after it,
/// capping every credential at a single device change. Binding the leaf gives each migration
/// its own spend while one leaf still admits exactly one successor.
#[must_use]
pub fn migration(key: &CredentialKey, leaf: &Commitment, agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(
        AlgebraicHasher::new(Domain::NullifierMigration)
            .absorb(key.expose())
            .absorb(leaf.as_bytes())
            .absorb(agora.as_bytes())
            .finalize(),
    )
}

#[cfg(test)]
mod tests {
    use super::{attestation, migration, policy, vouch};
    use nymora_core::{AgoraId, Commitment, CredentialKey, EpochSecretKey, MessageHash};

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

    fn leaf(byte: u8) -> Commitment {
        Commitment::from_bytes([byte; 32])
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
            vouch(&c, b"session", &a),
            attestation(&e, &message(0), &a),
            policy(&c, b"session", &a),
            migration(&c, &leaf(0), &a),
        ];
        for (i, x) in all.iter().enumerate() {
            for y in &all[i + 1..] {
                assert_ne!(x, y, "two nullifier contexts collided");
            }
        }
    }

    /// A lineage migrates more than once, and each migration is its own spend.
    ///
    /// `sk_cred` is constant across the lineage (§9.3), so a derivation over the key alone
    /// would make the second planned migration reproduce the value the first already spent —
    /// indistinguishable from a double-spend, and under §9.1's unspent clause it would brick
    /// the successor outright.
    #[test]
    fn each_consumed_leaf_spends_its_own_nullifier() {
        assert_ne!(
            migration(&cred_key(1), &leaf(7), &agora(3)),
            migration(&cred_key(1), &leaf(8), &agora(3)),
            "two migrations of one lineage collided"
        );
    }

    /// `vouch` and `policy` take caller-supplied identifiers of arbitrary length.
    #[test]
    fn identifier_boundaries_are_not_malleable() {
        assert_ne!(
            vouch(&cred_key(1), b"ab", &agora(3)),
            vouch(&cred_key(1), b"a", &agora(3))
        );
        assert_ne!(
            policy(&cred_key(1), b"ab", &agora(3)),
            policy(&cred_key(1), b"a", &agora(3))
        );
    }
}
