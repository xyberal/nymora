// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nullifier derivation (§9.1, proposal 0035).
//!
//! A nullifier is how the protocol enforces "at most once" without learning who. The
//! verifier keeps a set of seen values and rejects repeats; because the derivation is
//! deterministic, the same member acting twice in the same context produces the same
//! value, and because it is a hash of a secret, nobody can tell which member that is.
//!
//! # One derivation, with the tag absorbed
//!
//! Every action's output derives the same way — proposal 0035's uniform clause, which
//! is §6.5's one-proof-shape rule reaching into the hash itself:
//!
//! ```text
//! output = Poseidon(ACTION, tag, key, context, agora_id)
//! ```
//!
//! The numeric tag is what keeps contexts unforgeable for one another: an approval
//! cannot be replayed as a vouch because 1 ≠ 2 inside the hash, and the statement
//! constrains the tag rather than trusting a label beside the proof. The migration
//! spend is deliberately not an action — it is a clause of both statements, keyed by
//! the leaf it consumes — and derives under its own domain ([`migration`]).
//!
//! # Anything counted takes the durable key
//!
//! The window over which "once" is enforced is the lifetime of the key that produced
//! the nullifier. Three of the four derivations exist so something can be *counted*,
//! so all three take [`CredentialKey`] (§9.1):
//!
//! | | Tag | Key | What the count protects |
//! |---|---|---|---|
//! | [`vouch`] | 1 | [`CredentialKey`] | A k-of-n admission threshold (§5.3) |
//! | [`policy`] | 2 | [`CredentialKey`] | One approval per credential (§4.3) |
//! | [`migration`] | — | [`CredentialKey`] | One successor per leaf (§9.3) |
//! | [`attestation`] | 0 | [`EpochSecretKey`] | Nothing load-bearing — see below |
//!
//! The epoch key cannot serve a count: certifying an epoch key is purely local (§9.1),
//! so a member can certify a second one for the same epoch at will and produce two
//! nullifiers for one action, undetectably — `pk_epoch` is a private witness.
//! [`attestation`] keeps the epoch key deliberately: its objects are public, so a
//! durable key would permit retroactive attribution, and its uniqueness is secondary
//! to the proof's binding to `message_hash` (§6.1).
//!
//! # Agora scoping
//!
//! Every derivation absorbs the [`AgoraId`], so one member's actions in two agoras are
//! unlinkable and a nullifier from one cannot replay into another (§5.1, §6.1) — by
//! construction, not because identifiers happen to be distinct or key material was
//! correctly generated fresh per agora (proposals 0013, 0017).
//!
//! # Keys enter as their canonical values
//!
//! A secret enters the derivation as the field element its canonical bytes name.
//! Minted keys are canonical by construction (proposal 0035); for a witnessed key the
//! *statement* asserts canonicity (§9.1) — one key, one representation, one nullifier
//! stream — and these functions decode totally, by reduction, because a value derived
//! from bytes the statement would refuse never certifies anyway.

use nymora_core::{
    field_domain, AgoraId, Commitment, CredentialKey, EpochSecretKey, MessageHash, Nullifier,
};

use crate::field::{self, F};
use crate::poseidon;

/// The uniform action derivation (§9.1, proposal 0035).
fn action_output(tag: u64, key: F, context: F, agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(field::to_bytes(&poseidon::hash(&[
        F::from(field_domain::ACTION),
        F::from(tag),
        key,
        context,
        field::from_id(agora.as_bytes()),
    ])))
}

/// Scopes one vouching attestation to one admission session (§5.3, tag 1).
///
/// `session_id` is the opaque identifier Skiora issues at `vouch/session/start`; it
/// crosses into the field by byte-family compression (proposal 0035) and is never
/// interpreted here. The agora is absorbed even though a session identifier looks
/// unique enough without it: session identifiers are issued by Skiora, an adversary in
/// this threat model, and two colluding Skioras can issue the same one (proposals
/// 0013, 0017).
#[must_use]
pub fn vouch(key: &CredentialKey, session_id: &[u8], agora: &AgoraId) -> Nullifier {
    action_output(
        field_domain::action_tag::VOUCH,
        field::from_witness_bytes(key.expose()),
        field::from_context_bytes(session_id),
        agora,
    )
}

/// Binds an authorship attestation to one message within one agora (§6.1, tag 0).
///
/// Corroboration (§6.3) is deferred, and would have shared this derivation: a member
/// corroborating a message they authored in the same epoch would reproduce the
/// authorship nullifier, making same-epoch self-corroboration visible without a
/// separate check — same-epoch only, since the key dies with its epoch (§9.1).
#[must_use]
pub fn attestation(key: &EpochSecretKey, message: &MessageHash, agora: &AgoraId) -> Nullifier {
    action_output(
        field_domain::action_tag::AUTHORSHIP,
        field::from_witness_bytes(key.expose()),
        field::from_id(message.as_bytes()),
        agora,
    )
}

/// Enforces one approval per credential on a policy proposal (§4.3, tag 2).
///
/// `proposal_id` is the identifier under which approvals accumulate. Proposals still
/// expire with the epoch that raised them, but for quorum freshness rather than for
/// anything to do with this nullifier (§4.3).
#[must_use]
pub fn policy(key: &CredentialKey, proposal_id: &[u8], agora: &AgoraId) -> Nullifier {
    action_output(
        field_domain::action_tag::POLICY,
        field::from_witness_bytes(key.expose()),
        field::from_context_bytes(proposal_id),
        agora,
    )
}

/// Consumes a credential's old leaf during device migration (§9.3):
/// `Poseidon(SPEND, sk_cred, leaf, agora_id)`.
///
/// Not an action — a clause of both statements, under its own domain. The consumed
/// leaf is bound in, not only the credential: `sk_cred` carries across the lineage
/// deliberately (§9.3), so a derivation over the key alone would be constant for the
/// credential's life — spent once at the first migration and colliding at every one
/// after it. Binding the leaf gives each migration its own spend while one leaf still
/// admits exactly one successor.
#[must_use]
pub fn migration(key: &CredentialKey, leaf: &Commitment, agora: &AgoraId) -> Nullifier {
    Nullifier::from_bytes(field::to_bytes(&poseidon::hash(&[
        F::from(field_domain::SPEND),
        field::from_witness_bytes(key.expose()),
        field::from_witness_bytes(leaf.as_bytes()),
        field::from_id(agora.as_bytes()),
    ])))
}

#[cfg(test)]
mod tests {
    use super::{attestation, migration, policy, vouch};
    use nymora_core::{AgoraId, Commitment, CredentialKey, EpochSecretKey, MessageHash};

    fn epoch_key(byte: u8) -> EpochSecretKey {
        EpochSecretKey::new([byte; 32])
    }

    /// A credential key over the *same bytes* as [`epoch_key`], so the collision test
    /// below isolates the tag as the only difference between contexts.
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
    #[test]
    fn the_same_member_is_unlinkable_across_agoras() {
        assert_ne!(
            attestation(&epoch_key(1), &message(2), &agora(3)),
            attestation(&epoch_key(1), &message(2), &agora(4)),
            "one member's activity correlated across two agoras"
        );
    }

    /// A nullifier from one context must not be replayable in another. Every counted
    /// derivation absorbs the same key first; only the in-band tag — and for
    /// migration, the domain — separates them (proposal 0035).
    #[test]
    fn contexts_do_not_collide() {
        let (e, c, a) = (epoch_key(1), cred_key(1), agora(3));
        // The identifier bytes coincide across contexts deliberately.
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

    /// A lineage migrates more than once, and each migration is its own spend (§9.3).
    #[test]
    fn each_consumed_leaf_spends_its_own_nullifier() {
        assert_ne!(
            migration(&cred_key(1), &leaf(7), &agora(3)),
            migration(&cred_key(1), &leaf(8), &agora(3)),
            "two migrations of one lineage collided"
        );
    }

    /// The byte-family framing survives into the crossing: identifier boundaries are
    /// not malleable even though the circuit only ever sees one field element.
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
