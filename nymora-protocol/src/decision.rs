// SPDX-License-Identifier: MIT OR Apache-2.0

//! Quorum decisions and their subject identifiers (§4.3, §11, §12; proposal 0021).
//!
//! # One machine, three kinds of decision
//!
//! A policy change, a revocation, and a dissolution are the same shape: *k current members
//! approved subject X*. The specification gives each a wire flow but names an approval
//! mechanism only for policy changes (§4.3); proposal 0021 settles the other two by reuse
//! rather than invention — every quorum decision is approved with the one policy-approval
//! action of §6.5's closed action set, and what distinguishes the kinds is the **subject
//! identifier**, derived under a distinct domain tag per kind. An approval nullifier is
//! derived over the subject, so an approval collected for one kind can never be presented
//! toward another, for the same reason a migration certificate cannot stand in for an epoch
//! certificate: the tag is inside the derivation.
//!
//! # The subject identifier binds the content
//!
//! A subject is not an opaque ticket. It is recomputable —
//! `Hash(kind-tag; agora, epoch, approving class, canonical content, nonce)` — and every
//! approving member **must** recompute it from the proposal content Skiora serves before
//! approving ([`subject_id`] is deliberately ungated so the member side links it). A Skiora
//! that shows different content to different members under one identifier is caught by the
//! recomputation; one that uses two identifiers for the same content splits the approvals
//! and reaches quorum with neither. The nonce keeps two textually identical proposals —
//! §4.3 requires an expired proposal to be *re-raised* — from sharing an identifier and
//! therefore from inheriting each other's approval nullifiers.
//!
//! The epoch is absorbed for the same quorum-freshness rule that expires the proposal
//! (§4.3): a subject raised in one epoch cannot be re-presented in another, even by a
//! Skiora that kept the nonce.

use nymora_core::{AgoraId, Commitment, Domain, Epoch, PolicyClass};
use nymora_crypto::ByteHasher;

/// What a quorum is being asked to decide (proposal 0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Replace one class's admission arithmetic and the agora's governance quorum (§4.3).
    ///
    /// The values are the complete new state, not deltas: what members approve is exactly
    /// what activation applies, with nothing left to compose at execution time.
    Policy {
        /// The class whose admission policy changes.
        class: PolicyClass,
        /// Attestations required to admit into `class` (§5.3). At least 1
        /// (proposal 0027).
        admission_threshold: u32,
        /// Approvals required to execute any subsequent quorum decision. At least 1
        /// (proposal 0027): zero would make every execution vacuously approved.
        governance_quorum: u32,
    },
    /// Remove a credential's standing (§11). The leaf enters the revocation set and the
    /// epoch advances immediately.
    Revocation {
        /// The leaf being revoked.
        leaf: Commitment,
    },
    /// Freeze the agora permanently (§12).
    Dissolution,
}

impl Decision {
    /// The domain tag distinguishing this kind's subjects (see the module documentation).
    const fn domain(&self) -> Domain {
        match self {
            Self::Policy { .. } => Domain::ProposalPolicy,
            Self::Revocation { .. } => Domain::ProposalRevocation,
            Self::Dissolution => Domain::ProposalDissolution,
        }
    }

    /// Canonical content bytes — each field absorbed length-framed, in a fixed order per
    /// kind.
    ///
    /// Fixed layout per kind; the kind itself is carried by the domain tag, not by a
    /// discriminant byte, so the encodings need not be disjoint across kinds.
    fn absorb_content(&self, hasher: ByteHasher) -> ByteHasher {
        match self {
            Self::Policy {
                class,
                admission_threshold,
                governance_quorum,
            } => hasher
                .absorb(class.as_bytes())
                .absorb(&admission_threshold.to_le_bytes())
                .absorb(&governance_quorum.to_le_bytes()),
            Self::Revocation { leaf } => hasher.absorb(leaf.as_bytes()),
            Self::Dissolution => hasher,
        }
    }
}

/// A quorum decision's subject identifier — the value approvals accumulate under, and the
/// `proposal_id` of the policy-approval action (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectId([u8; 32]);

impl SubjectId {
    /// Borrows the identifier bytes — what the approval nullifier is derived over.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derives the subject identifier for a proposal.
///
/// Both roles compute this: Skiora when raising the proposal, and **every member from the
/// served proposal content before approving it** — the recomputation is what makes the
/// identifier a binding to the content rather than a ticket Skiora controls. `nonce` is
/// fresh per raise and served with the proposal.
#[must_use]
pub fn subject_id(
    agora: AgoraId,
    opened: Epoch,
    approving_class: PolicyClass,
    decision: &Decision,
    nonce: &[u8; 32],
) -> SubjectId {
    let hasher = ByteHasher::new(decision.domain())
        .absorb(agora.as_bytes())
        .absorb(&opened.get().to_le_bytes())
        .absorb(approving_class.as_bytes());
    SubjectId(decision.absorb_content(hasher).absorb(nonce).finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGORA: AgoraId = AgoraId::from_bytes([0x01; 32]);
    const CLASS: PolicyClass = PolicyClass::from_bytes([0x11; 32]);

    fn subject(decision: &Decision) -> SubjectId {
        subject_id(AGORA, Epoch::new(3), CLASS, decision, &[0x99; 32])
    }

    /// The 0021 property: kinds are unforgeable for one another even when their canonical
    /// content bytes coincide.
    #[test]
    fn kinds_with_identical_content_have_distinct_subjects() {
        // A revocation of leaf L and a policy change absorbing the same 32 bytes first:
        // the content encodings begin identically, the domains differ.
        let revocation = Decision::Revocation {
            leaf: Commitment::from_bytes([0x22; 32]),
        };
        let dissolution = Decision::Dissolution;
        let policy = Decision::Policy {
            class: PolicyClass::from_bytes([0x22; 32]),
            admission_threshold: 0,
            governance_quorum: 0,
        };
        let ids = [
            subject(&revocation),
            subject(&dissolution),
            subject(&policy),
        ];
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[1], ids[2]);
    }

    /// §4.3: a re-raised proposal is a new subject — approvals never carry over.
    #[test]
    fn re_raising_yields_a_fresh_subject() {
        let decision = Decision::Dissolution;
        let first = subject_id(AGORA, Epoch::new(3), CLASS, &decision, &[0x99; 32]);
        let re_raised_later = subject_id(AGORA, Epoch::new(4), CLASS, &decision, &[0x99; 32]);
        let re_raised_fresh_nonce = subject_id(AGORA, Epoch::new(3), CLASS, &decision, &[0x9a; 32]);
        assert_ne!(first, re_raised_later);
        assert_ne!(first, re_raised_fresh_nonce);
    }

    /// The binding property: any change to what is being decided changes the subject, so a
    /// member recomputing from served content catches a substitution.
    #[test]
    fn every_content_field_is_bound() {
        let base = Decision::Policy {
            class: CLASS,
            admission_threshold: 2,
            governance_quorum: 2,
        };
        let other_threshold = Decision::Policy {
            class: CLASS,
            admission_threshold: 3,
            governance_quorum: 2,
        };
        let other_quorum = Decision::Policy {
            class: CLASS,
            admission_threshold: 2,
            governance_quorum: 3,
        };
        assert_ne!(subject(&base), subject(&other_threshold));
        assert_ne!(subject(&base), subject(&other_quorum));

        let other_approvers = subject_id(
            AGORA,
            Epoch::new(3),
            PolicyClass::from_bytes([0x12; 32]),
            &base,
            &[0x99; 32],
        );
        assert_ne!(subject(&base), other_approvers);
    }

    /// The canonical bytes, pinned by independent computation (Python), because every
    /// implementation and every approving member must derive the identical subject.
    #[test]
    fn subject_derivation_matches_the_known_answer() {
        let subject = subject_id(
            AGORA,
            Epoch::new(3),
            CLASS,
            &Decision::Revocation {
                leaf: Commitment::from_bytes([0x22; 32]),
            },
            &[0x99; 32],
        );
        let expected: [u8; 32] = [
            0xa5, 0xef, 0x25, 0x64, 0x90, 0x96, 0x2b, 0xbb, 0xa3, 0x0f, 0xb8, 0x2e, 0x52, 0x2d,
            0x07, 0xec, 0xdc, 0xe1, 0x3b, 0x24, 0x76, 0x6c, 0x5d, 0x09, 0x56, 0x84, 0x3d, 0xcb,
            0xdd, 0xc9, 0x93, 0x8d,
        ];
        assert_eq!(subject.as_bytes(), &expected);
    }

    /// §5.1: a subject is a handle presented to Skiora, so it must not be derivable across
    /// agoras.
    #[test]
    fn subjects_do_not_correlate_across_agoras() {
        let decision = Decision::Revocation {
            leaf: Commitment::from_bytes([0x22; 32]),
        };
        let in_a = subject(&decision);
        let in_b = subject_id(
            AgoraId::from_bytes([0x02; 32]),
            Epoch::new(3),
            CLASS,
            &decision,
            &[0x99; 32],
        );
        assert_ne!(in_a, in_b);
    }
}
