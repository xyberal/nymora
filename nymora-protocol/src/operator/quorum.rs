// SPDX-License-Identifier: MIT OR Apache-2.0

//! The quorum-decision machine (§4.3, §11, §12; proposal 0021): propose, approve, execute.
//!
//! One machine serves all three decision kinds, because they are one shape — *k current
//! members approved subject X* — and because the alternative is three bespoke approval
//! flows, each a chance to get nullifier distinctness or quorum freshness wrong. What
//! keeps the kinds from bleeding into one another is not this code but the subject
//! derivation (`crate::decision`): approvals accumulate under a domain-separated subject
//! identifier, so an approval for a policy change is unforgeable as one for a revocation.
//!
//! Approvals are counted by a nullifier derived from `sk_cred`, which does not rotate —
//! §4.3 is explicit that expiry at the epoch boundary is **quorum freshness**, not
//! nullifier hygiene: a proposal outliving the membership set it was raised under would
//! accumulate approvals against a threshold that no longer describes the group. The
//! boundary clears open proposals (see [`AgoraState::advance_epoch`]), and a revocation —
//! which advances the epoch immediately — therefore expires every open proposal and vouch
//! session as a consequence of the same rule (§11).

use super::{AgoraState, Proposal, Recorded};
use crate::credential::FreshEntropy;
use crate::decision::{subject_id, Decision, SubjectId};
use alloc::collections::BTreeSet;
use nymora_circuits::ProofSystem;
use nymora_core::{Epoch, LocalReason, Nullifier, PolicyClass, ProtocolError, Rejection};
use nymora_proofs::verify_policy_approval;

/// What a member fetches to decide whether to approve: everything needed to recompute the
/// subject identifier locally and confirm it binds exactly this content (proposal 0021).
#[derive(Debug, Clone, Copy)]
pub struct ProposalView {
    /// What is proposed.
    pub decision: Decision,
    /// The class whose members' approvals count.
    pub approving_class: PolicyClass,
    /// The epoch the proposal was raised in — the only epoch it can execute in (§4.3).
    pub opened: Epoch,
    /// The freshness nonce absorbed into the subject identifier.
    pub nonce: [u8; 32],
}

impl<S: ProofSystem<DEPTH>, const DEPTH: usize> AgoraState<S, DEPTH> {
    /// Raises a quorum decision (§4.3's `propose`, §11's initiation, §12's `initiate`).
    ///
    /// The subject identifier is derived, not invented — members recompute it from the
    /// served [`ProposalView`] before approving, which is what makes approving the subject
    /// approving the *content*. The proposal expires at the epoch boundary; re-raising
    /// derives a fresh subject, so no approval ever carries over (§4.3).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for an unknown approving class, a policy decision
    /// naming an unknown class, or a dissolved agora — indistinguishably.
    pub fn propose(
        &mut self,
        decision: Decision,
        approving_class: PolicyClass,
        nonce_entropy: FreshEntropy,
    ) -> Result<SubjectId, ProtocolError> {
        self.live()?;
        self.class(approving_class)?;
        if let Decision::Policy { class, .. } = &decision {
            self.class(*class)?;
        }
        let nonce = nonce_entropy.take();
        let subject = subject_id(self.agora, self.epoch, approving_class, &decision, &nonce);
        self.proposals.insert(
            subject,
            Proposal {
                decision,
                approving_class,
                nonce,
                approvals: BTreeSet::new(),
            },
        );
        Ok(subject)
    }

    /// The open proposal under a subject, for members to recompute and weigh.
    ///
    /// `None` for anything not open right now — expired, executed, and never-raised are
    /// indistinguishable, as they must be.
    #[must_use]
    pub fn proposal(&self, subject: &SubjectId) -> Option<ProposalView> {
        let proposal = self.proposals.get(subject)?;
        Some(ProposalView {
            decision: proposal.decision,
            approving_class: proposal.approving_class,
            opened: self.epoch,
            nonce: proposal.nonce,
        })
    }

    /// Records one approval (§4.3's `approve`, §12's `confirm`).
    ///
    /// The proof is the §9.1 chain with the policy-approval clause over this subject,
    /// checked against the approving class at the current epoch. Like a vouch attestation,
    /// the response discloses nothing: no count, no progress, and a duplicate nullifier
    /// refuses exactly like every other refusal.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for an unknown or expired subject, a proof that does
    /// not verify, a duplicate nullifier, or a dissolved agora — indistinguishably.
    pub fn approve(
        &mut self,
        subject: SubjectId,
        proof: &S::Proof,
        nullifier: Nullifier,
    ) -> Result<Recorded, ProtocolError> {
        self.live()?;
        let agora = self.agora;
        let epoch = self.epoch;
        let approving_class = self
            .proposals
            .get(&subject)
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?
            .approving_class;
        let roots = self.roots_in(epoch, approving_class)?;
        if !verify_policy_approval(
            &self.system,
            proof,
            agora,
            epoch,
            &roots,
            subject.as_bytes(),
            nullifier,
        ) {
            return Err(Rejection::because(LocalReason::ProofInvalid).into());
        }
        let proposal = self
            .proposals
            .get_mut(&subject)
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?;
        if !proposal.approvals.insert(nullifier) {
            return Err(Rejection::because(LocalReason::DuplicateNullifier).into());
        }
        Ok(Recorded)
    }

    /// Executes a decision whose quorum is met (§4.3's `activate`, §12's `execute`).
    ///
    /// - **Policy**: the class's admission arithmetic and the governance quorum become the
    ///   proposed values, the class's policy version increments, and the change is logged
    ///   — *that* it changed, never who voted (§10.1).
    /// - **Revocation**: the leaf enters the revocation set and **the epoch advances
    ///   immediately** (§11) — the returned bulletin is inside [`Executed::Revocation`],
    ///   and its delivery cut is the read-capability cut. Every open proposal and session
    ///   expires with the boundary, this one having been consumed first.
    /// - **Dissolution**: the agora freezes, permanently (§12).
    ///
    /// An unmet quorum refuses and leaves the proposal open — more approvals may arrive
    /// until the boundary. A met quorum consumes it.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for an unknown or expired subject, an unmet quorum, or
    /// a dissolved agora — indistinguishably.
    pub fn execute(&mut self, subject: SubjectId) -> Result<Executed, ProtocolError> {
        self.live()?;
        let quorum = u64::from(self.governance_quorum);
        let met = self
            .proposals
            .get(&subject)
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?
            .approvals
            .len() as u64
            >= quorum;
        if !met {
            return Err(Rejection::because(LocalReason::ThresholdNotMet).into());
        }
        let proposal = self
            .proposals
            .remove(&subject)
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?;

        match proposal.decision {
            Decision::Policy {
                class,
                admission_threshold,
                governance_quorum,
            } => {
                let epoch = self.epoch;
                let version = {
                    let state = self
                        .classes
                        .get_mut(&class)
                        .ok_or(Rejection::because(LocalReason::PolicyDenied))?;
                    state.policy.admission_threshold = admission_threshold;
                    state.version += 1;
                    state.version
                };
                self.governance_quorum = governance_quorum;
                if let Some(log) = &mut self.log {
                    log.append(super::LogEntry::PolicyChanged {
                        epoch,
                        class,
                        version,
                    });
                }
                Ok(Executed::Policy { version })
            }
            Decision::Revocation { leaf } => {
                self.staged.revocations.push(leaf);
                let bulletin = self.advance_epoch()?;
                Ok(Executed::Revocation { bulletin })
            }
            Decision::Dissolution => {
                self.dissolve();
                Ok(Executed::Dissolved)
            }
        }
    }
}

/// What executing a decision did.
#[derive(Debug)]
#[non_exhaustive]
pub enum Executed {
    /// A policy change activated (§4.3).
    Policy {
        /// The class's new policy version.
        version: u64,
    },
    /// A revocation landed, advancing the epoch immediately (§11).
    Revocation {
        /// The boundary bulletin — deliver to **remaining** members only; withholding it
        /// from the revoked member is the read-capability cut of §11.
        bulletin: super::Bulletin,
    },
    /// The agora is frozen (§12).
    Dissolved,
}
