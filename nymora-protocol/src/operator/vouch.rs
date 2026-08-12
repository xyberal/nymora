// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vouch sessions (§5.3, §4.2): candidate intake, attestation, and threshold admission.
//!
//! # No incremental disclosure, structurally
//!
//! `attest` returns [`Recorded`] — a type with no fields — whether the attestation was the
//! first or the one that crossed the threshold, and there is no method that reports a
//! running count. The outcome exists exactly once, at [`AgoraState::vouch_finalize`]
//! (§5.3's timing-correlation argument). Duplicate nullifiers are refused with the same
//! [`ProtocolError::Rejected`] as everything else, so even the refusal does not say *why*.
//!
//! # The bootstrap is not a special case
//!
//! §4.2's threshold-of-1 founder vouch is this same code path under the founding policy's
//! `admission_threshold = 1` — there is no founder flag, and nothing in a session records
//! which policy version admitted it. Raising the threshold is an ordinary quorum decision
//! (§4.3), after which this same machine enforces the higher count.

use super::{Admission, AgoraState, ClassState, Recorded, SessionId, VouchSession};
use crate::credential::FreshEntropy;
use alloc::collections::BTreeSet;
use nymora_circuits::ProofSystem;
use nymora_core::{Commitment, LocalReason, PolicyClass, ProtocolError, Rejection};
use nymora_proofs::verify_vouch;

impl<S: ProofSystem<DEPTH>, const DEPTH: usize> AgoraState<S, DEPTH> {
    /// Accepts a candidate's commitment as pending admission (§5.3's `credentials/init`).
    ///
    /// Idempotent, and the acknowledgement is identical whether the commitment was new,
    /// already pending, or already a member — anything else would make this call a
    /// membership oracle for whoever can reach it.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] only on a dissolved agora.
    pub fn credentials_init(&mut self, commitment: Commitment) -> Result<Recorded, ProtocolError> {
        self.live()?;
        self.pending.insert(commitment);
        Ok(Recorded)
    }

    /// Opens a vouch session for a pending candidate (§5.3's `vouch/session/start`).
    ///
    /// The session identifier is drawn from entropy — it is what attestation nullifiers
    /// scope to, and §5.3 absorbs the agora into that derivation precisely because these
    /// identifiers are issuer-controlled, so nothing here depends on their uniqueness.
    ///
    /// The session lives until [`vouch_finalize`](AgoraState::vouch_finalize) or the epoch
    /// boundary, whichever comes first (§5.3: a session that does not finalize within its
    /// epoch is abandoned, for quorum freshness).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] when the candidate is not pending, is already in the
    /// target class, the class is unknown or exhausted (§5.2), or the agora is dissolved —
    /// indistinguishably.
    pub fn start_vouch(
        &mut self,
        candidate: Commitment,
        target: PolicyClass,
        id_entropy: FreshEntropy,
    ) -> Result<SessionId, ProtocolError> {
        self.live()?;
        if !self.pending.contains(&candidate) {
            return Err(Rejection::because(LocalReason::UnknownCredential).into());
        }
        let class = self.class(target)?;
        if class.positions.contains_key(&candidate) {
            return Err(Rejection::because(LocalReason::PolicyDenied).into());
        }
        if self.remaining_capacity(target) == 0 {
            // §5.2: exhaustion is terminal for the class. Refusing at start rather than
            // at finalize keeps a doomed session from collecting attestations.
            return Err(Rejection::opaque().into());
        }
        let id = SessionId(id_entropy.take());
        self.sessions.insert(
            id,
            VouchSession {
                candidate,
                target,
                nullifiers: BTreeSet::new(),
            },
        );
        Ok(id)
    }

    /// Records one attestation into a session (§5.3's `attest`).
    ///
    /// The proof is the §9.1 chain with the vouch clause, checked against the **voucher
    /// class** of the session's target — `Root_voucher_eligible` — at the current epoch's
    /// fixed roots. A duplicate nullifier is refused, which is the whole point of the
    /// nullifier: one credential counts once, with no one learning whose it was.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for an unknown or expired session, a proof that does
    /// not verify, a duplicate nullifier, or a dissolved agora — indistinguishably.
    pub fn vouch_attest(
        &mut self,
        session: SessionId,
        proof: &S::Proof,
        nullifier: nymora_core::Nullifier,
    ) -> Result<Recorded, ProtocolError> {
        self.live()?;
        let agora = self.agora;
        let epoch = self.epoch;
        let (voucher_class, target) = {
            let open = self
                .sessions
                .get(&session)
                .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?;
            (self.class(open.target)?.policy.voucher_class, open.target)
        };
        let roots = self.roots_in(epoch, voucher_class)?;
        if !verify_vouch(
            &self.system,
            proof,
            agora,
            epoch,
            &roots,
            session.as_bytes(),
            nullifier,
        ) {
            return Err(Rejection::because(LocalReason::ProofInvalid).into());
        }
        let open = self
            .sessions
            .get_mut(&session)
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?;
        debug_assert_eq!(open.target, target);
        if !open.nullifiers.insert(nullifier) {
            return Err(Rejection::because(LocalReason::DuplicateNullifier).into());
        }
        Ok(Recorded)
    }

    /// Closes a session and discloses the outcome — the one place it is disclosed (§5.3).
    ///
    /// On a met threshold the candidate's leaf is staged for the next boundary and the
    /// returned [`Admission`] says when it acts and where it sits. Either way the session
    /// is consumed: continuing to gather attestations after a failed finalize would be the
    /// incremental disclosure the response shape exists to prevent, so a failed admission
    /// is re-raised as a fresh session or not at all.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for an unknown or expired session, an unmet threshold,
    /// or a dissolved agora — indistinguishably.
    pub fn vouch_finalize(&mut self, session: SessionId) -> Result<Admission, ProtocolError> {
        self.live()?;
        let open = self
            .sessions
            .remove(&session)
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?;
        let threshold = self.class(open.target)?.policy.admission_threshold;
        if (open.nullifiers.len() as u64) < u64::from(threshold) {
            return Err(Rejection::because(LocalReason::ThresholdNotMet).into());
        }
        self.pending.remove(&open.candidate);
        Ok(self.stage_admission(open.target, open.candidate)?)
    }

    /// Stages a leaf for the next boundary, returning where and when it lands
    /// (proposal 0020). Callers have already checked their own preconditions; this checks
    /// capacity, the one condition they share.
    pub(super) fn stage_admission(
        &mut self,
        class: PolicyClass,
        leaf: Commitment,
    ) -> Result<Admission, Rejection> {
        if self.remaining_capacity(class) == 0 {
            return Err(Rejection::opaque());
        }
        let state = self
            .classes
            .get(&class)
            .ok_or(Rejection::because(LocalReason::PolicyDenied))?;
        let staged_before = self
            .staged
            .admissions
            .iter()
            .filter(|(c, _)| *c == class)
            .count() as u64;
        let position = state.occupied + staged_before;
        self.staged.admissions.push((class, leaf));
        let active_from = self.epoch.next().ok_or(Rejection::opaque())?;
        debug_assert!(position < ClassState::<DEPTH>::CAPACITY);
        Ok(Admission {
            active_from,
            position,
        })
    }
}
