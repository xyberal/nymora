// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification access (§7, proposal 0019): the member gate, and what it serves.
//!
//! # What the gate is for
//!
//! A non-member holding an attestation bundle must have no path to a trustworthy root
//! (§7). The gate is a single-use challenge redeemed by the §9.1 chain with 0019's final
//! clause — no nullifier anywhere, because access is not a count. What sits behind it is
//! the *historical* surface: roots at past epochs, past tag keys, the whole exclusion sets
//! (§11), and the consolidated verify. The *current operational* surface — this epoch's
//! roots, the member's own witness — is deliberately in front of the gate (see the module
//! documentation in [`super`]): a member must be able to assemble a standing proof before
//! holding one.
//!
//! # Access is an epoch-scoped capability
//!
//! [`MemberAccess`] is granted by a proof against the current epoch and dies with it. That
//! bound is what makes revocation effective here: the revoked member's last access token
//! dies at the boundary the revocation forces (§11), and no new proof of theirs verifies.

use super::*;
use nymora_core::MessageHash;
use nymora_proofs::{verify_authorship, verify_verification_access};

/// A single-use verification-access challenge (§7, proposal 0019).
///
/// Skiora-issued, bound into the access proof's transcript, consumed on first
/// presentation, and dead at the epoch boundary regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge([u8; 32]);

impl Challenge {
    /// The bytes the access proof binds (0019).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A member's proven standing, for this epoch (§7).
///
/// A capability value: holding one is what the gated methods check. It is deliberately
/// not `Clone` — the host that wants two should redeem two challenges.
#[derive(Debug)]
pub struct MemberAccess {
    epoch: Epoch,
}

impl<S: ProofSystem<DEPTH>, const DEPTH: usize> AgoraState<S, DEPTH> {
    /// Issues a fresh single-use challenge (§7).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] on a dissolved agora — §12 ends the serving of new
    /// verifications, and the gate is where that ending lives.
    pub fn issue_challenge(&mut self, entropy: FreshEntropy) -> Result<Challenge, ProtocolError> {
        self.live()?;
        let challenge = entropy.take();
        self.challenges.insert(challenge);
        Ok(Challenge(challenge))
    }

    /// Redeems a challenge with an access proof, granting this epoch's [`MemberAccess`].
    ///
    /// The challenge is consumed **on presentation**, not on success — replaying an
    /// observed challenge with a bad proof burns it for the observer too, and the honest
    /// holder simply requests another. The proof is the §9.1 chain against the member's
    /// own class at the current epoch, carrying no nullifier (proposal 0019).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for an unknown, spent, or expired challenge, a proof
    /// that does not verify, an unknown class, or a dissolved agora — indistinguishably.
    pub fn redeem_access(
        &mut self,
        class: PolicyClass,
        proof: &S::Proof,
        challenge: Challenge,
    ) -> Result<MemberAccess, ProtocolError> {
        self.live()?;
        if !self.challenges.remove(&challenge.0) {
            return Err(Rejection::because(LocalReason::EpochOutOfRange).into());
        }
        let roots = self.roots_in(self.epoch, class)?;
        if !verify_verification_access(
            &self.system,
            proof,
            self.agora,
            self.epoch,
            &roots,
            challenge.as_bytes(),
        ) {
            return Err(Rejection::because(LocalReason::ProofInvalid).into());
        }
        Ok(MemberAccess { epoch: self.epoch })
    }

    /// The roots in force at a past or current epoch (§7's `root-at-epoch`).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for stale access, an epoch before the agora existed or
    /// after now, an unknown class, or a dissolved agora — indistinguishably.
    pub fn roots_at(
        &self,
        access: &MemberAccess,
        class: PolicyClass,
        epoch: Epoch,
    ) -> Result<nymora_proofs::EpochRoots, ProtocolError> {
        self.admit(access)?;
        Ok(self.roots_in(epoch, class)?)
    }

    /// A past or current epoch's tag key (§6.4), for resolving older content.
    ///
    /// Members normally hold these from the boundary broadcasts; this is the gated path
    /// for one who joined later or lost sync. Future epochs' keys do not exist to be
    /// asked for — the KDF could produce them, and answering would hand a departing
    /// member exactly the read capability §11 cuts off.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] as [`roots_at`](AgoraState::roots_at).
    pub fn tag_key_at(&self, access: &MemberAccess, epoch: Epoch) -> Result<TagKey, ProtocolError> {
        self.admit(access)?;
        if epoch > self.epoch {
            return Err(Rejection::because(LocalReason::EpochOutOfRange).into());
        }
        Ok(derive_tag_key(self.tag_secret.expose(), &self.agora, epoch))
    }

    /// The whole revocation set (§11): every excluded key, for the member to rebuild
    /// locally and compute non-membership witnesses from without ever naming their own.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for stale access or a dissolved agora.
    pub fn revocation_keys(
        &self,
        access: &MemberAccess,
    ) -> Result<impl Iterator<Item = [u8; 32]> + '_, ProtocolError> {
        self.admit(access)?;
        Ok(self.revocations.keys())
    }

    /// The whole migration-spend set (§9.3), served as
    /// [`revocation_keys`](AgoraState::revocation_keys) is.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for stale access or a dissolved agora.
    pub fn spend_keys(
        &self,
        access: &MemberAccess,
    ) -> Result<impl Iterator<Item = [u8; 32]> + '_, ProtocolError> {
        self.admit(access)?;
        Ok(self.spends.keys())
    }

    /// The consolidated verification round-trip (§7): checks an authorship attestation
    /// against the roots of the epoch its tag resolved to.
    ///
    /// Returns whether the attestation verifies — `Ok(false)` is an answer about the
    /// bundle, not a refusal. The caller resolved `epoch` from the tag (§6.4) and supplies
    /// the class the content claims.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for stale access, an unknown epoch or class, or a
    /// dissolved agora — the *service* refusing, as distinct from the bundle failing.
    pub fn verify_attestation(
        &self,
        access: &MemberAccess,
        class: PolicyClass,
        epoch: Epoch,
        proof: &S::Proof,
        message: MessageHash,
        nullifier: Nullifier,
    ) -> Result<bool, ProtocolError> {
        self.admit(access)?;
        let roots = self.roots_in(epoch, class)?;
        Ok(verify_authorship(
            &self.system,
            proof,
            self.agora,
            epoch,
            &roots,
            message,
            nullifier,
        ))
    }

    /// Checks an access capability is for the epoch that is still current.
    fn admit(&self, access: &MemberAccess) -> Result<(), Rejection> {
        self.live()?;
        if access.epoch != self.epoch {
            return Err(Rejection::because(LocalReason::EpochOutOfRange));
        }
        Ok(())
    }
}
