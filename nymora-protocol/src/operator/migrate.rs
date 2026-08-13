// SPDX-License-Identifier: MIT OR Apache-2.0

//! The operator's side of planned migration (§9.3, path 1).
//!
//! The member's side existed by the end of phase 3 — authorize on the old device,
//! complete on the new, prove with the phase-4 migration statement. This is the acceptance
//! path: verify the proof, spend the old leaf, admit the successor.
//!
//! # The spend's timing is the accepted window
//!
//! A verified spend **stages** for the next boundary rather than landing immediately —
//! §9.3 fixes exclusion roots per epoch, so the superseded device keeps write capability
//! for at most the remainder of the epoch, the same bound a compromised `sk_epoch` already
//! carries. Migration, unlike revocation, is the member's own cooperative act; it does not
//! get to move the boundary.
//!
//! # Path 2 is deliberately absent here
//!
//! Lost-device recovery is a composition, not a mechanism: quorum revocation of the old
//! credential (§11, the quorum machine) followed by ordinary re-admission of fresh
//! material (§5.3, the vouch machine). There is nothing for this module to add — which is
//! §9.3's point that the two paths are disjoint situations, not competing designs.

use super::{Admission, AgoraState};
use nymora_circuits::ProofSystem;
use nymora_core::{Commitment, LocalReason, Nullifier, PolicyClass, ProtocolError, Rejection};
use nymora_proofs::verify_migration;

impl<S: ProofSystem<DEPTH>, const DEPTH: usize> AgoraState<S, DEPTH> {
    /// Accepts a planned migration (§9.3's `credentials/migrate`): verifies the migration
    /// proof, checks the spend fresh, stages the spend for the boundary, and stages the
    /// successor's leaf into the proven class.
    ///
    /// The proof establishes — in zero knowledge, with `pk_root_old` never in the clear —
    /// that the old leaf is present and unrevoked in this class, that the old root
    /// authorized exactly this successor, and that the successor commitment carries the
    /// same `sk_cred` (§9.3's laundering guard). The spend check is the verifier's own:
    /// the statement proves the nullifier well-derived, and this method is where "not
    /// already spent, not already staged" lives.
    ///
    /// One class per migration, because the statement proves presence in one class root —
    /// a limitation of the phase-4 statement shape recorded here deliberately: whether a
    /// multi-class credential migrates atomically is a question for the real circuit's
    /// design (§6.5), and pretending to answer it now with N separate spends would spend
    /// the same nullifier N times.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for a proof that does not verify, a spend already spent
    /// or staged, a successor already present, an unknown or exhausted class, or a
    /// dissolved agora — indistinguishably.
    pub fn migrate(
        &mut self,
        class: PolicyClass,
        proof: &S::MigrationProof,
        spend: Nullifier,
        successor: Commitment,
    ) -> Result<Admission, ProtocolError> {
        self.live()?;
        let already_spent = self.spends.keys().any(|key| key == spend.as_bytes())
            || self.staged.spends.contains(&spend);
        if already_spent {
            return Err(Rejection::because(LocalReason::DuplicateNullifier).into());
        }
        if self.class(class)?.positions.contains_key(&successor) {
            return Err(Rejection::because(LocalReason::PolicyDenied).into());
        }
        let roots = self.roots_in(self.epoch, class)?;
        if !verify_migration(
            &self.system,
            proof,
            self.agora,
            roots.class,
            roots.revocation,
            spend,
            successor,
        ) {
            return Err(Rejection::because(LocalReason::ProofInvalid).into());
        }
        // The admission stages before the spend does, so a staging refusal — a full
        // class, a duplicate successor — refuses the migration whole rather than
        // consuming the old leaf for nothing (proposal 0026).
        let admission = self.stage_admission(class, successor)?;
        self.staged.spends.push(spend);
        Ok(admission)
    }
}
