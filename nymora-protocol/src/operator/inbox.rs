// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbox registry and its two instructions (§9.3, §11; proposal 0036).

use super::{AgoraState, InboxRecord, Recorded};
use nymora_circuits::ProofSystem;
use nymora_core::{Commitment, InboxAction, InboxPublicKey, LocalReason, ProtocolError, Rejection};
use nymora_proofs::verify_inbox;

/// The default inbox horizon: a year of daily epochs (§11, proposal 0036).
pub const DEFAULT_INBOX_HORIZON: u64 = 365;

/// The protocol floor on the horizon, so a registration can never lapse inside a host's
/// catch-up window (§11, proposal 0036).
pub const MIN_INBOX_HORIZON: u64 = 7;

impl<S: ProofSystem<DEPTH>, const DEPTH: usize> AgoraState<S, DEPTH> {
    /// Applies a root-signed inbox instruction under its proof (§9.3's retirement, §11's
    /// renewal).
    ///
    /// The proof establishes that `leaf`'s committed root key issued `action` over
    /// `inbox`. **Retire** stops delivery to `inbox`, which must be the key registered
    /// for `leaf` — submitted by a successor at a time of its choosing, since it links
    /// predecessor and successor within the period's migration batch. **Renew**
    /// registers `inbox` (the same key or a fresh one) for a landed, unrevoked leaf and
    /// resets its horizon.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for a proof that does not verify, a retirement naming
    /// a key that is not the leaf's, a renewal for a leaf that is not a landed member, or
    /// a dissolved agora — indistinguishably.
    pub fn inbox_certificate(
        &mut self,
        leaf: Commitment,
        inbox: InboxPublicKey,
        action: InboxAction,
        proof: &S::InboxProof,
    ) -> Result<Recorded, ProtocolError> {
        self.live()?;
        if !verify_inbox(&self.system, proof, self.agora, leaf, inbox, action) {
            return Err(Rejection::because(LocalReason::ProofInvalid).into());
        }
        match action {
            InboxAction::Retire => {
                let registered = self
                    .inboxes
                    .get(&leaf)
                    .ok_or(Rejection::because(LocalReason::UnknownCredential))?;
                if registered.key != inbox {
                    return Err(Rejection::because(LocalReason::UnknownCredential).into());
                }
                self.inboxes.remove(&leaf);
            }
            InboxAction::Renew => {
                let landed = self
                    .classes
                    .values()
                    .any(|class| class.positions.contains_key(&leaf));
                if !landed || self.revoked_leaves.contains(&leaf) {
                    return Err(Rejection::because(LocalReason::UnknownCredential).into());
                }
                self.inboxes.insert(
                    leaf,
                    InboxRecord {
                        key: inbox,
                        since: self.epoch,
                    },
                );
            }
        }
        Ok(Recorded)
    }

    /// Whether `leaf`'s registration is live at the current epoch: registered, not
    /// revoked, and inside the horizon.
    pub(super) fn inbox_live(&self, leaf: &Commitment) -> Option<InboxPublicKey> {
        if self.revoked_leaves.contains(leaf) {
            return None;
        }
        let record = self.inboxes.get(leaf)?;
        let age = self.epoch.get().saturating_sub(record.since.get());
        (age < self.inbox_horizon).then_some(record.key)
    }
}
