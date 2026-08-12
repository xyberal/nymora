// SPDX-License-Identifier: MIT OR Apache-2.0

//! Witness assembly: from a member's stored material to the statement types (§9.1).
//!
//! This is the seam between phase 3 and phase 4: everything the credential lifecycle
//! stores, loaded back as the witnesses a proof consumes. It lives in `nymora-protocol`
//! because assembly reads `SecureStorage`, and this is the crate that drives the ports —
//! `nymora-proofs` stays pure and takes the assembled witness.
//!
//! # A destroyed key refuses here
//!
//! Loading the acting epoch's material is where §9.1's forward-secrecy bound becomes an
//! executable fact rather than prose: after the rollover sweep, the epoch key and its
//! certificate record are gone, so [`load_acting_material`] for a swept epoch returns
//! [`ProtocolError::Unavailable`] — however late the device wakes, and with no way to
//! reconstruct what would prove. The proof layer never sees a destroyed epoch; it cannot
//! be asked to.
//!
//! # What is deliberately a parameter
//!
//! The Merkle inclusion witness and the two absence witnesses are inputs to
//! [`ActingMaterial::witness`], not loads: they come from Skiora — cut against the current
//! epoch's roots, refreshed as the trees move — and fetching is I/O, which is the host's
//! (see `ARCHITECTURE.md`, sans-io). Storage holds what the member alone knows; the
//! witnesses describe where the member sits in structures the operator holds.

use crate::credential::{load_epoch_record, load_secret32, EpochRecord};
use nymora_core::{AgoraId, CredentialKey, Epoch, EpochSecretKey, ProtocolError, RootOpening};
use nymora_ports::{SecureStorage, Slot};

#[cfg(feature = "provisional-algebraic-hash")]
use nymora_accumulator::{AbsenceWitness, Witness};
#[cfg(feature = "provisional-algebraic-hash")]
use nymora_circuits::ChainWitness;

/// A member's stored proof material for acting at one epoch.
///
/// Secrets are owned (zeroizing, redacting); the root public key and the epoch record
/// borrow the caller's buffers. Everything here came out of the slots the lifecycle wrote
/// — nothing is derived, and nothing is checked against the statement yet: that is the
/// prover's job, which refuses an unsatisfiable witness as its own contract.
#[derive(Debug)]
pub struct ActingMaterial<'a> {
    credential_key: CredentialKey,
    root_opening: RootOpening,
    epoch_key: EpochSecretKey,
    root_public_key: &'a [u8],
    epoch_record: EpochRecord<'a>,
}

/// Loads everything the member stores that an ordinary proof takes as witness (§9.1):
/// `sk_cred`, `r_root`, `pk_root`, and the acting epoch's key and certificate record.
///
/// The two buffers receive the root public key and the epoch record; their sizes follow
/// the signature scheme, so size them generously rather than exactly.
///
/// # Errors
///
/// [`ProtocolError::Unavailable`] where any slot is absent or corrupt — no credential in
/// this agora, or an epoch whose material was destroyed by the rollover sweep (the §9.1
/// deletion, observed). [`ProtocolError::Malformed`] where a caller buffer is too small.
pub fn load_acting_material<'a>(
    agora: AgoraId,
    storage: &dyn SecureStorage,
    epoch: Epoch,
    root_public_key: &'a mut [u8],
    epoch_record: &'a mut [u8],
) -> Result<ActingMaterial<'a>, ProtocolError> {
    let credential_key = CredentialKey::new(*load_secret32(agora, storage, Slot::CredentialKey)?);
    let root_opening = RootOpening::new(*load_secret32(agora, storage, Slot::RootOpening)?);
    let epoch_key = EpochSecretKey::new(*load_secret32(agora, storage, Slot::EpochKey(epoch))?);

    let pk_len = storage
        .load(agora, Slot::RootPublicKey, root_public_key)?
        .ok_or(ProtocolError::Unavailable)?;
    let record = load_epoch_record(agora, storage, epoch, epoch_record)?
        .ok_or(ProtocolError::Unavailable)?;

    Ok(ActingMaterial {
        credential_key,
        root_opening,
        epoch_key,
        root_public_key: &root_public_key[..pk_len],
        epoch_record: record,
    })
}

impl<'a> ActingMaterial<'a> {
    /// Assembles the full chain witness (§9.1) from this material plus the three
    /// structure witnesses the host fetched from Skiora.
    ///
    /// The result borrows from both; hand it to `nymora-proofs` with the action's inputs.
    #[cfg(feature = "provisional-algebraic-hash")]
    #[must_use]
    pub fn witness<'w, const DEPTH: usize>(
        &'w self,
        leaf_witness: &'w Witness<DEPTH>,
        revocation_absence: &'w AbsenceWitness,
        spend_absence: &'w AbsenceWitness,
    ) -> ChainWitness<'w, DEPTH> {
        ChainWitness {
            epoch_key: &self.epoch_key,
            epoch_public_key: self.epoch_record.public_key,
            epoch_cert_signature: self.epoch_record.signature,
            credential_key: &self.credential_key,
            root_opening: &self.root_opening,
            root_public_key: self.root_public_key,
            leaf_witness,
            revocation_absence,
            spend_absence,
        }
    }
}
