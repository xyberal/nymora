// SPDX-License-Identifier: MIT OR Apache-2.0

//! The root authority (§9.2).
//!
//! A credential's root key signs two things and no more: the certificate binding a freshly
//! generated epoch key to the credential (§9.1), and the one-time certificate authorizing a
//! migration to new hardware (§9.3). Everything else a member does is signed by the epoch key,
//! which is ordinary software material and does not belong here.
//!
//! # Why the authority is abstract
//!
//! Nothing above this trait learns how many keys implement it. The specified construction is
//! two-level (§9.1, §9.2; proposal 0001 as applied by 0031): a capable backend keeps a
//! hardware anchor `sk_hw` and, wrapped under it where the platform allows, the
//! proving-native protocol root that actually signs — yet a key in a file presents the same
//! surface: a public key that goes in the accumulator leaf, an optional binding a verifier
//! can check, and two signing operations.
//!
//! That surface predates the two-level decision and survives it unchanged, which is what
//! kept 0001 off the critical path while its measurement waited: the anchor and its binding
//! evidence live entirely inside an implementation, carried here only as bytes this crate
//! never parses.

pub use nymora_core::{EpochCertPayload, MigrationCertPayload};

use nymora_core::{AgoraId, ProtocolError};

/// What a backend can actually do.
///
/// Reported rather than assumed, because the protocol's guarantees are not uniform across
/// backends and a caller that cannot see the difference will silently assume the strongest
/// case. §9.2's non-extractability argument holds only where [`non_exportable`] is true; a
/// software key store is a legitimate implementation for development and for hosts with no
/// secure element, but it is not the same security claim and must not present as one.
///
/// # The default claims nothing
///
/// Every field is `false` under [`Default`], so a backend that forgets to report a capability
/// under-claims rather than over-claims. That direction is deliberate: an under-claim costs a
/// caller some caution it did not need, while an over-claim is a false security statement.
///
/// [`non_exportable`]: Capabilities::non_exportable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capabilities {
    /// The root private key cannot be read out of the backend.
    ///
    /// §9.2's central property. Where this is false, a device compromise yields the root key
    /// itself, and the migration path of §9.3 stops being the only way to move a credential.
    pub non_exportable: bool,

    /// The backend produces evidence a verifier can check that the key is where it claims.
    ///
    /// Determines whether [`KeyStore::create_root`] can return a [`RootBinding`] at all.
    pub attests_binding: bool,

    /// Each signing operation requires the user to be present — biometric, passcode, or a
    /// physical touch.
    ///
    /// This is the protocol's only defence against a client acting with no human involvement.
    /// Note what it does *not* give: the prompt's wording is chosen by the application, not by
    /// the backend, so the user authorizes an opaque operation rather than a described one.
    pub requires_user_presence: bool,
}

/// Buffers a [`KeyStore`] writes newly created root material into.
///
/// Both are caller-supplied because the sizes depend on a signature scheme this crate does not
/// fix, and because `nymora` allocates nothing. See [`RootMaterialWritten`] for how much of each
/// was used.
#[derive(Debug)]
pub struct RootMaterialOut<'a> {
    /// Receives the public key committed in the accumulator leaf (§9.1).
    pub public_key: &'a mut [u8],
    /// Receives the binding, if the backend produces one. May be empty when it does not.
    pub binding: &'a mut [u8],
}

/// How much of each buffer [`KeyStore::create_root`] filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootMaterialWritten {
    /// Bytes written to [`RootMaterialOut::public_key`].
    pub public_key: usize,
    /// Bytes written to [`RootMaterialOut::binding`], or `None` when the backend offers no
    /// hardware evidence. Distinct from `Some(0)`, which would be a backend claiming a binding
    /// and producing an empty one.
    pub binding: Option<usize>,
}

/// A credential's root authority.
///
/// # Sign exactly the canonical message
///
/// Both signing methods take a payload type from `nymora-core`, and an implementation **must**
/// sign exactly its canonical compressed message — the Poseidon compression of the payload
/// stated in §9.1 and computed by `nymora-crypto` (proposal 0035) — never a message of its
/// own devising. Both certificates are recomputed and verified inside the standardized
/// circuit (§6.5), so a backend with a private message produces proofs no other
/// implementation can verify, or a per-backend proof shape — the fingerprinting §6.5
/// exists to prevent.
///
/// The encoding carries the agora and the certificate kind's domain tag inside the signed
/// message, so the two properties earlier revisions of this trait could only exhort —
/// no replay into another agora the member belongs to (§16.1), and no confusion between the
/// two certificate kinds sharing one signing key — hold by construction for any backend
/// that follows the rule above. `agora` still appears as a parameter on
/// [`create_root`](KeyStore::create_root), where there is no payload; the signing methods
/// read it from the payload itself.
///
/// # Errors
///
/// [`ProtocolError::Unavailable`] where the backend could not act — no such key, hardware
/// absent, the user declined a presence check. [`ProtocolError::Malformed`] where the caller's
/// buffer is too small to hold the result: that is a property of the caller's own input, not
/// an operational condition — retrying it cannot succeed — and it is the same mapping
/// `SecureStorage` and the bundle codec use for the same mistake.
/// [`ProtocolError::Rejected`] is not used here: this port has no counterparty and no hidden
/// protocol state to protect, so there is nothing for a coarse refusal to conceal.
pub trait KeyStore {
    /// What this backend can do. See [`Capabilities`] for why it is reported and not assumed.
    fn capabilities(&self) -> Capabilities;

    /// Creates a credential's root material for one agora.
    ///
    /// The returned public key is what the accumulator leaf commits to (§9.1). The binding, if
    /// present, is opaque to everything above this trait — the hardware anchor's evidence for
    /// the fresh root (§9.2, proposal 0031), or nothing at all where no hardware attests.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn create_root(
        &self,
        agora: AgoraId,
        out: RootMaterialOut<'_>,
    ) -> Result<RootMaterialWritten, ProtocolError>;

    /// Signs a certificate binding a generated epoch key to this credential (§9.1).
    ///
    /// The signed message is exactly the payload's canonical compressed message — see the
    /// trait documentation. Returns the number of bytes written to `signature`.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn sign_epoch_cert(
        &self,
        payload: &EpochCertPayload<'_>,
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError>;

    /// Signs a one-time certificate authorizing migration to a successor key (§9.3).
    ///
    /// The successor's public key is in the same encoding
    /// [`create_root`](KeyStore::create_root) produces, and the signed message is exactly the
    /// payload's canonical compressed message — see the trait documentation. Returns the
    /// number of bytes written to `signature`.
    ///
    /// The protocol requires this to be usable once: the old leaf is consumed by a migration
    /// nullifier derived from `sk_cred` and the leaf itself, so a second successor cannot be
    /// admitted even if a backend signs a second certificate. Enforcement lives in the
    /// accumulator, not here.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn sign_migration(
        &self,
        payload: &MigrationCertPayload<'_>,
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError>;
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, EpochCertPayload, KeyStore};
    use nymora_core::{AgoraId, Epoch};

    /// A host may hold this port behind a trait object; keep it dyn-compatible.
    fn _is_dyn_compatible(_: &dyn KeyStore) {}

    /// An unreported capability must read as absent, never as present.
    #[test]
    fn the_default_capability_set_claims_nothing() {
        let claimed = Capabilities::default();
        assert!(!claimed.non_exportable);
        assert!(!claimed.attests_binding);
        assert!(!claimed.requires_user_presence);
    }

    /// The payload carries the epoch and agora explicitly rather than leaving either
    /// implicit in the key.
    ///
    /// A certificate that did not name its epoch would verify in any epoch — the
    /// forward-secrecy bound of §9.1 expressed as a signed input — and one that did not name
    /// its agora would replay into another (§16.1). The canonical message these feed is
    /// pinned in `nymora-crypto`.
    #[test]
    fn an_epoch_cert_names_its_epoch_and_agora() {
        let payload = EpochCertPayload {
            agora: AgoraId::from_bytes([0x11; 32]),
            epoch: Epoch::new(7),
            epoch_public_key: &[0xab; 32],
        };
        assert_ne!(
            payload,
            EpochCertPayload {
                epoch: Epoch::new(8),
                ..payload
            }
        );
        assert_ne!(
            payload,
            EpochCertPayload {
                agora: AgoraId::from_bytes([0x12; 32]),
                ..payload
            }
        );
    }
}
