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
//! Nothing above this trait learns how many keys implement it. A Secure Enclave key, a
//! StrongBox key, a FIDO2 authenticator, a key in a file, or the two-level arrangement of
//! proposal 0001 all present the same surface: a public key that goes in the accumulator leaf,
//! an optional binding a verifier can check, and two signing operations.
//!
//! That is what keeps 0001 off the critical path. If it is adopted, the second key and its
//! `binding_cert` live entirely inside an implementation, and [`RootBinding`](self) carries the
//! certificate as bytes this crate never parses.

use nymora_core::{AgoraId, Epoch, ProtocolError};

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

/// What a credential's root key certifies about an epoch key (§9.1).
///
/// The epoch key is **generated**, never derived (proposal 0004), so nothing about it is
/// recomputable from the root key and this certificate is the only thing that ties the two
/// together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCertPayload<'a> {
    /// The epoch the key is being certified for.
    pub epoch: Epoch,
    /// The freshly generated epoch public key, in whatever encoding the signature scheme uses.
    pub epoch_public_key: &'a [u8],
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
/// # Every signature must bind the agora
///
/// Each method takes an [`AgoraId`], and an implementation **must** include it in the signed
/// message rather than treating it as a lookup key. A certificate that did not bind it would be
/// replayable into another agora the member belongs to, which §16.1 forbids: no value derived
/// within one agora may be usable in another. The parameter is not present so the backend can
/// find the right key; it is present so the right agora is signed over.
///
/// # Errors
///
/// [`ProtocolError::Unavailable`] where the backend could not act — no such key, hardware
/// absent, the user declined a presence check, or a buffer too small to hold the result.
/// [`ProtocolError::Rejected`] is not used here: this port has no counterparty and no hidden
/// protocol state to protect, so there is nothing for a coarse refusal to conceal.
pub trait KeyStore {
    /// What this backend can do. See [`Capabilities`] for why it is reported and not assumed.
    fn capabilities(&self) -> Capabilities;

    /// Creates a credential's root key for one agora.
    ///
    /// The returned public key is what the accumulator leaf commits to (§9.1). The binding, if
    /// present, is opaque to everything above this trait — a hardware attestation, 0001's
    /// `binding_cert`, or nothing at all.
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
    /// Returns the number of bytes written to `signature`.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn sign_epoch_cert(
        &self,
        agora: AgoraId,
        payload: &EpochCertPayload<'_>,
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError>;

    /// Signs a one-time certificate authorizing migration to `target` (§9.3).
    ///
    /// `target` is the successor's root public key, in the same encoding
    /// [`create_root`](KeyStore::create_root) produces. Returns the number of bytes written to
    /// `signature`.
    ///
    /// The protocol requires this to be usable once: the old leaf is consumed by a migration
    /// nullifier derived from `sk_cred`, so a second successor cannot be admitted even if a
    /// backend signs a second certificate. Enforcement lives in the accumulator, not here.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn sign_migration(
        &self,
        agora: AgoraId,
        target: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError>;
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, EpochCertPayload, KeyStore};
    use nymora_core::Epoch;

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

    /// The payload carries the epoch explicitly rather than leaving it implicit in the key.
    ///
    /// A certificate that did not name its epoch would verify in any epoch, which is the
    /// forward-secrecy bound of §9.1 expressed as a signed field.
    #[test]
    fn an_epoch_cert_names_its_epoch() {
        let payload = EpochCertPayload {
            epoch: Epoch::new(7),
            epoch_public_key: &[0xab; 32],
        };
        assert_eq!(payload.epoch, Epoch::new(7));
        assert_ne!(
            payload,
            EpochCertPayload {
                epoch: Epoch::new(8),
                epoch_public_key: &[0xab; 32],
            }
        );
    }
}
