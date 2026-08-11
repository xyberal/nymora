// SPDX-License-Identifier: MIT OR Apache-2.0

//! A reference [`KeyStore`] for development and tests. **Never production custody.**
//!
//! # What it is honest about
//!
//! Every root key comes from one seed. That is what makes it useful — `create_root` is
//! deterministic, so a test can recreate a credential without persisting anything — and it is
//! also precisely why it must not hold a real credential. A single seed compromise yields every
//! agora's root key at once, which no hardware backend behaves like. The per-agora derivation is
//! one-way, so §16.1's requirement that no value derived in one agora be derivable from another
//! survives *cryptographically*; it does not survive operationally, because one secret sits
//! behind all of them.
//!
//! [`Capabilities`] therefore reports nothing: not non-exportable, no binding, no user presence.
//! Callers exercising the variance path against this backend see the weakest case from the first
//! day, rather than discovering it when a hardware backend arrives and behaves differently.
//!
//! # Why the signatures are not signatures
//!
//! They are keyed hashes. The real construction cannot be chosen yet: §9.3 wants a migration
//! certificate verified inside a proof rather than transmitted in the clear, so the scheme is
//! constrained by the proving system — the same fault line that leaves the algebraic hash
//! provisional in `nymora-crypto`. Anything committed now would be committing to that decision
//! by implication.
//!
//! Nothing verifies these values, and nothing should. They exist so that callers exercise the
//! buffer, length, and error paths of the port before a real backend exists.
//!
//! # Why this does not use `nymora-crypto`
//!
//! Domain-separated hashing belongs there, and every value with a counterparty must come from
//! it, or two implementations will eventually disagree. These values have no counterparty: they
//! are local, never interoperable, and never recomputed by anyone else. Reaching for
//! `nymora-crypto` would have meant adding stand-in entries to a permanent public domain-tag
//! registry, which is a worse trade than the few lines of framing below.
//!
//! The prefixes here are deliberately **not** shaped like `nymora/v0/...` protocol domain tags,
//! so that no one mistakes one for the other. Protocol tags do appear in what the signing
//! methods absorb — but as part of the canonical certificate payloads from `nymora-core`,
//! which are the message being signed, not this backend's own separation.

use crate::key_store::{
    Capabilities, EpochCertPayload, KeyStore, MigrationCertPayload, RootMaterialOut,
    RootMaterialWritten,
};
use nymora_core::{AgoraId, ProtocolError, SecretBytes, DIGEST_LEN};
use sha2::{Digest, Sha256};

/// Separators for this backend's derivations. Local to it, not protocol domain tags.
///
/// The two signing methods absorb the canonical certificate payload, which already leads
/// with a protocol domain tag, so a single local separator suffices there: the kinds are
/// separated inside the message, exactly as they will be for a real signature scheme.
const ROOT: &[u8] = b"software-key-store/v0/root";
const SIGN: &[u8] = b"software-key-store/v0/sign";

/// Absorbs a length prefix before the bytes.
///
/// The same convention `nymora-crypto`'s hasher uses, for the same reason: without it the
/// boundary between two adjacent fields can be moved, and a value derived over one field
/// arrangement collides with a value derived over another.
fn framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Writes `value` into `out`, or reports that the caller's buffer is too small.
fn put(out: &mut [u8], value: &[u8; DIGEST_LEN]) -> Result<usize, ProtocolError> {
    out.get_mut(..DIGEST_LEN)
        .ok_or(ProtocolError::Unavailable)?
        .copy_from_slice(value);
    Ok(DIGEST_LEN)
}

/// A software-only root authority. See the module documentation before using it for anything.
///
/// `Debug` renders without the seed, since [`SecretBytes`] redacts its own.
#[derive(Debug)]
pub struct SoftwareKeyStore {
    seed: SecretBytes<DIGEST_LEN>,
}

impl SoftwareKeyStore {
    /// Builds a key store from a seed.
    ///
    /// The seed must carry real entropy: every root key this store will ever produce is derived
    /// from it, so a guessable seed makes every credential forgeable. A fixed seed is
    /// appropriate in a test and nowhere else.
    #[must_use]
    pub fn new(seed: [u8; DIGEST_LEN]) -> Self {
        Self {
            seed: SecretBytes::new(seed),
        }
    }

    /// Derives one value, binding the separator, the seed, and every supplied field.
    fn derive(&self, separator: &[u8], fields: &[&[u8]]) -> [u8; DIGEST_LEN] {
        let mut hasher = Sha256::new();
        framed(&mut hasher, separator);
        framed(&mut hasher, self.seed.expose());
        for field in fields {
            framed(&mut hasher, field);
        }
        hasher.finalize().into()
    }

    /// "Signs" a canonical certificate payload: a keyed hash over exactly its bytes.
    ///
    /// The payload is streamed through `encode_parts` rather than re-encoded here, so this
    /// backend cannot drift from the layout `nymora-core` pins — the property the `KeyStore`
    /// contract demands of real backends, obeyed by the stand-in for the same reason. The
    /// framing prefix uses `encoded_len`, keeping the message one framed field like every
    /// other absorption in this file.
    fn sign_canonical(
        &self,
        encoded_len: usize,
        encode_parts: impl FnOnce(&mut dyn FnMut(&[u8])),
    ) -> [u8; DIGEST_LEN] {
        let mut hasher = Sha256::new();
        framed(&mut hasher, SIGN);
        framed(&mut hasher, self.seed.expose());
        hasher.update((encoded_len as u64).to_le_bytes());
        encode_parts(&mut |part: &[u8]| hasher.update(part));
        hasher.finalize().into()
    }
}

impl KeyStore for SoftwareKeyStore {
    /// Claims nothing, because there is nothing to claim.
    fn capabilities(&self) -> Capabilities {
        // Written out rather than taken from `Default`, so that a reader sees three explicit
        // denials rather than an absence they have to go and check.
        Capabilities {
            non_exportable: false,
            attests_binding: false,
            requires_user_presence: false,
        }
    }

    fn create_root(
        &self,
        agora: AgoraId,
        out: RootMaterialOut<'_>,
    ) -> Result<RootMaterialWritten, ProtocolError> {
        let public_key = self.derive(ROOT, &[agora.as_bytes()]);
        Ok(RootMaterialWritten {
            public_key: put(out.public_key, &public_key)?,
            // Not `Some(0)`: this backend produces no binding at all, which is a different
            // statement from producing an empty one. `capabilities()` says the same thing.
            binding: None,
        })
    }

    fn sign_epoch_cert(
        &self,
        payload: &EpochCertPayload<'_>,
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let value = self.sign_canonical(payload.encoded_len(), |put| payload.encode_parts(put));
        put(signature, &value)
    }

    fn sign_migration(
        &self,
        payload: &MigrationCertPayload<'_>,
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let value = self.sign_canonical(payload.encoded_len(), |put| payload.encode_parts(put));
        put(signature, &value)
    }
}

#[cfg(test)]
mod tests {
    use super::SoftwareKeyStore;
    use crate::key_store::{EpochCertPayload, KeyStore, MigrationCertPayload, RootMaterialOut};
    use nymora_core::{AgoraId, Epoch, ProtocolError, DIGEST_LEN};
    use std::format;

    const SEED: [u8; DIGEST_LEN] = [0x5a; DIGEST_LEN];
    const AGORA_A: AgoraId = AgoraId::from_bytes([0x01; DIGEST_LEN]);
    const AGORA_B: AgoraId = AgoraId::from_bytes([0x02; DIGEST_LEN]);

    fn store() -> SoftwareKeyStore {
        SoftwareKeyStore::new(SEED)
    }

    fn root_of(store: &SoftwareKeyStore, agora: AgoraId) -> [u8; DIGEST_LEN] {
        let mut public_key = [0u8; DIGEST_LEN];
        let mut binding = [0u8; DIGEST_LEN];
        let written = store
            .create_root(
                agora,
                RootMaterialOut {
                    public_key: &mut public_key,
                    binding: &mut binding,
                },
            )
            .expect("buffers are large enough");
        assert_eq!(written.public_key, DIGEST_LEN);
        public_key
    }

    fn epoch_cert(
        store: &SoftwareKeyStore,
        agora: AgoraId,
        epoch: u64,
        key: &[u8],
    ) -> [u8; DIGEST_LEN] {
        let mut signature = [0u8; DIGEST_LEN];
        let written = store
            .sign_epoch_cert(
                &EpochCertPayload {
                    agora,
                    epoch: Epoch::new(epoch),
                    epoch_public_key: key,
                },
                &mut signature,
            )
            .expect("buffer is large enough");
        assert_eq!(written, DIGEST_LEN);
        signature
    }

    fn migration(store: &SoftwareKeyStore, agora: AgoraId, target: &[u8]) -> [u8; DIGEST_LEN] {
        let mut signature = [0u8; DIGEST_LEN];
        store
            .sign_migration(
                &MigrationCertPayload {
                    agora,
                    successor_public_key: target,
                },
                &mut signature,
            )
            .expect("buffer is large enough");
        signature
    }

    /// The whole point of 1.8: callers must see the weakest case from the first day.
    #[test]
    fn it_claims_no_capability_it_does_not_have() {
        let claimed = store().capabilities();
        assert!(!claimed.non_exportable, "a software seed is exportable");
        assert!(!claimed.attests_binding, "there is no hardware to attest");
        assert!(!claimed.requires_user_presence, "nothing prompts anyone");
    }

    /// A backend reporting no binding must return `None`, not an empty one.
    #[test]
    fn it_produces_no_binding() {
        let mut public_key = [0u8; DIGEST_LEN];
        let mut binding = [0u8; DIGEST_LEN];
        let written = store()
            .create_root(
                AGORA_A,
                RootMaterialOut {
                    public_key: &mut public_key,
                    binding: &mut binding,
                },
            )
            .expect("buffers are large enough");
        assert_eq!(written.binding, None);
        assert_eq!(
            binding, [0u8; DIGEST_LEN],
            "an unclaimed buffer was written"
        );
    }

    /// Determinism is what lets a test recreate a credential without persisting one.
    #[test]
    fn a_root_is_reproducible_from_the_seed() {
        assert_eq!(root_of(&store(), AGORA_A), root_of(&store(), AGORA_A));
    }

    /// §16.1 — nothing derived in one agora may be derivable from another.
    #[test]
    fn each_agora_gets_an_unrelated_root() {
        assert_ne!(root_of(&store(), AGORA_A), root_of(&store(), AGORA_B));
    }

    #[test]
    fn a_different_seed_is_a_different_credential() {
        let other = SoftwareKeyStore::new([0x5b; DIGEST_LEN]);
        assert_ne!(root_of(&store(), AGORA_A), root_of(&other, AGORA_A));
    }

    /// Each derivation must be separated from the others.
    ///
    /// Root material is separated from signatures by the local separators; the two
    /// certificate kinds are separated from each other by the protocol domain tag leading
    /// each canonical payload — the same separation a real signature scheme will rely on.
    /// Without either, two of these values over the same agora would be the same 32 bytes,
    /// and one could be presented as the other.
    #[test]
    fn the_three_derivations_do_not_collide() {
        let store = store();
        let root = root_of(&store, AGORA_A);
        assert_ne!(root, epoch_cert(&store, AGORA_A, 0, &[]));
        assert_ne!(root, migration(&store, AGORA_A, &[]));
        assert_ne!(
            epoch_cert(&store, AGORA_A, 0, &[]),
            migration(&store, AGORA_A, &[])
        );
    }

    /// The requirement stated on `KeyStore`: a certificate must not replay across agoras.
    #[test]
    fn an_epoch_cert_binds_its_agora() {
        let store = store();
        assert_ne!(
            epoch_cert(&store, AGORA_A, 7, &[0xcc; 32]),
            epoch_cert(&store, AGORA_B, 7, &[0xcc; 32])
        );
    }

    #[test]
    fn an_epoch_cert_binds_its_epoch_and_key() {
        let store = store();
        let base = epoch_cert(&store, AGORA_A, 7, &[0xcc; 32]);
        assert_ne!(base, epoch_cert(&store, AGORA_A, 8, &[0xcc; 32]));
        assert_ne!(base, epoch_cert(&store, AGORA_A, 7, &[0xcd; 32]));
    }

    #[test]
    fn a_migration_cert_binds_its_agora_and_target() {
        let store = store();
        let base = migration(&store, AGORA_A, &[0xee; 32]);
        assert_ne!(base, migration(&store, AGORA_B, &[0xee; 32]));
        assert_ne!(base, migration(&store, AGORA_A, &[0xef; 32]));
    }

    /// Field boundaries must not be movable.
    ///
    /// The epoch is fixed-width, but the epoch public key is not, so without length framing a
    /// key whose leading bytes absorbed the neighbouring field would produce a colliding
    /// certificate.
    #[test]
    fn field_boundaries_are_not_malleable() {
        let store = store();
        let mut shifted = [0u8; 33];
        shifted[1..].copy_from_slice(&[0xcc; 32]);
        assert_ne!(
            epoch_cert(&store, AGORA_A, 7, &[0xcc; 32]),
            epoch_cert(&store, AGORA_A, 7, &shifted)
        );
    }

    /// A buffer too small is the caller's own error, and the port reports it as operational.
    #[test]
    fn a_short_buffer_is_refused() {
        let store = store();
        let mut too_small = [0u8; DIGEST_LEN - 1];
        let mut binding = [0u8; DIGEST_LEN];

        assert_eq!(
            store.sign_migration(
                &MigrationCertPayload {
                    agora: AGORA_A,
                    successor_public_key: &[],
                },
                &mut too_small,
            ),
            Err(ProtocolError::Unavailable)
        );
        assert_eq!(
            store
                .create_root(
                    AGORA_A,
                    RootMaterialOut {
                        public_key: &mut too_small,
                        binding: &mut binding,
                    },
                )
                .unwrap_err(),
            ProtocolError::Unavailable
        );
    }

    /// The seed must not reach a log or a crash report.
    #[test]
    fn debug_does_not_leak_the_seed() {
        let rendered = format!("{:?}", store());
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains("5a"), "seed leaked into Debug output");
    }
}
