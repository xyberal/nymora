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
//! # The signatures are the real scheme
//!
//! The backend signs with the certificate scheme the standardized circuit verifies:
//! EdDSA over Jubjub with a Poseidon transcript, stated as an equation in §9.1
//! (proposals 0033, 0034) and implemented in `nymora-crypto`. Each agora's signing
//! scalar is minted from the derived seed by the truncation rule of proposal 0035, so
//! every key this store produces is canonical by construction. What stays provisional
//! is the *custody*, not the cryptography: one software seed behind every agora is
//! exactly what no hardware backend looks like.
//!
//! # Where `nymora-crypto` begins and ends here
//!
//! The per-agora seed derivations remain local keyed hashes over local separators: they have no
//! counterparty, are never recomputed by anyone else, and registering stand-in entries in the
//! permanent protocol domain-tag registry would be a worse trade than the few lines of framing
//! below. The signatures are the opposite case — every verifier recomputes exactly what was
//! signed — so both the message compression and the equation come from `nymora-crypto`,
//! where every value with a counterparty must live or two implementations will
//! eventually disagree.
//!
//! The local prefixes are deliberately **not** shaped like `nymora/v0/...` protocol domain
//! tags, so that no one mistakes one for the other.

use crate::key_store::{
    Capabilities, EpochCertPayload, KeyStore, MigrationCertPayload, RootMaterialOut,
    RootMaterialWritten,
};
use nymora_core::{AgoraId, ProtocolError, SecretBytes, DIGEST_LEN};
use nymora_crypto::signature;
use sha2::{Digest, Sha256};

/// Separator for this backend's root-seed derivation. Local to it, not a protocol domain tag.
///
/// One separator suffices: the only local derivation is the per-agora signing seed, and the
/// two certificate kinds are separated inside the messages they sign by the protocol domain
/// tag leading each canonical payload.
const ROOT: &[u8] = b"software-key-store/v0/root";

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
fn put(out: &mut [u8], value: &[u8]) -> Result<usize, ProtocolError> {
    out.get_mut(..value.len())
        .ok_or(ProtocolError::Malformed)?
        .copy_from_slice(value);
    Ok(value.len())
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

    /// Derives the signing scalar for one agora's root key.
    ///
    /// One master seed, one derived seed per agora, one canonical scalar per seed (the
    /// minting rule of proposal 0035): `create_root` and both signing methods meet at
    /// this derivation, which is what makes the signatures verify under the public key
    /// `create_root` published.
    fn root_key(&self, agora: AgoraId) -> SecretBytes<{ signature::SEED_LEN }> {
        let mut hasher = Sha256::new();
        framed(&mut hasher, ROOT);
        framed(&mut hasher, self.seed.expose());
        framed(&mut hasher, agora.as_bytes());
        SecretBytes::new(signature::mint_signing_secret(hasher.finalize().into()))
    }

    /// Signs a compressed certificate message with one agora's root key.
    ///
    /// The message is computed by `nymora-crypto`'s canonical compression rather than
    /// re-derived here, so this backend cannot drift from what the circuit recomputes —
    /// the property the `KeyStore` contract demands of real backends.
    fn sign_message(
        &self,
        agora: AgoraId,
        message: Option<nymora_crypto::F>,
    ) -> Result<[u8; signature::SIGNATURE_LEN], ProtocolError> {
        // No message means the payload's key bytes name no subgroup point — the
        // caller's own input, unusable for this scheme.
        let message = message.ok_or(ProtocolError::Malformed)?;
        signature::sign(self.root_key(agora).expose(), &message).ok_or(ProtocolError::Malformed)
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
        let public_key = signature::public_key(self.root_key(agora).expose())
            .expect("minted keys are canonical");
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
        let message = nymora_crypto::signature::epoch_cert_message(
            &payload.agora,
            payload.epoch,
            payload.epoch_public_key,
        );
        let value = self.sign_message(payload.agora, message)?;
        put(signature, &value)
    }

    fn sign_migration(
        &self,
        payload: &MigrationCertPayload<'_>,
        signature: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let message = nymora_crypto::signature::migration_cert_message(
            &payload.agora,
            payload.successor_public_key,
        );
        let value = self.sign_message(payload.agora, message)?;
        put(signature, &value)
    }
}

#[cfg(test)]
mod tests {
    use super::SoftwareKeyStore;
    use crate::key_store::{EpochCertPayload, KeyStore, MigrationCertPayload, RootMaterialOut};
    use nymora_core::{AgoraId, Epoch, ProtocolError, DIGEST_LEN};
    use nymora_crypto::signature;
    use std::format;

    const SEED: [u8; DIGEST_LEN] = [0x5a; DIGEST_LEN];
    const AGORA_A: AgoraId = AgoraId::from_bytes([0x01; DIGEST_LEN]);
    const AGORA_B: AgoraId = AgoraId::from_bytes([0x02; DIGEST_LEN]);

    fn store() -> SoftwareKeyStore {
        SoftwareKeyStore::new(SEED)
    }

    /// A real subgroup point to certify: the payload's key bytes must name one, or
    /// there is no message to sign.
    fn epoch_point(byte: u8) -> [u8; 32] {
        signature::public_key(&signature::mint_signing_secret([byte; 32]))
            .expect("minted keys are canonical")
    }

    fn root_of(store: &SoftwareKeyStore, agora: AgoraId) -> [u8; signature::PUBLIC_KEY_LEN] {
        let mut public_key = [0u8; signature::PUBLIC_KEY_LEN];
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
        assert_eq!(written.public_key, public_key.len());
        public_key
    }

    fn epoch_cert(
        store: &SoftwareKeyStore,
        agora: AgoraId,
        epoch: u64,
        key: &[u8],
    ) -> [u8; signature::SIGNATURE_LEN] {
        let mut sig = [0u8; signature::SIGNATURE_LEN];
        let written = store
            .sign_epoch_cert(
                &EpochCertPayload {
                    agora,
                    epoch: Epoch::new(epoch),
                    epoch_public_key: key,
                },
                &mut sig,
            )
            .expect("buffer is large enough");
        assert_eq!(written, sig.len());
        sig
    }

    fn migration(
        store: &SoftwareKeyStore,
        agora: AgoraId,
        target: &[u8],
    ) -> [u8; signature::SIGNATURE_LEN] {
        let mut sig = [0u8; signature::SIGNATURE_LEN];
        store
            .sign_migration(
                &MigrationCertPayload {
                    agora,
                    successor_public_key: target,
                },
                &mut sig,
            )
            .expect("buffer is large enough");
        sig
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
        let mut public_key = [0u8; signature::PUBLIC_KEY_LEN];
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

    /// The property the proof layer relies on: what this backend signs, anyone holding the
    /// public key from `create_root` can verify — including the stub prover recomputing
    /// the compressed message from witness values.
    #[test]
    fn an_epoch_cert_verifies_under_the_created_root() {
        let store = store();
        let key = epoch_point(0xcc);
        let sig = epoch_cert(&store, AGORA_A, 7, &key);
        let message = signature::epoch_cert_message(&AGORA_A, Epoch::new(7), &key)
            .expect("the key is a subgroup point");
        assert!(signature::verify(&root_of(&store, AGORA_A), &message, &sig));
    }

    #[test]
    fn a_migration_cert_verifies_under_the_created_root() {
        let store = store();
        let key = epoch_point(0xee);
        let sig = migration(&store, AGORA_A, &key);
        let message =
            signature::migration_cert_message(&AGORA_A, &key).expect("the key is a subgroup point");
        assert!(signature::verify(&root_of(&store, AGORA_A), &message, &sig));
    }

    /// The two certificate kinds must not be confusable, checked the way an attacker
    /// would probe it: a signature produced as one kind, presented as the other, must
    /// not verify. The separation comes from the field domain leading each compressed
    /// message, not from anything local to this backend.
    #[test]
    fn one_certificate_kind_does_not_verify_as_the_other() {
        let store = store();
        let key = epoch_point(0xcc);
        let root = root_of(&store, AGORA_A);
        let epoch_sig = epoch_cert(&store, AGORA_A, 0, &key);
        let migration_message =
            signature::migration_cert_message(&AGORA_A, &key).expect("the key is a subgroup point");
        assert!(!signature::verify(&root, &migration_message, &epoch_sig));
    }

    /// The requirement stated on `KeyStore`: a certificate must not replay across agoras.
    /// Two properties compound here — the message names its agora, and each agora's root
    /// is a different key entirely.
    #[test]
    fn an_epoch_cert_does_not_verify_in_another_agora() {
        let store = store();
        let key = epoch_point(0xcc);
        let sig = epoch_cert(&store, AGORA_A, 7, &key);
        let replayed = signature::epoch_cert_message(&AGORA_B, Epoch::new(7), &key)
            .expect("the key is a subgroup point");
        assert!(!signature::verify(
            &root_of(&store, AGORA_B),
            &replayed,
            &sig
        ));
    }

    #[test]
    fn an_epoch_cert_binds_its_epoch_and_key() {
        let store = store();
        let base = epoch_cert(&store, AGORA_A, 7, &epoch_point(0xcc));
        assert_ne!(base, epoch_cert(&store, AGORA_A, 8, &epoch_point(0xcc)));
        assert_ne!(base, epoch_cert(&store, AGORA_A, 7, &epoch_point(0xcd)));
    }

    #[test]
    fn a_migration_cert_binds_its_agora_and_target() {
        let store = store();
        let base = migration(&store, AGORA_A, &epoch_point(0xee));
        assert_ne!(base, migration(&store, AGORA_B, &epoch_point(0xee)));
        assert_ne!(base, migration(&store, AGORA_A, &epoch_point(0xef)));
    }

    /// A payload whose key bytes name no subgroup point has no message and cannot be
    /// signed — the serialization boundary of §9.1's cofactor clause, at the signer.
    #[test]
    fn a_non_point_key_is_refused() {
        let store = store();
        let mut sig = [0u8; signature::SIGNATURE_LEN];
        assert_eq!(
            store.sign_epoch_cert(
                &EpochCertPayload {
                    agora: AGORA_A,
                    epoch: Epoch::new(7),
                    epoch_public_key: &[0xff; 32],
                },
                &mut sig,
            ),
            Err(ProtocolError::Malformed)
        );
    }

    /// A buffer too small is the caller's own input error, not an operational condition —
    /// the same mapping `SecureStorage` and the bundle codec use.
    #[test]
    fn a_short_buffer_is_refused() {
        let store = store();
        let mut short_sig = [0u8; signature::SIGNATURE_LEN - 1];
        let mut short_key = [0u8; signature::PUBLIC_KEY_LEN - 1];
        let mut binding = [0u8; DIGEST_LEN];

        assert_eq!(
            store.sign_migration(
                &MigrationCertPayload {
                    agora: AGORA_A,
                    successor_public_key: &epoch_point(0xee),
                },
                &mut short_sig,
            ),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            store
                .create_root(
                    AGORA_A,
                    RootMaterialOut {
                        public_key: &mut short_key,
                        binding: &mut binding,
                    },
                )
                .unwrap_err(),
            ProtocolError::Malformed
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
