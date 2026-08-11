// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical signed payloads for the two root-key certificates (§9.1, §9.3).
//!
//! # Why certificates that never travel still have a wire format
//!
//! An epoch certificate never leaves the device, and a migration certificate is verified
//! inside a proof rather than transmitted in the clear. It is tempting to conclude their
//! byte layout is each backend's private business. It is the opposite: both are verified
//! **inside the standardized circuit** (§6.5), which recomputes the signed message from
//! witness values — so the message bytes must agree, bit for bit, between every signing
//! backend and the one shared circuit. A backend that framed them differently would produce
//! proofs no other implementation can verify, or a per-backend proof shape, which is the
//! fingerprinting §6.5 exists to prevent. That is the same argument [`crate::Bundle`] makes
//! for the external bundle, applied to bytes that happen never to cross a network.
//!
//! # The domain tag is inside the message
//!
//! Both certificates are signed by the same `sk_root`. The framed domain tag leading each
//! encoding is what keeps them unforgeable for each other: a migration certificate accepted
//! as an epoch certificate — or the reverse — would let one authorization stand in for the
//! other (see the tag registry in [`crate::Domain`]). The `agora_id` is likewise inside the
//! signed message, not merely alongside the signing request, so neither certificate can be
//! replayed into another agora the member belongs to (§16.1). Placing both in the payload
//! type makes the binding structural: there is no way to produce the bytes without them.
//!
//! # Encoding
//!
//! Every field, the tag included, is preceded by its length as a `u64` little-endian —
//! the same convention as the bundle (§6.6) and the hasher in `nymora-crypto` — making the
//! encoding injective: no arrangement of field contents can move the boundary between two
//! fields. Fields appear in a fixed order and none is optional, so two implementations
//! cannot disagree about what was signed.

use crate::agora::AgoraId;
use crate::digest::DIGEST_LEN;
use crate::domain::Domain;
use crate::epoch::Epoch;
use crate::error::ProtocolError;

/// Width of the length prefix on each field.
const LENGTH_PREFIX: usize = core::mem::size_of::<u64>();

/// A field's encoded width: its length prefix plus its contents.
const fn framed(len: usize) -> usize {
    LENGTH_PREFIX + len
}

/// Emits one length-framed field as two chunks.
fn put_framed<F: FnMut(&[u8])>(put: &mut F, bytes: &[u8]) {
    put(&(bytes.len() as u64).to_le_bytes());
    put(bytes);
}

/// Writes `encoded_len` bytes of parts into `out`, or refuses a short buffer.
fn encode_into(
    out: &mut [u8],
    encoded_len: usize,
    parts: impl FnOnce(&mut dyn FnMut(&[u8])),
) -> Result<usize, ProtocolError> {
    let out = out.get_mut(..encoded_len).ok_or(ProtocolError::Malformed)?;
    let mut at = 0;
    parts(&mut |part: &[u8]| {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    });
    Ok(encoded_len)
}

/// The payload an epoch certificate signs over (§9.1).
///
/// The certificate binds a freshly generated epoch key to a credential for exactly one
/// epoch, in exactly one agora. All three facts are fields here, so a signature over the
/// canonical encoding cannot omit any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCertPayload<'a> {
    /// The agora the certificate is for. Inside the signed message — see the module
    /// documentation for why this is structural rather than a backend obligation.
    pub agora: AgoraId,
    /// The epoch the key is being certified for. A certificate that did not name its epoch
    /// would verify in any epoch, which is §9.1's forward-secrecy bound expressed as a
    /// signed field.
    pub epoch: Epoch,
    /// The freshly generated epoch public key, in whatever encoding the signature scheme
    /// uses.
    pub epoch_public_key: &'a [u8],
}

impl EpochCertPayload<'_> {
    /// The exact number of bytes [`encode`](Self::encode) will write.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        framed(Domain::EpochCertificate.tag().len())
            + framed(DIGEST_LEN)
            + framed(8)
            + framed(self.epoch_public_key.len())
    }

    /// Emits the canonical encoding as a sequence of chunks, in order.
    ///
    /// This is the single source of truth for the byte sequence; [`encode`](Self::encode)
    /// is built on it, and a signing backend that hashes incrementally should consume it
    /// directly rather than restating the layout.
    pub fn encode_parts<F: FnMut(&[u8])>(&self, mut put: F) {
        put_framed(&mut put, Domain::EpochCertificate.tag().as_bytes());
        put_framed(&mut put, self.agora.as_bytes());
        put_framed(&mut put, &self.epoch.get().to_le_bytes());
        put_framed(&mut put, self.epoch_public_key);
    }

    /// Writes the canonical encoding into `out`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] if `out` is shorter than
    /// [`encoded_len`](Self::encoded_len).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ProtocolError> {
        encode_into(out, self.encoded_len(), |put| self.encode_parts(put))
    }
}

/// The payload a migration certificate signs over (§9.3).
///
/// A one-time authorization by the old device's root key for exactly one successor, in
/// exactly one agora. One-time-ness is not enforced here — the migration nullifier consuming
/// the old leaf is what makes a second successor unadmittable (§9.3) — but the successor
/// key and the agora are both inside the signed bytes, so the certificate authorizes this
/// transition and no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationCertPayload<'a> {
    /// The agora the migration happens within. See [`EpochCertPayload::agora`].
    pub agora: AgoraId,
    /// The successor credential's root public key, in the same encoding the key store
    /// produces it (§9.3's `pk_root_new`).
    pub successor_public_key: &'a [u8],
}

impl MigrationCertPayload<'_> {
    /// The exact number of bytes [`encode`](Self::encode) will write.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        framed(Domain::MigrationCertificate.tag().len())
            + framed(DIGEST_LEN)
            + framed(self.successor_public_key.len())
    }

    /// Emits the canonical encoding as a sequence of chunks, in order.
    ///
    /// See [`EpochCertPayload::encode_parts`].
    pub fn encode_parts<F: FnMut(&[u8])>(&self, mut put: F) {
        put_framed(&mut put, Domain::MigrationCertificate.tag().as_bytes());
        put_framed(&mut put, self.agora.as_bytes());
        put_framed(&mut put, self.successor_public_key);
    }

    /// Writes the canonical encoding into `out`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] if `out` is shorter than
    /// [`encoded_len`](Self::encoded_len).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ProtocolError> {
        encode_into(out, self.encoded_len(), |put| self.encode_parts(put))
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochCertPayload, MigrationCertPayload};
    use crate::agora::AgoraId;
    use crate::epoch::Epoch;
    use crate::error::ProtocolError;
    use std::vec;
    use std::vec::Vec;

    const AGORA: AgoraId = AgoraId::from_bytes([0x7e; 32]);

    fn epoch_payload(pk: &[u8]) -> EpochCertPayload<'_> {
        EpochCertPayload {
            agora: AGORA,
            epoch: Epoch::new(7),
            epoch_public_key: pk,
        }
    }

    fn encoded_epoch(payload: &EpochCertPayload<'_>) -> Vec<u8> {
        let mut buffer = vec![0u8; payload.encoded_len()];
        let written = payload
            .encode(&mut buffer)
            .expect("buffer is exactly sized");
        assert_eq!(written, buffer.len(), "encoded_len disagreed with encode");
        buffer
    }

    fn encoded_migration(payload: &MigrationCertPayload<'_>) -> Vec<u8> {
        let mut buffer = vec![0u8; payload.encoded_len()];
        let written = payload
            .encode(&mut buffer)
            .expect("buffer is exactly sized");
        assert_eq!(written, buffer.len(), "encoded_len disagreed with encode");
        buffer
    }

    /// The layout, restated independently of the implementation.
    ///
    /// If this fails, the signed bytes moved — a protocol break for every certificate ever
    /// signed and every circuit that recomputes one, requiring a domain-tag version bump
    /// rather than a fixed expectation.
    #[test]
    fn the_epoch_cert_layout_is_pinned() {
        let mut expected = Vec::new();
        for field in [
            &b"nymora/v0/epoch-cert"[..],
            &[0x7e; 32][..],
            &7u64.to_le_bytes()[..],
            &[0xcc; 4][..],
        ] {
            expected.extend_from_slice(&(field.len() as u64).to_le_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(encoded_epoch(&epoch_payload(&[0xcc; 4])), expected);
    }

    #[test]
    fn the_migration_cert_layout_is_pinned() {
        let mut expected = Vec::new();
        for field in [
            &b"nymora/v0/migration-cert"[..],
            &[0x7e; 32][..],
            &[0xdd; 4][..],
        ] {
            expected.extend_from_slice(&(field.len() as u64).to_le_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(
            encoded_migration(&MigrationCertPayload {
                agora: AGORA,
                successor_public_key: &[0xdd; 4],
            }),
            expected
        );
    }

    /// The two certificate kinds share a signing key; the tag is what separates them.
    ///
    /// The encodings must differ even when every other field byte coincides, or one
    /// authorization could stand in for the other.
    #[test]
    fn the_two_certificate_kinds_cannot_collide() {
        let epoch_bytes = encoded_epoch(&epoch_payload(&[0xcc; 4]));
        let migration_bytes = encoded_migration(&MigrationCertPayload {
            agora: AGORA,
            successor_public_key: &[0xcc; 4],
        });
        assert_ne!(epoch_bytes, migration_bytes);
        assert!(
            !epoch_bytes.starts_with(&migration_bytes[..16])
                && !migration_bytes.starts_with(&epoch_bytes[..16]),
            "the leading tags do not separate the encodings"
        );
    }

    /// Every fact the certificate binds must change the signed bytes.
    #[test]
    fn every_field_changes_the_encoding() {
        let base = encoded_epoch(&epoch_payload(&[0xcc; 4]));
        assert_ne!(
            base,
            encoded_epoch(&EpochCertPayload {
                agora: AgoraId::from_bytes([0x7f; 32]),
                ..epoch_payload(&[0xcc; 4])
            }),
            "the agora is not in the signed bytes"
        );
        assert_ne!(
            base,
            encoded_epoch(&EpochCertPayload {
                epoch: Epoch::new(8),
                ..epoch_payload(&[0xcc; 4])
            }),
            "the epoch is not in the signed bytes"
        );
        assert_ne!(
            base,
            encoded_epoch(&epoch_payload(&[0xcd; 4])),
            "the key is not in the signed bytes"
        );
    }

    /// `encode` and `encode_parts` are the same bytes — one layout, two consumers.
    #[test]
    fn streaming_and_buffered_encodings_agree() {
        let payload = epoch_payload(&[0xcc; 4]);
        let mut streamed = Vec::new();
        payload.encode_parts(|part| streamed.extend_from_slice(part));
        assert_eq!(streamed, encoded_epoch(&payload));

        let migration = MigrationCertPayload {
            agora: AGORA,
            successor_public_key: &[0xdd; 4],
        };
        let mut streamed = Vec::new();
        migration.encode_parts(|part| streamed.extend_from_slice(part));
        assert_eq!(streamed, encoded_migration(&migration));
    }

    #[test]
    fn a_short_buffer_is_refused() {
        let payload = epoch_payload(&[0xcc; 4]);
        let mut buffer = vec![0u8; payload.encoded_len() - 1];
        assert_eq!(payload.encode(&mut buffer), Err(ProtocolError::Malformed));
    }

    /// An empty key is representable and distinct from a short one — no field is optional.
    #[test]
    fn an_empty_key_is_framed_not_elided() {
        assert_ne!(
            encoded_epoch(&epoch_payload(&[])),
            encoded_epoch(&epoch_payload(&[0x00]))
        );
    }
}
