// SPDX-License-Identifier: MIT OR Apache-2.0

//! The planned-migration handoff and its canonical encoding (§9.3).
//!
//! When a member moves to a new device, the old device — after signing the migration
//! certificate over the successor's freshly generated root key — hands the successor three
//! things it cannot proceed without: `sk_cred`, which carries across the lineage and is not
//! regenerated; the certificate authorizing exactly this transition; and the leaf being
//! consumed, from which the successor derives the migration nullifier
//! `Hash(sk_cred, leaf_old, agora_id)`. This module is that handoff as bytes.
//!
//! # This is the one encoding that carries a secret
//!
//! Every other wire format in this crate is public material. The handoff exists to move
//! `sk_cred` between two devices the same member controls, so the secret in the bytes is the
//! point, not a leak — but it makes the transport rules absolute: §9.3 requires the transfer
//! be local and deliberate (the same class of channel as §8.3's commitment exchange), it must
//! never transit Skiora or any network service, and the host must destroy its copy of the
//! encoded buffer once decoded. An adversary holding these bytes holds the §15 durable-key
//! position *plus* a signed authorization for one successor.
//!
//! # Why it is canonical anyway
//!
//! The handoff never reaches a counterparty, but the two ends may be two implementations —
//! an old phone and a new CLI — so the bytes must agree across every implementation for the
//! same reason the conformance vectors exist. The encoding follows the bundle's discipline
//! (§6.6): version-led, every variable field length-framed, strict decoding, no optional
//! fields, trailing bytes rejected.
//!
//! # What it deliberately omits
//!
//! The old credential's hardware binding. The migration certificate — verified in-circuit
//! against the old, still-valid leaf — fully replaces it as the authorization for the
//! transition, and the successor presents its *own* binding at admission if its backend
//! attests. Carrying the old binding would add bytes an adversary could correlate and no
//! verifier would consume.

use crate::agora::AgoraId;
use crate::digest::{Commitment, DIGEST_LEN};
use crate::error::ProtocolError;
use crate::secret::CredentialKey;

/// The wire format this module reads and writes.
///
/// Decoders reject versions they do not know rather than guessing; see
/// [`FORMAT_VERSION`](crate::FORMAT_VERSION) for the argument.
pub const HANDOFF_VERSION: u8 = 1;

/// Width of the length prefix on the variable-length field.
const LENGTH_PREFIX: usize = core::mem::size_of::<u64>();

/// What the old device hands the successor in a planned migration (§9.3).
///
/// Owned where the material is secret, borrowed where it is not: `credential_key` is a
/// [`CredentialKey`] so that decoding produces a value that redacts, zeroizes, and resists
/// casual duplication, while the certificate stays a borrow of the caller's buffer.
///
/// Not `Clone`, deliberately — the handoff exists in as few places as possible.
#[derive(Debug, PartialEq, Eq)]
pub struct MigrationHandoff<'a> {
    /// The agora this migration happens within.
    ///
    /// Present so the handoff is self-describing to the successor and cannot be applied to
    /// the wrong membership: the certificate already binds the agora inside its signed
    /// payload, and the decoder's caller must check this field against the agora it expects.
    pub agora: AgoraId,
    /// `sk_cred`, carried across the lineage — never regenerated (§9.3).
    pub credential_key: CredentialKey,
    /// The old leaf this migration consumes, bound into the migration nullifier.
    pub consumed_leaf: Commitment,
    /// The root signature over the canonical [`MigrationCertPayload`] encoding.
    ///
    /// The signature alone: the payload is recomputed by the verifying circuit from values
    /// the successor already holds — the agora and its own root public key.
    ///
    /// [`MigrationCertPayload`]: crate::MigrationCertPayload
    pub migration_cert: &'a [u8],
}

impl<'a> MigrationHandoff<'a> {
    /// The exact number of bytes [`encode`](Self::encode) will write.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        1 + DIGEST_LEN + DIGEST_LEN + DIGEST_LEN + LENGTH_PREFIX + self.migration_cert.len()
    }

    /// Writes the canonical encoding into `out`, returning the number of bytes written.
    ///
    /// The output buffer contains `sk_cred` from this point on; the module documentation
    /// states what the host owes those bytes.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] if `out` is shorter than
    /// [`encoded_len`](Self::encoded_len).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ProtocolError> {
        let total = self.encoded_len();
        let out = out.get_mut(..total).ok_or(ProtocolError::Malformed)?;

        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };

        put(&[HANDOFF_VERSION]);
        put(self.agora.as_bytes());
        put(self.credential_key.expose());
        put(self.consumed_leaf.as_bytes());
        put(&(self.migration_cert.len() as u64).to_le_bytes());
        put(self.migration_cert);

        Ok(total)
    }

    /// Reads a handoff from its canonical encoding.
    ///
    /// Strict, like [`Bundle::decode`](crate::Bundle::decode): unknown versions, truncation,
    /// overstated lengths, and trailing bytes are all [`ProtocolError::Malformed`]. The
    /// caller must compare [`agora`](Self::agora) against the agora it expects before using
    /// anything else in the value.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] for any input that is not exactly one valid encoding.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut rest = bytes;

        let (version, tail) = rest.split_first().ok_or(ProtocolError::Malformed)?;
        if *version != HANDOFF_VERSION {
            return Err(ProtocolError::Malformed);
        }
        rest = tail;

        let agora = AgoraId::from_bytes(take_digest(&mut rest)?);
        let credential_key = CredentialKey::new(take_digest(&mut rest)?);
        let consumed_leaf = Commitment::from_bytes(take_digest(&mut rest)?);

        let prefix = rest
            .get(..LENGTH_PREFIX)
            .ok_or(ProtocolError::Malformed)?
            .try_into()
            .map_err(|_| ProtocolError::Malformed)?;
        let len =
            usize::try_from(u64::from_le_bytes(prefix)).map_err(|_| ProtocolError::Malformed)?;
        let migration_cert = rest
            .get(LENGTH_PREFIX..LENGTH_PREFIX + len)
            .ok_or(ProtocolError::Malformed)?;
        rest = &rest[LENGTH_PREFIX + len..];

        if !rest.is_empty() {
            return Err(ProtocolError::Malformed);
        }

        Ok(Self {
            agora,
            credential_key,
            consumed_leaf,
            migration_cert,
        })
    }
}

/// Reads a fixed-width 32-byte field, advancing `rest`.
fn take_digest(rest: &mut &[u8]) -> Result<[u8; DIGEST_LEN], ProtocolError> {
    let bytes = rest
        .get(..DIGEST_LEN)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    *rest = &rest[DIGEST_LEN..];
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{MigrationHandoff, HANDOFF_VERSION};
    use crate::agora::AgoraId;
    use crate::digest::Commitment;
    use crate::error::ProtocolError;
    use crate::secret::CredentialKey;
    use std::format;
    use std::vec;
    use std::vec::Vec;

    fn sample(cert: &[u8]) -> MigrationHandoff<'_> {
        MigrationHandoff {
            agora: AgoraId::from_bytes([0x7e; 32]),
            credential_key: CredentialKey::new([0x44; 32]),
            consumed_leaf: Commitment::from_bytes([0xab; 32]),
            migration_cert: cert,
        }
    }

    fn encoded(handoff: &MigrationHandoff<'_>) -> Vec<u8> {
        let mut buffer = vec![0u8; handoff.encoded_len()];
        let written = handoff
            .encode(&mut buffer)
            .expect("buffer is exactly sized");
        assert_eq!(written, buffer.len(), "encoded_len disagreed with encode");
        buffer
    }

    /// The layout, restated independently of the implementation.
    ///
    /// The handoff crosses implementations — an old phone to a new CLI — so a moved byte is
    /// a member stranded mid-migration. A failure here is a format version bump, never a
    /// fixed expectation.
    #[test]
    fn the_layout_is_pinned() {
        let mut expected = vec![HANDOFF_VERSION];
        expected.extend_from_slice(&[0x7e; 32]);
        expected.extend_from_slice(&[0x44; 32]);
        expected.extend_from_slice(&[0xab; 32]);
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(&[0xdd; 4]);
        assert_eq!(encoded(&sample(&[0xdd; 4])), expected);
    }

    #[test]
    fn round_trips_byte_exactly() {
        let handoff = sample(b"cert-bytes");
        let bytes = encoded(&handoff);
        let decoded = MigrationHandoff::decode(&bytes).expect("valid encoding");
        assert_eq!(decoded, handoff);
        assert_eq!(encoded(&decoded), bytes, "encoding is not canonical");
    }

    #[test]
    fn an_empty_certificate_is_framed_not_elided() {
        assert_ne!(encoded(&sample(&[])), encoded(&sample(&[0x00])));
        MigrationHandoff::decode(&encoded(&sample(&[]))).expect("empty cert is representable");
    }

    #[test]
    fn truncation_is_rejected_at_every_length() {
        let bytes = encoded(&sample(b"cert"));
        for cut in 0..bytes.len() {
            assert_eq!(
                MigrationHandoff::decode(&bytes[..cut]),
                Err(ProtocolError::Malformed),
                "a {cut}-byte prefix decoded"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encoded(&sample(b"cert"));
        bytes.push(0);
        assert_eq!(
            MigrationHandoff::decode(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = encoded(&sample(b"cert"));
        bytes[0] = HANDOFF_VERSION + 1;
        assert_eq!(
            MigrationHandoff::decode(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_overstated_length_is_rejected() {
        let mut bytes = encoded(&sample(b"cert"));
        let prefix_at = 1 + 32 + 32 + 32;
        bytes[prefix_at] = 0xff;
        assert_eq!(
            MigrationHandoff::decode(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn a_short_buffer_is_refused() {
        let handoff = sample(b"cert");
        let mut buffer = vec![0u8; handoff.encoded_len() - 1];
        assert_eq!(handoff.encode(&mut buffer), Err(ProtocolError::Malformed));
    }

    /// The struct must not leak `sk_cred` through `Debug` — it is the one wire type
    /// carrying a secret, so the redaction it inherits from [`CredentialKey`] is checked
    /// here by name rather than assumed.
    #[test]
    fn debug_does_not_leak_the_credential_key() {
        let rendered = format!("{:?}", sample(b"cert"));
        assert!(!rendered.contains("44, 44"), "sk_cred leaked: {rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }
}
