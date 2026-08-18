// SPDX-License-Identifier: MIT OR Apache-2.0

//! The planned-migration handoff and its canonical encoding (§9.3).
//!
//! When a member moves to a new device, the old device — after signing the migration
//! certificate over the successor's freshly generated root key — hands the successor
//! everything the migration *proof* needs about the predecessor, because the successor is
//! the prover: it is the device that submits `credentials/migrate`, and the statement it
//! proves must open the old leaf. That takes four things: `sk_cred`, which carries across
//! the lineage and is not regenerated; the old credential's `r_root` and `pk_root`, which
//! together with `sk_cred` open `Commit(pk_root, sk_cred, r_root, agora_id)`; and the
//! certificate authorizing exactly this transition. This module is that handoff as bytes.
//!
//! The consumed leaf itself is deliberately **not** carried: it is derivable from what is,
//! and a derived value cannot disagree with the values it derives from — carrying both
//! would create the one inconsistency this format could otherwise never represent.
//!
//! # This is the one encoding that carries secrets
//!
//! Every other wire format in this crate is public material. The handoff exists to move
//! `sk_cred` (and `r_root`, which rides with it) between two devices the same member
//! controls, so the secrets in the bytes are the point, not a leak — but it makes the
//! transport rules absolute: §9.3 requires the transfer be local and deliberate (the same
//! class of channel as §8.3's commitment exchange), it must never transit Skiora or any
//! network service, and the host must destroy its copy of the encoded buffer once decoded.
//! Decoding itself leaves residue the secret newtypes cannot reach — the secrets pass
//! through plain stack copies on their way into zeroizing storage — so the destruction
//! obligation covers the whole decode path, not only the buffer the host was handed.
//! An adversary holding these bytes holds the §15 durable-key position *plus* a signed
//! authorization for one successor.
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
use crate::digest::DIGEST_LEN;
use crate::error::ProtocolError;
use crate::secret::{CredentialKey, RootOpening};

/// The wire format this module reads and writes.
///
/// Decoders reject versions they do not know rather than guessing; see
/// [`FORMAT_VERSION`](crate::FORMAT_VERSION) for the argument.
pub const HANDOFF_VERSION: u8 = 1;

/// Width of the length prefix on each variable-length field.
const LENGTH_PREFIX: usize = core::mem::size_of::<u64>();

/// What the old device hands the successor in a planned migration (§9.3).
///
/// Owned where the material is secret, borrowed where it is not: `credential_key` and
/// `root_opening` decode into values that redact, zeroize, and resist casual duplication,
/// while the public key and certificate stay borrows of the caller's buffer.
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
    /// The old credential's `r_root` — a witness the migration proof opens the old leaf
    /// with. It does not survive into the successor credential, whose opening is fresh.
    pub root_opening: RootOpening,
    /// The old credential's `pk_root` — the key the migration certificate verifies under,
    /// inside the proof, never in the clear (§9.3).
    pub root_public_key: &'a [u8],
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
        1 + DIGEST_LEN
            + DIGEST_LEN
            + DIGEST_LEN
            + LENGTH_PREFIX
            + self.root_public_key.len()
            + LENGTH_PREFIX
            + self.migration_cert.len()
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
        put(self.root_opening.expose());
        put(&(self.root_public_key.len() as u64).to_le_bytes());
        put(self.root_public_key);
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
        let root_opening = RootOpening::new(take_digest(&mut rest)?);
        let root_public_key = take_framed(&mut rest)?;
        let migration_cert = take_framed(&mut rest)?;

        if !rest.is_empty() {
            return Err(ProtocolError::Malformed);
        }

        Ok(Self {
            agora,
            credential_key,
            root_opening,
            root_public_key,
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

/// Reads a length-prefixed field, advancing `rest`.
fn take_framed<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], ProtocolError> {
    let prefix = rest
        .get(..LENGTH_PREFIX)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    let len = usize::try_from(u64::from_le_bytes(prefix)).map_err(|_| ProtocolError::Malformed)?;
    // Split past the prefix first, then take `len` from the remainder: computing
    // `LENGTH_PREFIX + len` would overflow — and panic in an overflow-checked build — for a
    // hostile length near `usize::MAX`, where this returns `Malformed` instead. `body`'s
    // success bounds `len` at or below the remainder, so the reslice cannot panic.
    let after_prefix = rest.get(LENGTH_PREFIX..).ok_or(ProtocolError::Malformed)?;
    let body = after_prefix.get(..len).ok_or(ProtocolError::Malformed)?;
    *rest = &after_prefix[len..];
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{MigrationHandoff, HANDOFF_VERSION};
    use crate::agora::AgoraId;
    use crate::error::ProtocolError;
    use crate::secret::{CredentialKey, RootOpening};
    use std::format;
    use std::vec;
    use std::vec::Vec;

    fn sample<'a>(public_key: &'a [u8], cert: &'a [u8]) -> MigrationHandoff<'a> {
        MigrationHandoff {
            agora: AgoraId::from_bytes([0x7e; 32]),
            credential_key: CredentialKey::new([0x44; 32]),
            root_opening: RootOpening::new([0x22; 32]),
            root_public_key: public_key,
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
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&3u64.to_le_bytes());
        expected.extend_from_slice(&[0xcc; 3]);
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(&[0xdd; 4]);
        assert_eq!(encoded(&sample(&[0xcc; 3], &[0xdd; 4])), expected);
    }

    #[test]
    fn round_trips_byte_exactly() {
        let handoff = sample(b"public-key", b"cert-bytes");
        let bytes = encoded(&handoff);
        let decoded = MigrationHandoff::decode(&bytes).expect("valid encoding");
        assert_eq!(decoded, handoff);
        assert_eq!(encoded(&decoded), bytes, "encoding is not canonical");
    }

    /// Two adjacent framed fields: their boundary must not be movable, or bytes could slide
    /// between the public key and the certificate.
    #[test]
    fn the_framed_field_boundary_is_not_movable() {
        assert_ne!(encoded(&sample(b"ab", b"c")), encoded(&sample(b"a", b"bc")));
    }

    #[test]
    fn empty_variable_fields_are_framed_not_elided() {
        assert_ne!(encoded(&sample(b"", b"")), encoded(&sample(b"", b"\0")));
        MigrationHandoff::decode(&encoded(&sample(b"", b"")))
            .expect("empty variable fields are representable");
    }

    #[test]
    fn truncation_is_rejected_at_every_length() {
        let bytes = encoded(&sample(b"pk", b"cert"));
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
        let mut bytes = encoded(&sample(b"pk", b"cert"));
        bytes.push(0);
        assert_eq!(
            MigrationHandoff::decode(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = encoded(&sample(b"pk", b"cert"));
        bytes[0] = HANDOFF_VERSION + 1;
        assert_eq!(
            MigrationHandoff::decode(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_overstated_length_is_rejected() {
        for framed_field in 0..2 {
            let prefix_at = match framed_field {
                0 => 1 + 32 + 32 + 32,
                _ => 1 + 32 + 32 + 32 + 8 + 2,
            };
            // A moderately overstated length, then a pointer-width-maximum one: the latter
            // would overflow `prefix + len`, so it must refuse cleanly rather than panic.
            for width in [1, super::LENGTH_PREFIX] {
                let mut bytes = encoded(&sample(b"pk", b"cert"));
                bytes[prefix_at..prefix_at + width].fill(0xff);
                assert_eq!(
                    MigrationHandoff::decode(&bytes),
                    Err(ProtocolError::Malformed),
                    "framed field {framed_field} accepted an overstated length (width {width})"
                );
            }
        }
    }

    #[test]
    fn a_short_buffer_is_refused() {
        let handoff = sample(b"pk", b"cert");
        let mut buffer = vec![0u8; handoff.encoded_len() - 1];
        assert_eq!(handoff.encode(&mut buffer), Err(ProtocolError::Malformed));
    }

    /// The struct must not leak its secrets through `Debug` — it is the one wire type
    /// carrying them, so the redaction it inherits from [`CredentialKey`] and
    /// [`RootOpening`] is checked here by name rather than assumed.
    #[test]
    fn debug_does_not_leak_the_secrets() {
        let rendered = format!("{:?}", sample(b"pk", b"cert"));
        assert!(!rendered.contains("44, 44"), "sk_cred leaked: {rendered}");
        assert!(!rendered.contains("22, 22"), "r_root leaked: {rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }
}
