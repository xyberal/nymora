// SPDX-License-Identifier: MIT OR Apache-2.0

//! The external content bundle and its canonical encoding (§6.6).
//!
//! # Canonical encoding is a security requirement
//!
//! The attestation proof is Fiat-Shamir bound to `message_hash` (§6.5), so it cannot be
//! detached and reattached to different content. That binding is only as strong as the
//! encoding is unambiguous. If two distinct byte strings could decode to the same bundle, an
//! attacker could alter the bytes a recipient sees while leaving a proof that still verifies
//! — the proof would be checking a message the recipient is not reading.
//!
//! The encoding here is therefore **injective**, and decoding is strict rather than
//! forgiving. Every field is length-framed and present, lengths must account for the input
//! exactly, and trailing bytes are rejected. A decoder that accepted a sloppy encoding and
//! re-serialized it differently would reintroduce precisely the malleability the framing
//! removes, so the property to preserve when changing this module is that **every accepted
//! encoding re-encodes to itself, byte for byte**. There is a test for exactly that.
//!
//! The JSON in §6.6 describes which fields a bundle carries, not how they are laid out;
//! JSON's own encoding admits reordering, whitespace, and escape variation, none of which a
//! value bound by a proof can tolerate.
//!
//! # What the bundle does not contain
//!
//! No `agora_id`, no accumulator root, no epoch marker, no pseudonym of any kind (§6.6). A
//! verifier resolves the agora and epoch out-of-band through the tag (§6.4) before checking
//! anything. The encoded length is fully determined by the content and proof lengths, so
//! there is nowhere for such a field to hide.
//!
//! There are also no optional fields, which is why absent-versus-empty cannot arise: empty
//! content and empty proof are representable and distinct from each other, because each
//! carries its own explicit length.

use crate::digest::{MessageHash, Nullifier, Tag, DIGEST_LEN};
use crate::error::ProtocolError;

/// The wire format this module reads and writes.
///
/// Present so that a later revision — restoring corroboration (§6.3), say — is a new version
/// rather than a redefinition of this one. Decoders reject versions they do not know
/// (see [`Bundle::decode`]) rather than skipping unrecognized trailing data: a verifier that
/// silently ignored a corroboration section would report a weaker claim than the bundle
/// actually carries.
pub const FORMAT_VERSION: u8 = 1;

/// Width of the length prefix on each variable-length field.
const LENGTH_PREFIX: usize = core::mem::size_of::<u64>();

/// A published piece of content with the attestation standing behind it (§6.6).
///
/// Borrowed rather than owned: `nymora-core` is `no_std` with no allocator, and a bundle is
/// decoded from a buffer the host already holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bundle<'a> {
    /// The content itself, treated as opaque bytes.
    ///
    /// Opaque is load-bearing. `message_hash` is a hash of exactly these bytes, so anything
    /// that reinterpreted them — normalizing text, re-encoding a nested document — would
    /// break the binding, or worse, preserve it while changing what a reader sees.
    pub content: &'a [u8],
    /// The routing tag, `HMAC(K_tag_e, message_hash)` (§6.4).
    pub tag: Tag,
    /// The proof that a member of some agora stands behind this content.
    pub attestation: Attestation<'a>,
}

/// The `attestation_proof` object (§6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attestation<'a> {
    /// The zero-knowledge proof blob.
    ///
    /// Opaque here because the proving system is not yet chosen. §6.5 requires one
    /// standardized circuit across every agora, so in a deployed system this length is a
    /// constant — a bundle whose proof differs in size from everyone else's identifies its
    /// author's client, which is the fingerprinting §6.5 exists to prevent.
    pub proof: &'a [u8],
    /// `Hash(content)`, the value the proof is bound to.
    pub message_hash: MessageHash,
    /// The attestation nullifier (§6.1).
    pub nullifier: Nullifier,
}

impl<'a> Bundle<'a> {
    /// The exact number of bytes [`encode`](Self::encode) will write.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        1 + LENGTH_PREFIX
            + self.content.len()
            + DIGEST_LEN
            + LENGTH_PREFIX
            + self.attestation.proof.len()
            + DIGEST_LEN
            + DIGEST_LEN
    }

    /// Writes the canonical encoding into `out`, returning the number of bytes written.
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

        put(&[FORMAT_VERSION]);
        put(&(self.content.len() as u64).to_le_bytes());
        put(self.content);
        put(self.tag.as_bytes());
        put(&(self.attestation.proof.len() as u64).to_le_bytes());
        put(self.attestation.proof);
        put(self.attestation.message_hash.as_bytes());
        put(self.attestation.nullifier.as_bytes());

        Ok(total)
    }

    /// Reads a bundle from its canonical encoding.
    ///
    /// Strict by design: the input must be consumed exactly, every declared length must fit
    /// what remains, and the version must be one this decoder knows. Trailing bytes are an
    /// error rather than something to ignore — see the module documentation for why
    /// tolerance here would undo the proof binding.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] for any input that is not exactly one valid encoding.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut rest = bytes;

        let (version, tail) = rest.split_first().ok_or(ProtocolError::Malformed)?;
        if *version != FORMAT_VERSION {
            return Err(ProtocolError::Malformed);
        }
        rest = tail;

        let content = take_framed(&mut rest)?;
        let tag = Tag::from_bytes(take_digest(&mut rest)?);
        let proof = take_framed(&mut rest)?;
        let message_hash = MessageHash::from_bytes(take_digest(&mut rest)?);
        let nullifier = Nullifier::from_bytes(take_digest(&mut rest)?);

        if !rest.is_empty() {
            return Err(ProtocolError::Malformed);
        }

        Ok(Self {
            content,
            tag,
            attestation: Attestation {
                proof,
                message_hash,
                nullifier,
            },
        })
    }
}

/// Reads a length-prefixed field, advancing `rest`.
fn take_framed<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], ProtocolError> {
    let prefix = rest
        .get(..LENGTH_PREFIX)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    let len = u64::from_le_bytes(prefix);

    // A declared length wider than the machine's pointer type cannot address the input, and
    // saying so here keeps the cast below total on 32-bit hosts.
    let len = usize::try_from(len).map_err(|_| ProtocolError::Malformed)?;

    let body = rest
        .get(LENGTH_PREFIX..LENGTH_PREFIX + len)
        .ok_or(ProtocolError::Malformed)?;
    *rest = &rest[LENGTH_PREFIX + len..];
    Ok(body)
}

/// Reads a fixed-width digest, advancing `rest`.
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
    use super::{Attestation, Bundle, FORMAT_VERSION};
    use crate::digest::{MessageHash, Nullifier, Tag};
    use crate::error::ProtocolError;
    use std::vec;
    use std::vec::Vec;

    fn sample<'a>(content: &'a [u8], proof: &'a [u8]) -> Bundle<'a> {
        Bundle {
            content,
            tag: Tag::from_bytes([0x11; 32]),
            attestation: Attestation {
                proof,
                message_hash: MessageHash::from_bytes([0x22; 32]),
                nullifier: Nullifier::from_bytes([0x33; 32]),
            },
        }
    }

    fn encoded(bundle: &Bundle<'_>) -> Vec<u8> {
        let mut buffer = vec![0u8; bundle.encoded_len()];
        let written = bundle.encode(&mut buffer).expect("buffer is exactly sized");
        assert_eq!(written, buffer.len(), "encoded_len disagreed with encode");
        buffer
    }

    #[test]
    fn round_trips_byte_exactly() {
        let bundle = sample(b"hello", b"proof-blob");
        let bytes = encoded(&bundle);
        assert_eq!(Bundle::decode(&bytes).expect("valid encoding"), bundle);
    }

    /// The property the whole module exists to hold.
    ///
    /// Every accepted encoding must re-encode to itself. If some input decoded successfully
    /// but serialized back differently, two distinct byte strings would denote one bundle —
    /// and an attacker could hand a reader different bytes than the proof was computed over.
    #[test]
    fn every_accepted_encoding_re_encodes_to_itself() {
        for (content, proof) in [
            (&b""[..], &b""[..]),
            (&b"x"[..], &b""[..]),
            (&b""[..], &b"p"[..]),
            (&b"content of some length"[..], &b"proof"[..]),
        ] {
            let bytes = encoded(&sample(content, proof));
            let decoded = Bundle::decode(&bytes).expect("valid encoding");
            assert_eq!(encoded(&decoded), bytes, "encoding is not canonical");
        }
    }

    #[test]
    fn empty_fields_are_representable_and_distinct() {
        let empty_content = encoded(&sample(b"", b"p"));
        let empty_proof = encoded(&sample(b"p", b""));
        assert_ne!(
            empty_content, empty_proof,
            "an empty field aliased a populated one"
        );
    }

    /// Trailing bytes must be rejected, not ignored.
    ///
    /// A decoder that stopped at the last field it recognised would let an attacker append
    /// anything — including a section a later format version gives meaning to.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encoded(&sample(b"hello", b"proof"));
        bytes.push(0);
        assert_eq!(Bundle::decode(&bytes), Err(ProtocolError::Malformed));
    }

    #[test]
    fn truncation_is_rejected_at_every_length() {
        let bytes = encoded(&sample(b"hello", b"proof"));
        for cut in 0..bytes.len() {
            assert_eq!(
                Bundle::decode(&bytes[..cut]),
                Err(ProtocolError::Malformed),
                "a {cut}-byte prefix decoded"
            );
        }
    }

    /// A length prefix that overstates its field must not read past the input.
    #[test]
    fn an_overstated_length_is_rejected() {
        let mut bytes = encoded(&sample(b"hello", b"proof"));
        bytes[1] = 0xff;
        assert_eq!(Bundle::decode(&bytes), Err(ProtocolError::Malformed));
    }

    /// An unknown version is rejected rather than parsed on a best-effort basis.
    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = encoded(&sample(b"hello", b"proof"));
        bytes[0] = FORMAT_VERSION + 1;
        assert_eq!(Bundle::decode(&bytes), Err(ProtocolError::Malformed));
    }

    #[test]
    fn a_short_buffer_is_refused() {
        let bundle = sample(b"hello", b"proof");
        let mut buffer = vec![0u8; bundle.encoded_len() - 1];
        assert_eq!(bundle.encode(&mut buffer), Err(ProtocolError::Malformed));
    }

    /// No field hides in the encoding.
    ///
    /// §6.6 requires that no `agora_id`, root, epoch marker, or pseudonym appears. The
    /// length being exactly accounted for by the fields above is what makes that checkable
    /// rather than merely asserted.
    #[test]
    fn the_encoded_length_is_fully_accounted_for() {
        let bundle = sample(b"abcd", b"proofproof");
        assert_eq!(
            bundle.encoded_len(),
            1 + 8 + 4 + 32 + 8 + 10 + 32 + 32,
            "the encoding carries a field this test does not know about"
        );
    }
}
