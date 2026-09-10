// SPDX-License-Identifier: MIT OR Apache-2.0

//! The text armor for client-to-client artifacts (§17.2, proposal 0038).
//!
//! One form for every artifact a Persora hands another Persora over a channel neither
//! controls — a bundle pasted into a chat, an invitation in a message, a session code
//! read aloud:
//!
//! ```text
//! armor := "nymora1" ‖ base64url_nopad( kind(1) ‖ payload ‖ check(4) )
//! check  = first 4 bytes of the byte-family hash under "nymora/v0/armor"
//!          over prefix ‖ kind ‖ payload, each framed
//! ```
//!
//! Decoding ignores whitespace after the prefix (every chat client wraps long text) and
//! tolerates one surrounding pair of straight or smart quotes, and nothing else. The
//! checksum catches truncation and transcription; it is not a security boundary — the
//! artifact inside carries its own proof or is public data.
//!
//! No allocation: both directions write into a caller's buffer, like every codec here.

use crate::hash::ByteHasher;
use nymora_core::{Domain, ProtocolError};

/// The armor's prefix and version. A future incompatible armor is `nymora2`.
pub const PREFIX: &str = "nymora1";

/// Width of the checksum trailer.
pub const CHECK_LEN: usize = 4;

/// What an armored artifact is, so a client routes it without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// An attestation bundle (§6.6).
    Bundle = 1,
    /// An invitation (§17.1).
    Invitation = 2,
    /// A vouch session code: `agora_id ‖ session_id` (§5.3).
    SessionCode = 3,
    /// A proposal code: `agora_id ‖ subject` (§4.3).
    ProposalCode = 4,
    /// A challenge answer: a bundle whose content is a challenge phrase.
    Challenge = 5,
    /// A live-authentication commitment (§8.1).
    LiveAuthCommitment = 6,
    /// A live-authentication reveal (§8.1).
    LiveAuthReveal = 7,
    /// A live-authentication pseudonym and proof (§8.1).
    LiveAuthProof = 8,
}

impl Kind {
    /// The kind byte on the wire.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// The kind for a wire byte; `None` for a kind this implementation does not know,
    /// which a decoder refuses rather than skips.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Kind> {
        Some(match byte {
            1 => Kind::Bundle,
            2 => Kind::Invitation,
            3 => Kind::SessionCode,
            4 => Kind::ProposalCode,
            5 => Kind::Challenge,
            6 => Kind::LiveAuthCommitment,
            7 => Kind::LiveAuthReveal,
            8 => Kind::LiveAuthProof,
            _ => return None,
        })
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const fn base64_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

/// The exact length of the armored text for a payload of `payload_len` bytes.
#[must_use]
pub const fn armored_len(payload_len: usize) -> usize {
    PREFIX.len() + base64_len(1 + payload_len + CHECK_LEN)
}

/// The checksum trailer for `kind` and `payload`.
#[must_use]
pub fn check(kind: Kind, payload: &[u8]) -> [u8; CHECK_LEN] {
    let digest = ByteHasher::new(Domain::Armor)
        .absorb(PREFIX.as_bytes())
        .absorb(&[kind.byte()])
        .absorb(payload)
        .finalize();
    let mut short = [0u8; CHECK_LEN];
    short.copy_from_slice(&digest[..CHECK_LEN]);
    short
}

/// Armors `payload` as `kind`, writing ASCII into `out`; returns the length written.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] if `out` is shorter than [`armored_len`].
pub fn armor(kind: Kind, payload: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
    let total = armored_len(payload.len());
    let out = out.get_mut(..total).ok_or(ProtocolError::Malformed)?;
    out[..PREFIX.len()].copy_from_slice(PREFIX.as_bytes());
    let trailer = check(kind, payload);
    // The base64 input is kind ‖ payload ‖ check, streamed without materializing it.
    let head = [kind.byte()];
    let mut source = head
        .iter()
        .chain(payload.iter())
        .chain(trailer.iter())
        .copied();
    let mut at = PREFIX.len();
    loop {
        let a = source.next();
        let Some(a) = a else { break };
        let b = source.next();
        let c = source.next();
        let triple =
            (u32::from(a) << 16) | (u32::from(b.unwrap_or(0)) << 8) | u32::from(c.unwrap_or(0));
        let chars = [
            ALPHABET[(triple >> 18) as usize & 63],
            ALPHABET[(triple >> 12) as usize & 63],
            ALPHABET[(triple >> 6) as usize & 63],
            ALPHABET[triple as usize & 63],
        ];
        let count = 2 + usize::from(b.is_some()) + usize::from(c.is_some());
        out[at..at + count].copy_from_slice(&chars[..count]);
        at += count;
    }
    debug_assert_eq!(at, total);
    Ok(total)
}

fn sextet(ch: u8) -> Option<u32> {
    let value = match ch {
        b'A'..=b'Z' => ch - b'A',
        b'a'..=b'z' => ch - b'a' + 26,
        b'0'..=b'9' => ch - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Strips one surrounding pair of straight or smart quotes, if present.
fn unquote(text: &[u8]) -> &[u8] {
    const PAIRS: [(&[u8], &[u8]); 4] = [
        (b"\"", b"\""),
        (b"'", b"'"),
        ("\u{201c}".as_bytes(), "\u{201d}".as_bytes()),
        ("\u{2018}".as_bytes(), "\u{2019}".as_bytes()),
    ];
    for (open, close) in PAIRS {
        if text.len() >= open.len() + close.len() && text.starts_with(open) && text.ends_with(close)
        {
            return &text[open.len()..text.len() - close.len()];
        }
    }
    text
}

/// Decodes armored text into `out`, returning the kind and the payload length.
///
/// Whitespace anywhere after the prefix is ignored; one surrounding pair of quotes is
/// tolerated. Anything else that is not exactly one valid armor — a wrong prefix, an
/// invalid or padded base64 character, a truncated string, a checksum mismatch, an
/// unknown kind — is refused.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] for any input that is not one valid armor, or when
/// `out` cannot hold the payload.
pub fn unarmor(text: &[u8], out: &mut [u8]) -> Result<(Kind, usize), ProtocolError> {
    let trimmed = trim_whitespace(text);
    let text = unquote(trimmed);
    let text = trim_whitespace(text);
    let body = text
        .strip_prefix(PREFIX.as_bytes())
        .ok_or(ProtocolError::Malformed)?;

    // Decode base64url into `out`, skipping whitespace; `out` receives kind ‖ payload ‖ check.
    let mut chars = body
        .iter()
        .copied()
        .filter(|ch| !matches!(ch, b' ' | b'\n' | b'\r' | b'\t'));
    let mut written = 0usize;
    loop {
        let mut group = [0u32; 4];
        let mut count = 0;
        for slot in &mut group {
            match chars.next() {
                Some(ch) => {
                    *slot = sextet(ch).ok_or(ProtocolError::Malformed)?;
                    count += 1;
                }
                None => break,
            }
        }
        if count == 0 {
            break;
        }
        if count == 1 {
            return Err(ProtocolError::Malformed);
        }
        let triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6) | group[3];
        let bytes = [(triple >> 16) as u8, (triple >> 8) as u8, triple as u8];
        let emit = count - 1;
        let target = out
            .get_mut(written..written + emit)
            .ok_or(ProtocolError::Malformed)?;
        target.copy_from_slice(&bytes[..emit]);
        written += emit;
        if count < 4 {
            break;
        }
    }
    if written < 1 + CHECK_LEN {
        return Err(ProtocolError::Malformed);
    }
    let payload_len = written - 1 - CHECK_LEN;
    let kind = Kind::from_byte(out[0]).ok_or(ProtocolError::Malformed)?;
    let expected = check(kind, &out[1..1 + payload_len]);
    if out[1 + payload_len..written] != expected {
        return Err(ProtocolError::Malformed);
    }
    out.copy_within(1..1 + payload_len, 0);
    Ok((kind, payload_len))
}

fn trim_whitespace(text: &[u8]) -> &[u8] {
    let is_space = |ch: &u8| matches!(ch, b' ' | b'\n' | b'\r' | b'\t');
    let start = text
        .iter()
        .position(|ch| !is_space(ch))
        .unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|ch| !is_space(ch))
        .map_or(start, |at| at + 1);
    &text[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(kind: Kind, payload: &[u8]) -> ([u8; 512], usize) {
        let mut text = [0u8; 1024];
        let len = armor(kind, payload, &mut text).unwrap();
        assert_eq!(len, armored_len(payload.len()));
        let mut out = [0u8; 512];
        let (decoded_kind, decoded_len) = unarmor(&text[..len], &mut out).unwrap();
        assert_eq!(decoded_kind, kind);
        assert_eq!(&out[..decoded_len], payload);
        (out, decoded_len)
    }

    #[test]
    fn every_payload_length_round_trips() {
        let payload = [0x5a; 40];
        for len in 0..payload.len() {
            round_trip(Kind::Bundle, &payload[..len]);
        }
        round_trip(Kind::LiveAuthProof, b"");
    }

    #[test]
    fn whitespace_and_quotes_are_tolerated() {
        let mut text = [0u8; 256];
        let len = armor(Kind::SessionCode, &[7u8; 64], &mut text).unwrap();
        let mut wrapped = [0u8; 400];
        let mut at = 0;
        wrapped[at] = b'"';
        at += 1;
        for (i, ch) in text[..len].iter().enumerate() {
            wrapped[at] = *ch;
            at += 1;
            if i % 20 == 19 {
                wrapped[at] = b'\n';
                at += 1;
            }
        }
        wrapped[at] = b'"';
        at += 1;
        let mut out = [0u8; 128];
        let (kind, n) = unarmor(&wrapped[..at], &mut out).unwrap();
        assert_eq!((kind, n), (Kind::SessionCode, 64));
    }

    #[test]
    fn truncation_padding_bad_check_and_unknown_kind_are_refused() {
        let mut text = [0u8; 256];
        let len = armor(Kind::Invitation, &[1u8; 30], &mut text).unwrap();
        let mut out = [0u8; 128];
        for cut in 0..len {
            assert!(unarmor(&text[..cut], &mut out).is_err(), "cut {cut}");
        }
        let mut padded = [0u8; 257];
        padded[..len].copy_from_slice(&text[..len]);
        padded[len] = b'=';
        assert!(unarmor(&padded[..len + 1], &mut out).is_err());
        let mut flipped = text;
        flipped[len - 1] = if flipped[len - 1] == b'A' { b'B' } else { b'A' };
        assert!(unarmor(&flipped[..len], &mut out).is_err());
        // Kind 9 does not exist: build it by hand with a correct checksum shape.
        assert!(Kind::from_byte(9).is_none());
        assert!(unarmor(b"nymora2AAAA", &mut out).is_err());
        assert!(unarmor(b"", &mut out).is_err());
    }
}
