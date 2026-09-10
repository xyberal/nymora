// SPDX-License-Identifier: MIT OR Apache-2.0

//! The invitation a member hands a candidate (§17.1, proposal 0037).
//!
//! # What it is, and is not
//!
//! Everything a candidate needs before admission and can only get from a member — the
//! operator's address, the agora, the class, and the statement key to pin — plus the
//! current fetch key, so a freshly landed member fetches their first envelope with no
//! operator hand-off, and two advisory clock values. It is a client-to-client artifact:
//! no Skiora ever sees one, and nothing in it changes any proof or statement.
//!
//! # A members-only artifact
//!
//! The fetch key inside is what a member holds, and its blast radius is that the agora
//! exists and how many ciphertexts it publishes (§11). An invitation therefore travels
//! only over a channel the inviter trusts, and expires with the fetch key's window.
//!
//! # Unsigned, deliberately
//!
//! A signature by the inviter's credential would be an authorship bundle the invitee —
//! not yet a member — cannot verify (§7). The statement key is trusted exactly as far as
//! whoever handed over the invitation, which is the trust admission already rests on.

use crate::agora::AgoraId;
use crate::digest::DIGEST_LEN;
use crate::epoch::Epoch;
use crate::error::ProtocolError;
use crate::policy::PolicyClass;
use crate::secret::FetchKey;

/// The wire format this module reads and writes. Unknown versions are refused.
pub const INVITATION_VERSION: u8 = 1;

/// Width of the length prefix on the one variable-length field.
const LENGTH_PREFIX: usize = core::mem::size_of::<u64>();

/// One invitation (§17.1).
///
/// Not `Clone`: the fetch key inside is a bearer secret, and the value exists in as few
/// places as possible.
#[derive(Debug, PartialEq, Eq)]
pub struct Invitation<'a> {
    /// The agora being joined.
    pub agora: AgoraId,
    /// The policy class the candidate will be vouched into.
    pub policy_class: PolicyClass,
    /// The operator statement key every envelope verifies against (§11) — the trust
    /// root the invitee pins.
    pub statement_key: [u8; DIGEST_LEN],
    /// The transparency-log key (§10.1), or all zero when the agora publishes no log.
    pub log_key: [u8; DIGEST_LEN],
    /// The inviter's current fetch key (§11) — what fetches the invitee's first envelope.
    pub fetch_key: FetchKey,
    /// The epoch the fetch key belongs to.
    pub epoch: Epoch,
    /// The agora's epoch interval in seconds — advisory (§9.1's local-clock backstop).
    pub interval_seconds: u64,
    /// The last epoch at which the operator still serves this fetch key — advisory; a
    /// consuming client refuses an invitation past it rather than trying a dead key.
    pub valid_through: Epoch,
    /// The member plane's address, UTF-8.
    pub server: &'a str,
}

impl<'a> Invitation<'a> {
    /// The log key, if the agora publishes a log.
    #[must_use]
    pub fn log_key(&self) -> Option<&[u8; DIGEST_LEN]> {
        if self.log_key.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(&self.log_key)
        }
    }

    /// The exact number of bytes [`encode`](Self::encode) will write.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        1 + 5 * DIGEST_LEN + 3 * 8 + LENGTH_PREFIX + self.server.len()
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
        put(&[INVITATION_VERSION]);
        put(self.agora.as_bytes());
        put(self.policy_class.as_bytes());
        put(&self.statement_key);
        put(&self.log_key);
        put(self.fetch_key.expose());
        put(&self.epoch.get().to_le_bytes());
        put(&self.interval_seconds.to_le_bytes());
        put(&self.valid_through.get().to_le_bytes());
        put(&(self.server.len() as u64).to_le_bytes());
        put(self.server.as_bytes());
        Ok(total)
    }

    /// Reads an invitation from its canonical encoding.
    ///
    /// Strict: unknown versions, truncation, overstated lengths, trailing bytes, a
    /// server address that is not UTF-8, and a `valid_through` before `epoch` are all
    /// [`ProtocolError::Malformed`].
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] for any input that is not exactly one valid encoding.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut rest = bytes;
        let (version, tail) = rest.split_first().ok_or(ProtocolError::Malformed)?;
        if *version != INVITATION_VERSION {
            return Err(ProtocolError::Malformed);
        }
        rest = tail;
        let agora = AgoraId::from_bytes(take_digest(&mut rest)?);
        let policy_class = PolicyClass::from_bytes(take_digest(&mut rest)?);
        let statement_key = take_digest(&mut rest)?;
        let log_key = take_digest(&mut rest)?;
        let fetch_key = FetchKey::new(take_digest(&mut rest)?);
        let epoch = Epoch::new(take_u64(&mut rest)?);
        let interval_seconds = take_u64(&mut rest)?;
        let valid_through = Epoch::new(take_u64(&mut rest)?);
        let server =
            core::str::from_utf8(take_framed(&mut rest)?).map_err(|_| ProtocolError::Malformed)?;
        if !rest.is_empty() || valid_through < epoch {
            return Err(ProtocolError::Malformed);
        }
        Ok(Self {
            agora,
            policy_class,
            statement_key,
            log_key,
            fetch_key,
            epoch,
            interval_seconds,
            valid_through,
            server,
        })
    }
}

fn take_digest(rest: &mut &[u8]) -> Result<[u8; DIGEST_LEN], ProtocolError> {
    let bytes = rest
        .get(..DIGEST_LEN)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    *rest = &rest[DIGEST_LEN..];
    Ok(bytes)
}

fn take_u64(rest: &mut &[u8]) -> Result<u64, ProtocolError> {
    let bytes: [u8; 8] = rest
        .get(..8)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    *rest = &rest[8..];
    Ok(u64::from_le_bytes(bytes))
}

fn take_framed<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], ProtocolError> {
    let prefix = rest
        .get(..LENGTH_PREFIX)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    let len = usize::try_from(u64::from_le_bytes(prefix)).map_err(|_| ProtocolError::Malformed)?;
    let after_prefix = rest.get(LENGTH_PREFIX..).ok_or(ProtocolError::Malformed)?;
    let body = after_prefix.get(..len).ok_or(ProtocolError::Malformed)?;
    *rest = &after_prefix[len..];
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invitation<'static> {
        Invitation {
            agora: AgoraId::from_bytes([0x0a; 32]),
            policy_class: PolicyClass::from_bytes([0x0c; 32]),
            statement_key: [0x05; 32],
            log_key: [0; 32],
            fetch_key: FetchKey::new([0x0f; 32]),
            epoch: Epoch::new(7),
            interval_seconds: 86_400,
            valid_through: Epoch::new(8),
            server: "http://127.0.0.1:8080",
        }
    }

    #[test]
    fn round_trips() {
        let invitation = sample();
        let mut buffer = [0u8; 256];
        let len = invitation.encode(&mut buffer).unwrap();
        assert_eq!(len, invitation.encoded_len());
        let decoded = Invitation::decode(&buffer[..len]).unwrap();
        assert_eq!(decoded, invitation);
        assert!(decoded.log_key().is_none());
    }

    #[test]
    fn a_short_buffer_is_refused() {
        let invitation = sample();
        let mut buffer = [0u8; 16];
        assert_eq!(
            invitation.encode(&mut buffer),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn truncation_is_rejected_at_every_length() {
        let invitation = sample();
        let mut buffer = [0u8; 256];
        let len = invitation.encode(&mut buffer).unwrap();
        for cut in 0..len {
            assert!(Invitation::decode(&buffer[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn trailing_bytes_an_unknown_version_and_a_bad_clock_are_rejected() {
        let invitation = sample();
        let mut buffer = [0u8; 256];
        let len = invitation.encode(&mut buffer).unwrap();
        assert!(Invitation::decode(&buffer[..len + 1]).is_err());
        buffer[0] = INVITATION_VERSION + 1;
        assert!(Invitation::decode(&buffer[..len]).is_err());
        buffer[0] = INVITATION_VERSION;
        // valid_through (bytes 1+5*32+16 ..) set below epoch
        let at = 1 + 5 * 32 + 16;
        buffer[at..at + 8].copy_from_slice(&6u64.to_le_bytes());
        assert!(Invitation::decode(&buffer[..len]).is_err());
    }

    #[test]
    fn a_non_utf8_server_is_rejected() {
        let invitation = sample();
        let mut buffer = [0u8; 256];
        let len = invitation.encode(&mut buffer).unwrap();
        buffer[len - 1] = 0xff;
        assert!(Invitation::decode(&buffer[..len]).is_err());
    }
}
