// SPDX-License-Identifier: MIT OR Apache-2.0

//! Agora identity and founding parameters.

use crate::digest::DIGEST_LEN;

/// An agora's self-generated identifier, derived from its own public parameters (§3).
///
/// No external party issues or tracks this value, and it is never transmitted in the clear:
/// content is routed by an opaque tag instead, precisely so that an observer cannot confirm
/// which agora a bundle belongs to (§6.4). Its existence is itself the sensitive fact (§3).
///
/// For that reason `Debug` **redacts** the value rather than rendering it, so an
/// `agora_id` cannot reach a log, a crash report, or a diagnostic dump by accident. Use
/// [`as_bytes`](AgoraId::as_bytes) where the value is genuinely needed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgoraId([u8; DIGEST_LEN]);

impl AgoraId {
    /// Wraps 32 bytes as an `AgoraId`.
    ///
    /// The derivation itself lives in `nymora-crypto`, which owns the hash; this crate
    /// deliberately has no cryptographic dependencies.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for AgoraId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AgoraId(<redacted>)")
    }
}

/// How an agora's master key was held at creation (§4.1, §4.4).
///
/// This records the founding ceremony, not the current arrangement. An agora created
/// single-party re-keys to threshold custody once enough members exist (§4.4), and remains
/// `SingleParty` here forever — the value is a historical fact, which is what makes it
/// admissible in [`PublicParameters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CeremonyMode {
    /// One founder holds the master key alone — the bootstrap window of §4.1.
    SingleParty,
    /// Threshold custody from the outset, requiring `threshold` of `parties`.
    ///
    /// A performable ceremony has `1 <= threshold <= parties`. This type does not enforce
    /// that — it is a wire shape, and refusing to represent a value is not the same as
    /// refusing to act on one — but the identifier derivation guards it in debug builds,
    /// since an identifier derived from an unperformable ceremony is permanent.
    Threshold {
        /// Shares required to act.
        threshold: u16,
        /// Shares issued.
        parties: u16,
    },
}

impl CeremonyMode {
    /// Fixed-width canonical encoding.
    ///
    /// Fixed width rather than variable: the identifier derived from these parameters is
    /// permanent, so two implementations that encoded the same ceremony differently would
    /// produce different identifiers for the same agora and never discover why.
    #[must_use]
    pub const fn encode(self) -> [u8; 5] {
        match self {
            Self::SingleParty => [0, 0, 0, 0, 0],
            Self::Threshold { threshold, parties } => {
                let (t, p) = (threshold.to_le_bytes(), parties.to_le_bytes());
                [1, t[0], t[1], p[0], p[1]]
            }
        }
    }
}

/// The immutable facts an [`AgoraId`] is derived from (§3).
///
/// # Only immutable facts belong here
///
/// An `agora_id` is permanent: it is shared out-of-band, absorbed into every attestation
/// nullifier (§6.1), and cannot be reissued. Anything that can change is therefore
/// inadmissible — most importantly the master key itself, which §4.4 rotates from
/// single-party to threshold custody and destroys the old copy of.
///
/// What is committed is the **founding** material. A consequence worth stating, because it
/// is easy to assume otherwise: after a re-key, `agora_id` corresponds to no live key. It
/// cannot be verified against the agora's current state, and is not meant to be. It
/// identifies a parameter set, not a deployment.
///
/// Epoch length is likewise excluded — it is per-agora policy and adjustable through the
/// mechanism of §5.3 (§9.1).
///
/// # The founding key must be unguessable
///
/// `agora_id` is confidential: §3 makes an agora's very existence the sensitive fact, and
/// [`AgoraId`] redacts its own `Debug` output for that reason. But the derivation is a
/// public function of these parameters, so an adversary who can *guess* the parameters can
/// compute the identifier and confirm an agora exists.
///
/// [`founding_key`](Self::founding_key) is what prevents that, and only if it carries real
/// entropy. It must be actual public key material from the founding ceremony — never a
/// name, a domain, a timestamp, or anything else an adversary could enumerate.
#[derive(Debug, Clone, Copy)]
pub struct PublicParameters<'a> {
    /// The ceremony under which the agora was created.
    pub ceremony: CeremonyMode,
    /// Public key material from the founding ceremony. See the entropy note above.
    pub founding_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::AgoraId;
    use crate::digest::DIGEST_LEN;
    use std::format;

    #[test]
    fn debug_does_not_leak_the_identifier() {
        let bytes = [0xab; DIGEST_LEN];
        let rendered = format!("{:?}", AgoraId::from_bytes(bytes));
        assert_eq!(rendered, "AgoraId(<redacted>)");
        assert!(
            !rendered.contains("ab"),
            "identifier leaked into Debug output"
        );
    }

    #[test]
    fn round_trips_bytes() {
        let bytes = [3u8; DIGEST_LEN];
        assert_eq!(AgoraId::from_bytes(bytes).as_bytes(), &bytes);
    }
}
