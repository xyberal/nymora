// SPDX-License-Identifier: MIT OR Apache-2.0

//! Agora identity.

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
