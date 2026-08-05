// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy classes — the partitions membership is accumulated into (§5.2).

use crate::digest::DIGEST_LEN;

/// Names one of an agora's membership partitions, each with its own accumulator (§5.2).
///
/// "Tier2 members" and "Tier2-eligible vouchers" are policy classes; each has its own tree and
/// publishes its own root, so a root is addressed by `(agora, policy_class, epoch)` rather than
/// by agora alone.
///
/// # It is a derived value, not a constant
///
/// §5.1 is normative on this: *"No value derived within one agora is ever reused in, or
/// derivable from, another. This covers … **any handle presented to a Skiora**."* A policy class
/// identifier is exactly such a handle — §5.2 puts it in the request path — so a shared
/// constant like `TIER_2` would be the same value appearing in every agora that runs a tier
/// system, and a cross-agora correlator by construction.
///
/// It is therefore derived per agora, from the agora's own identifier and a label. The
/// derivation lives in `nymora-crypto`; this crate carries no cryptographic dependencies.
///
/// # Not enumerable
///
/// Which classes an agora runs is agora configuration, not a protocol constant — a tiered
/// structure is a fact about the group. There is deliberately no list, no registry, and no
/// mapping back to a label: recovering one means guessing the label *and* holding the
/// `agora_id`, which §3 keeps confidential.
///
/// `Debug` redacts for the same reason [`AgoraId`](crate::AgoraId) does. The value is derived
/// from a redacted one, so a log line carrying it is nearly as disclosing as a log line carrying
/// the identifier itself.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyClass([u8; DIGEST_LEN]);

impl PolicyClass {
    /// Wraps 32 bytes as a `PolicyClass`.
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

impl core::fmt::Debug for PolicyClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PolicyClass(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyClass;
    use crate::digest::DIGEST_LEN;
    use std::format;

    #[test]
    fn debug_does_not_leak_the_identifier() {
        let rendered = format!("{:?}", PolicyClass::from_bytes([0xcd; DIGEST_LEN]));
        assert_eq!(rendered, "PolicyClass(<redacted>)");
        assert!(
            !rendered.contains("cd"),
            "identifier leaked into Debug output"
        );
    }

    #[test]
    fn round_trips_bytes() {
        let bytes = [7u8; DIGEST_LEN];
        assert_eq!(PolicyClass::from_bytes(bytes).as_bytes(), &bytes);
    }
}
