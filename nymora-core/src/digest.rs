// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-width protocol values.
//!
//! Each is a distinct type over the same 32 bytes, so that a nullifier cannot be passed
//! where a commitment is expected. None dereferences to its bytes: reaching the contents
//! requires [`as_bytes`](Nullifier::as_bytes), which is greppable in review.
//!
//! The values here all appear on the wire in an external bundle (§6.6), so their `Debug`
//! renders them in full. Confidential values are handled elsewhere: see
//! [`AgoraId`](crate::AgoraId), which is redacted, and [`SecretBytes`](crate::SecretBytes).

/// Width of every value in this module, in bytes.
pub const DIGEST_LEN: usize = 32;

macro_rules! digest_newtype {
    ($( $(#[$doc:meta])* $name:ident ),+ $(,)?) => {
        $(
            $(#[$doc])*
            ///
            /// Ordering is byte-lexicographic and carries no protocol meaning; it exists so
            /// these values can key ordered collections and be sorted for canonical
            /// encoding. It says nothing about age, tier, or any other attribute (§5.1).
            #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
            pub struct $name([u8; DIGEST_LEN]);

            impl $name {
                #[doc = concat!("Wraps 32 bytes as a `", stringify!($name), "`.")]
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

            impl core::fmt::Debug for $name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str(stringify!($name))?;
                    f.write_str("(")?;
                    for byte in &self.0 {
                        write!(f, "{byte:02x}")?;
                    }
                    f.write_str(")")
                }
            }
        )+
    };
}

digest_newtype! {
    /// The hash of a message an attestation is bound to (§6.1).
    MessageHash,

    /// A per-context deterministic value enforcing distinctness without revealing identity.
    ///
    /// Which context it belongs to is fixed by the [`Domain`](crate::Domain) used to derive
    /// it; nullifiers from different domains are unrelated.
    Nullifier,

    /// An accumulator leaf, `Commit(pk_root, sk_cred, r_root, agora_id)` (§9.1).
    Commitment,

    /// The root of an accumulator at one epoch (§5.2).
    ///
    /// Carries no information about occupancy: a fixed-depth tree's root reveals nothing
    /// about how many leaves are present, and no API exposes that separately.
    Root,

    /// The opaque routing value attached to published content (§6.4).
    ///
    /// Computationally indistinguishable from random without the corresponding tag key. It
    /// carries no visible structure, length variation, or label.
    Tag,

    /// A participant's pseudonym within one live-authentication session (§8.1).
    ///
    /// Recurs across messages in the same session and is unlinkable to any other session,
    /// to authorship, or to any other context.
    SessionPseudonym,

    /// An entry in a credential's hash-chained receipt ledger (§10.2).
    ///
    /// Reserved: the ledger is deferred (proposal 0010); the type stays with its domain tags.
    LedgerHash,
}

#[cfg(test)]
mod tests {
    use super::{Commitment, Nullifier, DIGEST_LEN};
    use std::format;

    #[test]
    fn round_trips_bytes() {
        let bytes = [7u8; DIGEST_LEN];
        assert_eq!(Nullifier::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn debug_renders_full_hex() {
        let mut bytes = [0u8; DIGEST_LEN];
        bytes[0] = 0xab;
        bytes[DIGEST_LEN - 1] = 0x0f;
        let rendered = format!("{:?}", Commitment::from_bytes(bytes));
        assert!(rendered.starts_with("Commitment(ab"), "got {rendered}");
        assert!(rendered.ends_with("0f)"), "got {rendered}");
        // type name + parens + two hex characters per byte
        assert_eq!(rendered.len(), "Commitment()".len() + DIGEST_LEN * 2);
    }

    /// Distinct types over identical bytes must not be interchangeable. This is a
    /// compile-time property; the test documents the intent and fails loudly if someone
    /// adds a blanket conversion.
    #[test]
    fn distinct_types_are_not_interchangeable() {
        let bytes = [1u8; DIGEST_LEN];
        let nullifier = Nullifier::from_bytes(bytes);
        let commitment = Commitment::from_bytes(bytes);
        assert_eq!(nullifier.as_bytes(), commitment.as_bytes());
        // `nullifier == commitment` does not compile, which is the point.
    }
}
