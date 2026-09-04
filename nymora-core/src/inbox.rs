// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbox key's public half and the lookup tag (§11, proposal 0036).
//!
//! An inbox key is a per-credential X25519 keypair: the operator encrypts each member's
//! boundary ciphertext to it, and nothing else ever uses it. The public half is
//! registered exactly once — with the leaf at founding, admission, or migration — and is
//! **never presented on any other surface, in any proof, or on the log**: it is a
//! delivery address the operator holds against a row it already has (leaf, position),
//! not a new pseudonym in any hands that lacked one.
//!
//! The lookup tag is how a member finds their own ciphertext in the envelope without the
//! envelope labelling anything: derived from the agreed secret under its own domain, so
//! it is random to everyone but the two parties and unlinkable across boundaries (the
//! ephemeral half changes every time).

/// Width of an inbox public key: an X25519 point (RFC 7748).
pub const INBOX_PUBLIC_KEY_LEN: usize = 32;

/// Width of the ciphertext lookup tag.
pub const INBOX_TAG_LEN: usize = 8;

/// A credential's inbox public key (§11, proposal 0036).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboxPublicKey([u8; INBOX_PUBLIC_KEY_LEN]);

impl InboxPublicKey {
    /// Wraps the encoded point.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; INBOX_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The encoded point.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; INBOX_PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for InboxPublicKey {
    /// Not secret, but printing a durable per-credential handle in logs is how handles
    /// end up correlated; show the type, not the value.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InboxPublicKey(..)")
    }
}

/// The short tag a member finds their ciphertext by (§11, proposal 0036).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboxTag([u8; INBOX_TAG_LEN]);

impl InboxTag {
    /// Wraps the tag bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; INBOX_TAG_LEN]) -> Self {
        Self(bytes)
    }

    /// The tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; INBOX_TAG_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::InboxPublicKey;
    use std::format;

    #[test]
    fn debug_shows_no_value() {
        assert_eq!(
            format!("{:?}", InboxPublicKey::from_bytes([0xab; 32])),
            "InboxPublicKey(..)"
        );
    }
}
