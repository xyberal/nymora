// SPDX-License-Identifier: MIT OR Apache-2.0

//! The content hash a bundle attests (§6.1, §17.3; proposal 0038).
//!
//! `message_hash = Hash(M)` is the byte-family hash under its own domain, over the
//! content bytes length-framed like every other byte-family input. Two clients that
//! hashed content differently would attest different bundles for the same bytes — so
//! the hash is normative, not a host choice.

use crate::hash::ByteHasher;
use nymora_core::{Domain, MessageHash};

/// `Hash(M)` for the content `M` of a bundle (§6.1).
#[must_use]
pub fn message_hash(content: &[u8]) -> MessageHash {
    MessageHash::from_bytes(ByteHasher::new(Domain::Content).absorb(content).finalize())
}

#[cfg(test)]
mod tests {
    use super::message_hash;

    #[test]
    fn empty_and_nonempty_differ_and_are_deterministic() {
        let empty = message_hash(b"");
        let some = message_hash(b"nymora");
        assert_ne!(empty, some);
        assert_eq!(message_hash(b"nymora"), some);
    }
}
