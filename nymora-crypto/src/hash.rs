// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain-separated, length-framed hashing.
//!
//! # Why a wrapper rather than a hash function
//!
//! Two mistakes account for most domain-separation failures, and both are structural
//! rather than arithmetic. This type removes them by construction:
//!
//! 1. **Hashing without a domain at all.** [`Hasher::new`] takes a [`Domain`]; there is no
//!    way to obtain a hasher without naming the context it belongs to.
//! 2. **Ambiguous concatenation.** Absorbing `"ab"` then `"c"` must not produce the same
//!    digest as `"a"` then `"bc"`, or an attacker who controls where one field ends and the
//!    next begins can forge a collision between two different messages. Every absorbed
//!    value is therefore preceded by its length, making the encoding injective.
//!
//! The prefix-freedom test on the domain registry in `nymora-core` is a second line of
//! defence behind the framing here, not a substitute for it.

use nymora_core::{Domain, DIGEST_LEN};
use sha2::{Digest, Sha256};

/// A hash usable by [`Hasher`].
///
/// Implementations supply raw absorption only; framing and domain separation are applied
/// by [`Hasher`] so that every backend inherits them identically. That matters beyond
/// tidiness: divergent framing between two implementations would produce divergent proofs,
/// which is the fingerprinting vector §6.5 exists to close.
pub trait HashBackend: Default {
    /// Absorbs raw bytes. Callers should use [`Hasher::absorb`], which frames them.
    fn absorb_raw(&mut self, bytes: &[u8]);

    /// Consumes the state and produces a digest.
    fn finalize_raw(self) -> [u8; DIGEST_LEN];
}

/// SHA-256, the byte-hash backend.
///
/// See the module documentation of this crate for why a conventional hash is a permanent
/// part of the design rather than a stand-in for an algebraic one.
#[derive(Default, Clone)]
pub struct Sha256Backend(Sha256);

impl HashBackend for Sha256Backend {
    fn absorb_raw(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finalize_raw(self) -> [u8; DIGEST_LEN] {
        self.0.finalize().into()
    }
}

/// A domain-separated hasher, generic over its backend.
///
/// Use the [`ByteHasher`] alias unless you specifically need another backend.
///
/// ```
/// use nymora_core::Domain;
/// use nymora_crypto::ByteHasher;
///
/// let digest = ByteHasher::new(Domain::LedgerEntry)
///     .absorb(b"previous")
///     .absorb(b"payload")
///     .finalize();
/// assert_eq!(digest.len(), 32);
/// ```
pub struct Hasher<B: HashBackend> {
    backend: B,
}

impl<B: HashBackend> Hasher<B> {
    /// Begins a hash in the given domain.
    ///
    /// The domain tag is absorbed first, framed like any other input, so that no choice of
    /// subsequent data can reproduce a digest from a different domain.
    #[must_use]
    pub fn new(domain: Domain) -> Self {
        let mut hasher = Self {
            backend: B::default(),
        };
        hasher.absorb_framed(domain.tag().as_bytes());
        hasher
    }

    /// Absorbs a value, framed by its length.
    #[must_use]
    pub fn absorb(mut self, bytes: &[u8]) -> Self {
        self.absorb_framed(bytes);
        self
    }

    /// Produces the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        self.backend.finalize_raw()
    }

    fn absorb_framed(&mut self, bytes: &[u8]) {
        // Length first, fixed width: this is what makes the encoding injective, so that
        // the boundary between two absorbed values cannot be moved by an attacker who
        // controls their contents.
        let len = bytes.len() as u64;
        self.backend.absorb_raw(&len.to_le_bytes());
        self.backend.absorb_raw(bytes);
    }
}

/// The byte-family hasher: [`Hasher`] over SHA-256.
///
/// This is the hasher for every value that never enters a circuit — routing tags (§6.4),
/// ledger chaining (§10.2), the short authentication string (§8.3). The algebraic family
/// arrives with the circuit; see the crate documentation.
pub type ByteHasher = Hasher<Sha256Backend>;

#[cfg(test)]
mod tests {
    use super::ByteHasher;
    use nymora_core::Domain;

    #[test]
    fn is_deterministic() {
        let a = ByteHasher::new(Domain::LedgerEntry).absorb(b"x").finalize();
        let b = ByteHasher::new(Domain::LedgerEntry).absorb(b"x").finalize();
        assert_eq!(a, b);
    }

    #[test]
    fn domain_changes_the_digest() {
        let a = ByteHasher::new(Domain::LedgerEntry).absorb(b"x").finalize();
        let b = ByteHasher::new(Domain::TagRouting).absorb(b"x").finalize();
        assert_ne!(a, b, "domain separation had no effect");
    }

    /// The property length framing exists to provide.
    ///
    /// Without it, `"ab" || "c"` and `"a" || "bc"` absorb identical bytes and collide. An
    /// attacker who controls two adjacent fields could then move the boundary between them
    /// and produce a second message with the same digest — and every attestation in this
    /// design is bound to a message digest (§6.1).
    #[test]
    fn framing_makes_concatenation_unambiguous() {
        let split_one = ByteHasher::new(Domain::LedgerEntry)
            .absorb(b"ab")
            .absorb(b"c")
            .finalize();
        let split_two = ByteHasher::new(Domain::LedgerEntry)
            .absorb(b"a")
            .absorb(b"bc")
            .finalize();
        assert_ne!(split_one, split_two, "field boundary is malleable");
    }

    #[test]
    fn empty_absorption_is_distinguishable_from_none() {
        let none = ByteHasher::new(Domain::LedgerEntry).finalize();
        let empty = ByteHasher::new(Domain::LedgerEntry).absorb(b"").finalize();
        assert_ne!(none, empty, "an absent field looks like an empty one");
    }

    /// Pins the construction against silent change.
    ///
    /// The expected value was produced by an independent implementation of the framing and
    /// of SHA-256, not copied from this code's output, so it validates the construction
    /// rather than merely recording it.
    ///
    /// If this fails, the hash encoding moved. That is a protocol-breaking change: every
    /// nullifier, commitment, and tag derived under the old construction becomes
    /// unreproducible. It requires a domain-tag version bump, not a fixed expectation.
    #[test]
    fn known_answer() {
        let digest = ByteHasher::new(Domain::LedgerEntry)
            .absorb(b"nymora")
            .finalize();
        assert_eq!(
            digest,
            [
                0x3c, 0x43, 0x4d, 0xb8, 0xf7, 0x86, 0x60, 0x92, 0xf3, 0x01, 0xa3, 0x69, 0xbf, 0x39,
                0xc7, 0x81, 0xbf, 0xaf, 0x18, 0x24, 0xad, 0xca, 0xc8, 0xeb, 0x50, 0x2a, 0xa3, 0xd7,
                0x97, 0xd9, 0x98, 0xb5,
            ]
        );
    }
}
