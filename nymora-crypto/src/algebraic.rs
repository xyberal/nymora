// SPDX-License-Identifier: MIT OR Apache-2.0

//! The algebraic hash family — currently a stand-in.
//!
//! Every value in this family is recomputed inside the circuit: commitments, nullifiers,
//! accumulator nodes. Its cost is therefore measured in constraints rather than cycles, and
//! the right choice depends on the proving system, which is not yet decided.
//!
//! # Why there is no genericity here
//!
//! It would be natural to make the constructions generic over a backend and let each
//! deployment choose. That would be a mistake. §6.5 requires every proof in the protocol to
//! have a uniform shape, network-wide — a member whose proofs are shaped differently from
//! everyone else's is fingerprinted by that difference alone. There is exactly one algebraic
//! hash for the whole protocol, so there is exactly one type alias here, and swapping it is
//! a protocol-version change rather than a build-time choice.
//!
//! # The stand-in
//!
//! [`ProvisionalAlgebraicBackend`] is SHA-256. It is cryptographically sound — the
//! constructions built on it are correct and testable — but it is *not* the final choice:
//! SHA-256 inside a proof costs on the order of tens of thousands of constraints per
//! invocation, where an algebraic hash costs hundreds. Building the protocol on it now lets
//! the state machines and conformance vectors be written; shipping it would make proving
//! impractically slow.
//!
//! The whole family sits behind the `provisional-algebraic-hash` feature, on by default, so
//! that `--no-default-features` yields a build with no stand-in in it at all. That is the
//! configuration to check against if you need to be certain the placeholder has not reached
//! something it should not have.

use crate::hash::{HashBackend, Hasher};
use nymora_core::DIGEST_LEN;
use sha2::{Digest, Sha256};

/// SHA-256, standing in for the algebraic hash until the proving system is chosen.
///
/// Named to be conspicuous in a backtrace, in `cargo doc`, and in a grep. See the module
/// documentation for what makes it provisional and what it would cost to ship.
#[derive(Default, Clone)]
pub struct ProvisionalAlgebraicBackend(Sha256);

impl HashBackend for ProvisionalAlgebraicBackend {
    fn absorb_raw(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finalize_raw(self) -> [u8; DIGEST_LEN] {
        self.0.finalize().into()
    }
}

/// The algebraic-family hasher: the single swap point for the whole protocol.
///
/// When the proving system is chosen, this alias changes and every value derived through it
/// changes with it. That is a protocol-breaking change requiring a domain-tag version bump,
/// not a drop-in substitution.
pub type AlgebraicHasher = Hasher<ProvisionalAlgebraicBackend>;

#[cfg(test)]
mod tests {
    use super::AlgebraicHasher;
    use crate::ByteHasher;
    use nymora_core::Domain;

    /// The two families are separate types today even though they wrap the same hash.
    ///
    /// This test does not assert they differ — under the stand-in they do not, and that is
    /// expected. It asserts that the distinction is carried by the type system, so the
    /// eventual swap cannot silently change a byte-family value.
    #[test]
    fn both_families_are_usable_and_domain_separated() {
        let a = AlgebraicHasher::new(Domain::Commitment)
            .absorb(b"x")
            .finalize();
        let b = AlgebraicHasher::new(Domain::NullifierVouch)
            .absorb(b"x")
            .finalize();
        assert_ne!(
            a, b,
            "domain separation had no effect in the algebraic family"
        );

        let byte = ByteHasher::new(Domain::LedgerEntry).absorb(b"x").finalize();
        assert_ne!(a, byte, "families collided across domains");
    }
}
