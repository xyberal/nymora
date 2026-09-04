// SPDX-License-Identifier: MIT OR Apache-2.0

//! The revocation-set entry (§11, proposal 0036).
//!
//! The set holds `Poseidon(REVOKE, leaf)` rather than the leaf, so that no broadcast
//! carries a leaf and a set entry cannot be linked to a path's neighbour value. Stated
//! exactly, because the change is smaller than it looks: revocation must be computable
//! by the operator from the leaf alone — the revoked member does not cooperate — and the
//! absence witness computable by the member from their own material, so the entry has
//! to be a public function of the leaf. Anyone who already knows a leaf can compute its
//! entry and test the set. The routine proof's absence clause proves the absence of this
//! value (§9.1), recomputing it in-circuit from the leaf it opens.

use nymora_core::{field_domain, Commitment, DIGEST_LEN};

use crate::{field, poseidon, F};

/// The revocation-set entry for a leaf: `Poseidon(REVOKE, leaf)`, canonical bytes.
///
/// The leaf enters as the circuit reads it — a field element by wide reduction of its
/// bytes, the same crossing every other in-statement use of a leaf makes.
#[must_use]
pub fn revocation_key(leaf: &Commitment) -> [u8; DIGEST_LEN] {
    field::to_bytes(&poseidon::hash(&[
        F::from(field_domain::REVOKE),
        field::from_witness_bytes(leaf.as_bytes()),
    ]))
}

#[cfg(test)]
mod tests {
    use super::revocation_key;
    use nymora_core::Commitment;

    #[test]
    fn distinct_leaves_have_distinct_entries_and_neither_is_the_leaf() {
        let a = Commitment::from_bytes([0x11; 32]);
        let b = Commitment::from_bytes([0x12; 32]);
        assert_ne!(revocation_key(&a), revocation_key(&b));
        assert_ne!(&revocation_key(&a), a.as_bytes());
    }
}
