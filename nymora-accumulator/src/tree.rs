// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tree construction — the operator's side of §5.2.
//!
//! # This is the side that knows
//!
//! [`crate::witness`] is deliberately silent about occupancy, because a member must not learn
//! it. An operator holding the tree necessarily knows how many leaves it has put in, and
//! [`Tree::append`] returns the position it used because the operator has to hand that position
//! back as part of a witness.
//!
//! §5.2's rule governs what an agora *publishes*, not what its own operator can see. The line to
//! hold is that nothing here has any counterpart on a member-facing interface.
//!
//! # Append-only, so the occupied region is a prefix
//!
//! Leaves are never removed (§5.2, proposal 0014), and they are appended left to right, so the
//! tree is always an occupied prefix followed by empty subtrees. That is what makes this
//! implementation short: the empty subtree hash at each level is the same value everywhere it
//! occurs, so it is computed once per level rather than stored.

extern crate alloc;

use crate::witness::{hash_leaf, hash_node, Node, Witness};
use alloc::vec::Vec;
use nymora_core::{Commitment, Root, DIGEST_LEN};

/// The node value standing for an empty position.
///
/// All zeros, which is not in the image of [`hash_leaf`] for any value anyone can produce:
/// landing on it would require a preimage of zero under the accumulator's hash. So an empty
/// position cannot be confused with an occupied one, and no separate domain tag is needed to
/// keep them apart.
const EMPTY_LEAF: Node = Node::from_bytes([0u8; DIGEST_LEN]);

/// A fixed-depth append-only Merkle tree over opaque values.
///
/// `DEPTH` fixes capacity at `2^DEPTH` leaves, consumed permanently — §5.2 requires sizing it
/// for every credential the agora will ever issue, not for its live membership.
///
/// This type deliberately has no `len`, no `is_empty`, and no iterator. The operator knows its
/// own occupancy, but a type that reports it invites being wired to something that answers a
/// member.
pub struct Tree<const DEPTH: usize> {
    leaves: Vec<Commitment>,
}

impl<const DEPTH: usize> Default for Tree<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> Tree<DEPTH> {
    /// An empty tree.
    #[must_use]
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Capacity, or `None` when `DEPTH` is too large to count in a `u64`.
    const fn capacity() -> Option<u64> {
        if DEPTH < 64 {
            Some(1u64 << DEPTH)
        } else {
            None
        }
    }

    /// Appends a value, returning the position it took.
    ///
    /// Returns `None` only when the tree is full. There is no other failure: append-only means
    /// there is no occupied position to collide with, and so no error that could distinguish an
    /// occupied position from an empty one (§5.2).
    ///
    /// A full tree is not a transient condition. §5.2 makes exhaustion terminal for the policy
    /// class — no further admission and no further migration under the current protocol version
    /// — which is why depth is sized at creation for every credential the agora will ever
    /// issue, not for its expected membership.
    pub fn append(&mut self, value: Commitment) -> Option<u64> {
        let position = self.leaves.len() as u64;
        if Self::capacity().is_some_and(|max| position >= max) {
            return None;
        }
        self.leaves.push(value);
        Some(position)
    }

    /// The empty-subtree hash for each level, `[0]` being an empty leaf.
    ///
    /// Every empty position at a given level has the same hash, because every empty subtree is
    /// identical. That is a property of append-onlyness holding the occupied region to a prefix.
    fn empty_levels() -> Vec<Node> {
        let mut levels = Vec::with_capacity(DEPTH + 1);
        levels.push(EMPTY_LEAF);
        for level in 0..DEPTH {
            let below = levels[level];
            levels.push(hash_node(&below, &below));
        }
        levels
    }

    /// Every occupied node, level by level, `[0]` being the hashed leaves.
    ///
    /// Only the occupied prefix is materialised; anything beyond it is the level's empty hash.
    fn occupied_levels(&self) -> Vec<Vec<Node>> {
        let empty = Self::empty_levels();
        let mut levels = Vec::with_capacity(DEPTH + 1);
        levels.push(self.leaves.iter().map(hash_leaf).collect::<Vec<_>>());

        for level in 0..DEPTH {
            let below = &levels[level];
            let width = below.len().div_ceil(2);
            let mut up = Vec::with_capacity(width);
            for pair in 0..width {
                let left = below.get(pair * 2).copied().unwrap_or(empty[level]);
                let right = below.get(pair * 2 + 1).copied().unwrap_or(empty[level]);
                up.push(hash_node(&left, &right));
            }
            levels.push(up);
        }

        levels
    }

    /// The current root.
    #[must_use]
    pub fn root(&self) -> Root {
        let empty = Self::empty_levels();
        let levels = self.occupied_levels();
        Root::from_bytes(*levels[DEPTH].first().unwrap_or(&empty[DEPTH]).as_bytes())
    }

    /// The inclusion witness for `position`, if a value was appended there.
    ///
    /// A witness is valid only against the root current when it was cut; any later append that
    /// touches its path supersedes it. See [`Witness`] — staleness surfaces as verification
    /// failing, not as a flag.
    #[must_use]
    pub fn witness(&self, position: u64) -> Option<Witness<DEPTH>> {
        if position >= self.leaves.len() as u64 {
            return None;
        }

        let empty = Self::empty_levels();
        let levels = self.occupied_levels();
        let mut siblings = [EMPTY_LEAF; DEPTH];

        let mut index = position as usize;
        for level in 0..DEPTH {
            siblings[level] = levels[level]
                .get(index ^ 1)
                .copied()
                .unwrap_or(empty[level]);
            index /= 2;
        }

        Witness::new(position, siblings)
    }
}

#[cfg(test)]
mod tests {
    use super::{Tree, EMPTY_LEAF};
    use crate::witness::{hash_node, verifies};
    use nymora_core::{Commitment, DIGEST_LEN};

    fn value(byte: u8) -> Commitment {
        Commitment::from_bytes([byte; DIGEST_LEN])
    }

    fn filled(count: u8) -> Tree<3> {
        let mut tree = Tree::new();
        for byte in 0..count {
            tree.append(value(byte)).expect("depth 3 holds eight");
        }
        tree
    }

    /// The property the whole crate exists to provide: what the operator builds, a member proves.
    #[test]
    fn every_appended_value_verifies_against_the_root() {
        let tree = filled(5);
        let root = tree.root();
        for position in 0..5u64 {
            let witness = tree.witness(position).expect("appended");
            assert!(
                verifies(&value(position as u8), &witness, &root),
                "position {position} did not verify"
            );
        }
    }

    /// A witness proves its own position and no other.
    #[test]
    fn a_witness_does_not_verify_another_value() {
        let tree = filled(5);
        let witness = tree.witness(2).expect("appended");
        assert!(!verifies(&value(3), &witness, &tree.root()));
    }

    /// Appending supersedes witnesses whose path it touched, and verification is what notices.
    #[test]
    fn an_append_supersedes_an_earlier_witness() {
        let mut tree = filled(4);
        let stale = tree.witness(0).expect("appended");
        let before = tree.root();
        assert!(verifies(&value(0), &stale, &before));

        tree.append(value(9)).expect("depth 3 holds eight");
        assert!(
            !verifies(&value(0), &stale, &tree.root()),
            "a witness survived an append that changed its root"
        );
    }

    #[test]
    fn an_empty_tree_has_the_empty_root() {
        let empty = Tree::<3>::new();
        let mut level = EMPTY_LEAF;
        for _ in 0..3 {
            level = hash_node(&level, &level);
        }
        assert_eq!(empty.root().as_bytes(), level.as_bytes());
    }

    #[test]
    fn appending_changes_the_root() {
        let mut tree = Tree::<3>::new();
        let empty = tree.root();
        tree.append(value(1)).expect("depth 3 holds eight");
        assert_ne!(tree.root().as_bytes(), empty.as_bytes());
    }

    /// Capacity is `2^DEPTH` and is not reclaimed — §5.2, proposal 0014.
    #[test]
    fn a_full_tree_refuses_more() {
        let mut tree = filled(8);
        assert_eq!(tree.append(value(9)), None);
    }

    #[test]
    fn no_witness_for_a_position_never_appended() {
        let tree = filled(3);
        assert!(tree.witness(3).is_none());
        assert!(tree.witness(u64::MAX).is_none());
    }

    /// Positions are handed out in order, which is what makes the occupied region a prefix.
    #[test]
    fn positions_are_sequential() {
        let mut tree = Tree::<3>::new();
        for expected in 0..8u64 {
            assert_eq!(tree.append(value(expected as u8)), Some(expected));
        }
    }

    /// Depth 0 is a single leaf and no path.
    #[test]
    fn depth_zero_holds_one() {
        let mut tree = Tree::<0>::new();
        assert_eq!(tree.append(value(1)), Some(0));
        assert_eq!(tree.append(value(2)), None);

        let witness = tree.witness(0).expect("appended");
        assert!(verifies(&value(1), &witness, &tree.root()));
    }
}
