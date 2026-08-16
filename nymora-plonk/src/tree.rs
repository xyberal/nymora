// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CPU-side Poseidon Merkle tree the class accumulators use (§5.2), and the
//! authentication-path type both statements take as witness.
//!
//! Positional and append-only, like the provisional accumulator it will replace at
//! swap time — but over the pinned Poseidon instance and field-element leaves, so the
//! roots it produces are the ones the circuit's in-constraint fold recomputes. The
//! tree is sparse: only the occupied prefix is stored, empty subtrees fold to
//! precomputed all-zero roots, and an append costs one hash per level — which is what
//! makes `PROTOCOL_DEPTH = 32` a working size rather than a theoretical one.

use ff::Field;

use crate::{primitives::poseidon, F};

/// One authentication path: the sibling at each level, and whether the running node
/// is the right child there (`true` = sibling is on the left).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path<const DEPTH: usize> {
    /// The sibling hash at each level, leaf-adjacent first.
    pub siblings: [F; DEPTH],
    /// The direction bit at each level: `true` when the running node is the right child.
    pub bits: [bool; DEPTH],
}

impl<const DEPTH: usize> Default for Path<DEPTH> {
    fn default() -> Self {
        Path {
            siblings: [F::ZERO; DEPTH],
            bits: [false; DEPTH],
        }
    }
}

impl<const DEPTH: usize> Path<DEPTH> {
    /// The root this path computes from `leaf` — the CPU twin of the in-circuit fold.
    pub fn root(&self, leaf: F) -> F {
        let mut current = leaf;
        for (sibling, bit) in self.siblings.iter().zip(self.bits) {
            let (left, right) = if bit {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = poseidon(&[left, right]);
        }
        current
    }
}

/// A fixed-depth positional Merkle tree over the pinned Poseidon instance.
#[derive(Clone, Debug)]
pub struct Tree<const DEPTH: usize> {
    /// `nodes[level]` holds the occupied prefix of that level; `nodes[0]` is leaves.
    nodes: Vec<Vec<F>>,
    /// `zeros[level]` is the root of an all-empty subtree of height `level`.
    zeros: Vec<F>,
}

impl<const DEPTH: usize> Default for Tree<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> Tree<DEPTH> {
    /// An empty tree.
    pub fn new() -> Self {
        let mut zeros = Vec::with_capacity(DEPTH + 1);
        zeros.push(F::ZERO);
        for level in 0..DEPTH {
            let z = zeros[level];
            zeros.push(poseidon(&[z, z]));
        }
        Tree {
            nodes: vec![Vec::new(); DEPTH + 1],
            zeros,
        }
    }

    /// The number of appended leaves.
    pub fn len(&self) -> usize {
        self.nodes[0].len()
    }

    /// Whether no leaf has been appended.
    pub fn is_empty(&self) -> bool {
        self.nodes[0].is_empty()
    }

    /// The node at `(level, index)`, occupied or implicit-empty.
    fn node(&self, level: usize, index: usize) -> F {
        self.nodes[level]
            .get(index)
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// Appends a leaf, returning its position, or `None` when the tree is full.
    pub fn append(&mut self, leaf: F) -> Option<usize> {
        // At depth >= usize::BITS the tree cannot fill; the shift below stays safe
        // because DEPTH < 64 in every real instantiation.
        if DEPTH < usize::BITS as usize && self.nodes[0].len() >= (1usize << DEPTH) {
            return None;
        }
        let position = self.nodes[0].len();
        self.nodes[0].push(leaf);

        let mut index = position;
        for level in 0..DEPTH {
            let parent = index / 2;
            let value = poseidon(&[
                self.node(level, parent * 2),
                self.node(level, parent * 2 + 1),
            ]);
            if self.nodes[level + 1].len() <= parent {
                self.nodes[level + 1].push(value);
            } else {
                self.nodes[level + 1][parent] = value;
            }
            index = parent;
        }
        Some(position)
    }

    /// The current root.
    pub fn root(&self) -> F {
        self.node(DEPTH, 0)
    }

    /// The authentication path for the leaf at `position`.
    pub fn witness(&self, position: usize) -> Option<Path<DEPTH>> {
        if position >= self.nodes[0].len() {
            return None;
        }
        let mut siblings = [F::ZERO; DEPTH];
        let mut bits = [false; DEPTH];
        let mut index = position;
        for (level, (sibling, bit)) in siblings.iter_mut().zip(bits.iter_mut()).enumerate() {
            *sibling = self.node(level, index ^ 1);
            *bit = index & 1 == 1;
            index /= 2;
        }
        Some(Path { siblings, bits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witnesses_recompute_the_root() {
        let mut tree = Tree::<8>::new();
        let leaves: Vec<F> = (1u64..=5).map(F::from).collect();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let root = tree.root();
        for (position, leaf) in leaves.iter().enumerate() {
            let path = tree.witness(position).expect("appended");
            assert_eq!(path.root(*leaf), root, "position {position}");
        }
    }

    #[test]
    fn a_wrong_leaf_misses_the_root() {
        let mut tree = Tree::<8>::new();
        tree.append(F::from(1));
        let path = tree.witness(0).expect("appended");
        assert_ne!(path.root(F::from(2)), tree.root());
    }

    #[test]
    fn depth_32_is_a_working_size() {
        let mut tree = Tree::<32>::new();
        let position = tree.append(F::from(42)).expect("room");
        let path = tree.witness(position).expect("appended");
        assert_eq!(path.root(F::from(42)), tree.root());
    }
}
