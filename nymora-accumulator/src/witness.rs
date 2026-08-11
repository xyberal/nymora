// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inclusion witnesses and the root recomputation every role performs (§5.2).

use nymora_core::{Commitment, Domain, Root, DIGEST_LEN};
use nymora_crypto::AlgebraicHasher;
use subtle::{Choice, ConditionallySelectable};

/// A node in an accumulator — an interior hash, or a hashed leaf.
///
/// Distinct from [`Root`] although both are 32 bytes: a root is a published value that names an
/// accumulator's state at an epoch, while a node is an intermediate the holder of a witness
/// recomputes. Only the topmost node becomes a root, and [`root_from`] is the only place that
/// conversion happens.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Node([u8; DIGEST_LEN]);

impl Node {
    /// Wraps 32 bytes as a node.
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

impl core::fmt::Debug for Node {
    /// Renders as hex.
    ///
    /// A node is not secret — it is one hash on a path to a published root — but it *is* a
    /// member's position in a membership set, so it does not belong in a log by habit.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Node(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Hashes a value into an accumulator leaf.
///
/// The accumulator hashes what it is handed rather than relying on the value to carry its own
/// separation. A credential leaf is already a domain-separated commitment (§9.1) and would be
/// safe unwrapped, but this structure is generic over its contents — §11's revocation set is a
/// second instance — and its safety must not rest on their provenance.
#[must_use]
pub fn hash_leaf(value: &Commitment) -> Node {
    Node(
        AlgebraicHasher::new(Domain::AccumulatorLeaf)
            .absorb(value.as_bytes())
            .finalize(),
    )
}

/// Hashes two children into an interior node.
#[must_use]
pub fn hash_node(left: &Node, right: &Node) -> Node {
    Node(
        AlgebraicHasher::new(Domain::AccumulatorNode)
            .absorb(&left.0)
            .absorb(&right.0)
            .finalize(),
    )
}

/// A leaf's position and the sibling hashes along its path to the root.
///
/// `DEPTH` is fixed per accumulator and is not secret — it is a published property of the agora
/// — but how much of it is occupied is (§5.2), which is why nothing here reports a count.
///
/// # Staleness is caught by verification, not by a flag
///
/// Any insertion touching this path invalidates the witness. There is no `is_stale` and no
/// stored expiry: a stale witness simply recomputes a root that is no longer current, so
/// [`verifies`] returns false against the live root. That is the same check that catches a
/// forged witness, so there is exactly one way to be wrong and one way to detect it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Witness<const DEPTH: usize> {
    index: u64,
    siblings: [Node; DEPTH],
}

impl<const DEPTH: usize> core::fmt::Debug for Witness<DEPTH> {
    /// Renders without the index or the siblings.
    ///
    /// [`Node`]'s `Debug` rationale applies with more force here: the index *is* the member's
    /// position in the membership set — more sensitive than any single node on the path — and
    /// the siblings are the path itself. Only the depth appears, and it is a published
    /// property of the agora.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Witness {{ index: <redacted>, depth: {DEPTH} }}")
    }
}

impl<const DEPTH: usize> Witness<DEPTH> {
    /// Builds a witness for the leaf at `index`.
    ///
    /// `siblings[0]` is the leaf's immediate sibling and `siblings[DEPTH - 1]` is the child of
    /// the root, so the array reads from the leaf upward.
    ///
    /// Returns `None` if `index` does not name a leaf at this depth. That is a property of the
    /// caller's own argument rather than of any hidden state, so reporting it discloses nothing
    /// — and accepting it silently would be worse, since the surplus high bits would be ignored
    /// and the witness would verify against a position its holder did not intend.
    #[must_use]
    pub fn new(index: u64, siblings: [Node; DEPTH]) -> Option<Self> {
        // At DEPTH >= 64 every u64 names a leaf, and `1 << DEPTH` would overflow.
        if DEPTH < 64 && index >= (1u64 << DEPTH) {
            return None;
        }
        Some(Self { index, siblings })
    }

    /// The leaf's position.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// The sibling hashes, from the leaf upward.
    #[must_use]
    pub const fn siblings(&self) -> &[Node; DEPTH] {
        &self.siblings
    }
}

/// Recomputes the root a leaf and witness imply.
///
/// Total: a witness constructed by [`Witness::new`] always names a position, so there is no
/// failure mode here that is not "the result differs from the root you expected".
///
/// # Constant-time in the path
///
/// Whether the running node is a left or right child is a bit of the leaf's index, and the
/// index is the member's position in the membership set. The child ordering is therefore chosen
/// by a branchless conditional swap rather than an `if`, so the work at each level does not vary
/// with the position being proved. The number of levels is `DEPTH`, which is public.
#[must_use]
pub fn root_from<const DEPTH: usize>(value: &Commitment, witness: &Witness<DEPTH>) -> Root {
    let mut current = hash_leaf(value);

    for level in 0..DEPTH {
        // Bit set: this node is the right child, so the sibling goes first.
        #[allow(clippy::cast_possible_truncation)]
        let on_the_right = Choice::from(((witness.index >> level) & 1) as u8);

        let mut left = current.0;
        let mut right = witness.siblings[level].0;
        for byte in 0..DIGEST_LEN {
            u8::conditional_swap(&mut left[byte], &mut right[byte], on_the_right);
        }

        current = hash_node(&Node(left), &Node(right));
    }

    Root::from_bytes(current.0)
}

/// Whether a leaf and witness reproduce `root`.
///
/// Both values compared here are public — a root is published (§5.2) — so this does not need to
/// be constant-time in the comparison. The secret part is the path, and it has already been
/// consumed by [`root_from`], which is.
#[must_use]
pub fn verifies<const DEPTH: usize>(
    value: &Commitment,
    witness: &Witness<DEPTH>,
    root: &Root,
) -> bool {
    root_from(value, witness).as_bytes() == root.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::{hash_leaf, hash_node, root_from, verifies, Node, Witness};
    use nymora_core::{Commitment, Root, DIGEST_LEN};

    const VALUE: Commitment = Commitment::from_bytes([0x01; DIGEST_LEN]);

    fn sibs() -> [Node; 2] {
        [
            Node::from_bytes([0x02; DIGEST_LEN]),
            Node::from_bytes([0x03; DIGEST_LEN]),
        ]
    }

    fn witness(index: u64) -> Witness<2> {
        Witness::new(index, sibs()).expect("index is within depth 2")
    }

    #[test]
    fn a_witness_reproduces_its_own_root() {
        let root = root_from(&VALUE, &witness(1));
        assert!(verifies(&VALUE, &witness(1), &root));
    }

    /// A stale or forged witness fails the same way, which is the point.
    #[test]
    fn a_witness_fails_against_a_root_it_was_not_cut_for() {
        let root = root_from(&VALUE, &witness(1));
        assert!(!verifies(
            &VALUE,
            &witness(1),
            &Root::from_bytes([0xff; DIGEST_LEN])
        ));

        let moved = Witness::new(
            1,
            [
                Node::from_bytes([0x02; DIGEST_LEN]),
                Node::from_bytes([0x04; DIGEST_LEN]),
            ],
        )
        .expect("index is within depth 2");
        assert!(
            !verifies(&VALUE, &moved, &root),
            "a changed sibling still verified"
        );
    }

    /// Position is bound, not incidental.
    ///
    /// The same leaf with the same siblings at a different index must produce a different root,
    /// or a member could claim any position whose siblings they happen to know.
    #[test]
    fn the_index_changes_the_root() {
        let roots: [Root; 4] = [0, 1, 2, 3].map(|i| root_from(&VALUE, &witness(i)));
        for (a, first) in roots.iter().enumerate() {
            for second in roots.iter().skip(a + 1) {
                assert_ne!(
                    first.as_bytes(),
                    second.as_bytes(),
                    "two positions collided"
                );
            }
        }
    }

    #[test]
    fn a_different_value_changes_the_root() {
        let other = Commitment::from_bytes([0x02; DIGEST_LEN]);
        assert_ne!(
            root_from(&VALUE, &witness(1)).as_bytes(),
            root_from(&other, &witness(1)).as_bytes()
        );
    }

    /// The Merkle second-preimage substitution, which the two domain tags exist to block.
    ///
    /// Without separate tags an interior node — itself a hash of two children — could be
    /// presented as a leaf value, and an inclusion proof for it would verify. A member could
    /// then claim membership for a "leaf" they never held, having only observed a node on
    /// someone else's path.
    #[test]
    fn an_interior_node_cannot_be_presented_as_a_leaf() {
        let interior = hash_node(
            &Node::from_bytes([0x01; DIGEST_LEN]),
            &Node::from_bytes([0x02; DIGEST_LEN]),
        );
        let forged = Commitment::from_bytes(*interior.as_bytes());
        assert_ne!(
            hash_leaf(&forged).as_bytes(),
            interior.as_bytes(),
            "a leaf hash collided with an interior node"
        );
    }

    /// The index must not reach a log by habit — see `Debug` on [`Witness`].
    #[test]
    fn debug_redacts_the_position_and_the_path() {
        let rendered = std::format!("{:?}", witness(3));
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains('3'), "the index leaked: {rendered}");
        assert!(!rendered.contains("0202"), "a sibling leaked: {rendered}");
    }

    #[test]
    fn an_index_outside_the_depth_is_refused() {
        assert!(
            Witness::new(3, sibs()).is_some(),
            "3 is the last leaf at depth 2"
        );
        assert!(Witness::new(4, sibs()).is_none());
        assert!(Witness::new(u64::MAX, sibs()).is_none());
    }

    /// Depth 0 is one leaf and no siblings — the root is the leaf hash.
    #[test]
    fn depth_zero_is_representable() {
        let witness = Witness::new(0, []).expect("index 0 is the only leaf at depth 0");
        assert_eq!(
            root_from(&VALUE, &witness).as_bytes(),
            hash_leaf(&VALUE).as_bytes()
        );
        assert!(Witness::<0>::new(1, []).is_none());
    }

    /// Pins the recomputation, cross-checked against an independent implementation of the
    /// framing and of SHA-256 — which is what the provisional algebraic backend stands in with.
    ///
    /// This pins the *shape*: the two domain tags, the leaf-upward sibling order, and which
    /// child the index bit selects. The digest itself moves when the real algebraic hash
    /// arrives.
    #[test]
    fn known_answer() {
        assert_eq!(
            root_from(&VALUE, &witness(1)).as_bytes(),
            &[
                0x1a, 0x2b, 0x95, 0x0b, 0xc4, 0xc0, 0x14, 0xbf, 0x62, 0x9a, 0xc1, 0x3e, 0xb2, 0x26,
                0x81, 0xac, 0x57, 0x97, 0x97, 0xcd, 0x03, 0xb2, 0xb5, 0x7c, 0xb7, 0x11, 0x8a, 0x5b,
                0x68, 0x90, 0x45, 0x22,
            ]
        );
    }
}
