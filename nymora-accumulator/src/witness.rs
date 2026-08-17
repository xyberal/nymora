// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inclusion witnesses and the root recomputation every role performs (§5.2).
//!
//! The fold is the circuit's, exactly (proposal 0035): the leaf value enters as itself,
//! and each level is the untagged 2-to-1 Poseidon of the pinned instance. There is no
//! leaf tag and no node tag — the sponge writes the input length into its capacity
//! element, so the 2-element node function is structurally disjoint from the 5-element
//! credential leaf and the 3-element gap leaf that occupy these trees, which is what
//! the old tags existed to guarantee. The classical second-preimage shift is closed a
//! second way besides: depth is fixed per accumulator, and a witness carries exactly
//! `DEPTH` siblings, so a path one level short does not typecheck.

use nymora_core::{Commitment, Root, DIGEST_LEN};
use nymora_crypto::field::{from_witness_bytes, to_bytes, F};
use nymora_crypto::poseidon;
use subtle::{Choice, ConditionallySelectable};

/// A node in an accumulator — an interior hash, or a leaf value, as canonical field
/// bytes.
///
/// Distinct from [`Root`] although both are 32 bytes: a root is a published value that
/// names an accumulator's state at an epoch, while a node is an intermediate the holder
/// of a witness recomputes. Only the topmost node becomes a root, and [`root_from`] is
/// the only place that conversion happens.
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

    /// The field element this node names.
    ///
    /// Total, by reduction: a non-canonical byte string folds to *some* element rather
    /// than failing, which is harmless — witness forgery is prevented by preimage
    /// resistance, not encoding injectivity, and an adversary who controls the bytes
    /// could as easily have sent the canonical form (proposal 0035). The circuit never
    /// sees this decoding at all; it witnesses field elements directly.
    fn value(&self) -> F {
        from_witness_bytes(&self.0)
    }
}

impl core::fmt::Debug for Node {
    /// Renders as hex.
    ///
    /// A node is not secret — it is one hash on a path to a published root — but it *is*
    /// a member's position in a membership set, so it does not belong in a log by habit.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Node(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Hashes two children into an interior node: the untagged 2-to-1 Poseidon
/// (proposal 0035).
#[must_use]
pub fn hash_node(left: &Node, right: &Node) -> Node {
    Node(to_bytes(&poseidon::hash(&[left.value(), right.value()])))
}

/// A leaf's position and the sibling hashes along its path to the root.
///
/// `DEPTH` is fixed per accumulator and is not secret — it is a published protocol
/// constant (§5.2) — but how much of it is occupied is, which is why nothing here
/// reports a count.
///
/// # Staleness is caught by verification, not by a flag
///
/// Any insertion touching this path invalidates the witness. There is no `is_stale` and
/// no stored expiry: a stale witness simply recomputes a root that is no longer current,
/// so [`verifies`] returns false against the live root. That is the same check that
/// catches a forged witness, so there is exactly one way to be wrong and one way to
/// detect it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Witness<const DEPTH: usize> {
    index: u64,
    siblings: [Node; DEPTH],
}

impl<const DEPTH: usize> core::fmt::Debug for Witness<DEPTH> {
    /// Renders without the index or the siblings.
    ///
    /// [`Node`]'s `Debug` rationale applies with more force here: the index *is* the
    /// member's position in the membership set — more sensitive than any single node on
    /// the path — and the siblings are the path itself. Only the depth appears, and it
    /// is a published protocol constant.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Witness {{ index: <redacted>, depth: {DEPTH} }}")
    }
}

impl<const DEPTH: usize> Witness<DEPTH> {
    /// Builds a witness for the leaf at `index`.
    ///
    /// `siblings[0]` is the leaf's immediate sibling and `siblings[DEPTH - 1]` is the
    /// child of the root, so the array reads from the leaf upward.
    ///
    /// Returns `None` if `index` does not name a leaf at this depth. That is a property
    /// of the caller's own argument rather than of any hidden state, so reporting it
    /// discloses nothing — and accepting it silently would be worse, since the surplus
    /// high bits would be ignored and the witness would verify against a position its
    /// holder did not intend.
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

/// The fold itself, over field elements — shared by the inclusion check here and the
/// gap-leaf check in [`crate::exclusion`].
///
/// # Constant-time in the path
///
/// Whether the running node is a left or right child is a bit of the leaf's index, and
/// the index is the member's position in the membership set. The child ordering is
/// therefore chosen by a branchless conditional swap rather than an `if`, so the work at
/// each level does not vary with the position being proved. The number of levels is
/// `DEPTH`, which is public.
pub(crate) fn fold<const DEPTH: usize>(leaf: F, witness: &Witness<DEPTH>) -> Root {
    let mut current = leaf;

    for level in 0..DEPTH {
        // Bit set: this node is the right child, so the sibling goes first.
        #[allow(clippy::cast_possible_truncation)]
        let on_the_right = Choice::from(((witness.index >> level) & 1) as u8);

        let mut left = current;
        let mut right = witness.siblings[level].value();
        F::conditional_swap(&mut left, &mut right, on_the_right);

        current = poseidon::hash(&[left, right]);
    }

    Root::from_bytes(to_bytes(&current))
}

/// Recomputes the root a leaf and witness imply.
///
/// Total: a witness constructed by [`Witness::new`] always names a position, so there is
/// no failure mode here that is not "the result differs from the root you expected".
#[must_use]
pub fn root_from<const DEPTH: usize>(value: &Commitment, witness: &Witness<DEPTH>) -> Root {
    fold(from_witness_bytes(value.as_bytes()), witness)
}

/// Whether a leaf and witness reproduce `root`.
///
/// Both values compared here are public — a root is published (§5.2) — so this does not
/// need to be constant-time in the comparison. The secret part is the path, and it has
/// already been consumed by the fold, which is.
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
    use super::{root_from, verifies, Node, Witness};
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

    /// Position is bound, not incidental: the same leaf with the same siblings at a
    /// different index must produce a different root, or a member could claim any
    /// position whose siblings they happen to know.
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

    /// Depth 0 is one leaf and no siblings — the root is the leaf value itself.
    #[test]
    fn depth_zero_is_representable() {
        let witness = Witness::new(0, []).expect("index 0 is the only leaf at depth 0");
        assert_eq!(root_from(&VALUE, &witness).as_bytes(), VALUE.as_bytes());
        assert!(Witness::<0>::new(1, []).is_none());
    }

    /// A non-canonical sibling folds by reduction to the same root as its canonical
    /// twin — deliberately; see [`Node::value`]. Neither forges anything: both name the
    /// same field element, and the root comparison is what gatekeeps.
    #[test]
    fn a_non_canonical_sibling_names_its_reduced_element() {
        let canonical = root_from(&VALUE, &witness(0));
        // The field modulus reduces to zero, as does the zero string.
        let modulus: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
        ];
        let reduced = Witness::new(0, [Node::from_bytes(modulus), sibs()[1]])
            .expect("index 0 is within depth 2");
        let zeroed = Witness::new(0, [Node::from_bytes([0u8; 32]), sibs()[1]])
            .expect("index 0 is within depth 2");
        assert_eq!(
            root_from(&VALUE, &reduced).as_bytes(),
            root_from(&VALUE, &zeroed).as_bytes()
        );
        assert_ne!(root_from(&VALUE, &reduced).as_bytes(), canonical.as_bytes());
    }
}
