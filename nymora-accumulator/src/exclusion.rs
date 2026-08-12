// SPDX-License-Identifier: MIT OR Apache-2.0

//! The keyed exclusion sets and their non-membership witnesses (§9.1, §11).
//!
//! Two sets gate every routine proof: the revocation set, keyed by credential leaf (§11),
//! and the migration-spend set, keyed by migration nullifier (§9.3). A proof must show its
//! key **absent** from both at the current epoch — §9.1's currency clauses — so unlike the
//! positional accumulator of §5.2, this structure exists to prove what is *not* in it.
//!
//! # Provisional structure, permanent shape
//!
//! §9.1 fixes the real structure with the proving system. What is pinned here — and will
//! survive that choice — is the shape the rest of the protocol builds against: a keyed
//! root, a non-membership witness, and [`verifies_absent`]. The tree below is a sparse
//! Merkle tree over the key's 256 bits, chosen for being the simplest structure with an
//! honest non-membership proof; its digests move with the algebraic hash, which is why the
//! module sits behind the same provisional feature as [`crate::witness`].
//!
//! # One structure, two sets, distinct roots
//!
//! Both sets use this module. They are never merged: each is its own instance with its own
//! root, published per epoch, and a verifier accepts a routine proof only against the
//! current epoch's roots (§9.1). Nothing here reports how many keys a set holds — the
//! occupancy discipline of §5.2 carries over, since a revocation count is information
//! about members.

use crate::witness::Node;
use nymora_core::{Domain, Root, DIGEST_LEN};
use nymora_crypto::AlgebraicHasher;
use subtle::{Choice, ConditionallySelectable};

/// The number of levels in the sparse tree: one per key bit.
///
/// Every 32-byte key names exactly one leaf position, so two distinct keys can never
/// collide into one slot — absence of the position's leaf *is* absence of the key.
pub const KEY_BITS: usize = DIGEST_LEN * 8;

/// The node value standing for an absent key's leaf position.
///
/// All zeros, which is not in the image of [`occupied_leaf`] for any key anyone can
/// produce: landing on it would require a preimage of zero under the exclusion hash. The
/// same argument the positional tree uses for its empty positions.
const EMPTY_LEAF: Node = Node::from_bytes([0u8; DIGEST_LEN]);

/// Hashes a present key into its leaf.
///
/// Domain-separated from the positional accumulator's leaves, so a membership path and a
/// non-membership path can never be confused for each other even where the same 32 bytes
/// (a credential leaf) appear in both structures. Only construction hashes present keys —
/// verification proves absence, whose leaf is [`EMPTY_LEAF`] — so this sits with `build`.
#[cfg(feature = "build")]
fn occupied_leaf(key: &[u8; DIGEST_LEN]) -> Node {
    Node::from_bytes(
        AlgebraicHasher::new(Domain::ExclusionLeaf)
            .absorb(key)
            .finalize(),
    )
}

/// Hashes two children into an interior node of the sparse tree.
fn exclusion_node(left: &Node, right: &Node) -> Node {
    Node::from_bytes(
        AlgebraicHasher::new(Domain::ExclusionNode)
            .absorb(left.as_bytes())
            .absorb(right.as_bytes())
            .finalize(),
    )
}

/// Bit `level` of the key, where level 0 selects at the leaf and level 255 at the root's
/// children — the same LSB-first convention as the positional witness index.
fn bit_at(key: &[u8; DIGEST_LEN], level: usize) -> u8 {
    (key[DIGEST_LEN - 1 - level / 8] >> (level % 8)) & 1
}

/// The sibling hashes along one key's path, from the leaf upward.
///
/// Proves the leaf position named by a key holds the empty value — that the key is not in
/// the set. A witness is computable for *any* key, present or absent; for a present key
/// the recomputed root simply differs from the published one, so [`verifies_absent`]
/// returns false. Staleness is caught the same way: any insertion moves the root, and a
/// witness cut before it recomputes a root that is no longer current. One way to be wrong,
/// one check that catches it — the same design as the positional witness.
#[derive(Clone, PartialEq, Eq)]
pub struct AbsenceWitness {
    siblings: [Node; KEY_BITS],
}

impl core::fmt::Debug for AbsenceWitness {
    /// Renders without the siblings.
    ///
    /// The path is derived from the key, and for the revocation set the key is the
    /// member's own leaf — a witness rendered into a log would be a member's identity in a
    /// crash report.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AbsenceWitness {{ siblings: <redacted>, levels: {KEY_BITS} }}"
        )
    }
}

impl AbsenceWitness {
    /// Builds a witness from sibling hashes, `siblings[0]` being the leaf's immediate
    /// sibling.
    ///
    /// Unlike the positional witness there is no index to validate — the key supplied at
    /// verification names the path — so construction is total.
    #[must_use]
    pub const fn new(siblings: [Node; KEY_BITS]) -> Self {
        Self { siblings }
    }

    /// The sibling hashes, from the leaf upward.
    #[must_use]
    pub const fn siblings(&self) -> &[Node; KEY_BITS] {
        &self.siblings
    }
}

/// Recomputes the root implied by `key` being absent, given its path's siblings.
///
/// # Constant-time in the path
///
/// The path *is* the key, and for the revocation set the key is the member's own leaf.
/// Child ordering at each level is chosen branchlessly, as in the positional
/// recomputation, so the work does not vary with the key being proved absent.
#[must_use]
pub fn absent_root_from(key: &[u8; DIGEST_LEN], witness: &AbsenceWitness) -> Root {
    let mut current = EMPTY_LEAF;

    for level in 0..KEY_BITS {
        // Bit set: this node is the right child, so the sibling goes first.
        let on_the_right = Choice::from(bit_at(key, level));

        let mut left = *current.as_bytes();
        let mut right = *witness.siblings[level].as_bytes();
        for byte in 0..DIGEST_LEN {
            u8::conditional_swap(&mut left[byte], &mut right[byte], on_the_right);
        }

        current = exclusion_node(&Node::from_bytes(left), &Node::from_bytes(right));
    }

    Root::from_bytes(*current.as_bytes())
}

/// Whether `key` is absent from the set `root` names, as shown by `witness`.
///
/// This is the check the circuit performs for both currency clauses (§9.1). The comparison
/// is over public values — roots are published per epoch — and the secret-dependent work
/// has already been done, constant-time, by [`absent_root_from`].
#[must_use]
pub fn verifies_absent(key: &[u8; DIGEST_LEN], witness: &AbsenceWitness, root: &Root) -> bool {
    absent_root_from(key, witness).as_bytes() == root.as_bytes()
}

#[cfg(feature = "build")]
pub use build::ExclusionSet;

#[cfg(feature = "build")]
mod build {
    //! Set construction — the operator's side.
    //!
    //! Skiora holds each set, inserts on revocation (§11) and on migration spend (§9.3),
    //! publishes the root per epoch, and serves absence witnesses to members. As with the
    //! positional tree, the operator necessarily knows its own set; the line to hold is
    //! that nothing here has any counterpart on a member-facing interface.

    extern crate alloc;

    use super::{exclusion_node, occupied_leaf, AbsenceWitness, EMPTY_LEAF, KEY_BITS};
    use crate::witness::Node;
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;
    use nymora_core::{Root, DIGEST_LEN};

    /// A keyed exclusion set with non-membership witnesses.
    ///
    /// Insertion is permanent — nothing leaves a revocation or spend set (§11, §9.3) — and
    /// idempotent, since re-revoking a credential is a repeat of the same fact rather than
    /// an error. There is no `len`, no `is_empty`, no iterator, and no membership query:
    /// the set exists to prove absence, and a count of revocations is information about
    /// members (§5.2's discipline).
    pub struct ExclusionSet {
        keys: BTreeSet<[u8; DIGEST_LEN]>,
    }

    impl Default for ExclusionSet {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ExclusionSet {
        /// An empty set.
        #[must_use]
        pub const fn new() -> Self {
            Self {
                keys: BTreeSet::new(),
            }
        }

        /// Inserts a key. Idempotent; a repeat insertion changes nothing, including the root.
        pub fn insert(&mut self, key: [u8; DIGEST_LEN]) {
            self.keys.insert(key);
        }

        /// The current root. Publish per epoch; it moves on every first-time insertion.
        #[must_use]
        pub fn root(&self) -> Root {
            let keys: Vec<[u8; DIGEST_LEN]> = self.keys.iter().copied().collect();
            let empty = empty_levels();
            Root::from_bytes(*subtree(&keys, 0, &empty).as_bytes())
        }

        /// The absence witness for a key — the siblings along its path, leaf upward.
        ///
        /// Total: computable whether or not the key is present. For a present key the
        /// witness exists but shows the position occupied, so `verifies_absent` fails
        /// against this set's root — which is exactly the answer a verifier should get.
        #[must_use]
        pub fn absence_witness(&self, key: &[u8; DIGEST_LEN]) -> AbsenceWitness {
            let all: Vec<[u8; DIGEST_LEN]> = self.keys.iter().copied().collect();
            let empty = empty_levels();
            let mut siblings = [EMPTY_LEAF; KEY_BITS];

            // Walk from the root down the key's own path. At each depth the keys still in
            // scope split into the side the path descends into and the sibling side, whose
            // subtree hash is this level's witness entry.
            let mut in_scope: &[[u8; DIGEST_LEN]] = &all;
            for depth in 0..KEY_BITS {
                let split = in_scope.partition_point(|k| bit_from_top(k, depth) == 0);
                let (left, right) = in_scope.split_at(split);
                let descend_right = bit_from_top(key, depth) == 1;
                let (own, sibling) = if descend_right {
                    (right, left)
                } else {
                    (left, right)
                };
                siblings[KEY_BITS - 1 - depth] = subtree(sibling, depth + 1, &empty);
                in_scope = own;
            }

            AbsenceWitness::new(siblings)
        }
    }

    /// Bit `depth` of the key counted from the top of the tree, so that lexicographic key
    /// order is exactly path order and a sorted set splits by `partition_point`.
    ///
    /// `bit_from_top(key, d) == bit_at(key, KEY_BITS - 1 - d)` — the two views of the same
    /// path, one for descending and one for recomputing upward.
    fn bit_from_top(key: &[u8; DIGEST_LEN], depth: usize) -> u8 {
        (key[depth / 8] >> (7 - depth % 8)) & 1
    }

    /// The empty-subtree hash for a subtree whose top sits at each depth, `[KEY_BITS]`
    /// being an empty leaf.
    fn empty_levels() -> Vec<Node> {
        let mut levels = alloc::vec![EMPTY_LEAF; KEY_BITS + 1];
        for depth in (0..KEY_BITS).rev() {
            let below = levels[depth + 1];
            levels[depth] = exclusion_node(&below, &below);
        }
        levels
    }

    /// The hash of the subtree at `depth` containing exactly the given sorted keys.
    fn subtree(keys: &[[u8; DIGEST_LEN]], depth: usize, empty: &[Node]) -> Node {
        if keys.is_empty() {
            return empty[depth];
        }
        if depth == KEY_BITS {
            // Distinct keys cannot share all 256 bits, so a fully descended slice holds
            // exactly one.
            return occupied_leaf(&keys[0]);
        }
        let split = keys.partition_point(|k| bit_from_top(k, depth) == 0);
        let (left, right) = keys.split_at(split);
        exclusion_node(
            &subtree(left, depth + 1, empty),
            &subtree(right, depth + 1, empty),
        )
    }
}

#[cfg(all(test, feature = "build"))]
mod tests {
    use super::{verifies_absent, ExclusionSet, KEY_BITS};
    use nymora_core::DIGEST_LEN;

    fn key(byte: u8) -> [u8; DIGEST_LEN] {
        [byte; DIGEST_LEN]
    }

    /// An empty set proves every key absent.
    #[test]
    fn everything_is_absent_from_an_empty_set() {
        let set = ExclusionSet::new();
        let root = set.root();
        for probe in [key(0x00), key(0x42), key(0xff)] {
            assert!(verifies_absent(&probe, &set.absence_witness(&probe), &root));
        }
    }

    /// The clause the circuit checks, both ways: a revoked credential cannot show
    /// absence, and an unrevoked one still can.
    #[test]
    fn an_inserted_key_fails_absence_and_its_neighbours_still_pass() {
        let mut set = ExclusionSet::new();
        set.insert(key(0x42));
        let root = set.root();

        assert!(
            !verifies_absent(&key(0x42), &set.absence_witness(&key(0x42)), &root),
            "a present key proved itself absent"
        );

        // The nearest possible neighbours: the same key with only the last bit flipped,
        // and with only the first bit flipped — sharing all but one level of the path.
        let mut last_bit = key(0x42);
        last_bit[DIGEST_LEN - 1] ^= 0x01;
        let mut first_bit = key(0x42);
        first_bit[0] ^= 0x80;
        for probe in [last_bit, first_bit, key(0x43)] {
            assert!(
                verifies_absent(&probe, &set.absence_witness(&probe), &root),
                "an absent neighbour failed its absence proof"
            );
        }
    }

    #[test]
    fn every_first_time_insertion_moves_the_root_and_repeats_do_not() {
        let mut set = ExclusionSet::new();
        let empty = set.root();
        set.insert(key(0x01));
        let one = set.root();
        assert_ne!(empty.as_bytes(), one.as_bytes());

        set.insert(key(0x01));
        assert_eq!(
            one.as_bytes(),
            set.root().as_bytes(),
            "an idempotent re-insertion moved the root"
        );

        set.insert(key(0x02));
        assert_ne!(one.as_bytes(), set.root().as_bytes());
    }

    /// A witness cut before an insertion fails afterwards — staleness and forgery are the
    /// same failure, exactly as for the positional witness.
    #[test]
    fn a_stale_witness_fails_against_the_moved_root() {
        let mut set = ExclusionSet::new();
        set.insert(key(0x11));
        let stale = set.absence_witness(&key(0x22));
        set.insert(key(0x33));

        assert!(!verifies_absent(&key(0x22), &stale, &set.root()));
        assert!(verifies_absent(
            &key(0x22),
            &set.absence_witness(&key(0x22)),
            &set.root()
        ));
    }

    /// The two sets are separate instances, and one's witness says nothing about the other.
    #[test]
    fn absence_in_one_set_does_not_verify_against_another() {
        let mut revocations = ExclusionSet::new();
        let mut spends = ExclusionSet::new();
        revocations.insert(key(0x11));
        spends.insert(key(0x22));

        let witness = revocations.absence_witness(&key(0x33));
        assert!(verifies_absent(&key(0x33), &witness, &revocations.root()));
        assert!(!verifies_absent(&key(0x33), &witness, &spends.root()));
    }

    /// A witness must not put a member's path in a log. See `Debug` on `AbsenceWitness`.
    #[test]
    fn debug_redacts_the_path() {
        let set = ExclusionSet::new();
        let rendered = std::format!("{:?}", set.absence_witness(&key(0x42)));
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("4242"), "a sibling leaked: {rendered}");
    }

    /// Pins the construction against silent change, cross-checked against an independent
    /// implementation of the sparse tree over the framing and SHA-256 stand-in.
    ///
    /// This pins the *shape*: the two domain tags, the zero empty-leaf, the key-bits path
    /// with lexicographic order matching path order, and the leaf-upward sibling
    /// convention. The digest itself moves when the real algebraic hash arrives.
    #[test]
    fn known_answer() {
        let mut set = ExclusionSet::new();
        set.insert(key(0x42));
        assert_eq!(set.root().as_bytes(), &KNOWN_ROOT);
        assert_eq!(KEY_BITS, 256);
    }

    const KNOWN_ROOT: [u8; DIGEST_LEN] = [
        0x90, 0x56, 0xfe, 0xf9, 0x2c, 0xe6, 0x61, 0xbe, 0x97, 0x42, 0xfe, 0xfb, 0xc0, 0x0c, 0xd2,
        0xbb, 0x27, 0x88, 0xa5, 0x0a, 0xfb, 0x8a, 0xb9, 0xe5, 0xb9, 0x84, 0xf3, 0xee, 0x88, 0x96,
        0x5f, 0x9d,
    ];
}
