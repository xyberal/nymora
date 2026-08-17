// SPDX-License-Identifier: MIT OR Apache-2.0

//! The keyed exclusion sets and their non-membership witnesses (§9.1, §11).
//!
//! Two sets gate every routine proof: the revocation set, keyed by credential leaf
//! (§11), and the migration-spend set, keyed by migration nullifier (§9.3). A proof
//! must show its key **absent** from both at the current epoch — §9.1's currency
//! clauses — so unlike the positional accumulator of §5.2, this structure exists to
//! prove what is *not* in it.
//!
//! # Gap trees: absence as a positive statement (proposal 0035)
//!
//! A set holds its keys truncated to [`KEY_BITS`] bits, sorted, with sentinels 0 and
//! 2²⁵³−1 closing the ends. Consecutive pairs are the *gaps*; each gap `(low, high)` is
//! a leaf `Poseidon(GAP, low, high)` in a positional tree of the same depth as every
//! other accumulator. Absence of a key `t` is then inclusion of a gap that strictly
//! contains it — `low < t < high`, both comparisons in-statement — which a present key
//! can never satisfy, because its own truncation is what some gap boundary holds.
//! Soundness is unconditional; what truncation risks is only **availability**: two
//! distinct keys colliding in 253 bits (probability ~2⁻²⁵³) would leave the later one
//! unable to prove its own absence — an outcome the protocol survives and an adversary
//! cannot exploit.
//!
//! # One structure, two sets, distinct roots
//!
//! Both sets use this module. They are never merged: each is its own instance with its
//! own root, published per epoch, and a verifier accepts a routine proof only against
//! the current epoch's roots (§9.1). Nothing here reports how many keys a set holds —
//! the occupancy discipline of §5.2 carries over, since a revocation count is
//! information about members.

use nymora_core::{field_domain, Root, DIGEST_LEN};
use nymora_crypto::field::{from_witness_bytes, F};
use nymora_crypto::poseidon;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess};

use crate::witness::{fold, Witness};

/// The width of the exclusion ordering domain, in bits.
///
/// Full-field keys are truncated to this width before they order gaps, because the
/// in-circuit comparison is sound only below the field's bit length less two. A
/// truncation collision can only cost availability, never soundness — see the module
/// documentation.
pub const KEY_BITS: usize = 253;

/// Truncates a key into the ordering domain: little-endian, bits 253 and above cleared.
#[must_use]
pub fn truncate_key(key: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut out = *key;
    out[31] &= 0x1f;
    out
}

/// The upper sentinel: the largest value of the ordering domain, 2²⁵³−1.
fn upper_sentinel() -> [u8; DIGEST_LEN] {
    let mut out = [0xff; DIGEST_LEN];
    out[31] = 0x1f;
    out
}

/// Strict less-than over two truncated keys, constant-time.
///
/// The key being proved absent is, for the revocation set, the member's own leaf — so
/// the comparison walks every byte regardless of where the answer is decided.
fn ct_less(a: &[u8; DIGEST_LEN], b: &[u8; DIGEST_LEN]) -> Choice {
    let mut less = Choice::from(0u8);
    let mut equal = Choice::from(1u8);
    // Most significant byte decides; the values are little-endian.
    for i in (0..DIGEST_LEN).rev() {
        less |= equal & a[i].ct_lt(&b[i]);
        equal &= a[i].ct_eq(&b[i]);
    }
    less
}

/// The gap leaf: `Poseidon(GAP, low, high)` (proposal 0035).
fn gap_leaf(low: &[u8; DIGEST_LEN], high: &[u8; DIGEST_LEN]) -> F {
    poseidon::hash(&[
        F::from(field_domain::GAP),
        from_witness_bytes(low),
        from_witness_bytes(high),
    ])
}

/// A non-membership witness: the gap said to contain the key, and the inclusion path
/// showing that gap under the set's root.
///
/// A witness is computable for *any* key, present or absent; for a present key the
/// containment comparison honestly fails, so [`verifies_absent`] returns false.
/// Staleness is caught the same way: any insertion re-cuts the gaps and moves the
/// root. One way to be wrong, one check that catches it — the same design as the
/// positional witness.
#[derive(Clone, PartialEq, Eq)]
pub struct AbsenceWitness<const DEPTH: usize> {
    /// The gap's lower bound, in the ordering domain.
    low: [u8; DIGEST_LEN],
    /// The gap's upper bound.
    high: [u8; DIGEST_LEN],
    /// The gap leaf's inclusion path.
    witness: Witness<DEPTH>,
}

impl<const DEPTH: usize> core::fmt::Debug for AbsenceWitness<DEPTH> {
    /// Renders without the bounds or the path.
    ///
    /// The gap bounds neighbour the key being proved absent, and for the revocation set
    /// that key is the member's own leaf — a witness rendered into a log would be a
    /// member's identity in a crash report.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AbsenceWitness {{ <gap redacted>, depth: {DEPTH} }}")
    }
}

impl<const DEPTH: usize> AbsenceWitness<DEPTH> {
    /// Builds a witness from a claimed gap and its inclusion path.
    ///
    /// Total: whether the gap contains the key, and whether it is a real gap of the
    /// set, are both decided at verification — construction validates nothing, exactly
    /// like the positional witness.
    #[must_use]
    pub const fn new(
        low: [u8; DIGEST_LEN],
        high: [u8; DIGEST_LEN],
        witness: Witness<DEPTH>,
    ) -> Self {
        Self { low, high, witness }
    }

    /// The gap's lower bound, in the ordering domain.
    #[must_use]
    pub const fn low(&self) -> &[u8; DIGEST_LEN] {
        &self.low
    }

    /// The gap's upper bound.
    #[must_use]
    pub const fn high(&self) -> &[u8; DIGEST_LEN] {
        &self.high
    }

    /// The gap leaf's inclusion path.
    #[must_use]
    pub const fn path(&self) -> &Witness<DEPTH> {
        &self.witness
    }
}

/// Whether `key` is absent from the set `root` names, as shown by `witness`.
///
/// This is the check the circuit performs for both currency clauses (§9.1): the key,
/// truncated into the ordering domain, lies strictly inside the witnessed gap, and the
/// gap's leaf sits under the root. The comparisons are constant-time in the key; the
/// root comparison is over public values.
#[must_use]
pub fn verifies_absent<const DEPTH: usize>(
    key: &[u8; DIGEST_LEN],
    witness: &AbsenceWitness<DEPTH>,
    root: &Root,
) -> bool {
    let t = truncate_key(key);
    let contained = ct_less(&witness.low, &t) & ct_less(&t, &witness.high);
    let recomputed = fold(gap_leaf(&witness.low, &witness.high), &witness.witness);
    bool::from(contained) && recomputed.as_bytes() == root.as_bytes()
}

#[cfg(feature = "build")]
pub use build::ExclusionSet;

#[cfg(feature = "build")]
mod build {
    //! Set construction — the operator's side, and the member's own copy.
    //!
    //! Skiora holds each set, inserts on revocation (§11) and on migration spend
    //! (§9.3), publishes the root per epoch, and serves **the whole set** to members,
    //! member-gated like roots (§11). Each Persora then rebuilds the set locally and
    //! computes its own non-membership witnesses: a witness request naming a specific
    //! key would disclose to Skiora exactly which credential is about to act, and
    //! serving the full set is what keeps the request anonymous. It stays affordable
    //! because both sets grow with revocations and migrations, never with membership
    //! or content.

    extern crate alloc;

    use super::{gap_leaf, truncate_key, upper_sentinel, AbsenceWitness};
    use crate::tree::Tree;
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;
    use nymora_core::{Root, DIGEST_LEN};
    use nymora_crypto::field::to_bytes;

    /// A keyed exclusion set with non-membership witnesses.
    ///
    /// Insertion is permanent — nothing leaves a revocation or spend set (§11, §9.3) —
    /// and idempotent, since re-revoking a credential is a repeat of the same fact
    /// rather than an error. There is no `len`, no `is_empty`, and no membership
    /// query. The one enumeration is [`keys`](ExclusionSet::keys), because §11 makes
    /// whole-set service to members normative; unlike the positional tree, a
    /// member-visible count of exclusions is deliberate — *"k revocations since"* is
    /// exactly the epoch-coarse fact §11 tells members to weigh older content by.
    ///
    /// `DEPTH` is the gap tree's depth — the same network-wide constant as every
    /// accumulator (§5.2), the set's capacity being one gap more than its keys.
    pub struct ExclusionSet<const DEPTH: usize> {
        /// Truncated keys, kept in ordering form (big-endian) so the natural byte
        /// order of the collection is the integer order of the domain.
        keys: BTreeSet<[u8; DIGEST_LEN]>,
    }

    impl<const DEPTH: usize> Default for ExclusionSet<DEPTH> {
        fn default() -> Self {
            Self::new()
        }
    }

    fn to_ordering(le: [u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
        let mut be = le;
        be.reverse();
        be
    }

    fn to_le(be: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
        let mut le = *be;
        le.reverse();
        le
    }

    impl<const DEPTH: usize> ExclusionSet<DEPTH> {
        /// An empty set: one gap, spanning the whole ordering domain.
        #[must_use]
        pub const fn new() -> Self {
            Self {
                keys: BTreeSet::new(),
            }
        }

        /// Inserts a key. Idempotent; a repeat insertion changes nothing, including
        /// the root. The key is truncated into the ordering domain — see the module
        /// documentation for what a truncation collision can and cannot cost.
        pub fn insert(&mut self, key: [u8; DIGEST_LEN]) {
            self.keys.insert(to_ordering(truncate_key(&key)));
        }

        /// Every truncated key, in ordering (ascending) order — §11's whole-set
        /// service. This is how the set crosses to a member: whole, behind the member
        /// gate of §7, so the member can rebuild it and compute non-membership
        /// witnesses locally without ever naming the key they are about to prove
        /// absent.
        pub fn keys(&self) -> impl Iterator<Item = [u8; DIGEST_LEN]> + '_ {
            self.keys.iter().map(to_le)
        }

        /// The gap bounds, in order: sentinels closing both ends, consecutive keys
        /// between.
        fn gaps(&self) -> Vec<([u8; DIGEST_LEN], [u8; DIGEST_LEN])> {
            let mut bounds = Vec::with_capacity(self.keys.len() + 2);
            bounds.push([0u8; DIGEST_LEN]);
            bounds.extend(self.keys.iter().map(to_le));
            bounds.push(upper_sentinel());
            bounds.windows(2).map(|w| (w[0], w[1])).collect()
        }

        /// The gap tree over the current keys.
        fn tree(&self) -> Tree<DEPTH> {
            let mut tree = Tree::new();
            for (low, high) in self.gaps() {
                let leaf = nymora_core::Commitment::from_bytes(to_bytes(&gap_leaf(&low, &high)));
                // A full gap tree means 2^DEPTH exclusions — at the protocol depth,
                // beyond any set §11 can produce. Exhaustion here is the same terminal
                // condition as class exhaustion (§5.2) and surfaces at root time.
                let _ = tree.append(leaf);
            }
            tree
        }

        /// The current root. Publish per epoch; it moves on every first-time
        /// insertion.
        #[must_use]
        pub fn root(&self) -> Root {
            self.tree().root()
        }

        /// The absence witness for a key: the gap whose lower bound is the greatest
        /// bound at or below the truncated key, with its inclusion path.
        ///
        /// Total: computable whether or not the key is present. For a present key the
        /// returned gap has `low` equal to the truncation itself, so the strict
        /// containment in `verifies_absent` honestly fails — which is exactly the
        /// answer a verifier should get.
        #[must_use]
        pub fn absence_witness(&self, key: &[u8; DIGEST_LEN]) -> AbsenceWitness<DEPTH> {
            let t = to_ordering(truncate_key(key));
            let position = self.keys.range(..=t).count();
            let gaps = self.gaps();
            let (low, high) = gaps[position];
            let witness = self
                .tree()
                .witness(position as u64)
                .expect("every gap was appended");
            AbsenceWitness::new(low, high, witness)
        }
    }
}

#[cfg(all(test, feature = "build"))]
mod tests {
    use super::{truncate_key, verifies_absent, ExclusionSet};
    use nymora_core::DIGEST_LEN;

    const DEPTH: usize = 8;

    fn key(byte: u8) -> [u8; DIGEST_LEN] {
        [byte; DIGEST_LEN]
    }

    fn set(keys: &[[u8; DIGEST_LEN]]) -> ExclusionSet<DEPTH> {
        let mut set = ExclusionSet::new();
        for k in keys {
            set.insert(*k);
        }
        set
    }

    /// An empty set proves every key absent — every key except the two sentinel values
    /// themselves, whose containment is not strict. A real key is a hash output, so
    /// landing on either sentinel is the same ~2^-252 availability accident as a
    /// truncation collision, and costs the same: nothing an adversary can use.
    #[test]
    fn everything_is_absent_from_an_empty_set() {
        let set = set(&[]);
        let root = set.root();
        for probe in [key(0x01), key(0x42), key(0xfe)] {
            assert!(verifies_absent(&probe, &set.absence_witness(&probe), &root));
        }

        let on_the_sentinel = key(0xff); // Truncates to exactly the upper bound.
        assert!(!verifies_absent(
            &on_the_sentinel,
            &set.absence_witness(&on_the_sentinel),
            &root
        ));
    }

    /// The clause the circuit checks, both ways: a revoked credential cannot show
    /// absence, and an unrevoked one still can.
    #[test]
    fn an_inserted_key_fails_absence_and_its_neighbours_still_pass() {
        let set = set(&[key(0x42)]);
        let root = set.root();

        assert!(
            !verifies_absent(&key(0x42), &set.absence_witness(&key(0x42)), &root),
            "a present key proved itself absent"
        );

        // The nearest possible neighbours inside the ordering domain: the same key
        // with only its lowest bit flipped, and with a high in-domain bit flipped.
        let mut low_bit = key(0x42);
        low_bit[0] ^= 0x01;
        let mut high_bit = key(0x42);
        high_bit[31] ^= 0x10;
        for probe in [low_bit, high_bit, key(0x43)] {
            assert!(
                verifies_absent(&probe, &set.absence_witness(&probe), &root),
                "an absent neighbour failed its absence proof"
            );
        }
    }

    /// Truncation is identity, not similarity: a key differing only above the ordering
    /// domain shares the present key's truncation and honestly cannot prove absence —
    /// the availability cost the module documentation names, priced at 2^-253.
    #[test]
    fn a_truncation_twin_shares_its_fate() {
        let set = set(&[key(0x42)]);
        let mut twin = truncate_key(&key(0x42));
        twin[31] |= 0xe0; // Differs only in the cleared bits.
        assert!(
            !verifies_absent(&twin, &set.absence_witness(&twin), &set.root()),
            "a truncation twin escaped the availability bound"
        );
    }

    #[test]
    fn every_first_time_insertion_moves_the_root_and_repeats_do_not() {
        let mut set = set(&[]);
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

    /// A witness cut before an insertion fails afterwards — staleness and forgery are
    /// the same failure, exactly as for the positional witness.
    #[test]
    fn a_stale_witness_fails_against_the_moved_root() {
        let mut set = set(&[key(0x11)]);
        let stale = set.absence_witness(&key(0x22));
        set.insert(key(0x33));

        assert!(!verifies_absent(&key(0x22), &stale, &set.root()));
        assert!(verifies_absent(
            &key(0x22),
            &set.absence_witness(&key(0x22)),
            &set.root()
        ));
    }

    /// A gap from one side of the set cannot vouch for a key it does not contain,
    /// even under the correct root.
    #[test]
    fn a_real_gap_does_not_cover_a_key_outside_it() {
        let set = set(&[key(0x11), key(0x44)]);
        let root = set.root();
        let wrong_gap = set.absence_witness(&key(0x22));
        assert!(verifies_absent(&key(0x22), &wrong_gap, &root));
        assert!(
            !verifies_absent(&key(0x55), &wrong_gap, &root),
            "a gap vouched for a key beyond its bounds"
        );
    }

    /// The two sets are separate instances, and one's witness says nothing about the
    /// other.
    #[test]
    fn absence_in_one_set_does_not_verify_against_another() {
        let revocations = set(&[key(0x11)]);
        let spends = set(&[key(0x22)]);

        let witness = revocations.absence_witness(&key(0x33));
        assert!(verifies_absent(&key(0x33), &witness, &revocations.root()));
        assert!(!verifies_absent(&key(0x33), &witness, &spends.root()));
    }

    /// A witness must not put a member's neighbourhood in a log. See `Debug` on
    /// `AbsenceWitness`.
    #[test]
    fn debug_redacts_the_gap() {
        let set = set(&[key(0x42)]);
        let rendered = std::format!("{:?}", set.absence_witness(&key(0x41)));
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains("4242"), "a bound leaked: {rendered}");
    }

    /// Keys are served back truncated and in order — the whole-set service members
    /// rebuild from (§11).
    #[test]
    fn keys_enumerate_in_ordering_order() {
        let set = set(&[key(0xff), key(0x01)]);
        let listed: std::vec::Vec<_> = set.keys().collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], truncate_key(&key(0x01)));
        assert_eq!(listed[1], truncate_key(&key(0xff)));
    }
}
