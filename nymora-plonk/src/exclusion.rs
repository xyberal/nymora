// SPDX-License-Identifier: MIT OR Apache-2.0

//! The exclusion accumulators (§9.1's currency clauses, §9.3, §11), in the concrete
//! structure proposal 0034 deferred to the real circuit: a **gap tree**.
//!
//! # The structure
//!
//! The set's keys are truncated into a 253-bit ordering domain
//! ([`crate::primitives::KEY_BITS`]) and sorted; every *gap* between consecutive keys
//! — with sentinels `0` below and `2^253 - 1` above — becomes a leaf
//! `Poseidon(GAP, low, high)` in a Merkle tree over the same 2-to-1 compression as
//! §5.2's accumulators. Absence of a key `k` is then a *positive* statement: some gap
//! `(low, high)` with `low < t(k) < high` sits under the root. In-circuit that costs
//! one inclusion path and two bounded comparisons, which is what makes the currency
//! clauses affordable inside the statement.
//!
//! # Why truncation is safe
//!
//! The in-circuit comparison is sound only below `F::NUM_BITS - 2` bits, so ordering
//! runs over low-253-bit truncations. A truncation collision between two distinct
//! keys can only cost **availability** — a key whose truncation equals a present
//! key's cannot prove absence — never soundness: a present key's own truncation is
//! exactly what the set holds, so no witness places it strictly inside a gap. At
//! 2^-253 per pair, the availability risk is ignorable.
//!
//! # Totality
//!
//! [`GapSet::absence_witness`] is total, like the provisional accumulator's: asking
//! for a witness of a *present* key returns the gap that starts at that key, whose
//! `low < t` clause is false — a witness that honestly fails, rather than an error
//! path that leaks presence at a different API surface.
//!
//! Rebuilt per epoch by the operator, exactly as the boundary broadcast already
//! assumes (§11); membership never mutates mid-epoch.

use ff::{Field, PrimeField};

use crate::{
    domains,
    primitives::{poseidon, truncate_key, KEY_BITS},
    tree::{Path, Tree},
    F,
};

/// The upper sentinel: `2^KEY_BITS - 1`, the greatest value of the ordering domain.
pub fn upper_sentinel() -> F {
    let mut le = [0u8; 32];
    for bit in 0..KEY_BITS {
        le[(bit / 8) as usize] |= 1u8 << (bit % 8);
    }
    F::from_repr(le).expect("a 253-bit value is canonical")
}

/// An absence witness: the gap claimed to contain the key, and its inclusion path.
#[derive(Clone, Debug)]
pub struct AbsenceWitness<const DEPTH: usize> {
    /// The gap's lower bound (a present truncated key, or the `0` sentinel).
    pub low: F,
    /// The gap's upper bound (the next present truncated key, or the upper sentinel).
    pub high: F,
    /// The gap leaf's authentication path.
    pub path: Path<DEPTH>,
}

impl<const DEPTH: usize> Default for AbsenceWitness<DEPTH> {
    fn default() -> Self {
        AbsenceWitness {
            low: F::ZERO,
            high: F::ZERO,
            path: Path::default(),
        }
    }
}

/// The gap leaf a bound pair hashes to.
pub fn gap_leaf(low: F, high: F) -> F {
    poseidon(&[domains::tag(domains::GAP), low, high])
}

/// Whether `witness` proves `key` absent under `root` — the CPU twin of the
/// in-circuit absence clause, clause for clause.
pub fn verifies_absent<const DEPTH: usize>(
    key: F,
    witness: &AbsenceWitness<DEPTH>,
    root: &F,
) -> bool {
    let t = truncate_key(key);
    le_cmp(&witness.low, &t) == core::cmp::Ordering::Less
        && le_cmp(&t, &witness.high) == core::cmp::Ordering::Less
        && witness.path.root(gap_leaf(witness.low, witness.high)) == *root
}

/// A keyed exclusion set over the gap-tree structure.
#[derive(Clone, Debug, Default)]
pub struct GapSet {
    /// The present keys, truncated into the ordering domain, kept sorted.
    keys: Vec<F>,
}

/// Orders field elements by their canonical little-endian integer value.
fn le_cmp(a: &F, b: &F) -> core::cmp::Ordering {
    let (a, b) = (a.to_repr(), b.to_repr());
    a.as_ref().iter().rev().cmp(b.as_ref().iter().rev())
}

impl GapSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a key (truncating it into the ordering domain). Idempotent.
    pub fn insert(&mut self, key: F) {
        let t = truncate_key(key);
        if let Err(position) = self.keys.binary_search_by(|k| le_cmp(k, &t)) {
            self.keys.insert(position, t);
        }
    }

    /// The gaps between consecutive present keys, sentinels included.
    fn gaps(&self) -> Vec<(F, F)> {
        let mut bounds = Vec::with_capacity(self.keys.len() + 2);
        bounds.push(F::ZERO);
        bounds.extend(self.keys.iter().copied());
        bounds.push(upper_sentinel());
        bounds.windows(2).map(|w| (w[0], w[1])).collect()
    }

    /// The gap tree at depth `DEPTH`, rebuilt from the current keys.
    fn tree<const DEPTH: usize>(&self) -> Tree<DEPTH> {
        let mut tree = Tree::new();
        for (low, high) in self.gaps() {
            tree.append(gap_leaf(low, high))
                .expect("the gap count is far below 2^DEPTH");
        }
        tree
    }

    /// The current root at depth `DEPTH`.
    pub fn root<const DEPTH: usize>(&self) -> F {
        self.tree::<DEPTH>().root()
    }

    /// The absence witness for `key` — total: a present key receives the witness
    /// whose `low < t` clause is honestly false (module documentation).
    pub fn absence_witness<const DEPTH: usize>(&self, key: F) -> AbsenceWitness<DEPTH> {
        let t = truncate_key(key);
        let gaps = self.gaps();
        // The gap whose bounds should contain t: the last with low < t, or, for a
        // present key, the gap that starts at t (which then fails low < t).
        let position = gaps
            .iter()
            .position(|(low, high)| {
                le_cmp(low, &t) != core::cmp::Ordering::Greater
                    && le_cmp(&t, high) == core::cmp::Ordering::Less
            })
            .unwrap_or(0);
        let (low, high) = gaps[position];
        let path = self
            .tree::<DEPTH>()
            .witness(position)
            .expect("every gap was appended");
        AbsenceWitness { low, high, path }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::verifies_absent as verifies;

    #[test]
    fn an_absent_key_verifies_and_a_present_key_fails() {
        let mut set = GapSet::new();
        set.insert(F::from(100));
        set.insert(F::from(200));
        let root = set.root::<8>();

        let absent = F::from(150);
        assert!(verifies(absent, &set.absence_witness::<8>(absent), &root));

        let present = F::from(200);
        assert!(!verifies(
            present,
            &set.absence_witness::<8>(present),
            &root
        ));
    }

    #[test]
    fn the_empty_set_proves_everything_absent() {
        let set = GapSet::new();
        let root = set.root::<8>();
        let key = F::from(7);
        assert!(verifies(key, &set.absence_witness::<8>(key), &root));
    }

    #[test]
    fn insertion_changes_the_root_and_is_idempotent() {
        let mut set = GapSet::new();
        let before = set.root::<8>();
        set.insert(F::from(9));
        let after = set.root::<8>();
        assert_ne!(before, after);
        set.insert(F::from(9));
        assert_eq!(after, set.root::<8>());
    }
}
