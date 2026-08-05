// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-accumulator` — the fixed-depth Merkle accumulator of §5.2.
//!
//! # It verifies paths; it does not hold trees
//!
//! A fixed-depth accumulator over a realistic member space cannot sit in memory, and this
//! workspace is `no_std` with no allocator. The crate therefore splits where the roles already
//! do: a member holds one value and the `DEPTH` sibling hashes on its path, while an operator
//! holds the whole tree.
//!
//! Path verification is what every role performs and what a circuit will later recompute, so it
//! is the crate's core and allocates nothing. Tree construction is a separate, larger concern
//! and is not here yet.
//!
//! # Nothing reports how full it is
//!
//! §5.2 is unqualified: *"No API surface exposes accumulator size, leaf count, or leaf listing,
//! at any point."* §5.4 rules out decoy padding, so occupancy is information about real members
//! rather than about a configuration constant.
//!
//! There is accordingly no `len`, no `is_empty`, no capacity, and no iterator. `DEPTH` is public
//! — it is a published property of the agora — but how much of it is used is not, and the
//! easiest way to leak it is not an accessor but an *error*: a construction routine reporting
//! that a position is already occupied would be a membership oracle. Nothing here distinguishes
//! occupied from empty.
//!
//! # Generic over what it holds
//!
//! Leaves are opaque [`Commitment`](nymora_core::Commitment) values that this crate hashes and
//! never interprets. §5.2 already needs one instance per policy class and §11 keeps a separate
//! revocation set, so specialising to credentials would mean writing this more than once.

#![no_std]

#[cfg(feature = "provisional-algebraic-hash")]
pub mod witness;

#[cfg(feature = "provisional-algebraic-hash")]
pub use witness::{hash_leaf, hash_node, root_from, verifies, Node, Witness};

#[cfg(test)]
extern crate std;
