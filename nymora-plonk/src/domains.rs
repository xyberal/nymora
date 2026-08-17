// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain separation for every Poseidon derivation the statements compute.
//!
//! The constants are the protocol's field-domain registry, defined once in
//! `nymora-core` (proposal 0035) and re-exported here — the circuits and the
//! workspace primitives absorb literally the same values, so the two cannot drift.
//!
//! Two derivations deliberately carry no tag, because their shapes already separate
//! them: the Merkle 2-to-1 node compression (arity 2, and both §5.2 trees and the
//! exclusion trees compress identically — a node is a node), and the certificate
//! challenge `e = Poseidon(R.x, R.y, PK.x, PK.y, m)`, whose five-element shape is
//! pinned as an equation in §9.1 and which no other five-element derivation can
//! collide with without producing a specific curve point's coordinate as a constant.

pub use nymora_core::field_domain::{
    action_tag, ACTION, EPOCH_CERT, GAP, LEAF, MIGRATION_CERT, NONCE, SPEND,
};

use crate::F;

/// A domain tag as a field element.
pub fn tag(value: u64) -> F {
    F::from(value)
}
