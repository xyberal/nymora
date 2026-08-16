// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain separation for every Poseidon derivation the statements compute.
//!
//! Each derivation's first absorbed element is a distinct tag, so no value computed
//! under one clause can be replayed as a value of another. These constants are the
//! first concrete form of proposal 0034's open question 1 (the canonical encodings);
//! they harden into conformance-vector facts when the vectors regenerate with the
//! real-circuit swap, and must not change after that.
//!
//! Two derivations deliberately carry no tag, because their shapes already separate
//! them: the Merkle 2-to-1 node compression (arity 2, and both §5.2 trees and the
//! exclusion trees compress identically — a node is a node), and the certificate
//! challenge `e = Poseidon(R.x, R.y, PK.x, PK.y, m)`, whose five-element shape is
//! pinned as an equation in §9.1 and which no other five-element derivation can
//! collide with without producing a specific curve point's coordinate as a constant.

use crate::F;

/// The credential leaf commitment: `Poseidon(LEAF, pk_root.x, pk_root.y, sk_cred, r_root, agora)`.
pub const LEAF: u64 = 1;

/// An exclusion-set gap leaf: `Poseidon(GAP, low, high)` (§9.1's currency clauses).
pub const GAP: u64 = 2;

/// The action derivation: `Poseidon(ACTION, tag, key, context, agora)` — the tag
/// inside the hash is what makes one action's output unreplayable as another's.
pub const ACTION: u64 = 3;

/// The epoch-certificate payload: `Poseidon(EPOCH_CERT, agora, epoch, pk_epoch.x, pk_epoch.y)`.
pub const EPOCH_CERT: u64 = 4;

/// The migration-certificate payload: `Poseidon(MIGRATION_CERT, agora, succ.x, succ.y)`.
pub const MIGRATION_CERT: u64 = 5;

/// The migration-spend nullifier: `Poseidon(SPEND, sk_cred, leaf, agora)` (§9.3).
pub const SPEND: u64 = 6;

/// The deterministic signature nonce: `Poseidon(NONCE, sk, m)` — signer-side only,
/// never inside the circuit (§9.1's deterministic-nonce obligation).
pub const NONCE: u64 = 7;

/// The action tags, one per §9.1 final clause. The numbering is part of the
/// statement: the tag is a public input and an absorbed hash element.
pub mod action_tag {
    /// Authorship: derives from `sk_epoch` over the message hash (§6.1).
    pub const AUTHORSHIP: u64 = 0;
    /// Vouching: derives from `sk_cred` over the session id (§5.3).
    pub const VOUCH: u64 = 1;
    /// Policy approval: derives from `sk_cred` over the proposal id (§4.3).
    pub const POLICY: u64 = 2;
    /// Live authentication: derives from `sk_epoch` over the session context (§8.1).
    pub const LIVE_AUTH: u64 = 3;
    /// Verification access: binds the challenge, derives nothing (proposal 0019).
    pub const VERIFICATION: u64 = 4;
}

/// A domain tag as a field element.
pub fn tag(value: u64) -> F {
    F::from(value)
}
