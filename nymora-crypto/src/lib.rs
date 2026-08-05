// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-crypto` — cryptographic primitives for the Nymora protocol.
//!
//! # Two hash families, both permanent
//!
//! It is tempting to treat a conventional hash here as a placeholder until a
//! zero-knowledge-friendly one is chosen. That is the wrong model: the design needs both,
//! indefinitely, and they answer to different constraints.
//!
//! - **The byte family** — used wherever a value never enters a circuit. Routing tags are
//!   specified as an HMAC (§6.4); receipt-ledger chaining is client-side (§10.2); the
//!   short authentication string is read aloud by people (§8.3). None of these is
//!   constrained by a proving system, so the choice can be made now, and is: **SHA-256**,
//!   which is hardware-accelerated on the arm64 devices Persora targets.
//! - **The algebraic family** — used for values a circuit must recompute: nullifiers,
//!   accumulator nodes, commitments. Its cost is measured in constraints rather than
//!   cycles, and the right choice depends on the proving system, which is deliberately not
//!   yet decided. It arrives with the circuit.
//!
//! Both inherit the framing and domain separation in [`Hasher`] (use the [`ByteHasher`]
//! alias for the byte family), so that a value produced
//! in one context can never be reinterpreted as a value produced in another, and so that
//! two implementations cannot disagree about where one absorbed field ends and the next
//! begins.
//!
//! Until the proving system is chosen, the algebraic family is a documented stand-in behind
//! the `provisional-algebraic-hash` feature, on by default; see [`algebraic`] for what that
//! means and what it would cost to ship. Building with `--no-default-features` removes the
//! stand-in and everything derived through it — [`commit`] and [`nullifier`] — leaving only
//! the constructions that are settled.

#![no_std]

pub mod agora_id;
#[cfg(feature = "provisional-algebraic-hash")]
pub mod algebraic;
#[cfg(feature = "provisional-algebraic-hash")]
pub mod commit;
pub mod hash;
pub mod kdf;
#[cfg(feature = "provisional-algebraic-hash")]
pub mod nullifier;
pub mod tag;

#[cfg(feature = "provisional-algebraic-hash")]
pub use algebraic::{AlgebraicHasher, ProvisionalAlgebraicBackend};
#[cfg(feature = "provisional-algebraic-hash")]
pub use commit::commit;
pub use hash::{ByteHasher, HashBackend, Hasher, Sha256Backend};
pub use tag::{derive_tag_key, resolve, tag};

// `kdf::derive` and `agora_id::derive` are deliberately not re-exported here. Two functions
// named `derive` at the crate root would be ambiguous at a glance in exactly the place
// ambiguity is most expensive — one produces key material, the other a permanent public
// identifier. Reach them through their modules.

#[cfg(test)]
extern crate std;
