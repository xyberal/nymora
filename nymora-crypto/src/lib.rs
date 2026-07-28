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

#![no_std]

pub mod hash;
pub mod kdf;

pub use hash::{ByteHasher, HashBackend, Hasher, Sha256Backend};
pub use kdf::derive;

#[cfg(test)]
extern crate std;
