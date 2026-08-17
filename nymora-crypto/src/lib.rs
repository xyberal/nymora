// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-crypto` — cryptographic primitives for the Nymora protocol.
//!
//! # Two hash families, both permanent
//!
//! The design needs both, indefinitely, and they answer to different constraints:
//!
//! - **The byte family** — used wherever a value never enters a circuit. Routing tags are
//!   specified as an HMAC (§6.4); receipt-ledger chaining is client-side (§10.2); the
//!   short authentication string is read aloud by people (§8.3). None of these is
//!   constrained by a proving system: **SHA-256**, hardware-accelerated on the arm64
//!   devices Persora targets, with the framing and domain separation of [`Hasher`].
//! - **The algebraic family** — used for values a circuit must recompute: nullifiers,
//!   accumulator nodes, commitments, certificate messages. This is **Poseidon over the
//!   BLS12-381 scalar field** in the pinned instance of §6.5 (proposals 0033, 0034),
//!   implemented in [`poseidon`] as the circuit's CPU twin. Its domains are one absorbed
//!   field element from the registry in `nymora-core`, its inputs are field elements,
//!   and framing has no meaning there — arity is identity.
//!
//! The two families meet in exactly one place: [`field`], the crossing where protocol
//! bytes become field elements under proposal 0035's rules. Variable-length identifiers
//! are compressed by the byte family *before* they cross, which is how the byte family's
//! framing guarantee protects derivations the circuit computes.
//!
//! The certificate scheme sits with the algebraic family for the same reason it exists
//! at all — both certificates are verified inside the circuit (§9.1, §9.3) — and is
//! EdDSA over Jubjub with a Poseidon transcript, stated as an equation in §9.1 and
//! implemented in [`signature`].

#![no_std]

pub mod agora_id;
pub mod commit;
pub mod field;
pub mod hash;
pub mod kdf;
pub mod live_auth;
pub mod nullifier;
pub mod policy_class;
pub mod poseidon;
pub mod signature;
pub mod tag;
pub mod witness_key;

pub use commit::commit;
pub use field::F;
pub use hash::{ByteHasher, HashBackend, Hasher, Sha256Backend};
pub use tag::{derive_tag_key, resolve, tag};
pub use witness_key::derive_witness_key;

// `kdf::derive`, `agora_id::derive`, and `policy_class::derive` are deliberately not
// re-exported here. Three functions named `derive` at the crate root would be ambiguous at a
// glance in exactly the place ambiguity is most expensive — one produces key material, the
// others permanent identifiers. Reach them through their modules.

#[cfg(test)]
extern crate std;
