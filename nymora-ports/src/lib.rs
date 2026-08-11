// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-ports` — the trait interfaces ("ports") the pure core defines for a host to
//! implement: [`KeyStore`] and [`SecureStorage`].
//!
//! # Two ports, and why not four
//!
//! The engine is sans-io. Networking is not a port — protocol state machines consume events and
//! emit messages, and the host performs the I/O — and time is not a port either: [`Epoch`] is
//! passed in as a parameter rather than read from a clock trait. What remains is the material a
//! host holds on the engine's behalf, which is these two.
//!
//! No `async` appears anywhere in `nymora`, so embedding it imposes no runtime. See
//! `../../ARCHITECTURE.md` for the model, and `../../spec/` for the normative specification.
//!
//! [`Epoch`]: nymora_core::Epoch
//!
//! # Opaque material crosses as bytes, into caller buffers
//!
//! Public keys, signatures, and bindings are sized by a signature scheme this workspace has not
//! chosen, and their contents are never parsed above the port. They are therefore plain byte
//! slices written into buffers the caller supplies, with the written length returned — the same
//! convention `nymora-core`'s wire format uses, and the reason this crate needs no allocator.
//!
//! Fixing a maximum size here instead would have committed to a scheme by implication, in a
//! type that is awkward to change once a host has built against it.
//!
//! # What a host must not do
//!
//! Both ports carry requirements no signature can express, stated in their module
//! documentation. The two easiest to violate without noticing:
//!
//! - **Every root signature must cover exactly the canonical certificate payload**
//!   ([`key_store`]) — the encoding from `nymora-core` carries the agora and the certificate
//!   kind inside the signed message, so agora replay (§16.1) and cross-kind confusion are
//!   closed by construction, but only for a backend that signs those bytes and nothing else.
//! - **An `agora_id` must not become a visible storage label** ([`storage`]), or the store
//!   discloses the existence of agoras that §3 keeps confidential.
//!
//! # The reference backend
//!
//! [`software`] provides a `KeyStore` for development and tests, behind the default-off
//! `software-key-store` feature. It is not production custody and reports no capability at all,
//! so a caller written against it handles the weakest backend from the first day rather than
//! discovering the variance when hardware arrives.

#![no_std]

pub mod key_store;
#[cfg(feature = "software-key-store")]
pub mod software;
pub mod storage;

pub use key_store::{
    Capabilities, EpochCertPayload, KeyStore, MigrationCertPayload, RootMaterialOut,
    RootMaterialWritten,
};
#[cfg(feature = "software-key-store")]
pub use software::SoftwareKeyStore;
pub use storage::{SecureStorage, Slot};

#[cfg(test)]
extern crate std;
