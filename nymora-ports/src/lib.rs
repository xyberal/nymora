// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-ports` — the trait interfaces ("ports") the pure core defines for a host to
//! implement: `KeyStore` and `SecureStorage`.
//!
//! The engine is sans-io: networking and time are **not** ports. Protocol state machines
//! consume events and emit messages, and the host performs the I/O. See
//! `../../ARCHITECTURE.md` for the model, and `../../spec/` for the normative
//! specification.
//!
//! Not yet implemented.

/// Crate scaffold marker. Replaced by the real port traits in later steps.
pub const SCAFFOLD: &str = "nymora-ports";
