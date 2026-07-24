// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-ports` — the trait interfaces ("ports") the pure core defines for a host to
//! implement: `KeyStore` / `Authenticator`, `SecureStorage`, `Transport`, `EpochClock`.
//! See `../../ARCHITECTURE.md` for the pure-engine-plus-ports model, and `../../spec/`
//! for the normative protocol specification.
//!
//! Scaffold established in Step 1 (see `../SETUP.md`). No ports defined yet.

/// Crate scaffold marker. Replaced by the real port traits in later steps.
pub const SCAFFOLD: &str = "nymora-ports";
