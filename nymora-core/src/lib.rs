// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-core` — shared types and domain separation for the Nymora protocol.
//!
//! The protocol layer performs no field arithmetic: every protocol-visible value is an
//! opaque fixed-width byte string, and field elements appear only in `nymora-crypto` and
//! `nymora-circuits`. This crate therefore carries no cryptographic dependencies, and the
//! choice of proving system does not reach it.
//!
//! The crate is `no_std`. That is not portability decoration — it makes the engine's
//! sans-io property structural rather than aspirational, since there is no standard library
//! here through which a file could be opened or a socket dialled. See `../../ARCHITECTURE.md`.
//!
//! Three conventions run through everything below, each defending a property the
//! specification relies on:
//!
//! - **Distinct types over identical bytes.** A [`Nullifier`] cannot be passed where a
//!   [`Commitment`] is expected, and nothing dereferences to its bytes — reaching them
//!   takes an explicit, greppable call.
//! - **Confidential values are redacted in `Debug`.** [`AgoraId`] and [`SecretBytes`] render
//!   as placeholders, so neither can reach a log or crash report by accident.
//! - **Every hash is domain-separated.** See [`Domain`], where the tags are defined once and
//!   their distinctness is enforced by test.
//! - **Errors do not answer questions about hidden state.** See [`ProtocolError`], and the
//!   rule stated in that module for when an error may distinguish cases at all.
//!
//! The normative specification lives in `../../spec/`; section references throughout these
//! docs point into it.

#![no_std]

mod agora;
mod digest;
mod domain;
mod epoch;
mod error;
mod secret;

pub use agora::{AgoraId, CeremonyMode, PublicParameters};
pub use digest::{
    Commitment, LedgerHash, MessageHash, Nullifier, Root, SessionPseudonym, Tag, DIGEST_LEN,
};
pub use domain::Domain;
pub use epoch::Epoch;
pub use error::{LocalReason, ProtocolError, Rejection};
pub use secret::{CredentialKey, EpochSecretKey, RootOpening, SecretBytes, TagKey};

#[cfg(test)]
extern crate std;
