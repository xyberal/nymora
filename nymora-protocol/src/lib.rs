// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-protocol` — the protocol as code, for both roles.
//!
//! This crate is where sequencing lives: operations that touch several primitives and both
//! ports in an order that carries security properties. Today that is the credential
//! lifecycle of §9.1–§9.3 ([`credential`]); the transport-agnostic state machines and
//! message contracts — vouching, admission, revocation, dissolution, live authentication —
//! arrive in a later phase, and wait on the proof interfaces.
//!
//! Like everything in the engine it is sans-io and `no_std`: time arrives as [`Epoch`]
//! parameters, randomness as [`FreshEntropy`] parameters, and platform behaviour through
//! the two ports of `nymora-ports`. See `../../ARCHITECTURE.md` for why this crate drives
//! the ports rather than instructing a host to.
//!
//! [`Epoch`]: nymora_core::Epoch

#![no_std]

pub mod credential;

#[cfg(feature = "provisional-algebraic-hash")]
pub use credential::{authorize_migration, complete_migration, create, Created, Migrated};
pub use credential::{
    create_successor_root, discard_expired, load_epoch_record, roll_epoch, store_tag_key,
    EpochRecord, FreshEntropy, MAX_EPOCH_GAP,
};

#[cfg(test)]
extern crate std;
