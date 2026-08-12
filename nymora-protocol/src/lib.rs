// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-protocol` — the protocol as code, for both roles.
//!
//! This crate is where sequencing lives: operations that touch several primitives and both
//! ports in an order that carries security properties. Today that is the credential
//! lifecycle of §9.1–§9.3 ([`credential`]) and the witness-assembly path from stored
//! material into the proof statements ([`proving`]); the transport-agnostic state machines
//! and message contracts — vouching, admission, revocation, dissolution, live
//! authentication — arrive in a later phase, on top of both.
//!
//! Like everything in the engine it is sans-io and `no_std`: time arrives as [`Epoch`]
//! parameters, randomness as [`FreshEntropy`] parameters, and platform behaviour through
//! the two ports of `nymora-ports`. See `../../ARCHITECTURE.md` for why this crate drives
//! the ports rather than instructing a host to.
//!
//! [`Epoch`]: nymora_core::Epoch

#![no_std]

pub mod credential;
pub mod proving;

pub use credential::{
    authorize_migration, create_successor_root, discard_expired, load_epoch_record, roll_epoch,
    store_tag_key, EpochRecord, FreshEntropy, MAX_EPOCH_GAP,
};
#[cfg(feature = "provisional-algebraic-hash")]
pub use credential::{complete_migration, create, Created, Migrated};
pub use proving::{load_acting_material, ActingMaterial};

#[cfg(test)]
extern crate std;
