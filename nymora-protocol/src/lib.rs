// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-protocol` — the protocol as code, for both roles.
//!
//! This crate is where sequencing lives: operations that touch several primitives and both
//! ports — or several parties — in an order that carries security properties. For the
//! member that is the credential lifecycle of §9.1–§9.3 ([`credential`]), the
//! witness-assembly path into the proof statements ([`proving`]), and the live-auth
//! commit-reveal machine ([`live_auth`]); shared between the roles, the quorum-decision
//! subjects ([`decision`]); and for the operator — behind the `operator` feature — the
//! whole server side of §4–§12 ([`operator`]): vouch sessions, quorum decisions,
//! verification access, migration acceptance, revocation, dissolution, and the
//! transparency log.
//!
//! Like everything in the engine it is sans-io and `no_std`: time arrives as [`Epoch`]
//! parameters, randomness as [`FreshEntropy`] parameters, and platform behaviour through
//! the two ports of `nymora-ports`. The operator role additionally needs an allocator for
//! its collections; the member side deliberately does not. See `../../ARCHITECTURE.md`
//! for why this crate drives the ports rather than instructing a host to.
//!
//! [`Epoch`]: nymora_core::Epoch

#![no_std]

#[cfg(feature = "provisional-signature")]
pub mod bulletin;
pub mod credential;
pub mod decision;
pub mod live_auth;
#[cfg(feature = "operator")]
pub mod operator;
pub mod proving;

#[cfg(feature = "provisional-signature")]
pub use bulletin::{accept_bulletin, bulletin_equivocation, BulletinStatement, EmbeddedHead};
pub use credential::{
    authorize_migration, create_successor_root, discard_expired, load_epoch_record, roll_epoch,
    store_tag_key, EpochRecord, FreshEntropy, MAX_EPOCH_GAP,
};
#[cfg(feature = "provisional-algebraic-hash")]
pub use credential::{complete_migration, create, Created, Migrated};
pub use decision::{subject_id, Decision, SubjectId};
pub use proving::{load_acting_material, ActingMaterial};

#[cfg(feature = "operator")]
extern crate alloc;

#[cfg(test)]
extern crate std;
