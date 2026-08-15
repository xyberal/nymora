// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two proof statements, as types (§9.1, §6.5, §9.3).
//!
//! # One chain, actions as its final clause
//!
//! §9.1 defines a single membership chain for every ordinary proof, and says only the last
//! line varies by action. These types mirror that literally: [`ChainWitness`] is the fixed
//! witness set, [`Action`] is the varying clause, and a new kind of proof is a new variant
//! rather than a new statement — which is §6.5's uniform-shape requirement made structural.
//! An implementation that modelled five separate proof types could drift into five proof
//! shapes; this one cannot.
//!
//! # Migration is deliberately a second statement
//!
//! [`MigrationWitness`] is different in kind, not detail: no epoch key anywhere, a leaf
//! being consumed rather than used, and a certificate signed by the *old* root over the
//! *new* one. §6.5's uniform-shape requirement targets externally published bundles, and a
//! migration proof travels member-to-Skiora and never further, so §6.5's fingerprinting
//! concern does not reach it — the scope rule §6.5 states (proposals 0001, 0031).
//! Folding it into [`Action`] would force
//! every routine proof to carry migration's structure or the circuit to hide it, for no
//! property in return.
//!
//! # Witnesses borrow; nothing here allocates
//!
//! Every witness type borrows what the caller already holds — secrets stay where their
//! owners put them, and the statement types add no storage of their own. Public-input
//! types own their few fixed-width values.

use nymora_accumulator::{AbsenceWitness, Witness};
use nymora_core::{
    AgoraId, CredentialKey, Epoch, EpochSecretKey, MessageHash, Nullifier, Root, RootOpening,
    SessionContext, SessionPseudonym,
};

/// The witness set of §9.1's membership chain — everything the prover holds privately.
///
/// The leaf itself is deliberately absent: it is recomputed in-statement from `pk_root`,
/// `sk_cred`, `r_root`, and the agora, so a prover cannot present a leaf its secrets do
/// not open. The migration-spend key is likewise derived, not supplied.
///
/// `DEPTH` is the accumulator depth the leaf witness is cut for. It is a const parameter
/// here because the tree structures carry it; the real circuit fixes one value
/// network-wide, since a per-agora depth would be a per-agora proof shape (§6.5,
/// proposal 0030).
pub struct ChainWitness<'a, const DEPTH: usize> {
    /// `sk_epoch` — the acting key (§9.1).
    pub epoch_key: &'a EpochSecretKey,
    /// `pk_epoch` — a **private** witness; publishing it would link same-epoch actions
    /// (§9.1).
    pub epoch_public_key: &'a [u8],
    /// The root signature over the canonical epoch-certificate payload (§9.1).
    pub epoch_cert_signature: &'a [u8],
    /// `sk_cred` — the durable counting key, committed in the leaf (§9.1).
    pub credential_key: &'a CredentialKey,
    /// `r_root` — the commitment opening (§9.1).
    pub root_opening: &'a RootOpening,
    /// `pk_root` — private here even though it is "public" material: revealing which root
    /// key acted would name the leaf.
    pub root_public_key: &'a [u8],
    /// The Merkle path showing the recomputed leaf under the class root (§5.2).
    pub leaf_witness: &'a Witness<DEPTH>,
    /// Non-membership of the leaf in the revocation set (§11).
    pub revocation_absence: &'a AbsenceWitness,
    /// Non-membership of the derived migration nullifier in the spend set (§9.3).
    pub spend_absence: &'a AbsenceWitness,
}

/// The action-specific final clause of §9.1, with its public output.
///
/// Each variant carries what the verifier sees: the context the action binds and, where
/// the action has one, the claimed nullifier or pseudonym the statement checks against
/// the witness-derived value. Verification access carries neither — access is not a count
/// (proposal 0019) — so its clause is pure binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// Authoring content: the nullifier derives from the epoch key over `message_hash`,
    /// so attribution expires with the key (§6.1, §9.1).
    Authorship {
        /// The hash of the content the proof is bound to.
        message_hash: MessageHash,
        /// `Hash(sk_epoch, message_hash, agora_id)`.
        nullifier: Nullifier,
    },
    /// A vouching attestation: one count per credential per session (§5.3).
    Vouch {
        /// The session identifier Skiora issued at `vouch/session/start`.
        session_id: &'a [u8],
        /// `Hash(sk_cred, session_id, agora_id)`.
        nullifier: Nullifier,
    },
    /// A policy approval: one count per credential per proposal (§4.3).
    PolicyApproval {
        /// The identifier under which approvals accumulate.
        proposal_id: &'a [u8],
        /// `Hash(sk_cred, proposal_id, agora_id)`.
        nullifier: Nullifier,
    },
    /// A live-authentication presence proof: a pseudonym, not a nullifier (§8.1).
    LiveAuth {
        /// The jointly-derived session context.
        context: SessionContext,
        /// `Hash(sk_epoch, context_id, agora_id)` (proposal 0018).
        pseudonym: SessionPseudonym,
    },
    /// Verification access (§7): binds a Skiora-issued single-use challenge and derives
    /// nothing (proposal 0019).
    VerificationAccess {
        /// The challenge this proof is bound to. Opaque bytes; single-use is the
        /// issuer's bookkeeping.
        challenge: &'a [u8],
    },
}

/// The public inputs of an ordinary proof (§9.1, §6.5).
///
/// A verifier accepts a routine proof only against the current epoch's three roots; the
/// epoch also fixes the certificate payload the statement reconstructs. The agora is
/// resolved out-of-band (§6.4) and never travels labeled in a bundle (§6.6) — it is a
/// public *input*, not a transmitted field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPublicInputs<'a> {
    /// The agora the proof is scoped to.
    pub agora: AgoraId,
    /// The current epoch — the one the certificate must name.
    pub epoch: Epoch,
    /// `Root_{policy_class}`: the accumulator root the leaf must sit under (§5.2, §6.5).
    pub class_root: Root,
    /// The revocation set's root at this epoch (§11).
    pub revocation_root: Root,
    /// The migration-spend set's root at this epoch (§9.3).
    pub spend_root: Root,
    /// The action's final clause, with its public output.
    pub action: Action<'a>,
}

/// The witness set of the migration statement (§9.3).
///
/// No epoch key appears: migration is authorized by the root, not by routine standing,
/// and a member whose epoch key is long destroyed can still migrate. The old leaf and the
/// spend nullifier are recomputed in-statement, and the successor's public key stays a
/// witness — the certificate is verified inside the proof precisely so `pk_root`, old or
/// new, is never presented in the clear (§9.3).
pub struct MigrationWitness<'a, const DEPTH: usize> {
    /// The old credential's `pk_root`, committed in the leaf being consumed.
    pub old_root_public_key: &'a [u8],
    /// The old credential's `r_root`.
    pub old_root_opening: &'a RootOpening,
    /// `sk_cred` — carried across the lineage, so one key opens the old leaf and the
    /// successor commitment alike (§9.3).
    pub credential_key: &'a CredentialKey,
    /// The Merkle path showing the old leaf under the class root.
    pub old_leaf_witness: &'a Witness<DEPTH>,
    /// The old root's signature over the canonical migration-certificate payload.
    pub migration_cert_signature: &'a [u8],
    /// The successor's `pk_root` — the value the certificate signs over.
    pub successor_public_key: &'a [u8],
    /// The successor's fresh `r_root`.
    pub successor_opening: &'a RootOpening,
    /// Non-membership of the **old leaf** in the revocation set: a revoked credential
    /// cannot migrate out from under its revocation (§11). In-statement because the leaf
    /// is hidden; the spend set needs no clause here, since the spend nullifier is this
    /// proof's public output and the verifier checks its own set directly.
    pub revocation_absence: &'a AbsenceWitness,
}

/// The public inputs of a migration proof (§9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationPublicInputs {
    /// The agora the migration happens within — migration never crosses one (§16.3).
    pub agora: AgoraId,
    /// The accumulator root the old leaf must sit under.
    pub class_root: Root,
    /// The revocation set's root.
    pub revocation_root: Root,
    /// `Hash(sk_cred, leaf_old, agora_id)` — the spend consuming the old leaf, checked
    /// against and then entered into the spend set by the verifier (§9.3).
    pub spend_nullifier: Nullifier,
    /// `Commit(pk_root_new, sk_cred, r_root_new, agora_id)` — the successor leaf, proven
    /// to commit the same `sk_cred` the old leaf held (§9.3).
    pub successor_commitment: nymora_core::Commitment,
}
