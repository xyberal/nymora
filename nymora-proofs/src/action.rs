// SPDX-License-Identifier: MIT OR Apache-2.0

//! The action entry points. See the crate documentation for why these exist above
//! [`ProofSystem`].

use nymora_circuits::{
    Action, ChainPublicInputs, ChainWitness, MigrationPublicInputs, MigrationWitness, ProofSystem,
};
use nymora_core::{
    AgoraId, Commitment, Epoch, MessageHash, Nullifier, ProtocolError, Root, SessionContext,
    SessionPseudonym,
};
use nymora_crypto::{commit, live_auth, nullifier};

/// The current epoch's three roots, together (§9.1).
///
/// One value rather than three parameters, so a call site cannot mix roots from two
/// epochs without it being visible at the point the value was assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRoots {
    /// `Root_{policy_class}` — the accumulator root the proof is cut against (§5.2, §6.5).
    pub class: Root,
    /// The revocation set's root (§11).
    pub revocation: Root,
    /// The migration-spend set's root (§9.3).
    pub spend: Root,
}

fn chain_publics<'a>(
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    action: Action<'a>,
) -> ChainPublicInputs<'a> {
    ChainPublicInputs {
        agora,
        epoch,
        class_root: roots.class,
        revocation_root: roots.revocation,
        spend_root: roots.spend,
        action,
    }
}

/// Proves authorship of `message_hash` (§6.1), returning the proof and the nullifier the
/// bundle carries alongside it (§6.6).
///
/// The nullifier is derived here, from the witness — `Hash(sk_epoch, message_hash,
/// agora_id)` — never supplied.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] when the witness does not satisfy the chain against these
/// inputs — a destroyed epoch key's material, a stale root, a revoked or spent leaf.
pub fn prove_authorship<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    witness: &ChainWitness<'_, DEPTH>,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    message_hash: MessageHash,
) -> Result<(S::Proof, Nullifier), ProtocolError> {
    let derived = nullifier::attestation(witness.epoch_key, &message_hash, &agora);
    let public = chain_publics(
        agora,
        epoch,
        roots,
        Action::Authorship {
            message_hash,
            nullifier: derived,
        },
    );
    Ok((system.prove(witness, &public)?, derived))
}

/// Whether `proof` establishes authorship of `message_hash` under these roots, with
/// exactly the claimed nullifier (§6.5, §7).
pub fn verify_authorship<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    proof: &S::Proof,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    message_hash: MessageHash,
    claimed: Nullifier,
) -> bool {
    system.verify(
        proof,
        &chain_publics(
            agora,
            epoch,
            roots,
            Action::Authorship {
                message_hash,
                nullifier: claimed,
            },
        ),
    )
}

/// Proves one vouching attestation into `session_id` (§5.3), returning the proof and the
/// nullifier the session counts.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] as for [`prove_authorship`].
pub fn prove_vouch<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    witness: &ChainWitness<'_, DEPTH>,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    session_id: &[u8],
) -> Result<(S::Proof, Nullifier), ProtocolError> {
    let derived = nullifier::vouch(witness.credential_key, session_id, &agora);
    let public = chain_publics(
        agora,
        epoch,
        roots,
        Action::Vouch {
            session_id,
            nullifier: derived,
        },
    );
    Ok((system.prove(witness, &public)?, derived))
}

/// Whether `proof` establishes one vouching attestation into `session_id` with exactly
/// the claimed nullifier (§5.3).
pub fn verify_vouch<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    proof: &S::Proof,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    session_id: &[u8],
    claimed: Nullifier,
) -> bool {
    system.verify(
        proof,
        &chain_publics(
            agora,
            epoch,
            roots,
            Action::Vouch {
                session_id,
                nullifier: claimed,
            },
        ),
    )
}

/// Proves one approval of `proposal_id` (§4.3), returning the proof and the nullifier the
/// quorum counts.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] as for [`prove_authorship`].
pub fn prove_policy_approval<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    witness: &ChainWitness<'_, DEPTH>,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    proposal_id: &[u8],
) -> Result<(S::Proof, Nullifier), ProtocolError> {
    let derived = nullifier::policy(witness.credential_key, proposal_id, &agora);
    let public = chain_publics(
        agora,
        epoch,
        roots,
        Action::PolicyApproval {
            proposal_id,
            nullifier: derived,
        },
    );
    Ok((system.prove(witness, &public)?, derived))
}

/// Whether `proof` establishes one approval of `proposal_id` with exactly the claimed
/// nullifier (§4.3).
pub fn verify_policy_approval<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    proof: &S::Proof,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    proposal_id: &[u8],
    claimed: Nullifier,
) -> bool {
    system.verify(
        proof,
        &chain_publics(
            agora,
            epoch,
            roots,
            Action::PolicyApproval {
                proposal_id,
                nullifier: claimed,
            },
        ),
    )
}

/// Proves presence in the live session `context` (§8.1), returning the proof and the
/// pseudonym every peer checks it against.
///
/// The pseudonym is `Hash(sk_epoch, context_id, agora_id)` (proposal 0018), derived here.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] as for [`prove_authorship`].
pub fn prove_live_auth<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    witness: &ChainWitness<'_, DEPTH>,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    context: SessionContext,
) -> Result<(S::Proof, SessionPseudonym), ProtocolError> {
    let derived = live_auth::pseudonym(witness.epoch_key, &context, &agora);
    let public = chain_publics(
        agora,
        epoch,
        roots,
        Action::LiveAuth {
            context,
            pseudonym: derived,
        },
    );
    Ok((system.prove(witness, &public)?, derived))
}

/// Whether `proof` establishes presence in `context` under exactly the claimed pseudonym
/// (§8.1).
pub fn verify_live_auth<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    proof: &S::Proof,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    context: SessionContext,
    claimed: SessionPseudonym,
) -> bool {
    system.verify(
        proof,
        &chain_publics(
            agora,
            epoch,
            roots,
            Action::LiveAuth {
                context,
                pseudonym: claimed,
            },
        ),
    )
}

/// Proves current standing for verification access, bound to a Skiora-issued single-use
/// `challenge` (§7, proposal 0019). No nullifier — access is not a count.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] as for [`prove_authorship`].
pub fn prove_verification_access<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    witness: &ChainWitness<'_, DEPTH>,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    challenge: &[u8],
) -> Result<S::Proof, ProtocolError> {
    system.prove(
        witness,
        &chain_publics(
            agora,
            epoch,
            roots,
            Action::VerificationAccess { challenge },
        ),
    )
}

/// Whether `proof` establishes current standing bound to exactly this challenge (§7).
///
/// Single-use bookkeeping for the challenge is the issuer's; this checks only the
/// binding.
pub fn verify_verification_access<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    proof: &S::Proof,
    agora: AgoraId,
    epoch: Epoch,
    roots: &EpochRoots,
    challenge: &[u8],
) -> bool {
    system.verify(
        proof,
        &chain_publics(
            agora,
            epoch,
            roots,
            Action::VerificationAccess { challenge },
        ),
    )
}

/// Proves a planned migration (§9.3): the old leaf is current, the old root authorized
/// exactly this successor, and the successor commitment carries the same `sk_cred`.
/// Returns the proof and the spend nullifier consuming the old leaf.
///
/// The spend set has no root here: the spend nullifier is this proof's public output, and
/// the verifier checks its own set directly (§9.3). The successor commitment is a public
/// input — it is what `credentials/migrate` submits.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] when the witness does not satisfy the migration statement
/// against these inputs — including a successor commitment built over any key but the
/// carried `sk_cred`.
pub fn prove_migration<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    witness: &MigrationWitness<'_, DEPTH>,
    agora: AgoraId,
    class_root: Root,
    revocation_root: Root,
    successor_commitment: Commitment,
) -> Result<(S::MigrationProof, Nullifier), ProtocolError> {
    // A root key that names no subgroup point commits to nothing — the caller's own
    // material is unusable, which is the same refusal an unsatisfiable witness gets.
    let old_leaf = commit(
        witness.old_root_public_key,
        witness.credential_key,
        witness.old_root_opening,
        &agora,
    )
    .ok_or(ProtocolError::Malformed)?;
    let spend = nullifier::migration(witness.credential_key, &old_leaf, &agora);
    let public = MigrationPublicInputs {
        agora,
        class_root,
        revocation_root,
        spend_nullifier: spend,
        successor_commitment,
    };
    Ok((system.prove_migration(witness, &public)?, spend))
}

/// Whether `proof` establishes the migration consuming `spend_nullifier` in favour of
/// `successor_commitment` (§9.3).
pub fn verify_migration<S: ProofSystem<DEPTH>, const DEPTH: usize>(
    system: &S,
    proof: &S::MigrationProof,
    agora: AgoraId,
    class_root: Root,
    revocation_root: Root,
    spend_nullifier: Nullifier,
    successor_commitment: Commitment,
) -> bool {
    system.verify_migration(
        proof,
        &MigrationPublicInputs {
            agora,
            class_root,
            revocation_root,
            spend_nullifier,
            successor_commitment,
        },
    )
}
