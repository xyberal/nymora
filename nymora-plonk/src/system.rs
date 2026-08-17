// SPDX-License-Identifier: MIT OR Apache-2.0

//! The backend behind the `ProofSystem` boundary (§6.5, proposal 0035).
//!
//! This is the seam the whole workspace was built toward: [`Backend`] implements the
//! `nymora-circuits` trait, so everything above it — the action API in `nymora-proofs`,
//! witness assembly and both roles' state machines in `nymora-protocol` — drives the
//! real circuits through exactly the interface it drove the stub through, and nothing
//! above recompiles differently.
//!
//! # The conversions are the trust boundary
//!
//! The workspace speaks 32-byte protocol values; the circuits speak field elements and
//! curve points. Every conversion here either succeeds canonically or refuses:
//!
//! - Public inputs cross through the *workspace's own* field-entry rules
//!   (`nymora-crypto`'s crossing, bridged by canonical bytes), so the instance the
//!   verifier constrains is byte-for-byte the one the protocol derived. A public value
//!   whose bytes name no field element names no statement — prove refuses, verify
//!   returns false.
//! - Witness points decode through the subgroup-checking decoder, which is the
//!   serialization boundary of §9.1's cofactor clause: bytes naming a curve point off
//!   the prime-order subgroup convert to nothing, and the statement is refused before
//!   the prover is ever consulted.
//!
//! # Proof bytes are the proof
//!
//! A proof is the KZG proof byte string, fixed-size by construction (§6.5's uniform
//! shape). Verification recomputes nothing from a witness — it holds only the
//! verifying key, the instance, and the bytes.

use ff::PrimeField;
use group::GroupEncoding;
use midnight_curves::{Fr as JubjubScalar, JubjubSubgroup};
use nymora_accumulator::{AbsenceWitness as ByteAbsence, Witness as ByteWitness};
use nymora_circuits::{statement, Action, ChainPublicInputs, MigrationPublicInputs, ProofSystem};
use nymora_core::{field_domain, ProtocolError};
use nymora_crypto::field as crossing;

use crate::{
    backend::{Backend, ProveError},
    chain::{ChainInstance, ChainWitness},
    exclusion::AbsenceWitness,
    migration::{MigrationInstance, MigrationWitness},
    tree::Path,
    F,
};

/// A workspace field element (canonical bytes), as the circuit field's element.
///
/// The two crates implement the same field; canonical bytes are the bridge, and the
/// parity suite pins that they agree value for value.
fn bridge(value: nymora_crypto::F) -> F {
    F::from_repr(crossing::to_bytes(&value)).expect("one field, one canonical encoding")
}

/// Strict decoding of a 32-byte protocol value into the circuit field.
fn decode(bytes: &[u8; 32]) -> Option<F> {
    F::from_repr(*bytes).into()
}

/// The subgroup-checking point decoder — §9.1's cofactor clause at the boundary.
fn decode_point(bytes: &[u8]) -> Option<JubjubSubgroup> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    JubjubSubgroup::from_bytes(&bytes).into()
}

/// A 64-byte certificate: compressed `R`, canonical `S`.
fn decode_signature(bytes: &[u8]) -> Option<crate::primitives::Signature> {
    let bytes: [u8; 64] = bytes.try_into().ok()?;
    let r = decode_point(&bytes[..32])?;
    let s_bytes: [u8; 32] = bytes[32..].try_into().ok()?;
    let s = Option::<JubjubScalar>::from(JubjubScalar::from_bytes(&s_bytes))?;
    Some(crate::primitives::Signature { r, s })
}

/// An inclusion witness as the circuit's path: index bits and decoded siblings.
fn path<const DEPTH: usize>(witness: &ByteWitness<DEPTH>) -> Option<Path<DEPTH>> {
    let mut siblings = [F::from(0); DEPTH];
    let mut bits = [false; DEPTH];
    for (level, (sibling, bit)) in siblings.iter_mut().zip(bits.iter_mut()).enumerate() {
        *sibling = decode(witness.siblings()[level].as_bytes())?;
        *bit = (witness.index() >> level) & 1 == 1;
    }
    Some(Path { siblings, bits })
}

/// A gap-tree absence witness, field-native.
fn absence<const DEPTH: usize>(witness: &ByteAbsence<DEPTH>) -> Option<AbsenceWitness<DEPTH>> {
    Some(AbsenceWitness {
        low: decode(witness.low())?,
        high: decode(witness.high())?,
        path: path(witness.path())?,
    })
}

/// The instance an ordinary proof is constrained against — eight field elements,
/// derived through the workspace's own crossing so the two sides cannot disagree.
fn chain_instance(public: &ChainPublicInputs<'_>) -> Option<ChainInstance> {
    let (tag, context, output) = match &public.action {
        Action::Authorship {
            message_hash,
            nullifier,
        } => (
            field_domain::action_tag::AUTHORSHIP,
            bridge(crossing::from_id(message_hash.as_bytes())),
            decode(nullifier.as_bytes())?,
        ),
        Action::Vouch {
            session_id,
            nullifier,
        } => (
            field_domain::action_tag::VOUCH,
            bridge(crossing::from_context_bytes(session_id)),
            decode(nullifier.as_bytes())?,
        ),
        Action::PolicyApproval {
            proposal_id,
            nullifier,
        } => (
            field_domain::action_tag::POLICY,
            bridge(crossing::from_context_bytes(proposal_id)),
            decode(nullifier.as_bytes())?,
        ),
        Action::LiveAuth { context, pseudonym } => (
            field_domain::action_tag::LIVE_AUTH,
            bridge(crossing::from_id(context.as_bytes())),
            decode(pseudonym.as_bytes())?,
        ),
        Action::VerificationAccess { challenge } => (
            field_domain::action_tag::VERIFICATION,
            bridge(crossing::from_context_bytes(challenge)),
            F::from(0),
        ),
    };
    Some(ChainInstance {
        agora: bridge(crossing::from_id(public.agora.as_bytes())),
        epoch: F::from(public.epoch.get()),
        class_root: decode(public.class_root.as_bytes())?,
        revocation_root: decode(public.revocation_root.as_bytes())?,
        spend_root: decode(public.spend_root.as_bytes())?,
        action_tag: F::from(tag),
        action_context: context,
        action_output: output,
    })
}

fn chain_witness<const DEPTH: usize>(
    witness: &statement::ChainWitness<'_, DEPTH>,
) -> Option<ChainWitness<DEPTH>> {
    Some(ChainWitness {
        epoch_key_bytes: *witness.epoch_key.expose(),
        epoch_public_key: decode_point(witness.epoch_public_key)?,
        epoch_certificate: decode_signature(witness.epoch_cert_signature)?,
        credential_key: decode(witness.credential_key.expose())?,
        root_opening: decode(witness.root_opening.expose())?,
        root_public_key: decode_point(witness.root_public_key)?,
        class_path: path(witness.leaf_witness)?,
        revocation_absence: absence(witness.revocation_absence)?,
        spend_absence: absence(witness.spend_absence)?,
    })
}

fn migration_instance(public: &MigrationPublicInputs) -> Option<MigrationInstance> {
    Some(MigrationInstance {
        agora: bridge(crossing::from_id(public.agora.as_bytes())),
        class_root: decode(public.class_root.as_bytes())?,
        revocation_root: decode(public.revocation_root.as_bytes())?,
        spend_nullifier: decode(public.spend_nullifier.as_bytes())?,
        successor_commitment: decode(public.successor_commitment.as_bytes())?,
    })
}

fn migration_witness<const DEPTH: usize>(
    witness: &statement::MigrationWitness<'_, DEPTH>,
) -> Option<MigrationWitness<DEPTH>> {
    Some(MigrationWitness {
        old_root_public_key: decode_point(witness.old_root_public_key)?,
        old_root_opening: decode(witness.old_root_opening.expose())?,
        credential_key: decode(witness.credential_key.expose())?,
        old_class_path: path(witness.old_leaf_witness)?,
        migration_certificate: decode_signature(witness.migration_cert_signature)?,
        successor_public_key: decode_point(witness.successor_public_key)?,
        successor_opening: decode(witness.successor_opening.expose())?,
        revocation_absence: absence(witness.revocation_absence)?,
    })
}

/// A conversion failure means the witness cannot satisfy any statement — the caller's
/// own material, refused as such. A backend failure past the satisfiability check is
/// operational.
fn prove_error(error: ProveError) -> ProtocolError {
    match error {
        ProveError::Unsatisfiable => ProtocolError::Malformed,
        ProveError::Backend(_) => ProtocolError::Unavailable,
    }
}

impl<const DEPTH: usize> ProofSystem<DEPTH> for Backend<DEPTH> {
    type Proof = Vec<u8>;
    type MigrationProof = Vec<u8>;

    fn prove(
        &self,
        witness: &statement::ChainWitness<'_, DEPTH>,
        public: &ChainPublicInputs<'_>,
    ) -> Result<Self::Proof, ProtocolError> {
        let instance = chain_instance(public).ok_or(ProtocolError::Malformed)?;
        let witness = chain_witness(witness).ok_or(ProtocolError::Malformed)?;
        self.prove_chain(&witness, &instance).map_err(prove_error)
    }

    fn verify(&self, proof: &Self::Proof, public: &ChainPublicInputs<'_>) -> bool {
        let Some(instance) = chain_instance(public) else {
            return false;
        };
        self.verify_chain(proof, &instance)
    }

    fn prove_migration(
        &self,
        witness: &statement::MigrationWitness<'_, DEPTH>,
        public: &MigrationPublicInputs,
    ) -> Result<Self::MigrationProof, ProtocolError> {
        let instance = migration_instance(public).ok_or(ProtocolError::Malformed)?;
        let witness = migration_witness(witness).ok_or(ProtocolError::Malformed)?;
        self.prove_migration_statement(&witness, &instance)
            .map_err(prove_error)
    }

    fn verify_migration(
        &self,
        proof: &Self::MigrationProof,
        public: &MigrationPublicInputs,
    ) -> bool {
        let Some(instance) = migration_instance(public) else {
            return false;
        };
        self.verify_migration_statement(proof, &instance)
    }
}
