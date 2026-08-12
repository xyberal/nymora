// SPDX-License-Identifier: MIT OR Apache-2.0

//! The action surface, end to end through the stub backend.
//!
//! Clause-by-clause falsification lives with the stub in `nymora-circuits`; what these
//! tests pin is this crate's wiring — that each entry point derives the right output from
//! the witness, hands the backend the statement it names, and reconstructs the same
//! statement on the verify side.

#![cfg(all(feature = "provisional-algebraic-hash", feature = "stub-prover"))]

use nymora_accumulator::{AbsenceWitness, ExclusionSet, Tree, Witness};
use nymora_circuits::StubProver;
use nymora_core::{
    AgoraId, Commitment, CredentialKey, Epoch, EpochCertPayload, EpochSecretKey, MessageHash,
    MigrationCertPayload, RootOpening, SessionContext,
};
use nymora_crypto::{commit, nullifier, signature};
use nymora_proofs::{
    prove_authorship, prove_live_auth, prove_migration, prove_policy_approval,
    prove_verification_access, prove_vouch, verify_authorship, verify_live_auth, verify_migration,
    verify_policy_approval, verify_verification_access, verify_vouch, ChainWitness, EpochRoots,
    MigrationWitness,
};

const DEPTH: usize = 2;
const AGORA: AgoraId = AgoraId::from_bytes([0x01; 32]);
const EPOCH: Epoch = Epoch::new(7);
const ROOT_SEED: [u8; 32] = [0x0a; 32];
const EPOCH_SEED: [u8; 32] = [0x0d; 32];

struct Fixture {
    epoch_key: EpochSecretKey,
    epoch_public_key: [u8; signature::PUBLIC_KEY_LEN],
    epoch_cert_signature: [u8; signature::SIGNATURE_LEN],
    credential_key: CredentialKey,
    root_opening: RootOpening,
    root_public_key: [u8; signature::PUBLIC_KEY_LEN],
    leaf: Commitment,
    leaf_witness: Witness<DEPTH>,
    revocation_absence: AbsenceWitness,
    spend_absence: AbsenceWitness,
    roots: EpochRoots,
}

fn fixture() -> Fixture {
    let root_public_key = signature::public_key(&ROOT_SEED);
    let credential_key = CredentialKey::new([0x0b; 32]);
    let root_opening = RootOpening::new([0x0c; 32]);
    let leaf = commit(&root_public_key, &credential_key, &root_opening, &AGORA);

    let mut tree = Tree::<DEPTH>::new();
    let position = tree.append(leaf).expect("tree has room");
    let leaf_witness = tree.witness(position).expect("position was just appended");

    let revocations = ExclusionSet::new();
    let spends = ExclusionSet::new();
    let spend = nullifier::migration(&credential_key, &leaf, &AGORA);

    let epoch_key = EpochSecretKey::new(EPOCH_SEED);
    let epoch_public_key = signature::public_key(&EPOCH_SEED);
    let cert = EpochCertPayload {
        agora: AGORA,
        epoch: EPOCH,
        epoch_public_key: &epoch_public_key,
    };
    let epoch_cert_signature = signature::sign(&ROOT_SEED, |put| cert.encode_parts(put));

    Fixture {
        epoch_key,
        epoch_public_key,
        epoch_cert_signature,
        credential_key,
        root_opening,
        root_public_key,
        leaf,
        leaf_witness,
        revocation_absence: revocations.absence_witness(leaf.as_bytes()),
        spend_absence: spends.absence_witness(spend.as_bytes()),
        roots: EpochRoots {
            class: tree.root(),
            revocation: revocations.root(),
            spend: spends.root(),
        },
    }
}

impl Fixture {
    fn witness(&self) -> ChainWitness<'_, DEPTH> {
        ChainWitness {
            epoch_key: &self.epoch_key,
            epoch_public_key: &self.epoch_public_key,
            epoch_cert_signature: &self.epoch_cert_signature,
            credential_key: &self.credential_key,
            root_opening: &self.root_opening,
            root_public_key: &self.root_public_key,
            leaf_witness: &self.leaf_witness,
            revocation_absence: &self.revocation_absence,
            spend_absence: &self.spend_absence,
        }
    }
}

#[test]
fn authorship_round_trips_and_the_returned_nullifier_is_the_derivation() {
    let f = fixture();
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof, produced) =
        prove_authorship(&StubProver, &f.witness(), AGORA, EPOCH, &f.roots, message)
            .expect("a current credential proves");

    assert_eq!(
        produced,
        nullifier::attestation(&f.epoch_key, &message, &AGORA),
        "the returned nullifier is not the specified derivation"
    );
    assert!(verify_authorship(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        message,
        produced
    ));
    // A different claimed nullifier is a different statement.
    assert!(!verify_authorship(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        message,
        nymora_core::Nullifier::from_bytes([0x99; 32]),
    ));
    // And the epoch is bound: the same proof does not verify in the next one.
    assert!(!verify_authorship(
        &StubProver,
        &proof,
        AGORA,
        Epoch::new(8),
        &f.roots,
        message,
        produced
    ));
}

#[test]
fn vouch_and_policy_round_trip() {
    let f = fixture();
    let (proof, produced) = prove_vouch(
        &StubProver,
        &f.witness(),
        AGORA,
        EPOCH,
        &f.roots,
        b"session-1",
    )
    .expect("a current credential proves");
    assert_eq!(
        produced,
        nullifier::vouch(&f.credential_key, b"session-1", &AGORA)
    );
    assert!(verify_vouch(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        b"session-1",
        produced
    ));
    // Bound to its session: the same proof is nothing in another.
    assert!(!verify_vouch(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        b"session-2",
        produced
    ));

    let (proof, produced) = prove_policy_approval(
        &StubProver,
        &f.witness(),
        AGORA,
        EPOCH,
        &f.roots,
        b"proposal-1",
    )
    .expect("a current credential proves");
    assert!(verify_policy_approval(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        b"proposal-1",
        produced
    ));
}

#[test]
fn live_auth_round_trips_with_the_derived_pseudonym() {
    let f = fixture();
    let context = SessionContext::from_bytes([0xdd; 32]);
    let (proof, pseudonym) =
        prove_live_auth(&StubProver, &f.witness(), AGORA, EPOCH, &f.roots, context)
            .expect("a current credential proves");
    assert!(verify_live_auth(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        context,
        pseudonym
    ));
    // A refreshed context is a new statement — §8.2's continuity boundary.
    assert!(!verify_live_auth(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        SessionContext::from_bytes([0xde; 32]),
        pseudonym
    ));
}

#[test]
fn verification_access_binds_its_challenge_and_carries_no_output() {
    let f = fixture();
    let proof = prove_verification_access(
        &StubProver,
        &f.witness(),
        AGORA,
        EPOCH,
        &f.roots,
        b"challenge-1",
    )
    .expect("a current credential proves");
    assert!(verify_verification_access(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        b"challenge-1"
    ));
    // Replay against any other challenge fails — the whole point of proposal 0019.
    assert!(!verify_verification_access(
        &StubProver,
        &proof,
        AGORA,
        EPOCH,
        &f.roots,
        b"challenge-2"
    ));
}

#[test]
fn migration_round_trips_and_binds_its_successor() {
    let f = fixture();
    let successor_seed = [0x1a; 32];
    let successor_public_key = signature::public_key(&successor_seed);
    let successor_opening = RootOpening::new([0x1b; 32]);
    let cert = MigrationCertPayload {
        agora: AGORA,
        successor_public_key: &successor_public_key,
    };
    let cert_signature = signature::sign(&ROOT_SEED, |put| cert.encode_parts(put));
    let successor_commitment = commit(
        &successor_public_key,
        &f.credential_key,
        &successor_opening,
        &AGORA,
    );

    let witness = MigrationWitness {
        old_root_public_key: &f.root_public_key,
        old_root_opening: &f.root_opening,
        credential_key: &f.credential_key,
        old_leaf_witness: &f.leaf_witness,
        migration_cert_signature: &cert_signature,
        successor_public_key: &successor_public_key,
        successor_opening: &successor_opening,
        revocation_absence: &f.revocation_absence,
    };

    let (proof, spend) = prove_migration(
        &StubProver,
        &witness,
        AGORA,
        f.roots.class,
        f.roots.revocation,
        successor_commitment,
    )
    .expect("a current credential migrates");

    assert_eq!(
        spend,
        nullifier::migration(&f.credential_key, &f.leaf, &AGORA),
        "the returned spend is not the leaf-bound derivation"
    );
    assert!(verify_migration(
        &StubProver,
        &proof,
        AGORA,
        f.roots.class,
        f.roots.revocation,
        spend,
        successor_commitment
    ));
    // A different successor commitment is a different migration.
    assert!(!verify_migration(
        &StubProver,
        &proof,
        AGORA,
        f.roots.class,
        f.roots.revocation,
        spend,
        Commitment::from_bytes([0x99; 32])
    ));
}
