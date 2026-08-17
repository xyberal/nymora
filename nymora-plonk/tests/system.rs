// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boundary, end to end: the workspace's action API driving the real circuits
//! through the `ProofSystem` trait at the protocol depth (proposal 0035).
//!
//! Everything here is assembled from *workspace* types — the byte-valued witnesses
//! `nymora-protocol` stores and serves — and proven by [`Backend`] through exactly the
//! interface the stub prover implements. What these tests establish is the swap
//! itself: the same statement the stub evaluates in the clear now proves and verifies
//! in zero knowledge, with no caller changing shape.

use std::sync::OnceLock;

use nymora_accumulator::{AbsenceWitness, ExclusionSet, Tree, Witness};
use nymora_circuits::{ChainWitness, MigrationWitness, PROTOCOL_DEPTH};
use nymora_core::{
    AgoraId, Commitment, CredentialKey, Epoch, EpochSecretKey, MessageHash, ProtocolError,
    RootOpening,
};
use nymora_crypto::{commit, nullifier, signature};
use nymora_plonk::backend::Backend;
use nymora_proofs::{
    prove_authorship, prove_migration, prove_vouch, verify_authorship, verify_migration,
    verify_vouch, EpochRoots,
};

const DEPTH: usize = PROTOCOL_DEPTH;
const AGORA: AgoraId = AgoraId::from_bytes([0x01; 32]);
const EPOCH: Epoch = Epoch::new(7);

fn backend() -> &'static Backend<DEPTH> {
    static BACKEND: OnceLock<Backend<DEPTH>> = OnceLock::new();
    BACKEND.get_or_init(|| Backend::insecure_for_tests(0x4e59_4d4f_5241_0003))
}

struct World {
    epoch_key: EpochSecretKey,
    epoch_public_key: [u8; 32],
    epoch_cert_signature: [u8; 64],
    credential_key: CredentialKey,
    root_opening: RootOpening,
    root_public_key: [u8; 32],
    root_secret: [u8; 32],
    leaf: Commitment,
    leaf_witness: Witness<DEPTH>,
    revocation_absence: AbsenceWitness<DEPTH>,
    spend_absence: AbsenceWitness<DEPTH>,
    roots: EpochRoots,
}

fn world() -> World {
    let root_secret = signature::mint_signing_secret([0x0a; 32]);
    let root_public_key = signature::public_key(&root_secret).expect("canonical");
    let credential_key = CredentialKey::new(nymora_crypto::field::mint_secret([0x0b; 32]));
    let root_opening = RootOpening::new(nymora_crypto::field::mint_secret([0x0c; 32]));
    let leaf = commit(&root_public_key, &credential_key, &root_opening, &AGORA)
        .expect("the root key is a subgroup point");

    let mut tree = Tree::<DEPTH>::new();
    tree.append(Commitment::from_bytes(nymora_crypto::field::to_bytes(
        &nymora_crypto::F::from(999),
    )))
    .expect("room");
    let position = tree.append(leaf).expect("room");
    let leaf_witness = tree.witness(position).expect("appended");

    let revocations = ExclusionSet::<DEPTH>::new();
    let spends = ExclusionSet::<DEPTH>::new();
    let spend = nullifier::migration(&credential_key, &leaf, &AGORA);

    let epoch_secret = signature::mint_signing_secret([0x0d; 32]);
    let epoch_public_key = signature::public_key(&epoch_secret).expect("canonical");
    let message = signature::epoch_cert_message(&AGORA, EPOCH, &epoch_public_key)
        .expect("the epoch key is a subgroup point");
    let epoch_cert_signature = signature::sign(&root_secret, &message).expect("canonical");

    World {
        epoch_key: EpochSecretKey::new(epoch_secret),
        epoch_public_key,
        epoch_cert_signature,
        credential_key,
        root_opening,
        root_public_key,
        root_secret,
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

impl World {
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

/// The swap, demonstrated: authorship assembled from workspace material, proven by
/// the real circuit, verified by key and instance alone — and bound to exactly its
/// public inputs.
#[test]
fn authorship_proves_in_zero_knowledge_through_the_trait() {
    let w = world();
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof, produced) =
        prove_authorship(backend(), &w.witness(), AGORA, EPOCH, &w.roots, message)
            .expect("a current credential proves");

    assert!(verify_authorship(
        backend(),
        &proof,
        AGORA,
        EPOCH,
        &w.roots,
        message,
        produced
    ));
    // The Fiat–Shamir binding, through the trait: another message, another epoch,
    // another claimed nullifier all refuse.
    assert!(!verify_authorship(
        backend(),
        &proof,
        AGORA,
        EPOCH,
        &w.roots,
        MessageHash::from_bytes([0xab; 32]),
        produced
    ));
    assert!(!verify_authorship(
        backend(),
        &proof,
        AGORA,
        Epoch::new(EPOCH.get() + 1),
        &w.roots,
        message,
        produced
    ));
    assert!(!verify_authorship(
        backend(),
        &proof,
        AGORA,
        EPOCH,
        &w.roots,
        message,
        nymora_core::Nullifier::from_bytes([0x99; 32])
    ));
}

#[test]
fn vouch_proves_and_the_nullifier_is_the_workspace_derivation() {
    let w = world();
    let (proof, produced) = prove_vouch(
        backend(),
        &w.witness(),
        AGORA,
        EPOCH,
        &w.roots,
        b"session-1",
    )
    .expect("a current credential vouches");
    assert_eq!(
        produced,
        nullifier::vouch(&w.credential_key, b"session-1", &AGORA)
    );
    assert!(verify_vouch(
        backend(),
        &proof,
        AGORA,
        EPOCH,
        &w.roots,
        b"session-1",
        produced
    ));
}

#[test]
fn migration_proves_through_the_trait() {
    let w = world();
    let successor_secret = signature::mint_signing_secret([0x1a; 32]);
    let successor_public_key = signature::public_key(&successor_secret).expect("canonical");
    let successor_opening = RootOpening::new(nymora_crypto::field::mint_secret([0x1b; 32]));
    let message = signature::migration_cert_message(&AGORA, &successor_public_key)
        .expect("the successor key is a subgroup point");
    let cert = signature::sign(&w.root_secret, &message).expect("canonical");
    let successor_commitment = commit(
        &successor_public_key,
        &w.credential_key,
        &successor_opening,
        &AGORA,
    )
    .expect("the successor key is a subgroup point");

    let witness = MigrationWitness {
        old_root_public_key: &w.root_public_key,
        old_root_opening: &w.root_opening,
        credential_key: &w.credential_key,
        old_leaf_witness: &w.leaf_witness,
        migration_cert_signature: &cert,
        successor_public_key: &successor_public_key,
        successor_opening: &successor_opening,
        revocation_absence: &w.revocation_absence,
    };
    let (proof, spend) = prove_migration(
        backend(),
        &witness,
        AGORA,
        w.roots.class,
        w.roots.revocation,
        successor_commitment,
    )
    .expect("an authorized migration proves");
    assert_eq!(
        spend,
        nullifier::migration(&w.credential_key, &w.leaf, &AGORA)
    );
    assert!(verify_migration(
        backend(),
        &proof,
        AGORA,
        w.roots.class,
        w.roots.revocation,
        spend,
        successor_commitment
    ));
}

/// The serialization boundary of §9.1's cofactor clause, at the trait: witness bytes
/// that decode to a curve point *off* the prime-order subgroup are refused before the
/// prover is consulted. The fixture is the order-2 torsion point (0, -1) — a canonical
/// encoding, on the curve, outside the subgroup.
#[test]
fn an_off_subgroup_witness_point_is_refused_at_the_boundary() {
    let w = world();
    let torsion = {
        // v = -1 with the sign bit of u = 0: the canonical encoding of (0, -1).
        let mut bytes = [0u8; 32];
        let minus_one = -nymora_crypto::F::from(1);
        bytes.copy_from_slice(&nymora_crypto::field::to_bytes(&minus_one));
        bytes
    };
    let witness = ChainWitness {
        epoch_public_key: &torsion,
        ..w.witness()
    };
    let result = prove_authorship(
        backend(),
        &witness,
        AGORA,
        EPOCH,
        &w.roots,
        MessageHash::from_bytes([0xaa; 32]),
    );
    assert_eq!(result.err(), Some(ProtocolError::Malformed));
}

/// The canonicity clause at the trait: an epoch key whose bytes are not a canonical
/// scalar satisfies no statement, however honestly the rest of the witness was built.
#[test]
fn a_non_canonical_epoch_key_is_refused() {
    let w = world();
    let non_canonical = EpochSecretKey::new([0xff; 32]);
    let witness = ChainWitness {
        epoch_key: &non_canonical,
        ..w.witness()
    };
    let result = prove_authorship(
        backend(),
        &witness,
        AGORA,
        EPOCH,
        &w.roots,
        MessageHash::from_bytes([0xaa; 32]),
    );
    assert_eq!(result.err(), Some(ProtocolError::Malformed));
}

/// The custody chain, closed: the committed Filecoin excerpt — checksummed
/// provenance in `srs/README.md` — actually proves and verifies the chain statement.
/// Everything else in the suite runs on the insecure local string; this is the one
/// test against the real one.
#[test]
fn the_committed_filecoin_excerpt_proves() {
    let bytes = include_bytes!("../srs/bls_filecoin_2p14");
    let backend = Backend::<DEPTH>::from_srs_bytes(bytes.as_slice())
        .expect("the committed excerpt deserializes");
    let w = world();
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof, produced) =
        prove_authorship(&backend, &w.witness(), AGORA, EPOCH, &w.roots, message)
            .expect("the inherited string proves");
    assert!(verify_authorship(
        &backend, &proof, AGORA, EPOCH, &w.roots, message, produced
    ));
}
