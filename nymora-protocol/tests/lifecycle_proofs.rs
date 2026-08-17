// SPDX-License-Identifier: MIT OR Apache-2.0

//! The credential lifecycle meets the proof layer: proofs produced from material the
//! lifecycle **stored**, not fabricated inline.
//!
//! The exit criteria these tests carry: every action proves and verifies from stored
//! material across two agoras with adversarially identical entropy; a swept epoch can no
//! longer produce a proof, however late the device wakes; the revocation and spend
//! clauses each refuse an otherwise-valid credential; and migration runs end-to-end from
//! the handoff to a verified proof whose spend then locks the predecessor out.

use nymora_accumulator::{AbsenceWitness, ExclusionSet, Tree, Witness};
use nymora_circuits::StubProver;
use nymora_core::{
    AgoraId, Commitment, Epoch, MessageHash, ProtocolError, RootOpening, SessionContext,
};
use nymora_ports::{SecureStorage, Slot, SoftwareKeyStore};
use nymora_proofs::{
    prove_authorship, prove_live_auth, prove_migration, prove_vouch, verify_authorship,
    verify_migration, EpochRoots, MigrationWitness,
};
use nymora_protocol::{
    authorize_migration, complete_migration, create, create_successor_root, load_acting_material,
    FreshEntropy,
};
use std::collections::HashMap;
use std::vec::Vec;

const DEPTH: usize = 2;
const AGORA_A: AgoraId = AgoraId::from_bytes([0x01; 32]);
const AGORA_B: AgoraId = AgoraId::from_bytes([0x02; 32]);
const EPOCH: Epoch = Epoch::new(7);

/// A minimal in-memory `SecureStorage`. The lifecycle's own unit tests use a logging
/// double; here plain storage suffices — what is under test is what was stored.
#[derive(Default)]
struct TestStore {
    values: HashMap<([u8; 32], Slot), Vec<u8>>,
}

impl SecureStorage for TestStore {
    fn store(&mut self, agora: AgoraId, slot: Slot, value: &[u8]) -> Result<(), ProtocolError> {
        self.values
            .insert((*agora.as_bytes(), slot), value.to_vec());
        Ok(())
    }

    fn load(
        &self,
        agora: AgoraId,
        slot: Slot,
        out: &mut [u8],
    ) -> Result<Option<usize>, ProtocolError> {
        let Some(value) = self.values.get(&(*agora.as_bytes(), slot)) else {
            return Ok(None);
        };
        out.get_mut(..value.len())
            .ok_or(ProtocolError::Malformed)?
            .copy_from_slice(value);
        Ok(Some(value.len()))
    }

    fn delete(&mut self, agora: AgoraId, slot: Slot) -> Result<(), ProtocolError> {
        self.values.remove(&(*agora.as_bytes(), slot));
        Ok(())
    }
}

/// The operator's side of one agora: the class tree and the two exclusion sets.
struct Operator {
    tree: Tree<DEPTH>,
    revocations: ExclusionSet<DEPTH>,
    spends: ExclusionSet<DEPTH>,
}

impl Operator {
    fn new() -> Self {
        Self {
            tree: Tree::new(),
            revocations: ExclusionSet::new(),
            spends: ExclusionSet::new(),
        }
    }

    fn admit(&mut self, leaf: Commitment) -> u64 {
        self.tree.append(leaf).expect("tree has room")
    }

    fn roots(&self) -> EpochRoots {
        EpochRoots {
            class: self.tree.root(),
            revocation: self.revocations.root(),
            spend: self.spends.root(),
        }
    }

    fn leaf_witness(&self, position: u64) -> Witness<DEPTH> {
        self.tree.witness(position).expect("position was admitted")
    }

    fn absences(
        &self,
        leaf: &Commitment,
        spend_key: &[u8; 32],
    ) -> (AbsenceWitness<DEPTH>, AbsenceWitness<DEPTH>) {
        (
            self.revocations.absence_witness(leaf.as_bytes()),
            self.spends.absence_witness(spend_key),
        )
    }
}

fn entropy(byte: u8) -> FreshEntropy {
    FreshEntropy::new([byte; 32])
}

/// Creates a credential and rolls it to `epoch` with a host-produced provisional keypair.
fn member_acting_at(
    store: &mut TestStore,
    keys: &SoftwareKeyStore,
    agora: AgoraId,
    epoch: Epoch,
    epoch_seed: [u8; 32],
) -> Commitment {
    let mut pk = [0u8; 64];
    let mut binding = [0u8; 64];
    let made = create(
        agora,
        keys,
        store,
        entropy(0x44),
        entropy(0x22),
        &mut pk,
        &mut binding,
    )
    .expect("creation succeeds");

    let mut record = [0u8; 256];
    nymora_protocol::roll_epoch(
        agora,
        keys,
        store,
        epoch,
        FreshEntropy::new(epoch_seed),
        &mut record,
    )
    .expect("rollover succeeds");

    made.commitment
}

/// The member's own spend key for the currency clause: the migration nullifier its leaf
/// would spend, whose absence every routine proof shows.
fn spend_key(store: &TestStore, agora: AgoraId, leaf: &Commitment) -> [u8; 32] {
    let mut sk = [0u8; 32];
    store
        .load(agora, Slot::CredentialKey, &mut sk)
        .unwrap()
        .expect("credential stored");
    let key = nymora_core::CredentialKey::new(sk);
    *nymora_crypto::nullifier::migration(&key, leaf, &agora).as_bytes()
}

/// The headline test: identical entropy fed into two agoras, and every action proving
/// from stored material without a single shared value between the memberships.
#[test]
fn every_action_proves_from_stored_material_and_nothing_crosses_agoras() {
    let keys = SoftwareKeyStore::new([0x5a; 32]);
    let mut store = TestStore::default();

    // Same creation entropy, same epoch seed, same epoch number — adversarially.
    let leaf_a = member_acting_at(&mut store, &keys, AGORA_A, EPOCH, [0xd7; 32]);
    let leaf_b = member_acting_at(&mut store, &keys, AGORA_B, EPOCH, [0xd7; 32]);
    assert_ne!(leaf_a, leaf_b, "one leaf served two agoras");

    let mut op_a = Operator::new();
    let mut op_b = Operator::new();
    let at_a = op_a.admit(leaf_a);
    let at_b = op_b.admit(leaf_b);

    let mut pk_buf_a = [0u8; 64];
    let mut record_buf_a = [0u8; 256];
    let material_a = load_acting_material(AGORA_A, &store, EPOCH, &mut pk_buf_a, &mut record_buf_a)
        .expect("stored material loads");
    let mut pk_buf_b = [0u8; 64];
    let mut record_buf_b = [0u8; 256];
    let material_b = load_acting_material(AGORA_B, &store, EPOCH, &mut pk_buf_b, &mut record_buf_b)
        .expect("stored material loads");

    let inclusion_a = op_a.leaf_witness(at_a);
    let (rev_a, spend_a) = op_a.absences(&leaf_a, &spend_key(&store, AGORA_A, &leaf_a));
    let witness_a = material_a.witness(&inclusion_a, &rev_a, &spend_a);

    let inclusion_b = op_b.leaf_witness(at_b);
    let (rev_b, spend_b) = op_b.absences(&leaf_b, &spend_key(&store, AGORA_B, &leaf_b));
    let witness_b = material_b.witness(&inclusion_b, &rev_b, &spend_b);

    // Authorship of the same message in both agoras.
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof_a, nullifier_a) = prove_authorship(
        &StubProver,
        &witness_a,
        AGORA_A,
        EPOCH,
        &op_a.roots(),
        message,
    )
    .expect("a current credential proves");
    let (_proof_b, nullifier_b) = prove_authorship(
        &StubProver,
        &witness_b,
        AGORA_B,
        EPOCH,
        &op_b.roots(),
        message,
    )
    .expect("a current credential proves");
    assert_ne!(
        nullifier_a, nullifier_b,
        "one member's authorship correlated across two agoras"
    );
    assert!(verify_authorship(
        &StubProver,
        &proof_a,
        AGORA_A,
        EPOCH,
        &op_a.roots(),
        message,
        nullifier_a
    ));
    // A's proof is nothing in B — wrong agora, wrong roots, wrong everything.
    assert!(!verify_authorship(
        &StubProver,
        &proof_a,
        AGORA_B,
        EPOCH,
        &op_b.roots(),
        message,
        nullifier_a
    ));

    // The same vouch session and the same live context, adversarially replayed into both
    // agoras: every output distinct by construction (proposals 0017, 0018).
    let (_p, vouch_a) = prove_vouch(
        &StubProver,
        &witness_a,
        AGORA_A,
        EPOCH,
        &op_a.roots(),
        b"session-1",
    )
    .expect("proves");
    let (_p, vouch_b) = prove_vouch(
        &StubProver,
        &witness_b,
        AGORA_B,
        EPOCH,
        &op_b.roots(),
        b"session-1",
    )
    .expect("proves");
    assert_ne!(
        vouch_a, vouch_b,
        "colluding session identifiers linked two agoras"
    );

    let context = SessionContext::from_bytes([0xdd; 32]);
    let (_p, pseudonym_a) = prove_live_auth(
        &StubProver,
        &witness_a,
        AGORA_A,
        EPOCH,
        &op_a.roots(),
        context,
    )
    .expect("proves");
    let (_p, pseudonym_b) = prove_live_auth(
        &StubProver,
        &witness_b,
        AGORA_B,
        EPOCH,
        &op_b.roots(),
        context,
    )
    .expect("proves");
    assert_ne!(
        pseudonym_a, pseudonym_b,
        "one member's presence correlated across two agoras"
    );
}

/// §9.1's forward-secrecy bound, observed end to end: after the sweep there is no
/// material to assemble, however many boundaries the device slept through.
#[test]
fn a_swept_epoch_cannot_reach_the_proof_layer() {
    let keys = SoftwareKeyStore::new([0x5a; 32]);
    let mut store = TestStore::default();
    let _leaf = member_acting_at(&mut store, &keys, AGORA_A, Epoch::new(5), [0xd5; 32]);

    // The device wakes long after epoch 5 ended and rolls straight to 9.
    let mut record = [0u8; 256];
    nymora_protocol::roll_epoch(
        AGORA_A,
        &keys,
        &mut store,
        Epoch::new(9),
        FreshEntropy::new([0xd9; 32]),
        &mut record,
    )
    .expect("late rollover succeeds");

    let mut pk_buf = [0u8; 64];
    let mut record_buf = [0u8; 256];
    assert_eq!(
        load_acting_material(AGORA_A, &store, Epoch::new(5), &mut pk_buf, &mut record_buf).err(),
        Some(ProtocolError::Unavailable),
        "a destroyed epoch still assembled a witness"
    );
    // The current epoch still acts.
    load_acting_material(AGORA_A, &store, Epoch::new(9), &mut pk_buf, &mut record_buf)
        .expect("the current epoch's material loads");
}

/// The two currency clauses, refusing an otherwise-valid stored credential.
#[test]
fn revocation_and_spend_each_refuse_a_stored_credential() {
    let keys = SoftwareKeyStore::new([0x5a; 32]);
    let mut store = TestStore::default();
    let leaf = member_acting_at(&mut store, &keys, AGORA_A, EPOCH, [0xd7; 32]);

    let mut op = Operator::new();
    let position = op.admit(leaf);
    let message = MessageHash::from_bytes([0xaa; 32]);

    let mut pk_buf = [0u8; 64];
    let mut record_buf = [0u8; 256];
    let material = load_acting_material(AGORA_A, &store, EPOCH, &mut pk_buf, &mut record_buf)
        .expect("stored material loads");

    // Revoked: fresh witnesses against the moved roots, and the proof refuses.
    op.revocations.insert(*leaf.as_bytes());
    let inclusion = op.leaf_witness(position);
    let (rev, spend) = op.absences(&leaf, &spend_key(&store, AGORA_A, &leaf));
    assert_eq!(
        prove_authorship(
            &StubProver,
            &material.witness(&inclusion, &rev, &spend),
            AGORA_A,
            EPOCH,
            &op.roots(),
            message
        )
        .err(),
        Some(ProtocolError::Malformed),
        "a revoked credential produced a proof"
    );

    // Spent: a separate agora-state where the migration nullifier is in the spend set.
    let mut op = Operator::new();
    let position = op.admit(leaf);
    op.spends.insert(spend_key(&store, AGORA_A, &leaf));
    let inclusion = op.leaf_witness(position);
    let (rev, spend) = op.absences(&leaf, &spend_key(&store, AGORA_A, &leaf));
    assert_eq!(
        prove_authorship(
            &StubProver,
            &material.witness(&inclusion, &rev, &spend),
            AGORA_A,
            EPOCH,
            &op.roots(),
            message
        )
        .err(),
        Some(ProtocolError::Malformed),
        "a spent credential produced a proof"
    );
}

/// Path 1 end to end: handoff, completion, the migration proof from carried and stored
/// material, and the spend locking the predecessor out of routine proving.
#[test]
fn migration_proves_from_the_handoff_and_its_spend_locks_the_predecessor_out() {
    let old_keys = SoftwareKeyStore::new([0x5a; 32]);
    let mut old_store = TestStore::default();
    let old_leaf = member_acting_at(&mut old_store, &old_keys, AGORA_A, EPOCH, [0xd7; 32]);

    let mut op = Operator::new();
    let old_position = op.admit(old_leaf);

    // Successor's root exists first; its public key travels to the old device.
    let successor_keys = SoftwareKeyStore::new([0x5b; 32]);
    let mut successor_pk = [0u8; 64];
    let mut binding = [0u8; 64];
    let written = create_successor_root(AGORA_A, &successor_keys, &mut successor_pk, &mut binding)
        .expect("root creation succeeds");
    let successor_pk = &successor_pk[..written.public_key];

    // Old device authorizes; the handoff crosses devices.
    let mut old_pk = [0u8; 64];
    let mut cert = [0u8; 128];
    let mut handoff_bytes = [0u8; 512];
    let len = authorize_migration(
        AGORA_A,
        &old_keys,
        &old_store,
        successor_pk,
        &mut old_pk,
        &mut cert,
        &mut handoff_bytes,
    )
    .expect("authorization succeeds");
    let handoff =
        nymora_core::MigrationHandoff::decode(&handoff_bytes[..len]).expect("handoff decodes");

    // Successor completes, storing its own durable slots.
    let mut new_store = TestStore::default();
    let migrated = complete_migration(
        AGORA_A,
        &mut new_store,
        &handoff,
        successor_pk,
        entropy(0x23),
    )
    .expect("migration completes");

    // The successor proves the migration — predecessor material from the handoff, its own
    // opening from what completion just stored.
    let mut stored_opening = [0u8; 32];
    new_store
        .load(AGORA_A, Slot::RootOpening, &mut stored_opening)
        .unwrap()
        .expect("successor opening stored");
    let successor_opening = RootOpening::new(stored_opening);

    let inclusion = op.leaf_witness(old_position);
    let revocation_absence = op.revocations.absence_witness(old_leaf.as_bytes());
    let witness = MigrationWitness {
        old_root_public_key: handoff.root_public_key,
        old_root_opening: &handoff.root_opening,
        credential_key: &handoff.credential_key,
        old_leaf_witness: &inclusion,
        migration_cert_signature: handoff.migration_cert,
        successor_public_key: successor_pk,
        successor_opening: &successor_opening,
        revocation_absence: &revocation_absence,
    };

    let roots = op.roots();
    let (proof, spend) = prove_migration(
        &StubProver,
        &witness,
        AGORA_A,
        roots.class,
        roots.revocation,
        migrated.commitment,
    )
    .expect("the migration proves");
    assert_eq!(
        spend, migrated.spend,
        "the proof's spend disagrees with completion's"
    );
    assert!(verify_migration(
        &StubProver,
        &proof,
        AGORA_A,
        roots.class,
        roots.revocation,
        spend,
        migrated.commitment
    ));

    // The spend enters the set at the boundary; from then on the predecessor's routine
    // proofs refuse — the §9.3 bound on a superseded device, observed.
    op.spends.insert(*spend.as_bytes());
    let mut pk_buf = [0u8; 64];
    let mut record_buf = [0u8; 256];
    let material = load_acting_material(AGORA_A, &old_store, EPOCH, &mut pk_buf, &mut record_buf)
        .expect("the predecessor still holds its material");
    let inclusion = op.leaf_witness(old_position);
    let (rev, spend_absence) = op.absences(&old_leaf, spend.as_bytes());
    assert_eq!(
        prove_authorship(
            &StubProver,
            &material.witness(&inclusion, &rev, &spend_absence),
            AGORA_A,
            EPOCH,
            &op.roots(),
            MessageHash::from_bytes([0xaa; 32]),
        )
        .err(),
        Some(ProtocolError::Malformed),
        "a superseded credential still produced routine proofs"
    );
}
