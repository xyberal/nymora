// SPDX-License-Identifier: MIT OR Apache-2.0

//! The full-lifecycle milestone: everything, end to end, across **two agoras**, with
//! software keys and stub proofs — and the negative class as explicit assertions.
//!
//! One person — Dana — belongs to both agoras through the same "device" (the same seed,
//! adversarially: even a host that reused entropy across agoras must produce unlinkable
//! memberships, per §5.1 and proposal 0013). The story runs bootstrap, vouching,
//! governance, authorship, member-gated verification, live authentication, revocation,
//! planned migration, lost-device recovery, and dissolution — each in the agora where it
//! belongs, with the other agora asserted untouched and uncorrelated at every step.
//!
//! Cross-agora isolation is proved by demonstrating the *absence* of relationships —
//! the negative class: identifiers, leaves, nullifiers, pseudonyms, tags, tag keys,
//! subjects, and roots are compared pairwise and required distinct, and one agora's
//! terminal event — dissolution — is required invisible in the other.

#![cfg(feature = "operator")]

mod common;

use common::{admit, advance, entropy, found, Member};
use nymora_circuits::StubProver;
use nymora_core::{CeremonyMode, Epoch, MessageHash, ProtocolError, PublicParameters, RootOpening};
use nymora_crypto::{agora_id, policy_class, tag};
use nymora_ports::{SecureStorage, Slot, SoftwareKeyStore};
use nymora_proofs::{
    prove_authorship, prove_live_auth, prove_migration, prove_verification_access,
    verify_authorship, MigrationWitness,
};
use nymora_protocol::live_auth::Contribution;
use nymora_protocol::operator::{AgoraState, Executed, LogEntry};
use nymora_protocol::{authorize_migration, complete_migration, create_successor_root, Decision};

use common::DEPTH;
const GENESIS: Epoch = Epoch::new(1);

type Op = AgoraState<StubProver, DEPTH>;

#[test]
fn the_whole_lifecycle_runs_in_two_agoras_that_share_nothing() {
    // ---- Founding: identifiers and classes are derived, never assigned (§3, §5.2). ----
    let agora_a = agora_id::derive(&PublicParameters {
        ceremony: CeremonyMode::SingleParty,
        founding_key: &[0xa1; 32],
    });
    let agora_b = agora_id::derive(&PublicParameters {
        ceremony: CeremonyMode::SingleParty,
        founding_key: &[0xb2; 32],
    });
    assert_ne!(agora_a, agora_b);

    // The same tier label in both agoras: the class handle must not correlate (§5.1).
    let tier_a = policy_class::derive(&agora_a, b"tier-2");
    let tier_b = policy_class::derive(&agora_b, b"tier-2");
    assert_ne!(
        tier_a.as_bytes(),
        tier_b.as_bytes(),
        "one tier label produced one handle in two agoras"
    );

    // Alice founds A; Erin founds B. Both agoras opt into the transparency log — with
    // different log keys, since nothing may be shared.
    let mut alice = Member::<DEPTH>::enroll(0x11, agora_a, tier_a, GENESIS);
    let mut op_a: Op = found(&mut alice, 0x1b, Some(0x1c));
    let mut erin = Member::<DEPTH>::enroll(0x21, agora_b, tier_b, GENESIS);
    let mut op_b: Op = found(&mut erin, 0x2b, Some(0x2c));

    // ---- Dana joins both — same seed, adversarially (§5.1, proposal 0013). ----
    let mut dana_a = Member::<DEPTH>::enroll(0x33, agora_a, tier_a, GENESIS);
    let mut dana_b = Member::<DEPTH>::enroll(0x33, agora_b, tier_b, GENESIS);
    assert_ne!(
        dana_a.leaf, dana_b.leaf,
        "one person's leaves correlated across agoras"
    );

    admit(&mut op_a, &mut dana_a, &[&alice], 0x51);
    admit(&mut op_b, &mut dana_b, &[&erin], 0x52);
    let mut bob = Member::<DEPTH>::enroll(0x12, agora_a, tier_a, GENESIS);
    admit(&mut op_a, &mut bob, &[&alice], 0x53);
    advance(&mut op_a, &mut [&mut alice, &mut dana_a, &mut bob]);
    advance(&mut op_b, &mut [&mut erin, &mut dana_b]);

    // The epochs' roots share nothing between the agoras.
    let roots_a = alice.roots.unwrap();
    let roots_b = erin.roots.unwrap();
    assert_ne!(roots_a.class, roots_b.class);
    // Both exclusion sets are empty in both agoras, so those roots *do* coincide — the
    // empty tree is a public constant, not a correlator.

    // ---- Governance in A: the group leaves its bootstrap arithmetic (§4.3). ----
    let subject_a = op_a
        .propose(
            Decision::Policy {
                class: tier_a,
                admission_threshold: 2,
                governance_quorum: 2,
            },
            tier_a,
            entropy(0x61),
        )
        .unwrap();
    // The identical decision content raised in B derives an unrelated subject (0021).
    let subject_b = op_b
        .propose(
            Decision::Policy {
                class: tier_b,
                admission_threshold: 2,
                governance_quorum: 2,
            },
            tier_b,
            entropy(0x61),
        )
        .unwrap();
    assert_ne!(
        subject_a.as_bytes(),
        subject_b.as_bytes(),
        "one decision produced one subject in two agoras"
    );
    alice.approve(&mut op_a, subject_a);
    op_a.execute(subject_a).unwrap();
    erin.approve(&mut op_b, subject_b);
    op_b.execute(subject_b).unwrap();

    // ---- Authorship: Dana writes the same message in both agoras (§6.1). ----
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof_a, null_a) = dana_a.acting(&op_a, |witness, epoch, roots| {
        prove_authorship(&StubProver, witness, agora_a, epoch, roots, message).expect("proves")
    });
    let (_proof_b, null_b) = dana_b.acting(&op_b, |witness, epoch, roots| {
        prove_authorship(&StubProver, witness, agora_b, epoch, roots, message).expect("proves")
    });
    assert_ne!(
        null_a, null_b,
        "one authorship correlated across two agoras"
    );

    // The routing tags are unrelated, and neither agora's key resolves the other's tag
    // (§6.4): the bundle discloses nothing about which agora it belongs to.
    let key_a = &dana_a.tag_keys.last().unwrap().1;
    let key_b = &dana_b.tag_keys.last().unwrap().1;
    let tag_a = tag::tag(key_a, &message);
    let tag_b = tag::tag(key_b, &message);
    assert_ne!(tag_a, tag_b, "one message produced one tag in two agoras");
    let keys_b: Vec<_> = dana_b
        .tag_keys
        .iter()
        .map(|(_, k)| nymora_core::TagKey::new(*k.expose()))
        .collect();
    assert_eq!(
        tag::resolve(&keys_b, &message, &tag_a),
        None,
        "agora B's keys resolved agora A's tag"
    );

    // A's proof is nothing in B, even for the same message by the same person.
    assert!(!verify_authorship(
        &StubProver,
        &proof_a,
        agora_b,
        op_b.current_epoch(),
        &erin.roots.unwrap(),
        message,
        null_a
    ));

    // ---- Verification in A (§7): Bob checks Dana's bundle through the member gate. ----
    let authored_at = op_a.current_epoch();
    advance(&mut op_a, &mut [&mut alice, &mut dana_a, &mut bob]);
    let challenge = op_a.issue_challenge(entropy(0x71)).unwrap();
    let access_proof = bob.acting(&op_a, |witness, epoch, roots| {
        prove_verification_access(
            &StubProver,
            witness,
            agora_a,
            epoch,
            roots,
            challenge.as_bytes(),
        )
        .expect("proves access")
    });
    let access = op_a
        .redeem_access(tier_a, &access_proof, challenge)
        .unwrap();
    assert!(op_a
        .verify_attestation(&access, tier_a, authored_at, &proof_a, message, null_a)
        .unwrap());

    // ---- Live auth (§8): Dana and a peer in each agora, same context adversarially. ----
    // The context derivation does not absorb the agora, so a host reusing nonces across
    // agoras can produce the *same* context — exactly why 0018 absorbs the agora into the
    // pseudonym. Assert the defence: same context, unlinkable pseudonyms.
    let context = {
        let d = Contribution::new(entropy(0x81), entropy(0x82));
        let p = Contribution::new(entropy(0x83), entropy(0x84));
        let roster = [d.commitment(), p.commitment()];
        let d = d.lock(&roster).unwrap();
        let p = p.lock(&roster).unwrap();
        let reveals = [d.reveal(), p.reveal()];
        let mut scratch = [[0u8; 32]; 2];
        let session = d.finish(&reveals, &mut scratch, b"channel").unwrap();
        drop(p);
        session.context()
    };
    let (_, nym_a) = dana_a.acting(&op_a, |witness, epoch, roots| {
        prove_live_auth(&StubProver, witness, agora_a, epoch, roots, context).expect("proves")
    });
    let (_, nym_b) = dana_b.acting(&op_b, |witness, epoch, roots| {
        prove_live_auth(&StubProver, witness, agora_b, epoch, roots, context).expect("proves")
    });
    assert_ne!(
        nym_a, nym_b,
        "one person's presence correlated across agoras through a shared context"
    );

    // ---- Revocation in A (§11): Bob is expelled; B never notices. ----
    let revoke = op_a
        .propose(
            Decision::Revocation { leaf: bob.leaf },
            tier_a,
            entropy(0x63),
        )
        .unwrap();
    alice.approve(&mut op_a, revoke);
    dana_a.approve(&mut op_a, revoke);
    let bulletin = match op_a.execute(revoke).unwrap() {
        Executed::Revocation { bulletin } => bulletin,
        other => panic!("wrong effect: {other:?}"),
    };
    alice.apply_bulletin(&bulletin);
    dana_a.apply_bulletin(&bulletin);
    // Bob's next proof refuses even with fresh witnesses (worst case: he saw the bulletin).
    bob.apply_bulletin(&bulletin);
    bob.acting(&op_a, |witness, epoch, roots| {
        assert_eq!(
            prove_authorship(
                &StubProver,
                witness,
                agora_a,
                epoch,
                roots,
                MessageHash::from_bytes([0xab; 32])
            )
            .err(),
            Some(ProtocolError::Malformed)
        );
    });
    // B's revocation set is untouched: Dana still proves there, and B's current
    // revocation root is still the empty-set constant it started with.
    assert_eq!(
        op_b.current_bulletin().unwrap().revocation_root,
        roots_b.revocation,
        "a revocation in one agora moved another's set"
    );
    dana_b.acting(&op_b, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            agora_b,
            epoch,
            roots,
            MessageHash::from_bytes([0xac; 32]),
        )
        .expect("membership elsewhere is untouched by a revocation");
    });

    // ---- Planned migration in B (§9.3): Dana changes devices; A untouched. ----
    let successor_keys = SoftwareKeyStore::new([0x3c; 32]);
    let mut spk_buf = [0u8; 64];
    let mut binding = [0u8; 64];
    let written = create_successor_root(agora_b, &successor_keys, &mut spk_buf, &mut binding)
        .expect("successor root");
    let successor_pk = &spk_buf[..written.public_key];
    let mut old_pk = [0u8; 64];
    let mut cert = [0u8; 128];
    let mut handoff_bytes = [0u8; 512];
    let len = authorize_migration(
        agora_b,
        &dana_b.keys,
        &dana_b.store,
        successor_pk,
        &mut old_pk,
        &mut cert,
        &mut handoff_bytes,
    )
    .expect("authorizes");
    let handoff = nymora_core::MigrationHandoff::decode(&handoff_bytes[..len]).unwrap();
    let mut new_store = common::TestStore::default();
    let migrated = complete_migration(
        agora_b,
        &mut new_store,
        &handoff,
        successor_pk,
        entropy(0x3d),
    )
    .expect("completes");

    let mut opening = [0u8; 32];
    new_store
        .load(agora_b, Slot::RootOpening, &mut opening)
        .unwrap()
        .expect("stored");
    let successor_opening = RootOpening::new(opening);
    let inclusion = op_b
        .witness(
            dana_b.witness_key.as_ref().unwrap(),
            tier_b,
            dana_b.position,
        )
        .unwrap();
    let revocation_absence = dana_b.revocations.absence_witness(dana_b.leaf.as_bytes());
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
    let roots = dana_b.roots.unwrap();
    let (mig_proof, spend) = prove_migration(
        &StubProver,
        &witness,
        agora_b,
        roots.class,
        roots.revocation,
        migrated.commitment,
    )
    .expect("proves");
    let admission = op_b
        .migrate(tier_b, &mig_proof, spend, migrated.commitment)
        .expect("accepted");
    let bulletin_b = op_b.advance_epoch().unwrap();
    assert!(bulletin_b
        .spent
        .contains(&nymora_accumulator::exclusion::truncate_key(
            spend.as_bytes()
        )));
    erin.apply_bulletin(&bulletin_b);

    // The successor acts in B; A's spend set never moved.
    let mut dana_b2 = Member {
        seed: 0x3c,
        agora: agora_b,
        class: tier_b,
        keys: successor_keys,
        store: new_store,
        leaf: migrated.commitment,
        position: admission.position,
        revocations: nymora_accumulator::ExclusionSet::new(),
        spends: nymora_accumulator::ExclusionSet::new(),
        tag_keys: Vec::new(),
        roots: None,
        witness_key: None,
        statement_key: Some(op_b.statement_key()),
        epoch: None,
    };
    dana_b2.apply_bulletin(&bulletin_b);
    dana_b2.acting(&op_b, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            agora_b,
            epoch,
            roots,
            MessageHash::from_bytes([0xad; 32]),
        )
        .expect("the successor acts");
    });
    assert_eq!(
        op_a.current_bulletin().unwrap().spend_root,
        roots_a.spend,
        "a migration in one agora moved another's spend set"
    );
    // Dana's A-side credential is fully unaffected by her B-side device change.
    dana_a.acting(&op_a, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            agora_a,
            epoch,
            roots,
            MessageHash::from_bytes([0xae; 32]),
        )
        .expect("the A-side membership never noticed");
    });

    // ---- Lost-device recovery in A (§9.3 path 2): revoke, then ordinary re-vouch. ----
    // Dana's A-device is gone. Two members remain in A (Alice, Dana) against a quorum of
    // two, so the group first lowers its arithmetic *while it can still meet it* — a
    // group that revokes itself below its own quorum has no governance left to fix it
    // with, which is quorum freshness (§4.3) cutting both ways.
    let lower = op_a
        .propose(
            Decision::Policy {
                class: tier_a,
                admission_threshold: 1,
                governance_quorum: 1,
            },
            tier_a,
            entropy(0x66),
        )
        .unwrap();
    alice.approve(&mut op_a, lower);
    dana_a.approve(&mut op_a, lower);
    op_a.execute(lower).unwrap();

    let lost = op_a
        .propose(
            Decision::Revocation { leaf: dana_a.leaf },
            tier_a,
            entropy(0x65),
        )
        .unwrap();
    alice.approve(&mut op_a, lost);
    let bulletin = match op_a.execute(lost).unwrap() {
        Executed::Revocation { bulletin } => bulletin,
        other => panic!("wrong effect: {other:?}"),
    };
    alice.apply_bulletin(&bulletin);
    let old_dana_leaf = dana_a.leaf;

    // Fresh hardware, fresh everything, the standard vouch flow — and no continuity: the
    // new credential shares nothing with the old leaf (§9.3's accepted cost).
    let mut dana_a_new = Member::<DEPTH>::enroll(0x37, agora_a, tier_a, op_a.current_epoch());
    assert_ne!(dana_a_new.leaf, old_dana_leaf);
    admit(&mut op_a, &mut dana_a_new, &[&alice], 0x54);
    advance(&mut op_a, &mut [&mut alice, &mut dana_a_new]);
    dana_a_new.acting(&op_a, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            agora_a,
            epoch,
            roots,
            MessageHash::from_bytes([0xb0; 32]),
        )
        .expect("the recovered member acts on a structurally new credential");
    });

    // ---- Dissolution of B (§12): terminal there, invisible in A. ----
    let dissolve = op_b
        .propose(Decision::Dissolution, tier_b, entropy(0x67))
        .unwrap();
    erin.approve(&mut op_b, dissolve);
    dana_b2.approve(&mut op_b, dissolve);
    match op_b.execute(dissolve).unwrap() {
        Executed::Dissolved => {}
        other => panic!("wrong effect: {other:?}"),
    }
    assert_eq!(
        op_b.current_bulletin().unwrap_err(),
        ProtocolError::Rejected,
        "a dissolved agora still serves"
    );
    // A continues, entirely unaware: Alice acts, and A's log records no freeze.
    alice.acting(&op_a, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            agora_a,
            epoch,
            roots,
            MessageHash::from_bytes([0xaf; 32]),
        )
        .expect("the other agora's dissolution is invisible here");
    });
    let log_a = op_a.transparency_log().unwrap();
    assert!(
        !log_a
            .entries()
            .iter()
            .any(|e| matches!(e, LogEntry::Frozen { .. })),
        "one agora's dissolution appeared in another's log"
    );
    let log_b = op_b.transparency_log().unwrap();
    assert!(matches!(
        log_b.entries().last(),
        Some(LogEntry::Frozen { .. })
    ));
    // The two logs are cryptographically unrelated artifacts.
    assert_ne!(log_a.public_key(), log_b.public_key());
}
