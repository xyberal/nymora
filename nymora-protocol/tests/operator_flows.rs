// SPDX-License-Identifier: MIT OR Apache-2.0

//! The state machines, exercised as the protocol: real members with stored credentials
//! driving a real [`AgoraState`] through the flows of §4–§12, over software keys and stub
//! proofs.
//!
//! The exit criteria these tests carry: the §4 bootstrap arc with no founder special case
//! beyond the unavoidable ones; vouch sessions that disclose nothing incrementally and die
//! with their epoch; quorum decisions whose subjects bind their content; challenge-bound
//! verification access with single-use challenges (0019); the live-auth round deriving one
//! context for everyone; revocation taking effect at the very epoch it lands (§11);
//! migration's acceptance path with the §9.3 window at both edges; the transparency log
//! surviving audit and betraying tampering and forks; dissolution freezing everything
//! while cached history still verifies; and exhaustion refusing at the door (§5.2).

#![cfg(all(feature = "provisional-algebraic-hash", feature = "operator"))]

mod common;

use common::{admit, advance, entropy, found, Member, TestStore};
use nymora_accumulator::ExclusionSet;
use nymora_circuits::StubProver;
use nymora_core::{AgoraId, Epoch, MessageHash, PolicyClass, ProtocolError, RootOpening, TagKey};
use nymora_crypto::tag;
use nymora_ports::{SecureStorage, Slot, SoftwareKeyStore};
use nymora_proofs::{
    prove_authorship, prove_live_auth, prove_migration, prove_verification_access,
    verify_authorship, verify_live_auth, MigrationWitness,
};
use nymora_protocol::live_auth::Contribution;
use nymora_protocol::operator::{
    conforms, equivocation, verify_log, AgoraState, Executed, LogEntry,
};
use nymora_protocol::{
    authorize_migration, complete_migration, create_successor_root, load_acting_material, Decision,
};
use std::vec::Vec;

const DEPTH: usize = 4;
const AGORA: AgoraId = AgoraId::from_bytes([0x0a; 32]);
const TIER2: PolicyClass = PolicyClass::from_bytes([0x71; 32]);
const GENESIS: Epoch = Epoch::new(1);

type Op = AgoraState<StubProver, DEPTH>;

fn member(seed: u8) -> Member {
    Member::enroll(seed, AGORA, TIER2, GENESIS)
}

fn founded(founder: &mut Member, log: bool) -> Op {
    found(founder, 0x1b, if log { Some(0x1c) } else { None })
}

// ---- §4: the bootstrap arc ----

/// §4 end to end: founder alone, threshold-of-1 second admission, policy raised by
/// quorum, and every later member through the identical flow at the higher threshold.
#[test]
fn the_bootstrap_arc_reaches_a_governed_group() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, false);

    // Bob is vouched in at threshold 1 — the unavoidable §4.2 case, on the ordinary path.
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);

    // Bob is not yet present: admission lands at the boundary (proposal 0020).
    assert_eq!(
        op.witness(TIER2, bob.position).unwrap_err(),
        ProtocolError::Rejected,
        "an unlanded leaf served a witness"
    );
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Bob acts: a routine authorship proof from his stored material verifies.
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof, n) = bob.acting(&op, |witness, epoch, roots| {
        prove_authorship(&StubProver, witness, AGORA, epoch, roots, message)
            .expect("an admitted member proves")
    });
    assert!(verify_authorship(
        &StubProver,
        &proof,
        AGORA,
        op.current_epoch(),
        &op.current_roots(TIER2).unwrap(),
        message,
        n
    ));

    // The group raises the threshold to 2 and the governance quorum with it (§4.3).
    let subject = op
        .propose(
            Decision::Policy {
                class: TIER2,
                admission_threshold: 2,
                governance_quorum: 2,
            },
            TIER2,
            entropy(0x61),
        )
        .expect("proposal opens");
    alice.approve(&mut op, subject);
    match op.execute(subject).expect("quorum of one executes") {
        Executed::Policy { version } => assert_eq!(version, 2),
        other => panic!("wrong execution effect: {other:?}"),
    }

    // Charlie at threshold 2: one attestation no longer admits.
    let mut charlie = Member::enroll(0x13, AGORA, TIER2, op.current_epoch());
    op.credentials_init(charlie.leaf).unwrap();
    let session = op.start_vouch(charlie.leaf, TIER2, entropy(0x52)).unwrap();
    let (proof, n) = alice.vouch(&op, session);
    op.vouch_attest(session, &proof, n).unwrap();
    assert_eq!(
        op.vouch_finalize(session).unwrap_err(),
        ProtocolError::Rejected,
        "one attestation met a threshold of two"
    );
    // The failed finalize consumed the session — §5.3's one-time disclosure.
    let (proof, n) = bob.vouch(&op, session);
    assert_eq!(
        op.vouch_attest(session, &proof, n).unwrap_err(),
        ProtocolError::Rejected,
        "a finalized session accepted an attestation"
    );

    // Re-raised, both attest, and the identical flow admits him.
    admit(&mut op, &mut charlie, &[&alice, &bob], 0x53);
    advance(&mut op, &mut [&mut alice, &mut bob, &mut charlie]);
    charlie.acting(&op, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            AGORA,
            epoch,
            roots,
            MessageHash::from_bytes([0xab; 32]),
        )
        .expect("the third member acts like any other");
    });
}

/// §5.3's non-disclosure and distinctness, as behaviors: identical acknowledgements,
/// duplicate nullifiers refused opaquely, sessions dead at the boundary.
#[test]
fn vouch_sessions_disclose_nothing_and_die_with_their_epoch() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, false);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);

    let candidate = Member::enroll(0x14, AGORA, TIER2, op.current_epoch());
    op.credentials_init(candidate.leaf).unwrap();
    // Idempotent, indistinguishable: initializing twice is the same acknowledgement.
    assert_eq!(
        op.credentials_init(candidate.leaf).unwrap(),
        op.credentials_init(candidate.leaf).unwrap()
    );

    let session = op
        .start_vouch(candidate.leaf, TIER2, entropy(0x54))
        .unwrap();

    // Two members' acknowledgements are the same value — there is no count to read.
    let (proof_a, n_a) = alice.vouch(&op, session);
    let (proof_b, n_b) = bob.vouch(&op, session);
    let first = op.vouch_attest(session, &proof_a, n_a).unwrap();
    let second = op.vouch_attest(session, &proof_b, n_b).unwrap();
    assert_eq!(first, second, "the k-th acknowledgement differed");

    // A replayed attestation refuses like any other refusal.
    let (proof_again, n_again) = alice.vouch(&op, session);
    assert_eq!(
        n_again, n_a,
        "one credential derived two session nullifiers"
    );
    assert_eq!(
        op.vouch_attest(session, &proof_again, n_again).unwrap_err(),
        ProtocolError::Rejected
    );

    // A session opened in this epoch is unusable after the boundary (§5.3).
    let expiring = op
        .start_vouch(candidate.leaf, TIER2, entropy(0x55))
        .unwrap();
    advance(&mut op, &mut [&mut alice, &mut bob]);
    let (proof, n) = alice.vouch(&op, expiring);
    assert_eq!(
        op.vouch_attest(expiring, &proof, n).unwrap_err(),
        ProtocolError::Rejected,
        "an expired session accepted an attestation"
    );
    assert_eq!(
        op.vouch_finalize(expiring).unwrap_err(),
        ProtocolError::Rejected,
        "an expired session finalized"
    );
}

// ---- §7 / 0019: verification access ----

/// The full verification story: authored content, epoch resolved by tag, access redeemed
/// against a single-use challenge, historical roots served, and the attestation verified
/// both locally and through the consolidated round-trip.
#[test]
fn verification_is_member_gated_and_challenge_bound() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, false);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Alice authors at this epoch; the bundle's tag names the epoch's key (§6.4).
    let authored_at = op.current_epoch();
    let authored_roots = op.current_roots(TIER2).unwrap();
    let message = MessageHash::from_bytes([0xaa; 32]);
    let (proof, n) = alice.acting(&op, |witness, epoch, roots| {
        prove_authorship(&StubProver, witness, AGORA, epoch, roots, message).expect("proves")
    });
    let (_, author_tag_key) = alice.tag_keys.last().unwrap();
    let bundle_tag = tag::tag(author_tag_key, &message);

    // Time passes.
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Bob resolves the epoch from his stored tag keys (§6.4).
    let keys: Vec<TagKey> = bob
        .tag_keys
        .iter()
        .map(|(_, k)| TagKey::new(*k.expose()))
        .collect();
    let resolved = tag::resolve(&keys, &message, &bundle_tag).expect("the tag resolves");
    let resolved_epoch = bob.tag_keys[resolved].0;
    assert_eq!(resolved_epoch, authored_at);

    // Bob proves standing against a single-use challenge and gets the historical roots.
    let challenge = op.issue_challenge(entropy(0x71)).unwrap();
    let access_proof = bob.acting(&op, |witness, epoch, roots| {
        prove_verification_access(
            &StubProver,
            witness,
            AGORA,
            epoch,
            roots,
            challenge.as_bytes(),
        )
        .expect("a current member proves access")
    });
    let access = op
        .redeem_access(TIER2, &access_proof, challenge)
        .expect("access granted");

    let historical = op.roots_at(&access, TIER2, resolved_epoch).unwrap();
    assert_eq!(historical, authored_roots, "history served the wrong roots");
    assert!(verify_authorship(
        &StubProver,
        &proof,
        AGORA,
        resolved_epoch,
        &historical,
        message,
        n
    ));

    // The consolidated round-trip agrees (§7).
    assert!(op
        .verify_attestation(&access, TIER2, resolved_epoch, &proof, message, n)
        .unwrap());
    // And answers `false` — not a refusal — for a tampered claim.
    assert!(!op
        .verify_attestation(
            &access,
            TIER2,
            resolved_epoch,
            &proof,
            MessageHash::from_bytes([0xab; 32]),
            n
        )
        .unwrap());

    // The challenge is single-use: the same redemption refuses outright.
    assert_eq!(
        op.redeem_access(TIER2, &access_proof, challenge)
            .unwrap_err(),
        ProtocolError::Rejected
    );

    // Consumed on presentation, not on success: a proof bound to a *different* challenge
    // burns the presented one, and even the honest proof cannot redeem it afterwards.
    let second = op.issue_challenge(entropy(0x72)).unwrap();
    assert_eq!(
        op.redeem_access(TIER2, &access_proof, second).unwrap_err(),
        ProtocolError::Rejected
    );
    let honest = bob.acting(&op, |witness, epoch, roots| {
        prove_verification_access(&StubProver, witness, AGORA, epoch, roots, second.as_bytes())
            .expect("proves")
    });
    assert_eq!(
        op.redeem_access(TIER2, &honest, second).unwrap_err(),
        ProtocolError::Rejected,
        "a consumed challenge was redeemable"
    );

    // Access dies with its epoch.
    advance(&mut op, &mut [&mut alice, &mut bob]);
    assert_eq!(
        op.roots_at(&access, TIER2, resolved_epoch).unwrap_err(),
        ProtocolError::Rejected,
        "a stale capability still served history"
    );

    // A non-member has no path to a root (§7's premise): an outsider cannot even
    // assemble member material for this agora — their store holds nothing for it.
    let outsider = Member::enroll(0x66, AgoraId::from_bytes([0x0b; 32]), TIER2, GENESIS);
    let mut pk_buf = [0u8; 64];
    let mut record_buf = [0u8; 256];
    assert_eq!(
        load_acting_material(
            AGORA,
            &outsider.store,
            op.current_epoch(),
            &mut pk_buf,
            &mut record_buf
        )
        .err(),
        Some(ProtocolError::Unavailable),
        "an outsider assembled member material"
    );
}

// ---- §8: live authentication ----

/// A two-member live session over the machine: one context and SAS for everyone, one
/// proof per participant verified by every other, and a sybil visible as a duplicate
/// pseudonym — the offline §8.3 case being the same calls with cached roots.
#[test]
fn a_live_session_authenticates_everyone_present() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, false);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Commit, collect, reveal, derive — the transport here is function calls; QR codes
    // would carry the same values (§8.3).
    let a = Contribution::new(entropy(0x81), entropy(0x82));
    let b = Contribution::new(entropy(0x83), entropy(0x84));
    let roster = [a.commitment(), b.commitment()];
    let a = a.lock(&roster).unwrap();
    let b = b.lock(&roster).unwrap();
    let reveals = [a.reveal(), b.reveal()];
    let mut scratch = [[0u8; 32]; 2];
    let session_a = a.finish(&reveals, &mut scratch, b"call-7").unwrap();
    let session_b = b.finish(&reveals, &mut scratch, b"call-7").unwrap();
    assert_eq!(session_a.context(), session_b.context());
    assert_eq!(session_a.sas(), session_b.sas());

    // Each proves presence; each verifies the other against the same context and the
    // roots they hold — live here, pre-fetched cached ones in a §8.3 meeting, same call.
    let context = session_a.context();
    let (proof_a, nym_a) = alice.acting(&op, |witness, epoch, roots| {
        prove_live_auth(&StubProver, witness, AGORA, epoch, roots, context).expect("proves")
    });
    let (proof_b, nym_b) = bob.acting(&op, |witness, epoch, roots| {
        prove_live_auth(&StubProver, witness, AGORA, epoch, roots, context).expect("proves")
    });
    assert_ne!(nym_a, nym_b);
    let epoch = op.current_epoch();
    let roots = op.current_roots(TIER2).unwrap();
    assert!(verify_live_auth(
        &StubProver,
        &proof_b,
        AGORA,
        epoch,
        &roots,
        context,
        nym_b
    ));
    assert!(verify_live_auth(
        &StubProver,
        &proof_a,
        AGORA,
        epoch,
        &roots,
        context,
        nym_a
    ));
    // A pseudonym does not transfer between participants.
    assert!(!verify_live_auth(
        &StubProver,
        &proof_a,
        AGORA,
        epoch,
        &roots,
        context,
        nym_b
    ));

    // Sybil visibility: the same credential in one session derives one pseudonym, however
    // many seats it takes (§8.1).
    let (_, nym_a_again) = alice.acting(&op, |witness, epoch, roots| {
        prove_live_auth(&StubProver, witness, AGORA, epoch, roots, context).expect("proves")
    });
    assert_eq!(
        nym_a, nym_a_again,
        "one credential produced two pseudonyms in one session"
    );
}

// ---- §11: revocation ----

/// Revocation lands at the epoch it forces: the revoked member's next proof refuses even
/// with perfectly fresh witnesses, open business expires, and the tag key rotates away.
#[test]
fn revocation_ends_standing_at_its_own_boundary() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, false);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);
    let mut charlie = Member::enroll(0x13, AGORA, TIER2, op.current_epoch());
    admit(&mut op, &mut charlie, &[&alice], 0x52);
    advance(&mut op, &mut [&mut alice, &mut bob, &mut charlie]);

    // Raise governance to 2 so the revocation below is a real quorum act.
    let subject = op
        .propose(
            Decision::Policy {
                class: TIER2,
                admission_threshold: 2,
                governance_quorum: 2,
            },
            TIER2,
            entropy(0x61),
        )
        .unwrap();
    alice.approve(&mut op, subject);
    op.execute(subject).unwrap();

    // Charlie is active and proving; a vouch session and a proposal are open.
    charlie.acting(&op, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            AGORA,
            epoch,
            roots,
            MessageHash::from_bytes([0xaa; 32]),
        )
        .expect("a member in good standing proves");
    });
    let pending = Member::enroll(0x15, AGORA, TIER2, op.current_epoch());
    op.credentials_init(pending.leaf).unwrap();
    let open_session = op.start_vouch(pending.leaf, TIER2, entropy(0x56)).unwrap();
    let open_proposal = op
        .propose(
            Decision::Policy {
                class: TIER2,
                admission_threshold: 3,
                governance_quorum: 3,
            },
            TIER2,
            entropy(0x62),
        )
        .unwrap();
    let (_, tag_before) = alice.tag_keys.last().unwrap();
    let tag_before = TagKey::new(*tag_before.expose());

    // Alice and Bob revoke Charlie.
    let revoke = op
        .propose(
            Decision::Revocation { leaf: charlie.leaf },
            TIER2,
            entropy(0x63),
        )
        .unwrap();
    alice.approve(&mut op, revoke);
    bob.approve(&mut op, revoke);
    let bulletin = match op.execute(revoke).expect("quorum met") {
        Executed::Revocation { bulletin } => bulletin,
        other => panic!("wrong execution effect: {other:?}"),
    };
    assert!(
        bulletin.revoked.contains(charlie.leaf.as_bytes()),
        "the bulletin does not carry the revocation"
    );
    assert_ne!(
        bulletin.tag_key, tag_before,
        "the tag key did not rotate at the revocation"
    );

    // Delivery cut: remaining members apply the bulletin; Charlie receives nothing (§11).
    alice.apply_bulletin(&bulletin);
    bob.apply_bulletin(&bulletin);

    // Charlie, even granted perfectly fresh witnesses — worst case, he obtained the
    // bulletin anyway — cannot prove: his leaf is *in* the set the proof shows absence
    // from. Write capability ended at the revocation's own epoch.
    charlie.apply_bulletin(&bulletin);
    charlie.acting(&op, |witness, epoch, roots| {
        assert_eq!(
            prove_authorship(
                &StubProver,
                witness,
                AGORA,
                epoch,
                roots,
                MessageHash::from_bytes([0xab; 32]),
            )
            .err(),
            Some(ProtocolError::Malformed),
            "a revoked credential produced a proof at the revocation's own epoch"
        );
    });

    // Alice still proves — revocation touched one credential's standing, nothing else.
    alice.acting(&op, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            AGORA,
            epoch,
            roots,
            MessageHash::from_bytes([0xac; 32]),
        )
        .expect("an unrevoked member is untouched");
    });

    // The expiry cascade: the open session and proposal died with the forced boundary.
    let (proof, n) = alice.vouch(&op, open_session);
    assert_eq!(
        op.vouch_attest(open_session, &proof, n).unwrap_err(),
        ProtocolError::Rejected,
        "a vouch session survived a revocation"
    );
    assert!(
        op.proposal(&open_proposal).is_none(),
        "a proposal survived a revocation"
    );
}

// ---- §9.3: migration ----

/// The operator's acceptance path, with the §9.3 window at both edges: the superseded
/// device still writes for the remainder of the epoch, and not past it; one leaf admits
/// one successor; the successor acts from the boundary.
#[test]
fn migration_is_accepted_spent_at_the_boundary_and_unrepeatable() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, false);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Bob's new device: successor root first, then the old device authorizes.
    let successor_keys = SoftwareKeyStore::new([0x2b; 32]);
    let mut successor_pk_buf = [0u8; 64];
    let mut binding = [0u8; 64];
    let written =
        create_successor_root(AGORA, &successor_keys, &mut successor_pk_buf, &mut binding)
            .expect("successor root");
    let successor_pk = &successor_pk_buf[..written.public_key];

    let mut old_pk = [0u8; 64];
    let mut cert = [0u8; 128];
    let mut handoff_bytes = [0u8; 512];
    let len = authorize_migration(
        AGORA,
        &bob.keys,
        &bob.store,
        successor_pk,
        &mut old_pk,
        &mut cert,
        &mut handoff_bytes,
    )
    .expect("authorization succeeds");
    let handoff =
        nymora_core::MigrationHandoff::decode(&handoff_bytes[..len]).expect("handoff decodes");

    let mut new_store = TestStore::default();
    let migrated = complete_migration(AGORA, &mut new_store, &handoff, successor_pk, entropy(0x2c))
        .expect("completion succeeds");

    // The successor proves the migration against the current epoch's fixed roots.
    let mut stored_opening = [0u8; 32];
    new_store
        .load(AGORA, Slot::RootOpening, &mut stored_opening)
        .unwrap()
        .expect("successor opening stored");
    let successor_opening = RootOpening::new(stored_opening);
    let inclusion = op.witness(TIER2, bob.position).unwrap();
    let revocation_absence = bob.revocations.absence_witness(bob.leaf.as_bytes());
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
    let roots = op.current_roots(TIER2).unwrap();
    let (proof, spend) = prove_migration(
        &StubProver,
        &witness,
        AGORA,
        roots.class,
        roots.revocation,
        migrated.commitment,
    )
    .expect("the migration proves");
    assert_eq!(spend, migrated.spend);

    let admission = op
        .migrate(TIER2, &proof, spend, migrated.commitment)
        .expect("the operator accepts");
    assert_eq!(admission.active_from, op.current_epoch().next().unwrap());

    // A second successor from the same old leaf refuses immediately — the spend is
    // staged, and one leaf admits one successor (§9.3).
    assert_eq!(
        op.migrate(TIER2, &proof, spend, migrated.commitment)
            .unwrap_err(),
        ProtocolError::Rejected
    );

    // The window's near edge: the superseded device still writes this epoch (§9.3).
    bob.acting(&op, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            AGORA,
            epoch,
            roots,
            MessageHash::from_bytes([0xaa; 32]),
        )
        .expect("the superseded device keeps write capability until the boundary");
    });

    // The boundary: the spend lands and is broadcast.
    let bulletin = op.advance_epoch().unwrap();
    assert!(bulletin.spent.contains(spend.as_bytes()));
    alice.apply_bulletin(&bulletin);
    bob.apply_bulletin(&bulletin);

    // The far edge: the predecessor refuses even with fresh witnesses.
    bob.acting(&op, |witness, epoch, roots| {
        assert_eq!(
            prove_authorship(
                &StubProver,
                witness,
                AGORA,
                epoch,
                roots,
                MessageHash::from_bytes([0xab; 32]),
            )
            .err(),
            Some(ProtocolError::Malformed),
            "a superseded device wrote past the boundary"
        );
    });

    // And a post-boundary repeat of the migration refuses off the landed set.
    assert_eq!(
        op.migrate(TIER2, &proof, spend, migrated.commitment)
            .unwrap_err(),
        ProtocolError::Rejected
    );

    // The successor is a full member from its boundary: same sk_cred, its own device.
    let mut successor = Member {
        seed: 0x2b,
        agora: AGORA,
        class: TIER2,
        keys: successor_keys,
        store: new_store,
        leaf: migrated.commitment,
        position: admission.position,
        revocations: ExclusionSet::new(),
        spends: ExclusionSet::new(),
        tag_keys: Vec::new(),
    };
    successor.apply_bulletin(&bulletin);
    successor.acting(&op, |witness, epoch, roots| {
        prove_authorship(
            &StubProver,
            witness,
            AGORA,
            epoch,
            roots,
            MessageHash::from_bytes([0xac; 32]),
        )
        .expect("the successor acts from its boundary");
    });
}

// ---- §10.1: the transparency log ----

/// The log survives its own audit, betrays tampering, deletion, forgery, and forks, and
/// freezes with the agora — all from the public artifact alone.
#[test]
fn the_transparency_log_is_auditable_and_tamper_evident() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, true);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Some history: a policy change and another boundary.
    let subject = op
        .propose(
            Decision::Policy {
                class: TIER2,
                admission_threshold: 2,
                governance_quorum: 2,
            },
            TIER2,
            entropy(0x61),
        )
        .unwrap();
    alice.approve(&mut op, subject);
    op.execute(subject).unwrap();
    advance(&mut op, &mut [&mut alice, &mut bob]);

    let log = op.transparency_log().expect("this agora opted in");
    let public_key = log.public_key();
    assert!(verify_log(log.entries(), log.heads(), &public_key));
    assert!(conforms(log.entries()));
    assert!(
        log.entries()
            .iter()
            .any(|e| matches!(e, LogEntry::PolicyChanged { version: 2, .. })),
        "the policy change is not on the log"
    );

    // Tampering: rewrite one historical root and the chain breaks at every later head.
    let mut tampered: Vec<LogEntry> = log.entries().to_vec();
    for entry in &mut tampered {
        if let LogEntry::ClassRoot { root, .. } = entry {
            *root = nymora_core::Root::from_bytes([0xee; 32]);
            break;
        }
    }
    assert!(
        !verify_log(&tampered, log.heads(), &public_key),
        "a rewritten root passed the audit"
    );

    // Deletion: dropping an entry desynchronizes every head after it.
    let mut truncated: Vec<LogEntry> = log.entries().to_vec();
    truncated.remove(0);
    assert!(!verify_log(&truncated, log.heads(), &public_key));

    // A forged head fails its signature, and a forgery is not an equivocation.
    let genuine = log.heads().last().unwrap().clone();
    let mut forged = genuine.clone();
    forged.head = [0xef; 32];
    assert!(!verify_log(log.entries(), &[forged.clone()], &public_key));
    assert!(!equivocation(&genuine, &forged, &public_key));
    assert!(!equivocation(&genuine, &genuine, &public_key));

    // A real fork: a rogue operator running two views from one log key. The second view
    // shares the founding, then diverges; gossiped heads at the same sequence betray it.
    let mut alice_view_b = member(0x11);
    let mut op_b = founded(&mut alice_view_b, true);
    let mut bob_view_b = member(0x16);
    admit(&mut op_b, &mut bob_view_b, &[&alice_view_b], 0x58);
    advance(&mut op_b, &mut [&mut alice_view_b, &mut bob_view_b]);
    let log_b = op_b.transparency_log().unwrap();
    assert_eq!(
        log_b.public_key(),
        public_key,
        "the fork test needs one signing key"
    );
    let forked = log
        .heads()
        .iter()
        .zip(log_b.heads())
        .find(|(a, b)| a.head != b.head)
        .expect("the views diverge");
    assert!(
        equivocation(forked.0, forked.1, &public_key),
        "two validly signed conflicting heads were not called a fork"
    );
}

// ---- §12: dissolution ----

/// Dissolution freezes everything: every mutating and serving call refuses, while a
/// member's cached material still verifies history — §12's effects, each observed.
#[test]
fn dissolution_freezes_the_agora_terminally() {
    let mut alice = member(0x11);
    let mut op = founded(&mut alice, true);
    let mut bob = member(0x12);
    admit(&mut op, &mut bob, &[&alice], 0x51);
    advance(&mut op, &mut [&mut alice, &mut bob]);

    // Alice authors; Bob caches what verification needs *before* dissolution.
    let message = MessageHash::from_bytes([0xaa; 32]);
    let authored_at = op.current_epoch();
    let (proof, n) = alice.acting(&op, |witness, epoch, roots| {
        prove_authorship(&StubProver, witness, AGORA, epoch, roots, message).expect("proves")
    });
    let cached_roots = op.current_roots(TIER2).unwrap();

    // Quorum dissolution (§12): initiate is propose, confirm is approve, execute freezes.
    let subject = op
        .propose(Decision::Dissolution, TIER2, entropy(0x64))
        .unwrap();
    alice.approve(&mut op, subject);
    match op.execute(subject).expect("quorum met") {
        Executed::Dissolved => {}
        other => panic!("wrong execution effect: {other:?}"),
    }

    // Everything refuses now — mutation and service alike.
    assert_eq!(
        op.credentials_init(bob.leaf).unwrap_err(),
        ProtocolError::Rejected
    );
    assert_eq!(
        op.start_vouch(bob.leaf, TIER2, entropy(0x57)).unwrap_err(),
        ProtocolError::Rejected
    );
    assert_eq!(op.advance_epoch().unwrap_err(), ProtocolError::Rejected);
    assert_eq!(
        op.issue_challenge(entropy(0x73)).unwrap_err(),
        ProtocolError::Rejected
    );
    assert_eq!(
        op.propose(Decision::Dissolution, TIER2, entropy(0x65))
            .unwrap_err(),
        ProtocolError::Rejected
    );
    assert_eq!(
        op.current_roots(TIER2).unwrap_err(),
        ProtocolError::Rejected
    );
    assert_eq!(op.witness(TIER2, 0).unwrap_err(), ProtocolError::Rejected);

    // Bob's cached copy still verifies the historical attestation — §12: checkable for as
    // long as any member retains a cached copy.
    assert!(verify_authorship(
        &StubProver,
        &proof,
        AGORA,
        authored_at,
        &cached_roots,
        message,
        n
    ));

    // The log records the freeze and still audits.
    let log = op.transparency_log().expect("opted in");
    assert!(matches!(
        log.entries().last(),
        Some(LogEntry::Frozen { .. })
    ));
    assert!(verify_log(log.entries(), log.heads(), &log.public_key()));
    assert!(conforms(log.entries()));
}

// ---- §5.2: exhaustion ----

/// A full class admits nothing further — terminal, refused at session start rather than
/// after attestations were gathered, and counted against staged seats too.
#[test]
fn an_exhausted_class_refuses_at_the_door() {
    const TINY: usize = 1; // capacity 2
    let mut alice = member(0x11);
    let mut op: AgoraState<StubProver, TINY> = found(&mut alice, 0x1b, None);

    // The second member takes the final seat — staged, not yet landed.
    let mut second = member(0x12);
    admit(&mut op, &mut second, &[&alice], 0x51);

    // A third candidate is refused at the door: the staged seat already counts.
    let third = member(0x13);
    op.credentials_init(third.leaf).unwrap();
    assert_eq!(
        op.start_vouch(third.leaf, TIER2, entropy(0x52))
            .unwrap_err(),
        ProtocolError::Rejected,
        "a doomed session opened against an exhausted class"
    );

    // And after the boundary, still refused — exhaustion is terminal (§5.2).
    advance(&mut op, &mut [&mut alice, &mut second]);
    assert_eq!(
        op.start_vouch(third.leaf, TIER2, entropy(0x53))
            .unwrap_err(),
        ProtocolError::Rejected
    );
}
