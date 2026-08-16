// SPDX-License-Identifier: MIT OR Apache-2.0

//! The statement tests: every clause proves when true and refuses when false.
//!
//! One backend (one SRS, both key pairs) is built once and shared; every proof runs
//! at the real `PROTOCOL_DEPTH`. The negative tests are the per-clause vectors
//! proposal 0034 mandates: each mutates exactly one clause's witness or instance and
//! demands that no valid proof can come out — `prove` refusing (the CPU evaluator
//! catching it) and a proof failing verification are both acceptable refusals, a
//! proof that *verifies* is the failure.

use ff::Field;
use nymora_plonk::backend::Backend;
use nymora_plonk::chain::{ChainInstance, ChainWitness};
use nymora_plonk::domains::action_tag;
use nymora_plonk::exclusion::GapSet;
use nymora_plonk::migration::{MigrationInstance, MigrationWitness};
use nymora_plonk::primitives::{
    coords, poseidon, public_key, scalar_as_field, scalar_bytes, sign, Signature,
};
use nymora_plonk::tree::Tree;
use nymora_plonk::{domains, F, PROTOCOL_DEPTH};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEPTH: usize = PROTOCOL_DEPTH;

use std::sync::OnceLock;

/// The shared backend: built once, at the real depth, over the insecure test SRS.
fn backend() -> &'static Backend<DEPTH> {
    static BACKEND: OnceLock<Backend<DEPTH>> = OnceLock::new();
    BACKEND.get_or_init(|| Backend::insecure_for_tests(0x4e594d4f52410002))
}

/// A member's whole world: keys, certificate, tree position, exclusion witnesses.
struct World {
    witness: ChainWitness<DEPTH>,
    instance_base: ChainInstance,
    // Kept for deriving actions and migrations.
    epoch_key: midnight_curves::Fr,
    credential_key: F,
    root_key: midnight_curves::Fr,
    leaf: F,
    revocations: GapSet,
    spends: GapSet,
    class_tree: Tree<DEPTH>,
    position: usize,
}

fn world_with(mutate: impl FnOnce(&mut GapSet, &mut GapSet, F)) -> World {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let agora = F::random(&mut rng);
    let epoch = F::from(7);

    let root_key = midnight_curves::Fr::random(&mut rng);
    let root_public_key = public_key(&root_key);
    let credential_key = F::random(&mut rng);
    let root_opening = F::random(&mut rng);

    let (pk_x, pk_y) = coords(&root_public_key);
    let leaf = poseidon(&[
        domains::tag(domains::LEAF),
        pk_x,
        pk_y,
        credential_key,
        root_opening,
        agora,
    ]);

    let mut class_tree = Tree::<DEPTH>::new();
    class_tree.append(F::from(999)).expect("room");
    let position = class_tree.append(leaf).expect("room");

    let epoch_key = midnight_curves::Fr::random(&mut rng);
    let epoch_public_key = public_key(&epoch_key);
    let (epk_x, epk_y) = coords(&epoch_public_key);
    let payload = poseidon(&[
        domains::tag(domains::EPOCH_CERT),
        agora,
        epoch,
        epk_x,
        epk_y,
    ]);
    let epoch_certificate = sign(&root_key, payload);

    let spend = poseidon(&[domains::tag(domains::SPEND), credential_key, leaf, agora]);

    let mut revocations = GapSet::new();
    let mut spends = GapSet::new();
    mutate(&mut revocations, &mut spends, leaf);

    let witness = ChainWitness {
        epoch_key_bytes: scalar_bytes(&epoch_key),
        epoch_public_key,
        epoch_certificate,
        credential_key,
        root_opening,
        root_public_key,
        class_path: class_tree.witness(position).expect("appended"),
        revocation_absence: revocations.absence_witness::<DEPTH>(leaf),
        spend_absence: spends.absence_witness::<DEPTH>(spend),
    };
    let instance_base = ChainInstance {
        agora,
        epoch,
        class_root: class_tree.root(),
        revocation_root: revocations.root::<DEPTH>(),
        spend_root: spends.root::<DEPTH>(),
        action_tag: F::from(0),
        action_context: F::from(0),
        action_output: F::from(0),
    };
    World {
        witness,
        instance_base,
        epoch_key,
        credential_key,
        root_key,
        leaf,
        revocations,
        spends,
        class_tree,
        position,
    }
}

fn world() -> World {
    world_with(|_, _, _| {})
}

impl World {
    /// The instance for an action, output derived honestly.
    fn action(&self, tag: u64, context: F) -> ChainInstance {
        let key = match tag {
            t if t == action_tag::AUTHORSHIP || t == action_tag::LIVE_AUTH => {
                scalar_as_field(&self.epoch_key)
            }
            _ => self.credential_key,
        };
        let output = if tag == action_tag::VERIFICATION {
            F::from(0)
        } else {
            poseidon(&[
                domains::tag(domains::ACTION),
                F::from(tag),
                key,
                context,
                self.instance_base.agora,
            ])
        };
        ChainInstance {
            action_tag: F::from(tag),
            action_context: context,
            action_output: output,
            ..self.instance_base
        }
    }
}

/// No valid proof may come out of (witness, instance): refusal at prove time and a
/// failing proof are both honest; a verifying proof is the bug.
fn assert_unprovable(witness: &ChainWitness<DEPTH>, instance: &ChainInstance) {
    match backend().prove_chain(witness, instance) {
        Err(_) => {}
        Ok(proof) => assert!(
            !backend().verify_chain(&proof, instance),
            "a false statement produced a verifying proof"
        ),
    }
}

#[test]
fn every_action_proves_and_verifies() {
    let world = world();
    for tag in [
        action_tag::AUTHORSHIP,
        action_tag::VOUCH,
        action_tag::POLICY,
        action_tag::LIVE_AUTH,
        action_tag::VERIFICATION,
    ] {
        let instance = world.action(tag, F::from(1000 + tag));
        let proof = backend()
            .prove_chain(&world.witness, &instance)
            .expect("a satisfied statement must prove");
        assert!(backend().verify_chain(&proof, &instance), "tag {tag}");
    }
}

#[test]
fn verify_rejects_every_rebinding() {
    let world = world();
    let instance = world.action(action_tag::AUTHORSHIP, F::from(1234));
    let proof = backend()
        .prove_chain(&world.witness, &instance)
        .expect("a satisfied statement must prove");

    let rebindings = [
        ChainInstance {
            agora: F::from(99),
            ..instance
        },
        ChainInstance {
            epoch: F::from(8),
            ..instance
        },
        ChainInstance {
            class_root: F::from(99),
            ..instance
        },
        ChainInstance {
            revocation_root: F::from(99),
            ..instance
        },
        ChainInstance {
            spend_root: F::from(99),
            ..instance
        },
        ChainInstance {
            action_context: F::from(4321),
            ..instance
        },
        ChainInstance {
            action_output: F::from(99),
            ..instance
        },
    ];
    for rebound in rebindings {
        assert!(
            !backend().verify_chain(&proof, &rebound),
            "a rebound proof verified"
        );
    }
}

#[test]
fn one_action_does_not_verify_as_another() {
    let world = world();
    let context = F::from(555);
    let authorship = world.action(action_tag::AUTHORSHIP, context);
    let proof = backend()
        .prove_chain(&world.witness, &authorship)
        .expect("a satisfied statement must prove");
    // Same context, next tag — and even the correct output *for that tag*.
    let as_vouch = world.action(action_tag::VOUCH, context);
    assert!(!backend().verify_chain(&proof, &as_vouch));
}

#[test]
fn a_revoked_leaf_cannot_prove() {
    let world = world_with(|revocations, _, leaf| {
        revocations.insert(leaf);
    });
    let instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn a_spent_leaf_cannot_prove() {
    let world = world_with(|_, spends, _| {
        // The spend nullifier is deterministic from the fixture's seeds; recompute
        // it the way the fixture does, by poisoning after the leaf is known.
        let _ = spends;
    });
    // Poison the spend set with the real spend nullifier and rebuild the witness.
    let mut spends = world.spends.clone();
    let spend = poseidon(&[
        domains::tag(domains::SPEND),
        world.credential_key,
        world.leaf,
        world.instance_base.agora,
    ]);
    spends.insert(spend);
    let witness = ChainWitness {
        spend_absence: spends.absence_witness::<DEPTH>(spend),
        ..world.witness.clone()
    };
    let instance = ChainInstance {
        spend_root: spends.root::<DEPTH>(),
        ..world.action(action_tag::AUTHORSHIP, F::from(1))
    };
    assert_unprovable(&witness, &instance);
}

#[test]
fn a_wrong_nullifier_cannot_prove() {
    let world = world();
    let mut instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    instance.action_output = F::from(0xbad);
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn verification_access_must_output_zero() {
    let world = world();
    let mut instance = world.action(action_tag::VERIFICATION, F::from(77));
    instance.action_output = F::from(1);
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn an_out_of_range_action_tag_cannot_prove() {
    let world = world();
    let mut instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    instance.action_tag = F::from(5);
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn a_certificate_for_another_epoch_cannot_prove() {
    let world = world();
    let instance = ChainInstance {
        epoch: F::from(8),
        ..world.action(action_tag::AUTHORSHIP, F::from(1))
    };
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn a_certificate_by_a_stranger_cannot_prove() {
    let mut world = world();
    // A stranger signs a perfectly well-formed certificate over the same epoch key —
    // but the stranger's key is not the one committed in the leaf.
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let stranger = midnight_curves::Fr::random(&mut rng);
    let (epk_x, epk_y) = coords(&world.witness.epoch_public_key);
    let payload = poseidon(&[
        domains::tag(domains::EPOCH_CERT),
        world.instance_base.agora,
        world.instance_base.epoch,
        epk_x,
        epk_y,
    ]);
    world.witness.epoch_certificate = sign(&stranger, payload);
    let instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn an_uncertified_epoch_key_cannot_act() {
    let mut world = world();
    // A fresh epoch key the root never certified: correspondence holds for it, the
    // certificate does not.
    let mut rng = ChaCha20Rng::seed_from_u64(98);
    let rogue = midnight_curves::Fr::random(&mut rng);
    world.witness.epoch_key_bytes = scalar_bytes(&rogue);
    world.witness.epoch_public_key = public_key(&rogue);
    let instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    // The honest output for the rogue key, so only the certificate clause is false.
    let mut instance = instance;
    instance.action_output = poseidon(&[
        domains::tag(domains::ACTION),
        instance.action_tag,
        scalar_as_field(&rogue),
        instance.action_context,
        instance.agora,
    ]);
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn a_leaf_the_secrets_do_not_open_cannot_prove() {
    let mut world = world();
    world.witness.credential_key = F::from(0xbad);
    let instance = world.action(action_tag::VERIFICATION, F::from(1));
    assert_unprovable(&world.witness, &instance);
}

#[test]
fn a_non_canonical_epoch_key_representation_cannot_prove() {
    use ff::PrimeField;
    let world = world();
    // Add the Jubjub group order to the canonical bytes: same scalar, different
    // representation — the canonicity clause must refuse it, or one key could mint
    // several nullifier streams.
    let canonical = num_bigint::BigUint::from_bytes_le(&world.witness.epoch_key_bytes);
    let order = num_bigint::BigUint::parse_bytes(
        midnight_curves::Fr::MODULUS
            .trim_start_matches("0x")
            .as_bytes(),
        16,
    )
    .expect("valid hex");
    let shifted = &canonical + &order;
    let mut bytes = [0u8; 32];
    let shifted_bytes = shifted.to_bytes_le();
    // Skip if the shifted representation no longer fits 32 bytes meaningfully below
    // the circuit field — it always fits: order < 2^252, canonical < order.
    bytes[..shifted_bytes.len()].copy_from_slice(&shifted_bytes);
    let witness = ChainWitness {
        epoch_key_bytes: bytes,
        ..world.witness.clone()
    };
    let instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    assert_unprovable(&witness, &instance);
}

#[test]
fn migration_proves_and_a_laundered_successor_cannot() {
    let world = world();
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let successor_key = midnight_curves::Fr::random(&mut rng);
    let successor_public_key = public_key(&successor_key);
    let successor_opening = F::random(&mut rng);
    let (succ_x, succ_y) = coords(&successor_public_key);

    let payload = poseidon(&[
        domains::tag(domains::MIGRATION_CERT),
        world.instance_base.agora,
        succ_x,
        succ_y,
    ]);
    let migration_certificate = sign(&world.root_key, payload);

    let spend = poseidon(&[
        domains::tag(domains::SPEND),
        world.credential_key,
        world.leaf,
        world.instance_base.agora,
    ]);
    let successor_commitment = poseidon(&[
        domains::tag(domains::LEAF),
        succ_x,
        succ_y,
        world.credential_key,
        successor_opening,
        world.instance_base.agora,
    ]);

    let witness = MigrationWitness {
        old_root_public_key: world.witness.root_public_key,
        old_root_opening: world.witness.root_opening,
        credential_key: world.credential_key,
        old_class_path: world.class_tree.witness(world.position).expect("appended"),
        migration_certificate,
        successor_public_key,
        successor_opening,
        revocation_absence: world.revocations.absence_witness::<DEPTH>(world.leaf),
    };
    let instance = MigrationInstance {
        agora: world.instance_base.agora,
        class_root: world.instance_base.class_root,
        revocation_root: world.instance_base.revocation_root,
        spend_nullifier: spend,
        successor_commitment,
    };

    let proof = backend()
        .prove_migration(&witness, &instance)
        .expect("a satisfied migration must prove");
    assert!(backend().verify_migration(&proof, &instance));

    // Laundering: a successor commitment over a fresh credential key must not prove,
    // and the valid proof must not verify against it.
    let laundered = MigrationInstance {
        successor_commitment: poseidon(&[
            domains::tag(domains::LEAF),
            succ_x,
            succ_y,
            F::from(0x5eed),
            successor_opening,
            world.instance_base.agora,
        ]),
        ..instance
    };
    assert!(backend().prove_migration(&witness, &laundered).is_err());
    assert!(!backend().verify_migration(&proof, &laundered));

    // And a wrong spend nullifier is refused the same way.
    let wrong_spend = MigrationInstance {
        spend_nullifier: F::from(0xbad),
        ..instance
    };
    assert!(backend().prove_migration(&witness, &wrong_spend).is_err());
    assert!(!backend().verify_migration(&proof, &wrong_spend));
}

#[test]
fn a_revoked_credential_cannot_migrate() {
    let world = world_with(|revocations, _, leaf| {
        revocations.insert(leaf);
    });
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let successor_key = midnight_curves::Fr::random(&mut rng);
    let successor_public_key = public_key(&successor_key);
    let successor_opening = F::random(&mut rng);
    let (succ_x, succ_y) = coords(&successor_public_key);
    let payload = poseidon(&[
        domains::tag(domains::MIGRATION_CERT),
        world.instance_base.agora,
        succ_x,
        succ_y,
    ]);
    let witness = MigrationWitness {
        old_root_public_key: world.witness.root_public_key,
        old_root_opening: world.witness.root_opening,
        credential_key: world.credential_key,
        old_class_path: world.class_tree.witness(world.position).expect("appended"),
        migration_certificate: sign(&world.root_key, payload),
        successor_public_key,
        successor_opening,
        revocation_absence: world.revocations.absence_witness::<DEPTH>(world.leaf),
    };
    let instance = MigrationInstance {
        agora: world.instance_base.agora,
        class_root: world.instance_base.class_root,
        revocation_root: world.instance_base.revocation_root,
        spend_nullifier: poseidon(&[
            domains::tag(domains::SPEND),
            world.credential_key,
            world.leaf,
            world.instance_base.agora,
        ]),
        successor_commitment: poseidon(&[
            domains::tag(domains::LEAF),
            succ_x,
            succ_y,
            world.credential_key,
            successor_opening,
            world.instance_base.agora,
        ]),
    };
    match backend().prove_migration(&witness, &instance) {
        Err(_) => {}
        Ok(proof) => assert!(!backend().verify_migration(&proof, &instance)),
    }
}

#[test]
fn a_forged_certificate_signature_cannot_prove() {
    let mut world = world();
    // Flip the response scalar: the equation must fail in-circuit.
    world.witness.epoch_certificate = Signature {
        s: world.witness.epoch_certificate.s + midnight_curves::Fr::from(1u64),
        ..world.witness.epoch_certificate
    };
    let instance = world.action(action_tag::AUTHORSHIP, F::from(1));
    assert_unprovable(&world.witness, &instance);
}
