// SPDX-License-Identifier: MIT OR Apache-2.0

//! The parity suite: the workspace primitives against the circuit stack's, value for
//! value (proposal 0035).
//!
//! The workspace (`nymora-crypto`, `nymora-accumulator`) implements the pinned
//! instances over one set of curve crates; this crate's CPU twins implement them over
//! the proving stack's own fork. These tests are what makes "same instance" a checked
//! fact rather than a claim: every derivation both sides compute is compared through
//! canonical bytes, so any divergence — an upstream constants change, a fork drifting,
//! a convention misread — fails here before it can produce an unverifiable proof.

use ff::PrimeField;
use nymora_core::{
    field_domain, AgoraId, Commitment, CredentialKey, Epoch, EpochSecretKey, MessageHash,
    RootOpening, SessionContext,
};
use nymora_crypto::field as crossing;
use nymora_crypto::{commit, live_auth, nullifier, poseidon as wposeidon, signature as wsig};
use nymora_plonk::{domains, primitives, F};

/// Workspace field element → circuit field element, by canonical bytes.
fn bridge(value: nymora_crypto::F) -> F {
    F::from_repr(crossing::to_bytes(&value)).expect("one field, one canonical encoding")
}

/// Circuit field element → canonical bytes.
fn bytes(value: F) -> [u8; 32] {
    value.to_repr()
}

#[test]
fn the_two_poseidon_implementations_agree() {
    let cases: &[&[u64]] = &[
        &[],
        &[0],
        &[1, 2],
        &[1, 2, 3],
        &[1, 2, 3, 4, 5],
        &[7, 0, 7, 0, 7, 0, 7],
        &[u64::MAX, 1, u64::MAX],
    ];
    for inputs in cases {
        let workspace: Vec<nymora_crypto::F> =
            inputs.iter().map(|v| nymora_crypto::F::from(*v)).collect();
        let circuit: Vec<F> = inputs.iter().map(|v| F::from(*v)).collect();
        assert_eq!(
            crossing::to_bytes(&wposeidon::hash(&workspace)),
            bytes(primitives::poseidon(&circuit)),
            "poseidon diverged on {inputs:?}"
        );
    }
}

/// The full-range case: an input near the top of the field, crossing both
/// implementations' Montgomery boundaries.
#[test]
fn poseidon_agrees_on_large_field_elements() {
    let near_top = {
        let mut le = [0xffu8; 32];
        le[31] = 0x3f;
        le
    };
    let workspace = crossing::decode(&near_top).expect("254 bits is canonical");
    let circuit = F::from_repr(near_top).expect("254 bits is canonical");
    assert_eq!(
        crossing::to_bytes(&wposeidon::hash(&[workspace, workspace])),
        bytes(primitives::poseidon(&[circuit, circuit])),
    );
}

#[test]
fn the_two_signature_implementations_agree() {
    let sk = wsig::mint_signing_secret([0x42; 32]);
    let message_bytes = crossing::to_bytes(&nymora_crypto::F::from(77));
    let workspace_sig = wsig::sign(&sk, &crossing::decode(&message_bytes).unwrap())
        .expect("minted keys are canonical");

    // Same secret, same message, same 64 bytes — the deterministic nonce makes this
    // exact, not merely compatible.
    let circuit_sk = Option::<midnight_curves::Fr>::from(midnight_curves::Fr::from_bytes(&sk))
        .expect("minted keys are canonical for the fork too");
    let circuit_sig = primitives::signature_bytes(&primitives::sign(
        &circuit_sk,
        F::from_repr(message_bytes).unwrap(),
    ));
    assert_eq!(
        workspace_sig, circuit_sig,
        "the certificate scheme diverged"
    );

    // And cross-verification: each side accepts the other's signature.
    let pk = wsig::public_key(&sk).expect("canonical");
    assert!(wsig::verify(
        &pk,
        &crossing::decode(&message_bytes).unwrap(),
        &circuit_sig
    ));
}

#[test]
fn the_commitment_is_the_circuit_leaf() {
    let sk_root = wsig::mint_signing_secret([0x11; 32]);
    let pk_root = wsig::public_key(&sk_root).expect("canonical");
    let sk_cred = CredentialKey::new(crossing::mint_secret([0x22; 32]));
    let r_root = RootOpening::new(crossing::mint_secret([0x33; 32]));
    let agora = AgoraId::from_bytes([0x44; 32]);

    let leaf = commit(&pk_root, &sk_cred, &r_root, &agora).expect("subgroup point");

    // The circuit side, from its own curve fork's coordinates.
    let point = Option::<midnight_curves::JubjubSubgroup>::from(
        <midnight_curves::JubjubSubgroup as group::GroupEncoding>::from_bytes(&pk_root),
    )
    .expect("subgroup point in the fork too");
    let (x, y) = primitives::coords(&point);
    let expected = primitives::poseidon(&[
        domains::tag(domains::LEAF),
        x,
        y,
        F::from_repr(*sk_cred.expose()).unwrap(),
        F::from_repr(*r_root.expose()).unwrap(),
        bridge(crossing::from_id(agora.as_bytes())),
    ]);
    assert_eq!(
        leaf.as_bytes(),
        &bytes(expected),
        "the leaf commitment diverged"
    );
}

#[test]
fn every_action_derivation_matches_the_circuit_form() {
    let agora = AgoraId::from_bytes([0x44; 32]);
    let agora_f = bridge(crossing::from_id(agora.as_bytes()));
    let sk_cred = CredentialKey::new(crossing::mint_secret([0x22; 32]));
    let sk_cred_f = F::from_repr(*sk_cred.expose()).unwrap();
    let sk_epoch = EpochSecretKey::new(wsig::mint_signing_secret([0x55; 32]));
    let sk_epoch_f = F::from_repr(*sk_epoch.expose()).unwrap();

    let derive = |tag: u64, key: F, context: F| {
        bytes(primitives::poseidon(&[
            domains::tag(domains::ACTION),
            F::from(tag),
            key,
            context,
            agora_f,
        ]))
    };

    let message = MessageHash::from_bytes([0xaa; 32]);
    assert_eq!(
        nullifier::attestation(&sk_epoch, &message, &agora).as_bytes(),
        &derive(
            field_domain::action_tag::AUTHORSHIP,
            sk_epoch_f,
            bridge(crossing::from_id(message.as_bytes()))
        ),
        "authorship diverged"
    );
    assert_eq!(
        nullifier::vouch(&sk_cred, b"session-1", &agora).as_bytes(),
        &derive(
            field_domain::action_tag::VOUCH,
            sk_cred_f,
            bridge(crossing::from_context_bytes(b"session-1"))
        ),
        "vouch diverged"
    );
    assert_eq!(
        nullifier::policy(&sk_cred, b"proposal-1", &agora).as_bytes(),
        &derive(
            field_domain::action_tag::POLICY,
            sk_cred_f,
            bridge(crossing::from_context_bytes(b"proposal-1"))
        ),
        "policy diverged"
    );
    let context = SessionContext::from_bytes([0xdd; 32]);
    assert_eq!(
        live_auth::pseudonym(&sk_epoch, &context, &agora).as_bytes(),
        &derive(
            field_domain::action_tag::LIVE_AUTH,
            sk_epoch_f,
            bridge(crossing::from_id(context.as_bytes()))
        ),
        "live-auth diverged"
    );

    let leaf = Commitment::from_bytes(bytes(F::from(9)));
    assert_eq!(
        nullifier::migration(&sk_cred, &leaf, &agora).as_bytes(),
        &bytes(primitives::poseidon(&[
            domains::tag(domains::SPEND),
            sk_cred_f,
            F::from(9),
            agora_f,
        ])),
        "the migration spend diverged"
    );
}

#[test]
fn the_certificate_messages_match_the_circuit_payloads() {
    let agora = AgoraId::from_bytes([0x44; 32]);
    let pk = wsig::public_key(&wsig::mint_signing_secret([0x55; 32])).expect("canonical");
    let point = Option::<midnight_curves::JubjubSubgroup>::from(
        <midnight_curves::JubjubSubgroup as group::GroupEncoding>::from_bytes(&pk),
    )
    .expect("subgroup point");
    let (x, y) = primitives::coords(&point);
    let agora_f = bridge(crossing::from_id(agora.as_bytes()));

    let epoch = wsig::epoch_cert_message(&agora, Epoch::new(7), &pk).expect("subgroup point");
    assert_eq!(
        crossing::to_bytes(&epoch),
        bytes(primitives::poseidon(&[
            domains::tag(domains::EPOCH_CERT),
            agora_f,
            F::from(7),
            x,
            y,
        ])),
        "the epoch-certificate message diverged"
    );

    let migration = wsig::migration_cert_message(&agora, &pk).expect("subgroup point");
    assert_eq!(
        crossing::to_bytes(&migration),
        bytes(primitives::poseidon(&[
            domains::tag(domains::MIGRATION_CERT),
            agora_f,
            x,
            y,
        ])),
        "the migration-certificate message diverged"
    );
}

#[test]
fn the_two_tree_implementations_agree() {
    const DEPTH: usize = 8;
    let leaves: Vec<u64> = (1..=5).collect();

    let mut workspace = nymora_accumulator::Tree::<DEPTH>::new();
    let mut circuit = nymora_plonk::tree::Tree::<DEPTH>::new();
    for leaf in &leaves {
        workspace
            .append(Commitment::from_bytes(bytes(F::from(*leaf))))
            .expect("room");
        circuit.append(F::from(*leaf)).expect("room");
    }
    assert_eq!(
        workspace.root().as_bytes(),
        &bytes(circuit.root()),
        "the positional trees diverged"
    );

    // And the witnesses recompute identically.
    let witness = workspace.witness(2).expect("appended");
    assert!(nymora_accumulator::verifies(
        &Commitment::from_bytes(bytes(F::from(3))),
        &witness,
        &workspace.root()
    ));
}

#[test]
fn the_two_exclusion_implementations_agree() {
    const DEPTH: usize = 8;
    let keys = [bytes(F::from(100)), bytes(F::from(7)), bytes(F::from(4000))];

    let mut workspace = nymora_accumulator::ExclusionSet::<DEPTH>::new();
    let mut circuit = nymora_plonk::exclusion::GapSet::new();
    for key in &keys {
        workspace.insert(*key);
        circuit.insert(F::from_repr(*key).unwrap());
    }
    assert_eq!(
        workspace.root().as_bytes(),
        &bytes(circuit.root::<DEPTH>()),
        "the gap trees diverged"
    );

    // Absence agrees end to end: the workspace witness verifies against the shared
    // root, and a present key fails on both sides.
    let absent = bytes(F::from(55));
    assert!(nymora_accumulator::verifies_absent(
        &absent,
        &workspace.absence_witness(&absent),
        &workspace.root()
    ));
    let present = keys[0];
    assert!(!nymora_accumulator::verifies_absent(
        &present,
        &workspace.absence_witness(&present),
        &workspace.root()
    ));
}
