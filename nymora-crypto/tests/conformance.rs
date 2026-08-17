// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the conformance vectors in `vectors/` against this implementation.
//!
//! These are the interoperable form of the in-module `known_answer` tests: the same values, in a
//! format a second implementation in another language can consume. See `vectors/README.md` for
//! what `settled` and `provisional` mean.
//!
//! The fixture types live here rather than in `nymora-core` behind a feature. Phase 1 expected a
//! dev-dependency cycle and reserved a home for them; per-crate vectors avoid it, since nothing
//! outside this file needs to name these shapes.

use nymora_core::{
    AgoraId, CeremonyMode, Commitment, CredentialKey, Domain, Epoch, EpochSecretKey, MessageHash,
    Nullifier, PublicParameters, RootOpening, SessionContext, TagKey,
};
use nymora_crypto::{
    agora_id, commit, derive_tag_key, field, kdf, live_auth, nullifier, policy_class, signature,
    tag, ByteHasher,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Suite {
    constructions: Vec<Construction>,
}

#[derive(Deserialize)]
struct Construction {
    name: String,
    status: String,
    cases: Vec<serde_json::Value>,
}

/// Lowercase hex to bytes. Rejects anything that is not a byte string, since a malformed vector
/// silently skipped would be worse than one that fails.
fn bytes(value: &serde_json::Value, field: &str) -> Vec<u8> {
    let hex = value[field]
        .as_str()
        .unwrap_or_else(|| panic!("field `{field}` is missing or not a string"));
    assert!(hex.len() % 2 == 0, "field `{field}` has an odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&hex[at..at + 2], 16)
                .unwrap_or_else(|_| panic!("field `{field}` is not hex"))
        })
        .collect()
}

fn array(value: &serde_json::Value, field: &str) -> [u8; 32] {
    bytes(value, field)
        .try_into()
        .unwrap_or_else(|_| panic!("field `{field}` is not 32 bytes"))
}

fn domain_named(tag: &str) -> Domain {
    *Domain::ALL
        .iter()
        .find(|domain| domain.tag() == tag)
        .unwrap_or_else(|| panic!("no domain tag `{tag}` in the registry"))
}

fn check(construction: &str, case: &serde_json::Value, actual: &[u8; 32]) {
    let name = case["name"].as_str().unwrap_or("<unnamed>");
    assert_eq!(
        actual.as_slice(),
        bytes(case, "output"),
        "{construction}/{name} does not match its vector"
    );
}

#[test]
fn every_vector_matches() {
    let suite: Suite = serde_json::from_str(include_str!("../vectors/crypto.json"))
        .expect("vectors/crypto.json is valid JSON");

    let mut checked = 0usize;
    for construction in &suite.constructions {
        assert_eq!(
            construction.status.as_str(),
            "settled",
            "{} carries an unrecognised status `{}` — nothing is provisional after the swap              (proposal 0035)",
            construction.name,
            construction.status
        );

        for case in &construction.cases {
            match construction.name.as_str() {
                "hash" => {
                    let mut hasher = ByteHasher::new(domain_named(
                        case["domain"].as_str().expect("domain is a string"),
                    ));
                    for input in case["inputs"].as_array().expect("inputs is an array") {
                        let hex = input.as_str().expect("input is a hex string");
                        let raw = bytes(&serde_json::json!({ "v": hex }), "v");
                        hasher = hasher.absorb(&raw);
                    }
                    check(&construction.name, case, &hasher.finalize());
                }

                "kdf" => {
                    let derived = kdf::derive(
                        domain_named(case["domain"].as_str().expect("domain is a string")),
                        &bytes(case, "ikm"),
                        &bytes(case, "context"),
                    );
                    check(&construction.name, case, &derived);
                }

                "agora_id" => {
                    let encoded = bytes(case, "ceremony");
                    let ceremony = if encoded[0] == 0 {
                        CeremonyMode::SingleParty
                    } else {
                        CeremonyMode::Threshold {
                            threshold: u16::from_le_bytes([encoded[1], encoded[2]]),
                            parties: u16::from_le_bytes([encoded[3], encoded[4]]),
                        }
                    };
                    let derived = agora_id::derive(&PublicParameters {
                        ceremony,
                        founding_key: &bytes(case, "founding_key"),
                    });
                    check(&construction.name, case, derived.as_bytes());
                }

                "policy_class" => {
                    let derived = policy_class::derive(
                        &AgoraId::from_bytes(array(case, "agora_id")),
                        &bytes(case, "label"),
                    );
                    check(&construction.name, case, derived.as_bytes());
                }

                "derive_tag_key" => {
                    let derived = derive_tag_key(
                        &bytes(case, "agora_secret"),
                        &AgoraId::from_bytes(array(case, "agora_id")),
                        Epoch::new(case["epoch"].as_u64().expect("epoch is a number")),
                    );
                    check(&construction.name, case, derived.expose());
                }

                "tag" => {
                    let routed = tag(
                        &TagKey::new(array(case, "key")),
                        &MessageHash::from_bytes(array(case, "message_hash")),
                    );
                    check(&construction.name, case, routed.as_bytes());
                }

                "live_auth_commitment" => {
                    let committed =
                        live_auth::commitment(&array(case, "nonce"), &array(case, "blinding"));
                    check(&construction.name, case, committed.as_bytes());
                }

                "live_auth_context" => {
                    let mut nonces: Vec<[u8; 32]> = case["nonces"]
                        .as_array()
                        .expect("nonces is an array")
                        .iter()
                        .map(|nonce| {
                            let hex = nonce.as_str().expect("nonce is a hex string");
                            bytes(&serde_json::json!({ "v": hex }), "v")
                                .try_into()
                                .expect("nonce is 32 bytes")
                        })
                        .collect();
                    let derived = live_auth::context(&mut nonces, &bytes(case, "channel_metadata"));
                    check(&construction.name, case, derived.as_bytes());
                }

                // The one construction whose output is not 32 bytes: the SAS is short by
                // design, so it is compared directly rather than through `check`.
                "live_auth_sas" => {
                    let short = live_auth::sas(&SessionContext::from_bytes(array(case, "context")));
                    assert_eq!(
                        short.as_slice(),
                        bytes(case, "output"),
                        "live_auth_sas does not match its vector"
                    );
                }

                "pseudonym" => {
                    let derived = live_auth::pseudonym(
                        &EpochSecretKey::new(array(case, "key")),
                        &SessionContext::from_bytes(array(case, "context")),
                        &AgoraId::from_bytes(array(case, "agora_id")),
                    );
                    check(&construction.name, case, derived.as_bytes());
                }

                "commit" => {
                    let leaf = commit(
                        &bytes(case, "pk_root"),
                        &CredentialKey::new(array(case, "sk_cred")),
                        &RootOpening::new(array(case, "r_root")),
                        &AgoraId::from_bytes(array(case, "agora_id")),
                    )
                    .expect("the vector's root key is a subgroup point");
                    check(&construction.name, case, leaf.as_bytes());
                }

                "epoch_cert_message" => {
                    let message = signature::epoch_cert_message(
                        &AgoraId::from_bytes(array(case, "agora_id")),
                        Epoch::new(case["epoch"].as_u64().expect("epoch is a number")),
                        &bytes(case, "epoch_public_key"),
                    )
                    .expect("the vector's key is a subgroup point");
                    check(&construction.name, case, &field::to_bytes(&message));
                }

                "migration_cert_message" => {
                    let message = signature::migration_cert_message(
                        &AgoraId::from_bytes(array(case, "agora_id")),
                        &bytes(case, "successor_public_key"),
                    )
                    .expect("the vector's key is a subgroup point");
                    check(&construction.name, case, &field::to_bytes(&message));
                }

                // The one construction whose output is 64 bytes: the certificate
                // signature, deterministic by §9.1's nonce obligation.
                "certificate_sign" => {
                    let sk = array(case, "sk");
                    let message =
                        field::decode(&array(case, "message_field")).expect("canonical message");
                    let signed =
                        signature::sign(&sk, &message).expect("the vector's key is canonical");
                    assert_eq!(
                        signed.as_slice(),
                        bytes(case, "output"),
                        "certificate_sign does not match its vector"
                    );
                    let pk = bytes(case, "public_key");
                    assert!(
                        signature::verify(&pk, &message, &signed),
                        "the vector signature does not verify under its own key"
                    );
                }

                "nullifier" => {
                    let produced: Nullifier = match case["context"].as_str().expect("context") {
                        "vouch" => nullifier::vouch(
                            &CredentialKey::new(array(case, "key")),
                            &bytes(case, "scope"),
                            &AgoraId::from_bytes(array(case, "agora_id")),
                        ),
                        "attestation" => nullifier::attestation(
                            &EpochSecretKey::new(array(case, "key")),
                            &MessageHash::from_bytes(array(case, "scope")),
                            &AgoraId::from_bytes(array(case, "agora_id")),
                        ),
                        "policy" => nullifier::policy(
                            &CredentialKey::new(array(case, "key")),
                            &bytes(case, "scope"),
                            &AgoraId::from_bytes(array(case, "agora_id")),
                        ),
                        "migration" => nullifier::migration(
                            &CredentialKey::new(array(case, "key")),
                            &Commitment::from_bytes(array(case, "leaf")),
                            &AgoraId::from_bytes(array(case, "agora_id")),
                        ),
                        other => panic!("no nullifier context `{other}`"),
                    };
                    check(&construction.name, case, produced.as_bytes());
                }

                other => panic!("no runner for construction `{other}`"),
            }
            checked += 1;
        }
    }

    // A harness that silently ran nothing would pass forever. Cheap insurance, and the same
    // failure the secret scan was once found to have.
    assert!(checked >= 23, "only {checked} vectors ran");
}

/// A `Commitment` is not a `Nullifier` even where the bytes coincide, and the vectors must not
/// quietly rely on them being interchangeable.
#[test]
fn the_vector_types_stay_distinct() {
    let raw = [0x11u8; 32];
    assert_eq!(Commitment::from_bytes(raw).as_bytes(), &raw);
    assert_eq!(Nullifier::from_bytes(raw).as_bytes(), &raw);
}
