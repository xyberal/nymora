// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the conformance vectors in `vectors/` against this implementation.
//!
//! Every construction here is **provisional**: accumulator nodes are recomputed inside the
//! circuit, so they use the algebraic hash of §6.5, which is not yet chosen. What these vectors
//! pin is the shape — the two domain tags, the leaf-upward sibling order, which child an index
//! bit selects, and the empty-subtree value. The digests move when the real hash arrives.
//!
//! See `../../nymora-crypto/vectors/README.md` for the settled/provisional distinction.

use nymora_accumulator::{hash_leaf, hash_node, root_from, Node, Tree, Witness};
use nymora_core::Commitment;
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
    let suite: Suite = serde_json::from_str(include_str!("../vectors/accumulator.json"))
        .expect("vectors/accumulator.json is valid JSON");

    let mut checked = 0usize;
    for construction in &suite.constructions {
        assert_eq!(
            construction.status, "provisional",
            "{} claims a settled status, but every accumulator hash is algebraic-family",
            construction.name
        );

        for case in &construction.cases {
            match construction.name.as_str() {
                "hash_leaf" => {
                    let node = hash_leaf(&Commitment::from_bytes(array(case, "value")));
                    check(&construction.name, case, node.as_bytes());
                }

                "hash_node" => {
                    let node = hash_node(
                        &Node::from_bytes(array(case, "left")),
                        &Node::from_bytes(array(case, "right")),
                    );
                    check(&construction.name, case, node.as_bytes());
                }

                "root_from" => {
                    let siblings: Vec<Node> = case["siblings"]
                        .as_array()
                        .expect("siblings is an array")
                        .iter()
                        .map(|sibling| {
                            let hex = sibling.as_str().expect("sibling is a hex string");
                            Node::from_bytes(array(&serde_json::json!({ "v": hex }), "v"))
                        })
                        .collect();
                    let siblings: [Node; 2] = siblings.try_into().expect("this vector is depth 2");

                    let witness =
                        Witness::new(case["index"].as_u64().expect("index is a number"), siblings)
                            .expect("the vector's index is within its depth");

                    let root = root_from(&Commitment::from_bytes(array(case, "value")), &witness);
                    check(&construction.name, case, root.as_bytes());
                }

                "empty_root" => {
                    assert_eq!(case["depth"].as_u64(), Some(3), "this vector is depth 3");
                    check(&construction.name, case, Tree::<3>::new().root().as_bytes());
                }

                other => panic!("no runner for construction `{other}`"),
            }
            checked += 1;
        }
    }

    assert!(checked >= 4, "only {checked} vectors ran");
}

/// The operator's tree and a member's verification must agree — the reason both halves exist.
///
/// A vector pins each side against a fixed expectation; this pins them against *each other*, so
/// a change that moved both consistently would still be caught by the vectors, and a change that
/// moved only one is caught here.
#[test]
fn what_the_tree_builds_a_witness_proves() {
    let mut tree = Tree::<4>::new();
    for byte in 0..6u8 {
        tree.append(Commitment::from_bytes([byte; 32]))
            .expect("depth 4 holds sixteen");
    }

    let root = tree.root();
    for position in 0..6u64 {
        let witness = tree.witness(position).expect("appended");
        assert!(
            nymora_accumulator::verifies(
                &Commitment::from_bytes([position as u8; 32]),
                &witness,
                &root
            ),
            "position {position} did not verify against the tree that built it"
        );
    }
}
