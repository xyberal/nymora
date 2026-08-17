// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the conformance vectors in `vectors/` against this implementation.
//!
//! Every expected value here was computed by a second implementation of the same
//! pinned instances — the proving stack's own CPU primitives — not by this crate, so
//! the vectors validate the construction rather than merely recording its output (see
//! `../../nymora-crypto/vectors/README.md`). What they pin: the untagged 2-to-1 node,
//! the leaf-enters-as-itself fold with its index-bit child selection, the zero empty
//! subtree, and the gap-tree exclusion roots with their sentinels (proposal 0035).

// Building the trees and sets needs the `build` feature; without it there is nothing
// to run the vectors against.
#![cfg(feature = "build")]

use nymora_accumulator::{hash_node, root_from, ExclusionSet, Node, Tree, Witness};
use nymora_core::{Commitment, Root};
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

fn hex_array(value: &serde_json::Value) -> [u8; 32] {
    let hex = value.as_str().expect("entry is a hex string");
    bytes(&serde_json::json!({ "v": hex }), "v")
        .try_into()
        .expect("entry is 32 bytes")
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
            construction.status.as_str(),
            "settled",
            "{} carries an unrecognised status `{}`",
            construction.name,
            construction.status
        );
        for case in &construction.cases {
            match construction.name.as_str() {
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
                        .map(|s| Node::from_bytes(hex_array(s)))
                        .collect();
                    let siblings: [Node; 2] =
                        siblings.try_into().expect("this vector is cut at depth 2");
                    let witness = Witness::<2>::new(
                        case["index"].as_u64().expect("index is a number"),
                        siblings,
                    )
                    .expect("the vector index is within depth");
                    let root = root_from(&Commitment::from_bytes(array(case, "value")), &witness);
                    check(&construction.name, case, root.as_bytes());
                }

                "empty_root" => {
                    assert_eq!(
                        case["depth"].as_u64(),
                        Some(3),
                        "this vector is cut at depth 3"
                    );
                    let empty: Root = Tree::<3>::new().root();
                    check(&construction.name, case, empty.as_bytes());
                }

                "exclusion_root" => {
                    assert_eq!(
                        case["depth"].as_u64(),
                        Some(4),
                        "this vector is cut at depth 4"
                    );
                    let mut set = ExclusionSet::<4>::new();
                    for key in case["keys"].as_array().expect("keys is an array") {
                        set.insert(hex_array(key));
                    }
                    check(&construction.name, case, set.root().as_bytes());
                }

                other => panic!("no runner for construction `{other}`"),
            }
            checked += 1;
        }
    }

    assert!(checked >= 5, "only {checked} vectors ran");
}
