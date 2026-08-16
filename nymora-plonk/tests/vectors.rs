// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer pins for the instances proposal 0034 fixes.
//!
//! These constants were computed from this crate once and frozen. They pin the
//! Poseidon instance (width, rounds, Grain constants) and the certificate scheme
//! transitively: if the upstream implementation ever changes an instance — a round
//! count, a constant, a transcript detail — these tests break loudly instead of the
//! protocol quietly forking its own history. They are the working form of 0034's
//! "constants artifact" open question until the conformance vectors regenerate.

use ff::PrimeField;
use nymora_plonk::primitives::{poseidon, public_key, sign, signature_bytes, verify};
use nymora_plonk::F;

fn hex(value: F) -> String {
    let repr = value.to_repr();
    repr.as_ref()
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn print_or_check(label: &str, actual: String, expected: &str) {
    if expected.is_empty() {
        println!("{label}: {actual}");
    } else {
        assert_eq!(actual, expected, "{label} drifted");
    }
}

#[test]
fn poseidon_known_answers() {
    print_or_check(
        "poseidon(1,2)",
        hex(poseidon(&[F::from(1), F::from(2)])),
        "4ad818f39d91567d105c5bea1ec4b5ac201dc45b784e39a2beef781790bf5177",
    );
    print_or_check(
        "poseidon(1..5)",
        hex(poseidon(&[
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
        ])),
        "03d92ce21dccdc1597cdbbcd35545745f21fd11bd29ce099e3f5b3d6bad41f17",
    );
    print_or_check(
        "poseidon(1..6)",
        hex(poseidon(&[
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
            F::from(6),
        ])),
        "5265f4c28c2a132d7b2dc529dd3cf70ce03ca0899da200befb401f0d6316eac4",
    );
}

#[test]
fn certificate_known_answer() {
    let sk = midnight_curves::Fr::from(42u64);
    let message = F::from(7);
    let signature = sign(&sk, message);
    assert!(verify(&signature, &public_key(&sk), message));
    let bytes = signature_bytes(&signature);
    let rendered: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    print_or_check(
        "sign(42, 7)",
        rendered,
        "2f3143d77a2b1106956f3eec2a0b741dd869d5f12b57bfe800670598bbd517814d83cbd41f12c0f3c52618d3fe7ae8d28589bfb34359cf919ec40da5ce66f502",
    );
}

#[test]
fn the_statements_fit_the_inherited_string() {
    // Filecoin's phase-1 string covers 2^19 rows; the statements must sit inside it
    // with room to grow (proposal 0034's reference-string decision).
    let k = nymora_plonk::backend::Backend::<{ nymora_plonk::PROTOCOL_DEPTH }>::required_k();
    println!("required_k at depth {}: {k}", nymora_plonk::PROTOCOL_DEPTH);
    assert!(
        k <= 19,
        "the statement outgrew the inherited reference string"
    );
}
