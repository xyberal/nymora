// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regenerates the workspace conformance vectors from this crate's primitives.
//!
//! The workspace's vectors must be computed independently of the code under test
//! (`nymora-crypto`, `nymora-accumulator`); this generator is that independence: the
//! same pinned instances, implemented over the proving stack's own curve fork, with
//! the byte-family canonicalization restated locally from the specification rather
//! than imported. Run with:
//!
//! ```sh
//! cargo test --release --test generate_vectors -- --ignored --nocapture
//! ```
//!
//! and transcribe the printed values into `nymora-crypto/vectors/crypto.json` and
//! `nymora-accumulator/vectors/accumulator.json`.

use ff::PrimeField;
use group::{Group, GroupEncoding};
use midnight_curves::{Fr as JubjubScalar, JubjubSubgroup};
use nymora_plonk::{domains, primitives, F};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn field_hex(value: F) -> String {
    hex(&value.to_repr())
}

/// The identifier rule of proposal 0035, restated: little-endian, bits 254/255 cleared.
fn from_id(bytes: &[u8; 32]) -> F {
    let mut le = *bytes;
    le[31] &= 0x3f;
    F::from_repr(le).expect("254 bits is canonical")
}

/// The variable-length crossing, restated from the specification: SHA-256 with the
/// framed `nymora/v0/action-context` domain tag, then the identifier rule.
fn from_context(identifier: &[u8]) -> F {
    let mut hasher = Sha256::new();
    for part in [b"nymora/v0/action-context" as &[u8], identifier] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    from_id(&hasher.finalize().into())
}

fn scalar(bytes: [u8; 32]) -> JubjubScalar {
    Option::from(JubjubScalar::from_bytes(&bytes)).expect("canonical scalar")
}

fn point_of(sk: [u8; 32]) -> JubjubSubgroup {
    JubjubSubgroup::generator() * scalar(sk)
}

fn mint_jub(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[31] &= 0x07;
    bytes
}

const AGORA: [u8; 32] = [0x99; 32];

#[test]
#[ignore = "generator, not a check — run explicitly to regenerate vectors"]
fn print_crypto_vectors() {
    let agora = from_id(&AGORA);

    // commit/leaf
    let pk_root = point_of(mint_jub([0x11; 32]));
    let (x, y) = primitives::coords(&pk_root);
    let leaf = primitives::poseidon(&[
        domains::tag(domains::LEAF),
        x,
        y,
        F::from_repr([0x44; 32]).unwrap(),
        F::from_repr([0x22; 32]).unwrap(),
        agora,
    ]);
    println!("commit/pk_root      = {}", hex(&pk_root.to_bytes()));
    println!("commit/output       = {}", field_hex(leaf));

    // The uniform action derivation.
    let action = |tag: u64, key: F, context: F| {
        primitives::poseidon(&[
            domains::tag(domains::ACTION),
            F::from(tag),
            key,
            context,
            agora,
        ])
    };
    println!(
        "nullifier/vouch     = {}",
        field_hex(action(
            1,
            F::from_repr([0x31; 32]).unwrap(),
            from_context(b"session-1")
        ))
    );
    println!(
        "nullifier/attest    = {}",
        field_hex(action(
            0,
            F::from_repr(mint_jub([0x32; 32])).unwrap(),
            from_id(&[0x55; 32])
        ))
    );
    println!(
        "nullifier/policy    = {}",
        field_hex(action(
            2,
            F::from_repr([0x33; 32]).unwrap(),
            from_context(b"proposal-1")
        ))
    );
    println!(
        "nullifier/migration = {}",
        field_hex(primitives::poseidon(&[
            domains::tag(domains::SPEND),
            F::from_repr([0x34; 32]).unwrap(),
            F::from_repr([0x2b; 32]).unwrap(),
            agora,
        ]))
    );
    println!(
        "pseudonym/session   = {}",
        field_hex(action(
            3,
            F::from_repr(mint_jub([0x55; 32])).unwrap(),
            from_id(&[0xdd; 32])
        ))
    );

    // The certificate messages and a signature.
    let epoch_pk = point_of(mint_jub([0x55; 32]));
    let (ex, ey) = primitives::coords(&epoch_pk);
    println!("epoch_pk            = {}", hex(&epoch_pk.to_bytes()));
    println!(
        "epoch_cert_message  = {}",
        field_hex(primitives::poseidon(&[
            domains::tag(domains::EPOCH_CERT),
            agora,
            F::from(7),
            ex,
            ey,
        ]))
    );
    println!(
        "migration_cert_msg  = {}",
        field_hex(primitives::poseidon(&[
            domains::tag(domains::MIGRATION_CERT),
            agora,
            ex,
            ey,
        ]))
    );
    let sig = primitives::sign(&scalar(mint_jub([0x42; 32])), F::from(7));
    println!(
        "sign/pk             = {}",
        hex(&point_of(mint_jub([0x42; 32])).to_bytes())
    );
    println!(
        "sign/signature      = {}",
        hex(&primitives::signature_bytes(&sig))
    );
}

#[test]
#[ignore = "generator, not a check — run explicitly to regenerate vectors"]
fn print_accumulator_vectors() {
    // hash_node
    let node = primitives::poseidon(&[
        F::from_repr([0x01; 32]).unwrap(),
        F::from_repr([0x02; 32]).unwrap(),
    ]);
    println!("hash_node           = {}", field_hex(node));

    // root_from: value 0x01.., index 1, siblings [0x02.., 0x03..]
    let mut current = F::from_repr([0x01; 32]).unwrap();
    let siblings = [
        F::from_repr([0x02; 32]).unwrap(),
        F::from_repr([0x03; 32]).unwrap(),
    ];
    for (level, sibling) in siblings.iter().enumerate() {
        let bit = (1u64 >> level) & 1 == 1;
        let (left, right) = if bit {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        current = primitives::poseidon(&[left, right]);
    }
    println!("root_from           = {}", field_hex(current));

    // empty_root depth 3
    let mut zero = F::from(0);
    for _ in 0..3 {
        zero = primitives::poseidon(&[zero, zero]);
    }
    println!("empty_root(3)       = {}", field_hex(zero));

    // exclusion roots at depth 4, via this crate's own gap set.
    let empty = nymora_plonk::exclusion::GapSet::new();
    println!("exclusion_root([])  = {}", field_hex(empty.root::<4>()));
    let mut set = nymora_plonk::exclusion::GapSet::new();
    set.insert(F::from_repr([0x11; 32]).unwrap());
    set.insert(F::from_repr([0x2b; 32]).unwrap());
    println!("exclusion_root(2)   = {}", field_hex(set.root::<4>()));
}
