// SPDX-License-Identifier: MIT OR Apache-2.0

//! CPU-side evaluation of both statements, clause for clause.
//!
//! Two jobs. First, the `ProofSystem` contract's prove-side honesty: a proving
//! backend must *refuse* an unsatisfiable witness, and a Plonkish prover does not
//! check satisfiability on its own — it would emit an unverifiable proof — so
//! [`crate::backend::Backend`] evaluates here before synthesizing. Second, these
//! evaluators are the reference the conformance vectors will be generated from: any
//! divergence between them and the circuits is a bug the statement tests exist to
//! catch.

use ff::PrimeField;
use midnight_curves::Fr as JubjubScalar;

use crate::{
    chain::{ChainInstance, ChainWitness},
    domains,
    exclusion::verifies_absent,
    migration::{MigrationInstance, MigrationWitness},
    primitives::{challenge, coords, poseidon, public_key},
    F,
};

/// Reduces a field element into the Jubjub scalar field, as the challenge does.
fn reduce(value: F) -> JubjubScalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(value.to_repr().as_ref());
    JubjubScalar::from_bytes_wide(&wide)
}

/// Whether the §9.1 chain statement holds for this witness against these inputs.
pub fn satisfies_chain<const DEPTH: usize>(
    witness: &ChainWitness<DEPTH>,
    instance: &ChainInstance,
) -> bool {
    // Canonicity: the epoch-key bytes must name a scalar below the group order —
    // the same constraint the circuit enforces, so one key has one representation.
    let epoch_key =
        match Option::<JubjubScalar>::from(JubjubScalar::from_bytes(&witness.epoch_key_bytes)) {
            Some(scalar) => scalar,
            None => return false,
        };

    // Correspondence: pk_epoch is the public counterpart of sk_epoch.
    if public_key(&epoch_key) != witness.epoch_public_key {
        return false;
    }

    // The certificate verifies over pk_epoch, by pk_root, for this agora and epoch.
    let (epk_x, epk_y) = coords(&witness.epoch_public_key);
    let payload = poseidon(&[
        domains::tag(domains::EPOCH_CERT),
        instance.agora,
        instance.epoch,
        epk_x,
        epk_y,
    ]);
    {
        let e = reduce(challenge(
            &witness.epoch_certificate.r,
            &witness.root_public_key,
            payload,
        ));
        let lhs = public_key(&witness.epoch_certificate.s);
        let rhs = witness.epoch_certificate.r + witness.root_public_key * e;
        if lhs != rhs {
            return false;
        }
    }

    // The leaf opens from the secrets and sits under the class root.
    let (pk_x, pk_y) = coords(&witness.root_public_key);
    let leaf = poseidon(&[
        domains::tag(domains::LEAF),
        pk_x,
        pk_y,
        witness.credential_key,
        witness.root_opening,
        instance.agora,
    ]);
    if witness.class_path.root(leaf) != instance.class_root {
        return false;
    }

    // The currency clauses.
    if !verifies_absent(leaf, &witness.revocation_absence, &instance.revocation_root) {
        return false;
    }
    let spend = poseidon(&[
        domains::tag(domains::SPEND),
        witness.credential_key,
        leaf,
        instance.agora,
    ]);
    if !verifies_absent(spend, &witness.spend_absence, &instance.spend_root) {
        return false;
    }

    // The action clause: tag in range, key selected by tag, output as derived —
    // or zero for verification access, which derives nothing.
    let tag_value = (0..=4u64).find(|v| instance.action_tag == F::from(*v));
    let tag_value = match tag_value {
        Some(v) => v,
        None => return false,
    };
    let uses_epoch_key =
        tag_value == domains::action_tag::AUTHORSHIP || tag_value == domains::action_tag::LIVE_AUTH;
    let key = if uses_epoch_key {
        crate::primitives::scalar_as_field(&epoch_key)
    } else {
        witness.credential_key
    };
    let derived = poseidon(&[
        domains::tag(domains::ACTION),
        instance.action_tag,
        key,
        instance.action_context,
        instance.agora,
    ]);
    let expected = if tag_value == domains::action_tag::VERIFICATION {
        F::from(0)
    } else {
        derived
    };
    expected == instance.action_output
}

/// Whether the §9.3 migration statement holds for this witness against these inputs.
pub fn satisfies_migration<const DEPTH: usize>(
    witness: &MigrationWitness<DEPTH>,
    instance: &MigrationInstance,
) -> bool {
    let (old_x, old_y) = coords(&witness.old_root_public_key);
    let old_leaf = poseidon(&[
        domains::tag(domains::LEAF),
        old_x,
        old_y,
        witness.credential_key,
        witness.old_root_opening,
        instance.agora,
    ]);
    if witness.old_class_path.root(old_leaf) != instance.class_root {
        return false;
    }

    if !verifies_absent(
        old_leaf,
        &witness.revocation_absence,
        &instance.revocation_root,
    ) {
        return false;
    }

    let spend = poseidon(&[
        domains::tag(domains::SPEND),
        witness.credential_key,
        old_leaf,
        instance.agora,
    ]);
    if spend != instance.spend_nullifier {
        return false;
    }

    let (succ_x, succ_y) = coords(&witness.successor_public_key);
    let payload = poseidon(&[
        domains::tag(domains::MIGRATION_CERT),
        instance.agora,
        succ_x,
        succ_y,
    ]);
    {
        let e = reduce(challenge(
            &witness.migration_certificate.r,
            &witness.old_root_public_key,
            payload,
        ));
        let lhs = public_key(&witness.migration_certificate.s);
        let rhs = witness.migration_certificate.r + witness.old_root_public_key * e;
        if lhs != rhs {
            return false;
        }
    }

    let successor_leaf = poseidon(&[
        domains::tag(domains::LEAF),
        succ_x,
        succ_y,
        witness.credential_key,
        witness.successor_opening,
        instance.agora,
    ]);
    successor_leaf == instance.successor_commitment
}
