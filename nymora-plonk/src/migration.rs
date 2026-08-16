// SPDX-License-Identifier: MIT OR Apache-2.0

//! The §9.3 migration statement as a circuit — deliberately a second relation.
//!
//! Different in kind, not detail, from the chain (§6.5's scope rule, proposals 0001
//! and 0031): no epoch key anywhere, a leaf being consumed rather than used, and a
//! certificate signed by the *old* root over the *new* one. The spend nullifier is
//! this proof's public output — the verifier checks its own set directly, so no
//! spend-absence clause appears here — and the successor commitment is proven to
//! carry the same `sk_cred` the old leaf held, the clause that stops migration
//! laundering its own nullifier.

use midnight_circuits::{
    instructions::{
        AssertionInstructions, AssignmentInstructions, EccInstructions, PublicInputInstructions,
    },
    types::{AssignedNative, AssignedNativePoint},
};
use midnight_curves::{JubjubExtended as Jubjub, JubjubSubgroup};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

use crate::{domains, exclusion::AbsenceWitness, gadgets, primitives::Signature, tree::Path, F};

/// The public inputs of a migration proof — five field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationInstance {
    /// The agora the migration happens within (§16.3: it never crosses one).
    pub agora: F,
    /// The class accumulator root the old leaf must sit under.
    pub class_root: F,
    /// The revocation set's gap-tree root.
    pub revocation_root: F,
    /// The spend nullifier consuming the old leaf, checked against and then entered
    /// into the spend set by the verifier (§9.3).
    pub spend_nullifier: F,
    /// The successor leaf commitment, proven to carry the same `sk_cred`.
    pub successor_commitment: F,
}

impl Default for MigrationInstance {
    fn default() -> Self {
        MigrationInstance {
            agora: F::from(0),
            class_root: F::from(0),
            revocation_root: F::from(0),
            spend_nullifier: F::from(0),
            successor_commitment: F::from(0),
        }
    }
}

/// The private witness of a migration proof.
#[derive(Clone, Debug)]
pub struct MigrationWitness<const DEPTH: usize> {
    /// The old credential's `pk_root`, committed in the leaf being consumed.
    pub old_root_public_key: JubjubSubgroup,
    /// The old credential's `r_root`.
    pub old_root_opening: F,
    /// `sk_cred`, carried across the lineage.
    pub credential_key: F,
    /// The Merkle path showing the old leaf under the class root.
    pub old_class_path: Path<DEPTH>,
    /// The old root's certificate over the successor's public key.
    pub migration_certificate: Signature,
    /// The successor's `pk_root` — the value the certificate signs over, kept a
    /// witness so no root key, old or new, is ever presented in the clear.
    pub successor_public_key: JubjubSubgroup,
    /// The successor's fresh `r_root`.
    pub successor_opening: F,
    /// Non-membership of the old leaf in the revocation set: a revoked credential
    /// cannot migrate out from under its revocation (§11).
    pub revocation_absence: AbsenceWitness<DEPTH>,
}

impl<const DEPTH: usize> Default for MigrationWitness<DEPTH> {
    fn default() -> Self {
        MigrationWitness {
            old_root_public_key: crate::primitives::generator(),
            old_root_opening: ff::Field::ZERO,
            credential_key: ff::Field::ZERO,
            old_class_path: Path::default(),
            migration_certificate: Signature {
                r: crate::primitives::generator(),
                s: ff::Field::ZERO,
            },
            successor_public_key: crate::primitives::generator(),
            successor_opening: ff::Field::ZERO,
            revocation_absence: AbsenceWitness::default(),
        }
    }
}

/// The migration relation at accumulator depth `DEPTH`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MigrationRelation<const DEPTH: usize>;

impl<const DEPTH: usize> Relation for MigrationRelation<DEPTH> {
    type Instance = MigrationInstance;
    type Witness = MigrationWitness<DEPTH>;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![
            instance.agora,
            instance.class_root,
            instance.revocation_root,
            instance.spend_nullifier,
            instance.successor_commitment,
        ])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let jubjub = std_lib.jubjub();

        let agora: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.agora))?;
        let class_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.class_root))?;
        let revocation_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.revocation_root))?;
        let spend_nullifier: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.spend_nullifier))?;
        let successor_commitment: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.successor_commitment))?;

        let old_root_public_key: AssignedNativePoint<Jubjub> =
            jubjub.assign(layouter, witness.clone().map(|w| w.old_root_public_key))?;
        let old_root_opening: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.old_root_opening))?;
        let credential_key: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.credential_key))?;
        let old_class_path =
            gadgets::assign_path(std_lib, layouter, witness.clone().map(|w| w.old_class_path))?;
        let certificate = gadgets::assign_signature(
            std_lib,
            layouter,
            witness.clone().map(|w| w.migration_certificate),
        )?;
        let successor_public_key: AssignedNativePoint<Jubjub> =
            jubjub.assign(layouter, witness.clone().map(|w| w.successor_public_key))?;
        let successor_opening: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.successor_opening))?;

        // The old leaf opens with the carried sk_cred and sits under the class root.
        let (old_x, old_y) = (
            jubjub.x_coordinate(&old_root_public_key),
            jubjub.y_coordinate(&old_root_public_key),
        );
        let leaf_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::LEAF))?;
        let old_leaf = std_lib.poseidon(
            layouter,
            &[
                leaf_domain.clone(),
                old_x,
                old_y,
                credential_key.clone(),
                old_root_opening,
                agora.clone(),
            ],
        )?;
        let computed_root = gadgets::merkle_root(std_lib, layouter, &old_leaf, &old_class_path)?;
        std_lib.assert_equal(layouter, &computed_root, &class_root)?;

        // A revoked credential cannot migrate out from under its revocation.
        gadgets::assert_absent(
            std_lib,
            layouter,
            &old_leaf,
            witness.map(|w| w.revocation_absence),
            &revocation_root,
        )?;

        // The public spend is exactly the nullifier consuming this leaf.
        let spend_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::SPEND))?;
        let spend = std_lib.poseidon(
            layouter,
            &[
                spend_domain,
                credential_key.clone(),
                old_leaf,
                agora.clone(),
            ],
        )?;
        std_lib.assert_equal(layouter, &spend, &spend_nullifier)?;

        // The old root authorized exactly this successor — payload reconstructed,
        // never supplied.
        let (succ_x, succ_y) = (
            jubjub.x_coordinate(&successor_public_key),
            jubjub.y_coordinate(&successor_public_key),
        );
        let cert_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::MIGRATION_CERT))?;
        let payload = std_lib.poseidon(
            layouter,
            &[cert_domain, agora.clone(), succ_x.clone(), succ_y.clone()],
        )?;
        gadgets::verify_certificate(
            std_lib,
            layouter,
            certificate,
            &old_root_public_key,
            &payload,
        )?;

        // The successor commitment carries the same sk_cred — the clause that stops
        // migration laundering its own nullifier.
        let successor_leaf = std_lib.poseidon(
            layouter,
            &[
                leaf_domain,
                succ_x,
                succ_y,
                credential_key,
                successor_opening,
                agora,
            ],
        )?;
        std_lib.assert_equal(layouter, &successor_leaf, &successor_commitment)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(MigrationRelation)
    }
}
