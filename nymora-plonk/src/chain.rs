// SPDX-License-Identifier: MIT OR Apache-2.0

//! The §9.1 membership chain as a circuit — every ordinary proof's statement, with
//! the action clause as its final, uniform line.
//!
//! # One shape for every action
//!
//! §6.5 requires one standardized circuit, so the five actions share this single
//! relation: the public inputs are always the same eight field elements, and the
//! action's variation lives *inside* the derivation — the tag is both a public input
//! and an absorbed element of the derivation hash, which is what makes one action's
//! output unreplayable as another's. Verification access derives nothing (proposal
//! 0019); its output slot is constrained to zero rather than left floating, so even
//! the no-derivation clause has exactly one satisfying public input.
//!
//! # What each clause binds
//!
//! The clauses mirror §9.1's statement line by line: the epoch-key correspondence
//! (with the canonical-representation constraint that gives one key one nullifier
//! stream), the in-circuit certificate verification over a payload the statement
//! reconstructs — never one the prover supplies — the leaf recomputed from secrets,
//! the class inclusion, and the two currency clauses over the gap trees
//! ([`crate::exclusion`]).

use midnight_circuits::{
    instructions::{
        AssertionInstructions, AssignmentInstructions, ControlFlowInstructions, EccInstructions,
        PublicInputInstructions,
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

/// The public inputs of an ordinary proof — eight field elements, for every action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainInstance {
    /// The agora the proof is scoped to (§6.4: resolved out-of-band, never labeled).
    pub agora: F,
    /// The epoch the certificate must name.
    pub epoch: F,
    /// The class accumulator root (§5.2).
    pub class_root: F,
    /// The revocation set's gap-tree root (§11).
    pub revocation_root: F,
    /// The migration-spend set's gap-tree root (§9.3).
    pub spend_root: F,
    /// The action tag ([`domains::action_tag`]).
    pub action_tag: F,
    /// The action's bound context: message hash, session id, proposal id, session
    /// context, or challenge — canonicalized to one field element.
    pub action_context: F,
    /// The action's claimed output: nullifier or pseudonym; zero for verification
    /// access, which derives nothing.
    pub action_output: F,
}

impl Default for ChainInstance {
    fn default() -> Self {
        ChainInstance {
            agora: F::from(0),
            epoch: F::from(0),
            class_root: F::from(0),
            revocation_root: F::from(0),
            spend_root: F::from(0),
            action_tag: F::from(0),
            action_context: F::from(0),
            action_output: F::from(0),
        }
    }
}

/// The private witness of an ordinary proof — §9.1's witness set, field-native.
#[derive(Clone, Debug)]
pub struct ChainWitness<const DEPTH: usize> {
    /// `sk_epoch` as its canonical 32 little-endian bytes (the circuit re-checks
    /// canonicity in-constraint).
    pub epoch_key_bytes: [u8; 32],
    /// `pk_epoch` — private: publishing it would link same-epoch actions (§9.1).
    pub epoch_public_key: JubjubSubgroup,
    /// The root's certificate over the epoch key, for this agora and epoch.
    pub epoch_certificate: Signature,
    /// `sk_cred`, the durable counting key committed in the leaf.
    pub credential_key: F,
    /// `r_root`, the commitment opening.
    pub root_opening: F,
    /// `pk_root` — private even though it is "public" material: revealing which
    /// root key acted would name the leaf.
    pub root_public_key: JubjubSubgroup,
    /// The Merkle path showing the recomputed leaf under the class root.
    pub class_path: Path<DEPTH>,
    /// Non-membership of the leaf in the revocation set.
    pub revocation_absence: AbsenceWitness<DEPTH>,
    /// Non-membership of the derived spend nullifier in the spend set.
    pub spend_absence: AbsenceWitness<DEPTH>,
}

impl<const DEPTH: usize> Default for ChainWitness<DEPTH> {
    fn default() -> Self {
        ChainWitness {
            epoch_key_bytes: [0u8; 32],
            epoch_public_key: crate::primitives::generator(),
            epoch_certificate: Signature {
                r: crate::primitives::generator(),
                s: ff::Field::ZERO,
            },
            credential_key: ff::Field::ZERO,
            root_opening: ff::Field::ZERO,
            root_public_key: crate::primitives::generator(),
            class_path: Path::default(),
            revocation_absence: AbsenceWitness::default(),
            spend_absence: AbsenceWitness::default(),
        }
    }
}

/// The chain relation at accumulator depth `DEPTH`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChainRelation<const DEPTH: usize>;

impl<const DEPTH: usize> Relation for ChainRelation<DEPTH> {
    type Instance = ChainInstance;
    type Witness = ChainWitness<DEPTH>;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![
            instance.agora,
            instance.epoch,
            instance.class_root,
            instance.revocation_root,
            instance.spend_root,
            instance.action_tag,
            instance.action_context,
            instance.action_output,
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

        // The eight public inputs, in format_instance order.
        let agora: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.agora))?;
        let epoch: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.epoch))?;
        let class_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.class_root))?;
        let revocation_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.revocation_root))?;
        let spend_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.spend_root))?;
        let action_tag: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.action_tag))?;
        let action_context: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.action_context))?;
        let action_output: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.action_output))?;

        // Private witnesses. Point assignments constrain onto the prime-order
        // subgroup (§9.1's subgroup clause).
        let (epoch_key_scalar, epoch_key_field) = gadgets::assign_canonical_scalar(
            std_lib,
            layouter,
            witness.clone().map(|w| w.epoch_key_bytes),
        )?;
        let epoch_public_key: AssignedNativePoint<Jubjub> =
            jubjub.assign(layouter, witness.clone().map(|w| w.epoch_public_key))?;
        let certificate = gadgets::assign_signature(
            std_lib,
            layouter,
            witness.clone().map(|w| w.epoch_certificate),
        )?;
        let credential_key: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.credential_key))?;
        let root_opening: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.root_opening))?;
        let root_public_key: AssignedNativePoint<Jubjub> =
            jubjub.assign(layouter, witness.clone().map(|w| w.root_public_key))?;
        let class_path =
            gadgets::assign_path(std_lib, layouter, witness.clone().map(|w| w.class_path))?;

        // Clause 1 — correspondence: pk_epoch is the public counterpart of sk_epoch.
        let generator = jubjub.assign_fixed(layouter, crate::primitives::generator())?;
        let derived_epoch_pk = jubjub.msm(layouter, &[epoch_key_scalar], &[generator])?;
        jubjub.assert_equal(layouter, &derived_epoch_pk, &epoch_public_key)?;

        // Clause 2 — the certificate verifies over pk_epoch, by pk_root, for exactly
        // this agora and epoch. The payload is reconstructed from statement inputs,
        // never taken from the prover.
        let (epk_x, epk_y) = (
            jubjub.x_coordinate(&epoch_public_key),
            jubjub.y_coordinate(&epoch_public_key),
        );
        let cert_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::EPOCH_CERT))?;
        let payload =
            std_lib.poseidon(layouter, &[cert_domain, agora.clone(), epoch, epk_x, epk_y])?;
        gadgets::verify_certificate(std_lib, layouter, certificate, &root_public_key, &payload)?;

        // Clause 3 — the leaf opens from the witness secrets and sits under the
        // class root. The leaf is recomputed, so a prover cannot present a leaf its
        // secrets do not open.
        let (pk_x, pk_y) = (
            jubjub.x_coordinate(&root_public_key),
            jubjub.y_coordinate(&root_public_key),
        );
        let leaf_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::LEAF))?;
        let leaf = std_lib.poseidon(
            layouter,
            &[
                leaf_domain,
                pk_x,
                pk_y,
                credential_key.clone(),
                root_opening,
                agora.clone(),
            ],
        )?;
        let computed_class_root = gadgets::merkle_root(std_lib, layouter, &leaf, &class_path)?;
        std_lib.assert_equal(layouter, &computed_class_root, &class_root)?;

        // Clauses 4 and 5 — the currency clauses: not revoked, not migrated away.
        gadgets::assert_absent(
            std_lib,
            layouter,
            &leaf,
            witness.clone().map(|w| w.revocation_absence),
            &revocation_root,
        )?;
        let spend_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::SPEND))?;
        let spend = std_lib.poseidon(
            layouter,
            &[spend_domain, credential_key.clone(), leaf, agora.clone()],
        )?;
        gadgets::assert_absent(
            std_lib,
            layouter,
            &spend,
            witness.map(|w| w.spend_absence),
            &spend_root,
        )?;

        // Clause 6 — the action's own output is correctly derived; the only clause
        // that varies, and it varies inside one hash.
        gadgets::assert_action_tag(std_lib, layouter, &action_tag)?;
        let (uses_epoch_key, derives_nothing) =
            gadgets::action_selectors(std_lib, layouter, &action_tag)?;
        let key = std_lib.select(layouter, &uses_epoch_key, &epoch_key_field, &credential_key)?;
        let action_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::ACTION))?;
        let derived = std_lib.poseidon(
            layouter,
            &[action_domain, action_tag, key, action_context, agora],
        )?;
        let zero: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(0))?;
        let expected = std_lib.select(layouter, &derives_nothing, &zero, &derived)?;
        std_lib.assert_equal(layouter, &expected, &action_output)
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
        Ok(ChainRelation)
    }
}
