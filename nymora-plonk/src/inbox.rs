// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbox statement as a circuit (§9.3, §11; proposal 0036) — a third relation,
//! deliberately the smallest.
//!
//! It opens the leaf and verifies one root signature: the committed `pk_root` signed
//! the instruction `Poseidon(INBOX_CERT, agora, action, inbox_key)`. No path — the leaf
//! is a public input, because the operator resolves the inbox key through it and learns
//! nothing it did not already hold — and no epoch key, because retirement and renewal
//! are root-authorized acts like migration. Like the migration proof it travels
//! member-to-Skiora only, outside §6.5's uniform-shape rule.

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

use crate::{domains, gadgets, primitives::Signature, F};

/// The public inputs of an inbox proof — four field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxInstance {
    /// The agora the instruction applies within.
    pub agora: F,
    /// The leaf whose root key issued the instruction.
    pub leaf: F,
    /// The inbox key the instruction names, entered by the identifier rule (§6.5).
    pub inbox_key: F,
    /// Retire (0) or renew (1).
    pub action: F,
}

impl Default for InboxInstance {
    fn default() -> Self {
        InboxInstance {
            agora: F::from(0),
            leaf: F::from(0),
            inbox_key: F::from(0),
            action: F::from(0),
        }
    }
}

/// The private witness of an inbox proof.
#[derive(Clone, Debug)]
pub struct InboxWitness {
    /// `pk_root`, committed in the leaf.
    pub root_public_key: JubjubSubgroup,
    /// `r_root`.
    pub root_opening: F,
    /// `sk_cred`.
    pub credential_key: F,
    /// The root's certificate over the instruction.
    pub certificate: Signature,
}

impl Default for InboxWitness {
    fn default() -> Self {
        InboxWitness {
            root_public_key: crate::primitives::generator(),
            root_opening: ff::Field::ZERO,
            credential_key: ff::Field::ZERO,
            certificate: Signature {
                r: crate::primitives::generator(),
                s: ff::Field::ZERO,
            },
        }
    }
}

/// The inbox relation.
#[derive(Clone, Copy, Debug, Default)]
pub struct InboxRelation;

impl Relation for InboxRelation {
    type Instance = InboxInstance;
    type Witness = InboxWitness;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![
            instance.agora,
            instance.leaf,
            instance.inbox_key,
            instance.action,
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
        let leaf: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.leaf))?;
        let inbox_key: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.inbox_key))?;
        let action: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|i| i.action))?;

        let root_public_key: AssignedNativePoint<Jubjub> =
            jubjub.assign(layouter, witness.clone().map(|w| w.root_public_key))?;
        let root_opening: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.root_opening))?;
        let credential_key: AssignedNative<F> =
            std_lib.assign(layouter, witness.clone().map(|w| w.credential_key))?;
        let certificate =
            gadgets::assign_signature(std_lib, layouter, witness.map(|w| w.certificate))?;

        // The secrets open exactly the public leaf.
        let (pk_x, pk_y) = (
            jubjub.x_coordinate(&root_public_key),
            jubjub.y_coordinate(&root_public_key),
        );
        let leaf_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::LEAF))?;
        let opened = std_lib.poseidon(
            layouter,
            &[
                leaf_domain,
                pk_x,
                pk_y,
                credential_key,
                root_opening,
                agora.clone(),
            ],
        )?;
        std_lib.assert_equal(layouter, &opened, &leaf)?;

        // The action is one of the two, and the committed root key signed exactly this
        // instruction — payload reconstructed, never supplied.
        gadgets::assert_inbox_action(std_lib, layouter, &action)?;
        let cert_domain: AssignedNative<F> =
            std_lib.assign_fixed(layouter, domains::tag(domains::INBOX_CERT))?;
        let payload = std_lib.poseidon(layouter, &[cert_domain, agora, action, inbox_key])?;
        gadgets::verify_certificate(std_lib, layouter, certificate, &root_public_key, &payload)
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
        Ok(InboxRelation)
    }
}
