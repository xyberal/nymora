// SPDX-License-Identifier: MIT OR Apache-2.0

//! The stub prover — a plaintext evaluator of the exact statements. **Never production.**
//!
//! # What it is honest about
//!
//! Every clause is checked, none is skipped, and nothing is asserted that the real circuit
//! could not prove: the correspondence of `pk_epoch` to `sk_epoch`, both certificate
//! verifications, the commitment openings, the Merkle inclusion, both absence clauses, and
//! the action's derivation are all evaluated — in the clear — against exactly the witness
//! and public-input types the real prover will take. A protocol built and tested on this
//! backend is making claims the circuit can later discharge, which is the entire point
//! (SETUP's rule: a stub that asserts something no circuit could prove builds a protocol
//! that cannot be made real).
//!
//! # What it is dishonest about, and loudly
//!
//! A [`StubProof`] **contains the witness** — the member's secrets, copied, in a value
//! that gets passed around. It is the opposite of zero knowledge: verification works by
//! re-evaluating the statement from the embedded witness against the supplied public
//! inputs. It must never leave a test process, never be serialized, and never cross a
//! trust boundary — the same never-production standing as `SoftwareKeyStore`, for the
//! same reason: naming the dishonesty is what stops it becoming entrenched.
//!
//! # The binding is explicit, because re-evaluation alone is not it
//!
//! §6.5's Fiat–Shamir binding means a proof verifies against exactly the public inputs it
//! was produced for. Re-evaluation catches an altered input only when the alteration makes
//! the statement false — but the same witness can satisfy *two* instances (an authorship
//! proof's witness also derives a perfectly correct vouch nullifier), and re-evaluation
//! would happily accept the swap. So each stub proof carries a digest of its full public
//! inputs, taken at prove time, and verification first requires the presented inputs to
//! match. The digest's encoding is local to this backend — deliberately not a protocol
//! domain tag, because the real transcript encoding belongs to the proving system and
//! pinning a stand-in here would be pinning the thing phase 4 must not pin.
//!
//! Sizes follow the provisional schemes and are unpinned by every test; the proof types
//! redact themselves in `Debug` like the secrets they contain.

use crate::statement::{
    Action, ChainPublicInputs, ChainWitness, MigrationPublicInputs, MigrationWitness,
};
use crate::system::ProofSystem;
use nymora_accumulator::{verifies, verifies_absent, AbsenceWitness, Witness};
use nymora_core::{
    CredentialKey, EpochCertPayload, EpochSecretKey, MigrationCertPayload, ProtocolError,
    RootOpening,
};
use nymora_crypto::signature::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use nymora_crypto::{commit, live_auth, nullifier, signature};
use sha2::{Digest, Sha256};

/// Local separators for the stub's public-input digests. Not protocol domain tags — see
/// the module documentation on why the binding encoding stays local to this backend.
const CHAIN_BINDING: &[u8] = b"stub-prover/v0/chain-binding";
const MIGRATION_BINDING: &[u8] = b"stub-prover/v0/migration-binding";

/// Absorbs a length prefix before the bytes — the same convention as everywhere else, so
/// no field boundary in the digest is movable.
fn framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// The digest of an ordinary proof's full public inputs — the stub's stand-in for the
/// Fiat–Shamir transcript.
fn chain_binding(public: &ChainPublicInputs<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, CHAIN_BINDING);
    framed(&mut hasher, public.agora.as_bytes());
    framed(&mut hasher, &public.epoch.get().to_le_bytes());
    framed(&mut hasher, public.class_root.as_bytes());
    framed(&mut hasher, public.revocation_root.as_bytes());
    framed(&mut hasher, public.spend_root.as_bytes());
    match &public.action {
        Action::Authorship {
            message_hash,
            nullifier,
        } => {
            framed(&mut hasher, &[0]);
            framed(&mut hasher, message_hash.as_bytes());
            framed(&mut hasher, nullifier.as_bytes());
        }
        Action::Vouch {
            session_id,
            nullifier,
        } => {
            framed(&mut hasher, &[1]);
            framed(&mut hasher, session_id);
            framed(&mut hasher, nullifier.as_bytes());
        }
        Action::PolicyApproval {
            proposal_id,
            nullifier,
        } => {
            framed(&mut hasher, &[2]);
            framed(&mut hasher, proposal_id);
            framed(&mut hasher, nullifier.as_bytes());
        }
        Action::LiveAuth { context, pseudonym } => {
            framed(&mut hasher, &[3]);
            framed(&mut hasher, context.as_bytes());
            framed(&mut hasher, pseudonym.as_bytes());
        }
        Action::VerificationAccess { challenge } => {
            framed(&mut hasher, &[4]);
            framed(&mut hasher, challenge);
        }
    }
    hasher.finalize().into()
}

/// The digest of a migration proof's full public inputs.
fn migration_binding(public: &MigrationPublicInputs) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, MIGRATION_BINDING);
    framed(&mut hasher, public.agora.as_bytes());
    framed(&mut hasher, public.class_root.as_bytes());
    framed(&mut hasher, public.revocation_root.as_bytes());
    framed(&mut hasher, public.spend_nullifier.as_bytes());
    framed(&mut hasher, public.successor_commitment.as_bytes());
    hasher.finalize().into()
}

/// The phase-4 backend: proves by checking, verifies by re-checking.
///
/// Stateless — a real backend holds proving and verifying artifacts here, which is why
/// the trait takes `&self`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubProver;

/// A stub ordinary proof: the witness, embedded in the clear. See the module
/// documentation for what that means and where this must never go.
pub struct StubProof<const DEPTH: usize> {
    binding: [u8; 32],
    epoch_key: EpochSecretKey,
    epoch_public_key: [u8; PUBLIC_KEY_LEN],
    epoch_cert_signature: [u8; SIGNATURE_LEN],
    credential_key: CredentialKey,
    root_opening: RootOpening,
    root_public_key: [u8; PUBLIC_KEY_LEN],
    leaf_witness: Witness<DEPTH>,
    revocation_absence: AbsenceWitness,
    spend_absence: AbsenceWitness,
}

impl<const DEPTH: usize> core::fmt::Debug for StubProof<DEPTH> {
    /// Renders nothing but the type: every field is either a secret or a path that names
    /// the member's position.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StubProof {{ <witness redacted>, depth: {DEPTH} }}")
    }
}

/// A stub migration proof. Same standing as [`StubProof`].
pub struct MigrationStubProof<const DEPTH: usize> {
    binding: [u8; 32],
    old_root_public_key: [u8; PUBLIC_KEY_LEN],
    old_root_opening: RootOpening,
    credential_key: CredentialKey,
    old_leaf_witness: Witness<DEPTH>,
    migration_cert_signature: [u8; SIGNATURE_LEN],
    successor_public_key: [u8; PUBLIC_KEY_LEN],
    successor_opening: RootOpening,
    revocation_absence: AbsenceWitness,
}

impl<const DEPTH: usize> core::fmt::Debug for MigrationStubProof<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MigrationStubProof {{ <witness redacted>, depth: {DEPTH} }}"
        )
    }
}

/// Evaluates every clause of §9.1's chain. The order matches the specification text; a
/// short-circuit here is fine because the evaluator is not a proof — timing discipline
/// belongs to the primitives it calls.
fn chain_holds<const DEPTH: usize>(
    witness: &ChainWitness<'_, DEPTH>,
    public: &ChainPublicInputs<'_>,
) -> bool {
    // pk_epoch is the public counterpart of sk_epoch — without this the certificate
    // constrains nothing about the key the nullifier derives from (§9.1).
    if signature::public_key(witness.epoch_key.expose()).as_slice() != witness.epoch_public_key {
        return false;
    }

    // epoch_cert verifies over pk_epoch by pk_root, for exactly this agora and epoch —
    // the payload is reconstructed from statement inputs, never taken from the prover.
    let cert = EpochCertPayload {
        agora: public.agora,
        epoch: public.epoch,
        epoch_public_key: witness.epoch_public_key,
    };
    if !signature::verify(
        witness.root_public_key,
        |put| cert.encode_parts(put),
        witness.epoch_cert_signature,
    ) {
        return false;
    }

    // sk_cred and r_root open the committed leaf, and that leaf sits under the class root.
    let leaf = commit(
        witness.root_public_key,
        witness.credential_key,
        witness.root_opening,
        &public.agora,
    );
    if !verifies(&leaf, witness.leaf_witness, &public.class_root) {
        return false;
    }

    // The two currency clauses (§9.1): not revoked, not migrated away.
    if !verifies_absent(
        leaf.as_bytes(),
        witness.revocation_absence,
        &public.revocation_root,
    ) {
        return false;
    }
    let spend = nullifier::migration(witness.credential_key, &leaf, &public.agora);
    if !verifies_absent(spend.as_bytes(), witness.spend_absence, &public.spend_root) {
        return false;
    }

    // The action's own output is correctly derived — the only clause that varies.
    match &public.action {
        Action::Authorship {
            message_hash,
            nullifier: claimed,
        } => *claimed == nullifier::attestation(witness.epoch_key, message_hash, &public.agora),
        Action::Vouch {
            session_id,
            nullifier: claimed,
        } => *claimed == nullifier::vouch(witness.credential_key, session_id, &public.agora),
        Action::PolicyApproval {
            proposal_id,
            nullifier: claimed,
        } => *claimed == nullifier::policy(witness.credential_key, proposal_id, &public.agora),
        Action::LiveAuth {
            context,
            pseudonym: claimed,
        } => *claimed == live_auth::pseudonym(witness.epoch_key, context, &public.agora),
        // Pure binding: the challenge is part of the public inputs this proof is bound
        // to, and nothing is derived (proposal 0019).
        Action::VerificationAccess { .. } => true,
    }
}

/// Evaluates every clause of the migration statement (§9.3).
fn migration_holds<const DEPTH: usize>(
    witness: &MigrationWitness<'_, DEPTH>,
    public: &MigrationPublicInputs,
) -> bool {
    // The old leaf opens with the carried sk_cred and sits under the class root.
    let old_leaf = commit(
        witness.old_root_public_key,
        witness.credential_key,
        witness.old_root_opening,
        &public.agora,
    );
    if !verifies(&old_leaf, witness.old_leaf_witness, &public.class_root) {
        return false;
    }

    // A revoked credential cannot migrate out from under its revocation (§11).
    if !verifies_absent(
        old_leaf.as_bytes(),
        witness.revocation_absence,
        &public.revocation_root,
    ) {
        return false;
    }

    // The public spend is exactly the nullifier consuming this leaf (§9.3).
    if public.spend_nullifier
        != nullifier::migration(witness.credential_key, &old_leaf, &public.agora)
    {
        return false;
    }

    // The old root authorized exactly this successor (§9.3) — payload reconstructed, not
    // supplied.
    let cert = MigrationCertPayload {
        agora: public.agora,
        successor_public_key: witness.successor_public_key,
    };
    if !signature::verify(
        witness.old_root_public_key,
        |put| cert.encode_parts(put),
        witness.migration_cert_signature,
    ) {
        return false;
    }

    // The successor commitment carries the same sk_cred — the clause that stops migration
    // laundering its own nullifier (§9.3).
    public.successor_commitment
        == commit(
            witness.successor_public_key,
            witness.credential_key,
            witness.successor_opening,
            &public.agora,
        )
}

/// Copies a scheme-width slice, or reports the caller's input unusable for this backend.
fn sized<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes.try_into().map_err(|_| ProtocolError::Malformed)
}

impl<const DEPTH: usize> ProofSystem<DEPTH> for StubProver {
    type Proof = StubProof<DEPTH>;
    type MigrationProof = MigrationStubProof<DEPTH>;

    fn prove(
        &self,
        witness: &ChainWitness<'_, DEPTH>,
        public: &ChainPublicInputs<'_>,
    ) -> Result<Self::Proof, ProtocolError> {
        if !chain_holds(witness, public) {
            return Err(ProtocolError::Malformed);
        }
        Ok(StubProof {
            binding: chain_binding(public),
            // The one place secrets are deliberately duplicated: the stub proof *is* the
            // witness, which is its documented dishonesty.
            epoch_key: EpochSecretKey::new(*witness.epoch_key.expose()),
            epoch_public_key: sized(witness.epoch_public_key)?,
            epoch_cert_signature: sized(witness.epoch_cert_signature)?,
            credential_key: CredentialKey::new(*witness.credential_key.expose()),
            root_opening: RootOpening::new(*witness.root_opening.expose()),
            root_public_key: sized(witness.root_public_key)?,
            leaf_witness: *witness.leaf_witness,
            revocation_absence: witness.revocation_absence.clone(),
            spend_absence: witness.spend_absence.clone(),
        })
    }

    fn verify(&self, proof: &Self::Proof, public: &ChainPublicInputs<'_>) -> bool {
        // The binding first: a proof verifies only against the exact public inputs it was
        // produced for, however satisfiable the swapped ones might be.
        if proof.binding != chain_binding(public) {
            return false;
        }
        chain_holds(
            &ChainWitness {
                epoch_key: &proof.epoch_key,
                epoch_public_key: &proof.epoch_public_key,
                epoch_cert_signature: &proof.epoch_cert_signature,
                credential_key: &proof.credential_key,
                root_opening: &proof.root_opening,
                root_public_key: &proof.root_public_key,
                leaf_witness: &proof.leaf_witness,
                revocation_absence: &proof.revocation_absence,
                spend_absence: &proof.spend_absence,
            },
            public,
        )
    }

    fn prove_migration(
        &self,
        witness: &MigrationWitness<'_, DEPTH>,
        public: &MigrationPublicInputs,
    ) -> Result<Self::MigrationProof, ProtocolError> {
        if !migration_holds(witness, public) {
            return Err(ProtocolError::Malformed);
        }
        Ok(MigrationStubProof {
            binding: migration_binding(public),
            old_root_public_key: sized(witness.old_root_public_key)?,
            old_root_opening: RootOpening::new(*witness.old_root_opening.expose()),
            credential_key: CredentialKey::new(*witness.credential_key.expose()),
            old_leaf_witness: *witness.old_leaf_witness,
            migration_cert_signature: sized(witness.migration_cert_signature)?,
            successor_public_key: sized(witness.successor_public_key)?,
            successor_opening: RootOpening::new(*witness.successor_opening.expose()),
            revocation_absence: witness.revocation_absence.clone(),
        })
    }

    fn verify_migration(
        &self,
        proof: &Self::MigrationProof,
        public: &MigrationPublicInputs,
    ) -> bool {
        if proof.binding != migration_binding(public) {
            return false;
        }
        migration_holds(
            &MigrationWitness {
                old_root_public_key: &proof.old_root_public_key,
                old_root_opening: &proof.old_root_opening,
                credential_key: &proof.credential_key,
                old_leaf_witness: &proof.old_leaf_witness,
                migration_cert_signature: &proof.migration_cert_signature,
                successor_public_key: &proof.successor_public_key,
                successor_opening: &proof.successor_opening,
                revocation_absence: &proof.revocation_absence,
            },
            public,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::StubProver;
    use crate::statement::{
        Action, ChainPublicInputs, ChainWitness, MigrationPublicInputs, MigrationWitness,
    };
    use crate::system::ProofSystem;
    use nymora_accumulator::{AbsenceWitness, ExclusionSet, Tree, Witness};
    use nymora_core::{
        AgoraId, Commitment, CredentialKey, Epoch, EpochCertPayload, EpochSecretKey, MessageHash,
        MigrationCertPayload, ProtocolError, Root, RootOpening, SessionContext,
    };
    use nymora_crypto::signature::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
    use nymora_crypto::{commit, live_auth, nullifier, signature};

    const DEPTH: usize = 2;
    const AGORA_A: AgoraId = AgoraId::from_bytes([0x01; 32]);
    const AGORA_B: AgoraId = AgoraId::from_bytes([0x02; 32]);
    const EPOCH: u64 = 7;
    const ROOT_SEED: [u8; 32] = [0x0a; 32];
    const EPOCH_SEED: [u8; 32] = [0x0d; 32];

    /// Everything a member holds when producing an ordinary proof, owned so the borrowed
    /// witness and public-input views can be cut from it per test.
    struct Fixture {
        epoch_key: EpochSecretKey,
        epoch_public_key: [u8; PUBLIC_KEY_LEN],
        epoch_cert_signature: [u8; SIGNATURE_LEN],
        credential_key: CredentialKey,
        root_opening: RootOpening,
        root_public_key: [u8; PUBLIC_KEY_LEN],
        leaf: Commitment,
        leaf_witness: Witness<DEPTH>,
        revocation_absence: AbsenceWitness,
        spend_absence: AbsenceWitness,
        class_root: Root,
        revocation_root: Root,
        spend_root: Root,
    }

    fn fixture() -> Fixture {
        fixture_with(|_, _| {})
    }

    /// Builds the fixture, letting a test poison the exclusion sets first.
    fn fixture_with(mutate: impl FnOnce(&mut ExclusionSet, &mut ExclusionSet)) -> Fixture {
        let root_public_key = signature::public_key(&ROOT_SEED);
        let credential_key = CredentialKey::new([0x0b; 32]);
        let root_opening = RootOpening::new([0x0c; 32]);
        let leaf = commit(&root_public_key, &credential_key, &root_opening, &AGORA_A);

        let mut tree = Tree::<DEPTH>::new();
        tree.append(Commitment::from_bytes([0xf0; 32]))
            .expect("tree has room");
        let position = tree.append(leaf).expect("tree has room");
        let leaf_witness = tree.witness(position).expect("position was just appended");

        let mut revocations = ExclusionSet::new();
        let mut spends = ExclusionSet::new();
        mutate(&mut revocations, &mut spends);
        let spend = nullifier::migration(&credential_key, &leaf, &AGORA_A);

        let epoch_key = EpochSecretKey::new(EPOCH_SEED);
        let epoch_public_key = signature::public_key(&EPOCH_SEED);
        let cert = EpochCertPayload {
            agora: AGORA_A,
            epoch: Epoch::new(EPOCH),
            epoch_public_key: &epoch_public_key,
        };
        let epoch_cert_signature = signature::sign(&ROOT_SEED, |put| cert.encode_parts(put));

        Fixture {
            epoch_key,
            epoch_public_key,
            epoch_cert_signature,
            credential_key,
            root_opening,
            root_public_key,
            leaf,
            leaf_witness,
            revocation_absence: revocations.absence_witness(leaf.as_bytes()),
            spend_absence: spends.absence_witness(spend.as_bytes()),
            class_root: tree.root(),
            revocation_root: revocations.root(),
            spend_root: spends.root(),
        }
    }

    impl Fixture {
        fn witness(&self) -> ChainWitness<'_, DEPTH> {
            ChainWitness {
                epoch_key: &self.epoch_key,
                epoch_public_key: &self.epoch_public_key,
                epoch_cert_signature: &self.epoch_cert_signature,
                credential_key: &self.credential_key,
                root_opening: &self.root_opening,
                root_public_key: &self.root_public_key,
                leaf_witness: &self.leaf_witness,
                revocation_absence: &self.revocation_absence,
                spend_absence: &self.spend_absence,
            }
        }

        fn publics<'a>(&self, action: Action<'a>) -> ChainPublicInputs<'a> {
            ChainPublicInputs {
                agora: AGORA_A,
                epoch: Epoch::new(EPOCH),
                class_root: self.class_root,
                revocation_root: self.revocation_root,
                spend_root: self.spend_root,
                action,
            }
        }

        fn authorship(&self) -> Action<'static> {
            let message_hash = MessageHash::from_bytes([0xaa; 32]);
            Action::Authorship {
                message_hash,
                nullifier: nullifier::attestation(&self.epoch_key, &message_hash, &AGORA_A),
            }
        }

        fn actions(&self) -> [Action<'static>; 5] {
            let context = SessionContext::from_bytes([0xdd; 32]);
            [
                self.authorship(),
                Action::Vouch {
                    session_id: b"session-1",
                    nullifier: nullifier::vouch(&self.credential_key, b"session-1", &AGORA_A),
                },
                Action::PolicyApproval {
                    proposal_id: b"proposal-1",
                    nullifier: nullifier::policy(&self.credential_key, b"proposal-1", &AGORA_A),
                },
                Action::LiveAuth {
                    context,
                    pseudonym: live_auth::pseudonym(&self.epoch_key, &context, &AGORA_A),
                },
                Action::VerificationAccess {
                    challenge: b"challenge-1",
                },
            ]
        }
    }

    /// The whole ordinary surface: every action's clause proves and verifies from one
    /// valid witness set.
    #[test]
    fn every_action_proves_and_verifies() {
        let fixture = fixture();
        for action in fixture.actions() {
            let public = fixture.publics(action);
            let proof = StubProver
                .prove(&fixture.witness(), &public)
                .expect("a satisfied statement must prove");
            assert!(StubProver.verify(&proof, &public), "{action:?}");
        }
    }

    /// A real prover cannot produce a proof for a false statement, so neither may the
    /// stub — the semantic honesty rule.
    #[test]
    fn prove_refuses_a_wrong_nullifier() {
        let fixture = fixture();
        let lied = Action::Authorship {
            message_hash: MessageHash::from_bytes([0xaa; 32]),
            nullifier: nymora_core::Nullifier::from_bytes([0x99; 32]),
        };
        assert_eq!(
            StubProver
                .prove(&fixture.witness(), &fixture.publics(lied))
                .err(),
            Some(ProtocolError::Malformed)
        );
    }

    /// §9.1's first currency clause: a revoked credential's otherwise-perfect witness set
    /// no longer proves anything.
    #[test]
    fn a_revoked_leaf_cannot_prove() {
        let fixture = fixture_with(|revocations, _| {
            // The leaf is deterministic from the fixture's constants, so it can be
            // recomputed here before the fixture exists.
            let leaf = commit(
                &signature::public_key(&ROOT_SEED),
                &CredentialKey::new([0x0b; 32]),
                &RootOpening::new([0x0c; 32]),
                &AGORA_A,
            );
            revocations.insert(*leaf.as_bytes());
        });
        assert_eq!(
            StubProver
                .prove(&fixture.witness(), &fixture.publics(fixture.authorship()))
                .err(),
            Some(ProtocolError::Malformed)
        );
    }

    /// The second currency clause: a spent (migrated-away) leaf is no longer current.
    #[test]
    fn a_spent_leaf_cannot_prove() {
        let fixture = fixture_with(|_, spends| {
            let credential_key = CredentialKey::new([0x0b; 32]);
            let leaf = commit(
                &signature::public_key(&ROOT_SEED),
                &credential_key,
                &RootOpening::new([0x0c; 32]),
                &AGORA_A,
            );
            spends.insert(*nullifier::migration(&credential_key, &leaf, &AGORA_A).as_bytes());
        });
        assert_eq!(
            StubProver
                .prove(&fixture.witness(), &fixture.publics(fixture.authorship()))
                .err(),
            Some(ProtocolError::Malformed)
        );
    }

    /// The §6.5 binding: a valid proof presented against any altered public input fails.
    /// Rebinding a proof to different content, another epoch, another agora, or a
    /// different claimed output must all die in verification.
    #[test]
    fn verify_rejects_every_rebinding() {
        let fixture = fixture();
        let public = fixture.publics(fixture.authorship());
        let proof = StubProver
            .prove(&fixture.witness(), &public)
            .expect("a satisfied statement must prove");

        let reattached = Action::Authorship {
            message_hash: MessageHash::from_bytes([0xab; 32]),
            nullifier: match fixture.authorship() {
                Action::Authorship { nullifier, .. } => nullifier,
                _ => unreachable!(),
            },
        };
        let rebindings = [
            ChainPublicInputs {
                action: reattached,
                ..public
            },
            ChainPublicInputs {
                epoch: Epoch::new(EPOCH + 1),
                ..public
            },
            ChainPublicInputs {
                agora: AGORA_B,
                ..public
            },
            ChainPublicInputs {
                class_root: Root::from_bytes([0xee; 32]),
                ..public
            },
            ChainPublicInputs {
                revocation_root: Root::from_bytes([0xee; 32]),
                ..public
            },
            ChainPublicInputs {
                spend_root: Root::from_bytes([0xee; 32]),
                ..public
            },
        ];
        for rebound in rebindings {
            assert!(
                !StubProver.verify(&proof, &rebound),
                "a rebound proof verified: {rebound:?}"
            );
        }
    }

    /// An authorship proof presented as a vouch — same witness, different clause — must
    /// not verify, or one action could be replayed as another.
    #[test]
    fn one_action_does_not_verify_as_another() {
        let fixture = fixture();
        let proof = StubProver
            .prove(&fixture.witness(), &fixture.publics(fixture.authorship()))
            .expect("a satisfied statement must prove");
        let as_vouch = fixture.publics(Action::Vouch {
            session_id: b"session-1",
            nullifier: nullifier::vouch(&fixture.credential_key, b"session-1", &AGORA_A),
        });
        assert!(!StubProver.verify(&proof, &as_vouch));
    }

    /// §9.1: a member out of contact certifies against the last epoch they know, and
    /// risks rejection if the agora has advanced. The certificate names its epoch, so
    /// the same witness set against the advanced epoch's inputs fails.
    #[test]
    fn a_certificate_for_a_past_epoch_does_not_prove_in_the_current_one() {
        let fixture = fixture();
        let advanced = ChainPublicInputs {
            epoch: Epoch::new(EPOCH + 1),
            ..fixture.publics(fixture.authorship())
        };
        assert_eq!(
            StubProver.prove(&fixture.witness(), &advanced).err(),
            Some(ProtocolError::Malformed)
        );
    }

    /// The full migration statement, both ways.
    #[test]
    fn migration_proves_and_verifies() {
        let fixture = fixture();
        let successor_seed = [0x1a; 32];
        let successor_public_key = signature::public_key(&successor_seed);
        let successor_opening = RootOpening::new([0x1b; 32]);
        let cert = MigrationCertPayload {
            agora: AGORA_A,
            successor_public_key: &successor_public_key,
        };
        let migration_cert_signature = signature::sign(&ROOT_SEED, |put| cert.encode_parts(put));

        let witness = MigrationWitness {
            old_root_public_key: &fixture.root_public_key,
            old_root_opening: &fixture.root_opening,
            credential_key: &fixture.credential_key,
            old_leaf_witness: &fixture.leaf_witness,
            migration_cert_signature: &migration_cert_signature,
            successor_public_key: &successor_public_key,
            successor_opening: &successor_opening,
            revocation_absence: &fixture.revocation_absence,
        };
        let public = MigrationPublicInputs {
            agora: AGORA_A,
            class_root: fixture.class_root,
            revocation_root: fixture.revocation_root,
            spend_nullifier: nullifier::migration(&fixture.credential_key, &fixture.leaf, &AGORA_A),
            successor_commitment: commit(
                &successor_public_key,
                &fixture.credential_key,
                &successor_opening,
                &AGORA_A,
            ),
        };

        let proof = StubProver
            .prove_migration(&witness, &public)
            .expect("a satisfied statement must prove");
        assert!(StubProver.verify_migration(&proof, &public));

        // The clause that stops migration laundering its own nullifier: a successor
        // commitment built over a *fresh* credential key must not prove.
        let laundered = MigrationPublicInputs {
            successor_commitment: commit(
                &successor_public_key,
                &CredentialKey::new([0x77; 32]),
                &successor_opening,
                &AGORA_A,
            ),
            ..public
        };
        assert_eq!(
            StubProver.prove_migration(&witness, &laundered).err(),
            Some(ProtocolError::Malformed)
        );
        assert!(!StubProver.verify_migration(&proof, &laundered));

        // And the spend is bound: a different claimed nullifier fails.
        let wrong_spend = MigrationPublicInputs {
            spend_nullifier: nymora_core::Nullifier::from_bytes([0x99; 32]),
            ..public
        };
        assert!(!StubProver.verify_migration(&proof, &wrong_spend));
    }

    /// A stub proof is the witness — it must never render its contents.
    #[test]
    fn stub_proofs_redact_themselves() {
        let fixture = fixture();
        let proof = StubProver
            .prove(&fixture.witness(), &fixture.publics(fixture.authorship()))
            .expect("a satisfied statement must prove");
        let rendered = std::format!("{proof:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains("0b0b"),
            "a secret leaked into Debug output: {rendered}"
        );
    }
}
