// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared test harness: an in-memory store and a member driving a real operator.
//!
//! Each integration binary compiles this module separately and uses a different subset,
//! so unused-item lints are silenced here — this is support code, not a surface.

#![allow(dead_code)]

use nymora_accumulator::ExclusionSet;
use nymora_circuits::{ChainWitness, ProofSystem, StubProver};
use nymora_core::{
    AgoraId, Commitment, Epoch, Nullifier, PolicyClass, ProtocolError, TagKey, WitnessKey,
};
use nymora_crypto::signature::PUBLIC_KEY_LEN;
use nymora_crypto::{nullifier, signature};
use nymora_ports::{SecureStorage, Slot, SoftwareKeyStore};
use nymora_proofs::{prove_policy_approval, prove_vouch, EpochRoots};
use nymora_protocol::operator::{AgoraState, Bulletin, ClassPolicy, Founding, SessionId};
use nymora_protocol::{create, load_acting_material, subject_id, FreshEntropy, SubjectId};
use std::collections::HashMap;
use std::vec::Vec;

pub type Proof<const D: usize> = <StubProver as ProofSystem<D>>::Proof;

pub fn entropy(byte: u8) -> FreshEntropy {
    FreshEntropy::new([byte; 32])
}

/// A minimal in-memory `SecureStorage`.
#[derive(Default)]
pub struct TestStore {
    values: HashMap<([u8; 32], Slot), Vec<u8>>,
}

impl SecureStorage for TestStore {
    fn store(&mut self, agora: AgoraId, slot: Slot, value: &[u8]) -> Result<(), ProtocolError> {
        self.values
            .insert((*agora.as_bytes(), slot), value.to_vec());
        Ok(())
    }

    fn load(
        &self,
        agora: AgoraId,
        slot: Slot,
        out: &mut [u8],
    ) -> Result<Option<usize>, ProtocolError> {
        let Some(value) = self.values.get(&(*agora.as_bytes(), slot)) else {
            return Ok(None);
        };
        out.get_mut(..value.len())
            .ok_or(ProtocolError::Malformed)?
            .copy_from_slice(value);
        Ok(Some(value.len()))
    }

    fn delete(&mut self, agora: AgoraId, slot: Slot) -> Result<(), ProtocolError> {
        self.values.remove(&(*agora.as_bytes(), slot));
        Ok(())
    }
}

/// A member of one agora: stored credential material plus the local copies a Persora
/// keeps — the exclusion sets rebuilt from bulletins, the tag keys received from
/// broadcasts.
pub struct Member {
    pub seed: u8,
    pub agora: AgoraId,
    pub class: PolicyClass,
    pub keys: SoftwareKeyStore,
    pub store: TestStore,
    pub leaf: Commitment,
    pub position: u64,
    pub revocations: ExclusionSet,
    pub spends: ExclusionSet,
    pub tag_keys: Vec<(Epoch, TagKey)>,
    /// The epoch's roots, as the bulletin delivered them (proposal 0025) — a member
    /// holds no other source for them.
    pub roots: Option<EpochRoots>,
    /// The epoch's witness-service key, from the same bulletin (proposal 0025).
    pub witness_key: Option<WitnessKey>,
    /// The operator statement key, pinned at admission (proposal 0024) — every bulletin
    /// is verified against it before anything is applied.
    pub statement_key: Option<[u8; PUBLIC_KEY_LEN]>,
    /// The last accepted bulletin's epoch — the monotonicity cursor (proposal 0024).
    pub epoch: Option<Epoch>,
}

impl Member {
    /// Creates the credential and certifies it at `epoch`.
    ///
    /// The seed drives every piece of entropy, so feeding one seed into two agoras is the
    /// adversarial same-entropy case the negative class wants.
    pub fn enroll(seed: u8, agora: AgoraId, class: PolicyClass, epoch: Epoch) -> Self {
        let keys = SoftwareKeyStore::new([seed; 32]);
        let mut store = TestStore::default();
        let mut pk = [0u8; 64];
        let mut binding = [0u8; 64];
        let made = create(
            agora,
            &keys,
            &mut store,
            entropy(seed ^ 0x44),
            entropy(seed ^ 0x22),
            &mut pk,
            &mut binding,
        )
        .expect("creation succeeds");
        let mut member = Self {
            seed,
            agora,
            class,
            keys,
            store,
            leaf: made.commitment,
            position: u64::MAX,
            revocations: ExclusionSet::new(),
            spends: ExclusionSet::new(),
            tag_keys: Vec::new(),
            roots: None,
            witness_key: None,
            statement_key: None,
            epoch: None,
        };
        member.roll(epoch);
        member
    }

    /// Rolls to `epoch` with a per-member, per-epoch keypair.
    pub fn roll(&mut self, epoch: Epoch) {
        let epoch_seed = [self.seed.wrapping_add(epoch.get() as u8); 32];
        let public_key = signature::public_key(&epoch_seed);
        let mut record = [0u8; 256];
        nymora_protocol::roll_epoch(
            self.agora,
            &self.keys,
            &mut self.store,
            epoch,
            FreshEntropy::new(epoch_seed),
            &public_key,
            &mut record,
        )
        .expect("rollover succeeds");
    }

    /// What the host does with a boundary broadcast (§11): replace local set copies with
    /// the whole sets the bulletin carries, cache the roots and both epoch keys, roll the
    /// credential. The bulletin is a member's only source for current roots and the
    /// witness key (proposal 0025).
    pub fn apply_bulletin(&mut self, bulletin: &Bulletin) {
        // Proposal 0024: nothing is applied before the statement verifies — signature
        // under the pinned key, over the member's own agora, strictly advancing.
        nymora_protocol::accept_bulletin(
            self.statement_key.as_ref().expect("statement key pinned"),
            &bulletin.statement(self.agora),
            &bulletin.signature,
            self.epoch,
        )
        .expect("the bulletin is a valid signed statement");
        self.epoch = Some(bulletin.epoch);
        self.revocations = ExclusionSet::new();
        for key in &bulletin.revoked {
            self.revocations.insert(*key);
        }
        self.spends = ExclusionSet::new();
        for key in &bulletin.spent {
            self.spends.insert(*key);
        }
        let class_root = bulletin
            .class_roots
            .iter()
            .find(|(class, _)| *class == self.class)
            .map(|(_, root)| *root)
            .expect("the bulletin carries this member's class");
        self.roots = Some(EpochRoots {
            class: class_root,
            revocation: bulletin.revocation_root,
            spend: bulletin.spend_root,
        });
        self.witness_key = Some(WitnessKey::new(*bulletin.witness_key.expose()));
        nymora_protocol::store_tag_key(
            self.agora,
            &mut self.store,
            bulletin.epoch,
            &bulletin.tag_key,
        )
        .expect("tag key stores");
        self.tag_keys
            .push((bulletin.epoch, TagKey::new(*bulletin.tag_key.expose())));
        self.roll(bulletin.epoch);
    }

    /// The spend key whose absence this member's routine proofs show (§9.1).
    pub fn spend_key(&self) -> [u8; 32] {
        let mut sk = [0u8; 32];
        self.store
            .load(self.agora, Slot::CredentialKey, &mut sk)
            .unwrap()
            .expect("credential stored");
        let key = nymora_core::CredentialKey::new(sk);
        *nullifier::migration(&key, &self.leaf, &self.agora).as_bytes()
    }

    /// Assembles the full chain witness from stored material plus operator-served
    /// inclusion, and hands it to `f` — the closure keeps the borrows honest.
    pub fn acting<R, const D: usize>(
        &self,
        op: &AgoraState<StubProver, D>,
        f: impl FnOnce(&ChainWitness<'_, D>, Epoch, &EpochRoots) -> R,
    ) -> R {
        let epoch = op.current_epoch();
        let roots = *self.roots.as_ref().expect("equipped by a bulletin");
        let key = self.witness_key.as_ref().expect("equipped by a bulletin");
        let inclusion = op
            .witness(key, self.class, self.position)
            .expect("leaf landed");
        let revocation = self.revocations.absence_witness(self.leaf.as_bytes());
        let spend = self.spends.absence_witness(&self.spend_key());
        let mut pk_buf = [0u8; 64];
        let mut record_buf = [0u8; 256];
        let material =
            load_acting_material(self.agora, &self.store, epoch, &mut pk_buf, &mut record_buf)
                .expect("stored material loads");
        let witness = material.witness(&inclusion, &revocation, &spend);
        f(&witness, epoch, &roots)
    }

    /// One vouch attestation into a session (§5.3).
    pub fn vouch<const D: usize>(
        &self,
        op: &AgoraState<StubProver, D>,
        session: SessionId,
    ) -> (Proof<D>, Nullifier) {
        self.acting(op, |witness, epoch, roots| {
            prove_vouch(
                &StubProver,
                witness,
                self.agora,
                epoch,
                roots,
                session.as_bytes(),
            )
            .expect("a current member vouches")
        })
    }

    /// One approval of a quorum subject (§4.3, proposal 0021) — recomputing the subject
    /// from the served proposal first, as every honest member must.
    pub fn approve<const D: usize>(&self, op: &mut AgoraState<StubProver, D>, subject: SubjectId) {
        let view = op.proposal(&subject).expect("proposal is open");
        let recomputed = subject_id(
            self.agora,
            view.opened,
            view.approving_class,
            &view.decision,
            &view.nonce,
        );
        assert_eq!(
            recomputed, subject,
            "the served subject does not bind the served content"
        );
        let (proof, approval) = self.acting(op, |witness, epoch, roots| {
            prove_policy_approval(
                &StubProver,
                witness,
                self.agora,
                epoch,
                roots,
                subject.as_bytes(),
            )
            .expect("a current member approves")
        });
        op.approve(subject, &proof, approval)
            .expect("approval records");
    }
}

/// Founds an agora with `founder` and one self-vouching class, as in §4:
/// `Root_voucher_eligible` is the member class while its members are the vouchers.
pub fn found<const D: usize>(
    founder: &mut Member,
    tag_seed: u8,
    log_seed: Option<u8>,
) -> AgoraState<StubProver, D> {
    let op = AgoraState::create(
        StubProver,
        &Founding {
            agora: founder.agora,
            genesis: Epoch::new(1),
            founder: founder.leaf,
            classes: &[(
                founder.class,
                ClassPolicy {
                    voucher_class: founder.class,
                    admission_threshold: 1,
                },
            )],
            founder_classes: &[founder.class],
        },
        entropy(tag_seed),
        entropy(tag_seed ^ 0x5c),
        log_seed.map(entropy),
    )
    .expect("founding succeeds");
    founder.position = 0;
    // The founder pins the statement key as part of founding (proposal 0024), then —
    // genesis having no boundary — is equipped by the current bulletin, the same
    // members-only channel every later epoch uses (proposal 0025).
    founder.statement_key = Some(op.statement_key());
    let bulletin = op.current_bulletin().expect("agora is live");
    founder.apply_bulletin(&bulletin);
    op
}

/// Admits `candidate` through a full vouch session, `vouchers` attesting (§5.3).
pub fn admit<const D: usize>(
    op: &mut AgoraState<StubProver, D>,
    candidate: &mut Member,
    vouchers: &[&Member],
    id_seed: u8,
) {
    op.credentials_init(candidate.leaf).expect("init records");
    // The statement key travels in the host's admission package (proposal 0024).
    candidate.statement_key = Some(op.statement_key());
    let session = op
        .start_vouch(candidate.leaf, candidate.class, entropy(id_seed))
        .expect("session opens");
    for voucher in vouchers {
        let (proof, n) = voucher.vouch(op, session);
        op.vouch_attest(session, &proof, n).expect("attest records");
    }
    let admission = op.vouch_finalize(session).expect("threshold met");
    candidate.position = admission.position;
}

/// Advances the boundary and delivers the bulletin to `members` — and, pointedly, to
/// nobody else.
pub fn advance<const D: usize>(op: &mut AgoraState<StubProver, D>, members: &mut [&mut Member]) {
    let bulletin = op.advance_epoch().expect("boundary advances");
    for member in members {
        member.apply_bulletin(&bulletin);
    }
}
