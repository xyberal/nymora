// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared test harness: an in-memory store and a member driving a real operator.
//!
//! Each integration binary compiles this module separately and uses a different subset,
//! so unused-item lints are silenced here — this is support code, not a surface.

#![allow(dead_code)]

use nymora_accumulator::{verifies, ExclusionSet, Node, Witness};
use nymora_circuits::{ChainWitness, ProofSystem, StubProver};
use nymora_core::{
    AgoraId, Commitment, Epoch, FetchKey, InboxPublicKey, Nullifier, PolicyClass, ProtocolError,
    TagKey,
};
use nymora_crypto::signature::PUBLIC_KEY_LEN;
use nymora_crypto::{nullifier, revocation_key};
use nymora_ports::{SecureStorage, Slot, SoftwareKeyStore};
use nymora_proofs::{prove_policy_approval, prove_vouch, EpochRoots};
use nymora_protocol::operator::{AgoraState, ClassPolicy, Envelope, Founding, SessionId};
use nymora_protocol::{
    accept_envelope, create, load_acting_material, load_inbox_secret, open_own_ciphertext,
    own_lookup_tag, subject_id, BodyView, CredentialEntropy, FreshEntropy, SubjectId,
};
use std::collections::HashMap;
use std::vec::Vec;

pub type Proof<const D: usize> = <StubProver as ProofSystem<D>>::Proof;

pub fn entropy(byte: u8) -> FreshEntropy {
    FreshEntropy::new([byte; 32])
}

/// A minimal in-memory `SecureStorage`. `Clone` so a test can keep a copy of an old
/// device's material after migration destroyed the original — the §15 extracted-key
/// case, which is what the server-side migration window is measured against.
#[derive(Default, Clone)]
pub struct TestStore {
    values: HashMap<([u8; 32], Slot), Vec<u8>>,
}

impl TestStore {
    /// Whether a slot is populated.
    pub fn holds(&self, agora: AgoraId, slot: Slot) -> bool {
        self.values.contains_key(&(*agora.as_bytes(), slot))
    }
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

/// The accumulator depth most tests share; the exhaustion tests use their own. Trees
/// and exclusion sets alike carry it now that both are positional (proposal 0035).
pub const DEPTH: usize = 4;

/// A member of one agora: stored credential material plus the local copies a Persora
/// keeps — the exclusion sets rebuilt from envelopes, the tag keys received from
/// broadcasts, the inclusion path delivered in the member's own ciphertext. `D` is the
/// agora's accumulator depth, which the member's own set copies share.
pub struct Member<const D: usize> {
    pub seed: u8,
    pub agora: AgoraId,
    pub class: PolicyClass,
    pub keys: SoftwareKeyStore,
    pub store: TestStore,
    pub leaf: Commitment,
    /// The inbox key registered with the leaf (proposal 0036).
    pub inbox: InboxPublicKey,
    pub position: u64,
    pub revocations: ExclusionSet<D>,
    pub spends: ExclusionSet<D>,
    pub tag_keys: Vec<(Epoch, TagKey)>,
    /// The epoch's roots, as the envelope's body delivered them — a member holds no other
    /// source for them.
    pub roots: Option<EpochRoots>,
    /// The epoch's inclusion path, from the member's own ciphertext (proposal 0036).
    pub path: Option<Witness<D>>,
    /// The epoch's fetch key, from the body — what fetches the next envelope.
    pub fetch_key: Option<FetchKey>,
    /// The operator statement key, pinned at admission (proposal 0024) — every envelope
    /// is verified against it before anything is applied.
    pub statement_key: Option<[u8; PUBLIC_KEY_LEN]>,
    /// The last accepted envelope's epoch — the monotonicity cursor (proposal 0024).
    pub epoch: Option<Epoch>,
}

impl<const D: usize> Member<D> {
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
            CredentialEntropy {
                credential_key: entropy(seed ^ 0x44),
                root_opening: entropy(seed ^ 0x22),
                inbox_key: entropy(seed ^ 0x1b),
            },
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
            inbox: made.inbox,
            position: u64::MAX,
            revocations: ExclusionSet::new(),
            spends: ExclusionSet::new(),
            tag_keys: Vec::new(),
            roots: None,
            path: None,
            fetch_key: None,
            statement_key: None,
            epoch: None,
        };
        member.roll(epoch);
        member
    }

    /// Rolls to `epoch` with a per-member, per-epoch key.
    pub fn roll(&mut self, epoch: Epoch) {
        let epoch_seed = [self.seed.wrapping_add(epoch.get() as u8); 32];
        let mut record = [0u8; 256];
        nymora_protocol::roll_epoch(
            self.agora,
            &self.keys,
            &mut self.store,
            epoch,
            FreshEntropy::new(epoch_seed),
            &mut record,
        )
        .expect("rollover succeeds");
    }

    /// What the host does with a boundary envelope (§11, proposal 0036): verify the
    /// statement, find and open this member's own ciphertext, open the body with the key
    /// it carried, replace local set copies with the whole sets, cache the roots, the
    /// path (checked against the body's root), and both epoch keys, roll the credential.
    ///
    /// `Err(Unavailable)` when the envelope carries no ciphertext for this member — the
    /// delivery cut, observed.
    pub fn receive(&mut self, envelope: &Envelope) -> Result<(), ProtocolError> {
        // Proposal 0024: nothing is applied before the statement verifies — signature
        // under the pinned key, over the member's own agora, strictly advancing.
        accept_envelope(
            self.statement_key.as_ref().expect("statement key pinned"),
            &envelope.statement(self.agora),
            &envelope.signature,
            self.epoch,
        )?;
        let secret = load_inbox_secret(self.agora, &self.store)?;
        let tag = own_lookup_tag(&secret, &envelope.ephemeral_key, &self.class)
            .ok_or(ProtocolError::Malformed)?;
        let ciphertext = envelope
            .ciphertext(&tag)
            .ok_or(ProtocolError::Unavailable)?;
        let mut sealed = ciphertext.bytes.clone();
        let own = open_own_ciphertext(
            &secret,
            &envelope.ephemeral_key,
            &self.agora,
            envelope.epoch,
            &self.class,
            &mut sealed,
        )?;
        let prefix: Vec<Node> = own
            .path
            .chunks_exact(32)
            .map(|chunk| Node::from_bytes(chunk.try_into().expect("32 bytes")))
            .collect();
        let path =
            Witness::<D>::from_prefix(own.position, &prefix).ok_or(ProtocolError::Malformed)?;
        let mut body = envelope.body.clone();
        let view = BodyView::open(&own.body_key, &self.agora, envelope.epoch, &mut body)?;

        let class_root = view
            .class_root(self.class)
            .expect("the body carries this member's class");
        // The member's half of the single-body rule: the delivered path reproduces the
        // body's root for this leaf, or nothing is applied.
        assert!(
            verifies(&self.leaf, &path, &class_root),
            "the delivered path does not reproduce the body's class root"
        );

        self.epoch = Some(envelope.epoch);
        self.position = own.position;
        self.revocations = ExclusionSet::new();
        for key in view.revoked() {
            self.revocations.insert(key);
        }
        self.spends = ExclusionSet::new();
        for key in view.spent() {
            self.spends.insert(key);
        }
        self.roots = Some(EpochRoots {
            class: class_root,
            revocation: view.revocation_root(),
            spend: view.spend_root(),
        });
        self.path = Some(path);
        self.fetch_key = Some(FetchKey::new(*view.fetch_key().expose()));
        nymora_protocol::store_tag_key(self.agora, &mut self.store, envelope.epoch, view.tag_key())
            .expect("tag key stores");
        self.tag_keys
            .push((envelope.epoch, TagKey::new(*view.tag_key().expose())));
        self.roll(envelope.epoch);
        Ok(())
    }

    /// [`receive`](Self::receive), for a member the envelope must carry.
    pub fn apply_envelope(&mut self, envelope: &Envelope) {
        self.receive(envelope)
            .expect("the envelope is a valid signed statement carrying this member");
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

    /// Assembles the full chain witness from stored material plus the envelope-delivered
    /// inclusion path, and hands it to `f` — the closure keeps the borrows honest.
    pub fn acting<R>(
        &self,
        op: &AgoraState<StubProver, D>,
        f: impl FnOnce(&ChainWitness<'_, D>, Epoch, &EpochRoots) -> R,
    ) -> R {
        let epoch = op.current_epoch();
        let roots = *self.roots.as_ref().expect("equipped by an envelope");
        let inclusion = *self.path.as_ref().expect("equipped by an envelope");
        let revocation = self
            .revocations
            .absence_witness(&revocation_key(&self.leaf));
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
    pub fn vouch(
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
    pub fn approve(&self, op: &mut AgoraState<StubProver, D>, subject: SubjectId) {
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
    founder: &mut Member<D>,
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
            founder_inbox: founder.inbox,
        },
        entropy(tag_seed),
        entropy(tag_seed ^ 0x5c),
        log_seed.map(entropy),
    )
    .expect("founding succeeds");
    // The founder pins the statement key as part of founding (proposal 0024), then —
    // genesis having no boundary — is equipped by the current envelope, the same
    // members-only channel every later epoch uses.
    founder.statement_key = Some(op.statement_key());
    let envelope = op.current_envelope().expect("agora is live");
    founder.apply_envelope(&envelope);
    op
}

/// Admits `candidate` through a full vouch session, `vouchers` attesting (§5.3).
pub fn admit<const D: usize>(
    op: &mut AgoraState<StubProver, D>,
    candidate: &mut Member<D>,
    vouchers: &[&Member<D>],
    id_seed: u8,
) {
    op.credentials_init(candidate.leaf, candidate.inbox)
        .expect("init records");
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

/// Advances the boundary and delivers the envelope to `members`.
pub fn advance<const D: usize>(op: &mut AgoraState<StubProver, D>, members: &mut [&mut Member<D>]) {
    let envelope = op.advance_epoch().expect("boundary advances");
    for member in members {
        member.apply_envelope(&envelope);
    }
}
