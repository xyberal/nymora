// SPDX-License-Identifier: MIT OR Apache-2.0

//! The operator role: one agora's server-side state and every flow that mutates it.
//!
//! A protocol defines both roles, so the Skiora side lives here in the open engine — as
//! sans-io state: methods take typed inputs and return typed outputs, the host does the
//! transport, storage, and authentication of its channels. A conformant Skiora wraps
//! [`AgoraState`]; it does not reimplement the rules.
//!
//! # The epoch is the unit of state change (proposal 0020)
//!
//! Every root any proof is checked against is **fixed for the whole epoch**. Admissions
//! and migration spends stage during the epoch and land at the boundary; revocation lands
//! immediately by *being* a boundary (§11 advances the epoch rather than waiting for it).
//! §9.3 states this rule for the exclusion roots; proposal 0020 extends it to the class
//! accumulators, because §7's `root_at_epoch` is singular and a root that moved mid-epoch
//! would make an honest proof unverifiable minutes after it was cut. The dividends are
//! structural: a member's witnesses are valid for exactly an epoch, verification history
//! is one snapshot per epoch, and "current" never races with "just changed".
//!
//! # What refusal looks like from outside
//!
//! One shape: [`ProtocolError::Rejected`], whatever the reason. A duplicate nullifier, an
//! unmet threshold, an expired session, a revoked credential, and a dissolved agora are
//! indistinguishable to a counterparty by construction (`nymora-core`'s error discipline);
//! the reasons exist locally as [`Rejection`] diagnostics and cannot reach a response. In
//! the same spirit, the acknowledgement types here ([`Recorded`]) carry no fields at all —
//! §5.3's *no incremental disclosure* as API shape.
//!
//! # The boundary bulletin
//!
//! [`AgoraState::advance_epoch`] returns a [`Bulletin`] — the new epoch's roots, both
//! exclusion sets whole, the new tag key, and the new witness-service key. This is §11's
//! own distribution mechanism generalized: the new `K_tag` is *broadcast* to remaining
//! members, and the material a member needs to act in the new epoch travels the same way.
//! It also breaks a circularity §7 alone would create: proving standing requires current
//! roots and current non-membership witnesses, so if those were obtainable only behind a
//! standing proof, no member could cross an epoch boundary at which anything changed. The
//! bulletin is the *only* way current roots leave the engine ungated (proposal 0025) —
//! there is no lookup to probe, because a public current root plus the public verifier
//! would let an outsider test a bundle for agora affiliation, the confirmation §6.4
//! exists to prevent. Everything in the bulletin goes only where the tag key goes: to
//! remaining members, which is exactly the cut §11 requires (a revoked credential
//! receives nothing further). Delivery is the host's; a Skiora that hands the bulletin to
//! a revoked member has reimplemented §11 incorrectly on its own side of the port.

mod access;
mod log;
mod migrate;
mod quorum;
mod vouch;

pub use access::{Challenge, MemberAccess};
pub use log::{conforms, equivocation, verify_log, LogEntry, SignedHead, TransparencyLog};
pub use quorum::{Executed, ProposalView};

use crate::credential::FreshEntropy;
use crate::decision::SubjectId;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use nymora_accumulator::{ExclusionSet, Tree, Witness};
use nymora_circuits::ProofSystem;
use nymora_core::{
    AgoraId, Commitment, Epoch, LocalReason, Nullifier, PolicyClass, ProtocolError, Rejection,
    Root, SecretBytes, TagKey, WitnessKey,
};
use nymora_crypto::{derive_tag_key, derive_witness_key};
use nymora_proofs::EpochRoots;

/// A zero-information acknowledgement.
///
/// Returned where the specification requires that nothing be disclosed — a recorded
/// attestation (§5.3), a recorded approval (§4.3), a credential accepted as pending. It has
/// no fields *as the property itself*: every caller receives the identical value whether
/// their contribution was the first or the one that met a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded;

/// The acknowledgement of an admission that will land at the next boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// The first epoch at which the admitted leaf is present in its class root — the
    /// epoch from which the member can act (proposal 0020).
    pub active_from: Epoch,
    /// The leaf's permanent position in the class accumulator. Append-only means it never
    /// changes; it is what the member names to refresh an inclusion witness.
    pub position: u64,
}

/// An opaque vouch-session identifier (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// The bytes the vouch nullifier is derived over.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One policy class's admission arithmetic (§4.3, §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassPolicy {
    /// The class whose members' attestations count toward admission into this one —
    /// `Root_voucher_eligible` in §5.3's terms. May be the class itself.
    pub voucher_class: PolicyClass,
    /// Attestations required to admit (§5.3's k).
    pub admission_threshold: u32,
}

/// What the boundary broadcast carries to remaining members (§11, and the module
/// documentation).
///
/// Everything a member needs to act in the new epoch: the roots proofs are now cut
/// against, both exclusion sets **whole**, the epoch's tag key, and the epoch's
/// witness-service key (proposal 0025). The sets travel whole
/// rather than as deltas because §11 already prices that as affordable — they grow with
/// revocations and migrations, never with membership — and because a delta has a hidden
/// precondition: a member admitted this very boundary has no earlier copy to advance, and
/// would start life unable to compute the absence witnesses their first proof needs.
/// Delivery to *remaining members only* is the host's obligation — this value in a
/// revoked member's hands is §11 broken.
#[derive(Debug)]
pub struct Bulletin {
    /// The epoch now current.
    pub epoch: Epoch,
    /// Each class's root for the new epoch.
    pub class_roots: Vec<(PolicyClass, Root)>,
    /// The revocation-set root for the new epoch (§11).
    pub revocation_root: Root,
    /// The migration-spend root for the new epoch (§9.3).
    pub spend_root: Root,
    /// The whole revocation set as of this boundary (§11).
    pub revoked: Vec<[u8; 32]>,
    /// The whole migration-spend set as of this boundary (§9.3).
    pub spent: Vec<[u8; 32]>,
    /// The new epoch's routing tag key (§6.4, §11).
    pub tag_key: TagKey,
    /// The new epoch's witness-service key (§5.2, proposal 0025) — what a member presents
    /// to refresh an inclusion witness, since that service cannot be proof-gated.
    pub witness_key: WitnessKey,
}

/// One class's accumulator and bookkeeping.
struct ClassState<const DEPTH: usize> {
    tree: Tree<DEPTH>,
    policy: ClassPolicy,
    version: u64,
    /// Landed leaves. The operator knows its own occupancy; nothing here reaches a
    /// counterparty (§5.2).
    occupied: u64,
    positions: BTreeMap<Commitment, u64>,
}

impl<const DEPTH: usize> ClassState<DEPTH> {
    const CAPACITY: u64 = if DEPTH < 64 { 1 << DEPTH } else { u64::MAX };
}

/// A vouch session (§5.3).
struct VouchSession {
    candidate: Commitment,
    target: PolicyClass,
    nullifiers: BTreeSet<Nullifier>,
}

/// An open quorum decision (§4.3, proposal 0021).
struct Proposal {
    decision: crate::decision::Decision,
    approving_class: PolicyClass,
    nonce: [u8; 32],
    approvals: BTreeSet<Nullifier>,
}

/// Mutations staged for the next boundary (proposal 0020).
#[derive(Default)]
struct Staged {
    admissions: Vec<(PolicyClass, Commitment)>,
    spends: Vec<Nullifier>,
    revocations: Vec<Commitment>,
}

/// The roots in force during one epoch.
struct Snapshot {
    class_roots: BTreeMap<PolicyClass, Root>,
    revocation: Root,
    spend: Root,
}

/// The immutable facts an agora is founded with (§4.1).
#[derive(Debug, Clone, Copy)]
pub struct Founding<'a> {
    /// The agora's identifier, already derived from its public parameters (§3).
    pub agora: AgoraId,
    /// The epoch the agora begins at.
    pub genesis: Epoch,
    /// The founder's leaf, `Commit(pk_root, sk_cred, r_root, agora_id)` (§9.1).
    pub founder: Commitment,
    /// Every policy class and its admission arithmetic.
    pub classes: &'a [(PolicyClass, ClassPolicy)],
    /// The classes the founder enters at creation.
    pub founder_classes: &'a [PolicyClass],
}

/// One agora's operator state — the Skiora role of §2.1, as a value.
///
/// Generic over the [`ProofSystem`] it verifies with, exactly as the member side is
/// generic over the one it proves with; the stub backend and the eventual real circuit
/// slot in identically.
pub struct AgoraState<S: ProofSystem<DEPTH>, const DEPTH: usize> {
    system: S,
    agora: AgoraId,
    epoch: Epoch,
    governance_quorum: u32,
    classes: BTreeMap<PolicyClass, ClassState<DEPTH>>,
    revocations: ExclusionSet,
    spends: ExclusionSet,
    staged: Staged,
    pending: BTreeSet<Commitment>,
    sessions: BTreeMap<SessionId, VouchSession>,
    proposals: BTreeMap<SubjectId, Proposal>,
    challenges: BTreeSet<[u8; 32]>,
    history: BTreeMap<u64, Snapshot>,
    tag_secret: SecretBytes<32>,
    log: Option<TransparencyLog>,
    dissolved: bool,
}

impl<S: ProofSystem<DEPTH>, const DEPTH: usize> AgoraState<S, DEPTH> {
    /// Creates the agora with its founder admitted (§4.1).
    ///
    /// The founder's leaf enters every class in `founder_classes` at position 0 — the one
    /// direct insertion in the agora's whole history, structural to any bootstrap: someone
    /// must exist before the first vouch session can have a voucher. Every later admission,
    /// including a co-founder's, goes through the identical vouch flow (§4). The governance
    /// quorum starts at 1 for the same unavoidable reason (§4.2), and the group's first
    /// acts should be the policy proposals that raise it (§4.3).
    ///
    /// `tag_secret` seeds the per-epoch tag keys (§6.4); `log_seed`, when present, opts
    /// this agora into the transparency log and keys its tree heads (§10.1 — opt-in
    /// because publishing roots reveals the agora exists).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] when the configuration is not self-consistent: no
    /// classes, a voucher class that is not itself configured, or a founder class that is
    /// not configured. These are properties of the caller's input, not of hidden state.
    pub fn create(
        system: S,
        founding: &Founding<'_>,
        tag_secret: FreshEntropy,
        log_seed: Option<FreshEntropy>,
    ) -> Result<Self, ProtocolError> {
        if founding.classes.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        let mut state = Self {
            system,
            agora: founding.agora,
            epoch: founding.genesis,
            governance_quorum: 1,
            classes: BTreeMap::new(),
            revocations: ExclusionSet::new(),
            spends: ExclusionSet::new(),
            staged: Staged::default(),
            pending: BTreeSet::new(),
            sessions: BTreeMap::new(),
            proposals: BTreeMap::new(),
            challenges: BTreeSet::new(),
            history: BTreeMap::new(),
            tag_secret: SecretBytes::new(tag_secret.take()),
            log: log_seed.map(|seed| TransparencyLog::new(seed.take())),
            dissolved: false,
        };
        for (class, policy) in founding.classes {
            state.classes.insert(
                *class,
                ClassState {
                    tree: Tree::new(),
                    policy: *policy,
                    version: 1,
                    occupied: 0,
                    positions: BTreeMap::new(),
                },
            );
        }
        for (_, policy) in founding.classes {
            if !state.classes.contains_key(&policy.voucher_class) {
                return Err(ProtocolError::Malformed);
            }
        }
        for class in founding.founder_classes {
            let entry = state
                .classes
                .get_mut(class)
                .ok_or(ProtocolError::Malformed)?;
            let position = entry
                .tree
                .append(founding.founder)
                .ok_or(ProtocolError::Malformed)?;
            entry.occupied += 1;
            entry.positions.insert(founding.founder, position);
        }
        state.snapshot();
        Ok(state)
    }

    /// The current epoch. Public: the schedule is agora policy, not a secret.
    #[must_use]
    pub fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    /// The inclusion witness for a landed leaf, by its permanent position, under the
    /// epoch's witness-service key (§5.2, proposal 0025).
    ///
    /// Valid for exactly the current epoch (proposal 0020). Keyed rather than proof-gated,
    /// and the distinction is forced: a member's first proof of an epoch requires the
    /// witness itself, so a proof gate has an unreachable base case — while no gate at all
    /// answers position probes, and enumerating which positions answer yields the class
    /// occupancy §5.2 withholds. The key arrives in the boundary [`Bulletin`] and rotates
    /// with it, so a revoked member loses this service at the same cut as the tag key.
    /// Which *member* is asking remains invisible to the engine; keeping the request
    /// unlinkable on the wire is the transport's obligation (§16.2).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] for a stale or wrong key, an unknown class, an unlanded
    /// position, or a dissolved agora — indistinguishably.
    pub fn witness(
        &self,
        key: &WitnessKey,
        class: PolicyClass,
        position: u64,
    ) -> Result<Witness<DEPTH>, ProtocolError> {
        self.live()?;
        if *key != self.witness_key_now() {
            return Err(Rejection::because(LocalReason::WitnessKeyStale).into());
        }
        let class = self.class(class)?;
        Ok(class
            .tree
            .witness(position)
            .ok_or(Rejection::because(LocalReason::UnknownCredential))?)
    }

    /// The current epoch's [`Bulletin`], for host re-delivery to members only (§11).
    ///
    /// [`Self::advance_epoch`] hands the boundary's bulletin to the caller once; this
    /// serves the same value again — for the genesis epoch, where no boundary has occurred
    /// and the founder must be equipped (proposal 0025), and for re-broadcast to a member
    /// who missed the boundary delivery. It is the member-gated broadcast payload, not a
    /// public lookup: this value in a non-member's hands is §11 broken, exactly as for the
    /// value `advance_epoch` returns.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] on a dissolved agora.
    pub fn current_bulletin(&self) -> Result<Bulletin, ProtocolError> {
        self.live()?;
        Ok(self.bulletin_now())
    }

    /// Advances to the next epoch: staged mutations land, roots snapshot, everything open
    /// expires, and the boundary [`Bulletin`] is produced (proposal 0020; §11).
    ///
    /// Called on the agora's schedule (§9.1) — or early, which is not a parameter but a
    /// consequence: revocation calls this itself (§11). Open vouch sessions, proposals,
    /// and unspent challenges die here; §4.3 and §5.3 make that quorum freshness, not
    /// housekeeping.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] on a dissolved agora; [`ProtocolError::Unavailable`] on
    /// epoch exhaustion.
    pub fn advance_epoch(&mut self) -> Result<Bulletin, ProtocolError> {
        self.live()?;
        let staged = core::mem::take(&mut self.staged);

        for (class, leaf) in staged.admissions {
            // Unreachable by construction: staging checked capacity. Refusing rather than
            // panicking keeps a corrupted operator from becoming a crashed one.
            let entry = self
                .classes
                .get_mut(&class)
                .ok_or(ProtocolError::Unavailable)?;
            let position = entry.tree.append(leaf).ok_or(ProtocolError::Unavailable)?;
            entry.occupied += 1;
            entry.positions.insert(leaf, position);
        }

        for nullifier in staged.spends {
            self.spends.insert(*nullifier.as_bytes());
        }
        for leaf in staged.revocations {
            self.revocations.insert(*leaf.as_bytes());
        }

        self.epoch = self.epoch.next().ok_or(ProtocolError::Unavailable)?;
        self.sessions.clear();
        self.proposals.clear();
        self.challenges.clear();
        self.snapshot();

        Ok(self.bulletin_now())
    }

    /// The transparency log, when this agora opted in (§10.1) — the public artifact,
    /// readable after dissolution too, since freezing it is what it is for.
    #[must_use]
    pub fn transparency_log(&self) -> Option<&TransparencyLog> {
        self.log.as_ref()
    }

    // ---- internal ----

    /// Refuses everything on a dissolved agora (§12): serving new state ends at freeze.
    fn live(&self) -> Result<(), Rejection> {
        if self.dissolved {
            return Err(Rejection::because(LocalReason::Dissolved));
        }
        Ok(())
    }

    fn class(&self, class: PolicyClass) -> Result<&ClassState<DEPTH>, Rejection> {
        self.classes
            .get(&class)
            .ok_or(Rejection::because(LocalReason::PolicyDenied))
    }

    /// The roots in force at `epoch` for `class`, from history.
    fn roots_in(&self, epoch: Epoch, class: PolicyClass) -> Result<EpochRoots, Rejection> {
        let snapshot = self
            .history
            .get(&epoch.get())
            .ok_or(Rejection::because(LocalReason::EpochOutOfRange))?;
        let class_root = snapshot
            .class_roots
            .get(&class)
            .ok_or(Rejection::because(LocalReason::PolicyDenied))?;
        Ok(EpochRoots {
            class: *class_root,
            revocation: snapshot.revocation,
            spend: snapshot.spend,
        })
    }

    /// Records the current trees' roots as the epoch's fixed snapshot, and logs them.
    fn snapshot(&mut self) {
        let class_roots: BTreeMap<PolicyClass, Root> = self
            .classes
            .iter()
            .map(|(class, state)| (*class, state.tree.root()))
            .collect();
        let revocation = self.revocations.root();
        let spend = self.spends.root();

        if let Some(log) = &mut self.log {
            for (class, root) in &class_roots {
                log.append(LogEntry::ClassRoot {
                    epoch: self.epoch,
                    class: *class,
                    root: *root,
                });
            }
            log.append(LogEntry::ExclusionRoots {
                epoch: self.epoch,
                revocation,
                spend,
            });
        }

        self.history.insert(
            self.epoch.get(),
            Snapshot {
                class_roots,
                revocation,
                spend,
            },
        );
    }

    /// This epoch's tag key (§6.4). Derived, not stored: the KDF is the schedule.
    fn tag_key_now(&self) -> TagKey {
        derive_tag_key(self.tag_secret.expose(), &self.agora, self.epoch)
    }

    /// This epoch's witness-service key (§5.2, proposal 0025). Derived under its own
    /// domain from the same operator secret, so the two keys' compromises stay separate.
    fn witness_key_now(&self) -> WitnessKey {
        derive_witness_key(self.tag_secret.expose(), &self.agora, self.epoch)
    }

    /// The current epoch's members-only broadcast payload (§11).
    fn bulletin_now(&self) -> Bulletin {
        let snapshot = &self.history[&self.epoch.get()];
        Bulletin {
            epoch: self.epoch,
            class_roots: snapshot
                .class_roots
                .iter()
                .map(|(class, root)| (*class, *root))
                .collect(),
            revocation_root: snapshot.revocation,
            spend_root: snapshot.spend,
            revoked: self.revocations.keys().copied().collect(),
            spent: self.spends.keys().copied().collect(),
            tag_key: self.tag_key_now(),
            witness_key: self.witness_key_now(),
        }
    }

    /// How many admissions `class` can still stage before exhaustion (§5.2).
    fn remaining_capacity(&self, class: PolicyClass) -> u64 {
        let Some(state) = self.classes.get(&class) else {
            return 0;
        };
        let staged = self
            .staged
            .admissions
            .iter()
            .filter(|(c, _)| *c == class)
            .count() as u64;
        ClassState::<DEPTH>::CAPACITY - state.occupied - staged
    }

    /// Freezes the agora permanently (§12).
    ///
    /// Roots stay in history and the log gains its final entry; the tag secret is
    /// destroyed so no future epoch's key can ever exist. With software custody this
    /// destruction is best-effort erasure; the *provable* destruction §12 promises arrives
    /// with the MPC ceremony work, out of this phase's scope.
    fn dissolve(&mut self) {
        self.dissolved = true;
        self.sessions.clear();
        self.proposals.clear();
        self.challenges.clear();
        self.staged = Staged::default();
        self.pending.clear();
        // Dropping the old value zeroizes it; what remains derives nothing.
        self.tag_secret = SecretBytes::new([0u8; 32]);
        if let Some(log) = &mut self.log {
            log.append(LogEntry::Frozen { epoch: self.epoch });
        }
    }
}
