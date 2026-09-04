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
//! # The boundary envelope (proposal 0036)
//!
//! [`AgoraState::advance_epoch`] returns an [`Envelope`]: the new epoch's roots, both
//! exclusion sets whole, the tag key, and the fetch key in one body encrypted **once**,
//! plus one ciphertext per live credential carrying the body key and that member's own
//! inclusion path, sealed to the inbox key the member registered with its leaf. This is
//! §11's own distribution mechanism made literal: what reaches remaining members and not
//! the revoked one is exactly this broadcast, because a revoked leaf's ciphertext is
//! simply not produced. It also breaks the circularity §7 alone would create — proving
//! standing requires current roots and a current path, so if those were obtainable only
//! behind a standing proof, no member could cross a boundary — and it retires the
//! witness service that proposal 0025 keyed: no surface returns any path but the
//! requester's own. The envelope is the *only* way current roots leave the engine —
//! there is no lookup to probe, because a public current root plus the public verifier
//! would let an outsider test a bundle for agora affiliation (§6.4). The fetch key gates
//! the envelope's fetch; the host's obligation is the window, and its blast radius is
//! stated in `nymora-core`'s `FetchKey`.

mod access;
mod inbox;
mod log;
mod migrate;
mod quorum;
mod vouch;

pub use access::{Challenge, MemberAccess};
pub use inbox::{DEFAULT_INBOX_HORIZON, MIN_INBOX_HORIZON};
pub use log::{conforms, equivocation, verify_log, LogEntry, SignedHead, TransparencyLog};
pub use quorum::{Executed, ProposalView};

use crate::bulletin::{ciphertexts_digest, EmbeddedHead, EnvelopeStatement};
use crate::credential::FreshEntropy;
use crate::decision::SubjectId;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use nymora_accumulator::{ExclusionSet, Tree};
use nymora_circuits::ProofSystem;
use nymora_core::{
    AgoraId, Commitment, Epoch, FetchKey, InboxPublicKey, InboxTag, LocalReason, Nullifier,
    PolicyClass, ProtocolError, Rejection, Root, SecretBytes, TagKey, DIGEST_LEN,
};
use nymora_crypto::signature::{self, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use nymora_crypto::{derive_fetch_key, derive_tag_key, inbox as inbox_crypto, revocation_key};
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
    /// Attestations required to admit (§5.3's k). At least 1 (proposal 0027); a zero
    /// here refuses the founding as self-inconsistent.
    pub admission_threshold: u32,
}

/// The shared contents of one boundary — what the body carries, owned (§11, proposal
/// 0036). Host-facing: the operator's own record of what it broadcast, for bookkeeping
/// and for tests. Members receive it only inside the encrypted envelope.
#[derive(Debug)]
pub struct Body {
    /// The epoch now current.
    pub epoch: Epoch,
    /// Each class's root for the new epoch, in ascending class order.
    pub class_roots: Vec<(PolicyClass, Root)>,
    /// The revocation-set root for the new epoch (§11).
    pub revocation_root: Root,
    /// The migration-spend root for the new epoch (§9.3).
    pub spend_root: Root,
    /// The whole revocation set as of this boundary, ascending — entries
    /// `Poseidon(REVOKE, leaf)`, never leaves (§11, proposal 0036).
    pub revoked: Vec<[u8; 32]>,
    /// The whole migration-spend set as of this boundary, ascending (§9.3).
    pub spent: Vec<[u8; 32]>,
    /// The new epoch's routing tag key (§6.4, §11).
    pub tag_key: TagKey,
    /// The new epoch's fetch key — what fetches the next envelope (§11).
    pub fetch_key: FetchKey,
}

impl Body {
    /// The canonical layout `BodyView` reads (see `bulletin`).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.epoch.get().to_le_bytes());
        out.extend_from_slice(&(self.class_roots.len() as u64).to_le_bytes());
        for (class, root) in &self.class_roots {
            out.extend_from_slice(class.as_bytes());
            out.extend_from_slice(root.as_bytes());
        }
        out.extend_from_slice(self.revocation_root.as_bytes());
        out.extend_from_slice(self.spend_root.as_bytes());
        out.extend_from_slice(&(self.revoked.len() as u64).to_le_bytes());
        for entry in &self.revoked {
            out.extend_from_slice(entry);
        }
        out.extend_from_slice(&(self.spent.len() as u64).to_le_bytes());
        for entry in &self.spent {
            out.extend_from_slice(entry);
        }
        out.extend_from_slice(self.tag_key.expose());
        out.extend_from_slice(self.fetch_key.expose());
        out
    }
}

/// One member's ciphertext in an envelope: the lookup tag and the sealed bytes
/// (ciphertext with its authentication tag appended).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// What the member finds it by.
    pub tag: InboxTag,
    /// `seal(K_body ‖ position ‖ height ‖ path)`.
    pub bytes: Vec<u8>,
}

/// What the boundary broadcast is (§11, proposal 0036): one signed operator statement
/// carrying the encrypted body and one ciphertext per live credential.
///
/// [`Self::signature`] covers the canonical digest of everything above it
/// ([`EnvelopeStatement::digest`]), cut by the per-agora statement key
/// ([`AgoraState::statement_key`]). Members accept it with
/// [`accept_envelope`](crate::bulletin::accept_envelope) — signature under the key
/// pinned at admission, plus a strictly advancing epoch — then open their own ciphertext
/// and, with the body key it carries, the body.
#[derive(Debug)]
pub struct Envelope {
    /// The epoch now current.
    pub epoch: Epoch,
    /// The operator's agreement key for this boundary.
    pub ephemeral_key: InboxPublicKey,
    /// The body, sealed once under `K_body_e` (authentication tag appended).
    pub body: Vec<u8>,
    /// One ciphertext per live credential per class it holds, in class-then-position
    /// order.
    pub ciphertexts: Vec<Ciphertext>,
    /// The latest signed transparency-log head, where this agora keeps a log (§10.1;
    /// proposal 0024).
    pub head: Option<EmbeddedHead>,
    /// The statement key's signature over the canonical envelope digest.
    pub signature: [u8; SIGNATURE_LEN],
}

impl Envelope {
    /// This envelope's signed statement, bound to `agora`.
    ///
    /// The agora is the *viewer's*: the operator binds its own when signing, and a member
    /// binds theirs when verifying, so an envelope from any other agora fails
    /// structurally (§16.1).
    #[must_use]
    pub fn statement(&self, agora: AgoraId) -> EnvelopeStatement<'_> {
        EnvelopeStatement {
            agora,
            epoch: self.epoch,
            ephemeral_key: self.ephemeral_key,
            body: &self.body,
            ciphertexts_digest: self.ciphertexts_digest(),
            head: self.head.as_ref(),
        }
    }

    /// The digest of the ciphertext list, as the statement absorbs it.
    #[must_use]
    pub fn ciphertexts_digest(&self) -> [u8; DIGEST_LEN] {
        ciphertexts_digest(
            self.ciphertexts
                .iter()
                .map(|ciphertext| (&ciphertext.tag, ciphertext.bytes.as_slice())),
        )
    }

    /// The ciphertext under `tag`, if the envelope carries one.
    #[must_use]
    pub fn ciphertext(&self, tag: &InboxTag) -> Option<&Ciphertext> {
        self.ciphertexts
            .iter()
            .find(|ciphertext| ciphertext.tag == *tag)
    }
}

/// A credential's registered inbox key and when the registration (last) began.
struct InboxRecord {
    key: InboxPublicKey,
    since: Epoch,
}

/// The empty value the class accumulator places after every leaf (proposal 0036).
const PAD: Commitment = Commitment::from_bytes([0u8; DIGEST_LEN]);

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
    /// Leaves the class can ever hold: every leaf takes an even position and its odd
    /// neighbour stays empty (§5.2, proposal 0036), so half the tree's slots.
    const CAPACITY: u64 = if DEPTH == 0 {
        1
    } else if DEPTH < 64 {
        1 << (DEPTH - 1)
    } else {
        u64::MAX
    };

    /// The position the `index`-th leaf takes.
    const fn position_of(index: u64) -> u64 {
        index * 2
    }

    /// Lands a leaf at the next even position, padding its neighbour (proposal 0036).
    fn land(&mut self, leaf: Commitment) -> Option<u64> {
        let position = self.tree.append(leaf)?;
        debug_assert_eq!(position, Self::position_of(self.occupied));
        // A depth-0 tree has no neighbour to pad; elsewhere the pad always fits, since
        // capacity counts leaves as pairs of slots.
        let _ = self.tree.append(PAD);
        self.occupied += 1;
        self.positions.insert(leaf, position);
        Some(position)
    }
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
    /// The epoch the proposal was raised in — the value `subject_id` was derived under.
    /// Stored rather than read back as the current epoch: a proposal cannot outlive its
    /// epoch (it is cleared at the boundary), so the two coincide today, but binding the
    /// served `opened` to the derivation's own input keeps a member's recomputation
    /// correct by construction rather than by that coincidence.
    opened: Epoch,
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

/// Where a staged admission carries its inbox key to the boundary.
type StagedInbox = BTreeMap<Commitment, InboxPublicKey>;

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
    /// The founder's inbox key, registered with the leaf (§4.1, proposal 0036).
    pub founder_inbox: InboxPublicKey,
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
    revocations: ExclusionSet<DEPTH>,
    spends: ExclusionSet<DEPTH>,
    staged: Staged,
    pending: BTreeSet<Commitment>,
    sessions: BTreeMap<SessionId, VouchSession>,
    proposals: BTreeMap<SubjectId, Proposal>,
    challenges: BTreeSet<[u8; 32]>,
    history: BTreeMap<u64, Snapshot>,
    tag_secret: SecretBytes<32>,
    statement_seed: SecretBytes<32>,
    log: Option<TransparencyLog>,
    dissolved: bool,
    /// Every credential's delivery address, by leaf (proposal 0036). A row the
    /// operator already had — leaf, position — with one more column.
    inboxes: BTreeMap<Commitment, InboxRecord>,
    /// Inbox keys of leaves pending or staged, carried to the boundary.
    staged_inboxes: StagedInbox,
    /// Leaves whose revocation landed: the operator's own record, so no ciphertext is
    /// produced for them. The public set holds their hashed entries.
    revoked_leaves: BTreeSet<Commitment>,
    /// How many boundaries a registration lasts before renewal (§11, proposal 0036) —
    /// a per-agora policy value.
    inbox_horizon: u64,
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
    /// `tag_secret` seeds the per-epoch tag keys (§6.4); `statement_entropy` seeds the
    /// operator **statement key** that signs every bulletin (§11, proposal 0024) —
    /// distinct from member material and from the log key, and required for every agora,
    /// log or no log; `log_seed`, when present, opts this agora into the transparency
    /// log and keys its tree heads (§10.1 — opt-in because publishing roots reveals the
    /// agora exists).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] when the configuration is not self-consistent: no
    /// classes, a voucher class that is not itself configured, a founder class that is
    /// not configured, or a zero admission threshold (proposal 0027). These are
    /// properties of the caller's input, not of hidden state.
    pub fn create(
        system: S,
        founding: &Founding<'_>,
        tag_secret: FreshEntropy,
        statement_entropy: FreshEntropy,
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
            statement_seed: SecretBytes::new(signature::mint_signing_secret(
                statement_entropy.take(),
            )),
            log: log_seed.map(|seed| TransparencyLog::new(seed.take())),
            dissolved: false,
            inboxes: BTreeMap::new(),
            staged_inboxes: BTreeMap::new(),
            revoked_leaves: BTreeSet::new(),
            inbox_horizon: DEFAULT_INBOX_HORIZON,
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
            if policy.admission_threshold == 0 {
                // Proposal 0027: zero admits on no attestation at all.
                return Err(ProtocolError::Malformed);
            }
            if !state.classes.contains_key(&policy.voucher_class) {
                return Err(ProtocolError::Malformed);
            }
        }
        for class in founding.founder_classes {
            let entry = state
                .classes
                .get_mut(class)
                .ok_or(ProtocolError::Malformed)?;
            entry
                .land(founding.founder)
                .ok_or(ProtocolError::Malformed)?;
        }
        state.inboxes.insert(
            founding.founder,
            InboxRecord {
                key: founding.founder_inbox,
                since: founding.genesis,
            },
        );
        state.snapshot();
        Ok(state)
    }

    /// The current epoch. Public: the schedule is agora policy, not a secret.
    #[must_use]
    pub fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    /// The operator statement key's public half (§11, proposal 0024) — what members pin
    /// at admission and verify every bulletin against.
    ///
    /// How it reaches a member is the host's admission package, alongside the `agora_id`
    /// itself (§3): both are facts a member must hold before their first bulletin, and
    /// neither can be bootstrapped from the channel the bulletin arrives on.
    #[must_use]
    pub fn statement_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        signature::public_key(self.statement_seed.expose()).expect("minted keys are canonical")
    }

    /// The current epoch's [`Envelope`], for host re-delivery to members (§11).
    ///
    /// [`Self::advance_epoch`] hands the boundary's envelope to the caller once; this
    /// serves the same value again — for the genesis epoch, where no boundary has
    /// occurred and the founder must be equipped, and for a member who missed the
    /// boundary delivery. Gate it with the fetch key window; an envelope's contents are
    /// ciphertext to everyone but its members regardless.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] on a dissolved agora.
    pub fn current_envelope(&self) -> Result<Envelope, ProtocolError> {
        self.live()?;
        Ok(self.envelope_now())
    }

    /// The current epoch's shared body, owned — the operator's own record of what the
    /// envelope encrypts, for host bookkeeping. Member-gated semantics: this value in a
    /// non-member's hands is §11 broken.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] on a dissolved agora.
    pub fn current_body(&self) -> Result<Body, ProtocolError> {
        self.live()?;
        Ok(self.body_now())
    }

    /// This epoch's fetch key (§11, proposal 0036) — what the host's envelope route
    /// accepts, within its catch-up window, to serve the envelope.
    #[must_use]
    pub fn fetch_key_now(&self) -> FetchKey {
        derive_fetch_key(self.tag_secret.expose(), &self.agora, self.epoch)
    }

    /// The inbox horizon in force (§11, proposal 0036).
    #[must_use]
    pub fn inbox_horizon(&self) -> u64 {
        self.inbox_horizon
    }

    /// Advances to the next epoch: staged mutations land, roots snapshot, everything open
    /// expires, and the boundary [`Envelope`] is produced (proposal 0020; §11).
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
    pub fn advance_epoch(&mut self) -> Result<Envelope, ProtocolError> {
        self.live()?;
        let staged = core::mem::take(&mut self.staged);
        let next = self.epoch.next().ok_or(ProtocolError::Unavailable)?;

        for (class, leaf) in staged.admissions {
            // Unreachable by construction: staging checked capacity. Refusing rather than
            // panicking keeps a corrupted operator from becoming a crashed one.
            let entry = self
                .classes
                .get_mut(&class)
                .ok_or(ProtocolError::Unavailable)?;
            entry.land(leaf).ok_or(ProtocolError::Unavailable)?;
            if let Some(key) = self.staged_inboxes.remove(&leaf) {
                self.inboxes.insert(leaf, InboxRecord { key, since: next });
            }
        }

        for nullifier in staged.spends {
            self.spends.insert(*nullifier.as_bytes());
        }
        for leaf in staged.revocations {
            // The public set holds the hashed entry (proposal 0036); the raw leaf is the
            // operator's own record, so no ciphertext is produced for it again.
            self.revocations.insert(revocation_key(&leaf));
            self.revoked_leaves.insert(leaf);
        }

        self.epoch = next;
        self.sessions.clear();
        self.proposals.clear();
        self.challenges.clear();
        self.snapshot();

        Ok(self.envelope_now())
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

    /// The current epoch's shared body (§11, proposal 0036).
    fn body_now(&self) -> Body {
        let snapshot = &self.history[&self.epoch.get()];
        Body {
            epoch: self.epoch,
            class_roots: snapshot
                .class_roots
                .iter()
                .map(|(class, root)| (*class, *root))
                .collect(),
            revocation_root: snapshot.revocation,
            spend_root: snapshot.spend,
            revoked: self.revocations.keys().collect(),
            spent: self.spends.keys().collect(),
            tag_key: self.tag_key_now(),
            fetch_key: self.fetch_key_now(),
        }
    }

    /// The current epoch's envelope, signed (§11; proposals 0024, 0036).
    ///
    /// Every key here is derived from the operator secret and the epoch — the ephemeral
    /// agreement key, the body key, the fetch key — so a host replaying its journal
    /// reconstructs this value byte for byte. The embedded head is the log's latest —
    /// appended by [`Self::snapshot`] *before* any envelope for the epoch exists, so the
    /// head always covers the roots the body carries.
    fn envelope_now(&self) -> Envelope {
        let secret = self.tag_secret.expose();
        let ephemeral_secret =
            inbox_crypto::derive_ephemeral_secret(secret, &self.agora, self.epoch);
        let ephemeral_key = inbox_crypto::inbox_public_key(&ephemeral_secret);
        let body_key = inbox_crypto::derive_body_key(secret, &self.agora, self.epoch);
        let associated = inbox_crypto::associated_data(&self.agora, self.epoch);

        let mut body = self.body_now().encode();
        let tag = inbox_crypto::seal_in_place(body_key.expose(), &associated, &mut body);
        body.extend_from_slice(&tag);

        // One ciphertext per live credential per class, class-then-position order: the
        // path below the occupied height, the body key, the position. A revoked leaf, an
        // unregistered one, an expired registration, or a key that agrees on nothing is
        // simply not here — the delivery cut is the absence itself.
        let mut ciphertexts = Vec::new();
        for (class, state) in &self.classes {
            let height = state.tree.occupied_height();
            let mut by_position: Vec<(u64, Commitment)> = state
                .positions
                .iter()
                .map(|(leaf, position)| (*position, *leaf))
                .collect();
            by_position.sort_unstable();
            for (position, leaf) in by_position {
                let Some(inbox) = self.inbox_live(&leaf) else {
                    continue;
                };
                let Some(agreed) = inbox_crypto::agree(&ephemeral_secret, &inbox) else {
                    continue;
                };
                let Some(witness) = state.tree.witness(position) else {
                    continue;
                };
                let mut plain = Vec::with_capacity(DIGEST_LEN + 8 + 1 + height * DIGEST_LEN);
                plain.extend_from_slice(body_key.expose());
                plain.extend_from_slice(&position.to_le_bytes());
                plain.push(height as u8);
                for sibling in &witness.siblings()[..height] {
                    plain.extend_from_slice(sibling.as_bytes());
                }
                let key = inbox_crypto::seal_key(&agreed, &ephemeral_key, &inbox, class);
                let tag = inbox_crypto::seal_in_place(key.expose(), &associated, &mut plain);
                plain.extend_from_slice(&tag);
                ciphertexts.push(Ciphertext {
                    tag: inbox_crypto::lookup_tag(&agreed, &ephemeral_key, &inbox, class),
                    bytes: plain,
                });
            }
        }

        let head = self
            .log
            .as_ref()
            .and_then(|log| log.heads().last())
            .map(|head| EmbeddedHead {
                sequence: head.sequence,
                head: head.head,
                signature: head.signature,
            });
        let mut envelope = Envelope {
            epoch: self.epoch,
            ephemeral_key,
            body,
            ciphertexts,
            head,
            signature: [0u8; SIGNATURE_LEN],
        };
        let digest = envelope.statement(self.agora).digest();
        envelope.signature = signature::sign(
            self.statement_seed.expose(),
            &nymora_crypto::field::from_id(&digest),
        )
        .expect("minted keys are canonical");
        envelope
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
    /// with the MPC custody work (§4.4), which is roadmap rather than this module.
    fn dissolve(&mut self) {
        self.dissolved = true;
        self.sessions.clear();
        self.proposals.clear();
        self.challenges.clear();
        self.staged = Staged::default();
        self.pending.clear();
        // Dropping the old values zeroizes them; what remains derives nothing and signs
        // nothing — no bulletin follows a freeze (proposal 0024).
        self.tag_secret = SecretBytes::new([0u8; 32]);
        self.statement_seed = SecretBytes::new([0u8; 32]);
        if let Some(log) = &mut self.log {
            log.append(LogEntry::Frozen { epoch: self.epoch });
        }
    }
}
