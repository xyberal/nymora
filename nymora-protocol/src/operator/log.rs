// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-agora transparency log (§10.1): identity-free aggregate commitments, chained
//! and signed, auditable by anyone.
//!
//! # The never-on-the-log rule is the type
//!
//! §10.1's rule — a value derived from a durable secret may be revealed to Skiora but must
//! never be published here — is enforced by [`LogEntry`] simply having no variant that
//! could carry a nullifier, a commitment, a pseudonym, or anything per-member. The log is
//! roots, policy-change facts, and the freeze; adding a variant is the moment to reread
//! §10.1, because the log is public, permanent, and undeletable, and anything on it
//! belongs to every future adversary.
//!
//! No entry carries the `agora_id`, deliberately: the log's existence already reveals *an*
//! agora exists (why §10.1 makes it opt-in), and unlabeled roots are what §10.1's pooled
//! deployment needs — an auditor confirms consistency without isolating one agora's
//! history. What ties heads to one log is the signing key, not a name.
//!
//! # Why a chain, and what signs the heads
//!
//! The log is a linear hash chain, not a Merkle log with consistency proofs — proposal
//! 0023 records the argument (per-epoch growth makes full replay cheaper than one tree
//! consistency proof, and a consistency-proof query would reveal which head the asker
//! last saw). The member key hierarchy is the wrong tool for signing heads — those keys
//! are private witnesses (§9.1). The head key is operator-held log material: it exists
//! to make the *log* non-repudiable by its operator, not to say anything about members.
//! It uses the provisional signature and is as replaceable as the scheme itself.
//!
//! # What an auditor gets
//!
//! The three §10.1 checks, as pure functions over the public artifact: [`verify_log`]
//! (append-only integrity — every entry is under every later head, so removal or rewrite
//! breaks the chain), [`equivocation`] (two validly-signed heads for one sequence number
//! are proof of a fork, carryable to anyone), and [`conforms`] (protocol shape: epochs
//! never rewind, and nothing follows the freeze). The auditor holds no membership, no
//! content, and no identity — the log answers "is the machinery honest," never "who".

use alloc::vec::Vec;
use nymora_core::{Domain, Epoch, PolicyClass, Root, SecretBytes};
use nymora_crypto::signature::{self, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use nymora_crypto::ByteHasher;

/// One identity-free aggregate commitment (§10.1's admissible list, exactly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogEntry {
    /// One class's accumulator root at one epoch (§5.2 — a root reveals nothing on its
    /// own).
    ClassRoot {
        /// The epoch the root is fixed for.
        epoch: Epoch,
        /// The class whose root this is.
        class: PolicyClass,
        /// The root itself.
        root: Root,
    },
    /// The two exclusion roots every routine proof proves non-membership against, at one
    /// epoch (§9.1, §11) — published so exclusion state cannot be forked per member.
    ExclusionRoots {
        /// The epoch the roots are fixed for.
        epoch: Epoch,
        /// The revocation-set root (§11).
        revocation: Root,
        /// The migration-spend root (§9.3).
        spend: Root,
    },
    /// *That* a class's policy changed at an epoch — never who voted (§4.3, §10.1).
    PolicyChanged {
        /// The epoch of activation.
        epoch: Epoch,
        /// The class whose policy changed.
        class: PolicyClass,
        /// The class's new policy version.
        version: u64,
    },
    /// The agora froze (§12). Terminal: nothing may follow.
    Frozen {
        /// The epoch at which dissolution executed.
        epoch: Epoch,
    },
}

impl LogEntry {
    /// Absorbs the entry's canonical encoding: a discriminant, then every field framed.
    ///
    /// The discriminant keeps variants with coinciding field bytes distinct; framing does
    /// the rest. This is a hashing encoding, not a wire format — the host serializes the
    /// public artifact however it likes, but the chain is over *these* bytes everywhere.
    fn absorb_into(&self, hasher: ByteHasher) -> ByteHasher {
        match self {
            Self::ClassRoot { epoch, class, root } => hasher
                .absorb(&[0])
                .absorb(&epoch.get().to_le_bytes())
                .absorb(class.as_bytes())
                .absorb(root.as_bytes()),
            Self::ExclusionRoots {
                epoch,
                revocation,
                spend,
            } => hasher
                .absorb(&[1])
                .absorb(&epoch.get().to_le_bytes())
                .absorb(revocation.as_bytes())
                .absorb(spend.as_bytes()),
            Self::PolicyChanged {
                epoch,
                class,
                version,
            } => hasher
                .absorb(&[2])
                .absorb(&epoch.get().to_le_bytes())
                .absorb(class.as_bytes())
                .absorb(&version.to_le_bytes()),
            Self::Frozen { epoch } => hasher.absorb(&[3]).absorb(&epoch.get().to_le_bytes()),
        }
    }

    /// The epoch an entry speaks about, for the conformance check.
    fn epoch(&self) -> Epoch {
        match self {
            Self::ClassRoot { epoch, .. }
            | Self::ExclusionRoots { epoch, .. }
            | Self::PolicyChanged { epoch, .. }
            | Self::Frozen { epoch } => *epoch,
        }
    }
}

/// A signed tree head: the operator's commitment to the log's first `sequence + 1`
/// entries (§10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    /// The index of the newest entry this head commits to.
    pub sequence: u64,
    /// The chained digest over entries `0..=sequence`.
    pub head: [u8; 32],
    /// The log key's signature over the canonical head payload.
    ///
    /// Sized by the provisional scheme; like every signature in the workspace, its width
    /// is deliberately unpinned by anything but the scheme itself.
    pub signature: [u8; SIGNATURE_LEN],
}

/// The append-only log an opted-in agora publishes (§10.1).
pub struct TransparencyLog {
    seed: SecretBytes<32>,
    entries: Vec<LogEntry>,
    heads: Vec<SignedHead>,
}

impl TransparencyLog {
    /// A fresh log keyed by an operator-held seed (see the module documentation).
    pub(super) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed: SecretBytes::new(seed),
            entries: Vec::new(),
            heads: Vec::new(),
        }
    }

    /// Appends an entry, extends the chain, and signs the new head.
    pub(super) fn append(&mut self, entry: LogEntry) {
        let prev = self.heads.last().map_or([0u8; 32], |h| h.head);
        let head = chain_step(&prev, &entry);
        let sequence = self.entries.len() as u64;
        let signature = signature::sign(self.seed.expose(), |absorb| {
            head_payload(sequence, &head, absorb);
        });
        self.entries.push(entry);
        self.heads.push(SignedHead {
            sequence,
            head,
            signature,
        });
    }

    /// The key auditors verify heads against — the one public fact identifying this log.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        signature::public_key(self.seed.expose())
    }

    /// Every entry, in order. Public by definition.
    #[must_use]
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Every signed head, in order — one per entry.
    ///
    /// A deployment gossips these; two views disagreeing at any sequence is a fork
    /// ([`equivocation`]).
    #[must_use]
    pub fn heads(&self) -> &[SignedHead] {
        &self.heads
    }
}

/// One chain step: the previous head and the entry's canonical encoding, domain-tagged.
fn chain_step(prev: &[u8; 32], entry: &LogEntry) -> [u8; 32] {
    entry
        .absorb_into(ByteHasher::new(Domain::TransparencyEntry).absorb(prev))
        .finalize()
}

/// The canonical bytes a head signature covers: the head domain tag, the sequence, the
/// head. Fixed widths after the tag — nothing here is attacker-length-controlled.
fn head_payload(sequence: u64, head: &[u8; 32], absorb: &mut dyn FnMut(&[u8])) {
    absorb(Domain::TransparencyHead.tag().as_bytes());
    absorb(&sequence.to_le_bytes());
    absorb(head);
}

/// Whether a signed head verifies under a log key, on its own.
fn head_verifies(head: &SignedHead, public_key: &[u8]) -> bool {
    signature::verify(
        public_key,
        |absorb| head_payload(head.sequence, &head.head, absorb),
        &head.signature,
    )
}

/// §10.1 check 2 — append-only integrity: the entries recompute the chain, and every
/// presented head is a validly-signed commitment to exactly its prefix.
///
/// A retroactively altered or deleted entry changes every later head; a fabricated head
/// fails its signature. Auditable with no state but the public artifact and the log key.
#[must_use]
pub fn verify_log(entries: &[LogEntry], heads: &[SignedHead], public_key: &[u8]) -> bool {
    let mut chain = [0u8; 32];
    let mut recomputed = Vec::with_capacity(entries.len());
    for entry in entries {
        chain = chain_step(&chain, entry);
        recomputed.push(chain);
    }
    heads.iter().all(|head| {
        usize::try_from(head.sequence)
            .ok()
            .and_then(|i| recomputed.get(i))
            .is_some_and(|expected| *expected == head.head)
            && head_verifies(head, public_key)
    })
}

/// §10.1 check 1 — non-equivocation: two validly-signed heads for the same sequence with
/// different digests are a fork, and this pair is portable proof of it.
///
/// This is the check that requires gossip: it only ever fires when independent auditors
/// compare views (§10.1's stated condition for the guarantee).
#[must_use]
pub fn equivocation(a: &SignedHead, b: &SignedHead, public_key: &[u8]) -> bool {
    a.sequence == b.sequence
        && a.head != b.head
        && head_verifies(a, public_key)
        && head_verifies(b, public_key)
}

/// §10.1 check 3 — protocol conformance, from the log alone: epochs never rewind, and a
/// frozen agora publishes nothing further (§12's freeze, observable).
#[must_use]
pub fn conforms(entries: &[LogEntry]) -> bool {
    let mut last = None;
    let mut frozen = false;
    for entry in entries {
        if frozen {
            return false;
        }
        let epoch = entry.epoch();
        if last.is_some_and(|previous| epoch < previous) {
            return false;
        }
        last = Some(epoch);
        if matches!(entry, LogEntry::Frozen { .. }) {
            frozen = true;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chain step's canonical bytes, pinned by independent computation (Python):
    /// every implementation — and every auditor — must recompute the identical chain
    /// from the same public entries.
    #[test]
    fn the_chain_step_matches_the_known_answer() {
        let head = chain_step(
            &[0u8; 32],
            &LogEntry::ClassRoot {
                epoch: Epoch::new(3),
                class: PolicyClass::from_bytes([0x11; 32]),
                root: Root::from_bytes([0x22; 32]),
            },
        );
        let expected: [u8; 32] = [
            0x7e, 0x37, 0xb6, 0xf8, 0x6b, 0xa3, 0x78, 0xbc, 0xa6, 0x20, 0xfd, 0xbd, 0x7f, 0xfb,
            0x9a, 0x03, 0x3b, 0x01, 0x24, 0xbb, 0xe7, 0x62, 0xc1, 0x1d, 0x1a, 0xbd, 0xe7, 0x20,
            0x81, 0xa6, 0x6f, 0x2e,
        ];
        assert_eq!(head, expected);
    }
}
