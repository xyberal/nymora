// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boundary bulletin as a signed operator statement (§11, proposal 0024).
//!
//! The bulletin is a member's entire view of a new epoch — the roots to prove against,
//! the whole exclusion sets, both epoch keys — and it is meant to be cached, relayed
//! peer-to-peer, and fetched through infrastructure the member does not trust. That
//! calls for object security: the artifact carries its own authenticity, rather than
//! borrowing one hop's channel security. An unsigned bulletin fed to a *verifier* swaps
//! the integrity anchor under every proof they check (§8.3's offline story); replayed to
//! a member, it holds them at pre-revocation roots, defeating §11's forced-boundary
//! immediacy in transit.
//!
//! # What the signature covers, and who signs
//!
//! The canonical statement digest ([`BulletinStatement::digest`]) leads with
//! [`Domain::Bulletin`], absorbs the `agora_id` — so no-replay-across-agoras (§16.1)
//! holds by construction — and length-frames every field, the sets in the ascending
//! order the operator emits them. The signer is the per-agora **operator statement
//! key**: distinct from all member material (the signature makes the *operator*
//! non-repudiable and says nothing about members), and distinct from the log-head key
//! (§10.1) — role separation, so a log key disclosed for public auditing reveals
//! nothing about the member-gated channel.
//!
//! # Acceptance is signature plus strict monotonicity
//!
//! A member accepts a bulletin only if the signature verifies under the statement key
//! pinned at admission **and** the epoch is strictly greater than the member's current
//! one. Monotonicity is the whole freshness rule, and it is sufficient because the sets
//! arrive whole (§11): a member offline for several boundaries applies the latest
//! bulletin alone and is current.
//!
//! # Equivocation is portable
//!
//! Two validly signed bulletins for one epoch with different content are proof of a
//! fork, carryable to anyone who holds the statement key — §10.1's equivocation check
//! extended to agoras that declined the log. This is the property per-member
//! authenticators can never give, which is why 0024 rejects MACs outright: a per-member
//! authenticator is precisely the tool for undetectable per-member forking.
//!
//! # This module is feature-free deliberately
//!
//! Verification is the member's job, and the member build carries no allocator and no
//! `operator` feature. Everything here borrows; the operator's owned [`Bulletin`]
//! (`operator` feature) views into it to sign, and a host's parsed broadcast views into
//! it to verify.

use nymora_core::{AgoraId, Domain, Epoch, PolicyClass, ProtocolError, Root, TagKey, WitnessKey};
use nymora_crypto::signature::{self, SIGNATURE_LEN};
use nymora_crypto::ByteHasher;

/// The latest signed log head, embedded where the agora keeps a transparency log
/// (§10.1; proposal 0024's second open question, decided yes).
///
/// Embedding binds the member-gated artifact to the public one: a member cross-checks
/// the bulletin's roots against the log with no extra fetch, and a bulletin claiming
/// roots the log never saw carries the evidence of that inside itself. The shape
/// mirrors the log's `SignedHead`, restated here so a member build needs no `operator`
/// feature to absorb it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedHead {
    /// The index of the newest log entry the head commits to.
    pub sequence: u64,
    /// The chained digest over entries `0..=sequence` (§10.1).
    pub head: [u8; 32],
    /// The log key's signature over the canonical head payload.
    pub signature: [u8; SIGNATURE_LEN],
}

/// Everything a bulletin's signature covers, borrowed.
///
/// The `agora` is supplied by whoever computes the digest — the operator binds its own,
/// and a verifying member binds *theirs*, so a bulletin from any other agora fails
/// verification structurally rather than by inspection.
pub struct BulletinStatement<'a> {
    /// The agora the statement speaks for (§16.1: inside the signed bytes).
    pub agora: AgoraId,
    /// The epoch the bulletin equips.
    pub epoch: Epoch,
    /// Every class root fixed for the epoch, in the operator's ascending class order.
    pub class_roots: &'a [(PolicyClass, Root)],
    /// The revocation-set root (§11).
    pub revocation_root: Root,
    /// The migration-spend root (§9.3).
    pub spend_root: Root,
    /// The whole revocation set, ascending (§11).
    pub revoked: &'a [[u8; 32]],
    /// The whole migration-spend set, ascending (§9.3, §11).
    pub spent: &'a [[u8; 32]],
    /// The epoch's tag key (§6.4).
    pub tag_key: &'a TagKey,
    /// The epoch's witness-service key (§5.2, proposal 0025).
    pub witness_key: &'a WitnessKey,
    /// The latest signed log head, where a log exists (§10.1).
    pub head: Option<&'a EmbeddedHead>,
}

impl BulletinStatement<'_> {
    /// The canonical statement digest — the exact bytes the statement key signs.
    ///
    /// Every field is length-framed; the lists absorb their count first, then each
    /// element, so the boundary between two lists cannot be moved. The keys are inside
    /// the digest deliberately: a swapped `K_tag_e` is the mildest of 0024's attacks,
    /// and it is closed by the same signature as the roots.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = ByteHasher::new(Domain::Bulletin)
            .absorb(self.agora.as_bytes())
            .absorb(&self.epoch.get().to_le_bytes())
            .absorb(&(self.class_roots.len() as u64).to_le_bytes());
        for (class, root) in self.class_roots {
            hasher = hasher.absorb(class.as_bytes()).absorb(root.as_bytes());
        }
        hasher = hasher
            .absorb(self.revocation_root.as_bytes())
            .absorb(self.spend_root.as_bytes())
            .absorb(&(self.revoked.len() as u64).to_le_bytes());
        for key in self.revoked {
            hasher = hasher.absorb(key);
        }
        hasher = hasher.absorb(&(self.spent.len() as u64).to_le_bytes());
        for key in self.spent {
            hasher = hasher.absorb(key);
        }
        hasher = hasher
            .absorb(self.tag_key.expose())
            .absorb(self.witness_key.expose());
        match self.head {
            None => hasher = hasher.absorb(&[0]),
            Some(head) => {
                hasher = hasher
                    .absorb(&[1])
                    .absorb(&head.sequence.to_le_bytes())
                    .absorb(&head.head)
                    .absorb(&head.signature);
            }
        }
        hasher.finalize()
    }
}

/// Accepts or refuses a bulletin: the member-side rule of §11 (proposal 0024).
///
/// Verifies the signature under `statement_key` — the operator statement key the member
/// pinned at admission — and requires the epoch to be strictly greater than `current`,
/// the member's last accepted epoch (`None` for a member accepting their first).
/// Monotonicity refuses replay: an older bulletin held at a targeted member would keep
/// them verifying against pre-revocation roots (§11), and equality refuses a re-signed
/// same-epoch variant without needing to compare contents.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] for a signature that does not verify or an epoch that
/// does not advance — the counterparty's artifact is bad, which on the member side is a
/// property of the input, deterministically visible.
pub fn accept_bulletin(
    statement_key: &[u8],
    statement: &BulletinStatement<'_>,
    signature: &[u8],
    current: Option<Epoch>,
) -> Result<(), ProtocolError> {
    if current.is_some_and(|current| statement.epoch <= current) {
        return Err(ProtocolError::Malformed);
    }
    let digest = statement.digest();
    if !signature::verify(statement_key, |absorb| absorb(&digest), signature) {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

/// Whether two signed bulletins prove a fork: same epoch, different content, both
/// validly signed under the statement key (§11; the §10.1 parallel).
///
/// The pair is portable evidence — anyone holding the statement key can check it, with
/// no other state. `false` for the same content twice, and for anything whose signature
/// does not verify: an unverifiable artifact accuses no one.
#[must_use]
pub fn bulletin_equivocation(
    statement_key: &[u8],
    a: &BulletinStatement<'_>,
    a_signature: &[u8],
    b: &BulletinStatement<'_>,
    b_signature: &[u8],
) -> bool {
    let a_digest = a.digest();
    let b_digest = b.digest();
    a.epoch == b.epoch
        && a_digest != b_digest
        && signature::verify(statement_key, |absorb| absorb(&a_digest), a_signature)
        && signature::verify(statement_key, |absorb| absorb(&b_digest), b_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nymora_core::{AgoraId, Epoch, PolicyClass, Root, TagKey, WitnessKey};

    fn statement<'a>(
        class_roots: &'a [(PolicyClass, Root)],
        revoked: &'a [[u8; 32]],
        tag_key: &'a TagKey,
        witness_key: &'a WitnessKey,
        head: Option<&'a EmbeddedHead>,
    ) -> BulletinStatement<'a> {
        BulletinStatement {
            agora: AgoraId::from_bytes([0x0a; 32]),
            epoch: Epoch::new(7),
            class_roots,
            revocation_root: Root::from_bytes([0x03; 32]),
            spend_root: Root::from_bytes([0x04; 32]),
            revoked,
            spent: &[],
            tag_key,
            witness_key,
            head,
        }
    }

    /// The canonical digest, pinned by independent computation (Python: sha256 over
    /// u64-LE length-framed fields — the domain tag, then every field in statement
    /// order). Anything that moves this digest is a wire-format change for every
    /// deployed member.
    #[test]
    fn the_digest_matches_the_known_answer() {
        let class_roots = [(
            PolicyClass::from_bytes([0x01; 32]),
            Root::from_bytes([0x02; 32]),
        )];
        let revoked = [[0x05; 32]];
        let tag_key = TagKey::new([0x06; 32]);
        let witness_key = WitnessKey::new([0x07; 32]);
        let digest = statement(&class_roots, &revoked, &tag_key, &witness_key, None).digest();
        assert_eq!(
            digest,
            [
                0x9a, 0x7c, 0x42, 0x70, 0x68, 0x8e, 0x0c, 0xfd, 0xa1, 0xa6, 0x6f, 0x2b, 0xd3, 0x26,
                0x7a, 0x7e, 0x38, 0xfb, 0x39, 0xdf, 0x5c, 0xd1, 0x8b, 0xae, 0xfb, 0x57, 0x4a, 0x16,
                0xea, 0x0a, 0xe7, 0xe8,
            ]
        );
    }

    /// Every field moves the digest — including the embedded head and its absence.
    #[test]
    fn every_field_binds() {
        let class_roots = [(
            PolicyClass::from_bytes([0x01; 32]),
            Root::from_bytes([0x02; 32]),
        )];
        let revoked = [[0x05; 32]];
        let tag_key = TagKey::new([0x06; 32]);
        let witness_key = WitnessKey::new([0x07; 32]);
        let base = statement(&class_roots, &revoked, &tag_key, &witness_key, None).digest();

        let other_key = TagKey::new([0x66; 32]);
        assert_ne!(
            base,
            statement(&class_roots, &revoked, &other_key, &witness_key, None).digest(),
            "the tag key did not bind"
        );
        let no_revocations: [[u8; 32]; 0] = [];
        assert_ne!(
            base,
            statement(&class_roots, &no_revocations, &tag_key, &witness_key, None).digest(),
            "the revocation set did not bind"
        );
        let head = EmbeddedHead {
            sequence: 0,
            head: [0x08; 32],
            signature: [0x09; SIGNATURE_LEN],
        };
        assert_ne!(
            base,
            statement(&class_roots, &revoked, &tag_key, &witness_key, Some(&head)).digest(),
            "the embedded head did not bind"
        );
    }

    /// Acceptance end to end: the operator's signature admits, and every deviation —
    /// tampered content, a wrong key, a stale epoch — refuses.
    #[test]
    fn acceptance_requires_signature_and_advance() {
        let seed = [0x42; 32];
        let statement_key = signature::public_key(&seed);
        let class_roots = [(
            PolicyClass::from_bytes([0x01; 32]),
            Root::from_bytes([0x02; 32]),
        )];
        let revoked = [[0x05; 32]];
        let tag_key = TagKey::new([0x06; 32]);
        let witness_key = WitnessKey::new([0x07; 32]);
        let stated = statement(&class_roots, &revoked, &tag_key, &witness_key, None);
        let digest = stated.digest();
        let signed = signature::sign(&seed, |absorb| absorb(&digest));

        assert!(accept_bulletin(&statement_key, &stated, &signed, None).is_ok());
        assert!(accept_bulletin(&statement_key, &stated, &signed, Some(Epoch::new(6))).is_ok());

        // Monotonicity: equal and older epochs refuse, signature notwithstanding.
        assert!(accept_bulletin(&statement_key, &stated, &signed, Some(Epoch::new(7))).is_err());
        assert!(accept_bulletin(&statement_key, &stated, &signed, Some(Epoch::new(8))).is_err());

        // Tampered content refuses: the signature covers the digest it was cut over.
        let other_tag = TagKey::new([0x66; 32]);
        let tampered = statement(&class_roots, &revoked, &other_tag, &witness_key, None);
        assert!(accept_bulletin(&statement_key, &tampered, &signed, None).is_err());

        // A key the member never pinned refuses.
        let wrong_key = signature::public_key(&[0x43; 32]);
        assert!(accept_bulletin(&wrong_key, &stated, &signed, None).is_err());
    }

    /// The fork proof: same epoch + different content + two valid signatures — and
    /// nothing weaker.
    #[test]
    fn equivocation_requires_two_valid_signatures_on_divergent_content() {
        let seed = [0x42; 32];
        let statement_key = signature::public_key(&seed);
        let class_roots = [(
            PolicyClass::from_bytes([0x01; 32]),
            Root::from_bytes([0x02; 32]),
        )];
        let revoked = [[0x05; 32]];
        let tag_key = TagKey::new([0x06; 32]);
        let other_tag = TagKey::new([0x66; 32]);
        let witness_key = WitnessKey::new([0x07; 32]);
        let a = statement(&class_roots, &revoked, &tag_key, &witness_key, None);
        let b = statement(&class_roots, &revoked, &other_tag, &witness_key, None);
        let a_digest = a.digest();
        let b_digest = b.digest();
        let a_sig = signature::sign(&seed, |absorb| absorb(&a_digest));
        let b_sig = signature::sign(&seed, |absorb| absorb(&b_digest));

        assert!(bulletin_equivocation(
            &statement_key,
            &a,
            &a_sig,
            &b,
            &b_sig
        ));
        // The same content twice accuses no one.
        assert!(!bulletin_equivocation(
            &statement_key,
            &a,
            &a_sig,
            &a,
            &a_sig
        ));
        // An unverifiable signature accuses no one.
        assert!(!bulletin_equivocation(
            &statement_key,
            &a,
            &a_sig,
            &b,
            &a_sig
        ));
    }
}
