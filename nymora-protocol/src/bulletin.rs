// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boundary envelope as a signed operator statement, and the member's opening of it
//! (§11; proposals 0024, 0036).
//!
//! The envelope is a member's entire view of a new epoch — the roots to prove against,
//! the whole exclusion sets, the epoch keys, and their own inclusion path — and it is
//! meant to be cached, relayed peer-to-peer, and fetched through infrastructure the
//! member does not trust. That calls for object security: the artifact carries its own
//! authenticity rather than borrowing one hop's channel security.
//!
//! # Delivered per member (proposal 0036)
//!
//! ```text
//! envelope = { epoch, ephemeral_pk, body_ct, [ (tag_i, ct_i) … ], head, signature }
//! body     = { epoch, class_roots, revocation_root, spend_root, revoked, spent, K_tag, K_fetch }
//! ct_i     = seal( K_body ‖ position ‖ path_i )   to member i's inbox key
//! ```
//!
//! **The single-body rule.** Everything members must agree on lives in `body`, encrypted
//! **once** under one `K_body_e`; a per-member ciphertext carries only `K_body_e` and
//! that member's own path. §11 rejected per-member authenticators because "a per-member
//! MAC is precisely the tool for undetectable per-member forking"; per-member delivery
//! is the same tool, and this rule is what disarms it. An operator cannot show one
//! member different roots: the body is one ciphertext under one signed digest, a
//! substituted `K_body` fails the body's authentication, and a substituted path fails
//! the member's own check that it reproduces the body's root.
//!
//! # What the signature covers, and who signs
//!
//! The canonical statement digest ([`EnvelopeStatement::digest`]) leads with
//! [`Domain::Bulletin`], absorbs the `agora_id` — so no-replay-across-agoras (§16.1)
//! holds by construction — and length-frames the ephemeral key, the body ciphertext, the
//! digest of the ciphertext list, and the embedded log head. The signer is the per-agora
//! **operator statement key**: distinct from all member material and from the log-head
//! key (§10.1).
//!
//! # Acceptance is signature plus strict monotonicity
//!
//! A member accepts an envelope only if the signature verifies under the statement key
//! pinned at admission **and** the epoch is strictly greater than the member's current
//! one — monotonicity is the whole freshness rule (proposal 0024).
//!
//! # Equivocation is portable
//!
//! Two validly signed envelopes for one epoch with different content are proof of a
//! fork, carryable to anyone who holds the statement key.
//!
//! # This module is feature-free deliberately
//!
//! Verification and opening are the member's job, and the member build carries no
//! allocator and no `operator` feature. Everything here borrows or decrypts in place in
//! the caller's buffers; the operator's owned [`Envelope`](crate::operator::Envelope)
//! (`operator` feature) views into it to sign, and a host's parsed broadcast views into
//! it to verify.

use nymora_core::{
    AgoraId, BodyKey, Domain, Epoch, FetchKey, InboxPublicKey, InboxSecretKey, InboxTag,
    PolicyClass, ProtocolError, Root, TagKey, DIGEST_LEN,
};
use nymora_crypto::signature::{self, SIGNATURE_LEN};
use nymora_crypto::{inbox, ByteHasher};

/// The latest signed log head, embedded where the agora keeps a transparency log
/// (§10.1; proposal 0024's second open question, decided yes).
///
/// Embedding binds the member-gated artifact to the public one: a member cross-checks
/// the envelope's roots against the log with no extra fetch, and an envelope claiming
/// roots the log never saw carries the evidence of that inside itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedHead {
    /// The index of the newest log entry the head commits to.
    pub sequence: u64,
    /// The chained digest over entries `0..=sequence` (§10.1).
    pub head: [u8; 32],
    /// The log key's signature over the canonical head payload.
    pub signature: [u8; SIGNATURE_LEN],
}

/// Everything an envelope's signature covers, borrowed.
///
/// The `agora` is supplied by whoever computes the digest — the operator binds its own,
/// and a verifying member binds *theirs*, so an envelope from any other agora fails
/// verification structurally rather than by inspection.
pub struct EnvelopeStatement<'a> {
    /// The agora the statement speaks for (§16.1: inside the signed bytes).
    pub agora: AgoraId,
    /// The epoch the envelope equips.
    pub epoch: Epoch,
    /// The operator's agreement key for this boundary.
    pub ephemeral_key: InboxPublicKey,
    /// The body ciphertext, authentication tag included — one body for every member.
    pub body: &'a [u8],
    /// [`ciphertexts_digest`] over the per-member ciphertext list, in envelope order.
    pub ciphertexts_digest: [u8; DIGEST_LEN],
    /// The latest signed log head, where a log exists (§10.1).
    pub head: Option<&'a EmbeddedHead>,
}

impl EnvelopeStatement<'_> {
    /// The canonical statement digest — the exact bytes the statement key signs.
    #[must_use]
    pub fn digest(&self) -> [u8; DIGEST_LEN] {
        let mut hasher = ByteHasher::new(Domain::Bulletin)
            .absorb(self.agora.as_bytes())
            .absorb(&self.epoch.get().to_le_bytes())
            .absorb(self.ephemeral_key.as_bytes())
            .absorb(self.body)
            .absorb(&self.ciphertexts_digest);
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

/// The digest of a ciphertext list: the count, then each tag and ciphertext framed, in
/// envelope order — so the signed statement commits to every ciphertext and to the
/// count, and nothing in the list can be moved, dropped, or added unnoticed.
pub fn ciphertexts_digest<'a>(
    ciphertexts: impl ExactSizeIterator<Item = (&'a InboxTag, &'a [u8])>,
) -> [u8; DIGEST_LEN] {
    let mut hasher = ByteHasher::new(Domain::EnvelopeCiphertexts)
        .absorb(&(ciphertexts.len() as u64).to_le_bytes());
    for (tag, bytes) in ciphertexts {
        hasher = hasher.absorb(tag.as_bytes()).absorb(bytes);
    }
    hasher.finalize()
}

/// Accepts or refuses an envelope: the member-side rule of §11 (proposal 0024).
///
/// Verifies the signature under `statement_key` — the operator statement key the member
/// pinned at admission — and requires the epoch to be strictly greater than `current`,
/// the member's last accepted epoch (`None` for a member accepting their first).
///
/// # Errors
///
/// [`ProtocolError::Malformed`] for a signature that does not verify or an epoch that
/// does not advance.
pub fn accept_envelope(
    statement_key: &[u8],
    statement: &EnvelopeStatement<'_>,
    signature: &[u8],
    current: Option<Epoch>,
) -> Result<(), ProtocolError> {
    if current.is_some_and(|current| statement.epoch <= current) {
        return Err(ProtocolError::Malformed);
    }
    let digest = statement.digest();
    if !signature::verify(
        statement_key,
        &nymora_crypto::field::from_id(&digest),
        signature,
    ) {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

/// Whether two signed envelopes prove a fork: same epoch, different content, both
/// validly signed under the statement key (§11; the §10.1 parallel).
#[must_use]
pub fn envelope_equivocation(
    statement_key: &[u8],
    a: &EnvelopeStatement<'_>,
    a_signature: &[u8],
    b: &EnvelopeStatement<'_>,
    b_signature: &[u8],
) -> bool {
    let a_digest = a.digest();
    let b_digest = b.digest();
    a.epoch == b.epoch
        && a_digest != b_digest
        && signature::verify(
            statement_key,
            &nymora_crypto::field::from_id(&a_digest),
            a_signature,
        )
        && signature::verify(
            statement_key,
            &nymora_crypto::field::from_id(&b_digest),
            b_signature,
        )
}

// ---------------------------------------------------------------------------------------
// The member's side: finding and opening their own ciphertext, then the body.

/// The tag under which this credential's ciphertext for `class` sits in an envelope
/// sealed with `ephemeral`. `None` for an ephemeral key that agrees on nothing.
#[must_use]
pub fn own_lookup_tag(
    inbox_secret: &InboxSecretKey,
    ephemeral: &InboxPublicKey,
    class: &PolicyClass,
) -> Option<InboxTag> {
    let agreed = inbox::agree(inbox_secret, ephemeral)?;
    let own = inbox::inbox_public_key(inbox_secret);
    Some(inbox::lookup_tag(&agreed, ephemeral, &own, class))
}

/// What one member's ciphertext carried, borrowed from the decrypted buffer.
#[derive(Debug)]
pub struct OwnCiphertext<'a> {
    /// `K_body_e` — opens the shared body.
    pub body_key: BodyKey,
    /// The member's permanent position in the class accumulator.
    pub position: u64,
    /// The path's siblings below the tree's occupied height, leaf upward, 32 bytes each;
    /// the member fills the rest with each level's empty value
    /// (`Witness::from_prefix`).
    pub path: &'a [u8],
}

/// Opens this credential's own ciphertext in place (§11, proposal 0036).
///
/// `buffer` holds the ciphertext with its 16-byte authentication tag appended, exactly
/// as the envelope carries it, and is decrypted in place. Refuses unless the seal
/// authenticates under the key agreed with `ephemeral` for exactly this agora, epoch,
/// and class.
///
/// # Errors
///
/// [`ProtocolError::Malformed`] for a ciphertext that does not open, or a plaintext of
/// the wrong shape.
pub fn open_own_ciphertext<'a>(
    inbox_secret: &InboxSecretKey,
    ephemeral: &InboxPublicKey,
    agora: &AgoraId,
    epoch: Epoch,
    class: &PolicyClass,
    buffer: &'a mut [u8],
) -> Result<OwnCiphertext<'a>, ProtocolError> {
    let agreed = inbox::agree(inbox_secret, ephemeral).ok_or(ProtocolError::Malformed)?;
    let own = inbox::inbox_public_key(inbox_secret);
    let key = inbox::seal_key(&agreed, ephemeral, &own, class);
    let plain = open_sealed(key.expose(), agora, epoch, buffer)?;

    // body_key ‖ position ‖ height ‖ siblings
    if plain.len() < DIGEST_LEN + 8 + 1 {
        return Err(ProtocolError::Malformed);
    }
    let (body_key, rest) = plain.split_at(DIGEST_LEN);
    let (position, rest) = rest.split_at(8);
    let (height, path) = rest.split_first().ok_or(ProtocolError::Malformed)?;
    if path.len() != usize::from(*height) * DIGEST_LEN {
        return Err(ProtocolError::Malformed);
    }
    let mut key = [0u8; DIGEST_LEN];
    key.copy_from_slice(body_key);
    let mut position_bytes = [0u8; 8];
    position_bytes.copy_from_slice(position);
    Ok(OwnCiphertext {
        body_key: BodyKey::new(key),
        position: u64::from_le_bytes(position_bytes),
        path,
    })
}

/// Decrypts a sealed buffer (ciphertext ‖ 16-byte tag) in place, returning the plaintext.
fn open_sealed<'a>(
    key: &[u8; 32],
    agora: &AgoraId,
    epoch: Epoch,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], ProtocolError> {
    let split = buffer
        .len()
        .checked_sub(inbox::SEAL_TAG_LEN)
        .ok_or(ProtocolError::Malformed)?;
    let (ciphertext, tag) = buffer.split_at_mut(split);
    let tag: [u8; inbox::SEAL_TAG_LEN] =
        (&*tag).try_into().map_err(|_| ProtocolError::Malformed)?;
    inbox::open_in_place(key, &inbox::associated_data(agora, epoch), ciphertext, &tag)?;
    Ok(ciphertext)
}

/// A decrypted body, borrowed: the canonical layout read strictly.
///
/// ```text
/// epoch u64 | n_classes u64 | (class ‖ root)* | revocation_root | spend_root
/// | n_revoked u64 | entry* | n_spent u64 | entry* | K_tag | K_fetch
/// ```
#[derive(Debug)]
pub struct BodyView<'a> {
    epoch: Epoch,
    class_roots: &'a [u8],
    revocation_root: Root,
    spend_root: Root,
    revoked: &'a [u8],
    spent: &'a [u8],
    tag_key: TagKey,
    fetch_key: FetchKey,
}

impl<'a> BodyView<'a> {
    /// Opens and parses the shared body in place (§11, proposal 0036).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] for a body that does not authenticate under
    /// `body_key` for this agora and epoch, names a different epoch, or is not exactly
    /// one canonical layout.
    pub fn open(
        body_key: &BodyKey,
        agora: &AgoraId,
        epoch: Epoch,
        buffer: &'a mut [u8],
    ) -> Result<Self, ProtocolError> {
        let plain = open_sealed(body_key.expose(), agora, epoch, buffer)?;
        let mut rest = plain;
        let body_epoch = Epoch::new(take_u64(&mut rest)?);
        if body_epoch != epoch {
            return Err(ProtocolError::Malformed);
        }
        let classes = take_u64(&mut rest)?;
        let class_roots = take_entries(&mut rest, classes, 2 * DIGEST_LEN)?;
        let revocation_root = Root::from_bytes(take_digest(&mut rest)?);
        let spend_root = Root::from_bytes(take_digest(&mut rest)?);
        let revoked_count = take_u64(&mut rest)?;
        let revoked = take_entries(&mut rest, revoked_count, DIGEST_LEN)?;
        let spent_count = take_u64(&mut rest)?;
        let spent = take_entries(&mut rest, spent_count, DIGEST_LEN)?;
        let tag_key = TagKey::new(take_digest(&mut rest)?);
        let fetch_key = FetchKey::new(take_digest(&mut rest)?);
        if !rest.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        Ok(Self {
            epoch: body_epoch,
            class_roots,
            revocation_root,
            spend_root,
            revoked,
            spent,
            tag_key,
            fetch_key,
        })
    }

    /// The epoch the body equips.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Every class root, in the operator's ascending class order.
    pub fn class_roots(&self) -> impl Iterator<Item = (PolicyClass, Root)> + 'a {
        self.class_roots.chunks_exact(2 * DIGEST_LEN).map(|pair| {
            let mut class = [0u8; DIGEST_LEN];
            class.copy_from_slice(&pair[..DIGEST_LEN]);
            let mut root = [0u8; DIGEST_LEN];
            root.copy_from_slice(&pair[DIGEST_LEN..]);
            (PolicyClass::from_bytes(class), Root::from_bytes(root))
        })
    }

    /// One class's root, if the body carries the class.
    #[must_use]
    pub fn class_root(&self, class: PolicyClass) -> Option<Root> {
        self.class_roots()
            .find(|(named, _)| *named == class)
            .map(|(_, root)| root)
    }

    /// The revocation-set root (§11).
    #[must_use]
    pub const fn revocation_root(&self) -> Root {
        self.revocation_root
    }

    /// The migration-spend root (§9.3).
    #[must_use]
    pub const fn spend_root(&self) -> Root {
        self.spend_root
    }

    /// The whole revocation set, ascending: entries `Poseidon(REVOKE, leaf)`.
    pub fn revoked(&self) -> impl Iterator<Item = [u8; DIGEST_LEN]> + 'a {
        entries(self.revoked)
    }

    /// The whole migration-spend set, ascending.
    pub fn spent(&self) -> impl Iterator<Item = [u8; DIGEST_LEN]> + 'a {
        entries(self.spent)
    }

    /// The epoch's tag key (§6.4).
    #[must_use]
    pub const fn tag_key(&self) -> &TagKey {
        &self.tag_key
    }

    /// The epoch's fetch key — what fetches the next envelope (§11).
    #[must_use]
    pub const fn fetch_key(&self) -> &FetchKey {
        &self.fetch_key
    }
}

fn entries(bytes: &[u8]) -> impl Iterator<Item = [u8; DIGEST_LEN]> + '_ {
    bytes.chunks_exact(DIGEST_LEN).map(|chunk| {
        let mut entry = [0u8; DIGEST_LEN];
        entry.copy_from_slice(chunk);
        entry
    })
}

fn take_u64(rest: &mut &[u8]) -> Result<u64, ProtocolError> {
    let bytes: [u8; 8] = rest
        .get(..8)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    *rest = &rest[8..];
    Ok(u64::from_le_bytes(bytes))
}

fn take_digest(rest: &mut &[u8]) -> Result<[u8; DIGEST_LEN], ProtocolError> {
    let bytes: [u8; DIGEST_LEN] = rest
        .get(..DIGEST_LEN)
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)?;
    *rest = &rest[DIGEST_LEN..];
    Ok(bytes)
}

fn take_entries<'a>(
    rest: &mut &'a [u8],
    count: u64,
    width: usize,
) -> Result<&'a [u8], ProtocolError> {
    let total = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(width))
        .ok_or(ProtocolError::Malformed)?;
    let taken = rest.get(..total).ok_or(ProtocolError::Malformed)?;
    *rest = &rest[total..];
    Ok(taken)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement<'a>(body: &'a [u8], head: Option<&'a EmbeddedHead>) -> EnvelopeStatement<'a> {
        EnvelopeStatement {
            agora: AgoraId::from_bytes([0x0a; 32]),
            epoch: Epoch::new(7),
            ephemeral_key: InboxPublicKey::from_bytes([0x0e; 32]),
            body,
            ciphertexts_digest: [0x0c; 32],
            head,
        }
    }

    /// The canonical digest, pinned by independent computation (Python: sha256 over
    /// u64-LE length-framed fields — the domain tag, then every field in statement
    /// order). Anything that moves this digest is a wire-format change for every
    /// deployed member.
    #[test]
    fn the_digest_matches_the_known_answer() {
        let digest = statement(&[0x0b; 4], None).digest();
        assert_eq!(
            digest,
            [
                0x44, 0x73, 0xc1, 0xf5, 0x2b, 0xf4, 0x49, 0xc8, 0x25, 0x91, 0xa4, 0x6d, 0x48, 0xc9,
                0x95, 0x74, 0x88, 0x16, 0xfc, 0xb1, 0xb8, 0x40, 0x96, 0x97, 0x73, 0xb6, 0xb4, 0xa8,
                0x7d, 0x38, 0xe2, 0x9f,
            ]
        );
    }

    /// Every field moves the digest — including the embedded head and its absence.
    #[test]
    fn every_field_binds() {
        let base = statement(&[0x0b; 4], None).digest();
        assert_ne!(
            base,
            statement(&[0x0b; 5], None).digest(),
            "the body did not bind"
        );
        let mut other = statement(&[0x0b; 4], None);
        other.ciphertexts_digest = [0x0d; 32];
        assert_ne!(base, other.digest(), "the ciphertext list did not bind");
        let mut other = statement(&[0x0b; 4], None);
        other.ephemeral_key = InboxPublicKey::from_bytes([0x0f; 32]);
        assert_ne!(base, other.digest(), "the ephemeral key did not bind");
        let head = EmbeddedHead {
            sequence: 0,
            head: [0x08; 32],
            signature: [0x09; SIGNATURE_LEN],
        };
        assert_ne!(
            base,
            statement(&[0x0b; 4], Some(&head)).digest(),
            "the embedded head did not bind"
        );
    }

    /// The ciphertext-list digest commits to the count, the order, and every byte.
    #[test]
    fn the_ciphertext_digest_binds_count_and_order() {
        let a = (InboxTag::from_bytes([1; 8]), [0xaa; 3]);
        let b = (InboxTag::from_bytes([2; 8]), [0xbb; 3]);
        let ab = ciphertexts_digest([(&a.0, &a.1[..]), (&b.0, &b.1[..])].into_iter());
        let ba = ciphertexts_digest([(&b.0, &b.1[..]), (&a.0, &a.1[..])].into_iter());
        let a_only = ciphertexts_digest([(&a.0, &a.1[..])].into_iter());
        assert_ne!(ab, ba);
        assert_ne!(ab, a_only);
    }

    /// Acceptance end to end: the operator's signature admits, and every deviation —
    /// tampered content, a wrong key, a stale epoch — refuses.
    #[test]
    fn acceptance_requires_signature_and_advance() {
        let seed = signature::mint_signing_secret([0x42; 32]);
        let statement_key = signature::public_key(&seed).expect("minted keys are canonical");
        let stated = statement(&[0x0b; 4], None);
        let signed = signature::sign(&seed, &nymora_crypto::field::from_id(&stated.digest()))
            .expect("minted keys are canonical");

        assert!(accept_envelope(&statement_key, &stated, &signed, None).is_ok());
        assert!(accept_envelope(&statement_key, &stated, &signed, Some(Epoch::new(6))).is_ok());
        assert!(accept_envelope(&statement_key, &stated, &signed, Some(Epoch::new(7))).is_err());
        assert!(accept_envelope(&statement_key, &stated, &signed, Some(Epoch::new(8))).is_err());

        let tampered = statement(&[0x0c; 4], None);
        assert!(accept_envelope(&statement_key, &tampered, &signed, None).is_err());

        let wrong_key = signature::public_key(&signature::mint_signing_secret([0x43; 32]))
            .expect("minted keys are canonical");
        assert!(accept_envelope(&wrong_key, &stated, &signed, None).is_err());
    }

    #[test]
    fn equivocation_requires_two_valid_signatures_on_divergent_content() {
        let seed = signature::mint_signing_secret([0x42; 32]);
        let statement_key = signature::public_key(&seed).expect("minted keys are canonical");
        let a = statement(&[0x0b; 4], None);
        let b = statement(&[0x0c; 4], None);
        let a_sig = signature::sign(&seed, &nymora_crypto::field::from_id(&a.digest())).unwrap();
        let b_sig = signature::sign(&seed, &nymora_crypto::field::from_id(&b.digest())).unwrap();
        assert!(envelope_equivocation(
            &statement_key,
            &a,
            &a_sig,
            &b,
            &b_sig
        ));
        assert!(!envelope_equivocation(
            &statement_key,
            &a,
            &a_sig,
            &a,
            &a_sig
        ));
        assert!(!envelope_equivocation(
            &statement_key,
            &a,
            &a_sig,
            &b,
            &a_sig
        ));
    }

    /// A body round-trips through the canonical layout and refuses every deviation.
    #[test]
    fn a_sealed_body_opens_strictly() {
        let agora = AgoraId::from_bytes([0x0a; 32]);
        let epoch = Epoch::new(7);
        let key = BodyKey::new([0x77; 32]);
        let class = PolicyClass::from_bytes([0x01; 32]);
        let mut plain = std::vec::Vec::new();
        plain.extend_from_slice(&7u64.to_le_bytes());
        plain.extend_from_slice(&1u64.to_le_bytes());
        plain.extend_from_slice(class.as_bytes());
        plain.extend_from_slice(&[0x02; 32]);
        plain.extend_from_slice(&[0x03; 32]);
        plain.extend_from_slice(&[0x04; 32]);
        plain.extend_from_slice(&2u64.to_le_bytes());
        plain.extend_from_slice(&[0x05; 32]);
        plain.extend_from_slice(&[0x06; 32]);
        plain.extend_from_slice(&0u64.to_le_bytes());
        plain.extend_from_slice(&[0x07; 32]);
        plain.extend_from_slice(&[0x08; 32]);
        let tag = inbox::seal_in_place(
            key.expose(),
            &inbox::associated_data(&agora, epoch),
            &mut plain,
        );
        let mut sealed = plain.clone();
        sealed.extend_from_slice(&tag);

        let mut buffer = sealed.clone();
        let view = BodyView::open(&key, &agora, epoch, &mut buffer).expect("opens");
        assert_eq!(view.epoch(), epoch);
        assert_eq!(view.class_root(class), Some(Root::from_bytes([0x02; 32])));
        assert_eq!(view.revocation_root(), Root::from_bytes([0x03; 32]));
        assert_eq!(view.revoked().count(), 2);
        assert_eq!(view.spent().count(), 0);
        assert_eq!(view.tag_key(), &TagKey::new([0x07; 32]));
        assert_eq!(view.fetch_key(), &FetchKey::new([0x08; 32]));

        // Another epoch's associated data, another key, a flipped byte: refused.
        assert!(BodyView::open(&key, &agora, Epoch::new(8), &mut sealed.clone()).is_err());
        assert!(BodyView::open(
            &BodyKey::new([0x78; 32]),
            &agora,
            epoch,
            &mut sealed.clone()
        )
        .is_err());
        let mut flipped = sealed.clone();
        flipped[0] ^= 1;
        assert!(BodyView::open(&key, &agora, epoch, &mut flipped).is_err());
    }
}
