// SPDX-License-Identifier: MIT OR Apache-2.0

//! The live-authentication session, member side (§8.1–§8.3).
//!
//! # A typestate, because the ordering is the security property
//!
//! Commit-reveal-derive works only if every commitment is collected before any reveal is
//! sent: a participant who reveals early hands the others the ability to bias the context
//! against a prepared replay. The machine makes the order structural — [`Contribution`]
//! can produce a commitment but not a reveal; only [`Contribution::lock`], which takes the
//! full roster of commitments, yields a [`Locked`] session that can reveal; and only
//! [`Locked::finish`], which checks every reveal against the roster it locked, yields the
//! derived [`Session`]. There is no path through these types that reveals before the
//! roster is fixed, and no path to a context that skips checking an opening.
//!
//! # Transport is genuinely absent
//!
//! Nothing here sends: the host moves commitments and reveals over its channel — network
//! messages in §8.1, QR codes or NFC taps in §8.3 — and this same machine serves both,
//! which is §8.3's claim that only the transport changes taken literally. Offline
//! in-person verification follows for free: the roots a peer's proof is checked against
//! are parameters wherever proofs are verified, so pre-fetched cached roots work exactly
//! like live ones (§8.3's staleness caveat is the member's to weigh, not this machine's to
//! detect).
//!
//! # Late joiners restart, deliberately
//!
//! A finalized context admits no clean contribution (§8.1), so a late arrival means a new
//! round: fresh [`Contribution`] values for everyone, nothing carried over. The machine
//! holds no state outside its own round, which is what makes the restart the cheap and
//! correct operation rather than a recovery path.

use crate::credential::FreshEntropy;
use nymora_core::{ProtocolError, SecretBytes, SessionCommitment, SessionContext};
use nymora_crypto::live_auth::{self, NONCE_LEN, SAS_LEN};

/// This participant's secret contribution to one round.
///
/// Holds the nonce and blinding until the roster is locked. Secrets are zeroized on drop
/// and redacted in `Debug`; the only value that leaves before the reveal phase is the
/// commitment.
#[derive(Debug)]
pub struct Contribution {
    nonce: SecretBytes<NONCE_LEN>,
    blinding: SecretBytes<NONCE_LEN>,
}

/// One participant's opening, exchanged after all commitments are visible (§8.1 step 2).
///
/// Public by definition — revealing these values is the protocol — so the fields are bare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reveal {
    /// The nonce absorbed into the shared context.
    pub nonce: [u8; NONCE_LEN],
    /// The blinding that, with the nonce, opens the participant's commitment.
    pub blinding: [u8; NONCE_LEN],
}

/// A session whose roster of commitments is fixed; able to reveal and to finish.
///
/// Borrows the roster rather than copying or hashing it: the slice `finish` checks reveals
/// against is by construction the slice `lock` validated.
#[derive(Debug)]
pub struct Locked<'r> {
    contribution: Contribution,
    roster: &'r [SessionCommitment],
    position: usize,
}

/// A completed round: the jointly-derived context, ready for pseudonyms and proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    context: SessionContext,
}

impl Contribution {
    /// Draws this participant's nonce and blinding for one round.
    ///
    /// Both are fresh entropy per round, even for the same conversation — reuse across
    /// rounds would let a context be reproduced after a refresh (§8.1's late-joiner
    /// re-run assumes each round is independent).
    #[must_use]
    pub fn new(nonce: FreshEntropy, blinding: FreshEntropy) -> Self {
        Self {
            nonce: SecretBytes::new(nonce.take()),
            blinding: SecretBytes::new(blinding.take()),
        }
    }

    /// The commitment to post — the only value that may leave before the roster is fixed.
    #[must_use]
    pub fn commitment(&self) -> SessionCommitment {
        live_auth::commitment(self.nonce.expose(), self.blinding.expose())
    }

    /// Fixes the roster of every participant's commitment — including this one's — and
    /// unlocks the reveal phase.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] when the roster is not a valid session: fewer than two
    /// participants, this participant's commitment absent, or **any duplicate
    /// commitment**. A duplicate aborts the session before anything is revealed (§8.1): a
    /// participant contributing nothing new has no honest reason to exist, whatever the
    /// derivation below would tolerate.
    pub fn lock(self, roster: &[SessionCommitment]) -> Result<Locked<'_>, ProtocolError> {
        if roster.len() < 2 {
            return Err(ProtocolError::Rejected);
        }
        for (i, commitment) in roster.iter().enumerate() {
            if roster[..i].contains(commitment) {
                return Err(ProtocolError::Rejected);
            }
        }
        let mine = self.commitment();
        let Some(position) = roster.iter().position(|c| *c == mine) else {
            return Err(ProtocolError::Rejected);
        };
        Ok(Locked {
            contribution: self,
            roster,
            position,
        })
    }
}

impl Locked<'_> {
    /// The opening to send, now that every commitment is fixed (§8.1 step 2).
    #[must_use]
    pub fn reveal(&self) -> Reveal {
        Reveal {
            nonce: *self.contribution.nonce.expose(),
            blinding: *self.contribution.blinding.expose(),
        }
    }

    /// Checks every reveal against the locked roster and derives the shared context
    /// (§8.1 step 3).
    ///
    /// `reveals` is ordered as the roster is — the host pairs them by participant.
    /// `scratch` is caller-provided space for at least the roster's number of nonces; the
    /// derivation sorts in place, so no allocation happens here.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Rejected`] when any reveal fails to open its commitment, this
    /// participant's own slot does not match what it contributed, or the counts disagree.
    /// [`ProtocolError::Malformed`] when `scratch` is too small — a property of the
    /// caller's buffer, not of the session.
    pub fn finish(
        self,
        reveals: &[Reveal],
        scratch: &mut [[u8; NONCE_LEN]],
        channel_metadata: &[u8],
    ) -> Result<Session, ProtocolError> {
        if reveals.len() != self.roster.len() {
            return Err(ProtocolError::Rejected);
        }
        let nonces = scratch
            .get_mut(..reveals.len())
            .ok_or(ProtocolError::Malformed)?;

        for (i, (reveal, committed)) in reveals.iter().zip(self.roster).enumerate() {
            if live_auth::commitment(&reveal.nonce, &reveal.blinding) != *committed {
                return Err(ProtocolError::Rejected);
            }
            // A transport that swapped this participant's own reveal for another valid one
            // must not pass silently: the local truth is authoritative for the local slot.
            if i == self.position && reveal.nonce != *self.contribution.nonce.expose() {
                return Err(ProtocolError::Rejected);
            }
            nonces[i] = reveal.nonce;
        }

        Ok(Session {
            context: live_auth::context(nonces, channel_metadata),
        })
    }
}

impl Session {
    /// The jointly-derived context — what pseudonyms and proofs bind to (§8.1 steps 4–5).
    #[must_use]
    pub fn context(&self) -> SessionContext {
        self.context
    }

    /// The short authentication string for in-person comparison (§8.3).
    ///
    /// These four bytes are protocol; how a client renders them is not.
    #[must_use]
    pub fn sas(&self) -> [u8; SAS_LEN] {
        live_auth::sas(&self.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn entropy(byte: u8) -> FreshEntropy {
        FreshEntropy::new([byte; 32])
    }

    fn contribution(seed: u8) -> Contribution {
        Contribution::new(entropy(seed), entropy(seed.wrapping_add(0x80)))
    }

    /// Runs a full honest round for `n` participants and returns each one's context.
    fn honest_round(n: usize, metadata: &[u8]) -> Vec<Session> {
        let contributions: Vec<Contribution> = (0..n).map(|i| contribution(i as u8)).collect();
        let roster: Vec<SessionCommitment> =
            contributions.iter().map(Contribution::commitment).collect();
        let locked: Vec<Locked<'_>> = contributions
            .into_iter()
            .map(|c| c.lock(&roster).expect("honest roster locks"))
            .collect();
        let reveals: Vec<Reveal> = locked.iter().map(Locked::reveal).collect();
        locked
            .into_iter()
            .map(|l| {
                let mut scratch = [[0u8; NONCE_LEN]; 8];
                l.finish(&reveals, &mut scratch, metadata)
                    .expect("honest round finishes")
            })
            .collect()
    }

    /// §8.1 step 5: every participant independently derives the identical context and SAS,
    /// and n = 2 is the same machine with no special casing.
    #[test]
    fn every_participant_derives_the_same_context() {
        for n in [2, 3, 5] {
            let sessions = honest_round(n, b"channel");
            for s in &sessions[1..] {
                assert_eq!(s.context(), sessions[0].context());
                assert_eq!(s.sas(), sessions[0].sas());
            }
        }
    }

    /// A duplicate commitment aborts before anything is revealed (§8.1).
    #[test]
    fn a_duplicate_commitment_aborts_the_session() {
        let mine = contribution(1);
        let other = contribution(2).commitment();
        let roster = [mine.commitment(), other, other];
        assert_eq!(mine.lock(&roster).unwrap_err(), ProtocolError::Rejected);

        // Including a duplicate of *this* participant's own commitment.
        let mine = contribution(1);
        let duplicate_of_mine = [mine.commitment(), mine.commitment()];
        assert_eq!(
            mine.lock(&duplicate_of_mine).unwrap_err(),
            ProtocolError::Rejected
        );
    }

    #[test]
    fn a_roster_without_this_participant_refuses() {
        let roster = [contribution(2).commitment(), contribution(3).commitment()];
        assert_eq!(
            contribution(1).lock(&roster).unwrap_err(),
            ProtocolError::Rejected
        );
    }

    #[test]
    fn a_session_of_one_refuses() {
        let mine = contribution(1);
        let roster = [mine.commitment()];
        assert_eq!(mine.lock(&roster).unwrap_err(), ProtocolError::Rejected);
    }

    /// A reveal that does not open its commitment is a manipulated session (§8.1): the
    /// participant who detects it derives no context at all.
    #[test]
    fn a_reveal_that_does_not_open_its_commitment_refuses() {
        let mine = contribution(1);
        let peer = contribution(2);
        let roster = [mine.commitment(), peer.commitment()];
        let locked = mine.lock(&roster).unwrap();

        let mut forged = peer.lock(&roster).unwrap().reveal();
        forged.nonce[0] ^= 1;

        let reveals = [locked.reveal(), forged];
        let mut scratch = [[0u8; NONCE_LEN]; 2];
        assert_eq!(
            locked.finish(&reveals, &mut scratch, b"m").unwrap_err(),
            ProtocolError::Rejected
        );
    }

    /// §8.3's relay story, at the machine's boundary: a substituted nonce that *does* open
    /// a substituted commitment produces a different roster for the victim, so the honest
    /// participants and the manipulated one derive different contexts — the SAS
    /// comparison catches exactly this divergence.
    #[test]
    fn a_manipulated_roster_diverges_in_sas() {
        let honest = honest_round(3, b"room");

        // The same three participants, but one of them was fed a relayed third commitment.
        let a = contribution(0);
        let b = contribution(1);
        let relayed = contribution(9);
        let manipulated_roster = [a.commitment(), b.commitment(), relayed.commitment()];
        let locked_a = a.lock(&manipulated_roster).unwrap();
        let locked_b = b.lock(&manipulated_roster).unwrap();
        let locked_r = relayed.lock(&manipulated_roster).unwrap();
        let reveals = [locked_a.reveal(), locked_b.reveal(), locked_r.reveal()];
        let mut scratch = [[0u8; NONCE_LEN]; 3];
        let manipulated = locked_a
            .finish(&reveals, &mut scratch, b"room")
            .expect("internally consistent session still finishes");
        drop((locked_b, locked_r));

        assert_ne!(manipulated.context(), honest[0].context());
        assert_ne!(manipulated.sas(), honest[0].sas());
    }

    /// A transport swapping this participant's own reveal is caught even when the
    /// substitute opens some commitment.
    #[test]
    fn a_swapped_own_reveal_refuses() {
        let mine = contribution(1);
        let peer = contribution(2);
        let mine_nonce_committed = mine.commitment();
        let roster = [mine_nonce_committed, peer.commitment()];
        let locked = mine.lock(&roster).unwrap();
        let peer_locked = peer.lock(&roster).unwrap();

        // Both slots filled with the peer's (valid) reveal: slot 0 opens nothing.
        let reveals = [peer_locked.reveal(), peer_locked.reveal()];
        let mut scratch = [[0u8; NONCE_LEN]; 2];
        assert_eq!(
            locked.finish(&reveals, &mut scratch, b"m").unwrap_err(),
            ProtocolError::Rejected
        );
    }

    #[test]
    fn count_mismatch_and_short_scratch_are_distinguished_correctly() {
        let mine = contribution(1);
        let peer = contribution(2);
        let roster = [mine.commitment(), peer.commitment()];

        let locked = mine.lock(&roster).unwrap();
        let peer_reveal = peer.lock(&roster).unwrap().reveal();
        let my_reveal = locked.reveal();

        // Too few reveals: a session fact — Rejected.
        let mut scratch = [[0u8; NONCE_LEN]; 2];
        let short = [my_reveal];
        let locked_again = {
            let mine = contribution(1);
            mine.lock(&roster).unwrap()
        };
        assert_eq!(
            locked_again.finish(&short, &mut scratch, b"m").unwrap_err(),
            ProtocolError::Rejected
        );

        // Scratch too small: the caller's buffer — Malformed.
        let mut tiny = [[0u8; NONCE_LEN]; 1];
        let reveals = [my_reveal, peer_reveal];
        assert_eq!(
            locked.finish(&reveals, &mut tiny, b"m").unwrap_err(),
            ProtocolError::Malformed
        );
    }

    /// Fresh entropy per round means a refresh yields an unrelated context even for the
    /// same participants and channel (§8.1, late joiners).
    #[test]
    fn a_rerun_round_with_fresh_entropy_is_unrelated() {
        let first = honest_round(2, b"channel");
        let contributions = [contribution(0x40), contribution(0x41)];
        let roster = [contributions[0].commitment(), contributions[1].commitment()];
        let [a, b] = contributions;
        let locked = [a.lock(&roster).unwrap(), b.lock(&roster).unwrap()];
        let reveals = [locked[0].reveal(), locked[1].reveal()];
        let [la, _] = locked;
        let mut scratch = [[0u8; NONCE_LEN]; 2];
        let second = la.finish(&reveals, &mut scratch, b"channel").unwrap();
        assert_ne!(first[0].context(), second.context());
    }

    /// The context binds the channel: the same nonces over different channel metadata are
    /// different sessions.
    #[test]
    fn channel_metadata_is_bound() {
        let on_a = honest_round(2, b"channel-a");
        let on_b = honest_round(2, b"channel-b");
        assert_ne!(on_a[0].context(), on_b[0].context());
    }

    #[test]
    fn secrets_do_not_leak_through_debug() {
        use std::format;
        let c = contribution(0xab);
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("ab"), "secret leaked: {rendered}");
    }
}
