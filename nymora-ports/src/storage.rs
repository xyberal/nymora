// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable storage for a credential's own material.
//!
//! # Integrity, not only confidentiality
//!
//! The name says "secure" and the obvious reading is secrecy, but two of the properties this
//! port carries are about *tampering*. A silently altered `r_root` makes every membership proof
//! fail in a way indistinguishable from revocation; a silently altered epoch key makes a member
//! certify a key an attacker chose. A host backing this with a store that encrypts but does not
//! authenticate has implemented half of it.
//!
//! # Storing an agora is itself sensitive
//!
//! §3 makes an agora's *existence* the confidential fact, which is why [`AgoraId`] redacts its
//! own `Debug` output. That constraint reaches into the host: an implementation that names
//! keychain entries or files after the `agora_id` publishes the very thing the identifier is
//! kept quiet to protect, to anything that can enumerate the store — including another
//! application, a backup, and forensic acquisition.
//!
//! Implementations must therefore derive an opaque, non-invertible label from the `agora_id`
//! rather than using it directly, and must not vary the *number* of visible entries with the
//! number of agoras where the platform allows otherwise. This crate cannot enforce either; it
//! has no hash and takes no cryptographic dependency. It is stated here because the port is
//! where a host implementer will look.

use nymora_core::{AgoraId, Epoch, ProtocolError};

/// What a stored value is.
///
/// A closed set rather than caller-chosen strings. Free-form keys would let two call sites
/// disagree about a name, or collide, and the storage layout would stop being auditable from
/// the type alone.
///
/// # What is deliberately absent
///
/// **Receipt-ledger state (§10.2).** Proposal 0010 proposes deferring the ledger, and proposal
/// 0009 proposes a construction that would put chain state here whose loss has protocol
/// consequences. Neither is decided, so no slot is reserved. Adding one later is not a breaking
/// change — this enum is `#[non_exhaustive]` — whereas shipping a slot that turns out to hold
/// nothing would be a durability contract made on a guess.
///
/// **Cached accumulator roots (§8.3).** Roots are scoped per tier as well as per epoch (§5.2),
/// and tiers are not yet modelled in this workspace. A slot keyed only by [`Epoch`] would be
/// quietly wrong for a multi-tier agora.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Slot {
    /// `sk_cred` (§9.1) — durable, never rotated, carried across planned migration (§9.3).
    ///
    /// Every nullifier whose count must be correct derives from this (proposal 0008), so its
    /// loss ends the credential and its disclosure is permanent.
    CredentialKey,

    /// `r_root` (§9.1) — the commitment opening value, fixed once at credential creation.
    ///
    /// Supplied as a witness on every routine proof (proposal 0003), so it is software-held by
    /// necessity rather than by choice.
    RootOpening,

    /// `sk_epoch` for one epoch (§9.1).
    ///
    /// Keyed by epoch because deletion is driven by the epoch **ending**, not by a successor
    /// being certified (proposal 0007). A member who has not acted recently certifies nothing,
    /// and must still end up holding no usable key.
    EpochKey(Epoch),

    /// A routing tag key for one epoch (§6.4).
    ///
    /// Several may be live at once: §11's revocation asymmetry means read capability persists
    /// until the next tag-key broadcast, even where write capability has already ended.
    TagKey(Epoch),
}

/// Durable storage for one member's material, scoped per agora.
///
/// # Every operation names an agora, and none enumerates
///
/// There is no `list`, no `agoras`, no iterator, and no count. §5.1 requires that memberships
/// share nothing, and an unscoped enumeration API would hand any caller the set of agoras a
/// member belongs to — which is both the cross-agora linkage §16 exists to prevent and, per §3,
/// a disclosure of those agoras' existence.
///
/// The invariant is carried by the signatures rather than by a comment: every method takes an
/// [`AgoraId`], so there is no operation that could return something unscoped. A test in this
/// module implements the trait exhaustively and will stop compiling if the surface grows, which
/// is the point at which someone adding an enumeration method has to justify it.
///
/// # Errors
///
/// [`ProtocolError::Unavailable`] where the store could not be reached or the write did not
/// commit. [`ProtocolError::Malformed`] where the caller's buffer is too small to hold the
/// value. Absence is not an error — see [`load`](SecureStorage::load).
pub trait SecureStorage {
    /// Writes a value, replacing any current one.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn store(&mut self, agora: AgoraId, slot: Slot, value: &[u8]) -> Result<(), ProtocolError>;

    /// Reads a value into `out`, returning how many bytes were written.
    ///
    /// `Ok(None)` means the slot is empty. That is reported as a value rather than an error
    /// because absence here is a fact about the caller's own device, not about hidden protocol
    /// state — the distinction [`ProtocolError`] exists to withhold applies to a counterparty,
    /// and this port has none.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn load(
        &self,
        agora: AgoraId,
        slot: Slot,
        out: &mut [u8],
    ) -> Result<Option<usize>, ProtocolError>;

    /// Destroys a value.
    ///
    /// Succeeds whether or not the slot held anything, so a caller cannot learn from the result
    /// what was there — and so that the epoch-end deletion of §9.1 is idempotent, which it must
    /// be: a member whose device was off across a boundary performs it late, and a member who
    /// already performed it may perform it again.
    ///
    /// Implementations must destroy rather than unlink. A store that merely drops a reference
    /// leaves an epoch key recoverable, and forward secrecy is the whole reason the deletion is
    /// specified.
    ///
    /// # Errors
    ///
    /// See the trait documentation.
    fn delete(&mut self, agora: AgoraId, slot: Slot) -> Result<(), ProtocolError>;
}

#[cfg(test)]
mod tests {
    use super::{SecureStorage, Slot};
    use nymora_core::{AgoraId, Epoch, ProtocolError};

    /// A host may hold this port behind a trait object; keep it dyn-compatible.
    fn _is_dyn_compatible(_: &dyn SecureStorage) {}

    /// Fails to compile if the port's surface changes.
    ///
    /// If you are here because you added a method, check it against the no-enumeration rule in
    /// the trait documentation before making this compile again. An API returning anything not
    /// scoped to a single [`AgoraId`] is a §5.1 violation regardless of how convenient it is.
    struct SurfaceGuard;

    impl SecureStorage for SurfaceGuard {
        fn store(&mut self, _: AgoraId, _: Slot, _: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }

        fn load(&self, _: AgoraId, _: Slot, _: &mut [u8]) -> Result<Option<usize>, ProtocolError> {
            Ok(None)
        }

        fn delete(&mut self, _: AgoraId, _: Slot) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// Epoch-scoped slots must not collapse into one another.
    ///
    /// Two epochs sharing a slot would make the epoch-end deletion of §9.1 destroy the wrong
    /// key, or the certification of a successor overwrite a predecessor still inside its window.
    #[test]
    fn epoch_scoped_slots_are_distinct_per_epoch() {
        assert_ne!(Slot::EpochKey(Epoch::new(7)), Slot::EpochKey(Epoch::new(8)));
        assert_ne!(Slot::TagKey(Epoch::new(7)), Slot::TagKey(Epoch::new(8)));
    }

    /// Two kinds of key material for the same epoch are different slots.
    #[test]
    fn slot_kinds_do_not_collide_within_an_epoch() {
        assert_ne!(Slot::EpochKey(Epoch::new(3)), Slot::TagKey(Epoch::new(3)));
    }

    /// The durable slots carry no epoch, and are therefore never deleted by a rollover.
    #[test]
    fn durable_slots_are_not_epoch_scoped() {
        assert_ne!(Slot::CredentialKey, Slot::RootOpening);
        for epoch in [0, 1, u64::MAX] {
            assert_ne!(Slot::CredentialKey, Slot::EpochKey(Epoch::new(epoch)));
            assert_ne!(Slot::RootOpening, Slot::TagKey(Epoch::new(epoch)));
        }
    }

    /// Deletion is idempotent, so a late or repeated epoch-end sweep is safe.
    #[test]
    fn deleting_an_absent_slot_succeeds() {
        let mut store = SurfaceGuard;
        let agora = AgoraId::from_bytes([0x11; 32]);
        assert_eq!(store.delete(agora, Slot::EpochKey(Epoch::ZERO)), Ok(()));
        assert_eq!(store.delete(agora, Slot::EpochKey(Epoch::ZERO)), Ok(()));
    }
}
