// SPDX-License-Identifier: MIT OR Apache-2.0

//! The payloads of the two root-key certificates (§9.1, §9.3).
//!
//! # The canonical signed message is a field element
//!
//! Both certificates are verified **inside the standardized circuit** (§6.5), which
//! recomputes the signed message from witness values — so what is signed must agree,
//! bit for bit, between every signing backend and the one shared circuit. That message
//! is not a byte string: the payload compresses to one element of the proving field by
//! the pinned hash (proposal 0035), the domain constant leading and the `agora_id`
//! inside, and the compression — computed in `nymora-crypto`, which owns the field —
//! is the message the §9.1 equation signs:
//!
//! ```text
//! m_epoch     = Poseidon(EPOCH_CERT, agora_id, epoch, pk_epoch.x, pk_epoch.y)
//! m_migration = Poseidon(MIGRATION_CERT, agora_id, pk_root_new.x, pk_root_new.y)
//! ```
//!
//! The guarantees the retired byte layout carried survive in the arithmetic: the two
//! certificate kinds cannot collide (distinct leading domains), neither replays into
//! another agora (§16.1 — the agora is inside the message), and no field boundary is
//! movable because there are no boundaries — every input is one field element, and the
//! sponge pins the arity itself.
//!
//! The types here are the payloads as *data*: what a [`KeyStore`] backend is handed to
//! sign. They live in `nymora-core` because the ports name them; the compression lives
//! with the field.
//!
//! [`KeyStore`]: https://docs.rs/nymora-ports

use crate::agora::AgoraId;
use crate::epoch::Epoch;

/// The payload an epoch certificate signs over (§9.1).
///
/// The certificate binds a freshly generated epoch key to a credential for exactly one
/// epoch, in exactly one agora. All three facts are inputs to the compressed message,
/// so a signature cannot omit any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCertPayload<'a> {
    /// The agora the certificate is for — inside the signed message, so the
    /// certificate cannot be replayed into another agora the member belongs to (§16.1).
    pub agora: AgoraId,
    /// The epoch the key is being certified for. A certificate that did not name its
    /// epoch would verify in any epoch, which is §9.1's forward-secrecy bound expressed
    /// as a signed input.
    pub epoch: Epoch,
    /// The freshly generated epoch public key: the 32-byte compressed encoding of a
    /// point on Jubjub's prime-order subgroup (§9.1). The message absorbs its affine
    /// coordinates, so an encoding that names no subgroup point has no message and
    /// cannot be signed.
    pub epoch_public_key: &'a [u8],
}

/// The payload a migration certificate signs over (§9.3).
///
/// A one-time authorization by the old device's root key for exactly one successor, in
/// exactly one agora. One-time-ness is not enforced here — the migration nullifier
/// consuming the old leaf is what makes a second successor unadmittable (§9.3) — but
/// the successor key and the agora are both inside the compressed message, so the
/// certificate authorizes this transition and no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationCertPayload<'a> {
    /// The agora the migration happens within. See [`EpochCertPayload::agora`].
    pub agora: AgoraId,
    /// The successor credential's root public key (§9.3's `pk_root_new`), in the same
    /// 32-byte compressed encoding as every root key.
    pub successor_public_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::{EpochCertPayload, MigrationCertPayload};
    use crate::agora::AgoraId;
    use crate::epoch::Epoch;

    /// The payloads are plain data — the compression is `nymora-crypto`'s — but every
    /// fact each one binds must be a field of the type, or a backend could be handed a
    /// payload with no way to absorb it.
    #[test]
    fn every_bound_fact_is_a_field() {
        let epoch = EpochCertPayload {
            agora: AgoraId::from_bytes([0x7e; 32]),
            epoch: Epoch::new(7),
            epoch_public_key: &[0xcc; 32],
        };
        assert_eq!(epoch.epoch.get(), 7);

        let migration = MigrationCertPayload {
            agora: AgoraId::from_bytes([0x7e; 32]),
            successor_public_key: &[0xdd; 32],
        };
        assert_eq!(migration.agora, epoch.agora);
    }
}
