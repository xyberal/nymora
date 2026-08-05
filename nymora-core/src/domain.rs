// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain-separation tags.
//!
//! Every hashing context in the protocol has its own tag, so that a value produced for one
//! purpose can never be reinterpreted as a value produced for another. A collision between
//! two contexts is a silent and catastrophic failure — it would let, for example, a
//! live-authentication pseudonym be replayed as an attestation nullifier — so the tags are
//! defined once, here, and checked by tests rather than trusted to reviewer attention.

/// Declares the domain registry.
///
/// The enum and [`Domain::ALL`] are generated from a single list, so `ALL` is exhaustive by
/// construction; a new domain cannot be added without also appearing there, and therefore
/// cannot escape the uniqueness tests below.
macro_rules! domains {
    ($( $(#[$doc:meta])* $variant:ident => $tag:literal ),+ $(,)?) => {
        /// A distinct hashing context.
        ///
        /// Pass one to every hash, commitment, or derivation. See the module documentation
        /// for why this is mandatory rather than advisory.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Domain {
            $( $(#[$doc])* $variant, )+
        }

        impl Domain {
            /// Every domain, exhaustively.
            ///
            /// Generated from the same list as the enum itself, so it cannot fall out of
            /// step with it.
            pub const ALL: &'static [Domain] = &[ $( Domain::$variant, )+ ];

            /// The byte string mixed into the hash for this domain.
            #[must_use]
            pub const fn tag(self) -> &'static str {
                match self { $( Domain::$variant => $tag, )+ }
            }
        }
    };
}

domains! {
    /// Derivation of an agora's self-generated identifier from its public parameters (§3).
    AgoraId => "nymora/v0/agora-id",

    /// The accumulator leaf commitment, `Commit(pk_root, sk_cred, r_root)` (§9.1).
    Commitment => "nymora/v0/commitment",

    /// Derivation of a policy class identifier from its agora and label (§5.2).
    ///
    /// Per-agora rather than a shared constant, because the identifier is a handle presented
    /// to a Skiora and §5.1 forbids such a handle being derivable across agoras.
    PolicyClass => "nymora/v0/policy-class",

    /// The payload an epoch certificate signs over (§9.1).
    EpochCertificate => "nymora/v0/epoch-cert",

    /// Nullifier scoping a vouching attestation to one session (§5.3).
    NullifierVouch => "nymora/v0/nullifier/vouch",

    /// Nullifier binding an attestation to one message within one agora (§6.1).
    ///
    /// Authorship (§6.1) and corroboration (§6.3) share this domain deliberately: both
    /// derive `Hash(sk, message_hash, agora_id)`, so a member who authored a message
    /// produces the same nullifier when corroborating it, and the duplicate is rejected.
    /// Self-corroboration is prevented as a consequence of the shared domain rather than
    /// by a separate check.
    NullifierAttestation => "nymora/v0/nullifier/attestation",

    /// Nullifier enforcing one approval per credential on a policy proposal (§4.3).
    NullifierPolicy => "nymora/v0/nullifier/policy",

    /// Nullifier consuming the old leaf during device migration (§9.3).
    NullifierMigration => "nymora/v0/nullifier/migration",

    /// A participant's commitment in the live-authentication commit-reveal round (§8.1).
    LiveAuthCommitment => "nymora/v0/live-auth/commitment",

    /// The jointly-derived session context for a live exchange (§8.1).
    LiveAuthContext => "nymora/v0/live-auth/context",

    /// A participant's per-session pseudonym (§8.1).
    LiveAuthPseudonym => "nymora/v0/live-auth/pseudonym",

    /// The short authentication string compared aloud in person (§8.3).
    LiveAuthSas => "nymora/v0/live-auth/sas",

    /// Derivation of an agora's per-epoch tag key (§6.4).
    TagKey => "nymora/v0/tag/key",

    /// The routing tag attached to published content (§6.4).
    TagRouting => "nymora/v0/tag/routing",

    /// An entry in a credential's receipt ledger (§10.2).
    LedgerEntry => "nymora/v0/ledger/entry",

    /// The unlinkable per-epoch handle under which Skiora pins a ledger head (§10.4).
    LedgerHeadHandle => "nymora/v0/ledger/head-handle",
}

#[cfg(test)]
mod tests {
    use super::Domain;

    /// The version prefix every tag shares. Bumping it re-derives every value in the
    /// protocol, which is the point: it is how an incompatible change is made unambiguous.
    const PREFIX: &str = "nymora/v0/";

    #[test]
    fn every_tag_is_distinct() {
        for (i, a) in Domain::ALL.iter().enumerate() {
            for b in &Domain::ALL[i + 1..] {
                assert_ne!(a.tag(), b.tag(), "duplicate domain tag: {a:?} and {b:?}");
            }
        }
    }

    /// No tag may be a prefix of another.
    ///
    /// Domain separation is usually applied as `H(tag || data)`. If one tag were a prefix
    /// of another, attacker-chosen `data` could span the difference and make two distinct
    /// contexts hash identically — `H("a" || "bc") == H("ab" || "c")`. Length framing also
    /// prevents this, but prefix-freedom holds regardless of how any given call site frames
    /// its input, so it is enforced here rather than assumed downstream.
    #[test]
    fn no_tag_is_a_prefix_of_another() {
        for a in Domain::ALL {
            for b in Domain::ALL {
                if a == b {
                    continue;
                }
                assert!(
                    !b.tag().starts_with(a.tag()),
                    "{a:?} ({}) is a prefix of {b:?} ({})",
                    a.tag(),
                    b.tag()
                );
            }
        }
    }

    #[test]
    fn every_tag_is_versioned_and_non_empty() {
        for d in Domain::ALL {
            assert!(
                d.tag().starts_with(PREFIX),
                "{d:?} lacks the version prefix"
            );
            assert!(d.tag().len() > PREFIX.len(), "{d:?} has an empty context");
        }
    }

    #[test]
    fn registry_is_populated() {
        assert!(Domain::ALL.len() >= 15);
    }
}
