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

    /// The accumulator leaf commitment, `Commit(pk_root, sk_cred, r_root, agora_id)` (§9.1).
    Commitment => "nymora/v0/commitment",

    /// Derivation of a policy class identifier from its agora and label (§5.2).
    ///
    /// Per-agora rather than a shared constant, because the identifier is a handle presented
    /// to a Skiora and §5.1 forbids such a handle being derivable across agoras.
    PolicyClass => "nymora/v0/policy-class",

    /// Hashing a value into an accumulator leaf (§5.2).
    ///
    /// Distinct from [`Domain::AccumulatorNode`], and the distinction is the point. Without
    /// it, a fixed-depth tree admits the standard Merkle second-preimage substitution: an
    /// interior node, which is itself a hash of two children, is presented as a leaf, and an
    /// inclusion proof for it verifies. Two tags make the two positions unforgeable for each
    /// other.
    ///
    /// The accumulator hashes whatever value it is given rather than relying on that value
    /// already being domain-separated. A credential leaf is a [`Domain::Commitment`] and would
    /// be safe on its own, but the accumulator is generic over what it holds — §11's
    /// revocation set is a second instance — and its safety must not depend on the provenance
    /// of its contents.
    AccumulatorLeaf => "nymora/v0/accumulator/leaf",

    /// Hashing two children into an interior accumulator node (§5.2).
    AccumulatorNode => "nymora/v0/accumulator/node",

    /// Hashing an excluded key into a leaf of an exclusion set (§9.1, §11).
    ///
    /// The revocation set and the migration-spend set are keyed accumulators supporting
    /// non-membership witnesses — normative in §9.1's currency clauses, though the tree
    /// structure computing them is provisional until the real circuit lands (its hash is
    /// the Poseidon instance of §6.5, proposal 0033).
    /// The tags name the *context*, which survives whatever structure arrives. Distinct from
    /// [`Domain::AccumulatorLeaf`] for the same substitution reasons, and additionally so a
    /// membership path and a non-membership path can never be confused for each other.
    ExclusionLeaf => "nymora/v0/exclusion/leaf",

    /// Hashing two children into an interior exclusion-set node (§9.1, §11).
    ExclusionNode => "nymora/v0/exclusion/node",

    /// The one-time certificate authorizing migration to new hardware (§9.3).
    ///
    /// Distinct from [`Domain::EpochCertificate`]: both are signed by `sk_root`, and a
    /// migration certificate accepted as an epoch certificate — or the reverse — would let one
    /// authorization stand in for the other.
    MigrationCertificate => "nymora/v0/migration-cert",

    /// The payload an epoch certificate signs over (§9.1).
    EpochCertificate => "nymora/v0/epoch-cert",

    /// Nullifier scoping a vouching attestation to one session (§5.3).
    NullifierVouch => "nymora/v0/nullifier/vouch",

    /// Nullifier binding an attestation to one message within one agora (§6.1).
    ///
    /// Authorship (§6.1) and corroboration (§6.3) share this domain deliberately: both
    /// derive `Hash(sk, message_hash, agora_id)`, so a member corroborating a message
    /// they authored in the same epoch reproduces their authorship nullifier, and the
    /// duplicate is rejected without a separate check. The guarantee is same-epoch only —
    /// the key is destroyed when its epoch ends (§9.1), so a later self-corroboration
    /// would derive fresh — which is one strand of why corroboration is deferred rather
    /// than shipped (§6.3, proposal 0005).
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

    /// Reserved: the routing tag attached to published content (§6.4).
    ///
    /// Deliberately unused. §6.4's tag is bare `HMAC(K_tag_e, message_hash)` — the
    /// specification's literal construction — and the tag module argues that if `K_tag_e`
    /// ever acquires a second purpose, the separation belongs in the *key's* derivation,
    /// not in a prefix on this message. Registered so the name cannot quietly be claimed
    /// for something else.
    TagRouting => "nymora/v0/tag/routing",

    /// The canonical digest of a boundary bulletin, signed by the operator statement
    /// key (§11, proposal 0024).
    ///
    /// The digest leads with this tag and absorbs the `agora_id`, so a bulletin cannot
    /// be replayed into another agora (§16.1) and the statement key never signs bytes
    /// another artifact could share.
    Bulletin => "nymora/v0/bulletin",

    /// Derivation of an agora's per-epoch witness-service key (§5.2, proposal 0025).
    ///
    /// Distinct from [`Domain::TagKey`] although both derive from the same operator
    /// secret: the tag key resolves content, the witness key gates the inclusion-witness
    /// service, and a shared derivation would make leaking one leak both.
    WitnessKey => "nymora/v0/witness/key",

    /// The subject identifier of a policy-change proposal (§4.3).
    ///
    /// The three proposal domains exist so that every quorum decision can be approved by
    /// the one policy-approval action (§6.5's closed action set) while remaining
    /// unforgeable for one another: an approval nullifier is derived over the subject
    /// identifier, and subjects of different kinds derive under different tags, so an
    /// approval collected for a policy change can never count toward a revocation or a
    /// dissolution (proposal 0021).
    ProposalPolicy => "nymora/v0/proposal/policy",

    /// The subject identifier of a revocation proposal (§11).
    ProposalRevocation => "nymora/v0/proposal/revocation",

    /// The subject identifier of a dissolution proposal (§12).
    ProposalDissolution => "nymora/v0/proposal/dissolution",

    /// Chaining an entry into the per-agora transparency log (§10.1).
    TransparencyEntry => "nymora/v0/transparency/entry",

    /// The signed tree head committing to a transparency-log prefix (§10.1).
    TransparencyHead => "nymora/v0/transparency/head",

    /// An entry in a credential's receipt ledger (§10.2).
    ///
    /// Reserved: the ledger is deferred (proposal 0010). The tag stays because this registry
    /// is permanent — removing and later re-adding one would be indistinguishable from a
    /// redefinition.
    LedgerEntry => "nymora/v0/ledger/entry",

    /// The unlinkable per-epoch handle under which Skiora pins a ledger head (§10.4).
    ///
    /// Reserved: deferred with the ledger (proposal 0010).
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
