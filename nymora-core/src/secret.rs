// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret material.
//!
//! Values here are erased on drop, redacted in `Debug`, and compared in constant time.
//! They are also deliberately **not** `Clone`: a secret should be moved or borrowed, and
//! duplicating one should require enough friction to notice. Relax that only when a real
//! need appears.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// A fixed-width secret.
///
/// Reaching the bytes requires [`expose`](SecretBytes::expose), named so that every use is
/// trivially greppable in review.
pub struct SecretBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the secret bytes.
    ///
    /// Every call site is a place where secret material is in play; keep them few and
    /// obvious.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

/// Constant-time equality.
///
/// Comparing secrets with a short-circuiting `==` leaks their contents through timing, so
/// the ordinary operator is wired to a constant-time comparison rather than left to
/// derive.
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes<")?;
        write!(f, "{N}")?;
        f.write_str(">(<redacted>)")
    }
}

/// A credential's epoch secret key, `sk_epoch` (§9.1).
///
/// Used for every routine operation. Its compromise is bounded to the epoch it belongs to,
/// which rests on the key being destroyed when that epoch **ends** — not when a successor is
/// certified (§9.1). The two are separate events: certification happens when the member next
/// acts, so a member who is inactive holds no usable epoch key at all.
#[derive(Debug, PartialEq, Eq)]
pub struct EpochSecretKey(SecretBytes<32>);

/// The commitment opening value `r_root` (§9.1).
///
/// Supplied as the membership witness on every routine proof, and therefore held in
/// software rather than hardware. It authorizes nothing on its own: alone it permits no
/// forgery, only membership testing by an adversary who already holds a candidate
/// `pk_root`.
#[derive(Debug, PartialEq, Eq)]
pub struct RootOpening(SecretBytes<32>);

/// The durable key behind the migration nullifier, `sk_migrate` (§9.1, §9.3).
///
/// A nullifier enforces "at most once" only for the lifetime of the key that produced it,
/// and the verifier has nothing else to fall back on — it never learns which member acted.
/// Every other context in the protocol guards something that lives within one epoch and so
/// uses [`EpochSecretKey`]; a credential's accumulator leaf does not, since it remains in
/// the accumulator indefinitely. `sk_migrate` is therefore generated once at credential
/// creation, committed in the leaf, and never rotated.
///
/// It carries across planned migration rather than being regenerated. A fresh key would
/// launder the nullifier consuming the previous leaf, letting one credential spawn
/// successors without limit — each inheriting the original's tenure, vouch count, and tier
/// (§9.3).
///
/// This is a distinct type from [`EpochSecretKey`] so that the two lifetimes cannot be
/// confused at a call site: passing the epoch key where this belongs would silently reduce
/// a permanent guarantee to a per-epoch one.
#[derive(Debug, PartialEq, Eq)]
pub struct MigrationKey(SecretBytes<32>);

/// An agora's per-epoch routing tag key, `K_tag_e` (§6.4).
///
/// Symmetric, shared by every current member of one agora for one epoch, and distributed
/// through the same attribute-based-encryption gating used for tiered content. Revocation
/// is implicit: a revoked member simply stops receiving future broadcasts.
///
/// Because it is shared, it authenticates nothing about *who* produced a tag — it only
/// establishes that the producer held the epoch's key. Never treat a tag match as evidence
/// of authorship; that is what attestation proofs are for (§6.5).
#[derive(Debug, PartialEq, Eq)]
pub struct TagKey(SecretBytes<32>);

macro_rules! secret_newtype {
    ($($name:ident),+ $(,)?) => {
        $(
            impl $name {
                #[doc = concat!("Takes ownership of the bytes of a `", stringify!($name), "`.")]
                #[must_use]
                pub fn new(bytes: [u8; 32]) -> Self {
                    Self(SecretBytes::new(bytes))
                }

                /// Borrows the secret bytes. See [`SecretBytes::expose`].
                #[must_use]
                pub fn expose(&self) -> &[u8; 32] {
                    self.0.expose()
                }
            }
        )+
    };
}

secret_newtype!(EpochSecretKey, RootOpening, MigrationKey, TagKey);

#[cfg(test)]
mod tests {
    use super::{EpochSecretKey, MigrationKey, RootOpening, SecretBytes, TagKey};
    use std::format;

    #[test]
    fn debug_does_not_leak_the_secret() {
        let secret = SecretBytes::new([0xab; 32]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes<32>(<redacted>)");
        assert!(!rendered.contains("ab"), "secret leaked into Debug output");
    }

    /// Every named secret, not just the base type.
    ///
    /// A newtype that derived `Debug` over a redacting inner type would still redact, but a
    /// newtype added later over raw bytes would not — so each is checked by name rather
    /// than trusted to inherit.
    #[test]
    fn named_secrets_do_not_leak_either() {
        let rendered = [
            ("sk_epoch", format!("{:?}", EpochSecretKey::new([0xcd; 32]))),
            ("r_root", format!("{:?}", RootOpening::new([0xcd; 32]))),
            ("sk_migrate", format!("{:?}", MigrationKey::new([0xcd; 32]))),
            ("K_tag_e", format!("{:?}", TagKey::new([0xcd; 32]))),
        ];
        for (name, output) in rendered {
            assert!(!output.contains("cd"), "{name} leaked into Debug output");
        }
    }

    #[test]
    fn equality_compares_contents() {
        assert_eq!(SecretBytes::new([1u8; 32]), SecretBytes::new([1u8; 32]));
        assert_ne!(SecretBytes::new([1u8; 32]), SecretBytes::new([2u8; 32]));
    }

    #[test]
    fn exposing_returns_the_bytes() {
        let bytes = [9u8; 32];
        assert_eq!(EpochSecretKey::new(bytes).expose(), &bytes);
    }
}
