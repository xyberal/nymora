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
/// Used for every routine operation, and discarded at epoch rollover. Its compromise is
/// bounded to the epoch it belongs to.
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

secret_newtype!(EpochSecretKey, RootOpening);

#[cfg(test)]
mod tests {
    use super::{EpochSecretKey, RootOpening, SecretBytes};
    use std::format;

    #[test]
    fn debug_does_not_leak_the_secret() {
        let secret = SecretBytes::new([0xab; 32]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes<32>(<redacted>)");
        assert!(!rendered.contains("ab"), "secret leaked into Debug output");
    }

    #[test]
    fn named_secrets_do_not_leak_either() {
        let key = EpochSecretKey::new([0xcd; 32]);
        let opening = RootOpening::new([0xcd; 32]);
        assert!(!format!("{key:?}").contains("cd"), "sk_epoch leaked");
        assert!(!format!("{opening:?}").contains("cd"), "r_root leaked");
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
