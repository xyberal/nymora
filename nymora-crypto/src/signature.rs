// SPDX-License-Identifier: MIT OR Apache-2.0

//! The provisional signature scheme — publicly verifiable, and a stand-in.
//!
//! # Why it exists now
//!
//! The root authority signs two certificates (§9.1, §9.3), and both are verified *inside*
//! the standardized circuit (§6.5) — which fixes the real scheme with the proving system,
//! the same fault line that leaves the algebraic hash provisional. Through phase 3 nothing
//! verified those signatures, so the software key store could honestly use keyed hashes.
//! The stub prover ends that: it must check "this certificate verifies under `pk_root`"
//! while holding only the public key, and no keyed hash can satisfy a public-verification
//! clause for any holder of the public value alone.
//!
//! # What is pinned, and what moves
//!
//! The **shape** is the commitment: a keypair produced from a 32-byte seed, a signature
//! over exactly a caller-supplied message, and verification under the public key alone.
//! The **algorithm** is not: Ed25519 here will be replaced by whatever embedded-curve
//! scheme the proving system makes affordable in-circuit, and every length below moves
//! with it. Size buffers from these constants and carry lengths explicitly — the phase-3
//! rule that no test may pin the stand-in's sizes exists so that replacement is a
//! recompilation, not an excavation.
//!
//! # The message is the caller's canonical bytes
//!
//! [`sign`] and [`verify`] add no framing and no domain separation of their own: the
//! certificate payloads from `nymora-core` are already canonical, length-framed, and led
//! by their domain tags, and the signed message must be exactly those bytes or no other
//! implementation — nor the circuit — can reconstruct it. The streaming interface matches
//! `encode_parts` on the payload types so a caller cannot accidentally sign a private
//! re-encoding.
//!
//! Internally the scheme is Ed25519ph (RFC 8032), which signs a SHA-512 digest of the
//! message. That choice is what permits streaming without an allocator; it is as
//! provisional as everything else here.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

/// Width of a signing seed, in bytes.
pub const SEED_LEN: usize = 32;

/// Width of a public verification key under the stand-in scheme. Moves with the scheme.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Width of a signature under the stand-in scheme. Moves with the scheme.
pub const SIGNATURE_LEN: usize = 64;

/// Streams a message and returns its prehash.
fn prehash(message: impl FnOnce(&mut dyn FnMut(&[u8]))) -> Sha512 {
    let mut hasher = Sha512::new();
    message(&mut |part: &[u8]| hasher.update(part));
    hasher
}

/// Derives the public verification key for a seed.
///
/// Deterministic, so a key store that derives its seeds can republish the same public key
/// without persisting anything.
#[must_use]
pub fn public_key(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Signs a message, streamed as parts.
///
/// The message is the exact concatenation of the streamed parts — see the module
/// documentation for why no framing is added here. Signing is deterministic.
#[must_use]
pub fn sign(
    seed: &[u8; SEED_LEN],
    message: impl FnOnce(&mut dyn FnMut(&[u8])),
) -> [u8; SIGNATURE_LEN] {
    SigningKey::from_bytes(seed)
        .sign_prehashed(prehash(message), None)
        // The only failure mode Ed25519ph defines is a context string over 255 bytes,
        // and no context is supplied.
        .expect("signing with no context string cannot fail")
        .to_bytes()
}

/// Verifies a signature over a message, streamed as parts, under a public key.
///
/// Returns `false` for a wrong-length or malformed public key or signature rather than
/// distinguishing those from an honest mismatch: every caller in this protocol treats an
/// unverifiable certificate and a forged one identically, so there is nothing for the
/// distinction to inform.
#[must_use]
pub fn verify(
    public_key: &[u8],
    message: impl FnOnce(&mut dyn FnMut(&[u8])),
    signature: &[u8],
) -> bool {
    let Ok(key_bytes): Result<[u8; PUBLIC_KEY_LEN], _> = public_key.try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; SIGNATURE_LEN], _> = signature.try_into() else {
        return false;
    };
    key.verify_prehashed(prehash(message), None, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{public_key, sign, verify, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN};

    const SEED: [u8; SEED_LEN] = [0x42; SEED_LEN];

    #[test]
    fn a_signature_verifies_under_its_public_key() {
        let pk = public_key(&SEED);
        let sig = sign(&SEED, |put| {
            put(b"canonical");
            put(b"payload");
        });
        assert!(verify(
            &pk,
            |put| {
                put(b"canonical");
                put(b"payload");
            },
            &sig
        ));
    }

    /// The message is the concatenation of the parts, with no framing added here.
    ///
    /// This is deliberate — the payloads being signed are already canonical and framed —
    /// and it must hold or the circuit's reconstruction of the message would differ from
    /// the byte string that was signed.
    #[test]
    fn part_boundaries_do_not_change_the_message() {
        let sig = sign(&SEED, |put| {
            put(b"canonical");
            put(b"payload");
        });
        assert!(verify(
            &public_key(&SEED),
            |put| put(b"canonicalpayload"),
            &sig
        ));
    }

    #[test]
    fn signing_is_deterministic() {
        assert_eq!(sign(&SEED, |put| put(b"m")), sign(&SEED, |put| put(b"m")));
    }

    #[test]
    fn a_tampered_message_is_rejected() {
        let sig = sign(&SEED, |put| put(b"message"));
        assert!(!verify(&public_key(&SEED), |put| put(b"messagf"), &sig));
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let mut sig = sign(&SEED, |put| put(b"message"));
        sig[0] ^= 0x01;
        assert!(!verify(&public_key(&SEED), |put| put(b"message"), &sig));
    }

    #[test]
    fn another_key_is_rejected() {
        let sig = sign(&SEED, |put| put(b"message"));
        let other = public_key(&[0x43; SEED_LEN]);
        assert!(!verify(&other, |put| put(b"message"), &sig));
    }

    /// Wrong-width inputs are an honest `false`, not a panic and not a distinguishable
    /// error — see [`verify`].
    #[test]
    fn wrong_width_inputs_are_rejected() {
        let pk = public_key(&SEED);
        let sig = sign(&SEED, |put| put(b"message"));
        assert!(!verify(
            &pk[..PUBLIC_KEY_LEN - 1],
            |put| put(b"message"),
            &sig
        ));
        assert!(!verify(
            &pk,
            |put| put(b"message"),
            &sig[..SIGNATURE_LEN - 1]
        ));
        assert!(!verify(&pk, |put| put(b"message"), &[]));
    }

    /// Two seeds that differ produce unrelated keys — the property the software key
    /// store's per-agora seed derivation relies on for §16.1.
    #[test]
    fn distinct_seeds_yield_distinct_keys() {
        assert_ne!(public_key(&SEED), public_key(&[0x43; SEED_LEN]));
    }
}
