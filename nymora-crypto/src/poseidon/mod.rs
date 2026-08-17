// SPDX-License-Identifier: MIT OR Apache-2.0

//! The algebraic hash: Poseidon over the BLS12-381 scalar field, in the pinned
//! instance (§6.5; proposals 0033, 0034).
//!
//! Width 3 (rate 2, capacity 1), α = 5, 8 full and 60 partial rounds, Grain-generated
//! constants — see [`constants`] for the reproducible invocation. This is the hash the
//! standardized circuit computes in-constraint; the implementation here is its CPU
//! twin, and every convention below is normative because the circuit shares it:
//!
//! - **Fixed-length sponge, arity-separated.** The capacity element is initialized to
//!   the input length before anything is absorbed, so hashes of different arity are
//!   computed by structurally disjoint functions — a 2-element node can never collide
//!   with a 5-element leaf. This is what replaced the per-context leaf/node string
//!   domains (proposal 0035).
//! - **Rate-2 absorption**: inputs are added into the first two state elements, two
//!   per permutation, the final partial block padded by absence (the capacity already
//!   fixed the length).
//! - **One squeeze**: the output is the first state element after the last
//!   permutation.
//!
//! The permutation adds the first round's constants before any S-box, applies the full
//! S-box (x⁵) to the whole state in the 8 outer rounds and to the **last** state
//! element in the 60 partial rounds, and follows each round's S-box with the MDS
//! layer and the next round's constants — the final round adding none.
//!
//! Domain separation is one absorbed element, from the field-domain registry
//! (`nymora-core`), led by the derivation's own arity — not framing, which has no
//! meaning here. See `nymora-core`'s registry for the two deliberately untagged,
//! arity-pinned derivations.

mod constants;

use ff::Field;

use crate::field::F;

/// Sponge width: two rate elements and one capacity element.
const WIDTH: usize = 3;

/// Sponge rate.
const RATE: usize = 2;

/// The 8 outer rounds where the S-box covers the whole state.
const FULL_ROUNDS: usize = 8;

fn round_constant(round: usize, i: usize) -> F {
    F::from_raw(constants::ROUND_CONSTANTS[round][i])
}

/// The MDS layer plus the next round's constants: `state ← MDS·state + rc`.
fn linear_layer(state: &mut [F; WIDTH], next_round: Option<usize>) {
    let mut next = [F::ZERO; WIDTH];
    for (i, out) in next.iter_mut().enumerate() {
        if let Some(r) = next_round {
            *out = round_constant(r, i);
        }
        for (j, s) in state.iter().enumerate() {
            *out += F::from_raw(constants::MDS[i][j]) * s;
        }
    }
    *state = next;
}

fn sbox(x: &mut F) {
    *x = x.square().square() * *x;
}

/// The pinned permutation.
fn permute(state: &mut [F; WIDTH]) {
    for (i, s) in state.iter_mut().enumerate() {
        *s += round_constant(0, i);
    }
    for round in 0..constants::ROUNDS {
        let partial = (FULL_ROUNDS / 2..constants::ROUNDS - FULL_ROUNDS / 2).contains(&round);
        if partial {
            sbox(&mut state[WIDTH - 1]);
        } else {
            state.iter_mut().for_each(sbox);
        }
        let next = round + 1;
        linear_layer(state, (next < constants::ROUNDS).then_some(next));
    }
}

/// The pinned Poseidon hash of a fixed-length input.
///
/// Every derivation in the protocol states its inputs explicitly and hashes them
/// through this one function; the input length is part of the derivation's identity
/// (see the module documentation).
#[must_use]
pub fn hash(inputs: &[F]) -> F {
    let mut state = [F::ZERO, F::ZERO, F::from(inputs.len() as u64)];
    for block in inputs.chunks(RATE) {
        for (entry, value) in state.iter_mut().zip(block) {
            *entry += value;
        }
        permute(&mut state);
    }
    state[0]
}

#[cfg(test)]
mod tests {
    use super::hash;
    use crate::field::{to_bytes, F};

    fn of(values: &[u64]) -> F {
        let inputs: alloc::vec::Vec<F> = values.iter().map(|v| F::from(*v)).collect();
        hash(&inputs)
    }

    extern crate alloc;

    /// Pins the whole instance — constants, MDS, sponge convention, padding — against
    /// the values the proving stack's own CPU implementation computes. If any of these
    /// move, the two implementations have diverged and every proof is at stake.
    #[test]
    fn known_answers_match_the_circuit_stack() {
        let cases: [(&[u64], [u8; 32]); 3] = [
            (
                &[1, 2],
                [
                    0x4a, 0xd8, 0x18, 0xf3, 0x9d, 0x91, 0x56, 0x7d, 0x10, 0x5c, 0x5b, 0xea, 0x1e,
                    0xc4, 0xb5, 0xac, 0x20, 0x1d, 0xc4, 0x5b, 0x78, 0x4e, 0x39, 0xa2, 0xbe, 0xef,
                    0x78, 0x17, 0x90, 0xbf, 0x51, 0x77,
                ],
            ),
            (
                &[1, 2, 3, 4, 5],
                [
                    0x03, 0xd9, 0x2c, 0xe2, 0x1d, 0xcc, 0xdc, 0x15, 0x97, 0xcd, 0xbb, 0xcd, 0x35,
                    0x54, 0x57, 0x45, 0xf2, 0x1f, 0xd1, 0x1b, 0xd2, 0x9c, 0xe0, 0x99, 0xe3, 0xf5,
                    0xb3, 0xd6, 0xba, 0xd4, 0x1f, 0x17,
                ],
            ),
            (
                &[1, 2, 3, 4, 5, 6],
                [
                    0x52, 0x65, 0xf4, 0xc2, 0x8c, 0x2a, 0x13, 0x2d, 0x7b, 0x2d, 0xc5, 0x29, 0xdd,
                    0x3c, 0xf7, 0x0c, 0xe0, 0x3c, 0xa0, 0x89, 0x9d, 0xa2, 0x00, 0xbe, 0xfb, 0x40,
                    0x1f, 0x0d, 0x63, 0x16, 0xea, 0xc4,
                ],
            ),
        ];
        for (inputs, expected) in cases {
            let mut le = expected;
            le.reverse();
            assert_eq!(
                to_bytes(&of(inputs)),
                le,
                "poseidon({inputs:?}) moved — the pinned instance has diverged"
            );
        }
    }

    /// Arity is identity: a shorter input is not a prefix of a longer one's hash
    /// chain, because the capacity element differs from the first permutation on.
    #[test]
    fn arity_separates_derivations() {
        assert_ne!(of(&[1, 2]), of(&[1, 2, 0]));
        assert_ne!(of(&[0]), of(&[0, 0]));
    }

    #[test]
    fn is_deterministic_and_input_sensitive() {
        assert_eq!(of(&[7, 8, 9]), of(&[7, 8, 9]));
        assert_ne!(of(&[7, 8, 9]), of(&[7, 8, 10]));
        assert_ne!(of(&[7, 8, 9]), of(&[8, 7, 9]));
    }
}
