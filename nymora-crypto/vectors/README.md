<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Conformance vectors

Machine-readable test vectors for the constructions this crate defines, so a second
implementation — in another language, by another team — can confirm it computes the same bytes.

The in-module `known_answer` tests pin the same values for this implementation. These files are
the interoperable form of the same fact.

## How to use them

Each construction lists cases with named inputs and an expected `output`. All byte strings are
lowercase hex; empty strings mean zero-length inputs, which are meaningful — several
constructions accept them, and framing is what keeps them distinguishable from an absent field.

`tests/conformance.rs` runs them against this implementation and will fail if any value moves.

## `status`

Every construction is **`settled`** (proposal 0035; nothing has been provisional since the
real primitives landed). Two families share the file:

- **The byte family** — SHA-256 with framed domain tags, for every value that never enters
  a circuit.
- **The algebraic family** — Poseidon over the BLS12-381 scalar field in the pinned
  instance of §6.5, plus the §9.1 certificate scheme, for every value the standardized
  circuit recomputes. Inputs and outputs are canonical little-endian field-element bytes;
  identifiers cross into the field by the truncation rule proposal 0035 states.

The algebraic-family expected values were computed by a **second implementation** of the
same instances — the proving stack's own CPU primitives, over its own curve fork — so they
validate this implementation rather than merely recording its output. A change to any value
in this file is a protocol break requiring a domain-tag version bump.

## A note on the KDF

The `kdf` construction is full HKDF-SHA256 — extract with the default zero-filled salt
(`Hkdf::new(None, ikm)` in RustCrypto terms; a salt of `hashlen` zero bytes per RFC 5869
§2.2), then expand. It is **not** expand-only over the raw input keying material; an
implementation that skips extract derives different values and fails the vector. The `info`
string is the domain tag and the context, each prefixed with its length as 8 little-endian
bytes, concatenated in that order.

## A note on routing tags

`tag` is the one construction here that absorbs no domain tag, and that is deliberate. HMAC
takes its separation from the key, and `K_tag_e` is already bound to a domain, an agora, and an
epoch by `derive_tag_key` — which has its own vector, so the two can be checked as a chain.

These vectors were withheld for a while: the implementation had a domain tag inside the HMAC
message and §6.4 did not, so publishing either would have cemented the wrong one. A tag mismatch
is silent — every bundle simply resolves to "not addressed to me" — which is exactly the kind of
divergence vectors exist to prevent, and exactly the kind that publishing them prematurely would
have locked in.
