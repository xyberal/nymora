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

## `status`, and why it matters

**`settled`** — the byte family (§6.5). These constructions use SHA-256, which is chosen and
permanent because none of their values enters a circuit. A second implementation can match these
today, and a change to any of them is a protocol break requiring a domain-tag version bump.

**`provisional`** — the algebraic family. These will be recomputed inside the zero-knowledge
circuit, so they must use the single network-wide algebraic hash of §6.5, which is not yet
chosen. SHA-256 stands in for it. **The digests will change when the real hash arrives.**

What a provisional vector pins is the *shape*: the domain tag, the field order, the length
framing, and which value goes where. Those are settled, and getting them wrong is the failure
these vectors exist to catch. The digest itself is not yet a commitment.

## A note on routing tags

`tag` is the one construction here that absorbs no domain tag, and that is deliberate. HMAC
takes its separation from the key, and `K_tag_e` is already bound to a domain, an agora, and an
epoch by `derive_tag_key` — which has its own vector, so the two can be checked as a chain.

These vectors were withheld for a while: the implementation had a domain tag inside the HMAC
message and §6.4 did not, so publishing either would have cemented the wrong one. A tag mismatch
is silent — every bundle simply resolves to "not addressed to me" — which is exactly the kind of
divergence vectors exist to prevent, and exactly the kind that publishing them prematurely would
have locked in.
