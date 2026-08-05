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

## What is deliberately absent

**Routing tags (§6.4).** `tag()` and `derive_tag_key()` have no vectors here, and that is not an
oversight. §6.4 specifies

```
tag = HMAC(K_tag_e, message_hash)
```

while the implementation computes `HMAC(K_tag_e, domain_tag || message_hash)`. Both are
defensible; they are not the same function, and a vector would cement whichever is wrong. This
is the settled construction with the most to lose from that — a mismatch is silent, since every
bundle simply resolves to "not addressed to me".

Vectors follow once the specification and the implementation agree.
