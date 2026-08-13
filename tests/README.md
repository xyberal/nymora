# Conformance vectors

Cross-role conformance vectors live here — the single source of truth a conformant
**Skiora** (server) and **Persora** (client) both validate against.

These vectors are the **executable form of the [specification](../spec)**: prose in
`spec/` and vectors here are two encodings of the same truth, and they change in the same
commit. Each vector should cite the specification section it pins (e.g. `§6.5`).

Today the vectors live beside what they pin: the derivation and wire-format vectors in
[`../nymora-crypto/vectors/`](../nymora-crypto/vectors) (exercised by
`nymora-crypto/tests/conformance.rs`), and the state-machine conformance tests in
[`../nymora-protocol/tests/`](../nymora-protocol/tests). This directory takes over when
the wire formats freeze and the vectors become cross-role artifacts rather than crate
tests — nothing is published here until then.
