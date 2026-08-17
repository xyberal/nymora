# Nymora

Reference implementation of the **Nymora protocol** — anonymous, vouched, tiered group
membership and content provenance.

Nymora is the *protocol*: the cryptographic constructions, the one standardized
zero-knowledge circuit, the wire formats, and the state machines that any conformant
client (**Persora**) and server (**Skiora**) implementation must follow. This crate
workspace is pure protocol — no I/O, no networking, no storage, no platform APIs. Hosts
supply those through the trait interfaces in [`nymora-ports`](nymora-ports).

## Documentation

| | |
|---|---|
| [`spec/`](spec) | **The normative protocol specification** — mechanisms, threat model, known limitations |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How this implementation is structured: the pure-engine-plus-ports model and crate graph |
| [`tests/`](tests) | Conformance vectors — the executable form of the specification |

## Workspace

| Crate | Responsibility |
|---|---|
| `nymora-core` | Shared types, wire formats, the domain registry, secret newtypes, errors |
| `nymora-crypto` | The two hash families (SHA-256 byte family; the pinned Poseidon instance), the field crossing, commitments, nullifiers, the §9.1 certificate scheme, tags, KDF, `agora_id` and live-auth derivations |
| `nymora-circuits` | The two proof statements, the `ProofSystem` boundary, and the stub evaluator for tests |
| `nymora-accumulator` | Positional Merkle accumulator and the keyed exclusion sets |
| `nymora-proofs` | The per-action prove/verify surface |
| `nymora-protocol` | Credential lifecycle and state machines, both roles |
| `nymora-ports` | `KeyStore` and `SecureStorage` traits (the engine is sans-io) |

## Build

```sh
cargo build --workspace
cargo test  --workspace
```

The workspace is self-contained: no services, no platform dependencies, nothing to
configure — its only third-party dependencies are a handful of widely used cryptography
crates.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

> Status: **complete protocol logic on the real primitives.** Both roles' state
> machines run the whole lifecycle end-to-end — bootstrap, vouching, content, revocation,
> migration, dissolution — over the pinned Poseidon instance and the §9.1 certificate
> scheme, and the real circuits prove both statements behind the `ProofSystem` boundary
> (the `nymora-plonk` crate, standalone beside the workspace; proposals 0033–0035).
> [ARCHITECTURE.md](ARCHITECTURE.md) says exactly where each line sits.
>
> This design and its proving stack are **unaudited**, and nothing here is deployable.
> Do not use it to protect anyone yet. See [SECURITY.md](SECURITY.md) for the full
> status and how to report vulnerabilities.
