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
| `nymora-core` | Shared types, wire formats, `agora_id` derivation, errors |
| `nymora-crypto` | BBS+ credentials, Poseidon, commitments, nullifiers, tags, KDF |
| `nymora-circuits` | The one standardized ZK circuit; verifier keys |
| `nymora-accumulator` | Fixed-depth Merkle accumulator |
| `nymora-proofs` | Attestation / vouch / policy-check / live-auth proofs |
| `nymora-protocol` | State machines + conformance vectors, both roles |
| `nymora-ports` | `KeyStore` and `SecureStorage` traits (the engine is sans-io) |

## Build

```sh
cargo build --workspace
cargo test  --workspace
```

This workspace is designed to build and test in complete isolation — it depends on nothing
outside itself.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

> Status: **scaffold**. Crates are placeholders established in Step 1; protocol logic
> lands in subsequent steps.
