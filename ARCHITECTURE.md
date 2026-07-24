# Nymora — Architecture

How this reference implementation is structured. For *what* the protocol does, see
[`spec/`](spec).

---

## A pure engine with "ports"

The same core runs everywhere a Persora or Skiora does — a CLI, iOS, Android — while
Secure Enclave / StrongBox / WebAuthn, networking, and storage are inherently
platform-specific. The core therefore cannot *contain* any of that.

- **`nymora` is pure protocol** — no I/O, no clock, no network, no storage, no platform
  APIs. It takes inputs, emits proofs and messages, and verifies. Deterministic and
  portable.
- **The host supplies platform-specific behavior** through a small set of trait interfaces
  ("ports") the core defines in [`nymora-ports`](nymora-ports):

| Port | Host implements with | Covers |
|---|---|---|
| `KeyStore` / `Authenticator` | iOS Secure Enclave · Android StrongBox · CLI software/YubiKey · web WebAuthn | Hardware custody of `sk_root`/`r_root`, epoch-cert signing, `r_epoch` derivation, user-presence prompt (§9.2) |
| `SecureStorage` | Platform keychain / encrypted store | `sk_epoch`/`r_epoch`, receipt ledger (§10.2), cached roots (§8.3) |
| `Transport` | Native HTTP + local QR/NFC/BLE | Talking to Skiora; in-person nonce exchange (§8.3) |
| `EpochClock` | Host-provided | Current epoch, without baking a clock into the core |

Keeping the engine pure is what makes it testable without mocks of the physical world, and
what lets a single audited implementation serve every client — a security property in its
own right, since divergent client implementations would produce distinguishable proof
shapes (§6.5).

## Why one shared core

Uniform proof shape is a stated security requirement, not a convenience: §6.5 specifies one
standardized circuit precisely so that proof size and structure never vary. Independent
per-platform reimplementations would drift in serialization, field ordering, and encoding,
making content attributable to the client that produced it — exactly the fingerprinting
vector the design closes. A single core compiled to every target makes that uniformity
structural.

The same reasoning applies to nullifier derivation, Fiat–Shamir challenges, domain
separation, and the `KDF(r_root, epoch)` chain (§9.1): these must agree bit-for-bit across
every implementation or the protocol simply fails to interoperate.

## Crate graph

```
nymora-core          types, wire formats, agora_id, errors
   ├── nymora-crypto        BBS+, Poseidon, commitments, nullifiers, tags, KDF
   │      ├── nymora-accumulator    fixed-depth Merkle accumulator (§5.2)
   │      └── nymora-circuits       the one standardized ZK circuit (§6.5)
   │             └── nymora-proofs  attest / vouch / policy-check / live-auth
   │                    └── nymora-protocol   state machines, both roles
   └── nymora-ports         KeyStore / SecureStorage / Transport / EpochClock
```

Dependencies point one way only. `nymora-protocol` is the top of the graph: it defines the
state machines and message contracts that a conformant Skiora and Persora must follow.
