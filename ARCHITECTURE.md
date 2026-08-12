# Nymora — Architecture

How this reference implementation is structured. For *what* the protocol does, see
[`spec/`](spec).

---

## A pure engine with "ports"

The same core runs everywhere a Persora or Skiora does — a CLI, iOS, Android — while
Secure Enclave / StrongBox / WebAuthn, networking, and storage are inherently
platform-specific. The core therefore cannot *contain* any of that.

- **`nymora` is pure protocol** — no I/O, no clock, no network, no storage, no platform
  APIs, and no `async`. It takes inputs, emits proofs and messages, and verifies.
  Deterministic and portable.
- **The host supplies platform-specific behavior** through two trait interfaces ("ports")
  the core defines in [`nymora-ports`](nymora-ports):

| Port | Host implements with | Covers |
|---|---|---|
| `KeyStore` | iOS Secure Enclave · Android StrongBox · CLI software · FIDO2 key | The credential's root authority: creating it, signing epoch certificates and migrations, and reporting what the backend can actually do (§9.2) |
| `SecureStorage` | Platform keychain / encrypted store | `sk_cred`, `r_root`, `pk_root`, per-epoch `sk_epoch` with its certificate record, tag keys, the member's epoch cursor, cached roots (§8.3) |

Keeping the engine pure is what makes it testable without mocks of the physical world, and
what lets a single audited implementation serve every client — a security property in its
own right, since divergent client implementations would produce distinguishable proof
shapes (§6.5).

### Sans-io: what is deliberately *not* a port

`nymora` never performs I/O, so it does not abstract it:

- **Networking is not a port.** The protocol state machines consume events and emit
  messages; the host sends and receives them. This is the sans-io pattern, and it is what
  "transport-agnostic state machines" means taken literally. Per-agora network isolation
  (§16.2) is therefore a Persora obligation, not an engine trait — no interface inside
  `nymora` could enforce it anyway.
- **Time is not a port.** `Epoch` is passed in as a parameter. A clock trait would buy
  nothing over the value itself and would cost testability.

The practical dividend is that `nymora` contains no `async`, so it embeds in a CLI, an iOS
app, an Android app, or wasm without imposing a runtime or colliding with the host's.

### The root authority is abstract

`KeyStore` exposes a **root authority** — a public key committed in the accumulator, able to
sign epoch certificates — without revealing how many keys implement it. Creating one also
yields an opaque `RootBinding` that the protocol carries but never parses.

This is what keeps the hardware-custody question ([proposal 0001](spec/proposals/0001-two-level-root-key.md))
off the critical path: whether the root is one hardware key, a hardware key binding a
software key, or a key in a file changes the `KeyStore` implementation and nothing above it.

## Why one shared core

Uniform proof shape is a stated security requirement, not a convenience: §6.5 specifies one
standardized circuit precisely so that proof size and structure never vary. Independent
per-platform reimplementations would drift in serialization, field ordering, and encoding,
making content attributable to the client that produced it — exactly the fingerprinting
vector the design closes. A single core compiled to every target makes that uniformity
structural.

The same reasoning applies to nullifier derivation, Fiat–Shamir challenges, domain
separation, and the canonical certificate payload encodings (§9.1, §9.3): these must agree
bit-for-bit across every implementation or the protocol simply fails to interoperate.

## Crate graph

```
nymora-core          types, wire formats, domain registry, errors
   ├── nymora-crypto        hashing (byte + provisional algebraic), commitments,
   │                        nullifiers, tags, KDF, identifier and live-auth
   │                        derivations, the provisional signature
   │      ├── nymora-accumulator    positional accumulator (§5.2) and the keyed
   │      │        │                exclusion sets with non-membership witnesses
   │      │        │                (§9.1, §11)
   │      └────────┴── nymora-circuits   the two proof statements as types, the
   │             │                       `ProofSystem` boundary, and — until the
   │             │                       real circuit — the stub prover (§6.5)
   │             └── nymora-proofs       the per-action prove/verify surface
   └── nymora-ports         KeyStore / SecureStorage
                            (`software-key-store` also uses the provisional
                             signature from nymora-crypto)

nymora-protocol      credential lifecycle (§9.1–§9.3), witness assembly into the
   │                 statements, the member-side live-auth machine (§8), the shared
   │                 quorum-decision subjects — and, behind the `operator` feature,
   │                 the whole Skiora role of §4–§12 (`AgoraState`)
   └── depends on everything above, including the ports
```

Dependencies point one way only. `nymora-protocol` is the top of the graph: it defines the
lifecycle and the state machines and message contracts that a conformant Skiora and Persora
must follow — and it is, deliberately, the only crate that *drives* the ports rather than
merely defining or implementing them. The lifecycle's ordering carries security properties
(an epoch key destroyed when its epoch ends **is** the forward-secrecy bound of §9.1), and
one audited implementation of that sequencing is the same argument as one shared circuit —
a host asked to remember the ordering would eventually forget it. Everything below stays
port-free.

The operator role lives in the same open crate as the member role because a protocol
defines both sides: a conformant Skiora *wraps* `AgoraState` — adding HTTP, persistence,
sessions, and the delivery of boundary bulletins to remaining members — rather than
reimplementing the rules where no auditor can see them. The feature is off by default so
the member-side build stays allocation-free; the operator needs collections, and only the
operator.
