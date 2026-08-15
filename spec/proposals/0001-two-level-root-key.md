# Proposal 0001 — Two-level root key

**Status:** **Applied** — 2026-08-15, as adapted by [proposal 0031](0031-the-committed-root-is-proving-native.md), on the constraint measurement this proposal's deferral asked for: embedded-curve verification 6,238 constraints against 2,541,739 for non-native P-256 measured in its most favorable configuration (407×; `measure/`). The decision rule below fired; 0031 records the mapping onto the specification as it stands, including the one adaptation (migration certificates remain with the protocol root).
**Affects:** §9.1, §9.2, §9.3, §6.5, §15
**Supersedes:** nothing
**Split:** the `r_root` correction originally bundled here was extracted to
[proposal 0003](0003-commitment-opening-value.md) and has been applied, since it is required
regardless of how this proposal is settled. This proposal's §9.1 replacement incorporates
that correction consistently; applying 0003 first produces no conflict.

> **Not on the critical path.** The protocol is being built against an abstract root
> authority behind the `KeyStore` port, so this decision does not block the state machines,
> the conformance vectors, or the reference client. It is settled when the real circuit is
> implemented, informed by measured constraint counts for the candidate constructions.

---

## Problem

### Hardware custody and in-circuit verification are in tension

§9.1 requires `epoch_cert = Sign(sk_root, {epoch_number, pk_epoch})` to be verified
*inside* the zero-knowledge proof, so that `pk_epoch` remains a private witness — without
which every attestation in a given epoch would share a comparable public value and become
trivially linkable, reintroducing exactly what §6.2 and §6.3 close.

§9.2 requires `sk_root` to be generated inside, and never leave, a hardware authenticator.

Hardware authenticators sign with ECDSA P-256 or Ed25519. Verifying either inside a proof
system over a different field requires emulated ("non-native") arithmetic, which is
plausibly one to two orders of magnitude more expensive than the rest of the circuit
combined. Because the epoch certificate is checked on *every* routine proof — every post,
corroboration, vouch, and live-authentication handshake — that cost is paid continuously by
the member's device, not once per epoch.

---

## Decision

Split the root into a **hardware key** and a **protocol root key**, and commit the protocol
root — not the hardware key — in the accumulator. Correct the treatment of `r_root` by
reclassifying it as what it is: a blinding value, held in software, supplied on every
routine proof.

| Key | Type | Custody | Used | Verified |
|---|---|---|---|---|
| `sk_hw` | Whatever the authenticator offers (P-256, Ed25519) | Hardware, non-exportable, never leaves | Credential creation, migration, root governance | Out-of-circuit, or a separate rare circuit |
| `sk_proot` | Proving-system-native (e.g. twisted Edwards EdDSA) | Software, encrypted at rest under `sk_hw` where supported | Epoch rollover only | Cheaply in-circuit |
| `sk_epoch` | Proving-system-native | Software, platform keychain | Every routine operation | Cheaply in-circuit |
| `r_root` | Commitment opening value | Software | Every routine proof | In-circuit |

**Rejected alternative — hardware wraps `sk_root` but does not sign it.** Generating a
proving-system-native root in software and encrypting it under a hardware key keeps the
circuit cheap with one fewer key concept, but the root is then plaintext in application
memory on *every* use, contradicting §9.2's central claim directly rather than qualifying
it. It also requires an authenticator capable of decryption or symmetric derivation,
excluding the discrete FIDO2 security keys §9.2 explicitly supports.

**Rejected alternative — accept non-native verification.** Preserves the specification
unchanged, at a per-proof cost that is likely prohibitive on the modest and older hardware
this design's threat model pushes members toward (§15). To be reconsidered if the phase-0
spike shows the cost is tolerable, in which case this proposal should be withdrawn.

---

## Replacement text

### §9.1 — replaces the section in full

> ### 9.1 Key hierarchy: hardware root, protocol root, and epoch keys
>
> Rather than one flat `sk`, each member's credential is split into three tiers, each with a
> distinct job, usage frequency, and custody model:
>
> ```
> sk_hw     — hardware-resident, non-exportable; binds the credential to genuine hardware
> sk_proot  — the protocol root; committed (via pk_proot) in the accumulator; used at rollover
> sk_epoch  — freshly derived each epoch; used for routine, day-to-day operations
> ```
>
> **Why three tiers rather than two.** The epoch certificate must be verified inside a
> zero-knowledge proof on every routine operation (see below for why). Hardware
> authenticators sign only with curves whose arithmetic is foreign to any practical proving
> field, making in-circuit verification of a hardware signature far more expensive than the
> entire remainder of the circuit. Committing a hardware key directly in the accumulator
> would impose that cost on every post, vouch, corroboration, and live-authentication
> handshake. Separating a hardware key that signs *once* from a proving-system-native
> protocol root that signs *each epoch* confines the expensive verification to a single,
> rare, out-of-circuit check, while still anchoring the credential to real hardware.
>
> The accumulator leaf commits to `pk_proot`, using an opening value `r_root` fixed once at
> credential creation:
>
> ```
> leaf = Commit(pk_proot, r_root)
> ```
>
> `sk_hw`'s job is to bind that protocol root to genuine hardware, once, at credential
> creation:
>
> ```
> binding_cert = Sign(sk_hw, {pk_proot, agora_id})
> ```
>
> The binding certificate is verified when the credential is admitted, outside any circuit —
> and ideally itself wrapped in a zero-knowledge proof rather than transmitted with `pk_hw`
> in the clear, consistent with this design's general avoidance of exposing linkable
> identifiers. `sk_hw` is used again only for device migration (§9.3) and, at each agora's
> option, for root-level governance actions.
>
> `sk_proot`'s only routine job is to certify a new epoch key when one is generated:
>
> ```
> epoch_cert = Sign(sk_proot, {epoch_number, pk_epoch})
> ```
>
> Every ordinary proof — vouching, authoring content, corroborating, live authentication
> (§8) — uses `sk_epoch`, together with `epoch_cert`, inside a single zero-knowledge proof
> that checks the whole chain without ever exposing `pk_epoch` or the certificate as
> plaintext:
>
> ```
> ∃ sk_epoch, pk_epoch, epoch_cert, pk_proot, r_root, merkle_path such that:
>   Commit(pk_proot, r_root) is a leaf in Root_{policy_class}
>   ∧ epoch_cert verifies as a valid signature over {epoch_number, pk_epoch}, by pk_proot
>   ∧ pk_epoch is correctly derived from sk_epoch
>   ∧ nullifier = Hash(sk_epoch, message_hash, agora_id)
> ```
>
> `pk_epoch` is a **private witness only** — it is never transmitted as a public input
> alongside a proof. Making it public would reintroduce exactly the kind of same-epoch
> cross-post linkability this design closed for authorship (§6.2) and corroboration (§6.3):
> every attestation in a given epoch would otherwise share an identical, comparable
> `pk_epoch` value, letting an observer link them without needing any other pseudonym field.
> Folding certificate verification entirely inside the proof keeps the output a single bit —
> `valid: true/false` — consistent with every other proof in this design (§6.5).
>
> **Why a certificate chain rather than a derivation.** It would be simpler, and far cheaper
> in-circuit, to derive `sk_epoch = KDF(sk_proot, epoch_number)` and drop the signature
> entirely. That is deliberately not done. A derivation chain means anyone who later
> recovers `sk_proot` — from a seized device, for instance — can recompute *every past
> epoch's* key, hence every past nullifier, and retroactively link the member's entire
> history. The certificate chain keeps `sk_proot` out of the routine witness set, so past
> epochs remain unrecoverable even to an adversary holding the current device. The in-circuit
> signature verification is the price of that forward secrecy, and is not negotiable for
> performance reasons.
>
> **What this bounds:** if `sk_epoch` is compromised, the attacker can forge nullifiers and
> impersonate the member only for that one epoch — including retroactively recomputing that
> epoch's own past nullifiers, since `Hash(sk_epoch, context)` is deterministic. Prior
> epochs' keys have already been discarded and cannot be reconstructed from the current one,
> so past activity outside the compromised epoch stays unlinkable even to someone holding the
> current key. This is the same forward-secrecy principle behind ratcheting message keys,
> applied here to credential-derived nullifiers.
>
> **What this does not bound:** compromise of `sk_proot`. Since it can sign arbitrary future
> epoch certificates, its compromise is effectively total and permanent for that credential —
> and, because it sits below the hardware boundary rather than inside it, the authenticator
> cannot re-gate its use once it has been extracted. This is a real reduction against a
> design in which the accumulator-committed key never leaves hardware, and is stated as a
> limitation in §15 rather than presented as equivalent. It is why `sk_proot` is touched only
> at epoch rollover, held encrypted at rest wherever the authenticator supports it (§9.2),
> and never stored alongside `sk_epoch`.
>
> **`r_root` is a blinding value, not authority, and is held in software.** Every proof of
> leaf membership must open `Commit(pk_proot, r_root)`, which requires `r_root` itself as a
> witness. No per-epoch substitute is possible: any derivation one-way enough to protect
> `r_root` is, by construction, unable to open a commitment formed with it. `r_root` is
> therefore supplied on every routine proof, and cannot meaningfully be held in hardware
> custody — a value exported on every operation is not hardware-held in any useful sense.
>
> This is acceptable because `r_root` authorizes nothing. Its sole function is to hide
> `pk_proot` from Skiora, which receives only the commitment at credential creation. An
> adversary holding `r_root` alone can forge no proof, sign no certificate, and impersonate
> no one; the value becomes useful only in combination with a candidate `pk_proot`, and an
> adversary positioned to obtain both already holds the device. `r_root` is stored with
> `sk_epoch` in ordinary OS-protected storage, and is not rotated.
>
> ```mermaid
> graph TD
>     HW["Hardware authenticator<br/>(secure enclave / FIDO2 key)<br/><i>§9.2 — non-exportable</i>"]
>     HW -->|generates internally| SKH["sk_hw<br/><i>never leaves hardware;<br/>credential creation, migration,<br/>optional root governance</i>"]
>     SKH -->|"signs once"| BIND["binding_cert = Sign(sk_hw,<br/>{pk_proot, agora_id})<br/><i>verified out-of-circuit</i>"]
>
>     BIND -.->|"binds"| SKP["sk_proot<br/><i>proving-system-native;<br/>wrapped at rest by sk_hw;<br/>used only at epoch rollover</i>"]
>     SKP -->|derives| PKP["pk_proot<br/><i>committed in accumulator:<br/>leaf = Commit(pk_proot, r_root)</i>"]
>     SKP -->|"signs each epoch"| CERT["epoch_cert = Sign(sk_proot,<br/>{epoch_number, pk_epoch})<br/><i>verified in-circuit</i>"]
>
>     CERT -.->|"certifies"| SKE["sk_epoch<br/><i>fresh per epoch, software-held,<br/>used for all routine ops</i>"]
>
>     SKE --> V["Vouching (§5.3)"]
>     SKE --> AU["Authoring / corroborating (§6)"]
>     SKE --> LA["Live authentication (§8)"]
>     SKE --> GOV["Policy approval (§5.3)"]
>
>     style HW fill:#1a2e1a,stroke:#88aa88,color:#eee
>     style SKH fill:#1a2e1a,stroke:#88aa88,color:#eee
>     style SKP fill:#2b2b40,stroke:#aa8888,color:#eee
>     style SKE fill:#2b2b40,stroke:#8888aa,color:#eee
>     style PKP fill:#1a1a2e,stroke:#8888aa,color:#eee
>     style CERT fill:#1a1a2e,stroke:#8888aa,color:#eee
>     style BIND fill:#1a1a2e,stroke:#8888aa,color:#eee
> ```
>
> Compromise of `sk_epoch` (touched by every routine operation) is bounded to one epoch.
> Compromise of `sk_proot` (touched only at rollover) is total and permanent for that
> credential. Compromise of `sk_hw` requires defeating the hardware itself. The three are
> never stored or used together.

### §9.2 — replaces the "Mechanism" and "Per-agora scoping" passages

> **Mechanism.** Persora delegates generation and use of `sk_hw` to a hardware authenticator
> — a phone's secure enclave (Apple Secure Enclave, Android StrongBox), a discrete security
> key (YubiKey-class), or an equivalent FIDO2/WebAuthn-compatible element. The authenticator
> generates the key internally using its own random number generator; it never leaves the
> hardware in any form, encrypted or otherwise. Persora holds only a reference and requests
> operations:
>
> ```
> Persora → authenticator: "generate a keypair scoped to agora_id X"
> authenticator → Persora: pk_hw   (sk_hw never leaves the secure element)
>
> Persora → authenticator: "sign this binding certificate over pk_proot"
> authenticator → prompts for biometric/PIN (user-presence check)
> authenticator → Persora: signature bytes
> ```
>
> **Protecting `sk_proot` at rest.** Where the authenticator can also decrypt or derive a
> symmetric secret — Secure Enclave via P-256 key agreement, StrongBox via a hardware-held
> AES key — `sk_proot` is stored encrypted under that capability and unwrapped only at epoch
> rollover, behind a user-presence check. Authenticators that can only sign, including
> typical discrete FIDO2 keys, cannot provide this; on those, `sk_proot` falls back to
> ordinary OS-protected storage. Persora must therefore query authenticator capability rather
> than assume it, and should tell the member which protection is actually in force.
>
> **Per-agora scoping is native to this pattern.** WebAuthn/FIDO2 authenticators already
> generate a distinct, unrelated keypair per relying-party context by design — treating each
> `agora_id` as its own relying-party identifier means "one unlinked hardware anchor per
> agora" is enforced by the hardware's own architecture, not solely by Persora's software
> discipline.

### §9.3 — replaces the migration certificate in Path 1

> ```
> Old device: migration_cert = Sign(sk_hw_old, {pk_proot_new, agora_id})
> New device: generates a fresh sk_hw internally (hardware-backed as in §9.2), plus a
>             fresh (sk_proot_new, r_root_new), and binds them per §9.1
>
> POST /agora/{agora_id}/credentials/migrate
>   body: { migration_cert, new_commitment: Commit(pk_proot_new, r_root_new) }
> ```
>
> Signing migration with `sk_hw` rather than the protocol root means an attacker who has
> extracted `sk_proot` alone cannot mint a successor credential — migration remains gated on
> the hardware, and therefore on physical possession of the old device.

### §6.5 — append

> Governance proofs (re-keying §4.4, dissolution §12) are exchanged only with the agora's own
> Skiora and never appear in an externally shared bundle. An agora may therefore use a
> distinct, heavier circuit for those actions — for instance one that verifies a hardware
> signature directly — without weakening the uniform-shape property, which exists to prevent
> fingerprinting of *published* content.

### §15 — new entry

> **The accumulator-committed key is software-held, and hardware cannot re-gate it.** The
> credential's protocol root (`sk_proot`, §9.1) is committed in the accumulator and signs
> each epoch certificate, but lives below the hardware boundary — encrypted at rest where the
> authenticator supports it, in ordinary OS-protected storage where it does not. An adversary
> who extracts it can mint epoch certificates indefinitely without ever touching the hardware
> again, and no user-presence check stands in the way. The hardware anchor (`sk_hw`) still
> gates credential creation and device migration, so a stolen protocol root cannot spawn a
> successor credential, and the receipt ledger (§10.2) with enforced logging (§10.3) makes
> abuse detectable after the fact and feeds revocation (§11) — but this is detection, not
> prevention, and it is a genuine reduction from a design in which the committed key never
> leaves hardware. It is the accepted cost of keeping routine proofs cheap enough to generate
> on a phone.

---

## Consequences

**Gained:** a routine circuit of roughly 15k constraints rather than 10–100× that; a
genuinely non-exportable hardware key; compatibility with every authenticator class §9.2
lists, including sign-only FIDO2 keys; forward secrecy across epochs preserved unchanged;
hardware gating retained on the irreversible actions (creation, migration, optionally
governance).

**Paid:** one more key concept to document, implement, and audit; two signature schemes in
the system rather than one; a more intricate migration and recovery matrix; and a
catastrophic-compromise path that hardware no longer covers, now named in §15.

## Open questions

1. **Root governance** — does §4.4 re-keying and §12 dissolution require `sk_hw` via a
   separate heavy circuit, or is `sk_proot` sufficient? Recommendation: require `sk_hw` for
   dissolution, given its irreversibility.
2. **Binding expiry ("hardware heartbeat")** — requiring `sk_hw` to re-sign the binding every
   N epochs would convert permanent `sk_proot` compromise into expiring compromise. Enforcing
   freshness *anonymously* is subtle, since Skiora must reject stale bindings without
   learning which credential is stale; the workable shape is leaf-level expiry, which adds
   churn and interacts with revocation. Deferred, not rejected.
3. **Concrete signature scheme** for `sk_proot`, pending the proving-system decision
   (task 0.2).
