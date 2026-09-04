# Proposal 0036 — The boundary broadcast is delivered per member

**Status:** **Proposed** — the spec text it affects remains authoritative
**Affects:** §4.1, §5.2, §5.3, §9.1, §9.2, §9.3, §11, §15, §16.4
**Supersedes:** the witness-service half of [proposal 0025](0025-the-witness-service-is-keyed-not-proof-gated.md)
(its roots half — no lookup endpoint for current roots — stands unchanged)
**Amends:** [proposal 0024](0024-the-bulletin-is-a-signed-operator-statement.md) (the signature's scope)

> **Found in operation, not in review.** Preparing the first deployment experiment to be
> auditable by an outsider meant re-reading what each artifact hands to whom. Two of the
> answers contradicted the specification's own sentences. This proposal records both
> findings exactly, because the first was missed by two full read-throughs and an
> implementation audit — the Merkle path was treated as opaque hash material, and it is
> opaque only above level 0.

---

## Problem

### The witness path is a membership list

§5.2 states that "no API surface exposes accumulator size, leaf count, or leaf listing,
at any point," and proposal 0025 accepted a keyed witness service on the argument that a
leaked key "permits occupancy probing for its epoch, and nothing more." Both sentences
are false, and for a reason that needs no key leak:

1. The boundary broadcast delivers `K_witness_e` to every member (§11).
2. The witness service returns the inclusion path for **any** `(class, position)` under
   that key — the key authenticates that the requester was equipped for the epoch, never
   which position is theirs.
3. The fold rule is normative: "a leaf enters as itself" (§5.2, proposal 0035). So the
   level-0 sibling of position `p` is the neighbouring member's commitment, verbatim.
   Position 0 returns leaf 1; position 1 returns leaf 0; and so on.
4. Positions past the occupied range refuse, so the count falls out of the same walk.

`N` uniform requests — indistinguishable from legitimate refreshes, with nothing
per-member to rate-limit by design — reconstruct the whole class: every commitment, in
admission order (positions *are* admission order), with the exact count, and the class
root recomputes from the list to confirm it is complete. 0025 rejected serving the leaf
list whole because it "would hand every member the admission ordering," and then served
it one neighbour at a time.

A commitment is hiding — nothing about a person falls out of it — but it is a **durable
pseudonym**, and the same value appears wherever the credential is named: shown to its
vouchers during admission (a human act — the voucher knows who that is), submitted at
`credentials/init`, listed in the revocation set, consumed by migration. A member holding
the list can therefore place every leaf they can put a person behind at a position, watch
it across epochs (present, revoked, migrated), and read the group's size and growth. This
is a slice of what the threat model conceded only to the operator (§15's position entry).

### The bulletin gate does not cut a revoked member's reads

§11 defines revocation's read half by the delivery cut: "what reaches remaining members
and not the revoked one is exactly this broadcast," and 0025 has the witness key
"withheld from a revoked member at the same cut." Under pull delivery gated by a shared
key, neither holds. The revoked member's old key is inside the gate's catch-up window at
the revocation boundary; the bulletin they fetch with it **carries the new key**; and so
on at every later boundary, indefinitely. A shared bearer key renewed by the very artifact
it gates cannot distinguish a remaining member from a revoked one, and a pull server holds
no member identifiers with which to deliver anything else. What revocation cuts today is
*acting* — every proof fails against the new revocation root. Reading — roots, exclusion
sets, `K_tag`, and through it the agora's routing tags in the wild — continues.

The two findings compound: every ex-member, and every holder of one key ever leaked, is a
permanent enumerator of the class.

### Why the obvious repairs fail

*Gate the witness fetch behind a proof.* 0025's circularity stands: a boundary-admitted
member's first proof needs the path as its private input. *Withhold the level-0 sibling.*
It is required to verify the path. *Rate-limit the walk.* No per-member identifier exists,
by design, and a slow walk defeats any global cap. *Rotate keys faster.* The bulletin
delivers the rotation. Every repair that keeps a shared key and a by-position service
keeps the leak.

## Decision

**Members receive the boundary broadcast individually.** The operator holds, for every
credential, a delivery address it already knew how to reach — the leaf and the position —
and gains one more: an **inbox key**. At each boundary it encrypts each member's
inclusion path to that member alone and encrypts the shared material once for everyone.
The witness service is removed; the shared witness key is removed; a revoked member's
ciphertext is simply not produced.

### The envelope

```
envelope = {
  agora_id, epoch,
  ephemeral_pk,                         -- one operator X25519 key per boundary
  body_ct,                              -- AEAD_{K_body_e}(body)
  ciphertexts: [ct_0 … ct_{N-1}],       -- in position order, one per live credential
  head,                                 -- the latest signed log head, where a log exists (0024)
  signature                             -- statement key over every field above
}
body   = { class_roots, revocation_root, spend_root, revoked[], spent[], K_tag_e, K_fetch_{e+1} }
ct_i   = AEAD_{HKDF(DH(ephemeral_sk, inbox_pk_i))}( K_body_e ‖ path_i )
path_i = the siblings of leaf i below the tree's occupied height (the rest are constant)
```

The statement signature (0024) now covers the whole envelope, ciphertext list included:
one signed object per epoch, cacheable and relayable through infrastructure the member
does not trust, and two validly signed envelopes for one epoch remain portable proof of a
fork. The embedded log head keeps binding the member-gated artifact to the public one.

**The single-body rule (normative).** Everything members must agree on — roots,
exclusion sets, tag key, fetch key — lives in `body`, encrypted **once** under one
`K_body_e`, and a per-member ciphertext carries **only** `K_body_e` and that member's own
path. §11 rejected per-member authenticators because "a per-member MAC is precisely the
tool for undetectable per-member forking"; per-member *delivery* is the same tool, and
this rule is what disarms it. An operator cannot show one member different roots: the
body is one ciphertext under one signed digest, a substituted `K_body` fails the body's
authentication, and a substituted path fails the member's local check (below) or, if
used, is rejected by the server against the roots it holds. Any future proposal wanting
to put anything else in `ct_i` must argue against §11's warning explicitly.

### The inbox key

A per-credential X25519 keypair, generated fresh by Persora at credential creation
alongside `sk_cred` and `r_root`, held in its own storage slot and, where wrapping is in
force, wrapped like the epoch keys (§9.2). The public half is registered exactly once —
with the founder's leaf in the founding ceremony (§4.1), with a candidate's leaf at
`credentials/init` (§5.3), with the successor leaf in `credentials/migrate` (§9.3) — and is
**never presented on any other surface, in any proof, or on the log** (§10.1's rule: a
value tied to a member may be revealed to Skiora, never published). It is a delivery
address the operator holds against a row it already has, `(leaf, position, inbox_pk)`;
it is not a new pseudonym in any hands that lacked one. §5.1's freshness rule applies to
it as to every other credential value: independent per agora, never derived from a seed.

Not on Jubjub, deliberately: the certificate curve signs, the inbox key agrees on secrets,
and §9.1 keeps key roles apart. X25519 with HKDF-SHA256 and ChaCha20-Poly1305 are the
boring, `no_std`, well-analyzed choices; they join the pinned primitive set (§6.5) and
gain conformance vectors. No forward secrecy is claimed: a stolen inbox key reads that
credential's bulletins until it migrates or expires, which sits inside the device-
compromise residual §15 already states.

### What each party does

**Skiora, at a boundary:** snapshot the epoch's roots (0020); mint `K_body_e`, the
ephemeral key, and `K_fetch_{e+1}` as operator entropy, journaled like every other entropy
so replay reconstructs the envelope byte for byte; encrypt the body; for every class and
every occupied position whose leaf is neither revoked nor expired, cut the path and encrypt
`K_body_e ‖ path` to that inbox key; sign. `O(N)` per boundary — a path is a handful of
node lookups from a tree the operator holds, an agreement plus an AEAD is microseconds.

**Persora (`sync`):** fetch the envelope whole; verify the signature under the pinned
statement key and the strict-epoch-monotonicity rule (0024) — `accept_bulletin` unchanged
in spirit; decrypt its own ciphertext, found by its position; decrypt the body; **check
that the delivered path reproduces the body's class root for its own leaf** (normative —
this is the client's half of the single-body rule); cache roots, tag key, and path for the
epoch; roll keys. The acting chain (§9.1) now takes the path from local storage. There is
no witness fetch, ever.

**Bootstrap** has no special case. A credential's ciphertext exists in the first envelope
after its leaf lands, because the operator held its inbox key from registration. The
founder's genesis envelope contains the founder's ciphertext. 0025's unreachable base case
is dissolved rather than worked around.

### The fetch key

The envelope must still be gated: an ungated bulletin is an existence-and-size oracle to
anyone who learns an agora id. `K_fetch_e` is a shared per-epoch secret with exactly the
tag key's lifecycle, delivered in the body, presented to fetch the envelope, accepted
within the host's catch-up window as today. Its blast radius is now stated in full: a
leaked or retained fetch key reveals that the agora exists and how many ciphertexts it
published this epoch — and nothing behind them, which is all ciphertext. A revoked member
retains the last fetch key they received and learns the count going forward; that is the
residual, and it is the occupancy §5.2 already concedes to a key holder.

### Even positions

Per-member delivery ends enumeration by members, but each member's own path still carries
one neighbour's commitment at level 0. **Leaves occupy even positions only; odd positions
are permanently empty** (the field's zero). Every level-0 sibling is then zero, and the
first informative sibling is `Poseidon(neighbour_leaf, 0)` — a stable value that matches
nothing seen in vouching, `credentials/init`, the revocation set, or migration. A
placement rule in §5.2, no circuit change, no fold change; capacity halves to 2³¹ per
class, still past any class the network will host (0032's argument holds at half).

### Expiry and renewal

Ciphertexts accumulate per lifetime credential, not per live member — exactly as
accumulator capacity does ("consumption tracks device churn rather than recruitment",
§5.2) — and a consumed leaf's inbox key cannot be retired by the operator, because
migration is anonymous (§9.3: the spend nullifier does not name the consumed leaf). So an
inbox registration is valid for a **horizon** of boundaries (a year of daily epochs by
default; an operator parameter with a specified minimum), after which the operator stops
encrypting to it unless renewed. Renewal is a member action: the routine proof chain,
challenge-bound like §7's access proof and carrying no nullifier, naming the inbox key
(same or fresh) whose horizon resets. Consumed leaves never renew, so their ciphertexts
fall away without the operator learning which leaf was consumed. The cost is a coarse
activity signal — "the credential at this position was alive at renewal time" — once per
horizon, replacing the once-per-epoch signal the witness fetch gives today.

### Device change (§9.3)

**Path 1, planned migration.** The new device registers a fresh inbox key with the
successor leaf. The old key cannot be retired by the operator (above), so the exposure is
an old device that keeps decrypting bulletins until it is wiped. Closed in this order:

1. **Migration is atomic with key destruction (normative for Persora).** Producing
   `migration_cert` behind the user-presence check (§9.2) deletes the wrapped inbox key
   and epoch keys in the same key-store operation. On hardware-backed devices this is
   reliable and irreversible; the software fallback is best-effort and still the default.
   After this, a listening old device is one whose key store was defeated — the
   extracted-`sk_root` scenario §15 already bounds.
2. **Delayed retirement, opt-in.** The old device may also sign
   `retire_cert = Sign(sk_root_old, {inbox_pk_old, agora_id})` for the new device to submit
   at any later time, under a proof that the signature verifies against the key committed
   in the consumed leaf — the migration circuit's certificate clause under a new message
   domain, not a new statement. The operator drops the key at the next bulletin: no
   boundary, no quorum, no revocation-set entry. The price is migration's anonymity,
   partially: the operator learns which spent leaf belonged to *some* migration, so
   predecessor and successor become linkable within the batch of migrations in the same
   period — exact in an agora with one migration a month. The member chooses whether and
   when; submitting later widens the batch. Retirement in the migration's own epoch is
   **not** offered as a routine step: "migrate to Y" and "retire X" in one epoch hand the
   operator a timing link for nothing.
3. **Expiry** as the unconditional floor.
4. **Revocation** as the emergency: an old device later found lost un-wiped is Path 2
   arriving late.

What an un-wiped device gets meanwhile is the read half only — roots, sets, `K_tag` — the
exposure class §15 prices for a leaked tag key, extended in duration; it cannot act.

**Path 2, lost, stolen, or seized.** Quorum revocation names the old leaf, so the operator
drops its inbox key at the forced boundary: the device stops receiving from the moment of
revocation. This is a strict improvement over today, where a stolen device holding
`K_witness` reads forever through the renewal chain. Fresh admission registers a fresh
inbox key like any new credential. The window before revocation — the policy judgment
§9.3 leaves to each agora — is unchanged.

## Alternatives rejected

**Position-bound fetch** — keep a witness service, but require a proof of owning position
`p` (inclusion under last epoch's class root, absence from this epoch's revocation root,
`p` public) before serving `p`'s path. Closes enumeration and the witness-side renewal.
Rejected because it leaves `K_tag` shared — the revoked member keeps resolving the
agora's routing tags forever, the very thing §11 defines revocation's read half by — needs
a new verification path over mixed-epoch roots, bolts a base case onto 0025's circularity
(first path via the vouch session), and leaves the per-position query, and with it §15's
position correlation, in place.

**Hash leaves before folding** — level-0 nodes as `Poseidon(LEAF_NODE, commitment)`.
Closes cross-referencing, not enumeration: count, ordering, and stable pseudonyms still
leak to every key holder. Subsumed by even positions, which achieve the same
unlinkability with no circuit change.

**Serve the class whole in the bulletin** — 0025's rejected option. It is the leak made
honest; it does remove the per-position query, and that is now achieved without it.

**Padding, PIR, rate limits.** Dummy leaves are indistinguishable from real commitments,
so real ones remain in the list, and §5.4 refuses padding on principle; private
information retrieval fixes the position correlation only; rate limiting has no member
identifier to act on.

**Signature-based membership, no accumulator** — the operator issues an admission
certificate over the leaf (the circuit already verifies that signature form for epoch
certificates), and proofs show a valid certificate instead of a path. No witness service,
no positions, nothing to enumerate. Rejected on the transparency log: an accumulator makes
the membership *set* a public commitment the log can hold the operator to (§10.1); with
certificates the operator can mint **ghost members** no auditor can detect. Auditability is
not traded for this.

**A re-vouch generation** — the bulletin instructs every member to be re-admitted through
fresh vouch sessions, whose `finalize` is a per-member channel. Sound in shape (it is
per-member delivery), and rejected on price: `N × threshold` human vouching decisions per
trigger, a liveness cliff for members offline during the window, a burst of session
metadata, and — since re-vouching the same credential yields the same leaf — no rotation
of pseudonyms without mass migration. It remains available as *policy* (periodic
re-vetting, emergency re-key), which is a separate proposal.

## Consequences

**Gained.** §5.2's "no leaf listing" is true again — no surface returns any leaf but the
requester's own, and that one's neighbour is an unlinkable value. §11's delivery cut is
literal: a revoked member's ciphertext does not exist, so revocation ends reading and
acting at the same boundary, tag key included. Two shared secrets retire (`K_witness`, and
the bulletin's role as the renewal channel for anything but `K_fetch`). The witness
service and its per-position query disappear, closing §15's "durable per-member position"
residual on the only surface that presented it. 0025's base case dissolves. A stolen
device is cut off at revocation rather than never.

**Paid.** The envelope grows `O(N)`. A path needs only the siblings below the occupied
height, so a ciphertext is roughly `32·⌈log₂N⌉ + 64` bytes:

| live credentials | ciphertext | envelope per epoch |
|---|---|---|
| 1,000 | ~370 B | ~0.4 MB |
| 10,000 | ~500 B | ~5 MB |
| 100,000 | ~600 B | ~60 MB |

Fine at daily epochs to ten thousand, tolerable at a hundred thousand on clearnet, heavy
over Tor. The whole-download is the privacy-preserving mode: fetching only one's own
ciphertext by index presents the position per epoch — the correlation this proposal
otherwise removes — so it is a documented downgrade a large agora may choose over an
unlinkable transport, not a default (§16.4 gains the ceiling). Two primitives join the
pinned set. Operator work per boundary is `O(N)`, seconds at a million. One coarse
activity signal per horizon replaces one per epoch. Class capacity halves to 2³¹.

**Unchanged.** What a witness *is* and when it is valid (0020); the current roots' absence
of any lookup endpoint (0025's roots half); §7's challenge-bound access for history; the
statement key, the log key, and every property of the log; the proof statements and the
circuit (the path shape and the fold are untouched — only placement and delivery change);
the vouching protocol; what a seized, unlocked device reveals (§15 — a Persora home is a
membership by definition, and the inbox key sits inside that boundary, not beyond it).

## What lands together (README rule)

§5.2 (witness-service paragraph replaced by delivery-in-the-broadcast and the placement
rule), §11 (envelope, body, single-body rule, `K_fetch`; the `K_witness` sentence
removed), §4.1/§5.3/§9.3 (inbox key registered at founding, admission, migration;
Path 1's four-step sequence; Path 2's cut), §9.1/§9.2 (inbox key as member material
outside the derived hierarchy, wrapped where wrapping is in force), §15 (inbox key
replaces the position entry; envelope size; stolen-inbox-key scope; renewal signal;
retirement's batch linkability), §16.4 (the size ceiling and the whole-download rule),
0024's status note. Crates: `nymora-core` (inbox key types, envelope and body), `nymora-
crypto` (X25519, ChaCha20-Poly1305 behind the existing HKDF; vectors), `nymora-ports`
(`Slot::InboxKey`), `nymora-protocol` (create/migrate register the key; `accept_bulletin`
takes envelope and own ciphertext; operator builds the envelope; `witness()` removed;
renewal and retirement), conformance vectors, CHANGELOG. Skiora and Persora follow.

## Open questions

1. **Horizon.** Default and minimum, and whether it is a per-agora policy value (§4.3's
   machine can set it) or an operator parameter.
2. **Retirement's proof.** Confirm the migration circuit's certificate clause can be reused
   under a new message domain without a new instance (0034 pins instances; a new public
   input shape is a new instance).
3. **Ephemeral key per boundary versus per member.** One ephemeral saves 32 bytes per
   ciphertext; a per-member ephemeral would let ciphertexts be produced incrementally
   between boundaries. The single ephemeral is proposed; the trade is recorded.
4. **Exclusion sets in the body.** They travel whole as today. Whether the revocation set
   should hold `Poseidon(leaf, REVOKE)` rather than the leaf — so that even the body's
   contents cross-reference with nothing — is a hygiene change for a separate proposal;
   it touches the absence clause in the circuit.
