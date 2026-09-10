# Proposal 0038 — Artifacts have a text armor

**Status:** **Applied** — §17.2 and §17.3 are now normative in the specification, and §6.1 names the content hash
**Affects:** §6.1, §17.2, §17.3 (new); no change to Skiora's surfaces
**Companion:** [proposal 0037](0037-an-invitation-is-a-client-artifact.md)

> **Found designing the first native client.** Bundles (§6.6) are bytes, and the
> reference CLI moves them as files. People move things through Messages, WhatsApp,
> Signal, Discord, and email, which carry text, wrap it, and strip or mangle anything
> that is not. A bundle pasted into a chat and copied back out must decode to the same
> bytes on any client, or the "verify from any channel" property of §6.6 is a property
> of one client's file format.

---

## Problem

Several artifacts are produced by one member's client to be read by another's, over a
channel neither controls:

| Artifact | Bytes | Specified |
|---|---|---|
| attestation bundle (§6.6) | ~3.5 kB | yes, as bytes |
| invitation (0037) | ~180 B + server | yes, as bytes |
| vouch session id, proposal subject (§5.3, §4.3) | 32 B each, plus the agora id | as values, not as objects |
| an ad-hoc challenge (a chosen message for §6.6) | text | no |
| live-authentication commitment, reveal, pseudonym + proof (§8.1) | 32 B, 64 B, ~400 B | as values |

None has a text form. A text form must survive line wrapping and the occasional smart
quote, carry a checksum so a truncated paste fails loudly rather than as a "not valid"
verdict, and say what kind of artifact it is so a client can route it without guessing.

## Decision

**One armor for every client-to-client artifact:**

```
armor := "nymora1" ‖ base64url_nopad( kind(1) ‖ payload ‖ check(4) )
check  = first 4 bytes of the byte-family hash under "nymora/v0/armor"
         over prefix ‖ kind ‖ payload, each length-framed
```

- **`nymora1`** is the prefix and the version: a future incompatible armor is `nymora2`.
  It is ASCII, case-sensitive, and the only part of the string a human is expected to
  recognise.
- **base64url without padding** (RFC 4648 §5): no `+`, `/`, or `=`, so the string
  survives URL contexts and never ends in a character a chat app might drop.
- **Decoding ignores whitespace** — spaces, line breaks, tabs — anywhere after the
  prefix, because every chat client wraps long text. A decoder also accepts a
  surrounding pair of straight or smart quotes, and nothing else.
- **`kind`** routes the artifact: `0x01` bundle, `0x02` invitation, `0x03` vouch session
  code (`agora_id ‖ session_id`), `0x04` proposal code (`agora_id ‖ subject`), `0x05`
  challenge (a bundle whose content is a challenge phrase — the *same* bytes as `0x01`;
  the kind tells the recipient's client to match it against an outstanding challenge),
  `0x06` live-auth commitment, `0x07` live-auth reveal, `0x08` live-auth pseudonym and
  proof. Unknown kinds are refused, not skipped.
- **`check`** is the byte-family hash the protocol already uses for short digests
  (§8.3's SAS is the same construction under its own domain tag), truncated to four
  bytes: enough to catch truncation and transcription, not a security boundary — the
  artifact inside carries its own proof or is public data.

**The content hash is named with it.** §6.1 writes `message_hash = Hash(M)` and the
reference client chose SHA-256 by itself ("host-defined"). Two clients must agree, or
one verifies the other's bundle as corrupt on honest input. `Hash(M)` is therefore
the byte-family hash under `nymora/v0/content` over the content bytes, framed like
every byte-family input — stated in §6.1 and §17.3. Found by the iOS design review:
phase 1's acceptance test (a phone attests, the CLI verifies) fails without it.

**Files carry the same bytes, unarmored.** A `.nymora` file is `kind ‖ payload ‖ check`
exactly, so a file and an armored string are the same object with and without the
text envelope. Clients may register a file type for it; the type identifier is not
protocol.

**Uniformity is preserved.** Every armored bundle has the same shape and length
distribution as every other, across agoras, because the bundle inside does (§6.5);
the armor adds a constant prefix and a fixed-size trailer and nothing that varies by
agora. The prefix does announce "this is a Nymora artifact", which the bundle's fixed
size already announces to anyone who knows to look; the honest statement is that the
armor makes artifacts *recognisable*, not *attributable*.

## Consequences

- **A bundle is pasteable.** ~3.5 kB of bytes armor to ~4.7 kB of text, within the
  limits of Messages, WhatsApp, Signal, and email; Discord's 2,000-character message
  limit means a bundle goes as a file there, and a client should know that.
- **The reference CLI gains `persora armor` / `persora unarmor`** (or armor flags on
  `attest`, `verify`, `invite`, `join`), and the CLI's verification of a pasted string
  becomes the conformance test for every client's decoder.
- **Challenges need no new proof**: a challenge is a §6.6 bundle over a chosen
  message. The kind byte is what lets the challenger's client match the answer to its
  own outstanding nonce and check the epoch, which is where replay is closed.
- **Nothing here is secret**: an armored invitation is members-only because of the
  fetch key it carries (0037), not because of the armor.

## Open questions

1. ~~Whether `check` should cover the prefix as well~~ — resolved on applying: it does.
2. A word-based rendering (the SAS style) for the short kinds — session and proposal
   codes, challenge phrases — for reading aloud. Presentation; the armor is the
   interchange form.

## Applying this proposal requires

- §17.2 appended to the specification with the grammar, the kind table, and the
  decoding rules.
- `nymora-core`: `armor` encode/decode with the kind enum and the checksum, plus
  conformance vectors — at least one bundle, one invitation, and one truncation
  negative.
- The reference CLI's armor support and the demo passing a bundle through a text
  round trip.
- CHANGELOG "Added".
