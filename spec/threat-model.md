# Nymora — Purpose, Threat Model, and Known Limitations

**Status:** Design draft

This document holds the two framing sections of the Nymora specification: **§1**, which
states the purpose and the adversary model, and **§15**, which names — rather than hides —
everything the design does *not* solve.

The mechanisms themselves (§2–§14) are specified in
**[nymora-protocol.md](nymora-protocol.md)**.

> **Section numbers are stable identifiers** and are cited from source code. §1 and §15
> keep their original numbers here. Never renumber.

---

## 1. Purpose and Threat Model

Nymora lets a group of people organize, admit new members, and publish content such that:

- Membership is **anonymous** — no one, including the system's own operator, holds a mapping from real identity to credential.
- Membership is **authentic** — every action (vouching, publishing, policy change) is provably tied to *some* valid, currently-unrevoked member, without revealing *which* one.
- Content is **attributable to the group**, not to a traceable individual, while still allowing members internally to build trust in a recurring (but unlinkable-to-outsiders) source.
- The system can be **provably and irreversibly dissolved**, and can **revoke** a compromised member's standing without exposing anyone's identity in the process.

Nymora is designed against a spectrum of adversaries, from local law enforcement with subpoena power up to a resourced national security apparatus with network surveillance and infiltration capability. The relevant adversary capabilities the design accounts for include: legal compulsion of any operator; network-level surveillance and traffic correlation; infiltration by a genuinely-admitted member; device seizure and forensic extraction; and coercion of a member who is physically present with their device.

The design's guarantees scale with group size in one important respect: membership anonymity depends on the real membership pool being large enough that no single observer already knows who is in it. For very small groups, mutual knowledge of who belongs is a fact that exists outside the system, and Nymora's value there is authenticity, provable dissolution, and anonymity-preserving revocation — not membership anonymity, which no protocol can manufacture at that scale (see §15).

A foundational premise of this design, restated throughout: **cryptography protects what the system discloses. It cannot protect what already exists in the world independent of the system** — pre-existing social relationships, vetting quality, or an infiltrator who is genuinely, correctly admitted through legitimate process. Nymora's job is to make sure the system itself never becomes the leak.


---

## 15. Known Limitations — What This Design Does Not Solve

**Small-group inference floor (mathematically unfixable).** In agoras of roughly 3–10 people, members already possess complete or near-complete mutual knowledge of who else is present, independent of anything the system discloses. No protocol-level mechanism changes this, including padding an accumulator with decoy entries (§5.4). Real protection at this scale comes only from growing past small-number territory before undertaking sensitive vouching decisions, or from accepting the reduced guarantee honestly.

**Vetting quality is outside cryptographic reach.** The system attests only to "a credential satisfying stated rules participated" — never to whether the human behind that credential exercises sound judgment or harbors bad intent. A patient, genuinely well-vetted infiltrator produces proofs indistinguishable from any legitimate member's. This is a structural ceiling, not an implementation gap: the system formalizes an admission decision, it never makes one.

**Social and behavioral leakage.** Who recruits whom, response-timing patterns, visible authority asymmetry within the group, and founders' pre-existing real-world familiarity with each other are facts that exist entirely outside the system and are untouched by any mechanism described here. Mitigation is procedural (rotating recruitment/vetting duties, avoiding consistent behavioral tells), not technical.

**Network and device-level metadata is out of scope.** This design protects message content and cryptographic linkage. It says nothing about IP addresses, request timing at the network layer, or device compromise. Network-layer anonymity (Tor or equivalent) and device hardening (e.g., GrapheneOS) remain necessary complements this design assumes but does not provide.

**Operator dependency is real, given online-only verification.** Since roots, tag keys, and (optionally) proofs are member-gated and held by Skiora, its continued, honest cooperation matters for both live use and historical verification. A compelled or compromised Skiora deployment can observe query patterns (who checks what, when) even without learning content or identity — a narrower but non-zero metadata surface compared to a fully offline design.

**Shared-secret material carries broader blast radius than individual credentials.** A leaked tag epoch key (`K_tag_e`) lets whoever holds it test arbitrary content for agora affiliation — narrower than full deanonymization, but broader than any single compromised personal credential, since it is shared infrastructure rather than a per-person secret.

**Offline in-person verification trades revocation freshness for connectivity independence.** In-person authentication (§8.3) is designed to work from pre-cached roots with no live network dependency during the meeting itself — a deliberate choice, since it avoids generating correlatable network traffic at the moment it matters most. The cost is that revocation status can only be as current as each participant's last sync; a member revoked shortly before an in-person gathering will not be caught unless someone has synced since. Groups relying on in-person authentication should treat it as confirming validity "as of last sync," not "at this instant," and weigh that against the stronger, live-checked guarantee available when network authentication (§8.1) is possible.

**Live authentication inherits the underlying channel's security, it doesn't replace it.** The mutual authentication protocol in §8 proves membership and live possession of a credential, but its resistance to relay/person-in-the-middle attacks depends entirely on `channel_metadata` incorporating genuine, unforgeable session material from the secure channel it rides on (e.g., an authenticated key exchange). If the underlying channel itself is relayable, deriving pseudonyms on top of it does not independently fix that — this mechanism narrows *who can convincingly claim membership*, it does not harden the transport it runs over.

**Hardware-backed root key custody raises the bar against remote compromise but is not absolute, and does nothing against coercion.** Secure enclaves and hardware authenticators (§9.2) close the most common real-world extraction path — malware or forensic tooling silently reading a key out of accessible storage — but a sufficiently resourced adversary with specialized hardware-attack capability can, in principle, still defeat some secure elements. More importantly, hardware custody provides no protection at all against a present, compelled legitimate user: if an adversary controls both the device and its owner, the hardware will perform whatever signing operation is requested, since a user-presence check is exactly what coercion satisfies.

**Device migration without a reachable prior device costs reputation continuity.** Because `sk_root` is generated inside non-exportable hardware (§9.2), a lost, stolen, or seized device with no opportunity to sign a migration certificate forces fall-back to full re-vouching (§9.3, Path 2) — the resulting credential is cryptographically new, with tenure and vouch history not preserved. This is an accepted cost of eliminating key extractability, not an oversight, but it means the group should expect and plan for a real, non-trivial disruption whenever a device is lost under circumstances that prevent an orderly migration.

**Auditability catches misbehavior; it does not prevent valid-but-unwanted actions.** The integrity layer (§10) makes a rogue operator's state-tampering publicly detectable and a rogue client's action history complete and non-repudiable, but a compromised client holding a valid key can still take a legitimately-formed action its user never intended (a malicious vouch, malicious content). That action is faithfully recorded rather than blocked. Prevention of such actions rests on hardware-bound authorization (§9.2) and server-side structural enforcement (§5.3); the audit layer's role is to ensure the action cannot afterward be hidden, denied, or misrepresented, feeding timely revocation (§11).

**The transparency log's guarantees are conditional on independent replication and gossip.** A per-agora transparency log (§10.1) only detects a rogue Skiora if the log is operated or replicated independently of Skiora and if independent auditors compare their views. A log Skiora alone hosts, or one no one gossips about, provides no protection. The log also partially conflicts with existence-hiding (§3), which is why it is opt-in per agora and why existence-sensitive agoras may decline it or use pooled, unlabeled roots at the cost of per-agora audit granularity.

**Founding asymmetry is irreducible.** Some credential in every agora's history necessarily has zero prior attestations preceding it. Ordering and timestamp exposure have been closed at the API level (§5.1–5.2), but the underlying mathematical fact cannot be eliminated — only kept from being queryable through any interface the system exposes.

**Net position:** Nymora is designed so that the system itself never discloses more than the minimum necessary for its stated functions; every leak identified above is either closed at the protocol/API level or explicitly acknowledged as residual and named rather than hidden. It cannot manufacture anonymity where none exists in the real world, and it cannot substitute for the human judgment that vetting, timely revocation, and operational discipline still require.
