# Security Policy

## Status, stated plainly

Nymora is a **pre-release design draft** (protocol version `0.0.0`). It has had **no
independent security audit** — and neither has the third-party proving stack the real
circuits build on. The primitives are real (the pinned Poseidon instance, the §9.1
certificate scheme, the gap-tree exclusion sets) and both statements prove in zero
knowledge behind the `ProofSystem` boundary, but nothing here is deployable. **Do not
use this to protect anyone.** The threat model this project is written against involves
people whose safety depends on the guarantees holding — until independent review has
happened, those guarantees exist on paper and in this repository's own tests only.

## Reporting a vulnerability

Please report vulnerabilities **privately**, through GitHub's private vulnerability
reporting on this repository (*Security → Report a vulnerability*). Do not open a public
issue for anything you believe is exploitable.

Reports are welcome at every layer, and the design layers count as much as the code:

- **Specification-level attacks** — a mechanism in [`spec/`](spec) that fails to deliver
  a guarantee it claims, a leak through an interface the spec defines, an argument in a
  proposal that does not hold. These are the most valuable reports this project can
  receive.
- **Implementation divergence** — code that does not do what the specification says, a
  conformance vector that pins the wrong bytes, a statement clause the circuits or the
  stub evaluator check weakly, a divergence between the workspace primitives and the
  circuits' own that the parity suite fails to catch.
- **Ordinary code vulnerabilities** — memory-hygiene failures around secret material,
  timing side channels in comparisons the code promises are constant-time, panics
  reachable from untrusted input.

What is **out of scope**: the known, documented limitations in
[`spec/threat-model.md`](spec/threat-model.md) §15 (they are named there precisely so no
one has to rediscover them), and the stub prover proving nothing in zero knowledge —
it is the loudly documented test backend, not a finding.

There is no bug bounty. What you will get is a prompt, serious reading, credit if you
want it, and — where the finding is real — a proposal in [`spec/proposals/`](spec/proposals)
recording what was wrong and how it was fixed, which is this project's permanent form of
acknowledgement.

## Supported versions

There are no supported versions yet. When releases exist, this section will say which
receive fixes.
