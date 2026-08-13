# Security Policy

## Status, stated plainly

Nymora is a **pre-release design draft** (protocol version `0.0.0`). It has had **no
independent security audit**. The implementation runs on a stub prover and a provisional
signature: nothing is zero-knowledge yet, and nothing here is deployable. **Do not use
this to protect anyone.** The threat model this project is written against involves
people whose safety depends on the guarantees holding — until the real circuit lands and
independent review has happened, those guarantees exist on paper only.

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
  conformance vector that pins the wrong bytes, a statement clause the stub prover
  checks weakly.
- **Ordinary code vulnerabilities** — memory-hygiene failures around secret material,
  timing side channels in comparisons the code promises are constant-time, panics
  reachable from untrusted input.

What is **out of scope**: the known, documented limitations in
[`spec/threat-model.md`](spec/threat-model.md) §15 (they are named there precisely so no
one has to rediscover them), and the provisional primitives being provisional — the stub
prover proving nothing is the loudly documented status, not a finding.

There is no bug bounty. What you will get is a prompt, serious reading, credit if you
want it, and — where the finding is real — a proposal in [`spec/proposals/`](spec/proposals)
recording what was wrong and how it was fixed, which is this project's permanent form of
acknowledgement.

## Supported versions

There are no supported versions yet. When releases exist, this section will say which
receive fixes.
