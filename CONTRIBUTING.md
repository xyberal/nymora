# Contributing to Nymora

Thank you for looking closely. At this stage — a pre-release design draft on provisional
primitives — the most valuable contribution is **adversarial reading**: a mechanism in
[`spec/`](spec) that fails to deliver what it claims, an argument in a proposal that does
not hold, code that diverges from the specification it cites. Implementation and test
contributions are welcome too; the conventions below keep them landable.

**Security first:** if what you found is exploitable, do not open a public issue or PR.
See [SECURITY.md](SECURITY.md) — reports go through GitHub's private vulnerability
reporting.

## How this project takes changes

Three conventions are load-bearing. They are unusual enough to state up front:

1. **Normative changes start as proposals.** Every change to a normative section of the
   specification is drafted first in [`spec/proposals/`](spec/proposals) — the problem,
   the decision, the alternatives rejected and why. The proposal survives, unedited,
   after the change lands; it is the decision record, and an amended record is not a
   record. If your change touches what the spec *requires*, expect to write (or be asked
   to co-develop) a proposal. Read a few recent ones first — they are the house style.

2. **A mechanism change is one commit touching spec, code, and vectors.** The
   specification, the implementation, and the conformance vectors are three encodings of
   one truth and change together, in the same commit. A PR that changes code but leaves
   the spec describing the old behavior (or vice versa) will be asked to become whole
   before review proceeds.

3. **Section numbers are stable identifiers.** They are cited from source code (`§9.1`,
   `§6.5`). Never renumber a section; append new ones.

## How a pull request lands

`main` is append-only and is produced by pushes from the maintainers' tree of record —
pull requests are reviewed here but are not merged through the GitHub button. An accepted
change is applied to that tree **with your authorship preserved** (`git am`), appears on
`main` in the next push, and your PR is closed with a pointer to the landing commit. Your
name stays on your commit; only the merge mechanics are indirect.

Small consequences: keep PRs focused (one change, whole per rule 2 above), and expect
history on `main` to be linear — no merge commits.

## Before you open a PR

Run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --workspace
cargo test -p nymora-crypto    --no-default-features
cargo test -p nymora-protocol  --no-default-features
cargo test -p nymora-circuits  --no-default-features
cargo test -p nymora-proofs    --no-default-features
cargo test -p nymora-accumulator --no-default-features
./scripts/check-license-headers.sh
```

Conventions the code holds itself to, and reviews will hold yours to:

- **The member build is `no_std`, allocation-free, and sans-io.** Collections and the
  allocator exist only behind the `operator` feature. Networking, time, and randomness
  arrive as parameters or through the ports — never reached for directly.
- **Secrets live in the newtypes** (`nymora-core/src/secret.rs`): zeroized on drop,
  redacted in `Debug`, compared in constant time, exposed only through a greppable
  `expose()`. New secret material joins that discipline; it does not bypass it.
- **The error discipline is load-bearing.** Everything a counterparty is refused for is
  one indistinguishable `ProtocolError::Rejected`; diagnostic reasons exist locally and
  cannot reach a response. Member-side input problems are `Malformed`. Do not add an
  error variant that discloses state.
- **Every derivation gets a domain tag** from the registry in `nymora-core/src/domain.rs`,
  and every field is length-framed. New canonical bytes come with a known-answer test
  computed independently of the code under test.
- **Doc comments cite the spec** (`§N`, proposal numbers) and argue *why*, not *what*.
  Match the density and voice of the file you are editing.

## License

Dual-licensed under Apache-2.0 or MIT, at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
