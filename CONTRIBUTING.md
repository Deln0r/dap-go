# Contributing to dap-go

Thanks for your interest. This document explains how to contribute.

## Before you start

Read [(non-)AGENTS.md](./(non-)AGENTS.md). It documents the project's authorship and tooling policy. Cryptographic and protocol code is hand-written; commits and PRs follow the same rule.

## Developer Certificate of Origin (DCO)

All commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). This is not a CLA. It is a per-commit attestation that you have the right to contribute the code under the project's license.

Add `Signed-off-by: Your Name <your.email@example.com>` to each commit:

```bash
git commit -s -m "your message"
```

The `-s` flag adds the trailer automatically using your `git config user.name` and `user.email`.

## Code style

- Follow standard Go conventions (`gofmt`, `golangci-lint`).
- Keep public APIs minimal. Prefer adding methods over exposing fields.
- Document exported types and functions with `// PackagePrefix ...` comments.
- Tests required for any non-trivial change. Crypto-touching code requires test vectors.

## Wire format compatibility

Binary protocol compatibility with [draft-ietf-ppm-dap](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/), both the published -18 and -19, is non-negotiable. Any change that breaks the Janus cross-run is a regression even if every Go test passes. Janus is the peer to check against: Cloudflare archived Daphne in June 2026, and the published interop test design predates the current drafts, so Janus's in-tree interop binaries are the de-facto harness.

If your change touches encoding paths:
1. Add or extend a fixture under `testdata/fixtures/` from the CFRG VDAF test vector set or the DAP draft appendix.
2. Verify round-trip in Go.
3. Document any divergence (there should not be any).

## Development

The module requires **Go 1.26** or newer, and CI runs 1.26 and 1.27. `golang.org/x/crypto` v0.56 and later require it, and Go 1.25 left upstream support when 1.27 shipped.

```bash
make check   # gofmt check, go vet, go test -race with coverage, golangci-lint
make fuzz    # the wire fuzz targets against the checked-in seed corpus
```

Two things are not in `make check` because they need Docker.

The Matrix integration test runs against a real Dendrite homeserver, pinned by image digest:

```bash
scripts/dendrite_up.sh
DAP_REQUIRE_LIVE=1 go test ./integration/matrix/ -run TestLive -v
scripts/dendrite_up.sh down
```

`DAP_REQUIRE_LIVE=1` turns an unreachable homeserver into a failure instead of a skip, which is what CI sets. Without it the test skips, so a local run that prints nothing has told you nothing.

The Janus cross-implementation smoke needs Janus interop images built locally; `scripts/janus_smoke.sh` and [docs/interop.md](docs/interop.md) have the recipe and what to expect from it.

## Filing issues

- Search existing issues first.
- Include a reproducer when reporting protocol divergence (JS or Rust reference snippet welcome).
- Include Go version, dap-go version (commit SHA or tag), and OS.

## Pull requests

- One logical change per PR.
- Reference any related issue.
- Run `make check` before submitting, and `make fuzz` if you touched a decoder.
- Be patient with review (best-effort, response within 14 days).

## Communication

- GitHub Discussions for design questions and Q&A.
- GitHub Issues for bugs and concrete proposals.
- The PPM working group mailing list (`ppm@ietf.org`) for protocol-level questions.
- Mention `@Deln0r` for maintainer attention.

## License

By contributing, you agree that your contributions will be dual-licensed under the MIT License and the Apache License 2.0 (see [LICENSE](LICENSE)).
