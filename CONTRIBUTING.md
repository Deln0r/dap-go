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

Binary protocol compatibility with [draft-ietf-ppm-dap-18](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) is non-negotiable. Any change that breaks interop with Janus, Daphne, or divviup-ts on the official interop docker harness is a regression even if all Go tests pass.

If your change touches encoding paths:
1. Add or extend a fixture under `testdata/fixtures/` from the CFRG VDAF test vector set or the DAP draft appendix.
2. Verify round-trip in Go.
3. Document any divergence (there should not be any).

## Filing issues

- Search existing issues first.
- Include a reproducer when reporting protocol divergence (JS or Rust reference snippet welcome).
- Include Go version, dap-go version (commit SHA or tag), and OS.

## Pull requests

- One logical change per PR.
- Reference any related issue.
- Run `go test ./... -race` and `golangci-lint run` before submitting.
- Be patient with review (best-effort, response within 14 days).

## Communication

- GitHub Discussions for design questions and Q&A.
- GitHub Issues for bugs and concrete proposals.
- The PPM working group mailing list (`ppm@ietf.org`) for protocol-level questions.
- Mention `@Deln0r` for maintainer attention.

## License

By contributing, you agree that your contributions will be dual-licensed under the MIT License and the Apache License 2.0 (see [LICENSE](LICENSE)).
