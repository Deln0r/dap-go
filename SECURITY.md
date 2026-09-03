# Security Policy

## Reporting a vulnerability

Please do not file public issues for security-sensitive bugs. Use one of:

- GitHub Security Advisories: [Report a vulnerability](https://github.com/Deln0r/dap-go/security/advisories/new).
- Direct email to the maintainer via the address associated with [@Deln0r](https://github.com/Deln0r) on GitHub.

Include a description of the issue, affected versions or commit SHAs, and a reproducer if you have one.

You should expect an initial response within 7 days. If we cannot resolve the issue ourselves, we will coordinate with upstream maintainers of affected dependencies (notably [cloudflare/circl](https://github.com/cloudflare/circl) for HPKE and Prio3 primitives).

## Scope

In scope:

- Protocol-level deviations from [draft-ietf-ppm-dap](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) -18 or -19 that affect privacy or correctness of aggregation.
- Memory safety, panics on adversarial input, denial of service in the Helper or Client.
- Misuse of HPKE keys or nonces, and anything that lets one report be counted more than once or attributed to its sender.
- Side-channel issues introduced in our code (Prio3 timing properties depend on `cloudflare/circl`; bugs there should be reported upstream).

Out of scope:

- **The absence of request authentication.** DAP §3.5 requires it for the two interactions this Helper serves and dap-go implements none of it, deliberately and documented in the README. Reports of "the endpoints are unauthenticated" are already known; reports of a *bypass* of something that is supposed to protect them are not.
- Bugs in `cloudflare/circl` itself (report upstream).
- DoS via legitimate but expensive protocol use that follows the draft.
- Lack of features that are explicitly listed as v1.0 stretch in `README.md`.

## Supported versions

While dap-go is pre-1.0, only the `main` branch is supported.
