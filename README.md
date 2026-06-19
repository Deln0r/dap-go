# dap-go

A Go-language implementation of the IETF [Distributed Aggregation Protocol](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) (DAP), the wire protocol developed by the IETF Privacy-Preserving Measurement (PPM) working group.

[![CI](https://github.com/Deln0r/dap-go/actions/workflows/test.yml/badge.svg)](https://github.com/Deln0r/dap-go/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Deln0r/dap-go.svg)](https://pkg.go.dev/github.com/Deln0r/dap-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/Deln0r/dap-go)](https://goreportcard.com/report/github.com/Deln0r/dap-go)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](go.mod)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--MVP-orange.svg)]()
[![Spec](https://img.shields.io/badge/spec-draft--ietf--ppm--dap--18-7c3aed.svg)](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
[![VDAF vectors](https://img.shields.io/badge/CFRG%20Prio3Count-byte--verified-success.svg)](https://github.com/cfrg/draft-irtf-cfrg-vdaf)

> Pre-MVP. The from-scratch Prio3 VDAF (draft-18), the DAP-18 wire codec, the HPKE layer, and a synchronous Helper-role aggregation-init handler are implemented and verified byte-for-byte against the official CFRG Prio3Count test vectors. The Leader role, the collection path, and the other Prio3 instances are not done yet, and a cross-implementation run against Janus is still pending. Treat the [Status](#status) table as the source of truth.

## What is DAP

DAP carries encrypted measurement reports from clients to two non-colluding Aggregator servers (Leader and Helper) which run a verifiable multi-party computation to produce aggregate results without learning any individual contribution. The underlying primitives are Prio3 ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)) for distributed aggregation and HPKE ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) for report encryption.

Production deployments include Apple Private Cloud Compute, Mozilla Firefox telemetry, Cloudflare measurement infrastructure, and ISRG Divviup. Existing reference implementations are [Janus](https://github.com/divviup/janus) and [libprio-rs](https://github.com/divviup/libprio-rs) (Rust), [Daphne](https://github.com/cloudflare/daphne) (Rust on Cloudflare Workers), and [divviup-ts](https://github.com/divviup/divviup-ts) (TypeScript client).

dap-go targets the same wire format and interop test design so that a Go-based Aggregator or Client can eventually interoperate with those implementations.

## Status

Target spec: [draft-ietf-ppm-dap-18](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/). "Verified" below means a Go round-trip plus a byte-exact check against the official CFRG `draft-irtf-cfrg-vdaf-18` Prio3Count test vectors. It does **not** yet mean cross-implementation conformance with Janus or Daphne (see [Conformance](#conformance-and-interop)).

| Component | Status | Notes |
| --- | --- | --- |
| Prio3Count VDAF (`pkg/vdaf`) | Verified | From-scratch draft-18 stack (TurboSHAKE128, Goldilocks Field64, XOF, FLP, Prio3Count) byte-exact vs 3 positive + 4 negative CFRG vdaf-18 vectors |
| Wire codec (`pkg/dap/wire`) | Verified | DAP-18 §4.1, §4.2, §4.4, §4.5 types in TLS presentation language; round-trip + negative tests |
| HPKE layer (`internal/hpke`) | Verified | RFC 9180 Seal/Open over cloudflare/circl; tamper / wrong-key / wrong-AAD negatives |
| Helper aggregation-init (`pkg/dap/helper`) | Verified | Synchronous POST-create init for Prio3Count with ping-pong framing (vdaf §5.7.1): decrypt, decode framed initialize, combine, commit output share, framed finish response. verification_key_id keyring, aggregation-job + report-extension validation, in-memory store, content-derived idempotency |
| Helper continuation (POST) | Not started | Returns 501. Single-round VDAFs never reach continuation (DAP-18 §4.5.4); needed for 2-round VDAFs like Poplar1 |
| Prio3Sum / Histogram | Not started | Need the joint-randomness public-share path |
| Leader role | Not started | v1.0 |
| Collection / aggregate-share | Not started | v1.0 |
| Async aggregation, taskprov, durable store | Not started | v1.0 |
| Interop docker image | Not started | v1.0, after ping-pong framing |

## Conformance and interop

The Helper now speaks dap-18 end to end: the from-scratch draft-18 Prio3 backend (`pkg/vdaf/prio3`), the version-bound HPKE info and VDAF context strings (`"dap-18" || task_id`), and the ping-pong message framing of [draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/) §5.7.1 (consume a framed initialize message, answer with a framed finish). The verifier-share contents now carry the dap-18 XOF domain separation, not vdaf-14's. The remaining gap to a cross-implementation run:

- **A live Janus cross-run.** No Janus build ever spoke dap-17 (their version history goes dap-16 then dap-18), so the practical interop peer is Janus main speaking dap-18. The byte-exact checks here use the CFRG fixtures' bare context string, which proves intra-implementation VDAF correctness; a run against Janus proves cross-implementation conformance.

A docker-compose cross-run against a pinned Janus build is the next milestone; the published [PPM WG interop test design](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/) and its 2023 runner predate the current drafts, so Janus's in-tree interop binaries serve as the de-facto harness.

## Layout

```
pkg/dap/wire     DAP-18 wire types and TLS-presentation-language codec
pkg/dap/helper   Helper-role aggregator: HTTP handler + in-memory store
pkg/dap          Package doc + cross-layer integration tests
pkg/vdaf         From-scratch draft-18 Prio3: turboshake, field, xof, flp, prio3
internal/hpke    HPKE wrappers over cloudflare/circl/hpke
testdata/fixtures  CFRG VDAF test vectors (vdaf18)
```

Planned binaries `cmd/dap-helper` and `cmd/dap-client` are not built yet.

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl) (BSD-3) for HPKE only (RFC 9180). The Prio3 VDAF is hand-written in `pkg/vdaf`, with no crypto dependency.
- [golang.org/x/crypto/cryptobyte](https://pkg.go.dev/golang.org/x/crypto/cryptobyte) for TLS-presentation-language encoding (transitive via circl).
- Standard library only beyond that. No CGo.

Spec targeting: dap-go implements draft-ietf-ppm-dap-18 and the draft-irtf-cfrg-vdaf-18 Prio3Count it references. The VERSION byte is unchanged on the vdaf-19 tag, so the implementation remains valid for draft-19.

## Specifications

- [draft-ietf-ppm-dap-18](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
- [draft-irtf-cfrg-vdaf-18](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf)
- [RFC 9180 HPKE](https://datatracker.ietf.org/doc/rfc9180/)
- [draft-dcook-ppm-dap-interop-test-design-07](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/)

## Contributing

Issues and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Code style and authorship conventions are in [(non-)AGENTS.md](./(non-)AGENTS.md).

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) and Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)). You may use this project under either license. This matches the IETF reference-implementation convention used by `cloudflare/circl`, `divviup/janus`, and `divviup/libprio-rs`.
