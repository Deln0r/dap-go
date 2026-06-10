# dap-go

A Go-language implementation of the IETF [Distributed Aggregation Protocol](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) (DAP), the wire protocol developed by the IETF Privacy-Preserving Measurement (PPM) working group.

[![CI](https://github.com/Deln0r/dap-go/actions/workflows/test.yml/badge.svg)](https://github.com/Deln0r/dap-go/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Deln0r/dap-go.svg)](https://pkg.go.dev/github.com/Deln0r/dap-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/Deln0r/dap-go)](https://goreportcard.com/report/github.com/Deln0r/dap-go)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](go.mod)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--MVP-orange.svg)]()
[![Spec](https://img.shields.io/badge/spec-draft--ietf--ppm--dap--17-7c3aed.svg)](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
[![VDAF vectors](https://img.shields.io/badge/CFRG%20Prio3Count-byte--verified-success.svg)](https://github.com/cfrg/draft-irtf-cfrg-vdaf)

> Pre-MVP. The Prio3 wrapper, the DAP-17 wire codec, the HPKE layer, and a synchronous Helper-role aggregation-init handler are implemented and verified byte-for-byte against the CFRG Prio3Count test vectors. The Leader role, the collection path, multi-round VDAFs, and cross-implementation ping-pong framing are not done yet. Treat the [Status](#status) table as the source of truth.

## What is DAP

DAP carries encrypted measurement reports from clients to two non-colluding Aggregator servers (Leader and Helper) which run a verifiable multi-party computation to produce aggregate results without learning any individual contribution. The underlying primitives are Prio3 ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)) for distributed aggregation and HPKE ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) for report encryption.

Production deployments include Apple Private Cloud Compute, Mozilla Firefox telemetry, Cloudflare measurement infrastructure, and ISRG Divviup. Existing reference implementations are [Janus](https://github.com/divviup/janus) and [libprio-rs](https://github.com/divviup/libprio-rs) (Rust), [Daphne](https://github.com/cloudflare/daphne) (Rust on Cloudflare Workers), and [divviup-ts](https://github.com/divviup/divviup-ts) (TypeScript client).

dap-go targets the same wire format and interop test design so that a Go-based Aggregator or Client can eventually interoperate with those implementations.

## Status

Target spec: [draft-ietf-ppm-dap-17](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/). "Verified" below means a Go round-trip plus a byte-exact check against the CFRG `draft-irtf-cfrg-vdaf-14` Prio3Count test vectors. It does **not** yet mean cross-implementation conformance with Janus or Daphne (see [Conformance](#conformance-and-interop)).

| Component | Status | Notes |
| --- | --- | --- |
| Prio3Count wrapper (`pkg/prio3`) | Verified | Shard / PrepInit / PrepSharesToPrep / PrepNext / Aggregate / Unshard, byte-exact vs 3 CFRG vectors |
| Wire codec (`pkg/dap/wire`) | Verified | DAP-17 §4.1, §4.4, §4.5 types in TLS presentation language; round-trip + negative tests |
| HPKE layer (`internal/hpke`) | Verified | RFC 9180 Seal/Open over cloudflare/circl; tamper / wrong-key / wrong-AAD negatives |
| Helper aggregation-init (`pkg/dap/helper`) | Verified | Synchronous PUT init for Prio3Count with ping-pong framing (vdaf §5.7.1): decrypt, decode framed initialize, combine, commit output share, framed finish response. In-memory store, idempotent replay |
| Helper continuation (POST) | Not started | Returns 501. Single-round VDAFs never reach continuation (DAP-17 §4.5.3); needed for 2-round VDAFs like Poplar1 |
| Prio3Sum / Histogram | Not started | Need the joint-randomness public-share path |
| Leader role | Not started | v1.0 |
| Collection / aggregate-share | Not started | v1.0 |
| Async aggregation, taskprov, durable store | Not started | v1.0 |
| Interop docker image | Not started | v1.0, after ping-pong framing |

## Conformance and interop

The ping-pong message framing of [draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/) §5.7.1 is implemented: the Helper consumes a framed initialize message and answers with a framed finish message, byte-identical envelope across vdaf-14 and vdaf-18. The remaining gaps to a cross-implementation run, all targeted next:

- **VDAF draft contents.** `cloudflare/circl` v1.6.3 implements draft-irtf-cfrg-vdaf-14, whose XOF domain separation embeds the draft version byte. DAP-17/18 reference vdaf-18, so the verifier-share contents (not the envelope) differ between the two. Cross-implementation interop needs a vdaf-18 Prio3.
- **Protocol version targeting.** No Janus build ever spoke dap-17 (their version history goes dap-16 then dap-18). The practical interop peer is Janus main speaking dap-18, so the wire layer and the version-bound HPKE info / VDAF context strings (`"dap-18" || task_id`) retarget to draft-18.
- **Context binding.** The CFRG fixtures use a bare context string, so today's byte-exact checks prove intra-implementation VDAF correctness, not a cross-implementation conformance vector.

A docker-compose cross-run against a pinned Janus build is the next milestone; the published [PPM WG interop test design](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/) and its 2023 runner predate the current drafts, so Janus's in-tree interop binaries serve as the de-facto harness.

## Layout

```
pkg/dap/wire     DAP-17 wire types and TLS-presentation-language codec
pkg/dap/helper   Helper-role aggregator: HTTP handler + in-memory store
pkg/dap          Package doc + cross-layer integration tests
pkg/prio3        Prio3 wrappers over cloudflare/circl/vdaf/prio3
internal/hpke    HPKE wrappers over cloudflare/circl/hpke
testdata/fixtures  CFRG VDAF test vectors
```

Planned binaries `cmd/dap-helper` and `cmd/dap-client` are not built yet.

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl) (BSD-3) for Prio3 and HPKE.
- [golang.org/x/crypto/cryptobyte](https://pkg.go.dev/golang.org/x/crypto/cryptobyte) for TLS-presentation-language encoding (transitive via circl).
- Standard library only beyond that. No CGo.

Version-skew note: `cloudflare/circl/vdaf/prio3` is pinned to draft-irtf-cfrg-vdaf-14. CFRG HEAD is draft-19, and DAP-17 was superseded by draft-18 in May 2026. dap-go pins draft-17 + VDAF-14 for the v0.1 milestone and tracks circl for a later bump.

## Specifications

- [draft-ietf-ppm-dap-17](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
- [draft-irtf-cfrg-vdaf-15](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-15)
- [RFC 9180 HPKE](https://datatracker.ietf.org/doc/rfc9180/)
- [draft-dcook-ppm-dap-interop-test-design-07](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/)

## Contributing

Issues and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Code style and authorship conventions are in [(non-)AGENTS.md](./(non-)AGENTS.md).

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) and Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)). You may use this project under either license. This matches the IETF reference-implementation convention used by `cloudflare/circl`, `divviup/janus`, and `divviup/libprio-rs`.
