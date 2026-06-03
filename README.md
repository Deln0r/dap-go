# dap-go

A Go-language implementation of the IETF [Distributed Aggregation Protocol](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) (DAP), the wire protocol developed by the IETF Privacy-Preserving Measurement (PPM) working group.

Status: pre-MVP. Public scope and skeleton; no working code yet.

## What is DAP

DAP carries encrypted measurement reports from clients to two non-colluding Aggregator servers (Leader and Helper) which run a verifiable multi-party computation to produce aggregate results without learning any individual contribution. Underlying primitives are Prio3 ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)) for distributed aggregation and HPKE ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) for report encryption.

Production deployments include Apple Private Cloud Compute, Mozilla Firefox telemetry, Cloudflare measurement infrastructure, and ISRG Divviup. Existing reference implementations are [Janus](https://github.com/divviup/janus) and [libprio-rs](https://github.com/divviup/libprio-rs) (Rust), [Daphne](https://github.com/cloudflare/daphne) (Rust on Cloudflare Workers), and [divviup-ts](https://github.com/divviup/divviup-ts) (TypeScript client).

dap-go targets the same wire format and interop test design so that a Go-based Aggregator or Client can interoperate with those implementations.

## Scope

Target spec: [draft-ietf-ppm-dap-17](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/).

MVP (v0.1):

- Prio3Count, Prio3Sum, Prio3Histogram aggregators, wrapping [`cloudflare/circl/vdaf/prio3`](https://pkg.go.dev/github.com/cloudflare/circl/vdaf/prio3).
- DAP wire types: `Report`, `HpkeCiphertext`, `PlaintextInputShare`, `AggregationJob*`, `PrepareInit`, `PrepareContinue`, `BatchSelector`, `CollectionJob`.
- HPKE encryption via [`cloudflare/circl/hpke`](https://pkg.go.dev/github.com/cloudflare/circl/hpke).
- Helper role HTTP handler.
- Submitter Client library.
- Interop image compatible with [draft-dcook-ppm-dap-interop-test-design-07](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/).

v1.0 stretch:

- Leader role.
- Collection job lifecycle.
- Time-interval and fixed-size queries.
- TaskProv.
- Postgres state store.

Non-goals:

- No CGo. All crypto comes from pure-Go libraries.
- No Aggregator multi-tenancy outside TaskProv.
- No exotic VDAF beyond Prio3.

## Layout

```
cmd/dap-helper   Helper-role server binary
cmd/dap-client   Submitter Client binary
pkg/dap          Protocol types and state machine
pkg/dap/wire     Wire codec (encode/decode)
pkg/prio3        Prio3 wrappers over cloudflare/circl
internal/hpke    HPKE wrappers over cloudflare/circl
testdata/fixtures  CFRG and IETF test vectors
```

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl) (BSD-3) for Prio3 and HPKE.
- [fxamacker/cbor/v2](https://github.com/fxamacker/cbor/v2) (MIT) for CBOR encoding.
- Standard library only beyond that.

Version skew note: `cloudflare/circl/vdaf/prio3` is pinned to draft-irtf-cfrg-vdaf-14 as of writing. CFRG HEAD is draft-19. dap-go pins v14 for the v0.1 milestone and tracks circl for a v17/v19 bump.

## Specifications

- [draft-ietf-ppm-dap-17](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
- [draft-irtf-cfrg-vdaf-15](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-15)
- [RFC 9180 HPKE](https://datatracker.ietf.org/doc/rfc9180/)
- [draft-dcook-ppm-dap-interop-test-design-07](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/)

## Contributing

Issues and pull requests welcome once the v0.1 wire codec lands. See [CONTRIBUTING.md](CONTRIBUTING.md). Code style and authorship conventions are in [(non-)AGENTS.md](./(non-)AGENTS.md).

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) and Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)). You may use this project under either license. This matches the IETF reference-implementation convention used by `cloudflare/circl`, `divviup/janus`, and `divviup/libprio-rs`.
