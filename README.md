# dap-go

A Go-language implementation of the IETF [Distributed Aggregation Protocol](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) (DAP), the wire protocol developed by the IETF Privacy-Preserving Measurement (PPM) working group.

[![CI](https://github.com/Deln0r/dap-go/actions/workflows/test.yml/badge.svg)](https://github.com/Deln0r/dap-go/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Deln0r/dap-go.svg)](https://pkg.go.dev/github.com/Deln0r/dap-go)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8.svg)](go.mod)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-experimental-orange.svg)]()
[![Janus interop](https://img.shields.io/badge/Janus%20interop-Prio3Count%20aggregation-success.svg)]()
[![Spec](https://img.shields.io/badge/spec-dap--18%20and%20dap--19-7c3aed.svg)](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
[![VDAF vectors](https://img.shields.io/badge/CFRG%20Prio3Count-byte--verified-success.svg)](https://github.com/cfrg/draft-irtf-cfrg-vdaf)

> Experimental. The from-scratch Prio3Count VDAF, the wire codec for both published DAP drafts, the HPKE layer, and a Helper-role aggregator are implemented, and the crypto is checked byte for byte against the official CFRG Prio3Count vectors. A Prio3Count smoke against Janus (Janus plays Client, Leader and Collector; dap-go plays Helper) ran end to end against Janus `c1531764` in June 2026, with the aggregate converging to the expected value. Against a current Janus build the aggregation half still works — reports decrypt, verify and are accepted — and the run stops at the aggregate share, which the draft restructured around a collection path this project has not built. That is one VDAF, one job, one batch, against one peer: a smoke, not a conformance suite. Treat the [Status](#status) table as the source of truth.

## What is DAP

DAP carries encrypted measurement reports from clients to two non-colluding Aggregator servers (Leader and Helper) which run a verifiable multi-party computation to produce aggregate results without learning any individual contribution. The underlying primitives are Prio3 ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)) for distributed aggregation and HPKE ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) for report encryption.

Where it runs today, stated only as far as it can be checked: Mozilla ships a DAP **client** in Firefox ([toolkit/components/dap](https://searchfox.org/firefox-main/source/toolkit/components/dap), JavaScript and C++ over a Rust FFI), and ISRG operates [Divvi Up](https://divviup.org/) as a hosted deployment. On the **aggregator** side the field has narrowed rather than grown: Cloudflare [archived Daphne on 3 June 2026](https://github.com/cloudflare/daphne), leaving [Janus](https://github.com/divviup/janus) (Rust, ISRG) as the one open-source aggregator implementation still in active development. The other public codebases are [libprio-rs](https://github.com/divviup/libprio-rs) (Rust, the VDAF library rather than a deployable aggregator) and [divviup-ts](https://github.com/divviup/divviup-ts) (TypeScript client).

Draft status, precisely: DAP is an Internet-Draft of the IETF PPM working group, currently [draft-19](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) in "WG Consensus: Waiting for Write-Up" and not yet an RFC. The Prio3 VDAF it builds on is an IRTF CFRG draft, currently -22, which states that it "is not endorsed by the IETF and has no formal standing in the IETF standards process". Neither is a ratified standard, and this project does not describe them as one.

dap-go targets the same wire format and interop test design, so a Go-based Aggregator or Client can interoperate with those implementations. The Helper has done so for Prio3Count aggregation; the boundaries are in [Conformance](#conformance-and-interop).

## Status

Target spec: [draft-ietf-ppm-dap](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/), both the published -18 and -19, selected per task. "Verified" below means a Go round-trip plus a byte-exact check against the official CFRG `draft-irtf-cfrg-vdaf-18` **Prio3Count** vectors. It does **not** mean cross-implementation conformance: that is bounded in [Conformance](#conformance-and-interop).

| Component | Status | Notes |
| --- | --- | --- |
| Prio3Count VDAF (`pkg/vdaf`) | Verified | From-scratch draft-18 stack (TurboSHAKE128, Goldilocks Field64, XOF, FLP, Prio3Count) byte-exact vs 3 positive + 4 negative CFRG vdaf-18 vectors |
| Wire codec (`pkg/dap/wire`) | Verified | §4.1, §4.2, §4.4, §4.5 types in TLS presentation language; round-trip + negative tests. Three modes via `wire.Variant`: the published draft-18, the published draft-19, and the Janus variant |
| HPKE layer (`internal/hpke`) | Verified | RFC 9180 Seal/Open over cloudflare/circl; tamper / wrong-key / wrong-AAD negatives |
| Helper aggregation-init (`pkg/dap/helper`) | Verified | Prio3Count init with ping-pong framing (vdaf §5.7.1): decrypt, decode framed initialize, combine, commit output share, framed finish response. verification_key_id keyring, aggregation-job + report-extension validation, in-memory store, content-derived idempotency. Handles both the POST-create model of the published drafts and the Janus PUT resource model. A task selects its DAP version, and draft-19's per-report `unknown_verification_key_id` rejection is implemented |
| Report anti-replay (`pkg/dap/helper`) | Verified | A report counts once per task, not once per aggregation job: the store claims report IDs atomically, and a report already claimed by another job is rejected with `report_replayed`. A byte-identical retry of the same job is not a replay. In-memory, so it does not survive a restart, and claims are never released because releasing them would reopen the window |
| Helper aggregate-share (`pkg/dap/helper`) | Smoke only | Single-batch aggregate-share sealed to the Collector, built for the Janus cross-run. The general collection path (multi-batch, batch selectors, query modes) is not done |
| Matrix homeserver integration (`integration/matrix`) | Verified against a live homeserver | Turns a Matrix homeserver into a DAP Client: probes the two unauthenticated endpoints, shards the liveness measurement, and seals one input share to each Aggregator. CI starts a digest-pinned, unmodified [Dendrite](https://github.com/element-hq/dendrite) on pushes to main and on pull requests, and drives a real measurement through to a correct aggregate ([details](#matrix-homeservers-that-can-count-themselves)) |
| Janus cross-run, Prio3Count (`scripts/janus_smoke.sh`) | Green vs `c1531764`; aggregation-only vs current | Janus plays Client + Leader + Collector, dap-go plays Helper. Complete against the pinned June build (aggregate matches). Against current Janus all reports decrypt, verify, and are accepted; the aggregate-share step needs collection-path messages that are not implemented. See [docs/interop.md](docs/interop.md) |
| Helper continuation (POST) | Not started | Returns 501. Single-round VDAFs never reach continuation (DAP-18 §4.5.4); needed for 2-round VDAFs like Poplar1 |
| Prio3Sum / Histogram | Not started | Need the joint-randomness public-share path |
| Leader role | Not started | v1.0 |
| Collection path (general, multi-batch) | Not started | v1.0 |
| Async aggregation, taskprov, durable store | Not started | v1.0 |
| Interop docker image | Not started | v1.0. The Janus smoke drives the Janus interop containers against a host-run Helper; a standalone published dap-go interop image is not built yet |

## Conformance and interop

The Helper speaks one DAP version end to end per task: the from-scratch Prio3Count backend (`pkg/vdaf/prio3`), the version-bound HPKE info and VDAF context strings (`"dap-18" || task_id`, or `"dap-19"`), and the ping-pong message framing of [draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/) §5.7.1 (consume a framed initialize message, answer with a framed finish). The verifier-share contents carry the dap-18 XOF domain separation, not vdaf-14's.

`scripts/janus_smoke.sh` runs a cross-implementation smoke: the Janus interop containers play Client, Leader, and Collector, dap-go plays the Helper, and a Prio3Count aggregation job over a single batch converges to the expected aggregate. The only cross-implementation boundary is Leader to Helper, which is what the smoke validates.

One finding from the cross-run: at the time of the smoke (June 2026) Janus main advertised `DAP_VERSION_IDENTIFIER = "dap-18"` while implementing a wire format that differed from the published draft-18 in five places: a three-field input-share AAD with no task configuration, no verification-key id, a retained partial-batch selector, a PUT resource model, and uint32-length-prefixed aggregation messages. The version identifier alone did not pin the wire format. dap-go handles both through the variant-aware codec (`pkg/dap/wire.Variant`), which now has three modes: the two published drafts and the Janus one.

Janus has since adopted the published draft's **messages**: the initialization request carries `verification_key_id`, aggregation-job extensions replace the partial batch selector, and the input-share AAD is the four-field form. It has not adopted the published **resource model**: jobs are still created with `PUT` to a Leader-chosen URL. So a message format cannot be inferred from the HTTP method, and the Helper tries both AAD shapes and keeps whichever the sender sealed under.

That re-run has been done. On 28 August 2026, against Janus `d5d523d`, all four reports decrypted, verified and were accepted, and the run stopped at the aggregate share, which needs collection-path messages this project does not implement. `VariantJanus` remains a snapshot kept for reproducing the June run; `VariantDraft18` is the path that reaches a current build. Both runs, and the exact divergence table, are recorded in [docs/interop.md](docs/interop.md).

This is a single-VDAF, single-job, single-batch smoke against one peer, not a conformance suite. Full conformance, meaning all Prio3 instances, the Leader role, the general collection path, multiple query modes, and runs against the other implementations, is future work. The published [PPM WG interop test design](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/) and its 2023 runner predate the current drafts, so Janus's in-tree interop binaries serve as the de-facto harness.

## Layout

```
pkg/dap/wire     DAP wire types and TLS-presentation-language codec (draft-18, draft-19, Janus variant)
pkg/dap/helper   Helper-role aggregator: HTTP handler + in-memory store
pkg/dap          Package doc + cross-layer integration tests
pkg/vdaf         From-scratch Prio3Count (vdaf-18): turboshake, field, xof, flp, prio3
internal/hpke    HPKE wrappers over cloudflare/circl/hpke
cmd/dap-helper   Helper binary used by the Janus interop smoke
scripts/janus_smoke.sh  Janus cross-implementation smoke (Prio3Count)
docs/architecture.md  Contributor tour: package map, how a report flows, what is absent
docs/interop.md  Reproduction recipe + wire-format notes for the Janus smoke
testdata/fixtures  CFRG VDAF test vectors (vdaf18)
```

`cmd/dap-helper` is the interop-harness Helper binary the Janus smoke runs. `cmd/dap-client` is not built yet.

## Development

`make check` runs the full pre-commit gate (gofmt, `go vet`, `go test -race`, and golangci-lint); CI runs the same set. The lint config targets golangci-lint v2 (`make lint-install` installs the pinned version). For a quick pass, `go test ./...`.

`make fuzz` runs each wire-codec fuzz target in turn (`FUZZTIME=2m make fuzz` for a longer session). The checked-in seed corpus lives in `pkg/dap/wire/testdata/fuzz` and runs as part of the ordinary test suite; `GEN_CORPUS=1 go test -run TestGenCorpus ./pkg/dap/wire/` regenerates the golden seeds from the current fixtures.

### Running the Janus interop smoke

`scripts/janus_smoke.sh` runs the cross-implementation smoke described under [Conformance](#conformance-and-interop). It needs `docker`, `jq`, `python3`, and the Janus interop images built from [divviup/janus](https://github.com/divviup/janus):

```
# in a divviup/janus checkout, at the pinned commit, default (release) profile
git checkout c1531764d2fc0a05c64b722117004fd516e33a43
docker buildx bake janus_interop_aggregator janus_interop_client janus_interop_collector --load

# back in this repo
scripts/janus_smoke.sh
```

The script starts the Janus Client, Leader, and Collector containers, runs the dap-go Helper on the host, aggregates the Prio3Count measurements `[1, 1, 0, 1]`, and checks that the Collector unshards the expected aggregate, `3`. Build the images with the default release profile: a `dev` cargo profile writes to `target/debug` and breaks the bake.

Pin Janus to that commit: the smoke is verified against it, and Janus `main` has since been migrating toward the published draft-18 under the same `"dap-18"` identifier, so a newer build will not match the variant the smoke registers. [docs/interop.md](docs/interop.md) has the full recipe and the wire-format notes.

## Matrix homeservers that can count themselves

Matrix cannot count itself without asking servers to identify themselves.
Synapse's optional usage report is documented plainly on this point: "while
per-user statistics are not reported, homeserver server names are". An operator
who does not want to name their server to a third party sets `report_stats` to
false and vanishes from the count, so the network's own size is unknown to the
people running it and the privacy-conscious are the ones missing from the data.

That is the shape of problem DAP exists for. `integration/matrix` makes a
homeserver a DAP Client: it measures itself over its own unauthenticated
endpoints, splits the measurement into two shares, and encrypts one to each of
two non-colluding Aggregators. Neither Aggregator can reconstruct a single
server's contribution; only the sum across all reporting servers is revealed.
The server name is not merely left out of the payload, it is never read.

```go
m, _ := (&matrix.Probe{BaseURL: "https://matrix.example.org"}).Measure(ctx)
report, _ := task.Report(rand.Reader, m.Count(), time.Now())
// upload report to the Leader
```

Being Go is what makes this embeddable: [Dendrite](https://github.com/element-hq/dendrite),
the Go Matrix homeserver from Element (New Vector Ltd, United Kingdom), can take
this as a library with no cgo, no second runtime, and no per-platform artifacts.

The claim is checked by execution, not by assertion. On pushes to main and on
pull requests, CI starts an unmodified Dendrite image, pinned by digest so the
run is reproducible, measures it, and drives the report through the dap-go
Helper until the two aggregators' output shares sum to the true count. The
package is a library a Go homeserver can embed; no homeserver embeds it yet, and
the Leader in the test is a harness rather than an implementation. The test
sets `DAP_REQUIRE_LIVE=1`, which makes an unreachable homeserver a failure rather
than a skip, so the job cannot go green without having actually run. Locally:

```sh
scripts/dendrite_up.sh
DAP_REQUIRE_LIVE=1 go test ./integration/matrix/ -run TestLive -v
scripts/dendrite_up.sh down
```

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl) (BSD-3) for HPKE only (RFC 9180). The Prio3 VDAF is hand-written in `pkg/vdaf`, with no crypto dependency. (circl also ships a VDAF Prio3, currently at draft-14 and with no DAP layer; dap-go targets the DAP protocol itself and keeps the VDAF hand-written and dependency-free.)
- [golang.org/x/crypto/cryptobyte](https://pkg.go.dev/golang.org/x/crypto/cryptobyte) for TLS-presentation-language encoding (transitive via circl).
- Standard library only beyond that. No CGo.

Spec targeting: dap-go implements both published drafts, draft-ietf-ppm-dap-18 and draft-ietf-ppm-dap-19, selected per task through `wire.Variant`. Draft-19 is a small delta over -18 by its own change log: it deletes three unused `ReportError` variants and adds `unknown_verification_key_id` (#786, #784), relaxes `task_info` to allow an empty value, and moves the version tag that prefixes every domain-separation string from `dap-18` to `dap-19`. It also references draft-irtf-cfrg-vdaf-20, whose `VERSION` constant is still 18, so the Prio3 crypto and the checked-in CFRG test vectors are unchanged and stay authoritative for both. Both versions ship because the only DAP peer to interoperate with, Janus, still advertises `dap-18`.

## Security posture

This code has not been audited. It is an experimental implementation, and the
paragraphs below describe what has and has not been done, so that anyone
evaluating it can judge the risk themselves.

### There is no request authentication

Start here, because it is the largest gap and it is not a side channel. DAP §3.5
makes request authentication REQUIRED for exactly the two interactions this
Helper serves: a Leader initializing or continuing an aggregation job (§4.5), and
a Leader obtaining an aggregate share (§4.6.4). dap-go implements neither. The
spec leaves the scheme open — OAuth2 bearer credentials, TLS client
certificates, or RFC 9421 HTTP message signatures are all named as acceptable —
and this implementation has none of them.

Concretely: anyone who can reach the port can create aggregation jobs and can
trigger an aggregate-share response. The aggregate share is sealed to the
Collector's HPKE key, so a stranger cannot read it, and reports still have to
carry valid VDAF proofs and open under the task's HPKE key, so a stranger cannot
inject arbitrary measurements without those. What is missing is the check on
*who is allowed to ask at all*, and no amount of measurement validation supplies
it: the proof establishes that a measurement is well formed, not that its sender
is entitled to submit it.

Deploy this behind something that does the authentication, or do not expose it.
The interop harness binary in `cmd/dap-helper` is a test server and says so.

### Side channels

The Field64 arithmetic in `pkg/vdaf/field` is written to avoid operand-dependent
branching: `Add`, `Sub`, `Neg`, and `Mul` use branchless reductions over
`math/bits`, and `Inv` is a fixed square-and-multiply chain over the constant
exponent `p-2`, so its running time does not depend on the value being inverted.
That is a deliberate posture, not a proof: there is no formal verification, no
fiat-crypto-derived code, and no measurement of what the Go compiler emits on any
particular architecture. Correctness is established against `math/big` in the
package tests and against the official CFRG vectors at the Prio3 layer.

Two known places are not constant time by construction. Sampling field elements
from the XOF (`pkg/vdaf/xof`) uses rejection sampling, so the number of
iterations depends on the bytes drawn, as specified by draft-irtf-cfrg-vdaf.
Proof verification rejects at the first failing proof rather than evaluating all
of them.

HPKE is delegated to `cloudflare/circl`, so its side-channel properties are
whatever that library provides; they are not re-established here.

Constant-time hardening, a review of the compiled output, and an external audit
are future work. Until then, treat the timing behaviour of this implementation as
unverified.

## Specifications

- [draft-ietf-ppm-dap-18](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
- [draft-irtf-cfrg-vdaf-18](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf)
- [RFC 9180 HPKE](https://datatracker.ietf.org/doc/rfc9180/)
- [draft-dcook-ppm-dap-interop-test-design-07](https://datatracker.ietf.org/doc/draft-dcook-ppm-dap-interop-test-design/)

## Contributing

[docs/architecture.md](docs/architecture.md) is the tour for someone about to change the code: the package map, how one report flows through it, why the wire codec has two modes, and what is deliberately not built yet.

Issues and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Code style and authorship conventions are in [(non-)AGENTS.md](./(non-)AGENTS.md).

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) and Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)). You may use this project under either license. This matches the IETF reference-implementation convention used by `cloudflare/circl`, `divviup/janus`, and `divviup/libprio-rs`.
