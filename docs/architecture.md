# Architecture

A tour of the codebase for someone about to change it. The [README](../README.md)
says what dap-go is and what state it is in; this file says where things live and
why the boundaries fall where they do.

## The shape of the protocol

DAP exists to answer a question without collecting the data that would answer it
directly. A Client splits one measurement into shares and sends one to each of
two non-colluding Aggregators, the Leader and the Helper. Neither share reveals
anything on its own. The Aggregators run a verifiable computation over their
shares, prove to each other that the measurement was well-formed without seeing
it, and eventually hand a Collector two aggregate shares that only combine into
the answer.

Two layers do the work, and dap-go keeps them apart:

- **VDAF** (`pkg/vdaf`) is the cryptography: how a measurement becomes shares,
  how an Aggregator verifies a share it cannot read, how shares aggregate. It
  knows nothing about HTTP or DAP messages.
- **DAP** (`pkg/dap`) is the protocol around it: message encodings, HTTP
  resources, task configuration, encryption of shares in transit.

## Package map

```
pkg/vdaf/field        206 LOC   Field64 arithmetic (the prime 2^64 - 2^32 + 1)
pkg/vdaf/xof          138 LOC   XofTurboShake128: seeds -> pseudorandom field elements
pkg/vdaf/flp          550 LOC   the fully-linear proof system: circuits, gadgets, NTT
pkg/vdaf/prio3        326 LOC   Prio3Count on top of the above: shard, verify, aggregate
internal/turboshake   200 LOC   TurboSHAKE128 (RFC 9861), the only hash primitive
internal/hpke         158 LOC   RFC 9180 seal/open, wrapping cloudflare/circl
pkg/dap/wire         1644 LOC   every DAP message, encode and decode, draft-18 and -19
pkg/dap/helper        992 LOC   the Helper role: HTTP handler, task store, aggregation
integration/matrix    338 LOC   the Client role for a Matrix homeserver measuring itself
cmd/dap-helper        246 LOC   interop harness binary (not a production server)
```

The dependency direction is strictly downward: `wire` does not import `vdaf`,
`vdaf` does not import `wire`, and `helper` is the only place that knows both.
That is deliberate. It means the codec can be fuzzed and golden-tested with no
crypto in the picture, and the crypto can be checked against the CFRG test
vectors with no protocol in the picture.

`integration/matrix` sits above all of it and imports `wire`, `vdaf/prio3` and
`internal/hpke` but never `helper`: it is the other end of the protocol. It is
the only package in the tree that talks to a network peer that is not a DAP
party, which is why it is the only one whose tests need something running.

## The Client end, and why it is a Matrix homeserver

The rest of this tree is the Helper role, which is one aggregator among two.
`integration/matrix` is the opposite end: the party that has a measurement and
wants it counted without being identified.

Matrix is the case that makes the point concrete, because the ecosystem has
already written down the problem. Synapse's usage-report documentation says that
"while per-user statistics are not reported, homeserver server names are", so an
operator who does not want to be named opts out and disappears from the count.
The network's size is therefore unknown to the people running it, and the
servers missing from the data are exactly the privacy-conscious ones. Splitting
the measurement across two non-colluding aggregators removes the trade-off.

The package is deliberately small. `Probe` reads two unauthenticated endpoints
and returns two booleans; `Task.Report` shards the resulting 0 or 1 and seals one
input share to each aggregator. Everything else a homeserver could report is
either identifying or needs a privacy budget of its own, and neither belongs in a
first integration.

Its tests split along a line worth copying elsewhere. The stand-in-homeserver
tests can only check parsing, because a stand-in agrees with whatever the code
expects; they say so in a comment at the top of the file. The endpoint contract
is checked by `TestLive_DendriteToAggregate` against an unmodified Dendrite,
which CI starts on every push. `DAP_REQUIRE_LIVE=1` turns an unreachable
homeserver into a failure rather than a skip, so that job cannot pass without
having run.

## Following one report through the code

A report arrives at the Helper inside an aggregation job. Reading
`pkg/dap/helper/handler.go` and then `helper.go` top to bottom follows the same
path:

1. **Route** (`handler.go`, `ServeHTTP`). The URL decides everything: a POST to
   `/tasks/{id}/aggregation_jobs` creates a job, a PUT to a job resource is the
   older Janus-shaped init, GET polls, DELETE cleans up. Anything unrecognised
   becomes an RFC 9457 problem document, never a bare status code.
2. **Decode** (`pkg/dap/wire`). The body is an `AggregationJobInitReq` carrying
   one `VerifyInit` per report. Decoding is total: malformed input returns
   `ErrMalformed` or `ErrTrailingData` and never panics, which the fuzz targets
   in `wire/fuzz_test.go` exist to keep true.
3. **Validate** (`handler.go`, `handleCreate`). Task known, extensions ordered
   and unique, no aggregation parameter for Prio3Count, no duplicate report IDs,
   and the `verification_key_id` names a key the task actually holds.
4. **Decrypt** (`helper.go`, `aggregateInit`). The Helper reconstructs the
   `InputShareAad` exactly as the Client built it and opens the HPKE ciphertext.
   The AAD includes the task configuration, so a Helper configured with even
   slightly different task bytes fails every decryption. That is the single most
   common cause of an interop failure, and it fails closed rather than quietly.
5. **Verify** (`pkg/vdaf/prio3`). `VerifyInit` produces the Helper's verifier
   share; combined with the Leader's share from the ping-pong message it decides
   whether the measurement was well-formed. Prio3Count is single round, so the
   Helper reaches a terminal state immediately and answers with a framed finish.
6. **Commit** (`helper.go`). A valid report's output share is stored on the job;
   a rejected one records a `ReportError`. The response mirrors the request's
   report IDs in order, which the Leader relies on.
7. **Collect** (`handler.go`, `handleAggregateShare`). Committed output shares
   for the task are summed and sealed to the Collector's HPKE key.

Job creation is idempotent by construction: the job ID is `sha256(body)[:16]`,
so a byte-identical retry lands on the same resource and replays the stored
response, while the same ID with different content is a conflict.

## Why the wire codec has three modes

`pkg/dap/wire.Variant` exists because the string `"dap-18"` did not pin a byte
format. The published draft-ietf-ppm-dap-18 and the format the Janus reference
implementation shipped under the same identifier differed in five places, so the
codec learned to speak both, with the caller pinning the variant because nothing
on the wire announces it.

Janus has since converged on the published draft's messages, so `VariantDraft18`
is the path that matters and `VariantJanus` is a historical snapshot. The golden
tests in `wire/golden_test.go` pin both encodings byte for byte and assert the
difference stays confined to the documented header and length-prefix positions.
See [interop.md](interop.md) for the details and the reproduction recipe.

`VariantDraft19` was added for a different reason, and the distinction is worth
keeping straight when reading the codecs. Janus differs from draft-18 in message
*structure*; draft-19 does not differ from draft-18 in structure at all. What it
changes is version-bound *values*:

| | draft-18 | draft-19 |
|---|---|---|
| Version tag in every domain-separation string | `dap-18` | `dap-19` |
| `ReportError` for `invalid_message` | 8 | 7 |
| `unknown_verification_key_id` | absent | 9 |
| `task_expired`, `task_not_started`, `outdated_config` | 7, 10, 11 | deleted |
| `task_info` | `opaque<1..2^8-1>` | `opaque<0..2^8-1>` |
| Unknown `verification_key_id` | job fails with a problem document | every report is rejected with `unknown_verification_key_id` |

That split is why every structural branch in the codec tests against
`VariantJanus` rather than for `VariantDraft18`: a new published draft then
inherits the right message shapes automatically, and only the value tables and
the version string need touching. The `ReportError` code points are translated
at the wire boundary in both directions rather than cast, because the same byte
denotes different errors in the two registries — byte 7 is `task_expired` under
draft-18 and `invalid_message` under draft-19 — so a version-blind decoder would
silently report the wrong rejection reason rather than fail.

draft-19 also references draft-irtf-cfrg-vdaf-20, whose `VERSION` constant is
still 18. The Prio3 crypto is therefore unchanged and the checked-in CFRG
vectors stay authoritative for both DAP versions, which is what
`TestDraft19_EndToEnd` asserts by committing the same reference output share
under the new version.

## What is deliberately not here

The Leader role, the general collection path (multiple batches, batch selectors,
query modes), the Collector, the other Prio3 instances, multi-round VDAFs,
task provisioning, and durable storage are all absent. The Helper keeps its
state in memory and the store interface (`helper/store.go`) is the seam where a
real database would go.

Constant-time hardening is likewise future work; the
[security posture](../README.md#security-posture) section says exactly what has
and has not been done about side channels.

## Testing layers

Each layer is checked in the way that layer can be checked:

- **Crypto**: byte-exact against the official CFRG draft-18 test vectors, plus
  tampered-vector negatives and decode-time robustness tests.
- **Codec**: round-trip and golden-byte tests, plus fuzz targets asserting no
  panic and a re-encode fixed point, with a checked-in seed corpus.
- **Helper**: HTTP-level tests over `httptest`, covering both the happy path and
  every rejection path with its problem document.
- **Cross-implementation**: the Janus smoke, which is the only test that proves
  another implementation agrees with these bytes.

`make check` runs the first three; the smoke is run by hand, see
[interop.md](interop.md).
