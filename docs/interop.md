# Janus interop: reproducing the cross-implementation smoke

`scripts/janus_smoke.sh` runs a Prio3Count aggregation across two independent
DAP implementations: the [Janus](https://github.com/divviup/janus) interop
containers play Client, Leader, and Collector, and dap-go plays the Helper. The
only cross-implementation boundary is Leader to Helper, which is what the smoke
validates.

This document is the reproduction recipe and the wire-format notes behind it.

## Pin Janus to the verified commit

**Build the Janus interop images from commit `c1531764` (18 Jun 2026).** The
smoke is verified green against that commit and is not expected to pass against
current Janus `main`.

Janus has been migrating its wire format toward the published
draft-ietf-ppm-dap-18 since late June 2026 (verification key id, then binding
TaskConfiguration into the HPKE AAD), landing the changes one merge at a time.
Its `DAP_VERSION_IDENTIFIER` stayed `"dap-18"` throughout, so the version string
alone does not tell you which bytes a given build speaks. dap-go's Janus variant
encodes the shapes as of `c1531764`; a newer Janus build will disagree with it,
typically failing at HPKE open or at request decode.

Once Janus finishes converging on the published draft, the right target is
dap-go's `VariantDraft18` path against Janus `main`, and this pin goes away.

## Prerequisites

- `docker`, `jq`, `python3`
- Go toolchain (1.25+) to build the Helper
- A [divviup/janus](https://github.com/divviup/janus) checkout

## Steps

```sh
# 1. Build the Janus interop images at the pinned commit.
#    Use the default (release) cargo profile: PROFILE=dev writes to target/debug
#    while the Dockerfile copies from target/$PROFILE, which breaks the bake.
cd /path/to/janus
git checkout c1531764d2fc0a05c64b722117004fd516e33a43
docker buildx bake janus_interop_aggregator janus_interop_client janus_interop_collector --load

# 2. Run the smoke from this repository.
cd /path/to/dap-go
scripts/janus_smoke.sh
```

The script creates a docker network, starts the three Janus containers, runs the
dap-go Helper on the host (reachable from the containers as
`host.docker.internal`), provisions the task on both aggregators through the
interop test API, uploads the measurements, and drives a collection.

## Expected result

Measurements `[1, 1, 0, 1]` are uploaded, and the Collector unshards the
aggregate **3**. The script exits non-zero if the aggregate differs or any step
fails.

## What the smoke does and does not cover

Covered: one Prio3Count task, one aggregation job, a single batch, and the
Helper role, including the aggregate share sealed to the Collector.

Not covered: the Leader role, the general collection path (multiple batches,
batch selectors, query modes), the other Prio3 instances, multi-round VDAFs, and
runs against other implementations. This is a smoke against one peer, not a
conformance suite. See the status table in the [README](../README.md).

## Wire-format notes

Against Janus at `c1531764`, the following differed from the published
draft-ietf-ppm-dap-18. dap-go handles both through the dual-mode codec in
[`pkg/dap/wire`](../pkg/dap/wire) (`wire.Variant`); the caller pins the variant,
since it is not carried on the wire.

| Structure | Janus `c1531764` | Published draft-18 |
| --- | --- | --- |
| `AggregationJobInitReq` | `{agg_param, partial_batch_selector, verify_inits}` | `{verification_key_id, agg_param, extensions, verify_inits}` |
| `verification_key_id` | absent | `uint8`, first field |
| `PartialBatchSelector` | present | replaced by aggregation-job extensions |
| `InputShareAad` | `{task_id, metadata, public_share}` | `{task_id, task_configuration, metadata, public_share}` |
| `verify_inits` / `verify_resps` | `uint32` byte-length prefix | implicit-length remainder |
| Aggregation-job init | `PUT` to a Leader-chosen resource URL | `POST` to the collection URL |

Identical across both, and exercised live: the vdaf-18 Prio3Count crypto, the
`"dap-18 input share"` and `"dap-18 aggregate share"` HPKE info strings, the
`"dap-18" || task_id` VDAF context, `ReportShare`, `VerifyInit`, `VerifyResp`,
`HpkeConfig` / `HpkeConfigList`, and the aggregate-share messages.

Golden-byte tests pin both encodings and assert the divergence stays confined to
the documented header and length-prefix positions: see
`pkg/dap/wire/golden_test.go`.

## Interop harness note

The measurement in an interop `upload` request is a JSON string for Prio3
(`"1"`, not `1`). That is a property of the Janus interop test API, not of the
DAP wire format.
