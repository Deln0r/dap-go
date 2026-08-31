# Janus interop: running the cross-implementation smoke

`scripts/janus_smoke.sh` runs a Prio3Count aggregation across two independent
DAP implementations: the [Janus](https://github.com/divviup/janus) interop
containers play Client, Leader, and Collector, and dap-go plays the Helper. The
only cross-implementation boundary is Leader to Helper, which is what the smoke
exercises.

This document records what has actually been observed on two dates, and how to
reproduce either run.

## Two runs, two results

**20 June 2026, Janus `c1531764`: complete, aggregate `3`.** The whole path
worked end to end, including the aggregate share. At that commit Janus
advertised `DAP_VERSION_IDENTIFIER = "dap-18"` while implementing a wire format
that differed from the published draft-18 in five places, and dap-go spoke to it
through `wire.VariantJanus`.

**28 August 2026, Janus `d5d523d`: aggregation works, collection does not.** All
four reports decrypt, verify, and are accepted by the Leader. The run then stops
at the aggregate-share step. Details below.

The version identifier was `"dap-18"` on both dates. What changed underneath it
was the entire message layer.

## What Janus looks like now

Janus has converged on the published draft-18 messages: the aggregation-job
initialization request carries `verification_key_id` and aggregation-job
extensions in place of the partial batch selector, and the input-share AAD is the
four-field form including the task configuration.

It has not converged on the resource model. Aggregation jobs are still created
with `PUT` to a Leader-chosen URL, where the published draft uses `POST` to the
collection URL with a server-selected id. So Janus is a hybrid: draft-18
messages over the older HTTP model.

The practical consequence for an implementer: **you cannot infer the message
format from the HTTP method.** dap-go used to pick the AAD variant from the
method, which broke here; it now tries both variants and keeps whichever the
sender actually sealed under.

## Where the August run stops, and why

The Leader requests the aggregate share and dap-go rejects it with 400. Draft-18
restructured that exchange:

| Message | Janus today | dap-go |
| --- | --- | --- |
| `AggregateShareReq` | `{collection_job_req, batch_selector, report_count, checksum}` | `{batch_selector, agg_param, report_count, checksum}` |
| `AggregateShareAad` | `{task_id, task_configuration, collection_job_req}` | `{task_id, agg_param, batch_selector}` |
| `BatchSelector` | `{batch_identifier}` | `{batch_mode, identifier}` |

Closing this means implementing `CollectionJobReq` and the reworked
aggregate-share messages. That is collection-path work, which this project
deliberately has not built (see the status table in the
[README](../README.md)), so the August run is expected to stop there. It is a
scope boundary, not a defect.

## The task configuration must match byte for byte

Draft-18 binds the task configuration into the input-share AAD, so every party
has to construct identical bytes. The interop test API has no `task_info` field,
so every Janus interop binary uses the fixed placeholder `task-info`, and
anything else makes every HPKE open fail with a decryption error that looks like
a key problem but is not. dap-go uses the same placeholder in
`cmd/dap-helper`.

The same applies to the endpoints, the time precision, the minimum batch size,
and the batch configuration: the collector needs them too, which is why it is
registered with the helper endpoint even though it never talks to the Helper.

## Prerequisites

- `docker`, `jq`, `python3`
- Go toolchain (1.25+) to build the Helper
- A [divviup/janus](https://github.com/divviup/janus) checkout

Building the Janus images needs roughly 8 GiB available to Docker. With less,
`rustc` is killed while compiling `janus_aggregator` and the bake fails with an
allocation error.

## Steps

```sh
# 1. Build the Janus interop images. Use the default (release) cargo profile:
#    PROFILE=dev writes to target/debug while the Dockerfile copies from
#    target/$PROFILE, which breaks the bake.
cd /path/to/janus
git checkout c1531764d2fc0a05c64b722117004fd516e33a43   # for the complete June run
docker buildx bake janus_interop_aggregator janus_interop_client janus_interop_collector --load

# 2. Run the smoke from this repository.
cd /path/to/dap-go
scripts/janus_smoke.sh
```

Omit the `git checkout` to run against current Janus, which reaches aggregation
and stops at the aggregate share as described above.

Ports are overridable when something else already holds them:

```sh
HELPER_PORT=18080 LEADER_PORT=19001 CLIENT_PORT=19002 COLLECTOR_PORT=19003 \
  scripts/janus_smoke.sh
```

On failure the script dumps the Leader and Collector logs, and the Helper logs
every request with its response code.

## What the smoke covers

One Prio3Count task, one aggregation job, a single batch, and the Helper role.
Not covered: the Leader role, the general collection path, the other Prio3
instances, multi-round VDAFs, and runs against other implementations. It is a
smoke against one peer, not a conformance suite.

## Wire-format notes

Against Janus at `c1531764`, these differed from the published
draft-ietf-ppm-dap-18. dap-go encodes both through `wire.Variant`; the caller
pins the variant, since nothing on the wire announces it.

| Structure | Janus `c1531764` | Published draft-18 |
| --- | --- | --- |
| `AggregationJobInitReq` | `{agg_param, partial_batch_selector, verify_inits}` | `{verification_key_id, agg_param, extensions, verify_inits}` |
| `verification_key_id` | absent | `uint8`, first field |
| `PartialBatchSelector` | present | replaced by aggregation-job extensions |
| `InputShareAad` | `{task_id, metadata, public_share}` | `{task_id, task_configuration, metadata, public_share}` |
| `verify_inits` / `verify_resps` | `uint32` byte-length prefix | implicit-length remainder |
| Aggregation-job init | `PUT` to a Leader-chosen resource URL | `POST` to the collection URL |

Janus has since adopted every row except the last. Golden-byte tests pin both
encodings and assert the difference stays confined to the documented header and
length-prefix positions: see `pkg/dap/wire/golden_test.go`.

Identical across both and exercised live: the vdaf-18 Prio3Count crypto, the
`"dap-18 input share"` and `"dap-18 aggregate share"` HPKE info strings, the
`"dap-18" || task_id` VDAF context, `ReportShare`, `VerifyInit`, `VerifyResp`,
and `HpkeConfig` / `HpkeConfigList`.

## Interop harness notes

The harness API is not stable between Janus versions. As of `d5d523d`:

- `add_task` requires `task_start` and `task_end`. They are optional values but
  the keys must be present, and Janus rejects a task where one is set and the
  other is not.
- `upload` requires `batch_mode` and `min_batch_size`.
- The collector's `add_task` requires the helper endpoint and `min_batch_size`.
- A Prio3 measurement is a JSON string (`"1"`, not `1`).
