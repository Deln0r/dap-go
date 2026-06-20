#!/usr/bin/env bash
# Janus cross-implementation smoke for the dap-go Helper.
#
# Topology (divviup/janus interop test design): the Janus interop containers
# play Client + Leader + Collector (known-good), and dap-go runs the Helper.
# The only cross-implementation boundary is Leader <-> Helper, which is exactly
# what we want to validate. The Helper is registered in the Janus "dap-18" wire
# variant (see docs eb-1/dap-go/INTEROP_FINDINGS).
#
# Usage: scripts/janus_smoke.sh
# Requires: docker, jq, python3, and the janus_interop_{aggregator,client,collector}:latest
# images (docker buildx bake janus_interop_aggregator janus_interop_client janus_interop_collector --load).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET=dapsmoke
HELPER_PORT=8080
LEADER_PORT=9001
CLIENT_PORT=9002
COLLECTOR_PORT=9003
TAG="${JANUS_TAG:-latest}"

# Prio3Count measurements; the aggregate is their sum.
MEASUREMENTS=(1 1 0 1)
EXPECTED=3
MIN_BATCH=${#MEASUREMENTS[@]}
TIME_PRECISION=3600

b64url() { python3 -c "import sys,base64;sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip('='))"; }
randb64() { head -c "$1" /dev/urandom | b64url; }

HELPER_PID=""
cleanup() {
  set +e
  [ -n "$HELPER_PID" ] && kill "$HELPER_PID" 2>/dev/null
  docker rm -f leader client collector >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  set -e
}
trap cleanup EXIT

echo "== build + start dap-helper (host :$HELPER_PORT) =="
( cd "$REPO_ROOT" && go build -o /tmp/dap-helper ./cmd/dap-helper )
/tmp/dap-helper -addr ":$HELPER_PORT" &
HELPER_PID=$!

echo "== start Janus containers =="
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null
docker run -d --rm --name leader    --network "$NET" --add-host host.docker.internal:host-gateway -p "$LEADER_PORT:8080"    "janus_interop_aggregator:$TAG" >/dev/null
docker run -d --rm --name client    --network "$NET" --add-host host.docker.internal:host-gateway -p "$CLIENT_PORT:8080"    "janus_interop_client:$TAG" >/dev/null
docker run -d --rm --name collector --network "$NET" --add-host host.docker.internal:host-gateway -p "$COLLECTOR_PORT:8080" "janus_interop_collector:$TAG" >/dev/null

ready() { # url
  for _ in $(seq 1 60); do
    if curl -fsS -X POST "$1/internal/test/ready" -H 'content-type: application/json' -d '{}' >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "NOT READY: $1" >&2; return 1
}
echo "== wait for readiness =="
ready "http://localhost:$HELPER_PORT"
ready "http://localhost:$LEADER_PORT"
ready "http://localhost:$CLIENT_PORT"
ready "http://localhost:$COLLECTOR_PORT"

TASK_ID=$(randb64 32)
VERIFY_KEY=$(randb64 32)
LEADER_AUTH=$(randb64 16)
COLLECTOR_AUTH=$(randb64 16)
VDAF='{"type":"Prio3Count"}'
BATCH_MODE=1 # TimeInterval

LEADER_INT="http://leader:8080/"
HELPER_INT="http://host.docker.internal:$HELPER_PORT/"

post() { curl -fsS -X POST "$1" -H 'content-type: application/json' -d "$2"; }

echo "== endpoint_for_task (leader, helper) =="
post "http://localhost:$LEADER_PORT/internal/test/endpoint_for_task" \
  "$(jq -n --arg t "$TASK_ID" '{task_id:$t,role:"leader",hostname:"leader"}')" | jq -e '.status=="success"' >/dev/null
post "http://localhost:$HELPER_PORT/internal/test/endpoint_for_task" \
  "$(jq -n --arg t "$TASK_ID" '{task_id:$t,role:"helper",hostname:"host.docker.internal"}')" | jq -e '.status=="success"' >/dev/null

echo "== add_task: collector =="
COLLECTOR_HPKE=$(post "http://localhost:$COLLECTOR_PORT/internal/test/add_task" \
  "$(jq -n --arg t "$TASK_ID" --arg l "$LEADER_INT" --argjson v "$VDAF" --arg ca "$COLLECTOR_AUTH" --argjson bm "$BATCH_MODE" --argjson tp "$TIME_PRECISION" \
     '{task_id:$t,leader:$l,vdaf:$v,collector_authentication_token:$ca,batch_mode:$bm,time_precision:$tp}')" | jq -r '.collector_hpke_config')

addtask_body() { # role
  jq -n --arg t "$TASK_ID" --arg l "$LEADER_INT" --arg h "$HELPER_INT" --argjson v "$VDAF" \
        --arg la "$LEADER_AUTH" --arg ca "$COLLECTOR_AUTH" --arg r "$1" --arg vk "$VERIFY_KEY" \
        --argjson bm "$BATCH_MODE" --argjson mb "$MIN_BATCH" --argjson tp "$TIME_PRECISION" --arg ch "$COLLECTOR_HPKE" \
    '{task_id:$t,leader:$l,helper:$h,vdaf:$v,leader_authentication_token:$la,collector_authentication_token:$ca,role:$r,vdaf_verify_key:$vk,batch_mode:$bm,min_batch_size:$mb,time_precision:$tp,collector_hpke_config:$ch}'
}
echo "== add_task: leader =="
post "http://localhost:$LEADER_PORT/internal/test/add_task" "$(addtask_body leader)" | jq -e '.status=="success"' >/dev/null
echo "== add_task: helper (dap-go) =="
post "http://localhost:$HELPER_PORT/internal/test/add_task" "$(addtask_body helper)" | jq -e '.status=="success"' >/dev/null

echo "== upload ${#MEASUREMENTS[@]} measurements =="
for m in "${MEASUREMENTS[@]}"; do
  post "http://localhost:$CLIENT_PORT/internal/test/upload" \
    "$(jq -n --arg t "$TASK_ID" --arg l "$LEADER_INT" --arg h "$HELPER_INT" --argjson v "$VDAF" --argjson m "$m" --argjson tp "$TIME_PRECISION" \
       '{task_id:$t,leader:$l,helper:$h,vdaf:$v,measurement:$m,time_precision:$tp}')" | jq -e '.status=="success"' >/dev/null
done

echo "== collection_start =="
NOW=$(date +%s)
START=$(( NOW / TIME_PRECISION * TIME_PRECISION ))
QUERY=$(jq -n --argjson bm "$BATCH_MODE" --argjson s "$START" --argjson d "$((TIME_PRECISION*2))" '{type:$bm,batch_interval_start:$s,batch_interval_duration:$d}')
HANDLE=""
for _ in $(seq 1 20); do
  RESP=$(post "http://localhost:$COLLECTOR_PORT/internal/test/collection_start" \
    "$(jq -n --arg t "$TASK_ID" --arg ap "" --argjson q "$QUERY" '{task_id:$t,agg_param:$ap,query:$q}')")
  if [ "$(echo "$RESP" | jq -r '.status')" = "success" ]; then HANDLE=$(echo "$RESP" | jq -r '.handle'); break; fi
  sleep 1
done
[ -n "$HANDLE" ] || { echo "collection_start never succeeded" >&2; exit 1; }

echo "== collection_poll =="
for _ in $(seq 1 60); do
  PR=$(post "http://localhost:$COLLECTOR_PORT/internal/test/collection_poll" "$(jq -n --arg h "$HANDLE" '{handle:$h}')")
  ST=$(echo "$PR" | jq -r '.status')
  case "$ST" in
    complete) RESULT=$(echo "$PR" | jq -r '.result'); echo "RESULT=$RESULT (expected $EXPECTED)"; [ "$RESULT" = "$EXPECTED" ] && { echo "SMOKE PASS"; exit 0; } || { echo "SMOKE FAIL: wrong aggregate" >&2; exit 1; } ;;
    "in progress") sleep 1 ;;
    error) echo "poll error: $(echo "$PR" | jq -r '.error')" >&2; sleep 2 ;;
    *) echo "unexpected poll status: $PR" >&2; sleep 2 ;;
  esac
done
echo "SMOKE FAIL: timed out" >&2
exit 1
