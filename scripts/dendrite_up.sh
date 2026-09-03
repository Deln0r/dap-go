#!/usr/bin/env bash
# Start an unmodified Dendrite Matrix homeserver for the integration tests.
#
#   scripts/dendrite_up.sh          # start (idempotent)
#   scripts/dendrite_up.sh down     # stop and remove
#
# Then:
#   DAP_REQUIRE_LIVE=1 go test ./integration/matrix/ -run TestLive
#
# Dendrite is the Go Matrix homeserver from Element (New Vector Ltd, UK). The
# image is used as published, with no patches: the point of the integration test
# is that dap-go works against the real thing.
set -euo pipefail

# Pinned by digest, not by :latest. A moving tag makes "reproducible" false: the
# run that passes today and the run that fails next month would not be testing
# the same homeserver. Bump deliberately.
IMAGE="${DENDRITE_IMAGE:-matrixdotorg/dendrite-monolith@sha256:7dafe6edfc8cfab758a68a4cf20414df1ade4a36b45b1852554d81fb70b1272c}"
NAME="${DENDRITE_CONTAINER:-dap-go-dendrite}"
PORT="${DENDRITE_PORT:-8009}"
STATE_DIR="${DENDRITE_STATE_DIR:-${TMPDIR:-/tmp}/dap-go-dendrite}"

if [ "${1:-up}" = "down" ]; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
  echo "dendrite: removed"
  exit 0
fi

if [ -n "$(docker ps -q --filter "name=^${NAME}$" 2>/dev/null)" ]; then
  echo "dendrite: already running on :$PORT"
  exit 0
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true

mkdir -p "$STATE_DIR"
if [ ! -f "$STATE_DIR/dendrite.yaml" ]; then
  echo "dendrite: generating keys and config in $STATE_DIR"
  # Three things here were each a failed start before they were a flag:
  #   * generate-config's -db is PostgreSQL only, so omitting it is what selects
  #     the per-component SQLite files that -dir places.
  #   * -ci fills in defaults suitable for a throwaway server.
  #   * -ci leaves open registration on, and Dendrite refuses to start with open
  #     registration and no captcha. Nothing here registers a user, so the fix
  #     is to disable registration rather than to force it on.
  docker run --rm -v "$STATE_DIR:/data" -w /data --entrypoint sh "$IMAGE" -c '
    generate-keys --private-key /data/matrix_key.pem >/dev/null &&
    generate-config -dir /data/ -ci -server localhost > /data/dendrite.yaml &&
    sed -i "s/registration_disabled: false/registration_disabled: true/" /data/dendrite.yaml
  '
fi

docker run -d --name "$NAME" -p "$PORT:8008" \
  -v "$STATE_DIR:/data" -w /data "$IMAGE" --config /data/dendrite.yaml >/dev/null

echo "dendrite: waiting for :$PORT"
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:$PORT/_matrix/client/versions" >/dev/null 2>&1; then
    version=$(curl -fsS "http://localhost:$PORT/_matrix/federation/v1/version" 2>/dev/null || true)
    echo "dendrite: up on :$PORT  $version"
    exit 0
  fi
  sleep 1
done

echo "dendrite: did not become ready; logs follow" >&2
docker logs "$NAME" 2>&1 | tail -30 >&2
exit 1
