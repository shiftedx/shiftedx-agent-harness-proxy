#!/bin/sh
set -eu

image="shiftedx-agent-harness-proxy:smoke"
container="shiftedx-agent-harness-proxy-smoke"

docker build --tag "$image" .
docker run --detach --rm \
  --name "$container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --add-host host.docker.internal:host-gateway \
  --publish 8090:8090 \
  --env UPSTREAM_BASE_URL=http://host.docker.internal:18000/v1 \
  "$image" >/dev/null
trap 'docker stop "$container" >/dev/null 2>&1 || true' EXIT INT TERM

attempt=0
until curl --fail --silent http://127.0.0.1:8090/readyz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker logs "$container"
    exit 1
  fi
  sleep 1
done

test "$(docker inspect --format '{{.Config.User}}' "$container")" = "10001:10001"
curl --fail --silent http://127.0.0.1:8090/v1/models | grep 'fake-model' >/dev/null
curl --fail --silent \
  --header 'Content-Type: application/json' \
  --data '{"model":"fake-model","messages":[{"role":"user","content":"hello"}]}' \
  http://127.0.0.1:8090/v1/chat/completions | grep 'fake upstream ready' >/dev/null
