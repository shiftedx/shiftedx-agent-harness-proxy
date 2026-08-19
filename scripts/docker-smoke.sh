#!/bin/sh
# Exercise the same hardened image configuration used by CI. The fake upstream
# is intentionally a host process so this script has no external prerequisites.
set -eu

image="${IMAGE:-shiftedx-agent-harness-proxy:smoke}"
build_image="${BUILD_IMAGE:-1}"
proxy_port="${PROXY_PORT:-18090}"
upstream_port="${UPSTREAM_PORT:-18000}"
container="shiftedx-agent-harness-proxy-smoke-$$"
tmpdir="$(mktemp -d)"
upstream_pid=""

cleanup() {
  if [ -n "$upstream_pid" ]; then
    kill "$upstream_pid" >/dev/null 2>&1 || true
    wait "$upstream_pid" 2>/dev/null || true
  fi
  docker rm --force "$container" >/dev/null 2>&1 || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

if [ "$build_image" = "1" ]; then
  docker build --tag "$image" .
elif [ "$build_image" != "0" ]; then
  echo "BUILD_IMAGE must be 0 or 1" >&2
  exit 2
fi

mkdir "$tmpdir/secrets"
printf '%s' 'smoke-proxy-key' >"$tmpdir/secrets/proxy_api_key"
printf '%s' 'smoke-upstream-key' >"$tmpdir/secrets/upstream_api_key"
chmod 755 "$tmpdir/secrets"
chmod 444 "$tmpdir/secrets/proxy_api_key" "$tmpdir/secrets/upstream_api_key"

docker run --detach \
  --name "$container" \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 100 \
  --cpus 1 \
  --memory 256m \
  --add-host host.docker.internal:host-gateway \
  --mount "type=bind,src=$tmpdir/secrets,dst=/run/secrets,readonly" \
  --publish "127.0.0.1:$proxy_port:8090" \
  --env "UPSTREAM_BASE_URL=http://host.docker.internal:$upstream_port/v1" \
  --env MAX_UPSTREAM_RESPONSE_BYTES=1024 \
  "$image" >/dev/null

await_status() {
  expected="$1"
  url="$2"
  attempt=0
  while :; do
    status="$(curl --silent --output "$tmpdir/response" --write-out '%{http_code}' "$url" || true)"
    if [ "$status" = "$expected" ]; then
      return 0
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
      docker logs "$container" >&2 || true
      echo "expected HTTP $expected from $url, got $status" >&2
      return 1
    fi
    sleep 1
  done
}

assert_hardening() {
  test "$(docker inspect --format '{{.Config.User}}' "$container")" = "10001:10001"
  test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = "true"
  test "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container")" = '["ALL"]'
  docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep 'no-new-privileges' >/dev/null
  test "$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$container")" = "100"
  test "$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$container")" = "1000000000"
  test "$(docker inspect --format '{{.HostConfig.Memory}}' "$container")" = "268435456"
  docker inspect --format '{{json .Mounts}}' "$container" | grep '"Destination":"/run/secrets"' >/dev/null
}

await_status 200 "http://127.0.0.1:$proxy_port/healthz"
assert_hardening
await_status 503 "http://127.0.0.1:$proxy_port/readyz"
grep 'upstream_not_ready' "$tmpdir/response" >/dev/null

uv run python -m uvicorn tests.fake_upstream:app --host 0.0.0.0 --port "$upstream_port" >"$tmpdir/upstream.log" 2>&1 &
upstream_pid=$!
attempt=0
until curl --fail --silent "http://127.0.0.1:$upstream_port/v1/models" >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    cat "$tmpdir/upstream.log" >&2
    exit 1
  fi
  sleep 1
done

await_status 200 "http://127.0.0.1:$proxy_port/readyz"
await_status 401 "http://127.0.0.1:$proxy_port/v1/models"
grep 'authentication_failed' "$tmpdir/response" >/dev/null

auth_header='Authorization: Bearer smoke-proxy-key'
curl --fail --silent --header "$auth_header" "http://127.0.0.1:$proxy_port/v1/models" | grep 'fake-model' >/dev/null
curl --fail --silent \
  --header "$auth_header" \
  --header 'Content-Type: application/json' \
  --data '{"model":"fake-model","messages":[{"role":"user","content":"hello"}]}' \
  "http://127.0.0.1:$proxy_port/v1/chat/completions" | grep 'fake upstream ready' >/dev/null
await_status 401 "http://127.0.0.1:$proxy_port/metrics"
curl --fail --silent --header "$auth_header" "http://127.0.0.1:$proxy_port/metrics" |
  grep 'shiftedx_proxy_downstream_requests_total 1' >/dev/null

status="$(curl --silent --output "$tmpdir/response" --write-out '%{http_code}' \
  --header "$auth_header" \
  --header 'Content-Type: application/json' \
  --data '{"model":"oversized-response","messages":[{"role":"user","content":"hello"}]}' \
  "http://127.0.0.1:$proxy_port/v1/chat/completions")"
test "$status" = "502"
grep 'upstream_response_too_large' "$tmpdir/response" >/dev/null

docker kill --signal=SIGTERM "$container" >/dev/null
test "$(docker wait "$container")" = "0"
