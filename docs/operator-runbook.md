# v1 operator runbook

This runbook covers the authenticated, non-streaming v1 Chat Completions release candidate. The
Harness Proxy is policy middleware: it does not provide TLS, execute tools, select arbitrary
upstreams, or sandbox the Downstream Client's tool runner.

The exact AEON-tested artifact is authorized for controlled deployment under the latency exception
in [Release status](../RELEASE_STATUS.md). It is not a stable/public release or production-certified.
That exact artifact is non-streaming. A later source checkout that accepts `stream=true` is not a
substitute; validate-then-replay SSE requires its own immutable image and compatibility evidence.

## Supported topology

```text
Downstream Client
  -> trusted TLS ingress with connection/header/body timeouts
  -> Harness Proxy on private or loopback port 8090
  -> one fixed OpenAI-compatible Upstream Server
```

The ingress routes only `/v1/models` and `/v1/chat/completions`. Keep `/healthz`, `/readyz`, and
`/metrics` on the management side. Uvicorn's `SERVER_CONNECTION_LIMIT` applies after request headers
parse; the ingress must bound accepted connections, header-read time, idle/slow clients, request
size, and its own queue.

## Before deployment

Record and retain:

- approved source commit and image digest;
- release manifest, OCI archive checksum, SBOM, provenance, and green CI URL;
- `uv.lock`, base-image, Compose files, and configuration digests;
- fixed upstream URL and model/runtime identity;
- the production-pinned `UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE=phase_split` and its synthetic
  strict primitive-object tool/schema preflight;
- ingress limits, host/container profile, monitoring destination, and rollback image;
- secret owner and rotation procedure without copying secret values into the record.

For production qualification or promotion, deploy an exact approved image. Do not rebuild from a
floating branch or use an unverified local tag.

The controlled-deployment candidate is source
`75424328ce0dc0bcef6171b42e390c5ba8559471`, signed ARM64 OCI root
`sha256:c673ec73ffded8d28200f6157b696fb451735a3416a55407e686587150fe4230`.
That digest identifies the retained CI artifact; it is not a registry URL. Verify and preload the
artifact or mirror it to an approved internal registry, then use that registry's immutable digest
reference. A source build does not reproduce the evaluated bytes.

## Secrets

Create newline-free secret files outside version control:

```bash
install -d -m 700 secrets
install -m 600 /dev/null secrets/proxy_api_key.txt
printf '%s' "$CLIENT_PROXY_KEY" > secrets/proxy_api_key.txt
```

If the Upstream Server requires authentication:

```bash
install -m 600 /dev/null secrets/upstream_api_key.txt
printf '%s' "$MODEL_SERVER_KEY" > secrets/upstream_api_key.txt
```

Never use the same value for downstream and upstream authentication. Do not pass secret values on a
command line, place them in Compose YAML, or include them in logs, issues, benchmark manifests, or
support bundles.

## Validate configuration

For a source-based local evaluation build:

```bash
UPSTREAM_BASE_URL=http://host.docker.internal:8000/v1 \
  docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  config
```

For an exact prebuilt image, first make the approved registry digest or preloaded immutable image
reference available to Docker, then add the no-build release overlay:

```bash
APPROVED_PROXY_IMAGE='registry.example/shiftedx-agent-harness-proxy@sha256:<digest>'
PROXY_IMAGE="$APPROVED_PROXY_IMAGE" \
UPSTREAM_BASE_URL=http://host.docker.internal:8000/v1 \
  docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  -f docker-compose.release.yml \
  config
```

Inspect the rendered configuration. Production must retain:

- `DEPLOYMENT_PROFILE=production`;
- an explicit fixed `UPSTREAM_BASE_URL` ending at the intended `/v1` base;
- `UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE=phase_split`;
- loopback/private publication rather than `0.0.0.0:8090`;
- non-root UID/GID `10001:10001`, read-only root filesystem, all capabilities dropped, and
  `no-new-privileges`;
- finite PID, CPU, memory, server, admission, principal, request-body, upstream-response, retry, and
  deadline limits;
- file-mounted secrets and no writable application volume.

## Start

Source-based local evaluation:

```bash
UPSTREAM_BASE_URL=http://host.docker.internal:8000/v1 \
  docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  up --build -d
```

Exact-image qualification or release operation:

```bash
APPROVED_PROXY_IMAGE='registry.example/shiftedx-agent-harness-proxy@sha256:<digest>'
PROXY_IMAGE="$APPROVED_PROXY_IMAGE" \
UPSTREAM_BASE_URL=http://host.docker.internal:8000/v1 \
  docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  -f docker-compose.release.yml \
  up --no-build -d
```

If an upstream secret is required, include `-f docker-compose.secrets.yml` in the same ordered file
list. Save the exact rendered configuration digest with the deployment record.

## Hermes provider

For a separately qualified immutable streaming image, save this as `$HERMES_HOME/config.yaml`,
replace the endpoint and model ID, and keep the bearer token out of the file:

```yaml
model:
  default: served-model-id
  provider: shiftedx-proxy
providers:
  shiftedx-proxy:
    api: https://proxy.internal/v1
    transport: chat_completions
    default_model: served-model-id
    discover_models: false
    models:
      - served-model-id
display:
  streaming: true
```

Deliver the proxy Authorization bearer through a verified stock Hermes/provider secret mechanism
for the deployed Hermes version; do not put a credential in this file. Then run
`hermes chat --provider shiftedx-proxy --model served-model-id`. Hermes uses the stock Chat
Completions API; when it requests streaming, the proxy performs validate-then-replay: it buffers
and validates the complete upstream completion before emitting OpenAI-compatible SSE events. This
is compatibility streaming, not a token-time/TTFT improvement. Do not use this configuration to
claim that the historical non-streaming candidate is qualified for streaming.

The quality result also binds the client-side `historical-aeon-v1` sampler: temperature `1.0`,
top-p `0.95`, top-k `20`, thinking enabled at medium effort, and a 1024-token response limit.
Changing that profile is allowed operationally but is not covered by the reported quality evidence.

## Preflight

Use only synthetic, non-sensitive content. `/readyz` remains an upstream-reachability signal; the
deployment controller must not enable ingress/backend readiness until both the deterministic
exact-image smoke and the live-upstream synthetic smoke pass.

Before exposing an exact image to ingress, run its deterministic image smoke from the matching public
source checkout. Pull the immutable image first; the smoke must not rebuild it:

```bash
docker pull "$APPROVED_PROXY_IMAGE"
IMAGE="$APPROVED_PROXY_IMAGE" BUILD_IMAGE=0 ./scripts/docker-smoke.sh
```

The deterministic exact-image smoke uses a local fake upstream, not the deployed model. It fails if
`phase_split` forwards a merged tool/schema request, if its finalization request retains tools or
`tool_choice`, or if validate-then-replay SSE loses semantic content or emits anything other than
one `[DONE]`. It also retains the authenticated Models, readiness, bounded-response, hardening,
secret-redaction, and graceful-shutdown checks. This is deterministic image/protocol evidence, not
a model-performance claim or a replacement for the synthetic live-upstream smoke below.

After the exact image is running against the fixed live upstream, run this separate synthetic smoke
with a non-sensitive model ID and prompt. It verifies live reachability, authentication, and
validate-then-replay transport; the deterministic smoke above remains the grammar proof.

```bash
curl -fsS http://127.0.0.1:8090/healthz
curl -fsS http://127.0.0.1:8090/readyz
curl -fsS \
  -H "Authorization: Bearer $CLIENT_PROXY_KEY" \
  http://127.0.0.1:8090/v1/models
curl -fsS \
  -H "Authorization: Bearer $CLIENT_PROXY_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"model":"served-model-id","messages":[{"role":"user","content":"Return a short readiness acknowledgement."}]}' \
  http://127.0.0.1:8090/v1/chat/completions
curl -fsSN \
  -H "Authorization: Bearer $CLIENT_PROXY_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"model":"served-model-id","messages":[{"role":"user","content":"Return a short readiness acknowledgement."}],"stream":true}' \
  http://127.0.0.1:8090/v1/chat/completions |
  awk '/^data: / { event = 1 } /^data: \[DONE\]$/ { done++ } END { exit !(event && done == 1) }'
```

Also verify that unauthenticated `/v1/models`, `/v1/chat/completions`, and `/metrics` fail, the
public ingress cannot reach management routes, and proxy logs contain no test credential or request
content.

## Monitoring

Scrape `/metrics` through the authenticated management path. At minimum alert on:

- `shiftedx_proxy_errors_total`;
- `shiftedx_proxy_admission_rejections_total` and
  `shiftedx_proxy_principal_rate_rejections_total`;
- `shiftedx_proxy_request_deadline_expiries_total` and
  `shiftedx_proxy_downstream_cancellations_total`;
- `shiftedx_proxy_downstream_active`, `shiftedx_proxy_downstream_queued`, and
  `shiftedx_proxy_upstream_active`;
- `shiftedx_proxy_downstream_requests_total` and `shiftedx_proxy_upstream_calls_total` together with
  the authoritative model-server operation ledger; the latter counts every started Chat Completions
  attempt, including failed and cancelled attempts, while models/readiness traffic is excluded;
- correction, duplicate/stall, and Local Projection counters;
- `shiftedx_proxy_phase_acquisition_total`, `shiftedx_proxy_phase_finalization_total`, and
  `shiftedx_proxy_phase_schema_rejections_total` when phase splitting is enabled;
- ingress accepted/open connections, header/body timeouts, response status, and queue depth;
- container RSS/CPU/PIDs/restarts and Upstream Server latency, TTFT, throughput, errors, and cache
  state.

Metrics intentionally have no prompt, tool, credential, tenant, or principal labels. Do not add
request-derived labels in downstream monitoring relabel rules. Use counter deltas over a five-minute
window and the existing ingress/container collector for end-to-end latency and resource values.

| Signal | Stop the canary / page when |
| --- | --- |
| End-to-end p95 | Either cold or warm lane is `>125%` of its matched direct baseline. |
| Upstream amplification | `shiftedx_proxy_upstream_calls_total / shiftedx_proxy_downstream_requests_total` delta is `>2.0`. |
| Errors and cancellations | Error delta exceeds 1% of admitted request delta, or cancellation delta exceeds 5%, for five minutes. |
| Readiness | Any canary has no successful `/readyz` probe for 60 seconds, or no ready backend remains. |
| Corrections / blocks | Correction, duplicate, or stall deltas exceed 5% of admitted request delta for 15 minutes. |
| Resource pressure | RSS, CPU, or PIDs stay above 80% of the configured container limit for five minutes. |

Start with one backend or no more than 5% of traffic for 15 minutes. Expand only if every row stays
within its threshold; otherwise remove the canary from ingress and use the rollback procedure. The
historical AEON result still fails the end-to-end p95 gate, so these rules do not authorize its
promotion without fresh exact-image evidence.

## Public error and retry behavior

Clients may retry only according to an operation's idempotency and the returned contract:

- admission/principal overload: HTTP 429 with stable code and numeric `Retry-After`;
- upstream-operation queue overload: HTTP 503 with `upstream_concurrency_limited` and numeric
  `Retry-After`;
- total deadline: HTTP 504 with `request_deadline_exceeded`;
- downstream disconnect: internal/public-safe cancellation accounting; do not assume a response was
  delivered;
- upstream 429/5xx/timeout/malformed response: stable proxy-owned error semantics documented in the
  [policy contract](policy.md#transport-and-error-contract).

Never automatically retry a released Mutation unless the Downstream Client can prove it was not
dispatched or can enforce its own idempotency key.

## Readiness loss and graceful restart

`/healthz` means the process is alive. `/readyz` means the fixed Upstream Server is reachable. Remove
an instance from ingress routing when readiness fails; do not restart-loop a healthy proxy merely
because an unrelated upstream is unavailable.

For a planned restart:

1. remove the instance from new ingress traffic;
2. wait for downstream active/queued and upstream active gauges to drain;
3. send SIGTERM through Compose and retain the configured 20-second stop grace period;
4. start the exact approved image/configuration;
5. require liveness, readiness, authenticated Models, and synthetic Chat smoke before restoring
   ingress traffic.

Qualification requires no truncated or duplicate accepted response and readiness within 30 seconds.

## Rollback

Keep the previously approved image and its manifest locally available throughout deployment. Do not
rebuild it during an incident.

1. Stop new ingress traffic and record the incident start time.
2. Preserve logs and aggregate metrics without copying prompts, transcripts, model output, tool
   arguments, credentials, or tenant data.
3. Set `APPROVED_PROXY_IMAGE` to the retained prior immutable digest reference; the release overlay
   maps it to the required `PROXY_IMAGE` Compose variable.
4. Render the Compose configuration and confirm only the intended image reference changed.
5. Apply the exact-image command with `up --no-build -d`.
6. Require liveness, readiness, authenticated Models, synthetic Chat, and credential-isolation
   smoke.
7. Restore ingress only after the prior version is ready and record elapsed rollback time.

The v1 promotion gate is a complete rollback within 60 seconds once the prior image is locally
available. If rollback fails, keep traffic removed, preserve evidence, and record `DO NOT PROMOTE`;
do not delete or rewrite remote tags or artifacts to conceal the failed candidate.

## Evidence and disclosure

Follow the [v1 qualification plan](../benchmark-reports/v1-qualification-plan.md) for model-backed
promotion. Raw transcripts and model output belong only under ignored private storage. Public
reports use sanitized per-case/aggregate ledgers and allowlist-only Local Projection accounting.

Security incidents go through a private GitHub Security Advisory as described in
[SECURITY.md](../SECURITY.md). Operational questions may use public issues only when reproductions
contain synthetic content and no infrastructure details that weaken the deployment boundary.
