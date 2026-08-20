# v1 operator runbook

This runbook covers the authenticated, non-streaming v1 Chat Completions release candidate. The
Harness Proxy is policy middleware: it does not provide TLS, execute tools, select arbitrary
upstreams, or sandbox the Downstream Client's tool runner.

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
- the process-fixed `UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE`; use `phase_split` only after a
  synthetic strict primitive-object tool/schema preflight confirms the upstream cannot combine both grammars;
- ingress limits, host/container profile, monitoring destination, and rollback image;
- secret owner and rotation procedure without copying secret values into the record.

For production qualification or promotion, deploy an exact approved image. Do not rebuild from a
floating branch or use an unverified local tag.

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

## Preflight

Use only synthetic, non-sensitive content:

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
- `shiftedx_proxy_upstream_calls_total`, correction, duplicate/stall, and Local Projection counters;
- `shiftedx_proxy_phase_acquisition_total`, `shiftedx_proxy_phase_finalization_total`, and
  `shiftedx_proxy_phase_schema_rejections_total` when phase splitting is enabled;
- ingress accepted/open connections, header/body timeouts, response status, and queue depth;
- container RSS/CPU/PIDs/restarts and Upstream Server latency, TTFT, throughput, errors, and cache
  state.

Metrics intentionally have no prompt, tool, credential, tenant, or principal labels. Do not add
request-derived labels in downstream monitoring relabel rules.

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
