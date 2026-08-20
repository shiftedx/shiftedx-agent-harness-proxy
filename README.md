# Shiftedx Agent Harness Proxy

[![CI](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Status: v0.1 release candidate — do not promote.** The supported v1 surface is
implementation-complete, covered by 214 automated tests, and verified by hardened
multi-architecture image CI, dependency and image scanning, SBOM generation, provenance
attestation, and bounded-load checks. The first complete cold model-backed qualification missed
the quality and observability gates, so no stable package or container release has been promoted.
See [Release status](RELEASE_STATUS.md), the
[qualification result](benchmark-reports/v1-qualification-result-2026-08-20.md), and the
[operator runbook](docs/operator-runbook.md).

A small, stateless policy proxy for OpenAI-compatible Chat Completions. It blocks repeated or
stalled tool calls, requires verification after mutations, and corrects malformed terminal JSON
within fixed retry limits. It never executes tools or changes model weights.

## Local development

Prerequisites: Docker Compose and an OpenAI-compatible model server listening on host port `8000`.
The default Compose file is development-only: it permits unauthenticated clients, selects the local
upstream default, and publishes the service only on host loopback.

```bash
docker compose up --build -d
```

That builds the local image and exposes the proxy at `http://127.0.0.1:8090/v1`. It works on Docker
Desktop and Linux; the supplied Compose file maps `host.docker.internal` appropriately. Do not use
this profile on a shared host or route it from a public ingress.

Check it:

```bash
curl -fsS http://localhost:8090/readyz
curl -fsS http://localhost:8090/v1/models
```

Use a different upstream:

```bash
UPSTREAM_BASE_URL=http://host.docker.internal:1234/v1 docker compose up --build -d
```

Stop it with `docker compose down`.

## Connect a client

Point any non-streaming OpenAI-compatible client at `http://localhost:8090/v1`:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8090/v1", api_key="development-only")
response = client.chat.completions.create(
    model="served-model-id",
    messages=[{"role": "user", "content": "Inspect the project and report status."}],
)
print(response.choices[0].message)
```

Clients must send the complete visible conversation on every request, including assistant tool-call
IDs and their later matching `role=tool` results. Version 1 rejects `stream=true` and requires
`n=1` while the harness is enabled.

## v1 Chat Completions compatibility

`POST /v1/chat/completions` supports non-streaming Chat Completions requests with a non-empty
string `model`; an array of `system`, `user`, `assistant`, and `tool` messages; function tools; and
unknown compatible request fields, which are retained when forwarding upstream. `stream` is an
actual JSON boolean and only `false` is supported. While the Harness Proxy is enabled, `n` must be
the JSON integer `1` (JSON booleans are not integers). Tool schemas, tool-call transcripts, and
proxy-owned `x-shiftedx-*` policy extensions are validated locally before any upstream call.
Content-part arrays must be non-empty arrays of objects with non-empty string `type` values;
unknown well-formed part types and fields remain compatible.

Version 1 does not support SSE streaming, the Responses API, Anthropic Messages, multiple choices
in harness mode, provider-native policy controls, or verbatim upstream error responses. See the
[policy contract](docs/policy.md#transport-and-error-contract) for the error/status matrix.

## Authenticated production profile

Production mode refuses to start without a valid downstream bearer token and an explicit fixed
upstream URL. Create ignored, newline-free Docker secret files, then apply the production override:

```bash
install -m 600 /dev/null secrets/proxy_api_key.txt
printf '%s' "$CLIENT_PROXY_KEY" > secrets/proxy_api_key.txt
UPSTREAM_BASE_URL=http://host.docker.internal:8000/v1 \
  docker compose -f docker-compose.yml -f docker-compose.production.yml up --build -d
```

Clients must use `CLIENT_PROXY_KEY` as their bearer token in this mode.
Downstream credentials, cookies, and arbitrary forwarding headers are never sent upstream.
The proxy sends only its validated or generated `X-Request-ID` correlation ID to the credentialed
upstream; downstream `OpenAI-Organization` and `OpenAI-Project` headers are not forwarded.
If the fixed upstream also requires authentication, create `secrets/upstream_api_key.txt` with
`printf '%s' "$MODEL_SERVER_KEY"` and add `-f docker-compose.secrets.yml` to the command.

The merged production configuration keeps the host publication on `127.0.0.1:8090`, runs as the
image's non-root user with a read-only filesystem, drops every capability, enables
`no-new-privileges`, and applies finite PID, CPU, and memory limits. A trusted same-host ingress may
proxy the public `/v1/models` and `/v1/chat/completions` routes to that loopback listener and must
provide TLS. Do not publish port 8090 directly. `/healthz`, `/readyz`, and `/metrics` share the
internal listener; the profile does not create a separate management socket, so the ingress must
not route those endpoints publicly. `/healthz` remains unauthenticated for liveness, `/readyz`
reports upstream readiness, and `/metrics` requires the proxy bearer token.

For a trusted internal deployment, retain downstream bearer authentication and expose the service
only through a private network policy. The production startup requirements still apply; an internal
network is not a substitute for authentication.

## What the policy does

- Reconstructs compact receipts from paired assistant calls and public tool results.
- Blocks identical calls only while state is unchanged; successful mutation opens a new epoch.
- Requires successful verification after mutation and preserves unresolved failures.
- Withholds an entire parallel batch if one sibling is blocked, preventing false execution state.
- Applies at most two terminal-format corrections and hard-bounds every internal retry loop.
- Derives terminal key/type requirements from standard `response_format.json_schema` when present.

Default tool roles cover common names such as `apply_patch`, `run_tests`, `read_file`, and
`file_search`. Add `"x-shiftedx-role": "mutation|verification|investigation|other"` to a tool schema
for custom names; the proxy strips this extension before forwarding. Names configured by the server
are protected from ordinary clients. A safe-refusal or protected-role override requires a separate,
server-configured trusted policy-extension bearer capability. `X-Shiftedx-Harness: off` additionally
requires both that trusted capability and explicit server enablement; it is not an ordinary client
escape hatch.

Generic v1 cache namespace selection is disabled. Client top-level cache namespace fields are
rejected before forwarding; see the policy contract for normalization and the process-fixed
configuration controls reserved for future provider-native support.

See [the exact policy contract](docs/policy.md) for role configuration, receipt semantics, schema
projection, parallel calls, and degraded transcript behavior.

## Common configuration

| Variable | Default | Purpose |
|---|---:|---|
| `DEPLOYMENT_PROFILE` | `development` | `production` fails closed unless downstream authentication is configured |
| `UPSTREAM_BASE_URL` | host port `8000` in Compose | Fixed OpenAI-compatible `/v1` base |
| `UPSTREAM_API_KEY` | unset | Upstream credential; Docker secret preferred |
| `PROXY_API_KEY` | unset | Independent client-facing bearer token |
| `TRUSTED_POLICY_EXTENSION_API_KEYS` | unset | Distinct comma-separated opaque bearer capabilities allowed to disable receipt requirements or override protected tool roles |
| `ALLOW_HARNESS_OPT_OUT` | `false` | Allows only trusted policy-extension principals to send `X-Shiftedx-Harness: off` |
| `UPSTREAM_CACHE_CAPABILITY_MODE` | `disabled` | Generic cache capability profile; `disabled` and `unknown` reject client namespace controls |
| `UPSTREAM_CACHE_NAMESPACE_FIELDS` | unset | Comma-separated, nonblank additional top-level client cache namespace field names to reject |
| `MAX_INTERNAL_RETRIES` | `4` | Internal policy retries per request |
| `MAX_UPSTREAM_CALLS` | `7` | Total upstream-call ceiling per request |
| `UPSTREAM_TIMEOUT_SECONDS` | `120` | Upstream timeout |
| `CONCURRENCY_LIMIT` | `32` | Concurrent upstream operations (one slot per upstream request/retry) |
| `SERVER_CONNECTION_LIMIT` / `SERVER_BACKLOG` | `24` / `128` | Uvicorn parsed-request task ceiling and socket backlog, with management-route headroom beyond admission |
| `ADMISSION_LIMIT` | `16` | Concurrent downstream requests admitted before body buffering |
| `ADMISSION_WAIT_SECONDS` | `1` | Maximum admission queue wait before a retryable overload response |
| `TOTAL_REQUEST_DEADLINE_SECONDS` | `180` | Monotonic wall-clock limit for queueing, body reads, policy, retries, and response construction |
| `PRINCIPAL_BUDGET_MODE` | `authenticated` | Per configured bearer capability budget; `global` explicitly selects the single-principal fallback |
| `PRINCIPAL_CONCURRENCY_LIMIT` | `4` | Concurrent admitted requests per authenticated principal or global fallback |
| `PRINCIPAL_RATE_LIMIT` / `PRINCIPAL_RATE_WINDOW_SECONDS` | `60` / `60` | Finite in-process request budget per principal/fallback window |
| `OVERLOAD_RETRY_AFTER_SECONDS` | `1` | Bounded numeric retry hint for admission and rate overloads |
| `TELEMETRY_ENABLED` | `false` | Safe policy response headers |
| `METRICS_ENABLED` | `true` | Prompt-free counters at `/metrics` |

The container runs as UID/GID `10001:10001`, needs no writable volume, drops all capabilities, and
uses a read-only filesystem in Compose. The production override also provides finite CPU, memory,
and PID limits. Keep TLS, authentication, and network access control at a trusted ingress for public
deployments. See [SECURITY.md](SECURITY.md) and the
[architecture decision](docs/adr/0001-standalone-stateless-proxy.md).

## Admission and overload

Authentication happens before admission; body bytes are not read until the request obtains both the
global admission budget and the authenticated-principal (or documented global fallback) budget.
`429 admission_overloaded`, `429 principal_concurrency_limited`, and
`429 principal_rate_limited` include only the configured bounded numeric `Retry-After` hint. A total
deadline returns `504 request_deadline_exceeded`; upstream-operation queue timeout returns
`503 upstream_concurrency_limited`, also with that hint. The proxy never exposes queue position, limits,
credentials, principal IDs, prompts, or transcripts in these responses or metric labels.

`ADMISSION_LIMIT * MAX_REQUEST_BYTES` is the conservative buffered-body upper bound; leave room for
JSON objects, policy copies, and bounded upstream responses beneath the production Compose memory
limit. `CONCURRENCY_LIMIT` is separate: it bounds active upstream connections and is acquired only
for a single upstream operation, so body buffering and local policy work do not hold an upstream
slot. `SERVER_CONNECTION_LIMIT` bounds Uvicorn parsed-request task handling and intentionally leaves
headroom for health/readiness and metrics; it does not limit sockets whose headers have not yet
parsed. The trusted ingress must enforce finite accepted-connection, header-read, and slow-client
limits. Internal retries consume more operations but never reset the total request deadline.

## Development and evidence

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run mypy src
./scripts/docker-smoke.sh
```

The release-candidate branch has 214 tests. CI also runs the near-body-limit admission soak,
dependency audit, multi-architecture OCI build, hardened production-profile smoke, exact-image
vulnerability/secret/misconfiguration scan, SBOM generation, release-manifest capture, and SLSA
provenance attestation. The complete evidence boundary is summarized in
[Release status](RELEASE_STATUS.md); benchmark methodology and frozen promotion gates are documented
in [benchmarking](docs/benchmarking.md), the
[v1 qualification plan](benchmark-reports/v1-qualification-plan.md), and the
[qualification result](benchmark-reports/v1-qualification-result-2026-08-20.md).

This is an unreleased `0.1.0` release candidate. The source repository is suitable for review and
evaluation, but no package or container image has been promoted as a stable public release.
Publication and the final production decision require explicit owner authorization.
