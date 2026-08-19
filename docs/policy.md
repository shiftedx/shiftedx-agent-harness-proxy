# Policy contract

## Trust boundary

The proxy sees only client-supplied messages, public tool schemas, emitted tool calls, paired public
tool results, a declared response schema, and safe upstream status/timing. It must never receive
expected benchmark answers, hidden tests, required-call sets, grader results, holdout secrets, or
private evaluation artifacts. The upstream URL is fixed at process start. The proxy never executes
a tool or fabricates a successful receipt.

## Transport and error contract

The v1 surface is `/v1/models` and non-streaming `/v1/chat/completions`. The Chat Completions
boundary validates a non-empty string `model`, an array of supported message shapes (`system`,
`user`, `assistant`, and `tool`), function tools, and proxy-owned policy extensions before an
upstream request. It preserves unrelated compatible JSON fields. `stream` must be a JSON boolean
and `true` is rejected; with the harness enabled, `n` must be the JSON integer `1`, never a boolean.
Content-part arrays must be non-empty arrays of objects with non-empty string `type` values, while
unknown well-formed part types and fields are preserved. An assistant must have usable content or a
non-empty valid function tool-call array. For `response_format.type=json_schema`, the wrapper and
schema must be objects; object `properties`, when present, must also be an object. Well-formed
schemas outside the v1 projection subset are forwarded without projection.

Upstream response bodies are never returned. The stable mapping is:

| Upstream condition | Downstream status and code |
|---|---|
| 400 | `400 upstream_bad_request` |
| 401 or 403 | `502 upstream_authentication_failed` |
| 404 | `502 upstream_not_found` |
| 409 | `409 upstream_conflict` |
| 422 | `422 upstream_unprocessable` |
| 429 | `429 upstream_rate_limited` |
| 5xx or redirect | `502 upstream_server_error` |
| timeout | `504 upstream_timeout` |
| disconnect | `502 upstream_connection_error` |
| malformed JSON or oversized response | `502 upstream_malformed_json` or `502 upstream_response_too_large` |

For an upstream 429, only a decimal `Retry-After` of at most 3600 seconds is returned. Safe,
bounded upstream request/accounting IDs may be returned under `X-Shiftedx-Upstream-*`; cookies,
credentials, arbitrary headers, and raw error bodies are discarded. The proxy accepts a client
`X-Request-ID` only when it is a bounded token; otherwise it generates one. That correlation ID is
sent upstream, returned downstream, and used as a scalar structured-log value.
The credentialed upstream receives only that correlation header from the downstream header set;
downstream authorization, cookies, `OpenAI-Organization`, and `OpenAI-Project` are never forwarded.

## Admission, deadline, and overload contract

After downstream authentication and before body buffering, the proxy acquires a global admission
budget plus an authenticated-principal budget. Principal keys are opaque process-derived values from
the configured ordinary bearer or trusted policy-extension capability; they are never sourced from
caller IP, `user`, tenant fields, client IDs, headers, logs, or metric labels. Development,
unauthenticated deployments and the explicit `PRINCIPAL_BUDGET_MODE=global` profile use one internal
global budget key. Principal entries expire only when no request references them and their rate window
is idle.

`ADMISSION_LIMIT` bounds full downstream request lifetimes and `CONCURRENCY_LIMIT` bounds one
upstream operation at a time. The monotonic `TOTAL_REQUEST_DEADLINE_SECONDS` begins before admission
queueing and covers queueing, reading up to `MAX_REQUEST_BYTES`, validation, reconstruction, every
retry/upstream operation, disconnect cleanup, and response construction. The deadline never resets
for retries. A downstream disconnect cancels in-flight policy/upstream work and releases both gates.

Overload has no queue-detail disclosure: admission/concurrency/rate rejection returns `429` with
`admission_overloaded`, `principal_concurrency_limited`, or `principal_rate_limited`, respectively,
and only the configured bounded numeric `Retry-After`. Deadline expiry returns
`504 request_deadline_exceeded`. Upstream-operation queue timeout returns
`503 upstream_concurrency_limited` with the same bounded hint. Metrics are aggregate prompt-free counters for admission/rate
rejection, deadline expiry, and cancellation; active/queued downstream work and active upstream work
are gauges without principal labels.

`SERVER_CONNECTION_LIMIT` and `SERVER_BACKLOG` are process-fixed Uvicorn parsed-request task and
pending-socket limits. The parsed-request limit does not bound slow-header sockets before HTTP parsing;
only the parsed-request limit reserves management-route headroom. A trusted ingress must separately
apply finite accepted-connection, header-read, and slow-client limits. Application admission never
claims to bound sockets that have not reached the ASGI application.

## Cache namespace controls

Generic v1 upstreams run with `UPSTREAM_CACHE_CAPABILITY_MODE=disabled` by default. The only other
currently supported process-fixed profile is `unknown`; it fails closed identically. Neither profile
accepts a client-selected cache namespace. The default top-level denylist is `cache_salt`,
`prompt_cache_key`, `cache_namespace`, `cache_namespace_key`, `cache_key_version`,
`cache_principal_id`, `cache_hmac_namespace`, `tenant_id`, `cache_tenant_id`, `cache_key`, and
`prompt_cache_salt`; matching keys are rejected with `400 untrusted_cache_namespace` before any
upstream call. The comparison case-folds names and removes separators, so snake-case, kebab-case,
camel-case, and case variants are equivalent. Operators can extend this top-level denylist with
comma-separated `UPSTREAM_CACHE_NAMESPACE_FIELDS` names, which use the same normalization; empty or
separator-only configured entries fail process startup. The standard top-level OpenAI `user` field is
not a cache authority and remains compatible.

The response never identifies the rejected field or value, and the proxy never logs or labels either.
Nested message, tool, and provider objects are not recursively scanned; only top-level client fields
are cache controls in this compatibility mitigation. Other unknown top-level fields are forwarded
unchanged. Cache namespace, principal, and key-version headers are not an authority source and are
not forwarded. A future provider adapter may pass an internal server-derived opaque HMAC namespace and
key version from authenticated principal context; v1 does not derive or accept those values from a
request body or header and does not implement provider-native cache behavior.

## Tool roles

Compatibility defaults are:

| Role | Default tool names |
|---|---|
| Mutation | `apply_patch`, `edit_file`, `str_replace_editor`, `write_file` |
| Verification | `run_tests`, `run_checks`, `verify`, `check` |
| Investigation | `file_search`, `read_file`, `session_search`, `read_logs` |

Annotate a tool or its function with `x-shiftedx-role`. Allowed values are `mutation`,
`verification`, `investigation`, and `other`. The proxy strips its annotation before forwarding.
For names that are not protected by server configuration, annotations are client classification
hints. They may classify custom tools without changing the compatibility defaults.

Comma-separated `MUTATION_TOOLS`, `VERIFICATION_TOOLS`, and `INVESTIGATION_TOOLS` values or a
YAML file selected by `HARNESS_CONFIG_FILE` protect the names they configure:

```yaml
roles:
  mutation: [deploy_config]
  verification: [healthcheck, smoke_test]
  investigation: [inspect_config, read_logs]
```

Protected names are server-owned. An ordinary client may repeat the same role annotation, but a
conflicting annotation is rejected with `403 protected_role_override_denied`; it is never silently
treated as a downgrade. Top-level and function annotations must agree, and all annotations must be
one of the four allowed strings; invalid inputs return `400 conflicting_role_annotation` or
`400 invalid_role_annotation`. A server configuration that assigns the same name to multiple roles
is invalid.

An operator can explicitly authorize a separate authenticated policy-extension principal with
`TRUSTED_POLICY_EXTENSION_API_KEYS`, a comma-separated list of opaque bearer capabilities. A request
authenticated with one of those capabilities may change a protected role or use the trusted receipt
override below. The capability is checked against process configuration during authentication; a
caller-provided extension header has no effect. Keep these capabilities separate from ordinary
`PROXY_API_KEY` credentials and provision them as secrets. Startup rejects empty, malformed, or
overlapping capability entries, so an ordinary bearer can never silently become a trusted principal.

## Receipt and retry semantics

- Structured result `status` and `error` fields take priority over incidental words such as
  “error.”
- A compact receipt contains sequence, tool, canonical argument signature, status, and epoch; raw
  result text is not retained in policy state.
- Identical calls are blocked only within an unchanged epoch. Successful mutation increments it.
- Successful mutation opens a verification requirement. A successful verifier closes it.
- Failed verification remains unresolved through investigation. It closes only after changed
  action and a later successful verifier.
- After three successful investigations following failed verification, another investigation is
  blocked when a mutation tool exists.
- A terminal answer cannot follow a failed receipt, pending verification, unresolved verification
  failure, or blocked action.
- A parallel batch containing a blocked call is withheld atomically. Allowed siblings receive only
  a synthetic withheld result in the internal retry transcript and may be reissued.
- Terminal corrections, internal retries, and total upstream calls are independently bounded.

## Terminal schemas and projection

The proxy reads standard `response_format.json_schema`. Version 1 supports exact primitive
`string`, `integer`, `number`, and `boolean` properties. It does not coerce types, fill missing
values, override failed verification, or project nested schemas. The narrow successful verifier
receipt `N passed` can project into exactly `{status: string, tests: integer}`.

### Local projection accounting

A locally projected completion is a standard `chat.completion` response with an always-present
top-level extension:

```json
"x-shiftedx-projection-v1": {
  "origin": "local_projection",
  "upstream_calls": 0,
  "upstream_model_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
  "client_input_tokenization": {"available": false, "tokens": null}
}
```

Its standard `usage` object has the same three zero counts. These are exact **upstream model**
usage: no upstream call or model token occurred. They do not tokenize, estimate, or otherwise account
for client-visible input; that value is explicitly unavailable. SDKs that ignore unknown top-level
fields retain the ordinary completion shape, while extension-aware clients can distinguish the origin
without inspecting content or telemetry headers. Ordinary upstream completions have no marker.
`x-shiftedx-projection-v1` is reserved to the proxy: it is removed from every upstream-origin
completion before release, so an upstream cannot spoof a Local Projection. Other compatible unknown
upstream fields remain unchanged.

For accounting, count downstream requests, upstream calls, upstream model tokens, and client-input
tokenization separately. A local projection counts as one downstream request, zero upstream calls,
zero upstream model tokens, and unavailable client-input tokenization. Metrics expose
`shiftedx_proxy_receipt_projections_total` and
`shiftedx_proxy_local_projection_upstream_calls_avoided_total`; each increments once per local
projection, representing one immediate upstream request avoided. Neither counter is a billing,
tenant, prompt, or transcript record.

Requests containing tools require a paired tool receipt by default. Only a request authenticated as
the configured trusted policy-extension principal can set the proxy-owned top-level boolean
`x-shiftedx-require-receipt` to `false`; ordinary clients receive
`403 receipt_override_denied`. Non-boolean values receive `400 invalid_receipt_override`. The field
is consumed locally and never forwarded upstream.

The metrics endpoint records only aggregate policy-extension allow and deny counters. It does not
record arguments, credentials, messages, tool results, or raw transcripts.

Harness opt-out is also a policy-control extension. `X-Shiftedx-Harness: off` is honored only when
the server explicitly enables `ALLOW_HARNESS_OPT_OUT=true` and the request authenticates with a
trusted policy-extension capability. An ordinary principal receives
`403 harness_opt_out_denied` even when the server enables opt-out; when the server disables it, the
existing `403 harness_opt_out_disabled` response applies. The proxy-only header is never forwarded
upstream.

## Stateless transcript reconstruction

Every request must contain the complete visible conversation with original assistant tool-call IDs
and later matching `role=tool` messages. State is reconstructed independently per request and is
never keyed by IP address or the OpenAI `user` field. Orphaned results, malformed calls, or unmatched
IDs produce `X-Shiftedx-State: degraded`; a truncated transcript does not receive a full duplicate
guarantee.
