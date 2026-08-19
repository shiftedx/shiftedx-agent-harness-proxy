# Policy contract

## Trust boundary

The proxy sees only client-supplied messages, public tool schemas, emitted tool calls, paired public
tool results, a declared response schema, and safe upstream status/timing. It must never receive
expected benchmark answers, hidden tests, required-call sets, grader results, holdout secrets, or
private evaluation artifacts. The upstream URL is fixed at process start. The proxy never executes
a tool or fabricates a successful receipt.

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
