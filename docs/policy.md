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
Annotations override comma-separated `MUTATION_TOOLS`, `VERIFICATION_TOOLS`, and
`INVESTIGATION_TOOLS` values or a YAML file selected by `HARNESS_CONFIG_FILE`:

```yaml
roles:
  mutation: [deploy_config]
  verification: [healthcheck, smoke_test]
  investigation: [inspect_config, read_logs]
```

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

Requests containing tools require a paired tool receipt by default. Trusted safe-refusal cases can
set the proxy-owned top-level boolean `x-shiftedx-require-receipt` to `false`; it is consumed locally.

## Stateless transcript reconstruction

Every request must contain the complete visible conversation with original assistant tool-call IDs
and later matching `role=tool` messages. State is reconstructed independently per request and is
never keyed by IP address or the OpenAI `user` field. Orphaned results, malformed calls, or unmatched
IDs produce `X-Shiftedx-State: degraded`; a truncated transcript does not receive a full duplicate
guarantee.
