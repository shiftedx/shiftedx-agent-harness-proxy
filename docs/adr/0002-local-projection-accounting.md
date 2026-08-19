# ADR 0002: Local projection accounting is explicitly zero upstream usage

- Status: Accepted
- Date: 2026-08-19

## Decision

A Local Projection is not model inference: it retains the standard Chat Completions `usage` object
with `prompt_tokens`, `completion_tokens`, and `total_tokens` all exactly zero, and always adds the
top-level `x-shiftedx-projection-v1` extension. The extension states `origin: local_projection`,
`upstream_calls: 0`, the same zero upstream-model usage, and
`client_input_tokenization: {available: false, tokens: null}`. We do not add a tokenizer or estimate
client input tokens. This preserves SDK compatibility while preventing zero upstream usage from being
misread as client-input accounting; ordinary upstream completions receive no synthetic marker.
`x-shiftedx-projection-v1` is reserved to the proxy and stripped from every upstream-origin response,
so upstream output cannot spoof a Local Projection.

Each Local Projection increments `receipt_projections_total` and
`local_projection_upstream_calls_avoided_total` once: one immediate model request was avoided. These
are prompt-free aggregate counters, not billing or tenant accounting. A quota system may count the
downstream request under its own request policy, but must not debit an upstream-call or upstream-token
quota; client-input tokenization remains unavailable. Public benchmark exports use an allowlist-only
projection summary and cannot include raw completion fields.
