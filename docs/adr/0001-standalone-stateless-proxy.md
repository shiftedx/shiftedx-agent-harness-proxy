# ADR 0001: Standalone stateless proxy with policy-safe replay streaming

- Status: Accepted
- Date: 2026-08-17
- Amended: 2026-08-23

## Context

The Shiftedx Agent Harness must operate between an OpenAI Chat Completions client and a fixed
OpenAI-compatible upstream without executing client tools or seeing benchmark-private data.
Duplicate tool execution can be prevented only after a complete upstream response is inspected.

## Decision

The first release is a stateless HTTP proxy. Every downstream request must include the complete
visible conversation. The proxy reconstructs receipts from assistant tool-call IDs paired with
later tool-result messages, injects compact policy state, and performs a bounded internal retry
when a proposed tool call is blocked. It returns the first wholly allowed tool-call response or an
acceptable terminal response.

The original first-release boundary rejected streaming with HTTP 400. The 2026-08-23 amendment
allows Chat Completions `stream=true` only as validate-then-replay SSE: the proxy consumes the
streaming controls, obtains and validates the complete response through the same buffered policy
path, serializes the complete event sequence, and only then constructs the SSE response. No token,
tool-call, or terminal fragment is released before the complete response is approved. Progressive
or token-time streaming remains out of scope.

The upstream base URL is process configuration, never request data. Downstream and upstream
credentials remain separate. Internal rejected turns exist only for the duration of one request.

## Consequences

- The proxy cannot provide strong policy guarantees for truncated transcripts and signals that
  degraded state explicitly.
- Parallel tool calls are atomic at the downstream boundary: if any call is blocked, no sibling is
  dispatched to the client; the complete rejected assistant turn is used only for an internal retry.
- Calls and correction turns are bounded, so this is not an autonomous unbounded agent loop.
- Validate-then-replay removes client protocol incompatibility but cannot improve TTFT. Every
  upstream, policy, and serialization failure occurs before SSE response headers. The same total
  deadline remains active while replaying to the downstream client; if it expires after headers, the
  proxy releases admission before attempting a clean truncated SSE EOF without a `[DONE]` event. If
  downstream capacity cannot accept that bounded best-effort EOF, it closes the connection without a
  complete EOF because HTTP cannot replace an already-started response with a 504. Post-header
  upstream failures do not exist in this mode because upstream work is already complete.
- Stateful sessions may be added only if testing demonstrates a need, with explicit TTL and tenant
  isolation; client IP and the OpenAI `user` field are not session identifiers.
