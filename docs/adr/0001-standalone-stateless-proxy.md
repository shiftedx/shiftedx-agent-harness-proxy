# ADR 0001: Standalone stateless, non-streaming proxy

- Status: Accepted
- Date: 2026-08-17

## Context

The Shiftedx Agent Harness must operate between an OpenAI Chat Completions client and a fixed
OpenAI-compatible upstream without executing client tools or seeing benchmark-private data.
Duplicate tool execution can be prevented only after a complete upstream response is inspected.

## Decision

The first release is a stateless HTTP proxy. Every downstream request must include the complete
visible conversation. The proxy reconstructs receipts from assistant tool-call IDs paired with
later tool-result messages, injects compact policy state, and performs a bounded internal retry
when a proposed tool call is blocked. It returns the first wholly allowed tool-call response or an
acceptable terminal response. Streaming is rejected with HTTP 400.

The upstream base URL is process configuration, never request data. Downstream and upstream
credentials remain separate. Internal rejected turns exist only for the duration of one request.

## Consequences

- The proxy cannot provide strong policy guarantees for truncated transcripts and signals that
  degraded state explicitly.
- Parallel tool calls are atomic at the downstream boundary: if any call is blocked, no sibling is
  dispatched to the client; the complete rejected assistant turn is used only for an internal retry.
- Calls and correction turns are bounded, so this is not an autonomous unbounded agent loop.
- Stateful sessions may be added only if testing demonstrates a need, with explicit TTL and tenant
  isolation; client IP and the OpenAI `user` field are not session identifiers.
