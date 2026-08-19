# Shiftedx Agent Harness Proxy

The execution-policy domain between an OpenAI-compatible client and a fixed model server.

## Language

**Harness Proxy**:
Stateless middleware that evaluates model responses against execution policy before releasing them
to a client.
_Avoid_: Model upgrade, intelligence layer

**Downstream Client**:
The OpenAI-compatible client that submits complete transcripts and executes released tool calls.
_Avoid_: Upstream client

**Upstream Server**:
The fixed OpenAI-compatible model endpoint used by the Harness Proxy.
_Avoid_: Backend selected by the request

**Receipt**:
A compact policy record grounded in a paired assistant tool call and public tool result.
_Avoid_: Raw transcript, fabricated result

**Epoch**:
The duplicate-detection state in which identical tool calls are considered repetitions; successful
Mutation opens a new Epoch.
_Avoid_: Session

**Mutation**:
A tool action whose successful result changes externally visible work state.
_Avoid_: Write operation

**Verification**:
A tool action that evaluates whether mutated work satisfies its checks.
_Avoid_: Investigation

**Investigation**:
A read-only tool action used to inspect or locate work state.
_Avoid_: Verification

**Withheld Batch**:
A parallel tool-call batch retained by the Harness Proxy because at least one sibling violates
policy.
_Avoid_: Partially executed batch

**Terminal Correction**:
A bounded internal turn requesting a valid final response after the model produces an unacceptable
terminal answer.
_Avoid_: Unbounded retry

**Degraded State**:
Policy state reconstructed from an incomplete or malformed public transcript, carrying reduced
duplicate-detection guarantees.
_Avoid_: Validated state

**Local Projection**:
A response synthesized solely from a current successful public receipt without an upstream model
call.
_Avoid_: Model completion, cached response
