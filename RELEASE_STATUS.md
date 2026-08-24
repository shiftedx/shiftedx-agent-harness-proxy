# Release status

## r14 qualified exact-image deployment

The r14 qualification decision is `PROMOTE` for the exact candidate below. It authorizes controlled,
authenticated production deployment—not a generally available package, public registry image, tag,
support SLA, or claim about a future rebuild. The public evidence is
[v2-qualification-result-2026-08-24.json](benchmark-reports/v2-qualification-result-2026-08-24.json).

Across the fixed 240-row direct-then-proxy comparison, valid outcomes rose from direct `160/240`
(`66.7%`) to proxy `220/240` (`91.7%`), a `+25.0`-point improvement. Deadline-penalized mean time
to a valid outcome was `203.488 s` direct versus `54.605 s` proxy (ratio `0.268`: `73.2%` lower,
or `3.73×` faster). This is an agent-outcome/time-to-valid result, not a raw-inference-throughput
or token-latency result; the fixed direct-then-proxy sequence is not a randomized causal comparison.

The separate conditional both-valid latency diagnostic passed its p95 gate, but its independently
reviewed retained-row p50 regressed from `4.290 s` direct to `5.077 s` proxy (`+18.3%`). It does not
replace or weaken the time-to-valid gate; the public JSON remains the primary allowlisted evidence.

Supported by the qualified exact image:

- authenticated OpenAI-compatible `GET /v1/models` and `POST /v1/chat/completions`, including
  validate-then-replay SSE compatibility;
- stateless execution policy with bounded retries, receipt reconstruction, atomic Withheld Batches,
  verification requirements, and Local Projection accounting;
- fail-closed production configuration, credential isolation, stable public errors, bounded
  admission/deadlines, aggregate metrics, and hardened container operation;
- amd64 and arm64 OCI construction with dependency/image scanning, SBOMs, release manifests, and
  provenance attestations.

Deliberately outside the qualified surface:

- progressive/token-time streaming (the qualified `stream=true` mode is validate-then-replay
  compatibility streaming, not a TTFT improvement);
- OpenAI Responses and Anthropic Messages adapters;
- provider-native cache or context controls;
- client-selectable upstreams;
- tool execution, billing, distributed quotas, or a general API gateway.

Those items remain outside the qualified surface.

## Exact artifacts and gates

- Candidate source: `b5cdd1e5d5444d3064179baea0dc30cccfecb0ee`.
- Candidate OCI index: `sha256:cee2d12b263358414ff4519d11220d319684a431d4894215b04baedf0807afed`.
- Approved rollback predecessor: `sha256:c673ec73ffded8d28200f6157b696fb451735a3416a55407e686587150fe4230`.

The candidate digest is retained qualification evidence, not a public registry URL. Operators must
verify and preload it or mirror it to an approved private registry without changing the digest. A
source rebuild, local tag, or later `main` commit is not the evaluated artifact.

All r14 operational gates passed: candidate readiness; transient recovery; restart readiness and
graceful in-flight restart; sustained load and overload; upstream-concurrency and exact accounting; bounded
pass-through and proxy-only processing; SSE validity, TTFT, malformed-stream handling and
cancellation; injected timeout/disconnect/malformed/5xx/429 faults; privacy probes; resource
ceilings; and rollback readiness plus smoke within 60 seconds. Decode remained at least `90%` of
direct in each lane, and reconciliation and amplification gates passed. Raw evidence remains private.

Controlled deployment still requires `phase_split`, authenticated private/loopback operation, a
canary with end-to-end monitoring, and the approved rollback artifact locally available. Do not
claim general availability until a durable public image reference is published.

## Public review map

- [README](README.md): supported surface and setup
- [Policy contract](docs/policy.md): exact execution and public error semantics
- [Operator runbook](docs/operator-runbook.md): production topology, monitoring, and rollback
- [Benchmark protocol](docs/benchmarking.md): paired-run methodology and sanitization boundary
- [Qualification plan](benchmark-reports/v2-qualification-plan.md): frozen promotion gates
- [Public r14 qualification result](benchmark-reports/v2-qualification-result-2026-08-24.json): aggregate evidence and provenance
- [Changelog](CHANGELOG.md): release-candidate capabilities
- [Security policy](SECURITY.md): deployment boundary and private reporting
