# Release status

## v0.1.0 public qualified release

The r14 qualification decision is `PROMOTE` for the exact public image below. Version `v0.1.0` is
recommended for controlled, authenticated production deployment on the supported topology. This is
not a support-SLA or future-rebuild claim. The public evidence is
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
- Public candidate OCI index: `ghcr.io/shiftedx/shiftedx-agent-harness-proxy@sha256:cee2d12b263358414ff4519d11220d319684a431d4894215b04baedf0807afed`.
- Approved rollback predecessor: `sha256:c673ec73ffded8d28200f6157b696fb451735a3416a55407e686587150fe4230`.

The public reference resolves anonymously to the qualified amd64/arm64 OCI index. A source rebuild,
mutable tag, or later `main` commit is not the evaluated artifact.

All r14 operational gates passed: candidate readiness; transient recovery; restart readiness and
graceful in-flight restart; sustained load and overload; upstream-concurrency and exact accounting; bounded
pass-through and proxy-only processing; SSE validity, TTFT, malformed-stream handling and
cancellation; injected timeout/disconnect/malformed/5xx/429 faults; privacy probes; resource
ceilings; and rollback readiness plus smoke within 60 seconds. Decode remained at least `90%` of
direct in each lane, and reconciliation and amplification gates passed. Raw evidence remains private.

Deployment still requires `phase_split`, authenticated private/loopback operation, a canary with
end-to-end monitoring, and the approved rollback artifact locally available.

## Public review map

- [README](README.md): supported surface and setup
- [Policy contract](docs/policy.md): exact execution and public error semantics
- [Operator runbook](docs/operator-runbook.md): production topology, monitoring, and rollback
- [Benchmark protocol](docs/benchmarking.md): paired-run methodology and sanitization boundary
- [Qualification plan](benchmark-reports/v2-qualification-plan.md): frozen promotion gates
- [Public r14 qualification result](benchmark-reports/v2-qualification-result-2026-08-24.json): aggregate evidence and provenance
- [Changelog](CHANGELOG.md): release-candidate capabilities
- [Security policy](SECURITY.md): deployment boundary and private reporting
