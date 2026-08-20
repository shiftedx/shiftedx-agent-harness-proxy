# Release status

## v0.1 controlled-deployment candidate

The maintainer authorizes controlled, authenticated self-hosted deployment of the exact evaluated
artifact described below. This is a documented exception, not a passing frozen-v1 promotion:
there is no stable/public package, image, tag, support SLA, or production-certification claim.

The AEON campaign showed a clear quality benefit: direct `99/180` versus proxy-assisted `158/180`,
with the proxy winning all six matched pairs. Full-agentic p95 nevertheless failed the `125%`
ceiling: cold was `170.5%` of direct and warm-prefix was `145.6%`. Controlled deployments must use
the [operator runbook](docs/operator-runbook.md) and accept the limits in the
[historical-parity result](benchmark-reports/aeon-historical-parity-result-2026-08-20.md).

Supported now:

- authenticated, non-streaming OpenAI-compatible `GET /v1/models` and
  `POST /v1/chat/completions`;
- stateless execution policy with bounded retries, receipt reconstruction, atomic Withheld Batches,
  verification requirements, and Local Projection accounting;
- fail-closed production configuration, credential isolation, stable public errors, bounded
  admission/deadlines, aggregate metrics, and hardened container operation;
- amd64 and arm64 OCI construction with dependency/image scanning, SBOMs, release manifests, and
  provenance attestations.

Deliberately outside v1:

- SSE streaming;
- OpenAI Responses and Anthropic Messages adapters;
- provider-native cache or context controls;
- client-selectable upstreams;
- tool execution, billing, distributed quotas, or a general API gateway.

Those items belong to the separate provider/streaming roadmap and do not make this v1 release
candidate incomplete within its supported surface.

## Verified evidence

The controlled-deployment authorization is limited to:

- evaluated proxy source `75424328ce0dc0bcef6171b42e390c5ba8559471`;
- signed ARM64 OCI root
  `sha256:c673ec73ffded8d28200f6157b696fb451735a3416a55407e686587150fe4230`,
  retained by [CI run 32413338369](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/runs/32413338369);
- the pinned AEON 27B model, revision, MTPLX 2.7.1 runtime, and `historical-aeon-v1` profile recorded
  in the [sanitized report](benchmark-reports/aeon-historical-parity-result-2026-08-20.md).

The exact image is a retained CI OCI artifact, not a generally pullable public registry image. An
authorized operator must verify and preload it or mirror it to an approved internal registry,
preserving its immutable digest. A source rebuild or later `main` commit is not the evaluated
artifact.

The replacement campaign passed 13/13 immutable events, six direct/proxy reconciliations, 360
scored rows, and the executed exact-image operational matrix. It preserved weighted decode speed,
bounded mean upstream amplification at `1.0631`, and passed proxy-only latency, steady load,
overload, fault mapping, timeout, cancellation, readiness recovery, graceful restart, and RSS
checks. Raw evidence remains private.

### Historical failed candidate

The original failed v1 source is commit `3d8805c1d96d0790526a333ca5074eea20b16b72`. Its post-merge
[main CI run](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/runs/32314958324)
passed:

- 214 tests, Ruff, strict mypy, lock validation, and dependency audit;
- a three-wave, near-`MAX_REQUEST_BYTES` admission soak with bounded RSS and real TCP upstream
  connections;
- multi-architecture OCI construction;
- production-profile hardened image smoke and graceful shutdown;
- vulnerability, secret, and misconfiguration scanning;
- CycloneDX SBOM, immutable release manifest, SLSA provenance, and retained evidence upload.

That exact candidate, model, benchmark, runtime, host contract, results, and limitations are recorded
in the sanitized
[qualification result](benchmark-reports/v1-qualification-result-2026-08-20.md). Raw evidence stays
private.

## Promotion boundary

Stable/public promotion remains blocked. The replacement campaign used the historical temperature-1
sampler rather than the frozen temperature-0 contract; full-agentic p95 failed in both lanes;
matched pass-through wall/TTFT was unavailable; four direct-only regressions have no critical-case
classification; and rollback was not exercised because no approved predecessor was named.

Controlled deployment therefore requires the exact artifact, MTPLX `phase_split`, authenticated
loopback/private operation, a canary and end-to-end latency monitoring, and an operator-approved
rollback target before production traffic. Without a retained predecessor, restrict use to
evaluation/canary traffic that can be removed instead of claiming validated rollback. Do not call
this candidate stable, generally available, production-certified, or compliant with the frozen
latency SLO. The decision is tracked in
[issue #19](https://github.com/shiftedx/shiftedx-agent-harness-proxy/issues/19).

## Public review map

- [README](README.md): supported surface and setup
- [Policy contract](docs/policy.md): exact execution and public error semantics
- [Operator runbook](docs/operator-runbook.md): production topology, monitoring, and rollback
- [Benchmark protocol](docs/benchmarking.md): paired-run methodology and sanitization boundary
- [Qualification plan](benchmark-reports/v1-qualification-plan.md): frozen promotion gates
- [Qualification result](benchmark-reports/v1-qualification-result-2026-08-20.md): sanitized result and remediation
- [AEON historical-parity result](benchmark-reports/aeon-historical-parity-result-2026-08-20.md): positive quality evidence and non-promotion limits
- [Changelog](CHANGELOG.md): release-candidate capabilities
- [Security policy](SECURITY.md): deployment boundary and private reporting
