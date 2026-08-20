# Release status

## v0.1 release candidate

The v1 runtime is implementation-complete for its declared scope and ready for public review. The
2026-08-20 model-backed qualification result is **DO NOT PROMOTE**: the candidate passed most
operational gates but failed model quality and failure-path observability. It is not a generally
available production release.

A later replacement-candidate experiment with the AEON historical sampler demonstrated a clear
quality benefit: direct `99/180` versus proxy-assisted `158/180`, with the proxy winning all six
cold/warm matched pairs. That evidence does not authorize promotion because it used temperature
`1.0` rather than the frozen v1 temperature-0 contract, failed the full-agentic p95 gate in both
cache lanes, and has no approved rollback target. See the
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

Promotion remains blocked. The original three complete cold pairs scored direct `6/102` and proxy
`0/102`; all proxy rows ended in bounded harness exhaustion. Failure-path request/upstream counters
also omitted failed transactions and attempts. The warm lane was not run after the cold result made
promotion impossible, so completeness is an additional failed gate. The replacement
historical-parity experiment demonstrates that the remediated proxy restores the quality benefit
and reconciled accounting for its named contract, but its sampler does not supersede the frozen v1
plan and its full-agentic latency misses the promotion ceiling.

Use the repository as an unreleased evaluation candidate and describe it as “implementation-complete,
qualification attempted, do not promote.” Do not describe it as production-certified. A new
candidate must fix model/tool-acquisition compatibility and failed-attempt accounting, then rerun
the full pre-registered cold/warm protocol. The final promotion decision remains human-owned and is
tracked in [issue #19](https://github.com/shiftedx/shiftedx-agent-harness-proxy/issues/19).

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
