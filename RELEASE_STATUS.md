# Release status

## v0.1 release candidate

The v1 runtime is implementation-complete for its declared scope and ready for public review and
operator-controlled qualification. It is not yet a generally available production release.

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

The latest runtime-changing baseline is source commit
`106910410ccda393b5d9a7ecb6c0615fa5d82b29`. Its post-merge
[main CI run](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/runs/32300168490)
passed:

- 211 tests, Ruff, strict mypy, lock validation, and dependency audit;
- a three-wave, near-`MAX_REQUEST_BYTES` admission soak with bounded RSS and real TCP upstream
  connections;
- multi-architecture OCI construction;
- production-profile hardened image smoke and graceful shutdown;
- vulnerability, secret, and misconfiguration scanning;
- CycloneDX SBOM, immutable release manifest, SLSA provenance, and retained evidence upload.

Subsequent public-readiness documentation does not alter the runtime. The exact source commit,
image digest, model/runtime contract, thresholds, and host profile used for production qualification
must nevertheless be frozen together immediately before trial 1. The resulting immutable manifest
belongs in the sanitized qualification report and release notes, not in an editable “latest” claim.

## Promotion boundary

The remaining gate is the human-owned model-backed qualification tracked in
[issue #19](https://github.com/shiftedx/shiftedx-agent-harness-proxy/issues/19). The pre-registered
[qualification plan](benchmark-reports/v1-qualification-plan.md) requires three complete paired
direct/proxy trials, distinct proven cold/warm lanes, declared load and fault scenarios, a verified
rollback exercise, and an explicit maintainer decision.

Until that evidence exists, use the repository as a release candidate and describe it as
“implementation-complete and qualification-ready.” Do not describe it as production-certified,
publish private transcripts, or infer model-quality claims from scripted proxy-only measurements.

## Public review map

- [README](README.md): supported surface and setup
- [Policy contract](docs/policy.md): exact execution and public error semantics
- [Operator runbook](docs/operator-runbook.md): production topology, monitoring, and rollback
- [Benchmark protocol](docs/benchmarking.md): paired-run methodology and sanitization boundary
- [Qualification plan](benchmark-reports/v1-qualification-plan.md): frozen promotion gates
- [Changelog](CHANGELOG.md): release-candidate capabilities
- [Security policy](SECURITY.md): deployment boundary and private reporting
