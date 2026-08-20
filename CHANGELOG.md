# Changelog

All notable changes follow Keep a Changelog. Versions use semantic versioning after the first
public release.

## [Unreleased]

### Added

- Standalone non-streaming Chat Completions proxy for `shiftedx-harness-v1`.
- Stateless transcript reconstruction, configurable tool roles, response-schema contracts,
  duplicate/stall interception, bounded correction, and conservative receipt projection.
- Fail-closed production admission, per-principal concurrency and rate budgets, total request
  deadlines, bounded upstream operations, stable public errors, and cancellation accounting.
- Credential isolation, request/response limits, fail-closed unsupported cache-control rejection,
  health/readiness, prompt-free metrics, and allowlist-only Local Projection accounting.
- Hardened non-root multi-architecture OCI packaging with smoke testing, vulnerability and secret
  scanning, SBOMs, release manifests, provenance attestations, and a no-build exact-image Compose
  overlay.
- Public release-candidate status, preregistered model qualification gates, operator and rollback
  runbook, and sanitized evidence guidance.

### Changed

- The interrupted 2026-08-17 paired benchmark is retained only as a superseded historical audit
  note; it is not presented as release evidence.
- The exact AEON-tested artifact is documented for controlled deployment under its latency
  exception, and Compose can pass the required MTPLX `phase_split` capability mode.
