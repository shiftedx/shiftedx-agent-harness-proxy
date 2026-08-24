# Latency optimization implementation progress — 2026-08-20

## Verdict

Implementation and bounded mechanism probes progressed, but the latency mission is **not yet
qualified**. No current signed ARM64 image, green push-to-main CI result, immutable fresh campaign,
or complete cold/warm operational matrix exists. Unavailable evidence is not counted as a pass.

HTTP/1.1 over pooled TCP remains the transport. The bounded local mechanism probe did not meet the
handoff threshold for reopening an alternate transport: the observed keep-alive benefit was below
`5 ms`, and MTPLX 2.7.1 exposes no versioned WebSocket Chat Completions contract.

## Implemented

- Live private timing capture and supervisor finalization use exact monotonic integer nanoseconds,
  exact request/attempt partitions, raw failure/cancellation/deadline status, client/runner/server
  outcome agreement, and acyclic hash linkage into reconciliation.
- Timing summaries include intervention/cache-lane percentiles and tails, matched pass-through
  client wall time, transport phase availability, and fresh/reused/unavailable connection counts.
  Response-header time is not labeled TTFT; true TTFT/model/decode remain unavailable where the
  pinned non-streaming boundary cannot prove them.
- Valid receipt-backed phase-split terminals no longer require an unnecessary finalization model
  turn. Broader deterministic projection candidates remain shadow-only; production Local Projection
  is limited to the previously demonstrated verifier summary mapping.
- The proxy has a fail-closed experimental `combined_v1` capability contract. Qualification remains
  fixed to `phase_split` because the upstream MTPLX changes are neither released/versioned nor proven
  by a model-backed direct/proxy preflight.
- Cache evidence now binds a privacy-safe compatible-prefix identity without retaining prompts,
  transcripts, receipts, or tool results.
- The intervention fast path has a conservative server-controlled eligibility and structural shadow
  seam. `enabled` is rejected without immutable promotion authority, and `shadow` is rejected unless
  a private observer is explicitly injected. No bypass is active.
- The production HTTPX pool now explicitly pins the existing `5.0 s` keep-alive expiry.

## Bounded mechanism evidence

These probes are local and non-promotional. They are not substitutes for the frozen qualification
campaign.

### HTTP keep-alive

Twelve sequential requests against the deterministic local probe produced:

| Pool case | Fresh connections | Server-observed reused requests | Client wall p50 | Client wall p95 | Header wait p50 | Header wait p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Declared current contract, `5.0 s` expiry | 1 | 11 | `0.506 ms` | `0.600 ms` | `0.140 ms` | `0.166 ms` |
| Comparison, `0 s` expiry | 12 | 0 | `0.960 ms` | `1.311 ms` | `0.149 ms` | `0.183 ms` |

HTTPX/httpcore proved fresh connects but exposed no per-request reused event; reuse in this probe is
the local server's aggregate socket observation. Header wait is an HTTP phase, not model TTFT. No
pool value change was justified.

### Server-authoritative prefix reuse

One isolated local MTPLX 2.7.1 source-run used the pinned AEON model at native MTP depth 3 with SSD
session cache off. Synthetic long-prefix repeats reported:

| Path | First request cached/prompt tokens | Identical second request cached/prompt tokens |
| --- | ---: | ---: |
| Direct MTPLX | `3 / 2813` | `2813 / 2813` |
| Current source proxy | `0 / 3609` | `3609 / 3609` |

This proves RAM-compatible reuse for an identical stable prefix. It does not prove the frozen warm
lane, cross-case reuse, quality preservation, or end-to-end wall-time compliance.

## Local validation

- `uv sync --frozen --extra dev --python 3.11`: passed.
- `uv run pytest -q`: passed; `847` tests collected.
- `uv run ruff check .`: passed.
- `uv run mypy src`: passed; `22` source files.
- `uv run python scripts/admission-soak.py`: passed; maximum open upstream connections `2`, RSS delta
  `39,993,344` bytes.
- `git diff --check`: passed.
- Docker smoke: **unavailable**. Docker timed out resolving the pinned
  `docker/dockerfile:1.7` frontend before the repository build; a single pull retry then stalled in
  the local credential helper and was interrupted. This is not a container-runtime pass.

## Remaining blockers

- Build and sign a fresh exact ARM64 image from the reviewed merge and obtain green main CI.
- Add a durable qualification-owned shadow sink and approved promotion authority for broader Local
  Projection and the intervention fast path; run their frozen model-backed agreement corpora.
- Publish/version the authoritative MTPLX combined-capability implementation and pass native tools,
  strict terminal JSON, reasoning/tool transcript, cache, SSE, and direct/proxy parity preflight.
- Produce true TTFT evidence or retain the matched TTFT gate as unavailable.
- Freeze a new manifest and run the complete thirteen-instance campaign, all six cold/warm pairs,
  reconciliation, privacy scan, exact-image operational matrix, rollback, and final two-axis review.

Until those blockers clear, no optimized latency, promotion, combined-mode, fast-path, or WebSocket
claim is authorized.
