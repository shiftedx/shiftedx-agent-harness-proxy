# v1 production qualification result — 2026-08-20

Status: **DO NOT PROMOTE**

The release candidate is operationally well-bounded, but it did not produce a usable agent outcome
through the proxy with the frozen model and evaluation adapter. The quality, full-agentic latency,
decode-throughput, upstream-amplification, observability, and trial-completeness gates did not pass.
No stable package, image, or tag was published.

This report is an allowlist-only derivative. Raw prompts, transcripts, model output, tool arguments,
credentials, tenant identifiers, private endpoints, and host-local paths remain outside Git.

## Immutable public contract

| Component | Pinned value |
|---|---|
| Proxy source | `3d8805c1d96d0790526a333ca5074eea20b16b72` |
| Source tree | `b598aa55ce6548e44e975d0533b51ce4f8a3a34f` |
| ARM64 OCI manifest | `sha256:4a5ec24b8ab81f3245e89dec8b9d985f2ebb736ed2794ed504eacab860cf49d4` |
| Multi-architecture OCI index | `sha256:6bb6dba31cec81e7d27630be77eaa88d1fd922b54b17a00209c46054ffada445` |
| OCI archive SHA-256 | `70ff74dd1e66d93f4689dbb822640a6f27b5bb80418c692a6ad16e57ff769780` |
| CI evidence | [main run 32314958324](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/runs/32314958324), artifact `9387753153` |
| Benchmark | Shiftedx Bench `0.5.1`, revision `335e6694e4aec13e9370af8a993d8c8f14d7ffb5` |
| Model | `Shiftedx/qwen3.8-27b-aeon-ultimate-uncensored-attention8-bf16recurrence-vision-mtplx` |
| Model revision | `b5a54ea5d7745b6ddada238f83b66d63c979b9a5` |
| Runtime | MTPLX `2.7.1`, native MTP depth 3, `turbo`, paged KV quantization off |
| Generation | temperature `1.0`, top-p `0.95`, top-k `20`, thinking on, reasoning effort `medium` |
| Host class | Apple M4 Max, 64 GiB unified memory, macOS 26.5.1 |

The exact retained model snapshot passed all 30 immutable Git-blob/LFS identities. The model
repository's published `SHA256SUMS` has one stale `README.md` entry; the pinned README Git blob and
downloaded bytes match, and every runtime, tokenizer, template, language-weight, vision-weight, and
MTP identity passed. This metadata defect did not cause the qualification failure.

The host also ran an unrelated, mostly idle Docker stack. It was not stopped or altered. This is a
timing-variance limitation, not an explanation for the deterministic quality result.

## Execution integrity

The first window was invalidated before a complete pair existed: a bounded proxy `502` caused the
old paired runner to raise before writing its failed row. The incomplete window remains private and
does not contribute any result. [PR #30](https://github.com/shiftedx/shiftedx-agent-harness-proxy/pull/30)
made transport failures stable, prompt-free failed rows and proved that the runner continues in
fixed case order. Window 2 then restarted from cold pair 1, direct row 1, using the new exact image.

All 204 scored cold rows are present: three pairs, 34 direct plus 34 proxy rows per pair. There were
no selective case reruns. The warm-prefix lane was not run after the three-pair cold aggregate made
promotion impossible. That decision is disclosed and means the trial-completeness gate also fails;
the missing lane is not relabeled as cold or inferred from repeated requests.

## Model-backed cold results

Both treatments used the benchmark runner's `baseline` control profile. Direct ran against a fresh
model-server process; proxy ran against a separately fresh process. Persistent cache was off and
warmup tokens were zero before every measured treatment.

| Pair | Treatment | Passed / total | Client HTTP failures | Wall p95 (s) | TTFT p95 (s) | Weighted decode tok/s |
|---:|---|---:|---:|---:|---:|---:|
| 1 | Direct | 2 / 34 | 0 | 6.712 | 2.563 | 40.51 |
| 1 | Proxy | 0 / 34 | 34 | 49.817 | unavailable | unavailable |
| 2 | Direct | 2 / 34 | 0 | 5.264 | 2.559 | 39.66 |
| 2 | Proxy | 0 / 34 | 34 | 57.748 | unavailable | unavailable |
| 3 | Direct | 2 / 34 | 0 | 4.903 | 2.761 | 35.64 |
| 3 | Proxy | 0 / 34 | 34 | 59.373 | unavailable | unavailable |
| **Aggregate** | **Direct** | **6 / 102** | **0** | **5.264** | **2.559** | **38.65** |
| **Aggregate** | **Proxy** | **0 / 102** | **102** | **56.492** | **unavailable** | **unavailable** |

Every proxy row ended in the bounded `harness_retry_exhausted` public contract. Private
server-authoritative logs recorded 288 model generations for 102 downstream proxy requests, or
mean amplification `2.82`; the frozen mean gate was `<= 2.0`. No prompt or generated text from
those logs is included here.

## Operational results

Operational probes used the same ARM64 candidate image and a dedicated scripted upstream. Each
phase was restarted below the configured 60-request principal rate budget. An initial 200-request
attempt is retained privately but excluded from latency/load claims because the configured rate
limit correctly rejected requests after the first 60.

| Gate | Result | Verdict |
|---|---|---|
| Proxy-only latency | 50/50 successful; p50 `1.78 ms`, p95 `2.64 ms`, p99/max `26.58 ms` | Pass |
| Steady load | 48/48 successful; scripted-upstream max active `4` | Pass |
| Saturated overload | 4 accepted, 4 rejected with numeric `Retry-After`; upstream accepted exactly 4 | Pass |
| Upstream 429 | Downstream 429 `upstream_rate_limited`, numeric `Retry-After` | Pass |
| Upstream 500 | Downstream bounded 502 `upstream_server_error` | Pass |
| Malformed upstream JSON | Downstream bounded 502 `upstream_malformed_json` | Pass |
| Timeout fault profile | With declared 1s upstream/2s total fault overrides: bounded 504 at `1.05 s` | Pass |
| Downstream disconnect | Cancellation counter advanced exactly once | Pass |
| Readiness loss/recovery | Bounded 502 while absent; successful probe immediately after restoration | Pass |
| Graceful restart | In-flight 1.5s request returned 200; healthy again in `6.79 s` | Pass |
| Rollback | Prior reviewed ARM64 image healthy and smoke-verified in `5.75 s` | Pass |
| Observed container RSS | Approximately 44–46 MiB; no OOM or restart | Pass with sampling limitation |

The scripted upstream's 25ms delay is included in the steady-load p95 and is not reported as proxy
overhead. Resource samples were periodic rather than continuous; the hard 512 MiB limit and sampled
peak alone are not treated as a complete proof of an unobserved peak.

## Gate ledger

| Frozen gate | Verdict | Evidence |
|---|---|---|
| Three complete pairs per cold and warm lane | **Fail** | Three cold pairs complete; warm-prefix lane not run after decisive cold failure |
| Proxy quality at least direct | **Fail** | 0/102 proxy vs 6/102 direct |
| No critical policy/security regression | Pass in executed lanes | No duplicate mutation, partial batch, false provenance, credential/header leak, or public raw-data leak observed |
| Proxy-only p95 `<15 ms`, p99 `<30 ms` | Pass | p95 2.64 ms, p99 26.58 ms |
| Pass-through wall and TTFT overhead | **Fail / unavailable** | Scripted wall overhead passed; matched TTFT could not be measured for failed model-backed proxy rows |
| Full-agentic p95 `<=125%` baseline | **Fail** | 56.492s proxy vs 5.264s direct; allowed ceiling 6.580s |
| Decode throughput `>=90%` baseline | **Fail / unavailable** | No successful proxy outcome supplied comparable decode telemetry |
| Mean upstream amplification `<=2.0` | **Fail** | 288 authoritative generations / 102 downstream requests = 2.82 |
| Steady reliability `>=99%` | Pass for scripted capacity lane | 48/48 expected successes |
| Overload contract | Pass | All four excess requests rejected with bounded 429 and numeric `Retry-After` |
| Resource envelope | Pass with limitation | Sampled 44–46 MiB, no OOM/restart; periodic sampling disclosed |
| Concurrency ceilings | Pass in scripted lane | Upstream observed maximum active 4 |
| Recovery and graceful restart `<30 s` | Pass | Recovery immediate after upstream restoration; restart healthy in 6.79s |
| Rollback `<60 s` | Pass | 5.75s including healthy smoke |

## Observability defect

After cold pair 1, exported metrics showed one downstream request, two upstream calls, and 35
errors, while the same window contained the smoke plus 34 failed scored requests and 96
server-authoritative generations. The aggregate request and upstream-call counters therefore omit
failed transactions/attempts and cannot support production amplification or request-rate claims.
The report uses server-authoritative generation counts for the failed model-backed lane and treats
the metrics discrepancy as a release blocker.

## Required remediation

1. Make tool acquisition compatible with the frozen standard `response_format` contract on this
   MTPLX/Qwen model, without weakening downstream terminal-schema validation or treating expected
   answers as policy input.
2. Count every admitted downstream request and every upstream attempt, including failed and
   cancelled operations; add deterministic tests for failure-path accounting.
3. Build a new exact-image candidate and preregister a new window. Rerun all three cold and three
   proven warm-prefix pairs plus the operational gates; do not reuse these scored rows.
4. Require the maintainer's explicit decision after reviewing the replacement evidence.

Evaluator recommendation: **DO NOT PROMOTE `3d8805c`**. The maintainer's final decision remains
human-owned; absent an explicit `PROMOTE`, this candidate stays unreleased.

Later replacement work and the completed temperature-1.0 historical-parity campaign are reported
separately in the
[`AEON historical-parity result`](aeon-historical-parity-result-2026-08-20.md). That experiment
demonstrates positive quality impact without rewriting this result or superseding the frozen
temperature-0 promotion contract.
