# AEON 27B historical-parity proxy result — 2026-08-20

Status: **CONTROLLED DEPLOYMENT AUTHORIZED FOR THE EXACT ARTIFACT; FROZEN PROMOTION FAILED**

The maintainer authorizes controlled deployment of the exact evaluated artifact under a documented
latency exception. This does not convert failed frozen gates into passes or authorize a stable/public
release, tag, package, or registry publication.

The replacement Harness Proxy produced a clear, repeated quality benefit with the pinned AEON 27B
model. Across three cold and three proven warm-prefix matched pairs, the direct baseline passed
`99/180` cases (`55.0%`) and the proxy-assisted arm passed `158/180` (`87.8%`): a gain of 59 cases,
or 32.8 percentage points. The proxy won all six pairs.

This is a historical-parity experiment, not a passing v1 promotion qualification. It intentionally
used the earlier AEON sampler at temperature `1.0`; the frozen v1 promotion plan specifies
temperature `0.0`. Full-agentic p95 wall time also exceeded the frozen `125%` ceiling in both cache
lanes. Four paired positions passed direct and failed through the proxy, and the benchmark rows do
not designate a critical-case subset. No deployment follows automatically from this result; the
named controlled deployment is a later maintainer-owned exception.

This report is an allowlist-only derivative. Raw prompts, transcripts, generated text, tool
arguments or results, credentials, principal data, private endpoints, case identifiers, and
host-local paths remain outside Git.

## Immutable public contract

| Component | Pinned value |
|---|---|
| Proxy source | `75424328ce0dc0bcef6171b42e390c5ba8559471` |
| Source tree | `8badf7b5d751b071999e56a9be4ac6800ed99be6` |
| Main CI | [run 32413338369](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/runs/32413338369) |
| CI artifact SHA-256 | `eb57b145cb47031d726ab76b78fb86ce5847342548c494f903b6b9cc9e1104ab` |
| OCI archive SHA-256 | `07ce33a4159c62cf210c759ac6b508795f1a5bdc2049f0c23ffc4fb3a6a86554` |
| OCI root digest | `sha256:c673ec73ffded8d28200f6157b696fb451735a3416a55407e686587150fe4230` |
| ARM64 manifest | `sha256:e4500ee4da96b3eae01d8da004347cab2d00b33933ab3333ffaa317a4a899219` |
| Private run-manifest SHA-256 | `d36aa0af05d9e2e795fc01d7a4cf65098ece39f9d652ac276f29d14dee3ab391` |
| Campaign-outcome SHA-256 | `c3c705b16aa4ffd9ac8dddf356f216782c1e84d9489046a28a9a67e1bb5410b9` |
| Benchmark | Shiftedx Bench `0.5.1`, revision `335e6694e4aec13e9370af8a993d8c8f14d7ffb5` |
| Benchmark source tree | `24f8c428b32933c6839e48dcd2f5fd5d051300b2` |
| Model | `Shiftedx/qwen3.8-27b-aeon-ultimate-uncensored-attention8-bf16recurrence-vision-mtplx` |
| Model revision | `b5a54ea5d7745b6ddada238f83b66d63c979b9a5` |
| Safe model-identity digest | `24dadb0168adc36bce18ac72d8f83ee23eae409e674af702cdd1826cb96ad46b` |
| Runtime | MTPLX `2.7.1`, native MTP depth 3, `turbo`, SSD session cache off |
| Generation | temperature `1.0`, top-p `0.95`, top-k `20`, thinking on, reasoning effort `medium`, 1,024-token budget |

The retained CI artifact passed provenance verification against the repository's `main` workflow,
source commit, and GitHub-hosted runner policy. The imported image was Linux ARM64 and ran as the
declared non-root user. Model identity, runtime package, launch-vector, health, settings, and cache
evidence were checked before and after each treatment through the private qualification gate.

## Public evidence map

- [Evaluated source commit](https://github.com/shiftedx/shiftedx-agent-harness-proxy/commit/75424328ce0dc0bcef6171b42e390c5ba8559471)
- [Authoritative CI run and retained release-candidate artifact](https://github.com/shiftedx/shiftedx-agent-harness-proxy/actions/runs/32413338369)
- [Reproducible benchmark and qualification commands](../docs/benchmarking.md)
- [Frozen v1 gates and evidence requirements](v1-qualification-plan.md)
- [Production operation and rollback procedure](../docs/operator-runbook.md)
- [Policy and public error contract](../docs/policy.md)

The CI run's retained artifact contains the release manifest, CycloneDX SBOM, scan outputs, and
SLSA provenance attestation. GitHub does not provide those authenticated, expiring artifact members
as stable public file URLs, so this report binds the artifact, OCI archive, image manifests, source,
and run by their public identifiers and digests above. That limitation is not converted into a
promotion pass.

## Experiment design and integrity

- Both arms used Shiftedx Bench's `baseline` control profile. The direct arm did not use the
  in-process harness; the proxy arm received the harness policy.
- The frozen `expanded` set contained 30 cases in one fixed order. Three cold and three warm-prefix
  pairs produced 180 scored rows per arm, 360 total, with direct always preceding proxy.
- One preflight plus twelve scored treatments used thirteen distinct model-server instances.
- Cold treatments used fresh zero-request instances without a prime. Each warm-prefix treatment
  recorded and validated its own exact-payload prime before scoring.
- The unscored paired preflight passed native tool acquisition, phase and request-contract parity,
  no-tool terminal handling, schema validation, credential isolation, and accounting checks.
- The immutable campaign chain sealed 13 of 13 events as passed. All rows from this campaign are
  retained; no failed score was discarded or selectively rerun.
- One pre-action launcher liveness check was invalidated before any model request, supervisor
  action, or campaign artifact. The retained campaign began only after the fresh instance was
  verified healthy.

## Quality result

| Lane / pair | Direct | Proxy | Proxy net |
|---|---:|---:|---:|
| Cold 1 | 17 / 30 | 27 / 30 | +10 |
| Cold 2 | 16 / 30 | 26 / 30 | +10 |
| Cold 3 | 16 / 30 | 25 / 30 | +9 |
| **Cold total** | **49 / 90** | **78 / 90** | **+29** |
| Warm-prefix 1 | 19 / 30 | 29 / 30 | +10 |
| Warm-prefix 2 | 16 / 30 | 25 / 30 | +9 |
| Warm-prefix 3 | 15 / 30 | 26 / 30 | +11 |
| **Warm-prefix total** | **50 / 90** | **80 / 90** | **+30** |
| **Overall** | **99 / 180 (55.0%)** | **158 / 180 (87.8%)** | **+59 (+32.8 pp)** |

The complete per-treatment public ledger is below. It uses the same percentile and throughput
definitions as the aggregate performance section.

| Lane / pair | Treatment | Passed / total | Wall p50 / p95 / p99 (s) | TTFT p50 / p95 / p99 (s) | Weighted decode tok/s | Model turns |
|---|---|---:|---|---|---:|---:|
| Cold 1 | Direct | 17 / 30 | 13.753 / 39.133 / 46.074 | 1.988 / 2.751 / 2.775 | 43.511 | 103 |
| Cold 1 | Proxy | 27 / 30 | 16.356 / 37.911 / 38.850 | 2.256 / 2.915 / 2.919 | 44.770 | 84 |
| Cold 2 | Direct | 16 / 30 | 11.923 / 34.138 / 35.086 | 1.986 / 2.630 / 2.641 | 44.430 | 100 |
| Cold 2 | Proxy | 26 / 30 | 22.149 / 63.318 / 69.948 | 2.353 / 3.039 / 3.040 | 42.939 | 86 |
| Cold 3 | Direct | 16 / 30 | 14.086 / 34.866 / 37.136 | 2.040 / 2.737 / 2.750 | 42.045 | 97 |
| Cold 3 | Proxy | 25 / 30 | 14.838 / 70.932 / 73.856 | 2.314 / 2.997 / 3.001 | 44.228 | 79 |
| Warm-prefix 1 | Direct | 19 / 30 | 11.746 / 27.702 / 30.491 | 1.822 / 2.157 / 2.569 | 42.712 | 98 |
| Warm-prefix 1 | Proxy | 29 / 30 | 16.270 / 39.204 / 41.350 | 2.112 / 2.656 / 3.038 | 42.227 | 86 |
| Warm-prefix 2 | Direct | 16 / 30 | 11.924 / 24.317 / 28.392 | 1.780 / 2.172 / 2.566 | 43.044 | 94 |
| Warm-prefix 2 | Proxy | 25 / 30 | 14.785 / 35.491 / 55.352 | 2.108 / 2.654 / 3.038 | 43.483 | 86 |
| Warm-prefix 3 | Direct | 15 / 30 | 11.820 / 25.648 / 30.083 | 1.893 / 2.226 / 2.657 | 41.738 | 96 |
| Warm-prefix 3 | Proxy | 26 / 30 | 15.612 / 25.879 / 41.338 | 2.114 / 2.640 / 3.045 | 42.682 | 87 |

Paired positions comprised 63 proxy-only gains, four direct-only regressions, 95 cases both arms
passed, and 18 cases both arms failed. All four direct-only regressions occurred in cold pairs; the
warm-prefix pairs had none. Because the benchmark output has no critical-case marker, this report
does not relabel those regressions or claim that a designated critical subset had zero regressions.

Historical results are context, not thresholds or rows in this campaign:

| Historical corpus | Direct baseline | In-process harness | Context-only net |
|---|---:|---:|---:|
| Expanded plus repository sets | 63 / 102 | 97 / 102 | +34 cases |
| Expanded subset | 54 / 90 | 86 / 90 | +32 cases (+35.6 pp) |

The historical full corpus included four repository cases that are not part of this campaign; its
in-process treatment also differs from the network-proxy treatment. On the common expanded corpus,
this proxy experiment's 32.8-point uplift retains about 92% of the historical 35.6-point uplift,
while keeping policy outside the model-serving process. Neither historical score is used as a
promotion threshold or merged into the replacement result.

## Latency and decode throughput

Percentiles use the predeclared deterministic lower-rank projection
`sorted[floor((n - 1) * p)]`. Weighted decode throughput is
`sum(completion_tokens) / sum(completion_tokens / decode_tokens_per_second)` across retained model
turns. Wall time describes complete scored cases, including benchmark failures; a failed score is
not treated as a transport failure.

| Lane | Arm | n | Wall p50 / p95 / p99 (s) | TTFT p50 / p95 / p99 (s) | Weighted decode tok/s |
|---|---|---:|---|---|---:|
| Cold | Direct | 90 | 13.365 / 37.136 / 49.004 | 1.987 / 2.750 / 3.328 | 43.273 |
| Cold | Proxy | 90 | 16.701 / 63.318 / 107.649 | 2.273 / 3.033 / 3.247 (`n=88`) | 43.879 |
| Warm-prefix | Direct | 90 | 11.877 / 28.392 / 33.885 | 1.822 / 2.566 / 2.787 | 42.502 |
| Warm-prefix | Proxy | 90 | 15.612 / 41.338 / 66.878 | 2.112 / 3.038 / 3.062 | 42.815 |

| Frozen performance gate | Result | Verdict |
|---|---|---|
| Full-agentic p95 `<=125%` of direct | Cold `170.5%`; warm-prefix `145.6%` | **Fail** |
| Weighted decode throughput `>=90%` of direct | Cold `101.4%`; warm-prefix `100.7%` | Pass |
| Mean upstream calls `<=2.0` | `623 / 586 = 1.0631` | Pass |
| Every request `<=MAX_UPSTREAM_CALLS` | Observed maximum `5`; configured cap `7` | Pass |

The proxy preserved model decode speed; the failed wall-time gate reflects additional agentic work
and long-tail policy corrections, not a slower decoder. Pass-through-only matched wall/TTFT was not
separately retained, so that narrower gate is unavailable rather than inferred from these totals.

## Request and model-operation reconciliation

| Lane | Downstream | Upstream | Mean amplification | Corrections | Repeated-phase retries | Duplicate / stall blocks | Local projections | Proxy errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Cold | 291 | 310 | 1.0653 | 3 | 13 | 4 / 3 | 36 | 2 |
| Warm-prefix | 295 | 313 | 1.0610 | 4 | 10 | 7 / 6 | 36 | 0 |
| **Total** | **586** | **623** | **1.0631** | **7** | **23** | **11 / 9** | **72** | **2** |

Every proxy treatment's reconciliation artifact passed every typed identity, sequence, phase,
correction, projection, error, and model-operation check. The 623 scored model attempts plus three
warm proxy primes reconcile to 626 server-completed operations. Model-facing scored phases totaled
537 acquisitions and 86 finalizations. The two cold proxy failures were bounded and retained; all
180 proxy benchmark rows were scored.

## Exact-image operational matrix

The operational matrix used the same signed ARM64 candidate with a dedicated scripted upstream.
The final labelled run passed every executed non-rollback lane and verified scoped cleanup. Earlier
private driver attempts that lacked a required reset, concurrency overlap, or direct header
observation are retained as test-driver failures and do not contribute results.

| Gate | Safe result | Verdict |
|---|---|---|
| Proxy-only latency | 50/50; p50 `5.142 ms`, p95 `7.783 ms`, p99 `8.353 ms`, max `9.120 ms` | Pass |
| Steady load | 48/48 expected successes; p95 `55.042 ms`; scripted upstream max active `4` | Pass |
| Saturated overload | 4 accepted and 4 rejected with 429; all rejections had numeric `Retry-After`; upstream max active `4` | Pass |
| Upstream 429 | Bounded 429 `upstream_rate_limited` | Pass |
| Upstream 500 | Bounded 502 `upstream_server_error` | Pass |
| Malformed upstream JSON | Bounded 502 `upstream_malformed_json` | Pass |
| Timeout profile | With isolated 1s upstream / 2s total overrides: bounded 504 `upstream_timeout` in `1.015 s` | Pass |
| Downstream disconnect | Cancellation counter advanced exactly once | Pass |
| Readiness loss/recovery | Loss observed in `0.006 s`; ready and successful traffic restored in `0.010 s` | Pass |
| Graceful restart | Accepted in-flight request returned 200; replacement ready and smoke-verified in `2.350 s` | Pass |
| Container RSS | `47,647,293` to `47,930,408` bytes (`+0.59%`), both about 45.5 MiB | Pass |
| Rollback | Manifest names no approved predecessor; no predecessor was started | **Unavailable** |

After capture, the candidate container, scripted upstream, and all owned labelled resources were
absent, and every dedicated proxy, observer, and model port was clear. The rollback gate was kept
fail-closed rather than selecting an unapproved local image.

## Automated and synthetic evidence

At the evaluated source, the frozen environment passed 754 tests, Ruff, strict source mypy, the
real-TCP admission soak, and Docker smoke. A fresh 5,000-request scripted-upstream measurement had
proxy-only p50 `0.0146 ms`, p95 `0.0151 ms`, and observed maximum `0.1265 ms`; the separately
retained reference artifact reports p95 `0.0081 ms` and maximum `0.1718 ms`. These measurements
exclude network and inference and therefore are not end-to-end latency claims.

The additional in-process admission soak proved bounded admission and upstream concurrency,
numeric `Retry-After`, cleanup to zero active work, and bounded local RSS under its unit-level test
configuration. It is corroboration rather than a substitute for the exact-image matrix above.

## Gate ledger and limitations

| Gate | Verdict | Evidence or limitation |
|---|---|---|
| Complete three-pair cold and warm-prefix campaign | Pass | 13/13 immutable events; 360 scored rows |
| Strict positive quality impact | Pass | 158/180 proxy vs 99/180 direct; proxy won 6/6 pairs |
| No critical-case regression | **Unavailable** | Four direct-only regressions; no critical marker in benchmark rows |
| Policy/security correctness | Pass in executed qualification | Preflight and all six typed reconciliations passed; no forbidden public data retained |
| Proxy-only p95 `<15 ms`, p99 `<30 ms` | Pass | Exact-image p95 7.783 ms; p99 8.353 ms |
| Pass-through added wall/TTFT | **Unavailable** | A distinct no-retry/no-projection matched subset was not retained |
| Full-agentic p95 `<=125%` direct | **Fail** | Cold 170.5%; warm-prefix 145.6% |
| Weighted decode throughput `>=90%` direct | Pass | Cold 101.4%; warm-prefix 100.7% |
| Upstream amplification | Pass | Mean 1.0631; maximum 5 of 7 |
| Production-capacity load/fault/resource/recovery/restart | Pass in the exact-image scripted matrix | 48/48 steady; bounded overload/faults; recovery and restart under 30s; RSS +0.59% |
| Rollback `<60 s` | **Unavailable** | The historical-parity manifest names no approved predecessor image |
| Frozen v1 temperature-0 contract | **Not applicable** | This separately named experiment used historical AEON temperature 1.0 |

Repeated trials use the same fixed 30-case set, so the 180 rows are not represented as 180
independent draws. Pair-level consistency (six proxy wins in six pairs), per-pair denominators, and
the four paired regressions are reported instead of an independence-based significance claim.

Earlier private campaigns remain retained and contribute no rows to this result. Their terminal
categories covered preflight credential validation, runtime inspection, preflight action, and two
evidence-gate defects. The correction-accounting and correction-run parity defects discovered by
those attempts were fixed and reviewed before the fresh r6 manifest was frozen.

## Maintainer decision

The evidence supports a positive-impact claim for the named AEON historical-parity experiment: the
proxy recovers nearly all of the previously observed in-process harness uplift while preserving
decode throughput and bounded request amplification.

It does **not** support frozen-v1 or stable/public promotion. The experiment differs from the
frozen temperature-0 promotion contract, misses the full-agentic latency gate in both cache lanes,
cannot classify four paired regressions for criticality, lacks a separately retained pass-through
subset, and has no approved rollback target. The existing failed v1 result remains historical
evidence rather than being rewritten.

Decision: **authorize controlled, authenticated self-hosted deployment of proxy source
`75424328ce0dc0bcef6171b42e390c5ba8559471` and its signed ARM64 OCI root recorded above, under the
latency exception.** Require the tested MTPLX `phase_split` contract, a canary, end-to-end latency
monitoring, and an operator-approved rollback target before production traffic. This is not
production certification or a stable/public release. The handoff decision is tracked in
[issue #19](https://github.com/shiftedx/shiftedx-agent-harness-proxy/issues/19).
