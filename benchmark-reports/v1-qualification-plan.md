# v1 production qualification plan

Status: **pre-registered and qualification-ready**

This document fixes the evidence rules and promotion gates before the first model-backed request.
It is a run plan, not a claim that production qualification has already passed. A complete sanitized
report will supersede it after the coordinated qualification window; this plan remains in history so
reviewers can verify that thresholds were not changed after results were known.

## Qualification target

- Proxy surface: authenticated, non-streaming v1 Chat Completions
- Harness profile: `shiftedx-harness-v1`
- Benchmark: Shiftedx Bench revision
  `335e6694e4aec13e9370af8a993d8c8f14d7ffb5`
- Served model: `ornith-1.5-35b-a3b-abliterated`
- Artifact: `ornith-1.5-35b-a3b-abliterated-attention8-bf16recurrence-vision-mtplx`
- Runtime: MTPLX `2.9.0`, `sustained` profile, native MTP depth `1`; serial scheduler, `agent`
  batching, SSD session cache enabled, and paged-KV quantization disabled
- Public artifact identities: `config.json` `60717e3978992f7f967abfe7c100405b667d7bf48f5084affd9f933326d31750`;
  `tokenizer_config.json` `5186f0defcd7f232382c7f0aebcd2252d073bb921ab240e407b7ae8745d2b29b`;
  `chat_template.jinja` `182e77dd83bd8e9ca818b240b82e28f243762cd5dda32e6eef327df7b1cd107e`;
  `mtplx_runtime.json` `0f4619009ce61b168091d891c2a204ba960703f993229390609118b8e84478b3`;
  `model.safetensors.index.json` `5ea79f00036b670d13ef98ae1a4d597437921cdcf6896d1e95c151ead09b24ba`
- Sampler profile: `ornith-productization-v1` — temperature `1.0`, top-p `0.95`, top-k `20`,
  thinking enabled, reasoning effort `medium`, and `max_tokens=8192`; this immutable profile
  requires `--ssd-session-cache=on` in the model launch contract
- Treatments: direct upstream baseline and proxy-assisted, both using the benchmark runner's
  `baseline` control profile
- Trials: at least three complete matched pairs for every declared lane

A different model, sampler, profile-bound cache mode, reasoning mode, benchmark revision, or treatment
contract requires a reviewed plan revision committed before trial 1. It may not be changed in response to results.

## Immutable run manifest

Before any model-backed request, the window owner records one immutable manifest containing:

- proxy source commit, OCI digest, OCI archive checksum, lock digest, base-image digest, SBOM,
  provenance, and green CI URL;
- benchmark revision and package fingerprint;
- model weights revision, public model ID, model-server/runtime revision, complete launch arguments,
  tokenizer/chat-template revision, and reasoning parser;
- sampler, context window, output/token budgets, per-case timeout, case order, tool schemas, and
  harness configuration digest;
- host CPU/GPU/accelerator, RAM, operating system, runtime versions, power profile, ingress topology,
  container limits, and monitoring sources;
- cache implementation/configuration and the exact method used to establish and prove cold and warm
  state;
- trial identifiers, coordinated window, named owner, raw-evidence location, retention policy, and
  the approved rollback target.

Credentials, private endpoints, raw prompts, model output, tool arguments, and host-local paths stay
in the private manifest. The public report records their presence and verification method without
copying their values.

## Non-negotiable correctness and security gates

All of these must be zero across every trial and fault lane:

- critical policy regressions;
- downstream or upstream credential/header leaks;
- duplicate released Mutations in one Epoch;
- partial release of a Withheld Batch;
- released Mutation after unresolved Verification failure;
- fabricated Receipt or Local Projection provenance;
- untrusted harness disablement, protected-role override, or cache-namespace control;
- raw prompt, transcript, tool argument, model output, or tenant identifier in logs, metrics, public
  errors, or published artifacts.

Any violation is an automatic `DO NOT PROMOTE`, regardless of aggregate quality or speed.

## Frozen numeric promotion gates

| Area | Promotion gate |
|---|---|
| Trial completeness | At least 3 complete matched direct/proxy pairs per cold/warm lane; no discarded or selectively rerun row |
| Quality | Aggregate proxy-assisted passed-case count is at least the direct baseline count, with no critical-case regression |
| Proxy-only latency | Scripted-upstream processing p95 `< 15 ms` and p99 `< 30 ms` |
| Pass-through latency | For responses requiring no policy retry or Local Projection, added p95 wall time and TTFT are each no more than the larger of `15 ms` or `5%` of the matched baseline |
| Policy-benefit performance | Across the preregistered policy-benefit and recovery cohorts, proxy p95 wall time to a valid outcome is `<=80%` of the matched direct p95; failed outcomes remain in the denominator |
| Full agentic latency | Aggregate p95 wall time to final valid outcome is no more than `125%` of matched baseline in each cache lane |
| Decode throughput | Weighted decode throughput is at least `90%` of matched baseline in each cache lane |
| Upstream amplification | Mean upstream calls per downstream request `<= 2.0`; every request remains `<= MAX_UPSTREAM_CALLS` |
| Steady-load reliability | At or below declared capacity, at least `99%` of requests receive the expected successful public contract, excluding deliberately injected upstream failures |
| Overload contract | `100%` of excess requests receive the documented bounded 429/503/504 family and required numeric `Retry-After`; no accepted-work ceiling is exceeded |
| Resource envelope | No OOM/restart; peak container RSS `<= 460 MiB` under the 512 MiB Compose limit; no sustained upward RSS trend greater than `10%` between first and final steady-state windows |
| Concurrency | Downstream active `<= ADMISSION_LIMIT`, upstream active `<= CONCURRENCY_LIMIT`, per-principal active `<= PRINCIPAL_CONCURRENCY_LIMIT`, and parsed-request handling stays within `SERVER_CONNECTION_LIMIT` |
| Recovery | Readiness and successful traffic recover within `30 s` after an injected transient fault is removed |
| Graceful restart | No accepted response is truncated or duplicated; service returns ready within `30 s` |
| Rollback | Previously approved image is restored, ready, and smoke-verified within `60 s` after rollback begins |

The public report includes p50/p95/p99, sample counts, confidence/variance notes, throughput, TTFT,
RSS, open connections, active/queued work, error/rejection counts, recovery time, and every failed
gate. A hard container limit is not itself proof of a passing resource result.

The policy-benefit performance cohort is fixed before scoring: tasks with duplicate, stall,
verification, terminal-schema, or repeated-failure recovery pressure. Ordinary tool-use and
pass-through tasks remain separate cohorts and cannot be moved into or out of this cohort after
results are observed. A faster invalid answer is not a valid outcome.

The immutable private campaign manifest binds this cohort before trial 1 through its allowed
scenario-family list (`failed_search_recovery`, `repair_loop`, `stale_evidence`,
`structured_status`, and `wrong_path_recovery`), canonical selected-case-ID hash
`73c007092312a9b187b66c67fd73e4d343641696ab59aafc56b36d2284ff1fc1`, and selected-case count
`22` against frozen expanded revision `335e6694e4aec13e9370af8a993d8c8f14d7ffb5`. At terminal
completion, every direct/proxy scored ledger in all three cold and all three warm-prefix pairs must
contain the same bound cohort with `passed: true` and finite positive runner `telemetry.wall_s`.
The campaign computes p95 with the frozen sorted index `(n - 1) * 95 // 100` from all twelve
matched treatment rows per selected case and passes only when proxy p95 is `<=80%` of direct p95.
A missing, malformed, failed, zero-sample, or
mismatched row is a terminal failed gate, never a reason to remove it from the calculation. The
published campaign outcome contains hash/count and aggregate timing only.

## Cache lanes

Cold and warm-prefix results are separate datasets.

- **Cold** requires an approved cache reset, isolated fresh model-server instance, or another
  server-authoritative method proving that the evaluated prefix was not resident.
- **Warm-prefix** requires one recorded prime request followed by server-authoritative cache metrics
  proving effective reuse of the same compatible prefix.
- A client guess, repeated request, or lower TTFT alone is not proof of cache state.
- If the operator cannot establish or observe either state, that lane is blocked and cannot be
  relabeled or merged into the other lane.

## Execution sequence

1. Approve the coordinated window and immutable run manifest.
2. Verify the retained OCI checksum, provenance subject, SBOM, image digest, and source commit.
3. Start the exact proxy image and approved model runtime without rebuilding or tuning either.
4. Run preflight authentication, readiness, credential-isolation, and the required hash-only paired
   tool-acquisition/no-tool-terminal preflight. It must prove native tool calls, direct/proxy
   phase/fingerprint parity, proxy phase-counter deltas, and terminal-schema validation before any
   scored row is written.
5. For each cold/warm lane, run three complete pairs in the fixed order: direct baseline, then
   proxy-assisted. Keep model/runtime/sampler/task contracts identical.
6. Run steady load at declared capacity and overload above it while collecting client, proxy,
   ingress, container, and model-server measurements.
7. Against a controlled production-like target, exercise upstream 429/5xx/timeout, malformed
   response, downstream disconnect, readiness loss/recovery, and graceful restart. Do not inject
   faults into an unrelated shared service.
8. Restore the approved prior image and complete the timed rollback smoke.
9. Close the private evidence set, generate allowlist-only public ledgers, and independently scan
   every proposed public file for secrets, prompts, transcripts, model output, tool arguments, host
   paths, and tenant identifiers.
10. Publish the complete sanitized report and record `PROMOTE` or `DO NOT PROMOTE` without changing
    thresholds or omitting failures.

## Public report contents

The final report contains:

- immutable public provenance and run-contract fields;
- one row for every trial/treatment/lane and a complete aggregate;
- quality, policy, latency, throughput, amplification, load, fault, recovery, and rollback results;
- declared limitations and any unavailable measurement;
- links to reproducible commands, CI, manifests, SBOM/provenance, and the operator runbook;
- the named maintainer's explicit promotion decision and rationale.

Raw benchmark-source output is private and is never treated as a sanitizer. Local Projection data
may be published only through `scripts/summarize_public_projection_accounting.py`, whose output is
an explicit allowlist.

## Failure policy

A missed gate is reported as a failure, not converted into a softer metric after the run. A failed
trial is retained and counted. Infrastructure invalidation is allowed only when the recorded
manifest proves the treatment contract was not executed; the invalidation and complete rerun are
both disclosed. Model tuning, threshold changes, selective case reruns, or hidden prompt/fixture
changes require a new candidate and a new pre-registration commit.
