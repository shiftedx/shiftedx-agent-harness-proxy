# Paired benchmark protocol

Use the immutable public Shiftedx Bench revision
`335e6694e4aec13e9370af8a993d8c8f14d7ffb5` and record the exact proxy commit and image digest.

For each of at least three complete trials:

1. Fix the model revision, model-server revision, sampler, reasoning mode, context, tool schemas,
   case order, and budgets.
2. Run the unchanged baseline directly against the same model server.
3. Run the harness profile through this proxy with complete client transcripts and streaming off.
4. Preserve raw transcripts privately. Publish only sanitized per-case and aggregate ledgers.
5. Report cases passed/total, emitted/dispatched calls, blocked duplicate/stall counts,
   corrections, projections, prompt/completion tokens, wall time, weighted decode throughput,
   and upstream calls per downstream request.
6. Measure proxy-only processing latency around a scripted upstream and report p50/p95 separately
   from network and inference. The initial reference target is p95 under 15 ms, subject to measured
   revision rather than marketing claims.

The immutable benchmark revision does not send its per-case terminal schema or `require_receipt`
field over the OpenAI wire. `scripts/run_paired_agentic_trial.py` imports those public scenario
declarations and adds a standard `response_format` for both treatments. For proxy requests only,
it also adds `x-shiftedx-require-receipt`; the proxy consumes that field before forwarding. This is
an evaluation adapter, not benchmark or proxy policy derived from expected answers. Use
`--proxy-policy` only for the proxy endpoint. The benchmark runner's control profile remains
`baseline` in both treatments so policy is not applied twice.

Use a table like this for each profile and trial:

| Trial | Profile | Proxy commit/image | Model/runtime revisions | Passed | Emitted | Dispatched | Blocked duplicate | Blocked stall | Corrections | Projections | Wall time | Decode tok/s |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | baseline | n/a | pending | pending | pending | pending | 0 | 0 | 0 | 0 | pending | pending |
| 1 | shiftedx-harness-v1 | pending | pending | pending | pending | pending | pending | pending | pending | pending | pending | pending |

Do not publish a benchmark report with missing trials, mismatched revisions, private prompts/raw
model outputs, host paths, API keys, or holdout artifacts.

The latest scripted proxy-only measurement is stored in
[`benchmark-reports/proxy-overhead-2026-08-18.json`](../benchmark-reports/proxy-overhead-2026-08-18.json).
It excludes network and inference and therefore is not an end-to-end latency claim.

The external model-backed comparison is currently deferred after an interrupted smoke attempt;
see
[`benchmark-reports/paired-benchmark-deferred-2026-08-17.md`](../benchmark-reports/paired-benchmark-deferred-2026-08-17.md).
