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
   corrections, projections, **upstream-model** prompt/completion tokens, wall time, weighted
   decode throughput, and upstream calls per downstream request. Report client-input tokenization
   separately only when it is actually available; a Local Projection never estimates it.
   Reconcile the aggregate proxy upstream-attempt counter to the model server's authoritative
   operation count, including retries and failures; report a zero delta or stop the candidate.
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

Pass authenticated proxy credentials with `--api-key-file`; never put a bearer value directly in
the command line. If the benchmark client cannot obtain a response (for example, a bounded proxy
`502`), the runner writes a failed row with only the exception type, HTTP status when available,
elapsed time, and the ordinary request hash, then continues in fixed case order. It does not copy
the response body into that row. A transport failure is therefore counted instead of aborting the
trial or disappearing from the report.

The public ledger has one row per trial, profile, and cache lane. Each row records the immutable
proxy/model/runtime contract; passed/total cases; emitted and dispatched calls; blocked duplicate
and stall counts; corrections; projections; upstream-model usage; wall time; TTFT; and weighted
decode throughput. It also links the shared run manifest rather than repeating private endpoint or
host data.

Do not publish a benchmark report with missing trials, mismatched revisions, private prompts/raw
model outputs, host paths, API keys, or holdout artifacts.

`scripts/run_paired_agentic_trial.py` writes benchmark-source output and must remain private: it is
not a public export or a sanitizer. To publish only Local Projection accounting from a private JSON
array of **proxy-normalized** completion records, use the separate allowlist-only path:

```bash
uv run scripts/summarize_public_projection_accounting.py \
  --completion-records benchmark-reports/private/completions.json \
  --output benchmark-reports/public-projection-summary.json
```

The summary retains only record count, Local Projection count, avoided immediate upstream calls,
zero upstream-model usage, and unavailable client-input tokenization. It never copies prompt
content, tenant identifiers, transcripts, model names, arbitrary response fields, or credentials.

The latest scripted proxy-only measurement is stored in
[`benchmark-reports/proxy-overhead-2026-08-18.json`](../benchmark-reports/proxy-overhead-2026-08-18.json).
It excludes network and inference and therefore is not an end-to-end latency claim.

Promotion thresholds, cold/warm requirements, load/fault coverage, rollback criteria, and failure
handling are frozen in the
[`v1 qualification plan`](../benchmark-reports/v1-qualification-plan.md). The interrupted 2026-08-17
smoke produced no benchmark row and is retained only as a
[`historical audit note`](../benchmark-reports/historical/paired-benchmark-interruption-2026-08-17.md);
it is not the current release status or a quality result.
