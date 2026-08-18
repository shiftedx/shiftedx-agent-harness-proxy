# Paired agentic benchmark: deferred

Status: **not run; no performance or quality claim**

The first proxy smoke attempt was interrupted by a host crash before any benchmark row was
written. A separate workload was subsequently using the shared MTPLX instance, so the model
server was not relaunched, queried, stopped, or otherwise disturbed. No partial result is treated
as evidence.

The eventual paired run must use:

- benchmark revision `335e6694e4aec13e9370af8a993d8c8f14d7ffb5`;
- model revision `b5a54ea5d7745b6ddada238f83b66d63c979b9a5`;
- the same model server, sampler, reasoning settings, schemas, order, and budgets for both arms;
- at least three complete direct-baseline and three complete proxy-assisted trials;
- an exclusive or explicitly coordinated MTPLX window with host monitoring;
- the benchmark runner's `baseline` control profile in both arms, using
  `scripts/run_paired_agentic_trial.py` to supply the public per-case wire contract.

Raw transcripts belong under ignored `benchmark-reports/private/`. Only a complete sanitized
ledger may replace this deferral notice.
