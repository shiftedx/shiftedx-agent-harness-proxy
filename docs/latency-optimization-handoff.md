# Latency optimization implementation handoff

## Mission

Lead a subagent-driven implementation that preserves the demonstrated AEON quality benefit while
bringing every frozen latency gate to a measured pass. Implement all five workstreams below, merge
the reviewed changes, build a fresh attested candidate, and run one complete final qualification.

Completion means evidence of improvement, not code completion:

- full-agentic p95 wall time is `<=125%` of direct in both cold and warm-prefix lanes;
- matched pass-through added p95 wall time and TTFT each stay within the larger of `15 ms` or `5%`;
- proxy-only p95 remains `<15 ms` and p99 remains `<30 ms`;
- weighted decode throughput remains `>=90%` of direct in each lane;
- mean upstream calls remain `<=2.0` and every request remains within `MAX_UPSTREAM_CALLS`;
- proxy quality is `>=158/180`, retains an uplift of at least `59` cases over its paired direct arm,
  wins all six pairs, and has no predeclared critical regression;
- every request, phase, correction, retry, projection, cache observation, and model operation
  reconciles with zero unexplained delta;
- the exact-image operational matrix, cleanup, privacy scan, and rollback gate pass.

If any criterion is unavailable or fails, retain the evidence and report the exact result. A new
candidate requires a new manifest and a complete fresh campaign.

This is an apples-to-apples latency optimization of the historical temperature-1 evidence. A pass
does not satisfy the separate frozen temperature-0 promotion contract. Run a second complete
`corrected-parity-v1` campaign before making that stronger claim.

## Immutable comparator

Read these before planning:

- [AEON result](../benchmark-reports/aeon-historical-parity-result-2026-08-20.md)
- [Frozen gates](../benchmark-reports/v1-qualification-plan.md)
- [Qualification protocol](benchmarking.md)
- [Policy contract](policy.md)
- [Operator runbook](operator-runbook.md)
- [Release boundary](../RELEASE_STATUS.md)

Comparator identity:

- proxy source: `75424328ce0dc0bcef6171b42e390c5ba8559471`;
- signed ARM64 OCI root:
  `sha256:c673ec73ffded8d28200f6157b696fb451735a3416a55407e686587150fe4230`;
- model: `Shiftedx/qwen3.8-27b-aeon-ultimate-uncensored-attention8-bf16recurrence-vision-mtplx`;
- model revision: `b5a54ea5d7745b6ddada238f83b66d63c979b9a5`;
- MTPLX `2.7.1`, native MTP depth 3;
- Shiftedx Bench `0.5.1`, revision `335e6694e4aec13e9370af8a993d8c8f14d7ffb5`;
- `historical-aeon-v1`: temperature `1.0`, top-p `0.95`, top-k `20`, thinking enabled,
  reasoning effort `medium`, max tokens `1024`;
- direct `99/180`; proxy `158/180`; six proxy wins in six matched pairs;
- cold wall p95 ratio `170.5%`; warm-prefix ratio `145.6%`;
- proxy-only p95 `7.783 ms`, p99 `8.353 ms`;
- weighted decode throughput cold `101.4%`, warm-prefix `100.7%` of direct;
- `586` downstream requests, `623` scored attempts, mean amplification `1.0631`, maximum `5`;
- `7` corrections, `23` repeated-phase retries, `72` Local Projections, `11` duplicate blocks,
  `9` stall blocks, and `2` bounded errors.

The historical campaign used repeated fixed cases, so pair consistency and exact denominators carry
more weight than independence-based significance claims. Preserve raw prompts, transcripts, model
output, tool arguments/results, credentials, private endpoints, host paths, and case identifiers
only in ignored mode-`0700`/`0600` private evidence.

## Team operating model

The lead agent owns architecture, sequencing, integration, final qualification, and the final
decision. Use at most three concurrent subagents so the fourth slot remains with the lead.

Route by complexity:

- **Sol medium** (`gpt-5.6-sol`, reasoning `medium`): cross-repository architecture, MTPLX
  tool-plus-schema support, experiment design, evidence-gate changes, and final Spec review.
- **Terra medium** (`gpt-5.6-terra`, reasoning `medium`): bounded implementation slices,
  instrumentation, tests, prompt/correction changes, Local Projection rules, cache work, docs, and
  Standards review.

Use `fork_turns="none"` and give every agent a self-contained packet:

```text
Task: one objective
Ownership: exact files/modules or read-only scope
Context: inputs, invariants, and links required for the task
Constraints: privacy, compatibility, and files outside ownership
Done evidence: tests, measurements, diff summary, and success criteria
Report blockers instead of guessing. Other agents share the worktree; preserve their edits.
```

Each implementation packet starts with a red test or a failing measurement, ends with focused and
full validation, and returns a commit. Keep file ownership disjoint within a wave. Ask Sol to settle
ambiguous policy or evidence semantics before Terra implements them.

## Transport decision

Retain pooled HTTP/1.1 over TCP as the qualified downstream and upstream transport. WebSocket is
layered over TCP and is not a latency optimization by itself. The current proxy already owns one
long-lived HTTPX client with bounded connection pooling and keep-alive, while the pinned MTPLX
contract exposes HTTP Chat Completions and SSE rather than a versioned WebSocket Chat Completions
endpoint. Do not add a proxy-only WebSocket protocol or represent it as OpenAI-compatible transport.

The demonstrated latency gap is not transport-sized: exact-image proxy-only p95 is `7.783 ms`, while
the full-agentic p95 deltas are `26.182 s` cold and `12.946 s` warm-prefix. Prioritize avoided model
turns, corrections, repeated phases, safe Local Projection, and cache reuse over alternate framing.
SSE may be evaluated separately for perceived time-to-first-byte, but it cannot satisfy the
time-to-final-valid-outcome gate and must not release content before the policy can uphold its
terminal-schema, correction, cancellation, and accounting contract.

Instrument connection establishment and reuse in the diagnosis workstream. Record aggregate-only
fresh-versus-reused connection counts and connect, pool-wait, request-write, response-header, and
response-read timing where the libraries expose them without raw content. Run a bounded HTTP
transport micro-probe comparing the current pool with an explicitly declared keep-alive expiry under
identical concurrency and request spacing. Accept a pool-setting change only when it improves the
predeclared pass-through wall/TTFT measurements without weakening deadlines, cancellation,
connection limits, readiness, error mapping, or qualification reproducibility.

Reopen an alternate-transport design only if both conditions hold:

- retained evidence attributes at least the larger of `5 ms` or `5%` of matched pass-through p95 to
  avoidable HTTP transport overhead after connection-pool tuning; and
- authoritative MTPLX exposes a versioned native transport contract with equivalent authentication,
  request semantics, concurrency, cancellation, errors, observability, and cache behavior.

Any such experiment is a separate HTTP-versus-candidate A/B against the pinned runtime. It requires
direct/proxy semantic parity, operational and privacy gates, a rollback path, and measured end-to-end
improvement before it may replace the HTTP comparator. HTTP/2, Unix-domain sockets, SSE, and
WebSocket are candidates only under this evidence gate; none is assumed faster in advance.

## Execution sequence

### 1. Freeze the diagnosis contract

Dispatch a Sol medium experiment-design agent and a Terra medium instrumentation agent.

Extend private qualification evidence so every scored downstream request can be classified without
raw content by:

- downstream wall time and outcome;
- proxy policy time, admission/queue time, and transport time where observable, including aggregate
  connection reuse and connect/pool-wait/write/response-header/read partitions;
- ordered upstream attempt count and acquisition/finalization phase;
- per-attempt wall time, TTFT, decode time/rate, cache result, and status;
- correction, repeated-phase retry, duplicate/stall block, and Local Projection counts;
- intervention class: pass-through, phase split, correction, blocked-call recovery, projection, or
  bounded failure;
- stable hash linkage to the existing request, observer, model-evidence, and reconciliation rows.

Produce aggregate-only public projections for:

- matched pass-through wall/TTFT;
- p50/p95/p99 by intervention class and cache lane;
- contribution of each class to the p95 tail;
- attempts and model time avoided or added;
- the slowest aggregate buckets without case identifiers.

Prefer qualification-only ledgers over new public API fields. Reuse strict no-clobber, mode-`0600`,
duplicate-key-rejecting evidence primitives. Extend reconciliation so every timing row partitions the
same request and attempt sequences exactly once.

**Done:** focused red/green tests cover missing, duplicate, reordered, malformed, partial, Local
Projection, failure, cancellation, and phase-split records; a fresh baseline probe produces all
required aggregates and attributes 100% of retained wall time without exposing private content.

### 2. Reduce correction and phase round trips

Dispatch a Terra medium agent for proxy policy changes and a Sol medium agent for MTPLX capability
work. Keep their files separate.

Proxy work:

- measure which `AgentHarness.terminal_issue` and phase transitions produce extra attempts;
- make finalization instructions minimal, stable, and cache-friendly;
- release already-valid terminal content without another model turn;
- extend local JSON normalization only for deterministic syntax/canonicalization that preserves the
  parsed value and passes the declared schema;
- keep semantic field creation, guessed values, and failure recovery model-owned;
- keep corrections, internal retries, and total upstream calls independently bounded.

MTPLX work:

- implement native tool acquisition plus strict terminal-schema handling in one supported contract,
  if the authoritative MTPLX source and release authority are available;
- expose an immutable capability/version signal and add an explicit proxy capability mode;
- prove native tool calls, strict final JSON, reasoning/tool transcript compatibility, cache
  behavior, and standard Chat Completions semantics through preflight;
- retain `phase_split` as the fail-closed fallback for MTPLX versions without proven support.

An upstream change requires its own tests, versioned artifact, provenance, and direct/proxy parity.
If authoritative source or publication authority is unavailable, record that external blocker; the
overall mission remains incomplete while the other workstreams continue. A proxy-only emulation
must keep the `phase_split` label and cannot claim combined upstream support.

**Done:** deterministic tests show fewer model turns for each optimized path, unchanged public
errors and schema enforcement, exact accounting, and preflight rejection of unsupported or drifted
combined capability.

### 3. Expand safe Local Projection

Assign one Terra medium agent ownership of `core.py`, projection helpers, `service.py` projection
integration, and their focused tests.

Start in shadow mode: record only whether a response could have been projected and compare its
canonical terminal value with the actual model terminal. Freeze eligibility rules before enabling
release:

- complete, current, successful receipts;
- no pending verification, open failure, degraded transcript, blocked unresolved action, or unknown
  tool result;
- exact supported terminal schema and type validation;
- deterministic projection from visible tool output, with no inferred or synthesized semantic data;
- proxy-owned projection marker and zero model usage/attempt accounting.

Promote only rule families with exact shadow agreement across the frozen scenarios and adversarial
tests. Add negative tests for stale epochs, failed receipts, partial objects, extra/missing keys,
wrong types, spoofed markers, parallel batches, and mutation-after-verification.

**Done:** enabled rules have 100% shadow agreement in the declared corpus, increase proven avoided
upstream calls, retain strict receipt/state gates, and reconcile Local Projections to zero model
attempts.

### 4. Stabilize cache prefixes

Assign a Terra medium agent the request-shaping/cache packet and a Sol medium reviewer the cache
evidence design.

- keep the harness suffix, phase instructions, tool schemas, sampler fields, and message ordering
  byte-stable when semantics are unchanged;
- separate stable prefix material from per-request receipts without changing visible policy;
- bind template, reasoning, model, phase, and cache-policy identities in evidence;
- use server-authoritative MTPLX cache observations for miss/hit and cached-token counts;
- prime and measure each direct/proxy warm treatment independently in a fresh owned runtime;
- preserve cold proof through a fresh zero-request instance or another server-authoritative method.

Treat cache hit rate as a mechanism metric. The outcome gate remains wall time and quality.

**Done:** tests prove semantic equivalence and stable hashes; a private probe shows increased
compatible-prefix reuse or reports a categorical lack of improvement; cold/warm evidence remains
strict and non-overlapping.

## Integration gates

Merge instrumentation first. Merge each optimization independently after two-axis review. After
each merge:

```bash
uv sync --frozen --extra dev --python 3.11
uv run pytest
uv run ruff check .
uv run mypy src
uv run python scripts/admission-soak.py
./scripts/docker-smoke.sh
git diff --check
```

Also run the packet's model-backed micro-probe against the pinned AEON runtime. Record before/after
attempt counts and latency by intervention class. A packet advances when its declared mechanism
improves or is neutral, policy/security gates remain exact, and no quality smoke regresses. Revert
or redesign a packet that trades correctness for speed.

Before final inference:

1. merge every accepted implementation and review fix;
2. require green push-to-main CI;
3. obtain the signed exact ARM64 candidate produced from that merge;
4. freeze a new private master manifest, model/runtime identity, scenario order, sampler, cache
   lanes, thresholds, outcome-independent critical-case definition, source/image, and approved
   rollback predecessor;
5. verify empty campaign storage, exclusive ports/runtime, memory/disk headroom, credentials, and
   immutable evidence paths;
6. run paired preflight; stop before scoring on any parity, schema, identity, accounting, timing, or
   privacy failure.

## Final qualification and confirmation

Run one immutable campaign: preflight, then three cold and three warm-prefix direct→proxy pairs.
Use thirteen fresh model-server instances, independent warm primes, the fixed expanded scenario
order, baseline control in both arms, and the historical sampler comparator. Retain every row; a
terminal campaign failure stays terminal.

Then run the exact-image operational matrix at declared production capacity, including latency,
steady load, overload, faults, timeout, cancellation, readiness recovery, graceful restart,
resources, and the preapproved rollback target.

Dispatch final read-only reviews in parallel:

- Sol medium Spec review: optimization requirements, experiment integrity, quality preservation,
  latency gates, reconciliation, and exact-artifact claims;
- Terra medium Standards review: repository standards, policy/security boundary, privacy scan,
  test quality, docs consistency, and baseline code smells.

Publish one allowlist-only comparison table with comparator and optimized values for quality,
pair wins, cold/warm wall p50/p95/p99, matched pass-through wall/TTFT, decode throughput, upstream
amplification, corrections, retries, projections, cache outcomes, proxy-only latency, operational
gates, and rollback. Link the exact source, image, CI, manifest digest, and review outcome.

**Mission complete:** all implementation PRs and the report are merged; push-to-main CI is green;
the final campaign is complete; every listed gate has an explicit pass/fail/unavailable verdict;
the measured full-agentic latency improves over the comparator and meets `<=125%` in both lanes;
quality and policy correctness remain intact; and the maintainer decision is recorded without
turning unavailable evidence into a pass.
