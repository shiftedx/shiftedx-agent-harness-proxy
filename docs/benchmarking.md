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

## Parity preflight and score gate

The replacement qualification uses the frozen sampler `temperature=0.0`, `top_p=0.95`,
`top_k=20`, thinking enabled, reasoning effort `medium`, and `max_tokens=1024`. Temperature `1.0`
is a distinct future experiment and must not share a ledger with this parity run.

Before a scored command, run the paired preflight against the direct and proxy arms. It uses the
same versioned phase planner on each arm while keeping the proxy's downstream request standard:
tool acquisition has tools but no terminal grammar; forced finalization has terminal grammar but
no tools. The proxy arm also compares its aggregate acquisition/finalization counter delta with
the synthetic one-tool path. The preflight writes only `scored:false` hash-only rows; it never
copies prompts, schemas, tool calls or arguments/results, model output, credentials, endpoints,
or host paths.

For the proxy arm, the qualification observer runs only on the private hop between the proxy and
model. It forwards requests and records only ordered hashes of allowlisted model-boundary fields.
The runner consumes records immediately after each proxy turn and rejects missing, stale,
malformed, out-of-order, raw-field-bearing, or field-drifting records. It records the full system
hash, normalized base-system hash, and only the exact declared harness suffix delta; no other
system-prompt mutation is accepted. A validated Local Projection has no model-boundary attempt and
therefore consumes zero observer records.

### Supervised qualification runtime

Do not paste Docker, observer, secret-copy, readiness, or cleanup commands into a qualification
run. `scripts/run_qualification_runtime.py` owns that private mechanics and accepts only an
immutable manifest, stage, and new private run directory. It derives every other runner input from
the manifest; there are intentionally no behavior overrides.

`benchmark-reports/private/` is ignored by Git. Create it and a unique mode-`700` run directory
before any request. Do not pre-create, truncate, or reuse a ledger, attestation, or outcome path.
Every evidence writer is no-clobber and atomic.

```bash
umask 077
install -d -m 700 benchmark-reports/private
RUN_DIR="$(mktemp -d benchmark-reports/private/qualification.XXXXXX)"
RUN_MANIFEST="/absolute/private/path/approved-qualification-manifest.json"

uv run python scripts/run_qualification_runtime.py \
  --manifest "$RUN_MANIFEST" --private-run-dir "$RUN_DIR" --stage preflight

uv run python scripts/run_qualification_runtime.py \
  --manifest "$RUN_MANIFEST" --private-run-dir "$RUN_DIR" --stage score-direct

uv run python scripts/run_qualification_runtime.py \
  --manifest "$RUN_MANIFEST" --private-run-dir "$RUN_DIR" --stage score-proxy
```

The commands are sequential. `preflight` creates the passed paired ledger and its immutable
runtime attestation; `score-direct` validates that exact preflight attestation and starts no
container; `score-proxy` creates a fresh observer, volume, proxy instance, and scored-proxy
attestation. A failure retains its safe outcome after scoped cleanup and never authorizes a later
stage. A stale labelled container or volume is a failure, never an automatic deletion target.

The supervisor reserves these private evidence names:

| Stage | New evidence |
| --- | --- |
| `preflight` | `preflight.jsonl`, `preflight-proxy-model-boundary.jsonl`, `preflight-runtime-attestation.json`, `preflight-runtime-outcome.json` |
| `score-direct` | `scored-direct.jsonl`, `scored-direct-runtime-outcome.json` |
| `score-proxy` | `scored-proxy.jsonl`, `scored-proxy-model-boundary.jsonl`, `scored-proxy-runtime-attestation.json`, `scored-proxy-runtime-outcome.json` |

The attestation is allowlist-only: candidate source commit, image digest, manifest SHA-256,
canonical model/order hashes, benchmark revision, runtime-contract/instance hashes, and the fixed
true checks. It contains no endpoint, host path, container name, PID, secret, or credential hash.
The separate outcome is categorical only and does not rewrite either attestation or benchmark
ledger.

### Private manifest v1

The manifest may have project-owned top-level material, but its `qualification_runtime` section is
strict. It uses `schema_version: "1.0"` and exactly these keys:

```yaml
qualification_runtime:
  schema_version: "1.0"
  source_commit: "<exact 40-lowercase-hex checked-out commit>"
  image:
    reference: "registry.example/shiftedx/proxy@sha256:<64-lowercase-hex>"
    digest: "sha256:<same 64-lowercase-hex>"
    uid: 10001
    gid: 10001
  model:
    public_id: "<approved public model identifier>"
    upstream_url: "https://private-model.example/v1"
    upstream_authenticated: true
  benchmark:
    revision: "335e6694e4aec13e9370af8a993d8c8f14d7ffb5"
    agentic_set: expanded
    scenario_order_sha256: "<canonical JSON SHA-256 of the exact selected case-id list>"
    scenario_count: 0
  observer:
    host: "127.0.0.1"
    port: 18092
    container_url: "http://host.docker.internal:18092/v1"
  proxy:
    host: "127.0.0.1"
    port: 8090
    container_port: 8090
    cpus: 1.0
    memory_bytes: 536870912
    pids_limit: 128
    stop_timeout_seconds: 20
    settings: { ...exact settings object below... }
  credentials:
    ordinary_proxy_api_key_file: "/absolute/private/path/proxy_server_key"
    qualification_policy_api_key_file: "/absolute/private/path/qualification_policy_key"
    upstream_model_api_key_file: "/absolute/private/path/upstream_model_key"
```

`image` is the local exact digest image (`--pull never`) and UID/GID must be `10001`. The model
and observer URLs must be absolute `http(s)` URLs without userinfo, query, or fragment. The
observer host and proxy publish host are loopback only. `observer.container_url` is the reviewed
container-reachable route to that loopback-bound observer; container loopback is not the host
observer. Stop if that route cannot be proven rather than weakening the observer bind.

`credentials` names three distinct, regular, non-symlink, mode-`600`, nonempty host files. The
first is the ordinary production `PROXY_API_KEY`; the second is the distinct trusted
`TRUSTED_POLICY_EXTENSION_API_KEYS` credential used by the qualification runner and authenticated
metrics; the optional third is the model `UPSTREAM_API_KEY`. It is `null` exactly when
`upstream_authenticated` is false. The exact image copies the files to a dedicated labelled volume
as `10001:10001` mode `0400`, using a root initializer with only `CHOWN` and `DAC_OVERRIDE`; the
final proxy runs as UID/GID `10001`, read-only, `cap-drop ALL`, no-new-privileges, init, resource
limits, and a read-only `/run/secrets` mount. The observer forwards any upstream Authorization and
never loads that credential itself. Secret values never appear in argv, environment, Docker
inspect, attestation, outcome, or public evidence.

`proxy.settings` is also exact, with no extra/missing key:

```yaml
deployment_profile: production
harness_profile: shiftedx-harness-v1
upstream_tool_response_capability_mode: phase_split
upstream_cache_capability_mode: disabled
telemetry_enabled: true
metrics_enabled: true
max_internal_retries: <reviewed integer>
max_upstream_calls: <reviewed integer>
upstream_timeout_seconds: <reviewed positive number>
total_request_deadline_seconds: <reviewed positive number>
server_connection_limit: <reviewed integer>
admission_limit: <reviewed integer>
principal_concurrency_limit: <reviewed integer>
concurrency_limit: <reviewed integer>
require_receipt_when_tools_present: true
allow_harness_opt_out: false
log_level: <reviewed level>
```

The supervisor validates this object through `Settings`, starts a fresh identity-bound observer,
checks local exact-image metadata, Docker inspect hardening/bind/mount/resources, effective
non-secret settings, trusted metrics authorization, and `/healthz` plus `/readyz` before it writes
the attestation or invokes the paired benchmark child. It verifies the owned observer and container
again after the child returns, then only cleans the captured labelled IDs and volume. Cleanup failure
fails the stage. SIGINT/SIGTERM records an interruption outcome after the same scoped cleanup.

The paired child still fails before any scored row when either arm produces zero native acquisition
calls, phase/field fingerprints differ outside the declared proxy receipt policy, proxy phase
counters do not prove the equivalent split, or either terminal response fails strict-schema
validation. Failed preflights are atomically retained with `status:"failed"`, still contain only
hashes/counts/allowlisted categories, and can never authorize scoring. The passed summary binds
each arm to its full selected scenario order and request-contract digest. Proxy scored rows carry
only the newly consumed, ordered observer fingerprints for that case/turn; direct rows use their
actual sent model-facing payload fingerprints.

If the benchmark client cannot obtain a response (for example, a bounded proxy `502`), the runner
writes a failed row with only the exception type, HTTP status when available, elapsed time, and the
ordinary request hash, then continues in fixed case order. It does not copy the response body into
that row. A transport failure is therefore counted instead of aborting the trial or disappearing
from the report.

The public ledger has one row per trial, profile, and cache lane. Each row records the immutable
proxy/model/runtime contract; passed/total cases; emitted and dispatched calls; blocked duplicate
and stall counts; corrections; projections; upstream-model usage; wall time; TTFT; and weighted
decode throughput. It links the shared run manifest rather than repeating private endpoint or host
data.

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
