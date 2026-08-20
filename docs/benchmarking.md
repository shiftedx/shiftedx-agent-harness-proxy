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
immutable master manifest and private campaign directory. It advances exactly the sole next
manifest-derived stage; there is intentionally no stage, slot, run-ID, or behavior override.

`benchmark-reports/private/` is ignored by Git. Create it and a unique mode-`700` campaign directory
before any request. Do not pre-create, truncate, or reuse a ledger, attestation, or outcome path.
Every evidence writer is no-clobber and atomic.

```bash
umask 077
install -d -m 700 benchmark-reports/private
CAMPAIGN_DIR="$(mktemp -d benchmark-reports/private/qualification.XXXXXX)"
RUN_MANIFEST="/absolute/private/path/approved-qualification-manifest.json"

uv run python scripts/run_qualification_runtime.py \
  --manifest "$RUN_MANIFEST" --private-campaign-dir "$CAMPAIGN_DIR"
```

Run that same command again only after it reports the prior stage complete. It advances one event
at a time in this fixed order: the sole preflight, then direct/proxy for cold pairs 1–3, then
direct/proxy for warm-prefix pairs 1–3. An exit status of `2` means the next scored stage requires
the independently operated MTPLX restart; restart the exact frozen model process, then repeat the
same command. A failure retains its safe outcome after scoped cleanup, appends a terminal campaign
event, and never authorizes a rerun. A stale labelled container or volume is a failure, never an
automatic deletion target.
The local MTPLX server is outside the supervisor lifecycle: restart it from the exact frozen model
launch contract before `score-direct`, then restart it again before `score-proxy`. Each measured
treatment needs its own dedicated process with `requests_completed == 0`; the supervisor rejects
a nonzero counter or a runtime instance reused from its preceding stage.

The sole preflight is always in `slots/00-preflight-pair0`. Each direct/proxy pair shares exactly
one `slots/0N-<cache_lane>-pairN` directory. The supervisor reserves these private evidence names:

| Stage | New evidence |
| --- | --- |
| `preflight` | `preflight.jsonl`, `preflight-direct-model-boundary.jsonl`, `preflight-proxy-model-boundary.jsonl`, `preflight-proxy-requests.jsonl`, `preflight-model-cache-evidence.json`, `preflight-runtime-attestation.json`, `preflight-runtime-outcome.json` |
| `score-direct` | `scored-direct.jsonl`, `scored-direct-model-boundary.jsonl`, `scored-direct-prime-model-boundary.jsonl` (warm lane only), `scored-direct-model-cache-evidence.json`, `scored-direct-runtime-outcome.json` |
| `score-proxy` | `scored-proxy.jsonl`, `scored-proxy-model-boundary.jsonl`, `scored-proxy-requests.jsonl`, `scored-proxy-prime-model-boundary.jsonl` (warm lane only), `scored-proxy-model-cache-evidence.json`, `scored-proxy-runtime-attestation.json`, `scored-proxy-reconciliation.json`, `scored-proxy-runtime-outcome.json` |

The attestation is allowlist-only: candidate source commit, image digest, manifest SHA-256,
canonical model/order hashes, benchmark revision, runtime-contract/instance hashes, and the fixed
true checks. It contains no endpoint, host path, container name, PID, secret, or credential hash.
The separate outcome is categorical only and does not rewrite either attestation or benchmark
ledger.

### Private manifest v1

The manifest is duplicate-rejecting JSON; YAML and JSON last-key-wins parsing are not accepted.
It may have project-owned top-level material, but its `qualification_runtime` section is strict. It
uses `"schema_version": "1.0"` and exactly these keys:

```json
{
  "qualification_runtime": {
    "schema_version": "1.0",
    "source_commit": "0123456789abcdef0123456789abcdef01234567",
    "image": {
      "reference": "registry.example/shiftedx/proxy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "uid": 10001,
      "gid": 10001
    },
    "model": {
      "public_id": "approved-public-model-id",
      "upstream_url": "http://127.0.0.1:19999/v1",
      "upstream_authenticated": true,
      "stage_path": "/absolute/private/path/mtplx-stage",
      "stage_revision": "1111111111111111111111111111111111111111",
      "identity_ledger": "/absolute/private/path/mtplx-identity.json",
      "identity_ledger_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "inspect_artifact": "/absolute/private/path/mtplx-inspect.json",
      "inspect_artifact_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "runtime_executable": "/absolute/private/path/mtplx-runtime",
      "runtime_executable_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
      "mtplx_distribution_root": "/absolute/private/path/site-packages",
      "mtplx_record": "/absolute/private/path/site-packages/mtplx-2.7.1.dist-info/RECORD",
      "mtplx_version": "2.7.1",
      "launch_command_sha256": "0202020202020202020202020202020202020202020202020202020202020202",
      "required_launch_flags": [
        "--host=127.0.0.1",
        "--port=19999",
        "--no-auth",
        "--generation-mode=mtp",
        "--depth=3",
        "--temperature=0",
        "--ssd-session-cache=off"
      ],
      "health_contract_sha256": "0303030303030303030303030303030303030303030303030303030303030303",
      "settings_contract_sha256": "0404040404040404040404040404040404040404040404040404040404040404"
    },
    "benchmark": {
      "revision": "335e6694e4aec13e9370af8a993d8c8f14d7ffb5",
      "tree": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "package": "shiftedx-bench==0.5.1",
      "checkout_path": "/absolute/private/path/shiftedx-bench",
      "interpreter_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "agentic_set": "expanded",
      "scenario_order_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "scenario_count": 12
    },
    "campaign": {
      "campaign_id": "qualification-2026-08-20",
      "slots": [
        {"cache_lane": "cold", "pair_index": 1, "run_id": "qualification-cold-pair-1"},
        {"cache_lane": "cold", "pair_index": 2, "run_id": "qualification-cold-pair-2"},
        {"cache_lane": "cold", "pair_index": 3, "run_id": "qualification-cold-pair-3"},
        {"cache_lane": "warm-prefix", "pair_index": 1, "run_id": "qualification-warm-pair-1"},
        {"cache_lane": "warm-prefix", "pair_index": 2, "run_id": "qualification-warm-pair-2"},
        {"cache_lane": "warm-prefix", "pair_index": 3, "run_id": "qualification-warm-pair-3"}
      ],
      "stage_order": ["preflight", "score-direct", "score-proxy"],
      "treatment_order": ["direct", "proxy"],
      "model_instance_policy": "fresh-per-scored-treatment",
      "failure_policy": "terminal-no-rerun"
    },
    "observer": {
      "host": "127.0.0.1",
      "port": 18092,
      "container_url": "http://host.docker.internal:18092/v1"
    },
    "proxy": {
      "host": "127.0.0.1",
      "port": 8090,
      "container_port": 8090,
      "cpus": 1.0,
      "memory_bytes": 536870912,
      "pids_limit": 128,
      "stop_timeout_seconds": 20,
      "settings": {
        "deployment_profile": "production",
        "harness_profile": "shiftedx-harness-v1",
        "upstream_tool_response_capability_mode": "phase_split",
        "upstream_cache_capability_mode": "disabled",
        "telemetry_enabled": true,
        "metrics_enabled": true,
        "max_internal_retries": 4,
        "max_upstream_calls": 7,
        "upstream_timeout_seconds": 120.0,
        "total_request_deadline_seconds": 180.0,
        "server_connection_limit": 24,
        "admission_limit": 16,
        "principal_concurrency_limit": 4,
        "concurrency_limit": 32,
        "require_receipt_when_tools_present": true,
        "allow_harness_opt_out": false,
        "log_level": "INFO"
      }
    },
    "credentials": {
      "ordinary_proxy_api_key_file": "/absolute/private/path/proxy_server_key",
      "qualification_policy_api_key_file": "/absolute/private/path/qualification_policy_key",
      "upstream_model_api_key_file": "/absolute/private/path/upstream_model_key"
    }
  }
}
```

`image` is the local exact digest image (`--pull never`) and UID/GID must be `10001`. The model
URL is an absolute `http` URL for a local loopback MTPLX listener; the observer URL is an absolute
`http(s)` URL. Neither permits userinfo, query, or fragment. The observer host and proxy publish host are loopback only.
`observer.container_url` is the reviewed container-reachable route to that loopback-bound
observer; container loopback is not the host observer. Stop if that route cannot be proven rather
than weakening the observer bind.

The full `model` object is a private identity contract, not an assertion supplied by the runner.
It binds the staged model revision, mode-`600` identity and inspect artifacts, non-symlink runtime
executable and hash, the pinned `mtplx==2.7.1` distribution `RECORD`, complete launch argv hash,
and every reviewed semantic launch flag. It also binds safe projections of `/health` and
`/v1/mtplx/settings`. Produce their two manifest hashes with
`model_endpoint_contract_hashes(health, settings)` from
`shiftedx_harness_proxy.qualification_model_evidence`; do not hand-reimplement its allowlist or
put endpoint bodies in the manifest. The placeholder flag list above is illustrative: a real
manifest carries the complete frozen semantic vector for that model process.

The supervisor probes only `/health`, `/v1/models`, and `/v1/mtplx/settings`, joins the health
startup PID to the sole loopback listener, and verifies the executable, launch vector (including
`--ssd-session-cache=off`), package, model identity, and quiescent request count before and after
each stage. A scored lane requires a newly restarted instance with `requests_completed == 0`; an
already-ready unrelated service, a replacement PID, a reused preceding-stage instance, or
intervening model traffic fails the exclusive qualification window. No model endpoint, path, PID,
launch argv, or server response is emitted into an attestation, outcome, or cache-evidence artifact.

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

`proxy.settings` is the exact JSON object in the manifest above: it has no extra or missing
keys, is validated by `Settings`, and carries only the reviewed production values. Do not create a
second hand-maintained settings file or substitute environment overrides.

The supervisor validates this object through `Settings`, verifies the benchmark checkout's pinned
HEAD/tree, an empty `git status --untracked-files=all`, the exact `shiftedx-bench==0.5.1` version
from tracked `HEAD:pyproject.toml`, and the current interpreter SHA-256. Before any normal child
starts, an isolated `-I -S` source-resolution probe confirms that `shiftedx_bench` is rooted under
`checkout_path/src`; it never consults ambient package metadata. Thus an untracked source file
(including `src/sitecustomize.py`) rejects the run before Python can execute it. The paired child
receives only that source tree on `PYTHONPATH` with user site packages and bytecode writes disabled;
an ambient `shiftedx-bench` installation cannot qualify. It starts a fresh identity-bound observer,
checks local exact-image metadata, Docker inspect hardening/bind/mount/resources, effective
non-secret settings, trusted metrics authorization, and `/healthz` plus `/readyz` before it writes
the attestation or invokes the paired benchmark child. It verifies the owned observer and container
again after the child returns, including the effective Docker stop timeout. The secret initializer
and proxy use predeclared, labelled detached names; cleanup re-resolves only those exact owned
resources before removing the labelled volume. Cleanup failure fails the stage. SIGINT/SIGTERM
records an interruption outcome after the same scoped cleanup; additional interrupts are held until
that cleanup and the atomic outcome write finish.

The outcome is a mode-`600`, no-clobber JSON record written only after cleanup. Its exact fields
are `schema_version`, `record_type`, `stage`, `status`, `action_exit_code`, `failure_category`,
`run_manifest_sha256`, `attestation_sha256`, `model_evidence_sha256`, `output_ledger_sha256`,
`output_record_count`, `proxy_reconciliation_sha256`, `campaign_id_sha256`, `slot_ordinal`,
`cache_lane`, and `pair_index`. Every outcome is slot-bound; a copied result cannot authorize a
different pair. A passed outcome requires a passed exact model-cache-evidence artifact. A passed
preflight requires five complete ledger rows; a passed scored treatment requires exactly the
manifest's positive `scenario_count`. `score-direct` requires the sole passed preflight outcome,
attestation, and model evidence, while `score-proxy` additionally requires the passed direct
outcome from its own pair directory, ledger, and model evidence. A passed proxy outcome also binds
the passed authenticated `scored-proxy-reconciliation.json`; it snapshots zero proxy metrics before
the child, validates its request/observer/model evidence after the child, and fails closed on a
counter or partition mismatch. The supervisor supplies each slot's frozen run ID to both
treatments and derives variants as `<cache_lane>-pair<pair_index>-direct|proxy-<agentic_set>`.

`cache_lane` is measured proof, not a `cache_proof_sha256` self-assertion. Preflight always sends
`--cache-mode bypass`, including a later `warm-prefix` campaign: every successful preflight attempt
must report bypass, no RAM or SSD hit, zero cached tokens, a full new prefill, and no postcommit
store. The `cold` scored lane enforces the same evidence on its dedicated zero-counter process. In
the `warm-prefix` scored lane, that separate process has persistent SSD cache disabled and the
supervisor first runs one direct-to-model prime child with the same frozen run ID, scenario order,
variant, and a `direct` or `proxy` prime arm. It records exactly one safe prime attempt, then runs
the scored child. The prime request digest must equal the first measured request digest; that first
measured attempt must be a non-bypass **RAM** hit with positive cached tokens and no SSD-hit fields,
and the server request-count delta must leave no room for intervening traffic. A pending postcommit
flag is corroborating information only, because a tool-required MTPLX prime can commit after the
first matching request.

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
