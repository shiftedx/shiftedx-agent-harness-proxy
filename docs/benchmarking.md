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

For the proxy arm, place `scripts/qualification_model_boundary_observer.py` on the private hop
between the proxy and model. It forwards requests and records only ordered hashes of allowlisted
model-boundary fields. The runner consumes records immediately after each proxy turn and rejects
missing, stale, malformed, out-of-order, raw-field-bearing, or field-drifting records. It records
the full system hash, normalized base-system hash, and only the exact declared harness suffix
delta; no other system-prompt mutation is accepted. A validated Local Projection has no model
boundary attempt and therefore consumes zero observer records.

Create a private, unique run directory before either arm starts. Do not pre-create or truncate a
ledger: a preflight output path must be new, and its atomic writer will never overwrite existing
evidence. The frozen manifest itself carries the approved exact model revision and runtime; pass
only its SHA-256 to the runner.

```bash
umask 077
install -d -m 700 benchmark-reports/private
RUN_DIR="$(mktemp -d benchmark-reports/private/qualification.XXXXXX)"
PREFLIGHT_OBSERVER_LEDGER="$RUN_DIR/preflight-proxy-model-boundary.jsonl"
PREFLIGHT_LEDGER="$RUN_DIR/preflight.jsonl"
SCORED_PROXY_OBSERVER_LEDGER="$RUN_DIR/scored-proxy-model-boundary.jsonl"
RUN_MANIFEST_SHA256="$(shasum -a 256 "$RUN_MANIFEST" | awk '{print $1}')"
ORDINARY_PROXY_API_KEY_FILE="$(pwd)/secrets/proxy_server_key"
QUALIFICATION_POLICY_API_KEY_FILE="$(pwd)/secrets/qualification_policy_key"
UPSTREAM_MODEL_API_KEY_FILE="$(pwd)/secrets/upstream_model_key"
: "${QUALIFICATION_RUN_ID:?Set the manifest-frozen qualification run identifier}"
: "${CANDIDATE_IMAGE_REF:?Set the approved image reference by digest}"
: "${QUALIFICATION_OBSERVER_CONTAINER_URL:?Set the manifest-frozen observer URL reachable from the container}"
[[ "$QUALIFICATION_RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
[[ "$CANDIDATE_IMAGE_REF" =~ @sha256:[0-9a-f]{64}$ ]]
CANDIDATE_IMAGE_DIGEST="${CANDIDATE_IMAGE_REF##*@}"
PREFLIGHT_PROXY_CONTAINER="shiftedx-qualification-preflight-$QUALIFICATION_RUN_ID"
SCORED_PROXY_CONTAINER="shiftedx-qualification-scored-$QUALIFICATION_RUN_ID"
QUALIFICATION_SECRETS_VOLUME="shiftedx-qualification-secrets-$QUALIFICATION_RUN_ID"
PROXY_URL=http://127.0.0.1:8090/v1
PRIVATE_PROXY_METRICS_URL=http://127.0.0.1:8090/metrics

docker image inspect "$CANDIDATE_IMAGE_REF" >/dev/null
docker run --rm --pull never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --entrypoint /bin/sh "$CANDIDATE_IMAGE_REF" \
  -c 'command -v cp >/dev/null && command -v chown >/dev/null && command -v chmod >/dev/null'
if docker volume inspect "$QUALIFICATION_SECRETS_VOLUME" >/dev/null 2>&1; then
  echo "qualification secret volume already exists" >&2
  exit 1
fi
docker volume create "$QUALIFICATION_SECRETS_VOLUME" >/dev/null
docker run --rm --pull never --network none --read-only \
  --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --mount "type=bind,src=$ORDINARY_PROXY_API_KEY_FILE,dst=/source/proxy_api_key,readonly" \
  --mount "type=bind,src=$QUALIFICATION_POLICY_API_KEY_FILE,dst=/source/trusted_policy_extension_api_keys,readonly" \
  --mount "type=bind,src=$UPSTREAM_MODEL_API_KEY_FILE,dst=/source/upstream_api_key,readonly" \
  --mount "type=volume,src=$QUALIFICATION_SECRETS_VOLUME,dst=/target" \
  --entrypoint /bin/sh "$CANDIDATE_IMAGE_REF" -c '
    set -eu
    cp /source/proxy_api_key /target/proxy_api_key
    cp /source/trusted_policy_extension_api_keys /target/trusted_policy_extension_api_keys
    cp /source/upstream_api_key /target/upstream_api_key
    chmod 0400 /target/proxy_api_key /target/trusted_policy_extension_api_keys /target/upstream_api_key
    chown 10001:10001 /target/proxy_api_key /target/trusted_policy_extension_api_keys /target/upstream_api_key
  '

start_qualification_proxy() {
  qualification_container="$1"
  if docker container inspect "$qualification_container" >/dev/null 2>&1; then
    echo "qualification container already exists: $qualification_container" >&2
    return 1
  fi
  docker run --detach --pull never --name "$qualification_container" \
    --init --stop-timeout 20 --user 10001:10001 --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --cpus 1.0 --memory 512m \
    --publish 127.0.0.1:8090:8090 \
    --mount "type=volume,src=$QUALIFICATION_SECRETS_VOLUME,dst=/run/secrets,readonly" \
    --env DEPLOYMENT_PROFILE=production \
    --env LISTEN_HOST=0.0.0.0 \
    --env TELEMETRY_ENABLED=true \
    --env METRICS_ENABLED=true \
    --env UPSTREAM_BASE_URL="$QUALIFICATION_OBSERVER_CONTAINER_URL" \
    --env UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE=phase_split \
    "$CANDIDATE_IMAGE_REF" >/dev/null
  test "$(docker container inspect --format '{{.Image}}' "$qualification_container")" = \
    "$(docker image inspect --format '{{.Id}}' "$CANDIDATE_IMAGE_REF")"
  docker exec "$qualification_container" python -c '
from shiftedx_harness_proxy.config import Settings
s = Settings()
assert s.deployment_profile == "production"
assert s.listen_host == "0.0.0.0"
assert s.telemetry_enabled and s.metrics_enabled
assert s.upstream_tool_response_capability_mode == "phase_split"
assert s.proxy_api_key is not None and s.upstream_api_key is not None
trusted = s.trusted_policy_extension_keys()
assert len(trusted) == 1
assert len({s.proxy_api_key.get_secret_value(), s.upstream_api_key.get_secret_value(), *trusted}) == 3
'
  qualification_ready=false
  for qualification_attempt in $(seq 1 30); do
    if curl --fail --silent --show-error http://127.0.0.1:8090/readyz >/dev/null; then
      qualification_ready=true
      break
    fi
    sleep 1
  done
  test "$qualification_ready" = true
}

QUALIFICATION_OBSERVER_UPSTREAM="$MODEL_URL" \
QUALIFICATION_OBSERVER_LEDGER="$PREFLIGHT_OBSERVER_LEDGER" \
  uv run python scripts/qualification_model_boundary_observer.py &
PREFLIGHT_OBSERVER_PID=$!
start_qualification_proxy "$PREFLIGHT_PROXY_CONTAINER"
```

Provision the three roles from distinct host mode-`600` files without printing their values: the
ordinary downstream `PROXY_API_KEY`, the trusted qualification policy-extension key, and the
upstream model key. The initializer copies them into a dedicated volume as the exact Pydantic secret
filenames, owned by image UID/GID `10001:10001` with mode `0400`; the candidate mounts that volume
read-only. Never reuse a value between roles. The runner's proxy key file is the trusted
qualification key, not the ordinary server key. For an authenticated model, the proxy creates the
upstream Authorization from `upstream_api_key`; the host observer forwards that header without
loading the credential itself.

The observer remains a host process, but the approved proxy is the exact digest-addressed image.
Freeze `QUALIFICATION_OBSERVER_CONTAINER_URL`, the image reference, host port, resource limits, and
all effective settings in the run manifest. The URL must be proven reachable from inside the
container; container loopback is not the host observer. On an engine that cannot privately route a
container to this loopback-only observer, stop and establish a reviewed route rather than weakening
the observer bind. The settings assertion and `/readyz` gate must pass before preflight or scoring.

The preflight runner requires that observer ledger to be absent or empty before requests and will
neither delete nor overwrite it. Use a newly launched observer and a distinct new ledger for every
preflight and every scored proxy treatment. Restore the fixed approved model URL after each
qualification-only observer exercise; do not use this observer as a production routing layer.

```bash
uv run scripts/run_paired_agentic_trial.py \
  --paired-preflight --variant preflight \
  --model "$PUBLIC_MODEL_ID" --agentic-set expanded \
  --direct-base-url "$DIRECT_URL" --proxy-base-url "$PROXY_URL" \
  --proxy-metrics-url "$PRIVATE_PROXY_METRICS_URL" \
  --proxy-observer-ledger "$PREFLIGHT_OBSERVER_LEDGER" \
  --direct-api-key-file "$UPSTREAM_MODEL_API_KEY_FILE" \
  --proxy-api-key-file "$QUALIFICATION_POLICY_API_KEY_FILE" \
  --output "$PREFLIGHT_LEDGER" \
  --candidate-source-commit "$CANDIDATE_SOURCE_COMMIT" \
  --candidate-image-digest "$CANDIDATE_IMAGE_DIGEST" \
  --run-manifest-sha256 "$RUN_MANIFEST_SHA256"
```

The command fails before any scored row when either arm produces zero native acquisition calls,
phase/field fingerprints differ outside the declared proxy receipt policy, proxy phase counters do
not prove the equivalent split, or either terminal response fails strict-schema validation. A
scored command requires that passed ledger and exactly matching checked-out source and immutable
image digest. Failed preflights are atomically retained with `status:"failed"`, still contain only
hashes/counts/allowlisted categories, and can never authorize scoring. The passed summary also
binds each arm to its full selected scenario order and request-contract digest, so a `--case-id` or
`--limit` preflight cannot authorize a differently selected scored run:

```bash
uv run scripts/run_paired_agentic_trial.py \
  --base-url "$DIRECT_URL" --model "$PUBLIC_MODEL_ID" --variant direct \
  --api-key-file "$UPSTREAM_MODEL_API_KEY_FILE" \
  --output "$RUN_DIR/direct.jsonl" --agentic-set expanded \
  --preflight-ledger "$PREFLIGHT_LEDGER" \
  --candidate-source-commit "$CANDIDATE_SOURCE_COMMIT" \
  --candidate-image-digest "$CANDIDATE_IMAGE_DIGEST" \
  --run-manifest-sha256 "$RUN_MANIFEST_SHA256"
```

Before the equivalent proxy command, stop and remove only the named preflight container, then stop
its observer. Launch a new host observer wired to the distinct scored ledger and start the same
frozen candidate configuration under a new dedicated container name:

```bash
docker stop "$PREFLIGHT_PROXY_CONTAINER" >/dev/null
docker rm "$PREFLIGHT_PROXY_CONTAINER" >/dev/null
kill "$PREFLIGHT_OBSERVER_PID"
wait "$PREFLIGHT_OBSERVER_PID" 2>/dev/null || true

QUALIFICATION_OBSERVER_UPSTREAM="$MODEL_URL" \
QUALIFICATION_OBSERVER_LEDGER="$SCORED_PROXY_OBSERVER_LEDGER" \
  uv run python scripts/qualification_model_boundary_observer.py &
SCORED_OBSERVER_PID=$!
start_qualification_proxy "$SCORED_PROXY_CONTAINER"
```

Pass that same new path to the runner:

```bash
uv run scripts/run_paired_agentic_trial.py \
  --base-url "$PROXY_URL" --model "$PUBLIC_MODEL_ID" --variant proxy \
  --output "$RUN_DIR/proxy.jsonl" --agentic-set expanded --proxy-policy \
  --api-key-file "$QUALIFICATION_POLICY_API_KEY_FILE" \
  --proxy-observer-ledger "$SCORED_PROXY_OBSERVER_LEDGER" \
  --preflight-ledger "$PREFLIGHT_LEDGER" \
  --candidate-source-commit "$CANDIDATE_SOURCE_COMMIT" \
  --candidate-image-digest "$CANDIDATE_IMAGE_DIGEST" \
  --run-manifest-sha256 "$RUN_MANIFEST_SHA256"

docker stop "$SCORED_PROXY_CONTAINER" >/dev/null
docker rm "$SCORED_PROXY_CONTAINER" >/dev/null
kill "$SCORED_OBSERVER_PID"
wait "$SCORED_OBSERVER_PID" 2>/dev/null || true
docker volume rm "$QUALIFICATION_SECRETS_VOLUME" >/dev/null
```

If the approved model endpoint is unauthenticated, omit together the upstream source mount and
`upstream_api_key` copy/chmod/chown entries from the initializer, the upstream-key assertion from
`start_qualification_proxy`, preflight `--direct-api-key-file`, and direct scored `--api-key-file`.
This leaves the proxy's `UPSTREAM_API_KEY` unset. Do not omit only one side of that direct/proxy
model-auth contract.

Never invoke either command without the same frozen candidate provenance, model ID, and manifest
digest; the runner refuses to append to an existing scored output. Proxy scored rows carry only
the newly consumed, ordered observer fingerprints for that case/turn; direct rows use their actual
sent model-facing payload fingerprints.

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
