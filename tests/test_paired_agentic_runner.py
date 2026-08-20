from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import types
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

import shiftedx_harness_proxy.qualification_contract as contract_module
from shiftedx_harness_proxy.core import HARNESS_SYSTEM_SUFFIX
from shiftedx_harness_proxy.projection_accounting import (
    LOCAL_PROJECTION_EXTENSION,
    local_projection_accounting,
)
from shiftedx_harness_proxy.qualification_contract import (
    BENCHMARK_REVISION,
    load_model_evidence,
    load_runtime_attestation,
    load_runtime_outcome,
    read_model_boundary_observer_records,
)
from shiftedx_harness_proxy.qualification_reconciliation import (
    ReconciliationFailure,
    read_request_accounting_ledger,
)

_RUN_MANIFEST_SHA256 = "1" * 64


def _lane_contract_digests(direct: str = "1" * 64, proxy: str = "2" * 64):
    return {
        "cold": {"direct": direct, "proxy": proxy},
        "warm-prefix": {"direct": direct, "proxy": proxy},
    }


def test_load_model_evidence_binds_a_passed_private_artifact_to_stage_manifest_and_contract(tmp_path) -> None:
    """The scoring gate admits only the exact completed C1 artifact, never a self-assertion."""

    evidence = tmp_path / "preflight-model-cache-evidence.json"
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_model_cache_evidence",
        "stage": "preflight",
        "status": "passed",
        "failure_category": None,
        "run_manifest_sha256": _RUN_MANIFEST_SHA256,
        "model_identity_sha256": "a" * 64,
        "model_contract_sha256": "a" * 64,
        "runtime_instance_sha256": "b" * 64,
        "live_before_sha256": "c" * 64,
        "live_after_sha256": "d" * 64,
        "request_window": {
            "before": 7,
            "after": 7,
            "delta": 0,
            "expected": 0,
            "successful_measured": 0,
        },
        "prime": {"record_sha256": None, "count": 0, "request_digest": None},
        "first_attempt": {
            "record_sha256": None,
            "status": None,
            "measured_count": 0,
            "successful_count": 0,
            "prompt_tokens": None,
            "cached_tokens": None,
            "new_prefill_tokens": None,
        },
        "checks": {
            "contract": True,
            "live_before": True,
            "attempts": True,
            "request_window": True,
            "live_after": True,
        },
    }
    evidence.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    evidence.chmod(0o600)

    loaded = load_model_evidence(
        evidence,
        expected_stage="preflight",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        model_identity_sha256="a" * 64,
        model_contract_sha256="a" * 64,
    )

    assert loaded.stage == "preflight"
    assert loaded.model_contract_sha256 == "a" * 64
    assert loaded.file_sha256 == hashlib.sha256(evidence.read_bytes()).hexdigest()


def test_runtime_outcome_binds_the_exact_passed_model_evidence_bytes(tmp_path) -> None:
    """Later scoring must not accept an outcome detached from C1 model/cache evidence."""

    attestation = tmp_path / "preflight-runtime-attestation.json"
    output = tmp_path / "preflight.jsonl"
    evidence = tmp_path / "preflight-model-cache-evidence.json"
    outcome = tmp_path / "preflight-runtime-outcome.json"
    attestation.write_text('{"model_identity_sha256":"' + "a" * 64 + '"}\n', encoding="utf-8")
    output.write_text('{"row":1}\n', encoding="utf-8")
    evidence.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "record_type": "qualification_model_cache_evidence",
                "stage": "preflight",
                "status": "passed",
                "failure_category": None,
                "run_manifest_sha256": _RUN_MANIFEST_SHA256,
                "model_identity_sha256": "a" * 64,
                "model_contract_sha256": "a" * 64,
                "runtime_instance_sha256": "b" * 64,
                "live_before_sha256": "c" * 64,
                "live_after_sha256": "d" * 64,
                "request_window": {
                    "before": 7,
                    "after": 7,
                    "delta": 0,
                    "expected": 0,
                    "successful_measured": 0,
                },
                "prime": {"record_sha256": None, "count": 0, "request_digest": None},
                "first_attempt": {
                    "record_sha256": None,
                    "status": None,
                    "measured_count": 0,
                    "successful_count": 0,
                    "prompt_tokens": None,
                    "cached_tokens": None,
                    "new_prefill_tokens": None,
                },
                "checks": {
                    "contract": True,
                    "live_before": True,
                    "attempts": True,
                    "request_window": True,
                    "live_after": True,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    for path in (attestation, output, evidence):
        path.chmod(0o600)
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_outcome",
        "stage": "preflight",
        "status": "passed",
        "action_exit_code": 0,
        "failure_category": None,
        "run_manifest_sha256": _RUN_MANIFEST_SHA256,
        "attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "model_evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "output_ledger_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "output_record_count": 1,
        "proxy_reconciliation_sha256": None,
        "campaign_id_sha256": "c" * 64,
        "slot_ordinal": 0,
        "cache_lane": "preflight",
        "pair_index": 0,
    }
    outcome.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    outcome.chmod(0o600)

    loaded = load_runtime_outcome(
        outcome,
        expected_stage="preflight",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        attestation=attestation,
        model_evidence=evidence,
        model_identity_sha256="a" * 64,
        model_contract_sha256="a" * 64,
        output_ledger=output,
        expected_output_record_count=1,
    )

    assert loaded.model_evidence_sha256 == hashlib.sha256(evidence.read_bytes()).hexdigest()


def load_runner(monkeypatch):
    scenarios = [
        SimpleNamespace(
            case_id=f"case-{index}",
            prompt=f"private prompt marker {index}",
            tools=[{"type": "function", "function": {"name": "read_file"}}],
            final_keys=("status",),
            final_types={"status": "string"},
            require_receipt=True,
            max_turns=3,
            max_tool_calls=2,
            family="test",
            real_repo=False,
            forbidden_calls={"delete_file"},
        )
        for index in (1, 2)
    ]
    agentic = types.ModuleType("shiftedx_bench.agentic")
    agentic.scenario_set = lambda _name: scenarios

    def fail_case(**_kwargs):
        raise RuntimeError('HTTP 502: {"error":{"message":"private body marker"}}')

    agentic.run_agentic_cases = fail_case
    api = types.ModuleType("shiftedx_bench.api")

    class DroppingOpenAIClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def complete(self, _payload, *, stream=False):
            raise AssertionError(f"unexpected benchmark client call (stream={stream})")

        @staticmethod
        def _normalize(value, *, wall_s, ttft_s):
            del wall_s, ttft_s
            return {
                "content": value.get("content") or "",
                "tool_calls": value.get("tool_calls") or [],
            }

    api.OpenAIClient = DroppingOpenAIClient
    package = types.ModuleType("shiftedx_bench")
    monkeypatch.setitem(sys.modules, "shiftedx_bench", package)
    monkeypatch.setitem(sys.modules, "shiftedx_bench.agentic", agentic)
    monkeypatch.setitem(sys.modules, "shiftedx_bench.api", api)
    script = Path(__file__).parents[1] / "scripts" / "run_paired_agentic_trial.py"
    spec = importlib.util.spec_from_file_location("paired_agentic_runner", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_provenance_uses_frozen_git_with_a_scrubbed_environment(monkeypatch) -> None:
    """Qualification provenance must not inherit Git or proxy configuration from the shell."""

    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return SimpleNamespace(stdout="a" * 40 + "\n")

    monkeypatch.setenv("DOCKER_HOST", "private-daemon-marker")
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy.invalid")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setattr(contract_module.subprocess, "run", fake_run)

    contract_module.require_candidate_provenance("a" * 40, "sha256:" + "b" * 64)

    assert calls == [
        (
            ["/usr/bin/git", "rev-parse", "HEAD"],
            {
                "capture_output": True,
                "text": True,
                "check": True,
                "env": {},
            },
        )
    ]


def test_client_failure_is_recorded_without_response_body_and_run_continues(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    output = tmp_path / "raw.jsonl"
    preflight = tmp_path / "preflight.jsonl"
    git = shutil.which("git")
    assert git is not None
    source_commit = subprocess.run(  # noqa: S603 - resolved executable and fixed Git arguments
        [git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    image_digest = "sha256:" + "0" * 64
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation)
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://example.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--agentic-set",
            "expanded",
            "--variant",
            "proxy",
            "--proxy-policy",
            "--run-id",
            "run-one",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
            "--direct-runtime-outcome",
            str(direct_outcome),
            "--proxy-observer-ledger",
            str(tmp_path / "scored-observer.jsonl"),
            "--proxy-request-ledger",
            str(tmp_path / "scored-proxy-requests.jsonl"),
        ],
    )

    runner.main()

    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["case_id"] for row in rows] == ["case-1", "case-2"]
    for row in rows:
        assert row["passed"] is False
        assert row["score"] == 0.0
        assert row["error"] == "client request failed with HTTP 502"
        assert row["response"] == {"client_error": {"type": "RuntimeError", "http_status": 502}}
        assert row["metadata"]["runner_failure_stage"] == "benchmark_client"
        assert row["scored"] is True
        assert set(row["contract_fingerprints"]) == {"downstream", "model_facing", "model_facing_turns"}
    serialized = json.dumps(rows)
    assert "private prompt marker" not in serialized
    assert "private body marker" not in serialized


def test_scored_mode_rejects_missing_runtime_attestation_before_client_or_output(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    _write_passing_preflight(runner, preflight, source_commit, image_digest)
    output = tmp_path / "scored.jsonl"

    class UnexpectedClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("runtime attestation must be required before client construction")

    runner.ProjectionAwareOpenAIClient = UnexpectedClient
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://direct.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--variant",
            "direct",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
        ],
    )

    with pytest.raises(SystemExit, match="--runtime-attestation"):
        runner.main()
    assert not output.exists()


def test_scored_mode_requires_preflight_runtime_outcome_before_client_or_output(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    runtime_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    output = tmp_path / "scored.jsonl"

    class UnexpectedClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("runtime outcome must be required before client construction")

    runner.ProjectionAwareOpenAIClient = UnexpectedClient
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://direct.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--variant",
            "direct",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
        ],
    )

    with pytest.raises(SystemExit, match="--preflight-runtime-outcome"):
        runner.main()
    assert not output.exists()


def test_scored_proxy_mode_requires_direct_runtime_outcome_before_client_or_output(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome = _write_runtime_outcome(
        tmp_path / "preflight-runtime-outcome.json",
        stage="preflight",
        attestation=preflight_attestation,
        output=preflight,
        output_record_count=5,
    )
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    output = tmp_path / "scored.jsonl"

    class UnexpectedClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("direct runtime outcome must be required before client construction")

    runner.ProjectionAwareOpenAIClient = UnexpectedClient
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://proxy.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--variant",
            "proxy",
            "--proxy-policy",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
        ],
    )

    with pytest.raises(SystemExit, match="--direct-runtime-outcome"):
        runner.main()
    assert not output.exists()


def test_contract_fingerprints_are_exact_for_equal_arms_and_never_retain_payloads(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    payload = runner.request_payload(scenario, model="model", proxy_policy=False)

    direct = runner.contract_fingerprints(payload, [scenario.case_id], policy_delta={})
    proxy = runner.contract_fingerprints(
        runner.request_payload(scenario, model="model", proxy_policy=True),
        [scenario.case_id],
        policy_delta={"x-shiftedx-require-receipt": True},
    )

    assert runner.contract_mismatches(direct, proxy) == []
    serialized = json.dumps({"direct": direct, "proxy": proxy})
    assert scenario.prompt not in serialized
    assert "read_file" not in serialized
    assert '"model"' not in serialized
    assert "system_prompt_sha256" in serialized
    assert "tool_schema_sha256" in serialized


def test_phase_planner_splits_tools_and_terminal_schema(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    planner = runner.PhasePlanner()

    acquisition = planner.plan(payload, phase="acquisition")
    finalization = planner.plan(payload, phase="finalization")

    assert acquisition["tools"] == scenario.tools
    assert "response_format" not in acquisition
    assert finalization["response_format"] == payload["response_format"]
    assert "tools" not in finalization
    assert "tool_choice" not in finalization
    assert payload["temperature"] == 0.0
    assert payload["top_p"] == 0.95
    assert payload["top_k"] == 20
    assert payload["thinking"] == {"enabled": True}
    assert payload["reasoning_effort"] == "medium"
    assert payload["max_tokens"] == 1024


def test_historical_aeon_profile_binds_payload_fingerprint_prime_and_score_gate(monkeypatch):
    """The known-good AEON sampler is a named, end-to-end qualification contract."""

    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    order = [scenario.case_id]

    historical = runner.request_payload(
        scenario,
        model="model",
        proxy_policy=False,
        sampler_profile="historical-aeon-v1",
    )
    corrected = runner.request_payload(scenario, model="model", proxy_policy=False)
    sampler_keys = ("temperature", "top_p", "top_k", "thinking", "reasoning_effort", "max_tokens")
    assert {key: historical[key] for key in sampler_keys} == {
        "temperature": 1.0,
        "top_p": 0.95,
        "top_k": 20,
        "thinking": {"enabled": True},
        "reasoning_effort": "medium",
        "max_tokens": 1024,
    }
    historical_digest = runner.contract_fingerprints(historical, order, policy_delta={})["downstream"]["digest"]
    corrected_digest = runner.contract_fingerprints(corrected, order, policy_delta={})["downstream"]["digest"]
    assert historical_digest != corrected_digest

    prime = runner.cache_prime_payload(
        scenario, model="model", arm="direct", sampler_profile="historical-aeon-v1"
    )
    first_scored = runner.PhasePlanner().plan(historical, phase="acquisition")
    assert runner.model_boundary_fingerprint(prime, scenario_order=order).digest == runner.model_boundary_fingerprint(
        first_scored, scenario_order=order
    ).digest

    digests = runner._qualification_contract_digests("model", [scenario], order, "a" * 64, "historical-aeon-v1")
    expected = runner.qualification_contract_digest(
        [
            runner.request_payload(
                scenario,
                model="model",
                proxy_policy=False,
                cache_mode="bypass",
                sampler_profile="historical-aeon-v1",
            )
        ],
        order,
        policy_delta={},
        run_manifest_sha256="a" * 64,
    )
    assert digests["cold"]["direct"] == expected
    assert digests["cold"]["direct"] != runner._qualification_contract_digests(
        "model", [scenario], order, "a" * 64, "corrected-parity-v1"
    )["cold"]["direct"]


def test_contract_fingerprint_reports_accidental_sampler_mismatch(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    direct_payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    proxy_payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    proxy_payload["temperature"] = 1.0

    direct = runner.contract_fingerprints(direct_payload, [scenario.case_id], policy_delta={})
    proxy = runner.contract_fingerprints(
        proxy_payload, [scenario.case_id], policy_delta={"x-shiftedx-require-receipt": True}
    )

    assert runner.contract_mismatches(direct, proxy) == ["sampler"]


def test_model_boundary_fingerprint_binds_only_safe_cache_mode_policy(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    normal = runner.request_payload(scenario, model="model", proxy_policy=False)
    bypass = copy.deepcopy(normal)
    bypass["metadata"] = {"cache_mode": "bypass"}

    normal_fingerprint = runner.model_boundary_fingerprint(runner.PhasePlanner().plan(normal, phase="acquisition"))
    bypass_fingerprint = runner.model_boundary_fingerprint(runner.PhasePlanner().plan(bypass, phase="acquisition"))

    assert normal_fingerprint.fields["cache_mode_policy"] is None
    assert bypass_fingerprint.fields["cache_mode_policy"] == "bypass"
    assert normal_fingerprint.digest != bypass_fingerprint.digest


def test_preflight_rejects_invalid_terminal_schema(monkeypatch):
    runner = load_runner(monkeypatch)
    schema = runner.response_format("case", ("status",), {"status": "string"})

    assert runner.terminal_schema_valid({"content": '{"status":"passed"}'}, schema)
    assert not runner.terminal_schema_valid({"content": '{"status":1}'}, schema)


def test_preflight_ledger_retains_only_hashes_and_allowlisted_outcomes(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    direct_payload = runner.request_payload(scenario, model="private-model", proxy_policy=False)
    proxy_payload = runner.request_payload(scenario, model="private-model", proxy_policy=True)
    terminal_payload = runner._preflight_payload(scenario, model="private-model", proxy_policy=False, no_tools=True)
    direct, direct_phases = runner.request_fingerprints(direct_payload, [scenario.case_id], policy_delta={})
    proxy, proxy_phases = runner.request_fingerprints(
        proxy_payload, [scenario.case_id], policy_delta={"x-shiftedx-require-receipt": True}
    )
    terminal, terminal_phases = runner.request_fingerprints(terminal_payload, [scenario.case_id], policy_delta={})
    output = tmp_path / "preflight.jsonl"
    runner.write_preflight_ledger(
        output,
        [
            runner.PreflightObservation(
                arm="direct",
                tool_required=True,
                native_acquisition_tool_calls=1,
                phases=("acquisition", "finalization"),
                terminal_schema_valid=True,
                downstream=direct,
                model_facing=direct_phases,
            ),
            runner.PreflightObservation(
                arm="proxy",
                tool_required=True,
                native_acquisition_tool_calls=1,
                phases=("acquisition", "finalization"),
                terminal_schema_valid=True,
                downstream=proxy,
                model_facing=proxy_phases,
                proxy_phase_counts={"acquisition": 2, "finalization": 1},
            ),
            *[
                runner.PreflightObservation(
                    arm=arm,
                    tool_required=False,
                    native_acquisition_tool_calls=0,
                    phases=("terminal",),
                    terminal_schema_valid=True,
                    downstream=terminal,
                    model_facing=terminal_phases,
                )
                for arm in ("direct", "proxy")
            ],
        ],
        source_commit="a" * 40,
        image_digest="sha256:" + "0" * 64,
        contract_digests=_lane_contract_digests(),
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
    )

    serialized = output.read_text()
    assert '"scored":false' in serialized
    assert scenario.prompt not in serialized
    assert "read_file" not in serialized
    assert "private-model" not in serialized
    assert "synthetic preflight tool completed" not in serialized


def test_preflight_blocks_collapsed_combined_grammar_before_scored_rows(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    output = tmp_path / "scored.jsonl"
    preflight = tmp_path / "preflight.jsonl"
    collapsed = runner.PreflightObservation(
        arm="direct",
        tool_required=True,
        native_acquisition_tool_calls=0,
        phases=("acquisition", "finalization"),
        terminal_schema_valid=True,
        downstream=runner.SafeFingerprint("downstream", "same", {}),
        model_facing=(runner.SafeFingerprint("model_facing", "same", {}),),
    )
    proxy = runner.PreflightObservation(
        arm="proxy",
        tool_required=True,
        native_acquisition_tool_calls=1,
        phases=("acquisition", "finalization"),
        terminal_schema_valid=True,
        downstream=runner.SafeFingerprint("downstream", "same", {}),
        model_facing=(runner.SafeFingerprint("model_facing", "same", {}),),
    )

    with pytest.raises(runner.PreflightFailure, match="zero native acquisition tool calls"):
        runner.assert_preflight([collapsed, proxy])
    assert not output.exists()
    assert not preflight.exists()


def test_scored_mode_requires_a_successful_paired_preflight_and_exact_provenance(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    output = tmp_path / "scored.jsonl"
    missing_ledger = tmp_path / "missing-preflight.jsonl"

    with pytest.raises(SystemExit, match="successful paired preflight"):
        runner.require_scoring_gate(
            output=output,
            preflight_ledger=missing_ledger,
            candidate_source_commit="not-the-current-source",
            candidate_image_digest="sha256:" + "0" * 64,
            contract_digest="not-the-current-contract",
            arm="direct",
            cache_lane="warm-prefix",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
        )
    assert not output.exists()


def test_fake_combined_tools_and_schema_collapse_is_recorded_as_zero_native_calls(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]

    class CollapsingModel:
        def complete(self, payload, *, stream=False):
            assert stream is False
            if payload.get("tools") and payload.get("response_format"):
                return {"content": '{"status":"passed"}', "tool_calls": []}
            if payload.get("tools"):
                return {
                    "content": "",
                    "tool_calls": [{"id": "call-1", "function": {"name": "read_file", "arguments": "{}"}}],
                }
            return {"content": '{"status":"passed"}', "tool_calls": []}

    payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    legacy_proxy = runner.CompatibilityClient(
        CollapsingModel(), arm="proxy", scenario_order=[scenario.case_id], proxy_policy=True
    )
    runner._run_preflight_path(legacy_proxy, payload, tool_required=True)
    observation = legacy_proxy.observation(tool_required=True, original_payload=payload)

    assert observation.native_acquisition_tool_calls == 0
    with pytest.raises(runner.PreflightFailure, match="zero native acquisition tool calls"):
        runner.assert_preflight([observation])


def test_proxy_preflight_counts_native_tool_calls_from_returned_responses(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]

    class ProxyModel:
        def complete(self, payload, *, stream=False):
            if any(message.get("role") == "tool" for message in payload["messages"]):
                return {"content": '{"status":"passed"}', "tool_calls": []}
            return {
                "content": "",
                "tool_calls": [{"id": "call-1", "function": {"name": "read_file", "arguments": "{}"}}],
            }

    payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    client = runner.CompatibilityClient(ProxyModel(), arm="proxy", scenario_order=[scenario.case_id], proxy_policy=True)
    runner._run_preflight_path(client, payload, tool_required=True)

    assert client.observation(tool_required=True, original_payload=payload).native_acquisition_tool_calls == 1


def test_proxy_request_accounting_records_one_safe_row_for_the_actual_downstream_call(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer_path = tmp_path / "observer.jsonl"
    payload = runner.request_payload(scenario, model="private-model", proxy_policy=True)
    planner = runner.PhasePlanner()

    class ProxyModel:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            for sequence, phase in enumerate(("acquisition", "acquisition", "finalization"), start=1):
                observed = planner.plan(payload, phase=phase)
                observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
                _append_observer_record(runner, observer_path, observed, sequence)
            return {
                "content": '{"status":"passed"}',
                "tool_calls": [],
                runner.PROXY_RESPONSE_ACCOUNTING: {
                    "upstream_calls": 3,
                    "corrections": 1,
                    "blocked_duplicates": 2,
                    "blocked_stalls": 1,
                },
            }

    accounting = runner.ProxyRequestAccounting()
    client = runner.CompatibilityClient(
        ProxyModel(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(observer_path, [scenario.case_id]),
        request_accounting=accounting,
    )

    response = client.complete(payload)

    assert runner.PROXY_RESPONSE_ACCOUNTING not in response
    assert accounting.records == (
        runner.ProxyRequestRecord(
            sequence=1,
            outcome="succeeded",
            local_projection=False,
            attempt_sequence_start=1,
            attempt_sequence_end=3,
            attempt_count=3,
            successful_attempt_count=3,
            phase_counts={"acquisition": 2, "finalization": 1},
            retry_attempt_count=1,
            blocked_duplicate_count=2,
            blocked_stall_count=1,
        ),
    )


def test_proxy_request_accounting_records_local_projection_with_exactly_zero_attempts(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer_path = tmp_path / "observer.jsonl"

    class ProjectingProxy:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            return {
                LOCAL_PROJECTION_EXTENSION: local_projection_accounting(),
                runner.PROXY_RESPONSE_ACCOUNTING: {
                    "upstream_calls": 0,
                    "corrections": 0,
                    "blocked_duplicates": 0,
                    "blocked_stalls": 0,
                },
            }

    accounting = runner.ProxyRequestAccounting()
    client = runner.CompatibilityClient(
        ProjectingProxy(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(observer_path, [scenario.case_id]),
        request_accounting=accounting,
    )

    client.complete(runner.request_payload(scenario, model="model", proxy_policy=True))

    assert accounting.records[0] == runner.ProxyRequestRecord(
        sequence=1,
        outcome="succeeded",
        local_projection=True,
        attempt_sequence_start=None,
        attempt_sequence_end=None,
        attempt_count=0,
        successful_attempt_count=0,
        phase_counts={"acquisition": 0, "finalization": 0},
        retry_attempt_count=0,
        blocked_duplicate_count=0,
        blocked_stall_count=0,
    )
    assert not observer_path.exists()


@pytest.mark.parametrize(
    ("error", "outcome"),
    [
        (ConnectionError("private transport"), "failed"),
        (TimeoutError("private timeout"), "deadline"),
        (asyncio.CancelledError("private cancellation"), "cancelled"),
    ],
)
def test_proxy_request_accounting_classifies_failed_deadline_and_cancelled_calls(monkeypatch, tmp_path, error, outcome):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer_path = tmp_path / "observer.jsonl"
    payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    observed = runner.PhasePlanner().plan(payload, phase="acquisition")
    observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX

    class FailingProxy:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            _append_observer_record(runner, observer_path, observed, 1, cache=False, status_code=None)
            raise error

    accounting = runner.ProxyRequestAccounting()
    client = runner.CompatibilityClient(
        FailingProxy(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(observer_path, [scenario.case_id]),
        request_accounting=accounting,
    )

    with pytest.raises(type(error)):
        client.complete(payload)

    assert accounting.records[0] == runner.ProxyRequestRecord(
        sequence=1,
        outcome=outcome,
        local_projection=False,
        attempt_sequence_start=1,
        attempt_sequence_end=1,
        attempt_count=1,
        successful_attempt_count=0,
        phase_counts={"acquisition": 1, "finalization": 0},
        retry_attempt_count=0,
        blocked_duplicate_count=0,
        blocked_stall_count=0,
    )


@pytest.mark.parametrize("failure_kind", ["cache", "observer"])
def test_proxy_request_accounting_is_exactly_once_after_post_response_validation_failure(
    monkeypatch, tmp_path, failure_kind
):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer_path = tmp_path / "observer.jsonl"
    payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    observed = runner.PhasePlanner().plan(payload, phase="acquisition")
    observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    if failure_kind == "observer":
        observed["top_k"] = 999

    class Proxy:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            _append_observer_record(
                runner,
                observer_path,
                observed,
                1,
                cache=failure_kind != "cache",
            )
            return {
                "content": "",
                "tool_calls": [],
                runner.PROXY_RESPONSE_ACCOUNTING: {
                    "upstream_calls": 1,
                    "corrections": 0,
                    "blocked_duplicates": 0,
                    "blocked_stalls": 0,
                },
            }

    accounting = runner.ProxyRequestAccounting()
    client = runner.CompatibilityClient(
        Proxy(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(observer_path, [scenario.case_id]),
        require_cache_evidence=True,
        request_accounting=accounting,
    )

    with pytest.raises(runner.PreflightFailure):
        client.complete(payload)

    assert len(accounting.records) == 1
    assert accounting.records[0].outcome == "failed"
    assert accounting.records[0].attempt_sequence_start == 1
    assert accounting.records[0].attempt_sequence_end == 1
    assert accounting.records[0].attempt_count == 1


def test_proxy_http_client_projects_only_exact_safe_telemetry_headers(monkeypatch) -> None:
    runner = load_runner(monkeypatch)
    headers = Message()
    headers["X-Shiftedx-Upstream-Calls"] = "3"
    headers["X-Shiftedx-Corrections"] = "1"
    headers["X-Shiftedx-Blocked-Duplicates"] = "2"
    headers["X-Shiftedx-Blocked-Stalls"] = "0"
    headers["X-Private-Diagnostic"] = "must-not-survive"

    class Response:
        def __init__(self):
            self.headers = headers

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"choices":[{"message":{"content":"ok"}}]}'

        def geturl(self):
            return "http://proxy.invalid/v1/chat/completions"

    monkeypatch.setattr(runner._NO_PROXY_OPENER, "open", lambda *_args, **_kwargs: Response())
    client = runner.ProjectionAwareOpenAIClient("http://proxy.invalid/v1")
    client.capture_proxy_accounting = True
    client.timeout_s = 1.0
    client._request = lambda _payload: SimpleNamespace(full_url="http://proxy.invalid/v1/chat/completions")

    response = client.complete({"model": "model"})

    assert response[runner.PROXY_RESPONSE_ACCOUNTING] == {
        "upstream_calls": 3,
        "corrections": 1,
        "blocked_duplicates": 2,
        "blocked_stalls": 0,
    }
    assert "must-not-survive" not in json.dumps(response)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "nonnumeric", "negative", "leading-zero"])
def test_proxy_http_client_rejects_missing_duplicate_or_noncanonical_accounting_headers(monkeypatch, mutation) -> None:
    runner = load_runner(monkeypatch)
    headers = Message()
    for name in (
        "Upstream-Calls",
        "Corrections",
        "Blocked-Duplicates",
        "Blocked-Stalls",
    ):
        headers[f"X-Shiftedx-{name}"] = "0"
    if mutation == "missing":
        del headers["X-Shiftedx-Corrections"]
    elif mutation == "duplicate":
        headers["X-Shiftedx-Corrections"] = "7"
    elif mutation == "nonnumeric":
        headers.replace_header("X-Shiftedx-Corrections", "private-value")
    elif mutation == "negative":
        headers.replace_header("X-Shiftedx-Corrections", "-1")
    else:
        headers.replace_header("X-Shiftedx-Corrections", "01")

    with pytest.raises(runner.PreflightFailure, match="^proxy response accounting is unavailable$"):
        runner._proxy_accounting_from_headers(headers)


def test_proxy_http_transport_disables_ambient_proxies_and_rejects_redirects(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy.invalid")
    runner = load_runner(monkeypatch)
    redirect_handlers = [
        handler for handler in runner._NO_PROXY_OPENER.handlers if isinstance(handler, runner._RejectAllRedirects)
    ]

    assert runner._NO_PROXY_HANDLER.proxies == {}
    assert len(redirect_handlers) == 1
    assert redirect_handlers[0].redirect_request(None, None, None, None, None, None) is None


def test_proxy_http_client_accepts_canonical_zero_header_local_projection(monkeypatch) -> None:
    runner = load_runner(monkeypatch)
    body = json.dumps(
        {
            "choices": [{"message": {"content": '{"status":"passed"}'}}],
            LOCAL_PROJECTION_EXTENSION: local_projection_accounting(),
        }
    ).encode()

    class Response:
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return body

        def geturl(self):
            return "http://proxy.invalid/v1/chat/completions"

    monkeypatch.setattr(runner._NO_PROXY_OPENER, "open", lambda *_args, **_kwargs: Response())
    client = runner.ProjectionAwareOpenAIClient("http://proxy.invalid/v1")
    client.capture_proxy_accounting = True
    client.timeout_s = 1.0
    client._request = lambda _payload: SimpleNamespace(full_url="http://proxy.invalid/v1/chat/completions")

    response = client.complete({"model": "model"})

    assert response[runner.PROXY_RESPONSE_ACCOUNTING] == {
        "upstream_calls": 0,
        "corrections": 0,
        "blocked_duplicates": 0,
        "blocked_stalls": 0,
    }
    assert response[LOCAL_PROJECTION_EXTENSION]["origin"] == "local_projection"


def test_proxy_http_client_rejects_oversized_or_redirected_responses(monkeypatch) -> None:
    runner = load_runner(monkeypatch)

    class Response:
        headers = Message()

        def __init__(self, *, redirected=False, oversized=False):
            self.redirected = redirected
            self.oversized = oversized

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            return b"x" * limit if self.oversized else b"{}"

        def geturl(self):
            return "http://redirect.invalid/" if self.redirected else "http://proxy.invalid/v1/chat/completions"

    client = runner.ProjectionAwareOpenAIClient("http://proxy.invalid/v1")
    client.capture_proxy_accounting = True
    client.timeout_s = 1.0
    client._request = lambda _payload: SimpleNamespace(full_url="http://proxy.invalid/v1/chat/completions")
    monkeypatch.setattr(runner._NO_PROXY_OPENER, "open", lambda *_args, **_kwargs: Response(redirected=True))
    with pytest.raises(runner.PreflightFailure, match="final URL differed"):
        client.complete({"model": "model"})

    monkeypatch.setattr(runner._NO_PROXY_OPENER, "open", lambda *_args, **_kwargs: Response(oversized=True))
    with pytest.raises(runner.PreflightFailure, match="exceeded size limit"):
        client.complete({"model": "model"})


def test_proxy_http_client_suppresses_private_malformed_body_and_transport_causes(monkeypatch) -> None:
    runner = load_runner(monkeypatch)
    private_marker = "private-response-and-endpoint-marker"

    class MalformedResponse:
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return (private_marker + "{").encode()

        def geturl(self):
            return "http://proxy.invalid/v1/chat/completions"

    client = runner.ProjectionAwareOpenAIClient("http://proxy.invalid/v1")
    client.capture_proxy_accounting = True
    client.timeout_s = 1.0
    client._request = lambda _payload: SimpleNamespace(full_url="http://proxy.invalid/v1/chat/completions")
    monkeypatch.setattr(runner._NO_PROXY_OPENER, "open", lambda *_args, **_kwargs: MalformedResponse())

    with pytest.raises(runner.PreflightFailure) as malformed:
        client.complete({"model": "model"})
    assert str(malformed.value) == "proxy response is malformed"
    assert malformed.value.__cause__ is None
    assert private_marker not in str(malformed.value)

    private_transport = runner.urllib.error.URLError(private_marker)
    monkeypatch.setattr(
        runner._NO_PROXY_OPENER,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(private_transport),
    )
    with pytest.raises(ConnectionError) as transport:
        client.complete({"model": "model"})
    assert str(transport.value) == "proxy transport failed"
    assert transport.value.__cause__ is None
    assert private_marker not in str(transport.value)


def test_proxy_http_504_is_body_free_and_classified_as_deadline(monkeypatch) -> None:
    runner = load_runner(monkeypatch)
    failure = runner.urllib.error.HTTPError(
        "http://proxy.invalid/v1/chat/completions",
        504,
        "private reason",
        Message(),
        io.BytesIO(b"private response body and credential"),
    )
    monkeypatch.setattr(runner._NO_PROXY_OPENER, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(failure))
    client = runner.ProjectionAwareOpenAIClient("http://proxy.invalid/v1")
    client.capture_proxy_accounting = True
    client.timeout_s = 1.0
    client._request = lambda _payload: SimpleNamespace(full_url="http://proxy.invalid/v1/chat/completions")

    with pytest.raises(runner.ProxyHTTPFailure) as raised:
        client.complete({"model": "model"})

    assert raised.value.status_code == 504
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)
    accounting = runner.ProxyRequestAccounting()
    accounting.record_failure((), raised.value)
    assert accounting.records[0].outcome == "deadline"


def test_proxy_request_ledger_is_exact_private_atomic_and_no_clobber(monkeypatch, tmp_path) -> None:
    runner = load_runner(monkeypatch)
    output = tmp_path / "proxy-requests.jsonl"
    records = [
        runner.ProxyRequestRecord(
            sequence=1,
            outcome="succeeded",
            local_projection=False,
            attempt_sequence_start=1,
            attempt_sequence_end=2,
            attempt_count=2,
            successful_attempt_count=2,
            phase_counts={"acquisition": 1, "finalization": 1},
            retry_attempt_count=0,
            blocked_duplicate_count=1,
            blocked_stall_count=0,
        ),
        runner.ProxyRequestRecord(
            sequence=2,
            outcome="succeeded",
            local_projection=True,
            attempt_sequence_start=None,
            attempt_sequence_end=None,
            attempt_count=0,
            successful_attempt_count=0,
            phase_counts={"acquisition": 0, "finalization": 0},
            retry_attempt_count=0,
            blocked_duplicate_count=0,
            blocked_stall_count=0,
        ),
    ]

    runner.write_request_accounting_ledger(output, records)

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert rows == [
        {
            "sequence": 1,
            "outcome": "succeeded",
            "local_projection": False,
            "attempt_sequence_start": 1,
            "attempt_sequence_end": 2,
            "attempt_count": 2,
            "successful_attempt_count": 2,
            "phase_counts": {"acquisition": 1, "finalization": 1},
            "retry_attempt_count": 0,
            "blocked_duplicate_count": 1,
            "blocked_stall_count": 0,
        },
        {
            "sequence": 2,
            "outcome": "succeeded",
            "local_projection": True,
            "attempt_sequence_start": None,
            "attempt_sequence_end": None,
            "attempt_count": 0,
            "successful_attempt_count": 0,
            "phase_counts": {"acquisition": 0, "finalization": 0},
            "retry_attempt_count": 0,
            "blocked_duplicate_count": 0,
            "blocked_stall_count": 0,
        },
    ]
    assert output.stat().st_mode & 0o777 == 0o600
    prior = output.read_bytes()
    with pytest.raises(ReconciliationFailure, match="reconciliation_request_ledger_exists"):
        runner.write_request_accounting_ledger(output, records)
    assert output.read_bytes() == prior


def test_proxy_request_ledger_rejects_symlink_and_untyped_private_input(monkeypatch, tmp_path) -> None:
    runner = load_runner(monkeypatch)
    target = tmp_path / "prior.jsonl"
    target.write_text('{"private":"prior"}\n', encoding="utf-8")
    target.chmod(0o600)
    symlink = tmp_path / "proxy-requests.jsonl"
    symlink.symlink_to(target)

    with pytest.raises(ReconciliationFailure, match="reconciliation_request_ledger_exists"):
        runner.write_request_accounting_ledger(symlink, [])
    assert target.read_text(encoding="utf-8") == '{"private":"prior"}\n'

    invalid = tmp_path / "invalid.jsonl"
    with pytest.raises(ReconciliationFailure, match="reconciliation_request_ledger_invalid"):
        runner.write_request_accounting_ledger(invalid, [{"private_prompt": "must-not-survive"}])
    assert not invalid.exists()


def test_direct_client_records_each_actual_attempt_in_sequence_with_safe_cache(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]

    class DirectModel:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            return _cache_response(content='{"status":"passed"}', bypass=True)

    payload = runner._preflight_payload(scenario, model="private-model", proxy_policy=False, no_tools=True)
    payload["metadata"] = {"cache_mode": "bypass"}
    client = runner.CompatibilityClient(
        DirectModel(), arm="direct", scenario_order=[scenario.case_id], proxy_policy=False
    )

    client.complete(payload)
    client.complete(payload)

    assert [record.sequence for record in client.attempt_records] == [1, 2]
    assert all(record.status_code == 200 for record in client.attempt_records)
    assert all(record.cache is not None for record in client.attempt_records)
    assert all(record.fields["cache_mode_policy"] == "bypass" for record in client.attempt_records)
    assert "private-model" not in json.dumps([record.to_dict() for record in client.attempt_records])


def test_direct_client_records_null_response_before_transport_error(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]

    class Unavailable:
        def complete(self, _payload, *, stream=False):
            raise ConnectionError("private transport detail")

    client = runner.CompatibilityClient(
        Unavailable(), arm="direct", scenario_order=[scenario.case_id], proxy_policy=False
    )
    payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)

    with pytest.raises(ConnectionError):
        client.complete(payload)

    assert len(client.attempt_records) == 1
    assert client.attempt_records[0].status_code is None
    assert client.attempt_records[0].cache is None


def test_bypass_metadata_reaches_every_direct_phase(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    sent = []

    class DirectModel:
        def complete(self, payload, *, stream=False):
            sent.append(copy.deepcopy(payload))
            return _cache_response(content='{"status":"passed"}', bypass=True)

    payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    payload["metadata"] = {"cache_mode": "bypass"}
    runner.CompatibilityClient(
        DirectModel(), arm="direct", scenario_order=[scenario.case_id], proxy_policy=False
    ).complete(payload)

    assert len(sent) == 2
    assert all(item["metadata"] == {"cache_mode": "bypass"} for item in sent)


def test_cache_prime_payload_matches_first_scored_model_facing_digest(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    scenario_order = [scenario.case_id]

    direct_prime = runner.cache_prime_payload(scenario, model="model", arm="direct")
    direct_scored = runner.PhasePlanner().plan(
        runner.request_payload(scenario, model="model", proxy_policy=False),
        phase="acquisition",
    )
    proxy_prime = runner.cache_prime_payload(scenario, model="model", arm="proxy")
    proxy_scored = runner.PhasePlanner().plan(
        runner.request_payload(scenario, model="model", proxy_policy=True),
        phase="acquisition",
    )
    proxy_scored["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX

    assert (
        runner.model_boundary_fingerprint(direct_prime, scenario_order=scenario_order).digest
        == runner.model_boundary_fingerprint(direct_scored, scenario_order=scenario_order).digest
    )
    assert (
        runner.model_boundary_fingerprint(proxy_prime, scenario_order=scenario_order).digest
        == runner.model_boundary_fingerprint(proxy_scored, scenario_order=scenario_order).digest
    )
    assert proxy_prime["messages"][0]["content"].count(HARNESS_SYSTEM_SUFFIX) == 1


def test_cache_prime_cli_sends_one_payload_and_writes_only_one_safe_attempt(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    sent = []

    class PrimeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def complete(self, payload, *, stream=False):
            sent.append(copy.deepcopy(payload))
            return _cache_response(content="private model output", bypass=False)

    runner.ProjectionAwareOpenAIClient = PrimeClient
    attempt_ledger = tmp_path / "prime-attempt.jsonl"
    scored_output = tmp_path / "must-not-exist.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://model.invalid/v1",
            "--model",
            "private-model",
            "--output",
            str(scored_output),
            "--variant",
            "prime",
            "--cache-mode",
            "warm-prefix",
            "--cache-prime-only",
            "--cache-prime-arm",
            "proxy",
            "--model-attempt-ledger",
            str(attempt_ledger),
        ],
    )

    runner.main()

    assert len(sent) == 1
    assert sent[0]["messages"][0]["content"].count(HARNESS_SYSTEM_SUFFIX) == 1
    records = read_model_boundary_observer_records(attempt_ledger)
    assert len(records) == 1
    assert records[0].cache is not None
    assert "private-model" not in attempt_ledger.read_text(encoding="utf-8")
    assert "private model output" not in attempt_ledger.read_text(encoding="utf-8")
    assert not scored_output.exists()


def test_cache_prime_rejects_bypass_before_client_or_output(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)

    class UnexpectedClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("bypass prime must fail before client construction")

    runner.ProjectionAwareOpenAIClient = UnexpectedClient
    attempt_ledger = tmp_path / "prime-attempt.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://model.invalid/v1",
            "--model",
            "model",
            "--output",
            str(tmp_path / "unused.jsonl"),
            "--variant",
            "prime",
            "--cache-mode",
            "bypass",
            "--cache-prime-only",
            "--cache-prime-arm",
            "direct",
            "--model-attempt-ledger",
            str(attempt_ledger),
        ],
    )

    with pytest.raises(SystemExit, match="warm-prefix"):
        runner.main()
    assert not attempt_ledger.exists()


def test_private_api_key_reader_rejects_symlink_and_non_private_mode(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    target = tmp_path / "key"
    target.write_text("private credential", encoding="utf-8")
    target.chmod(0o600)
    symlink = tmp_path / "key-link"
    symlink.symlink_to(target)

    with pytest.raises(SystemExit, match="private mode-0600 regular file"):
        runner._read_key(symlink)

    target.chmod(0o644)
    with pytest.raises(SystemExit, match="private mode-0600 regular file"):
        runner._read_key(target)


def test_scored_direct_run_writes_actual_attempt_ledger_atomically(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome, _direct_outcome = _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation)
    output = tmp_path / "direct-live.jsonl"
    attempts = tmp_path / "direct-attempts.jsonl"

    class DirectClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def complete(self, _payload, *, stream=False):
            return _cache_response(
                tool_calls=[{"id": "call-1", "function": {"name": "read_file"}}],
                bypass=False,
            )

    def run_cases(*, client, model, output_path, case_id, **_kwargs):
        scenario = next(item for item in runner.scenario_set("expanded") if item.case_id == case_id)
        client.complete(runner.request_payload(scenario, model=model, proxy_policy=False))
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"case_id": case_id, "passed": True}) + "\n")
        return [{"case_id": case_id}]

    runner.ProjectionAwareOpenAIClient = DirectClient
    runner.run_agentic_cases = run_cases
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://model.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--variant",
            "direct",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(preflight_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
            "--direct-model-attempt-ledger",
            str(attempts),
        ],
    )

    runner.main()

    records = read_model_boundary_observer_records(attempts)
    assert [record.sequence for record in records] == [1, 2]
    assert all(record.cache is not None for record in records)
    assert attempts.stat().st_mode & 0o777 == 0o600


def _cache_response(*, content="", tool_calls=None, bypass=False):
    prompt_tokens = 11
    cached_tokens = 0 if bypass else 5
    return {
        "content": content,
        "tool_calls": tool_calls or [],
        "mtplx_stats": {
            "prompt_tokens": prompt_tokens,
            "cached_tokens": cached_tokens,
            "new_prefill_tokens": prompt_tokens - cached_tokens,
            "cache_source": "none" if bypass else "ram",
            "ssd_cache_hit": False,
            "ssd_cached_tokens": 0,
            "session_cache_hit": not bypass,
            "request_session_bank_bypass": bypass,
            "session_postcommit_snapshot": {"stored": not bypass},
        },
    }


def test_end_to_end_fake_paired_proxy_preflight_passes(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer = tmp_path / "observer.jsonl"
    planner = runner.PhasePlanner()
    sequence = [0]

    class FakeClient:
        def __init__(self, base_url, *_args, **_kwargs):
            self.is_proxy = "proxy" in base_url

        def complete(self, payload, *, stream=False):
            assert stream is False
            if self.is_proxy:
                observed_payloads = (
                    (planner.plan(payload, phase="acquisition"),)
                    if payload.get("tools")
                    and not any(message.get("role") == "tool" for message in payload["messages"])
                    else (
                        planner.plan(payload, phase="acquisition"),
                        planner.plan(payload, phase="finalization"),
                    )
                    if payload.get("tools")
                    else (payload,)
                )
                for observed in observed_payloads:
                    observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
                    sequence[0] += 1
                    _append_observer_record(runner, observer, observed, sequence[0])
            if payload.get("tools") and not any(message.get("role") == "tool" for message in payload["messages"]):
                response = _cache_response(
                    tool_calls=[{"id": "call-1", "function": {"name": "read_file", "arguments": "{}"}}],
                    bypass=True,
                )
            else:
                response = _cache_response(content='{"status":"passed"}', bypass=True)
            if self.is_proxy:
                response[runner.PROXY_RESPONSE_ACCOUNTING] = {
                    "upstream_calls": len(observed_payloads),
                    "corrections": 0,
                    "blocked_duplicates": 0,
                    "blocked_stalls": 0,
                }
            return response

    runner.ProjectionAwareOpenAIClient = FakeClient
    metric_values = iter(({"acquisition": 0, "finalization": 0}, {"acquisition": 2, "finalization": 1}))
    monkeypatch.setattr(runner, "_phase_metrics", lambda *_args: next(metric_values))
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "preflight-runtime-attestation.json",
        stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
        scenario_order=[scenario.case_id],
    )
    args = SimpleNamespace(
        direct_base_url="http://direct.invalid/v1",
        proxy_base_url="http://proxy.invalid/v1",
        proxy_metrics_url="http://metrics.invalid",
        proxy_observer_ledger=observer,
        candidate_source_commit=source_commit,
        candidate_image_digest=image_digest,
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        direct_api_key_file=None,
        proxy_api_key_file=None,
        runtime_attestation=runtime_attestation,
        cache_mode="bypass",
        direct_model_attempt_ledger=tmp_path / "direct-attempts.jsonl",
        proxy_request_ledger=tmp_path / "proxy-requests.jsonl",
        output=tmp_path / "preflight.jsonl",
    )

    runner._run_paired_preflight(args, [scenario])

    assert '"status":"passed"' in args.output.read_text()
    direct_attempts = read_model_boundary_observer_records(args.direct_model_attempt_ledger)
    assert [record.sequence for record in direct_attempts] == [1, 2, 3, 4]
    assert all(record.fields["cache_mode_policy"] == "bypass" for record in direct_attempts)
    assert all(record.cache.request_session_bank_bypass for record in direct_attempts if record.cache)
    proxy_attempts = read_model_boundary_observer_records(observer)
    assert all(record.fields["cache_mode_policy"] == "bypass" for record in proxy_attempts)
    assert all(record.cache.request_session_bank_bypass for record in proxy_attempts if record.cache)


def test_stale_proxy_observer_ledger_is_rejected_without_overwriting_it(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    observer = tmp_path / "observer.jsonl"
    observer.write_text('{"old":"record"}\n')
    output = tmp_path / "preflight.jsonl"
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "preflight-runtime-attestation.json",
        stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
        scenario_order=["case-1"],
    )
    args = SimpleNamespace(
        direct_base_url="http://direct.invalid/v1",
        proxy_base_url="http://proxy.invalid/v1",
        proxy_metrics_url="http://metrics.invalid",
        proxy_observer_ledger=observer,
        candidate_source_commit=source_commit,
        candidate_image_digest=image_digest,
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        direct_api_key_file=None,
        proxy_api_key_file=None,
        runtime_attestation=runtime_attestation,
        output=output,
    )

    with pytest.raises(SystemExit, match="proxy_model_boundary_observer_failed"):
        runner._run_paired_preflight(args, [runner.scenario_set("expanded")[0]])

    assert observer.read_text() == '{"old":"record"}\n'
    assert '"status":"failed"' in output.read_text()


def test_scored_fingerprint_uses_the_actual_compatibility_payload(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]

    class TerminalModel:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            return {"content": '{"status":"passed"}', "tool_calls": []}

    payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    payload["top_k"] = 99
    client = runner.CompatibilityClient(
        TerminalModel(), arm="direct", scenario_order=[scenario.case_id], proxy_policy=False
    )
    client.complete(payload)

    assert client.actual_contract_fingerprints()["downstream"]["fields"]["sampler"]["top_k"] == 99


def test_observed_proxy_model_boundary_drift_is_not_masked_by_matching_plan(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    direct_components = runner.model_boundary_fingerprint(runner.PhasePlanner().plan(payload, phase="acquisition"))
    drifted_payload = runner.PhasePlanner().plan(payload, phase="acquisition")
    drifted_payload["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    drifted_payload["top_k"] = 99
    proxy_components = runner.model_boundary_fingerprint(drifted_payload)
    terminal_payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)
    terminal = runner.model_boundary_fingerprint(terminal_payload)
    proxy_terminal_payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)
    proxy_terminal_payload["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    proxy_terminal = runner.model_boundary_fingerprint(proxy_terminal_payload)
    fingerprint = runner.SafeFingerprint("downstream", "same", {})
    observations = [
        runner.PreflightObservation(
            "direct", True, 1, ("acquisition", "finalization"), True, fingerprint, (direct_components,)
        ),
        runner.PreflightObservation(
            "proxy",
            True,
            1,
            ("acquisition", "finalization"),
            True,
            fingerprint,
            (proxy_components,),
            {"acquisition": 2, "finalization": 1},
        ),
        runner.PreflightObservation("direct", False, 0, ("terminal",), True, fingerprint, (terminal,)),
        runner.PreflightObservation("proxy", False, 0, ("terminal",), True, fingerprint, (proxy_terminal,)),
    ]

    with pytest.raises(runner.PreflightFailure, match="model-facing contract mismatch"):
        runner.assert_preflight(observations)


def test_failed_preflight_writes_safe_unscored_ledger_and_never_creates_scored_output(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    payload = runner.request_payload(scenario, model="private-model", proxy_policy=False)
    fingerprint, model_facing = runner.request_fingerprints(payload, [scenario.case_id], policy_delta={})
    output = tmp_path / "preflight.jsonl"

    with pytest.raises(runner.PreflightFailure, match="zero native acquisition tool calls"):
        runner.write_preflight_ledger(
            output,
            [
                runner.PreflightObservation(
                    "direct", True, 0, ("acquisition", "finalization"), True, fingerprint, model_facing
                )
            ],
            source_commit="a" * 40,
            image_digest="sha256:" + "0" * 64,
            contract_digests=_lane_contract_digests(),
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
        )

    serialized = output.read_text()
    assert '"status":"failed"' in serialized
    assert '"scored":false' in serialized
    assert scenario.prompt not in serialized
    assert "read_file" not in serialized
    assert "private-model" not in serialized


def test_scoring_gate_rejects_a_different_scenario_contract(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    _write_passing_preflight(runner, ledger, source_commit, image_digest, contract_digests=_lane_contract_digests())

    with pytest.raises(SystemExit, match="qualification contract"):
        runner.require_scoring_gate(
            output=tmp_path / "scored.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest="different",
            arm="direct",
            cache_lane="warm-prefix",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
        )


def test_failed_proxy_variant_uses_declared_proxy_policy_not_label_heuristics(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    row = runner.failure_row(
        scenario=scenario,
        error=RuntimeError("HTTP 502"),
        run_id="run",
        variant="cold-pair1-proxy-expanded",
        agentic_set="expanded",
        model="model",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        wall_s=0.1,
    )

    assert row["contract_fingerprints"]["downstream"]["fields"]["declared_policy_deltas"] == {
        "x-shiftedx-require-receipt": True
    }


def test_observed_proxy_harness_suffix_is_the_only_allowed_system_delta(monkeypatch):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    direct = runner.model_boundary_fingerprint(
        runner.PhasePlanner().plan(payload, phase="acquisition"), scenario_order=[scenario.case_id]
    )
    proxy_payload = runner.PhasePlanner().plan(payload, phase="acquisition")
    proxy_payload["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    proxy = runner.model_boundary_fingerprint(proxy_payload, scenario_order=[scenario.case_id])

    assert direct.fields["system_prompt_sha256"] != proxy.fields["system_prompt_sha256"]
    assert direct.fields["base_system_prompt_sha256"] == proxy.fields["base_system_prompt_sha256"]
    assert set(proxy.fields["declared_policy_deltas"]) == {"harness_system_suffix_sha256"}
    assert runner._contract_mismatches(direct, proxy) == []


def test_preflight_ledger_never_overwrites_existing_evidence(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    output = tmp_path / "preflight.jsonl"
    output.write_text('{"prior":"evidence"}\n')

    with pytest.raises(runner.PreflightFailure, match="overwrite"):
        runner.write_preflight_ledger(
            output,
            [],
            source_commit="a" * 40,
            image_digest="sha256:" + "0" * 64,
            contract_digests=_lane_contract_digests(),
            run_manifest_sha256="1" * 64,
        )

    assert output.read_text() == '{"prior":"evidence"}\n'


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("", "harness system policy delta"),
        (HARNESS_SYSTEM_SUFFIX.replace("receipt-grounded", "receipt altered"), "harness system policy delta"),
        (HARNESS_SYSTEM_SUFFIX + HARNESS_SYSTEM_SUFFIX, "harness system policy delta"),
        (" extra mutation" + HARNESS_SYSTEM_SUFFIX, "model-facing contract mismatch"),
    ],
)
def test_preflight_rejects_every_proxy_system_mutation_except_the_exact_suffix(monkeypatch, mutation, message):
    runner = load_runner(monkeypatch)

    with pytest.raises(runner.PreflightFailure, match=message):
        runner.assert_preflight(_suffix_pair_observations(runner, mutation))


def test_preflight_rejects_proxy_model_identity_drift(monkeypatch):
    runner = load_runner(monkeypatch)
    observations = _suffix_pair_observations(runner, HARNESS_SYSTEM_SUFFIX)
    proxy_tool = observations[1]
    proxy_model = dict(proxy_tool.model_facing[0].fields)
    proxy_model["model_id_sha256"] = "0" * 64
    observations[1] = runner.PreflightObservation(
        proxy_tool.arm,
        proxy_tool.tool_required,
        proxy_tool.native_acquisition_tool_calls,
        proxy_tool.phases,
        proxy_tool.terminal_schema_valid,
        proxy_tool.downstream,
        (runner.SafeFingerprint("model_facing_observed", "identity-drift", proxy_model),),
        proxy_tool.proxy_phase_counts,
    )

    with pytest.raises(runner.PreflightFailure, match="model-facing contract mismatch: model_id_sha256"):
        runner.assert_preflight(observations)


def test_scoring_gate_rejects_manifest_and_model_identity_mismatch(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    _write_passing_preflight(runner, ledger, source_commit, image_digest)
    summary = next(
        json.loads(line)
        for line in ledger.read_text().splitlines()
        if json.loads(line)["record_type"] == "paired_preflight_summary"
    )

    with pytest.raises(SystemExit, match="run-manifest identity"):
        runner.require_scoring_gate(
            output=tmp_path / "manifest-mismatch.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["direct"],
            cache_lane="warm-prefix",
            arm="direct",
            model="model",
            run_manifest_sha256="2" * 64,
        )
    with pytest.raises(SystemExit, match="model identity"):
        runner.require_scoring_gate(
            output=tmp_path / "model-mismatch.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["direct"],
            cache_lane="warm-prefix",
            arm="direct",
            model="other-model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
        )


def test_direct_scoring_requires_the_exact_preflight_runtime_attestation(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    runtime_attestation = _write_passing_preflight(runner, ledger, source_commit, image_digest)
    preflight_outcome = _write_runtime_outcome(
        tmp_path / "preflight-runtime-outcome.json",
        stage="preflight",
        attestation=runtime_attestation,
        output=ledger,
        output_record_count=5,
    )
    summary = next(
        json.loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["record_type"] == "paired_preflight_summary"
    )

    runner.require_scoring_gate(
        output=tmp_path / "direct.jsonl",
        preflight_ledger=ledger,
        candidate_source_commit=source_commit,
        candidate_image_digest=image_digest,
        contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["direct"],
        cache_lane="warm-prefix",
        arm="direct",
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        scenario_order=["case-1", "case-2"],
        runtime_attestation=runtime_attestation,
        preflight_runtime_outcome=preflight_outcome,
    )

    document = json.loads(runtime_attestation.read_text(encoding="utf-8"))
    runtime_attestation.write_text(json.dumps(document, indent=2), encoding="utf-8")
    with pytest.raises(SystemExit, match="runtime attestation identity"):
        runner.require_scoring_gate(
            output=tmp_path / "tampered.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["direct"],
            cache_lane="warm-prefix",
            arm="direct",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            scenario_order=["case-1", "case-2"],
            runtime_attestation=runtime_attestation,
            preflight_runtime_outcome=preflight_outcome,
        )
    assert not (tmp_path / "tampered.jsonl").exists()


@pytest.mark.parametrize("kind", ["missing", "failed", "tampered", "incomplete"])
def test_scoring_gate_rejects_invalid_preflight_runtime_outcome(monkeypatch, tmp_path, kind):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    runtime_attestation = _write_passing_preflight(runner, ledger, source_commit, image_digest)
    outcome = _write_runtime_outcome(
        tmp_path / "preflight-runtime-outcome.json",
        stage="preflight",
        attestation=runtime_attestation,
        output=ledger,
        output_record_count=5,
    )
    summary = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    if kind == "missing":
        outcome.unlink()
    elif kind == "failed":
        document = json.loads(outcome.read_text(encoding="utf-8"))
        document.update(status="failed", action_exit_code=1, failure_category="runtime_cleanup_failed")
        outcome.write_text(json.dumps(document), encoding="utf-8")
    elif kind == "tampered":
        document = json.loads(outcome.read_text(encoding="utf-8"))
        document["private_prompt"] = "must never enter an error"
        outcome.write_text(json.dumps(document), encoding="utf-8")
    else:
        ledger.write_text("\n".join(ledger.read_text(encoding="utf-8").splitlines()[1:]) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="passed matching preflight runtime outcome") as raised:
        runner.require_scoring_gate(
            output=tmp_path / "scored.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["direct"],
            cache_lane="warm-prefix",
            arm="direct",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            scenario_order=["case-1", "case-2"],
            runtime_attestation=runtime_attestation,
            preflight_runtime_outcome=outcome,
        )

    assert "must never enter an error" not in str(raised.value)
    assert not (tmp_path / "scored.jsonl").exists()


@pytest.mark.parametrize("kind", ["missing", "failed", "tampered", "incomplete"])
def test_proxy_scoring_requires_a_passed_direct_runtime_outcome(monkeypatch, tmp_path, kind):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, ledger, source_commit, image_digest)
    preflight_outcome = _write_runtime_outcome(
        tmp_path / "preflight-runtime-outcome.json",
        stage="preflight",
        attestation=preflight_attestation,
        output=ledger,
        output_record_count=5,
    )
    scored_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    direct_output = tmp_path / "scored-direct.jsonl"
    direct_output.write_text('{"case_id":"case-1"}\n{"case_id":"case-2"}\n', encoding="utf-8")
    direct_output.chmod(0o600)
    direct_outcome = _write_runtime_outcome(
        tmp_path / "scored-direct-runtime-outcome.json",
        stage="scored-direct",
        attestation=preflight_attestation,
        output=direct_output,
        output_record_count=2,
    )
    if kind == "missing":
        direct_outcome.unlink()
    elif kind == "failed":
        document = json.loads(direct_outcome.read_text(encoding="utf-8"))
        document.update(status="failed", action_exit_code=1, failure_category="action_failed")
        direct_outcome.write_text(json.dumps(document), encoding="utf-8")
    elif kind == "tampered":
        direct_output.write_text('{"case_id":"changed"}\n{"case_id":"case-2"}\n', encoding="utf-8")
    else:
        direct_output.write_text('{"case_id":"case-1"}\n', encoding="utf-8")
    summary = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])

    with pytest.raises(SystemExit, match="passed matching direct runtime outcome"):
        runner.require_scoring_gate(
            output=tmp_path / "proxy.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["proxy"],
            cache_lane="warm-prefix",
            arm="proxy",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            scenario_order=["case-1", "case-2"],
            runtime_attestation=scored_attestation,
            preflight_runtime_outcome=preflight_outcome,
            direct_runtime_outcome=direct_outcome,
        )

    assert not (tmp_path / "proxy.jsonl").exists()


def test_proxy_scoring_resolves_direct_evidence_from_the_direct_outcome_slot(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight_dir = tmp_path / "slots" / "00-preflight"
    scored_dir = tmp_path / "slots" / "01-cold-pair1"
    wrong_dir = tmp_path / "slots" / "02-cold-pair2"
    for directory in (preflight_dir, scored_dir, wrong_dir):
        directory.mkdir(parents=True)
        directory.chmod(0o700)

    ledger = preflight_dir / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, ledger, source_commit, image_digest)
    preflight_outcome = _write_runtime_outcome(
        preflight_dir / "preflight-runtime-outcome.json",
        stage="preflight",
        attestation=preflight_attestation,
        output=ledger,
        output_record_count=5,
    )
    direct_output = scored_dir / "scored-direct.jsonl"
    direct_output.write_text('{"case_id":"case-1"}\n{"case_id":"case-2"}\n', encoding="utf-8")
    direct_output.chmod(0o600)
    direct_outcome = _write_runtime_outcome(
        scored_dir / "scored-direct-runtime-outcome.json",
        stage="scored-direct",
        attestation=preflight_attestation,
        output=direct_output,
        output_record_count=2,
    )
    scored_attestation = _write_runtime_attestation(
        scored_dir / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    summary = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    common = {
        "preflight_ledger": ledger,
        "candidate_source_commit": source_commit,
        "candidate_image_digest": image_digest,
        "contract_digest": summary["qualification_contract_digests"]["warm-prefix"]["proxy"],
        "cache_lane": "warm-prefix",
        "arm": "proxy",
        "model": "model",
        "run_manifest_sha256": _RUN_MANIFEST_SHA256,
        "scenario_order": ["case-1", "case-2"],
        "runtime_attestation": scored_attestation,
        "preflight_runtime_outcome": preflight_outcome,
    }

    runner.require_scoring_gate(
        output=scored_dir / "proxy.jsonl",
        direct_runtime_outcome=direct_outcome,
        **common,
    )

    wrong_outcome = wrong_dir / direct_outcome.name
    wrong_outcome.write_bytes(direct_outcome.read_bytes())
    wrong_outcome.chmod(0o600)
    for name, invalid_outcome in (
        ("wrong-slot", wrong_outcome),
        ("missing-slot", wrong_dir / "missing-runtime-outcome.json"),
    ):
        with pytest.raises(SystemExit, match="passed matching direct runtime outcome"):
            runner.require_scoring_gate(
                output=scored_dir / f"proxy-{name}.jsonl",
                direct_runtime_outcome=invalid_outcome,
                **common,
            )


def test_proxy_scoring_rejects_coordinated_preflight_attestation_and_outcome_replacement(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, ledger, source_commit, image_digest)
    document = json.loads(preflight_attestation.read_text(encoding="utf-8"))
    preflight_attestation.write_text(json.dumps(document, indent=2), encoding="utf-8")
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, ledger, preflight_attestation)
    scored_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    summary = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])

    with pytest.raises(SystemExit, match="passed matching preflight runtime outcome"):
        runner.require_scoring_gate(
            output=tmp_path / "proxy.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["proxy"],
            cache_lane="warm-prefix",
            arm="proxy",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            scenario_order=["case-1", "case-2"],
            runtime_attestation=scored_attestation,
            preflight_runtime_outcome=preflight_outcome,
            direct_runtime_outcome=direct_outcome,
        )

    assert not (tmp_path / "proxy.jsonl").exists()


def test_proxy_scoring_rejects_runtime_contract_drift_before_provenance_or_output(monkeypatch, tmp_path):
    """A fresh proxy instance still has to implement the preflight runtime contract."""

    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, ledger, source_commit, image_digest)
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, ledger, preflight_attestation)
    scored_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_contract_sha256="f" * 64,
        runtime_instance_sha256="5" * 64,
    )
    summary = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    provenance_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        runner,
        "require_candidate_provenance",
        lambda *args: provenance_calls.append(args),
    )

    with pytest.raises(SystemExit, match="runtime contract does not match"):
        runner.require_scoring_gate(
            output=tmp_path / "proxy.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["proxy"],
            cache_lane="warm-prefix",
            arm="proxy",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            scenario_order=["case-1", "case-2"],
            runtime_attestation=scored_attestation,
            preflight_runtime_outcome=preflight_outcome,
            direct_runtime_outcome=direct_outcome,
        )

    assert provenance_calls == []
    assert not (tmp_path / "proxy.jsonl").exists()


def test_proxy_scoring_requires_a_fresh_runtime_instance(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    ledger = tmp_path / "preflight.jsonl"
    _write_passing_preflight(runner, ledger, source_commit, image_digest)
    summary = next(
        json.loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["record_type"] == "paired_preflight_summary"
    )
    scored_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_contract_sha256="3" * 64,
        runtime_instance_sha256="4" * 64,
    )

    with pytest.raises(SystemExit, match="fresh runtime instance"):
        runner.require_scoring_gate(
            output=tmp_path / "proxy.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest=summary["qualification_contract_digests"]["warm-prefix"]["proxy"],
            cache_lane="warm-prefix",
            arm="proxy",
            model="model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            scenario_order=["case-1", "case-2"],
            runtime_attestation=scored_attestation,
        )
    assert not (tmp_path / "proxy.jsonl").exists()


def test_proxy_scored_fingerprints_come_from_new_observer_records_in_turn_order(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer_path = tmp_path / "scored-observer.jsonl"
    planner = runner.PhasePlanner()

    class ProxyClient:
        def __init__(self):
            self.sequence = 0

        def complete(self, payload, *, stream=False):
            assert stream is False
            observed = planner.plan(payload, phase="acquisition")
            observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
            self.sequence += 1
            _append_observer_record(runner, observer_path, observed, self.sequence)
            return {"content": "", "tool_calls": [{"id": "call-1"}]}

    client = runner.CompatibilityClient(
        ProxyClient(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(observer_path, [scenario.case_id]),
    )
    client.complete(runner.request_payload(scenario, model="model", proxy_policy=True))
    actual = client.actual_contract_fingerprints()

    assert len(actual["model_facing"]) == 1
    assert actual["model_facing_turns"] == [{"turn_index": 0, "fingerprints": actual["model_facing"]}]
    assert actual["model_facing"][0]["fields"]["declared_policy_deltas"]
    planned = runner.model_boundary_fingerprint(
        planner.plan(runner.request_payload(scenario, model="model", proxy_policy=True), phase="acquisition"),
        scenario_order=[scenario.case_id],
    )
    assert actual["model_facing"][0]["fields"]["system_prompt_sha256"] != planned.fields["system_prompt_sha256"]


def test_proxy_success_without_typed_response_cache_evidence_fails_closed(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    observer_path = tmp_path / "observer.jsonl"
    planner = runner.PhasePlanner()

    class ProxyClient:
        def complete(self, payload, *, stream=False):
            observed = planner.plan(payload, phase="acquisition")
            observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
            _append_observer_record(runner, observer_path, observed, 1, cache=False)
            return {"content": "", "tool_calls": [{"id": "call-1"}]}

    client = runner.CompatibilityClient(
        ProxyClient(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(observer_path, [scenario.case_id]),
        require_cache_evidence=True,
    )

    with pytest.raises(runner.PreflightFailure, match="response cache evidence"):
        client.complete(runner.request_payload(scenario, model="model", proxy_policy=True))


def test_proxy_observer_missing_stale_or_field_drift_fails_closed_with_safe_partial_evidence(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    scenario = runner.scenario_set("expanded")[0]
    payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    planner = runner.PhasePlanner()

    stale = tmp_path / "stale.jsonl"
    observed = planner.plan(payload, phase="acquisition")
    observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    _append_observer_record(runner, stale, observed, 1)
    with pytest.raises(runner.PreflightFailure, match="not fresh"):
        runner.ModelBoundaryObserverCursor(stale, [scenario.case_id])

    class NoObserverClient:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            return {"content": "", "tool_calls": [{"id": "call-1"}]}

    missing = runner.CompatibilityClient(
        NoObserverClient(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(tmp_path / "missing.jsonl", [scenario.case_id]),
    )
    with pytest.raises(runner.PreflightFailure, match="record count differed"):
        missing.complete(payload)

    drift_path = tmp_path / "drift.jsonl"

    class DriftClient:
        def complete(self, _payload, *, stream=False):
            assert stream is False
            drifted = planner.plan(payload, phase="acquisition")
            drifted["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
            drifted["top_k"] = 99
            _append_observer_record(runner, drift_path, drifted, 1)
            return {"content": "", "tool_calls": [{"id": "call-1"}]}

    drift = runner.CompatibilityClient(
        DriftClient(),
        arm="proxy",
        scenario_order=[scenario.case_id],
        proxy_policy=True,
        observer=runner.ModelBoundaryObserverCursor(drift_path, [scenario.case_id]),
    )
    with pytest.raises(runner.PreflightFailure, match="observer fields differed"):
        drift.complete(payload)
    partial = drift.actual_contract_fingerprints()
    assert partial["model_facing"][0]["fields"]["sampler"]["top_k"] == 99


def test_scored_proxy_cli_requires_a_new_observer_ledger(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation)
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://proxy.invalid/v1",
            "--model",
            "model",
            "--output",
            str(tmp_path / "scored.jsonl"),
            "--agentic-set",
            "expanded",
            "--variant",
            "proxy",
            "--proxy-policy",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
            "--direct-runtime-outcome",
            str(direct_outcome),
        ],
    )

    with pytest.raises(SystemExit, match="requires --proxy-observer-ledger"):
        runner.main()


def test_scored_proxy_cli_requires_a_fresh_request_accounting_ledger_before_client(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation)
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )

    class UnexpectedClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("request-accounting path must be required before client construction")

    runner.ProjectionAwareOpenAIClient = UnexpectedClient
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://proxy.invalid/v1",
            "--model",
            "model",
            "--output",
            str(tmp_path / "scored.jsonl"),
            "--variant",
            "proxy",
            "--proxy-policy",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
            "--direct-runtime-outcome",
            str(direct_outcome),
            "--proxy-observer-ledger",
            str(tmp_path / "observer.jsonl"),
        ],
    )

    with pytest.raises(SystemExit, match="requires --proxy-request-ledger"):
        runner.main()


def test_scored_proxy_rows_use_actual_observer_fingerprints_and_failures_keep_safe_subset(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    observer_path = tmp_path / "scored-observer.jsonl"
    request_path = tmp_path / "scored-proxy-requests.jsonl"
    output = tmp_path / "scored.jsonl"
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation)
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    planner = runner.PhasePlanner()

    class ObservingProxy:
        def __init__(self, *_args, **_kwargs):
            self.sequence = 0

        def complete(self, payload, *, stream=False):
            assert stream is False
            observed = planner.plan(payload, phase="acquisition")
            observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
            self.sequence += 1
            _append_observer_record(runner, observer_path, observed, self.sequence)
            return {
                "content": "",
                "tool_calls": [{"id": f"call-{self.sequence}"}],
                runner.PROXY_RESPONSE_ACCOUNTING: {
                    "upstream_calls": 1,
                    "corrections": 0,
                    "blocked_duplicates": 0,
                    "blocked_stalls": 0,
                },
            }

    def run_cases(*, client, model, output_path, case_id, **_kwargs):
        scenario = next(item for item in runner.scenario_set("expanded") if item.case_id == case_id)
        client.complete(runner.request_payload(scenario, model=model, proxy_policy=True))
        if case_id == "case-2":
            raise RuntimeError("HTTP 502 private-scored-body")
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"case_id": case_id, "passed": True}) + "\n")
        return [{"case_id": case_id}]

    runner.ProjectionAwareOpenAIClient = ObservingProxy
    runner.run_agentic_cases = run_cases
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://proxy.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--agentic-set",
            "expanded",
            "--variant",
            "proxy",
            "--proxy-policy",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
            "--direct-runtime-outcome",
            str(direct_outcome),
            "--proxy-observer-ledger",
            str(observer_path),
            "--proxy-request-ledger",
            str(request_path),
        ],
    )

    runner.main()

    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["case_id"] for row in rows] == ["case-1", "case-2"]
    for row in rows:
        fingerprints = row["contract_fingerprints"]
        assert len(fingerprints["model_facing"]) == 1
        assert fingerprints["model_facing_turns"][0]["turn_index"] == 0
        assert fingerprints["model_facing"][0]["fields"]["declared_policy_deltas"]
    assert rows[1]["metadata"]["runner_failure_stage"] == "benchmark_client"
    serialized = output.read_text()
    assert "private-scored-body" not in serialized
    assert "private prompt marker" not in serialized
    request_records = read_request_accounting_ledger(request_path)
    assert [record.sequence for record in request_records] == [1, 2]
    assert [(record.attempt_sequence_start, record.attempt_sequence_end) for record in request_records] == [
        (1, 1),
        (2, 2),
    ]


def test_scored_proxy_local_projection_keeps_successful_rows_without_observer_records(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    observer_path = tmp_path / "scored-observer.jsonl"
    output = tmp_path / "scored.jsonl"
    request_path = tmp_path / "scored-proxy-requests.jsonl"
    preflight_attestation = _write_passing_preflight(runner, preflight, source_commit, image_digest)
    preflight_outcome, direct_outcome = _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation)
    runtime_attestation = _write_runtime_attestation(
        tmp_path / "scored-proxy-runtime-attestation.json",
        stage="scored_proxy",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="5" * 64,
    )
    clients = []

    def complete(self, _payload, *, stream=False):
        assert stream is False
        response = self._normalize({LOCAL_PROJECTION_EXTENSION: local_projection_accounting()}, wall_s=0.1, ttft_s=None)
        response[runner.PROXY_RESPONSE_ACCOUNTING] = {
            "upstream_calls": 0,
            "corrections": 0,
            "blocked_duplicates": 0,
            "blocked_stalls": 0,
        }
        return response

    def run_cases(*, client, model, output_path, case_id, **_kwargs):
        clients.append(client)
        scenario = next(item for item in runner.scenario_set("expanded") if item.case_id == case_id)
        response = client.complete(runner.request_payload(scenario, model=model, proxy_policy=True))
        assert response[LOCAL_PROJECTION_EXTENSION]["origin"] == "local_projection"
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"case_id": case_id, "passed": True}) + "\n")
        return [{"case_id": case_id}]

    monkeypatch.setattr(runner.ProjectionAwareOpenAIClient, "complete", complete)
    runner.run_agentic_cases = run_cases
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_paired_agentic_trial.py",
            "--base-url",
            "http://proxy.invalid/v1",
            "--model",
            "model",
            "--output",
            str(output),
            "--agentic-set",
            "expanded",
            "--variant",
            "proxy",
            "--proxy-policy",
            "--preflight-ledger",
            str(preflight),
            "--candidate-source-commit",
            source_commit,
            "--candidate-image-digest",
            image_digest,
            "--run-manifest-sha256",
            _RUN_MANIFEST_SHA256,
            "--runtime-attestation",
            str(runtime_attestation),
            "--preflight-runtime-outcome",
            str(preflight_outcome),
            "--direct-runtime-outcome",
            str(direct_outcome),
            "--proxy-observer-ledger",
            str(observer_path),
            "--proxy-request-ledger",
            str(request_path),
        ],
    )

    runner.main()

    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["case_id"] for row in rows] == ["case-1", "case-2"]
    assert all(row["passed"] is True and row["scored"] is True for row in rows)
    for row in rows:
        fingerprints = row["contract_fingerprints"]
        assert fingerprints["downstream"]["boundary"] == "downstream"
        assert fingerprints["model_facing"] == []
        assert fingerprints["model_facing_turns"] == [{"turn_index": 0, "fingerprints": []}]
        assert "error" not in row
    assert not observer_path.exists()
    assert all(client.attempt_records == () for client in clients)
    assert "private prompt marker" not in output.read_text()
    request_records = read_request_accounting_ledger(request_path)
    assert [record.sequence for record in request_records] == [1, 2]
    assert all(record.local_projection and record.attempt_count == 0 for record in request_records)


@pytest.mark.parametrize(
    "response",
    [
        {LOCAL_PROJECTION_EXTENSION: "local_projection"},
        {LOCAL_PROJECTION_EXTENSION: {"origin": "upstream"}},
        {"x-shiftedx-local-projection": {"origin": "local_projection"}},
    ],
)
def test_local_projection_detection_rejects_malformed_or_spoofed_extensions(monkeypatch, response):
    runner = load_runner(monkeypatch)

    assert runner._is_local_projection(response) is False


def test_projection_aware_client_preserves_only_the_canonical_projection_marker(monkeypatch):
    runner = load_runner(monkeypatch)
    canonical = local_projection_accounting()

    normalized = runner.ProjectionAwareOpenAIClient._normalize(
        {
            LOCAL_PROJECTION_EXTENSION: canonical,
            "untrusted_response_field": "private marker that must be stripped",
        },
        wall_s=0.1,
        ttft_s=None,
    )

    assert normalized[LOCAL_PROJECTION_EXTENSION] == canonical
    assert normalized[LOCAL_PROJECTION_EXTENSION] is not canonical
    assert runner._is_local_projection(normalized) is True
    assert "untrusted_response_field" not in normalized

    malformed = runner.ProjectionAwareOpenAIClient._normalize(
        {LOCAL_PROJECTION_EXTENSION: {"origin": "local_projection"}}, wall_s=0.1, ttft_s=None
    )
    assert LOCAL_PROJECTION_EXTENSION not in malformed
    assert runner._is_local_projection(malformed) is False


@pytest.mark.parametrize("operation", ("failure", "annotation"))
def test_atomic_scored_rewrites_preserve_completed_rows_when_replace_fails(monkeypatch, tmp_path, operation):
    runner = load_runner(monkeypatch)
    output = tmp_path / "scored.jsonl"
    original = '{"case_id":"complete","passed":true}\n'
    output.write_text(original, encoding="utf-8")

    def replace_failure(_source, _destination):
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(runner.os, "replace", replace_failure)
    with pytest.raises(OSError, match="simulated atomic replace failure"):
        if operation == "failure":
            runner.append_failure(output, {"case_id": "failed", "passed": False})
        else:
            client = SimpleNamespace(
                actual_contract_fingerprints=lambda: {
                    "downstream": None,
                    "model_facing": [],
                    "model_facing_turns": [],
                }
            )
            runner.annotate_scored_rows(output, client, {"complete"})

    assert output.read_text(encoding="utf-8") == original
    assert [path.name for path in tmp_path.iterdir()] == ["scored.jsonl"]


def test_metrics_preflight_failure_is_retained_as_categorical_unscored_evidence(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    args = _preflight_args(tmp_path)
    monkeypatch.setattr(
        runner,
        "_phase_metrics",
        lambda *_args: (_ for _ in ()).throw(runner.PreflightFailure("proxy_phase_metrics_unavailable")),
    )

    with pytest.raises(SystemExit, match="proxy_phase_metrics_unavailable"):
        runner._run_paired_preflight(args, [runner.scenario_set("expanded")[0]])

    rows = [json.loads(line) for line in args.output.read_text().splitlines()]
    summary = rows[-1]
    assert summary["status"] == "failed"
    assert summary["scored"] is False
    assert summary["failure"] == "proxy_phase_metrics_unavailable"
    assert summary["runtime_attestation_sha256"] == hashlib.sha256(args.runtime_attestation.read_bytes()).hexdigest()
    assert summary["runtime_contract_sha256"] == "3" * 64
    assert summary["runtime_instance_sha256"] == "4" * 64
    assert "metrics.invalid" not in args.output.read_text()


def test_missing_runtime_attestation_retains_only_safe_failed_preflight_before_network(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    args = _preflight_args(tmp_path)
    args.runtime_attestation = None

    def unexpected_network(*_args, **_kwargs):
        raise AssertionError("runtime attestation must be checked before network")

    monkeypatch.setattr(runner, "_phase_metrics", unexpected_network)
    monkeypatch.setattr(runner, "ProjectionAwareOpenAIClient", unexpected_network)

    with pytest.raises(SystemExit, match="runtime_attestation_invalid"):
        runner._run_paired_preflight(args, [runner.scenario_set("expanded")[0]])

    rows = [json.loads(line) for line in args.output.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert rows[0]["record_type"] == "paired_preflight_summary"
    assert rows[0]["status"] == "failed"
    assert rows[0]["failure"] == "runtime_attestation_invalid"
    assert rows[0]["runtime_attestation_sha256"] is None
    assert rows[0]["runtime_contract_sha256"] is None
    assert rows[0]["runtime_instance_sha256"] is None


def test_tampered_runtime_attestation_never_copies_raw_fields_into_failed_preflight(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    args = _preflight_args(tmp_path)
    document = json.loads(args.runtime_attestation.read_text(encoding="utf-8"))
    document["private_prompt"] = "must not enter retained evidence"
    args.runtime_attestation.write_text(json.dumps(document), encoding="utf-8")

    def unexpected_network(*_args, **_kwargs):
        raise AssertionError("tampered runtime attestation must be checked before network")

    monkeypatch.setattr(runner, "_phase_metrics", unexpected_network)
    with pytest.raises(SystemExit, match="runtime_attestation_invalid"):
        runner._run_paired_preflight(args, [runner.scenario_set("expanded")[0]])

    serialized = args.output.read_text(encoding="utf-8")
    rows = [json.loads(line) for line in serialized.splitlines()]
    assert len(rows) == 1
    assert rows[0]["failure"] == "runtime_attestation_invalid"
    assert "must not enter retained evidence" not in serialized


def test_network_preflight_failure_retains_partial_safe_observation_without_exception_text(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    args = _preflight_args(tmp_path)

    class FailingClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def complete(self, _payload, *, stream=False):
            assert stream is False
            raise RuntimeError("HTTP 502 https://private.invalid body=private-marker")

    runner.ProjectionAwareOpenAIClient = FailingClient
    monkeypatch.setattr(runner, "_phase_metrics", lambda *_args: {"acquisition": 0, "finalization": 0})

    with pytest.raises(SystemExit, match="preflight_client_failure"):
        runner._run_paired_preflight(args, [runner.scenario_set("expanded")[0]])

    serialized = args.output.read_text()
    rows = [json.loads(line) for line in serialized.splitlines()]
    assert rows[-1]["status"] == "failed"
    assert rows[-1]["failure"] == "preflight_client_failure"
    assert rows[0]["arm"] == "direct"
    assert rows[0]["model_facing_contracts"]
    assert "private.invalid" not in serialized
    assert "private-marker" not in serialized


def test_preflight_existing_output_is_rejected_before_any_model_request(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    args = _preflight_args(tmp_path)
    args.output.write_text('{"prior":"evidence"}\n')

    class UnexpectedClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("must not make a preflight request")

    runner.ProjectionAwareOpenAIClient = UnexpectedClient

    with pytest.raises(SystemExit, match="existing preflight ledger"):
        runner._run_paired_preflight(args, [runner.scenario_set("expanded")[0]])
    assert args.output.read_text() == '{"prior":"evidence"}\n'


def _source_commit():
    git = shutil.which("git")
    assert git is not None
    return subprocess.run(  # noqa: S603 - resolved executable and fixed Git arguments
        [git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _suffix_pair_observations(runner, proxy_system_mutation):
    scenario = runner.scenario_set("expanded")[0]
    scenario_order = [scenario.case_id]
    planner = runner.PhasePlanner()
    payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    direct_tool_model = runner.model_boundary_fingerprint(
        planner.plan(payload, phase="acquisition"), scenario_order=scenario_order
    )
    proxy_tool_payload = planner.plan(payload, phase="acquisition")
    proxy_tool_payload["messages"][0]["content"] += proxy_system_mutation
    proxy_tool_model = runner.model_boundary_fingerprint(proxy_tool_payload, scenario_order=scenario_order)
    direct_terminal_payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)
    direct_terminal_model = runner.model_boundary_fingerprint(direct_terminal_payload, scenario_order=scenario_order)
    proxy_terminal_payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)
    proxy_terminal_payload["messages"][0]["content"] += proxy_system_mutation
    proxy_terminal_model = runner.model_boundary_fingerprint(proxy_terminal_payload, scenario_order=scenario_order)
    downstream = runner.SafeFingerprint("downstream", "same", {})
    return [
        runner.PreflightObservation(
            "direct", True, 1, ("acquisition", "finalization"), True, downstream, (direct_tool_model,)
        ),
        runner.PreflightObservation(
            "proxy",
            True,
            1,
            ("acquisition", "finalization"),
            True,
            downstream,
            (proxy_tool_model,),
            {"acquisition": 2, "finalization": 1},
        ),
        runner.PreflightObservation("direct", False, 0, ("terminal",), True, downstream, (direct_terminal_model,)),
        runner.PreflightObservation("proxy", False, 0, ("terminal",), True, downstream, (proxy_terminal_model,)),
    ]


def _append_observer_record(runner, path, payload, sequence, *, cache=True, status_code=200):
    fingerprint = runner.model_boundary_fingerprint(payload)
    bypass = fingerprint.fields["cache_mode_policy"] == "bypass"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "record_type": "qualification_model_boundary",
                    "sequence": sequence,
                    "digest": fingerprint.digest,
                    "fields": fingerprint.fields,
                    "response": {
                        "status_code": status_code,
                        "cache": {
                            "prompt_tokens": 11,
                            "cached_tokens": 0 if bypass else 5,
                            "new_prefill_tokens": 11 if bypass else 6,
                            "cache_source": "none" if bypass else "ram",
                            "ssd_cache_hit": False,
                            "ssd_cached_tokens": 0,
                            "session_cache_hit": not bypass,
                            "request_session_bank_bypass": bypass,
                            "postcommit_stored": not bypass,
                        }
                        if cache and status_code is not None
                        else None,
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
    path.chmod(0o600)


def _preflight_args(tmp_path):
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    runtime_attestation = tmp_path / "preflight-runtime-attestation.json"
    _write_runtime_attestation(
        runtime_attestation,
        stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
        model="model",
        scenario_order=["case-1"],
        runtime_contract_sha256="3" * 64,
        runtime_instance_sha256="4" * 64,
    )
    return SimpleNamespace(
        direct_base_url="http://direct.invalid/v1",
        proxy_base_url="http://proxy.invalid/v1",
        proxy_metrics_url="http://metrics.invalid",
        proxy_observer_ledger=tmp_path / "observer.jsonl",
        proxy_request_ledger=tmp_path / "proxy-requests.jsonl",
        candidate_source_commit=source_commit,
        candidate_image_digest=image_digest,
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        direct_api_key_file=None,
        proxy_api_key_file=None,
        runtime_attestation=runtime_attestation,
        output=tmp_path / "preflight.jsonl",
    )


def _write_runtime_attestation(
    path,
    *,
    stage,
    source_commit,
    image_digest,
    model="model",
    scenario_order=("case-1", "case-2"),
    model_identity_sha256="6" * 64,
    runtime_contract_sha256="3" * 64,
    runtime_instance_sha256="4" * 64,
):
    canonical_model = json.dumps(model, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    canonical_order = json.dumps(list(scenario_order), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_attestation",
        "status": "passed",
        "stage": stage,
        "source_commit": source_commit,
        "image_digest": image_digest,
        "run_manifest_sha256": _RUN_MANIFEST_SHA256,
        "model_id_sha256": hashlib.sha256(canonical_model.encode()).hexdigest(),
        "benchmark_revision": BENCHMARK_REVISION,
        "scenario_order": {
            "sha256": hashlib.sha256(canonical_order.encode()).hexdigest(),
            "count": len(scenario_order),
        },
        "model_identity_sha256": model_identity_sha256,
        "runtime_contract_sha256": runtime_contract_sha256,
        "runtime_instance_sha256": runtime_instance_sha256,
        "checks": {
            "exact_image": True,
            "settings": True,
            "resources": True,
            "bind": True,
            "observer": True,
            "ready": True,
            "secret_roles_distinct": True,
        },
    }
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_runtime_attestation_reader_requires_private_mode_and_stable_inode(monkeypatch, tmp_path):
    """The scored gate must not parse an attestation replaced after its first stat."""

    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    attestation = _write_runtime_attestation(
        tmp_path / "preflight-runtime-attestation.json",
        stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
    )
    attestation.chmod(0o644)

    with pytest.raises(contract_module.RuntimeAttestationFailure, match="runtime_attestation_invalid"):
        load_runtime_attestation(
            attestation,
            expected_stage="preflight",
            source_commit=source_commit,
            image_digest=image_digest,
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            model="model",
            scenario_order=["case-1", "case-2"],
        )

    attestation.chmod(0o600)
    replacement = _write_runtime_attestation(
        tmp_path / "replacement-runtime-attestation.json",
        stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
        runtime_instance_sha256="f" * 64,
    )
    original_open = contract_module.os.open
    replaced = False

    def replace_before_open(path, *args, **kwargs):
        nonlocal replaced
        if not replaced and os.fspath(path) == os.fspath(attestation):
            replaced = True
            os.replace(replacement, attestation)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(contract_module.os, "open", replace_before_open)
    with pytest.raises(contract_module.RuntimeAttestationFailure, match="runtime_attestation_invalid"):
        load_runtime_attestation(
            attestation,
            expected_stage="preflight",
            source_commit=source_commit,
            image_digest=image_digest,
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
            model="model",
            scenario_order=["case-1", "case-2"],
        )
    assert replaced is True


def _write_model_evidence(
    path,
    *,
    stage,
    model_identity_sha256="6" * 64,
    model_contract_sha256="6" * 64,
):
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_model_cache_evidence",
        "stage": stage,
        "status": "passed",
        "failure_category": None,
        "run_manifest_sha256": _RUN_MANIFEST_SHA256,
        "model_identity_sha256": model_identity_sha256,
        "model_contract_sha256": model_contract_sha256,
        "runtime_instance_sha256": "7" * 64,
        "live_before_sha256": "8" * 64,
        "live_after_sha256": "9" * 64,
        "request_window": {
            "before": 0,
            "after": 0,
            "delta": 0,
            "expected": 0,
            "successful_measured": 0,
        },
        "prime": {"record_sha256": None, "count": 0, "request_digest": None},
        "first_attempt": {
            "record_sha256": None,
            "status": None,
            "measured_count": 0,
            "successful_count": 0,
            "prompt_tokens": None,
            "cached_tokens": None,
            "new_prefill_tokens": None,
        },
        "checks": {
            "contract": True,
            "live_before": True,
            "attempts": True,
            "request_window": True,
            "live_after": True,
        },
    }
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _write_runtime_outcome(
    path,
    *,
    stage,
    attestation,
    output,
    output_record_count,
    model_evidence=None,
    status="passed",
    action_exit_code=0,
    failure_category=None,
):
    attestation_document = json.loads(attestation.read_text(encoding="utf-8"))
    model_identity_sha256 = attestation_document["model_identity_sha256"]
    if model_evidence is None:
        model_evidence = path.with_name(f"{stage}-model-cache-evidence.json")
        _write_model_evidence(
            model_evidence,
            stage={"preflight": "preflight", "scored-direct": "score-direct", "scored-proxy": "score-proxy"}[stage],
            model_identity_sha256=model_identity_sha256,
        )
    slot_ordinal, cache_lane, pair_index = (0, "preflight", 0) if stage == "preflight" else (4, "warm-prefix", 1)
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_outcome",
        "stage": stage,
        "status": status,
        "action_exit_code": action_exit_code,
        "failure_category": failure_category,
        "run_manifest_sha256": _RUN_MANIFEST_SHA256,
        "attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "model_evidence_sha256": hashlib.sha256(model_evidence.read_bytes()).hexdigest(),
        "output_ledger_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "output_record_count": output_record_count,
        "proxy_reconciliation_sha256": None,
        "campaign_id_sha256": "c" * 64,
        "slot_ordinal": slot_ordinal,
        "cache_lane": cache_lane,
        "pair_index": pair_index,
    }
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return path


def _write_passing_scored_prerequisites(tmp_path, preflight, preflight_attestation):
    preflight_outcome = _write_runtime_outcome(
        tmp_path / "preflight-runtime-outcome.json",
        stage="preflight",
        attestation=preflight_attestation,
        output=preflight,
        output_record_count=5,
    )
    direct_output = tmp_path / "scored-direct.jsonl"
    direct_output.write_text('{"case_id":"case-1"}\n{"case_id":"case-2"}\n', encoding="utf-8")
    direct_output.chmod(0o600)
    direct_outcome = _write_runtime_outcome(
        tmp_path / "scored-direct-runtime-outcome.json",
        stage="scored-direct",
        attestation=preflight_attestation,
        output=direct_output,
        output_record_count=2,
    )
    return preflight_outcome, direct_outcome


def _write_passing_preflight(runner, output, source_commit, image_digest, contract_digests=None):
    scenario = runner.scenario_set("expanded")[0]
    scenario_order = [item.case_id for item in runner.scenario_set("expanded")]
    planner = runner.PhasePlanner()
    direct_tool_payload = runner.request_payload(scenario, model="model", proxy_policy=False)
    proxy_tool_payload = runner.request_payload(scenario, model="model", proxy_policy=True)
    direct_tool, _ = runner.request_fingerprints(direct_tool_payload, scenario_order, policy_delta={})
    proxy_tool, _ = runner.request_fingerprints(
        proxy_tool_payload, scenario_order, policy_delta={"x-shiftedx-require-receipt": True}
    )
    direct_tool_model = runner.model_boundary_fingerprint(
        planner.plan(direct_tool_payload, phase="acquisition"), scenario_order=scenario_order
    )
    proxy_tool_model_payload = planner.plan(proxy_tool_payload, phase="acquisition")
    proxy_tool_model_payload["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    proxy_tool_model = runner.model_boundary_fingerprint(proxy_tool_model_payload, scenario_order=scenario_order)
    direct_terminal_payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)
    direct_terminal, _ = runner.request_fingerprints(direct_terminal_payload, scenario_order, policy_delta={})
    direct_terminal_model = runner.model_boundary_fingerprint(direct_terminal_payload, scenario_order=scenario_order)
    proxy_terminal_payload = runner._preflight_payload(scenario, model="model", proxy_policy=False, no_tools=True)
    proxy_terminal_payload["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    proxy_terminal_model = runner.model_boundary_fingerprint(proxy_terminal_payload, scenario_order=scenario_order)
    observations = [
        runner.PreflightObservation(
            "direct", True, 1, ("acquisition", "finalization"), True, direct_tool, (direct_tool_model,)
        ),
        runner.PreflightObservation(
            "proxy",
            True,
            1,
            ("acquisition", "finalization"),
            True,
            proxy_tool,
            (proxy_tool_model,),
            {"acquisition": 2, "finalization": 1},
        ),
        runner.PreflightObservation("direct", False, 0, ("terminal",), True, direct_terminal, (direct_terminal_model,)),
        runner.PreflightObservation("proxy", False, 0, ("terminal",), True, direct_terminal, (proxy_terminal_model,)),
    ]
    if contract_digests is None:
        scenarios = runner.scenario_set("expanded")
        contract_digests = runner._qualification_contract_digests(
            "model",
            scenarios,
            [item.case_id for item in scenarios],
            _RUN_MANIFEST_SHA256,
        )
    runtime_attestation_path = output.with_name(f"{output.stem}-runtime-attestation.json")
    _write_runtime_attestation(
        runtime_attestation_path,
        stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
        scenario_order=scenario_order,
    )
    runtime_attestation = runner.load_runtime_attestation(
        runtime_attestation_path,
        expected_stage="preflight",
        source_commit=source_commit,
        image_digest=image_digest,
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        model="model",
        scenario_order=scenario_order,
    )
    runner.write_preflight_ledger(
        output,
        observations,
        source_commit=source_commit,
        image_digest=image_digest,
        contract_digests=contract_digests,
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        runtime_attestation=runtime_attestation,
    )
    return runtime_attestation_path
