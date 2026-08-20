from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from shiftedx_harness_proxy.core import HARNESS_SYSTEM_SUFFIX
from shiftedx_harness_proxy.projection_accounting import (
    LOCAL_PROJECTION_EXTENSION,
    local_projection_accounting,
)

_RUN_MANIFEST_SHA256 = "1" * 64


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
    _write_passing_preflight(runner, preflight, source_commit, image_digest)
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
            "--proxy-observer-ledger",
            str(tmp_path / "scored-observer.jsonl"),
        ],
    )

    runner.main()

    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["case_id"] for row in rows] == ["case-1", "case-2"]
    for row in rows:
        assert row["passed"] is False
        assert row["score"] == 0.0
        assert row["error"] == "client request failed with HTTP 502"
        assert row["response"] == {
            "client_error": {"type": "RuntimeError", "http_status": 502}
        }
        assert row["metadata"]["runner_failure_stage"] == "benchmark_client"
        assert row["scored"] is True
        assert set(row["contract_fingerprints"]) == {"downstream", "model_facing", "model_facing_turns"}
    serialized = json.dumps(rows)
    assert "private prompt marker" not in serialized
    assert "private body marker" not in serialized


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
    terminal_payload = runner._preflight_payload(
        scenario, model="private-model", proxy_policy=False, no_tools=True
    )
    direct, direct_phases = runner.request_fingerprints(direct_payload, [scenario.case_id], policy_delta={})
    proxy, proxy_phases = runner.request_fingerprints(
        proxy_payload, [scenario.case_id], policy_delta={"x-shiftedx-require-receipt": True}
    )
    terminal, terminal_phases = runner.request_fingerprints(
        terminal_payload, [scenario.case_id], policy_delta={}
    )
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
        contract_digests={"direct": "one", "proxy": "two"},
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
                with observer.open("a", encoding="utf-8") as handle:
                    for observed in observed_payloads:
                        observed["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
                        fingerprint = runner.model_boundary_fingerprint(observed)
                        sequence[0] += 1
                        handle.write(
                            json.dumps(
                                {
                                    "record_type": "qualification_model_boundary",
                                    "sequence": sequence[0],
                                    "digest": fingerprint.digest,
                                    "fields": fingerprint.fields,
                                },
                                sort_keys=True,
                            )
                            + "\n"
                        )
            if payload.get("tools") and not any(message.get("role") == "tool" for message in payload["messages"]):
                return {
                    "content": "",
                    "tool_calls": [{"id": "call-1", "function": {"name": "read_file", "arguments": "{}"}}],
                }
            return {"content": '{"status":"passed"}', "tool_calls": []}

    runner.ProjectionAwareOpenAIClient = FakeClient
    metric_values = iter(({"acquisition": 0, "finalization": 0}, {"acquisition": 2, "finalization": 1}))
    monkeypatch.setattr(runner, "_phase_metrics", lambda *_args: next(metric_values))
    args = SimpleNamespace(
        direct_base_url="http://direct.invalid/v1",
        proxy_base_url="http://proxy.invalid/v1",
        proxy_metrics_url="http://metrics.invalid",
        proxy_observer_ledger=observer,
        candidate_source_commit=_source_commit(),
        candidate_image_digest="sha256:" + "0" * 64,
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        direct_api_key_file=None,
        proxy_api_key_file=None,
        output=tmp_path / "preflight.jsonl",
    )

    runner._run_paired_preflight(args, [scenario])

    assert '"status":"passed"' in args.output.read_text()


def test_stale_proxy_observer_ledger_is_rejected_without_overwriting_it(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    observer = tmp_path / "observer.jsonl"
    observer.write_text('{"old":"record"}\n')
    output = tmp_path / "preflight.jsonl"
    args = SimpleNamespace(
        direct_base_url="http://direct.invalid/v1",
        proxy_base_url="http://proxy.invalid/v1",
        proxy_metrics_url="http://metrics.invalid",
        proxy_observer_ledger=observer,
        candidate_source_commit=_source_commit(),
        candidate_image_digest="sha256:" + "0" * 64,
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        direct_api_key_file=None,
        proxy_api_key_file=None,
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
    terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
    terminal = runner.model_boundary_fingerprint(terminal_payload)
    proxy_terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
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
            contract_digests={"direct": "one", "proxy": "two"},
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
    _write_passing_preflight(
        runner, ledger, source_commit, image_digest, contract_digests={"direct": "one", "proxy": "two"}
    )

    with pytest.raises(SystemExit, match="qualification contract"):
        runner.require_scoring_gate(
            output=tmp_path / "scored.jsonl",
            preflight_ledger=ledger,
            candidate_source_commit=source_commit,
            candidate_image_digest=image_digest,
            contract_digest="different",
            arm="direct",
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
            contract_digests={"direct": "one", "proxy": "two"},
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
def test_preflight_rejects_every_proxy_system_mutation_except_the_exact_suffix(
    monkeypatch, mutation, message
):
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
            contract_digest=summary["qualification_contract_digests"]["direct"],
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
            contract_digest=summary["qualification_contract_digests"]["direct"],
            arm="direct",
            model="other-model",
            run_manifest_sha256=_RUN_MANIFEST_SHA256,
        )


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
    assert actual["model_facing_turns"] == [
        {"turn_index": 0, "fingerprints": actual["model_facing"]}
    ]
    assert actual["model_facing"][0]["fields"]["declared_policy_deltas"]
    planned = runner.model_boundary_fingerprint(
        planner.plan(runner.request_payload(scenario, model="model", proxy_policy=True), phase="acquisition"),
        scenario_order=[scenario.case_id],
    )
    assert actual["model_facing"][0]["fields"]["system_prompt_sha256"] != planned.fields[
        "system_prompt_sha256"
    ]


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
    _write_passing_preflight(runner, preflight, source_commit, image_digest)
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
        ],
    )

    with pytest.raises(SystemExit, match="requires --proxy-observer-ledger"):
        runner.main()


def test_scored_proxy_rows_use_actual_observer_fingerprints_and_failures_keep_safe_subset(monkeypatch, tmp_path):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    observer_path = tmp_path / "scored-observer.jsonl"
    output = tmp_path / "scored.jsonl"
    _write_passing_preflight(runner, preflight, source_commit, image_digest)
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
            return {"content": "", "tool_calls": [{"id": f"call-{self.sequence}"}]}

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
            "--proxy-observer-ledger",
            str(observer_path),
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


def test_scored_proxy_local_projection_keeps_successful_rows_without_observer_records(
    monkeypatch, tmp_path
):
    runner = load_runner(monkeypatch)
    source_commit = _source_commit()
    image_digest = "sha256:" + "0" * 64
    preflight = tmp_path / "preflight.jsonl"
    observer_path = tmp_path / "scored-observer.jsonl"
    output = tmp_path / "scored.jsonl"
    _write_passing_preflight(runner, preflight, source_commit, image_digest)

    def complete(self, _payload, *, stream=False):
        assert stream is False
        return self._normalize(
            {LOCAL_PROJECTION_EXTENSION: local_projection_accounting()}, wall_s=0.1, ttft_s=None
        )

    def run_cases(*, client, model, output_path, case_id, **_kwargs):
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
            "--proxy-observer-ledger",
            str(observer_path),
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
    assert "private prompt marker" not in output.read_text()


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
    assert "metrics.invalid" not in args.output.read_text()


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
    direct_terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
    direct_terminal_model = runner.model_boundary_fingerprint(
        direct_terminal_payload, scenario_order=scenario_order
    )
    proxy_terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
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
        runner.PreflightObservation(
            "direct", False, 0, ("terminal",), True, downstream, (direct_terminal_model,)
        ),
        runner.PreflightObservation(
            "proxy", False, 0, ("terminal",), True, downstream, (proxy_terminal_model,)
        ),
    ]


def _append_observer_record(runner, path, payload, sequence):
    fingerprint = runner.model_boundary_fingerprint(payload)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "record_type": "qualification_model_boundary",
                    "sequence": sequence,
                    "digest": fingerprint.digest,
                    "fields": fingerprint.fields,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )


def _preflight_args(tmp_path):
    return SimpleNamespace(
        direct_base_url="http://direct.invalid/v1",
        proxy_base_url="http://proxy.invalid/v1",
        proxy_metrics_url="http://metrics.invalid",
        proxy_observer_ledger=tmp_path / "observer.jsonl",
        candidate_source_commit=_source_commit(),
        candidate_image_digest="sha256:" + "0" * 64,
        model="model",
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
        direct_api_key_file=None,
        proxy_api_key_file=None,
        output=tmp_path / "preflight.jsonl",
    )


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
    direct_terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
    direct_terminal, _ = runner.request_fingerprints(direct_terminal_payload, scenario_order, policy_delta={})
    direct_terminal_model = runner.model_boundary_fingerprint(
        direct_terminal_payload, scenario_order=scenario_order
    )
    proxy_terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
    proxy_terminal_payload["messages"][0]["content"] += HARNESS_SYSTEM_SUFFIX
    proxy_terminal_model = runner.model_boundary_fingerprint(
        proxy_terminal_payload, scenario_order=scenario_order
    )
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
        contract_digests = {
            arm: runner.qualification_contract_digest(
                [runner.request_payload(item, model="model", proxy_policy=arm == "proxy") for item in scenarios],
                [item.case_id for item in scenarios],
                policy_delta={"x-shiftedx-require-receipt": True} if arm == "proxy" else {},
                run_manifest_sha256=_RUN_MANIFEST_SHA256,
            )
            for arm in ("direct", "proxy")
        }
    runner.write_preflight_ledger(
        output,
        observations,
        source_commit=source_commit,
        image_digest=image_digest,
        contract_digests=contract_digests,
        run_manifest_sha256=_RUN_MANIFEST_SHA256,
    )
