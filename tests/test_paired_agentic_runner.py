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
    api.OpenAIClient = lambda *_args, **_kwargs: object()
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
        assert set(row["contract_fingerprints"]) == {"downstream", "model_facing"}
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
                        fingerprint = runner.model_boundary_fingerprint(observed)
                        handle.write(
                            json.dumps(
                                {
                                    "record_type": "qualification_model_boundary",
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

    runner.OpenAIClient = FakeClient
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
        direct_api_key_file=None,
        proxy_api_key_file=None,
        output=output,
    )

    with pytest.raises(SystemExit, match="new empty"):
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
    drifted_payload["top_k"] = 99
    proxy_components = runner.model_boundary_fingerprint(drifted_payload)
    terminal_payload = runner._preflight_payload(
        scenario, model="model", proxy_policy=False, no_tools=True
    )
    terminal = runner.model_boundary_fingerprint(terminal_payload)
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
        *[
            runner.PreflightObservation(arm, False, 0, ("terminal",), True, fingerprint, (terminal,))
            for arm in ("direct", "proxy")
        ],
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


def _source_commit():
    git = shutil.which("git")
    assert git is not None
    return subprocess.run(  # noqa: S603 - resolved executable and fixed Git arguments
        [git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _write_passing_preflight(runner, output, source_commit, image_digest, contract_digests=None):
    fingerprint = runner.SafeFingerprint("downstream", "same", {})
    model_fingerprint = runner.SafeFingerprint("model_facing", "same", {})
    observations = [
        runner.PreflightObservation(
            arm=arm,
            tool_required=tool_required,
            native_acquisition_tool_calls=1 if tool_required else 0,
            phases=("acquisition", "finalization") if tool_required else ("terminal",),
            terminal_schema_valid=True,
            downstream=fingerprint,
            model_facing=(model_fingerprint,),
            proxy_phase_counts={"acquisition": 2, "finalization": 1} if arm == "proxy" and tool_required else None,
        )
        for arm in ("direct", "proxy")
        for tool_required in (True, False)
    ]
    if contract_digests is None:
        scenarios = runner.scenario_set("expanded")
        contract_digests = {
            arm: runner.qualification_contract_digest(
                [runner.request_payload(item, model="model", proxy_policy=arm == "proxy") for item in scenarios],
                [item.case_id for item in scenarios],
                policy_delta={"x-shiftedx-require-receipt": True} if arm == "proxy" else {},
            )
            for arm in ("direct", "proxy")
        }
    runner.write_preflight_ledger(
        output,
        observations,
        source_commit=source_commit,
        image_digest=image_digest,
        contract_digests=contract_digests,
    )
