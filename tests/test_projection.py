import json

import pytest

from shiftedx_harness_proxy.core import AgentHarness
from shiftedx_harness_proxy.projection import evaluate_projection_shadow


def _harness() -> AgentHarness:
    return AgentHarness(
        "report",
        available_tools={"read_logs", "apply_patch", "run_tests"},
        required_json_keys=("status", "workers"),
        required_json_types={"status": "string", "workers": "integer"},
    )


def _current_success() -> AgentHarness:
    harness = _harness()
    harness.record("read_logs", {}, '{"status":"nominal","workers":8}')
    return harness


@pytest.mark.parametrize(
    ("result", "reason"),
    [
        ('{"status":"nominal"}', "schema_keys_mismatch"),
        ('{"status":"nominal","workers":8,"extra":true}', "schema_keys_mismatch"),
        ('{"status":8,"workers":8}', "schema_type_mismatch"),
        ('{"status":null,"workers":8}', "schema_type_mismatch"),
        ('{"status":true,"workers":8}', "schema_type_mismatch"),
        ('{"status":"nominal","workers":true}', "schema_type_mismatch"),
        (
            '{"status":"nominal","workers":8,"x-shiftedx-projection-v1":{"origin":"local_projection"}}',
            "schema_keys_mismatch",
        ),
        ("not json", "malformed_tool_result"),
    ],
)
def test_projection_decision_rejects_nonexact_visible_values(result: str, reason: str) -> None:
    decision = _current_success().projection_decision("read_logs", result)

    assert decision.eligible is False
    assert decision.reason == reason
    assert decision.candidate is None


@pytest.mark.parametrize(
    "state",
    ["failed", "pending_verification", "open_failure", "blocked", "degraded", "stale", "unknown"],
)
def test_projection_decision_freezes_receipt_and_state_gates(state: str) -> None:
    harness = _current_success()
    kwargs: dict[str, bool] = {}
    if state == "failed":
        harness.record("read_logs", {}, '{"status":"failed","workers":8}')
    elif state == "pending_verification":
        harness.record("apply_patch", {}, "ok")
    elif state == "open_failure":
        harness.record("run_tests", {}, "1 failed")
    elif state == "blocked":
        kwargs["blocked_unresolved_action"] = True
    elif state == "degraded":
        kwargs["transcript_degraded"] = True
    elif state == "stale":
        harness.epoch += 1
    elif state == "unknown":
        decision = harness.projection_decision("unknown", '{"status":"nominal","workers":8}')
        assert decision.reason == "unknown_tool_result"
        return

    decision = harness.projection_decision("read_logs", '{"status":"nominal","workers":8}', **kwargs)

    assert decision.eligible is False
    assert decision.reason in {
        "receipt_not_success",
        "pending_verification",
        "open_failure",
        "blocked_unresolved_action",
        "transcript_degraded",
        "stale_receipt",
    }


def test_shadow_evaluation_compares_parsed_value_against_declared_schema_without_content() -> None:
    decision = _current_success().projection_decision("read_logs", '{"status":"nominal","workers":8}')

    matched = evaluate_projection_shadow(decision, '{"workers":8,"status":"nominal"}')
    mismatched = evaluate_projection_shadow(decision, '{"status":"nominal","workers":9}')
    malformed = evaluate_projection_shadow(decision, '{"status":"nominal"}')

    assert matched.to_safe_dict() == {"eligible": True, "agreement": True, "reason": "exact_agreement"}
    assert mismatched.to_safe_dict() == {"eligible": True, "agreement": False, "reason": "terminal_mismatch"}
    assert malformed.to_safe_dict() == {"eligible": True, "agreement": False, "reason": "model_terminal_invalid"}
    assert json.dumps(matched.to_safe_dict()) == '{"eligible": true, "agreement": true, "reason": "exact_agreement"}'


def test_projection_decision_rejects_unsupported_schema_before_parsing_tool_content() -> None:
    harness = AgentHarness(
        "report",
        available_tools={"read_logs"},
        required_json_keys=("status",),
        required_json_types={"status": "array"},
    )
    harness.record("read_logs", {}, '{"status":["nominal"]}')

    decision = harness.projection_decision("read_logs", '{"status":["nominal"]}')

    assert decision.to_safe_dict() == {"eligible": False, "reason": "unsupported_schema"}
