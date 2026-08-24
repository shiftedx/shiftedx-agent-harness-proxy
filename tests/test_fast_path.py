from typing import Any

from shiftedx_harness_proxy.core import HARNESS_SYSTEM_SUFFIX, AgentHarness
from shiftedx_harness_proxy.fast_path import (
    FAST_PATH_CONTRACT_ID,
    HARNESS_MUTATION_ID,
    FastPathShadowResult,
    classify_fast_path,
    compare_fast_path_shadow,
)
from shiftedx_harness_proxy.transcript import Reconstruction


def _rebuilt(*, degraded: bool = False) -> Reconstruction:
    return Reconstruction(AgentHarness("answer the question", require_receipt=False), degraded, ())


def _candidate() -> dict[str, Any]:
    return {"model": "model", "messages": [{"role": "user", "content": "hello"}]}


def test_fast_path_classifier_accepts_only_the_proven_non_intervention_class() -> None:
    decision = classify_fast_path(
        mode="shadow",
        harness_enabled=True,
        has_receipt_extension=False,
        normalized_tools=[],
        has_response_format=False,
        has_tool_choice=False,
        has_parallel_tool_calls=False,
        rebuilt=_rebuilt(),
        local_projection_available=False,
        uses_phase_split=False,
        uses_combined_capability=False,
    )

    assert decision.eligible is True
    assert decision.reason == "eligible"


def test_fast_path_classifier_rejects_any_policy_relevant_request_or_state() -> None:
    baseline = dict(
        mode="shadow",
        harness_enabled=True,
        has_receipt_extension=False,
        normalized_tools=[],
        has_response_format=False,
        has_tool_choice=False,
        has_parallel_tool_calls=False,
        rebuilt=_rebuilt(),
        local_projection_available=False,
        uses_phase_split=False,
        uses_combined_capability=False,
    )
    cases = {
        "receipt_extension_present": {"has_receipt_extension": True},
        "tools_present": {"normalized_tools": [{"type": "function"}]},
        "response_format_present": {"has_response_format": True},
        "tool_choice_present": {"has_tool_choice": True},
        "parallel_tool_calls_present": {"has_parallel_tool_calls": True},
        "transcript_degraded": {"rebuilt": _rebuilt(degraded=True)},
        "local_projection_available": {"local_projection_available": True},
        "phase_split_required": {"uses_phase_split": True},
        "combined_capability_required": {"uses_combined_capability": True},
    }
    for expected_reason, change in cases.items():
        decision = classify_fast_path(**(baseline | change))
        assert decision.eligible is False
        assert decision.reason == expected_reason


def test_fast_path_shadow_compares_only_the_versioned_harness_mutation() -> None:
    rebuilt = _rebuilt()
    candidate = _candidate()
    normal = {
        "model": "model",
        "messages": [
            {"role": "system", "content": HARNESS_SYSTEM_SUFFIX.strip()},
            {"role": "user", "content": "hello"},
            {"role": "user", "content": rebuilt.harness.render()},
        ],
    }

    result = compare_fast_path_shadow(candidate, normal, rebuilt)

    assert isinstance(result, FastPathShadowResult)
    assert result.equivalent is True
    assert result.reason == "exact_harness_mutation"
    safe = result.to_safe_dict()
    assert set(safe) == {
        "eligible",
        "equivalent",
        "reason",
        "candidate_payload_sha256",
        "normal_payload_sha256",
        "fast_path_contract_id",
        "harness_mutation_id",
    }
    assert safe["fast_path_contract_id"] == FAST_PATH_CONTRACT_ID
    assert safe["harness_mutation_id"] == HARNESS_MUTATION_ID
    assert "hello" not in str(safe)


def test_fast_path_shadow_rejects_any_extra_payload_difference() -> None:
    rebuilt = _rebuilt()
    candidate = _candidate()
    normal = {
        "model": "other-model",
        "messages": [
            {"role": "system", "content": HARNESS_SYSTEM_SUFFIX.strip()},
            {"role": "user", "content": "hello"},
            {"role": "user", "content": rebuilt.harness.render()},
        ],
    }

    result = compare_fast_path_shadow(candidate, normal, rebuilt)

    assert result.equivalent is False
    assert result.reason == "non_message_payload_mismatch"
