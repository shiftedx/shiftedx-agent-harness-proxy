from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Literal

import pytest

from shiftedx_harness_proxy.qualification_campaign_v2 import (
    QualificationV2Failure,
    V2OutcomeRecord,
    evaluate_qualification_v2,
)

Arm = Literal["direct", "proxy"]
_LANES = ("cold", "warm-prefix")

def _records(
    *,
    passed: Callable[[str, int, int, Arm], bool] | None = None,
    wall: Callable[[str, int, int, Arm], str] | None = None,
    integrity: Callable[[str, int, int, Arm], bool] | None = None,
) -> list[V2OutcomeRecord]:
    passed = passed or (lambda _lane, _replicate, ordinal, arm: not (ordinal <= 3 and arm == "direct"))
    wall = wall or (lambda _lane, _replicate, _ordinal, arm: "10" if arm == "direct" else "8")
    integrity = integrity or (lambda _lane, _replicate, _ordinal, _arm: False)
    values: list[V2OutcomeRecord] = []
    for lane in _LANES:
        for replicate in range(1, 5):
            for ordinal in range(1, 31):
                for arm in ("direct", "proxy"):
                    values.append(
                        V2OutcomeRecord(
                            case_ordinal=ordinal,
                            cache_lane=lane,
                            replicate=replicate,
                            arm=arm,
                            passed=passed(lane, replicate, ordinal, arm),
                            wall_s=Decimal(wall(lane, replicate, ordinal, arm)),
                            deadline_s=Decimal("100"),
                            critical_integrity_violation=integrity(lane, replicate, ordinal, arm),
                        )
                    )
    return values


def test_fixed_topology_retains_direct_failure_proxy_success_and_uses_deadline_penalty() -> None:
    result = evaluate_qualification_v2(
        _records(
            passed=lambda lane, replicate, ordinal, arm: (lane, replicate, ordinal, arm)
            != ("cold", 1, 1, "direct")
        )
    )

    assert result["row_count_per_arm"] == 240
    assert result["pooled"]["direct_valid_count"] == 239
    assert result["pooled"]["proxy_valid_count"] == 240
    assert result["pooled"]["direct_only_success_count"] == 0
    assert result["pooled"]["proxy_only_success_count"] == 1
    assert result["pooled"]["direct_penalized_mean_wall_us"] == 10_375_000
    assert result["pooled"]["both_valid_count"] == 239


def test_proxy_failure_and_both_failure_receive_declared_deadline_penalties() -> None:
    def passed(lane: str, replicate: int, ordinal: int, arm: Arm) -> bool:
        if (lane, replicate, ordinal) == ("cold", 1, 1):
            return arm == "direct"
        return (lane, replicate, ordinal) != ("cold", 1, 2)

    result = evaluate_qualification_v2(_records(passed=passed))

    assert result["pooled"]["direct_penalized_mean_wall_us"] == 10_375_000
    assert result["pooled"]["proxy_penalized_mean_wall_us"] == 8_766_667
    assert result["pooled"]["both_valid_count"] == 238


@pytest.mark.parametrize("broken", ("duplicate", "missing", "mismatch"))
def test_rejects_duplicate_missing_or_mismatched_pairs(broken: str) -> None:
    records = _records()
    if broken == "duplicate":
        records[-1] = records[-2]
    elif broken == "missing":
        records.pop()
    else:
        last = records[-1]
        records[-1] = V2OutcomeRecord(
            **{**last.__dict__, "deadline_s": Decimal("101")}
        )

    with pytest.raises(QualificationV2Failure):
        evaluate_qualification_v2(records)


def test_proxy_only_integrity_violation_fails_safety_even_when_both_outcomes_pass() -> None:
    result = evaluate_qualification_v2(
        _records(
            passed=lambda _lane, _replicate, ordinal, arm: not (ordinal <= 3 and arm == "direct"),
            integrity=lambda lane, replicate, ordinal, arm: (
                (lane, replicate, ordinal, arm) == ("cold", 1, 30, "proxy")
            )
        )
    )

    assert result["pooled"]["proxy_only_critical_integrity_violation_count"] == 1
    assert result["gates"]["quality_safety"] is False
    assert result["gates"]["quality_efficacy"] is True
    assert result["gates"]["unconditional_time_to_valid"] is True
    assert result["gates"]["promotion_passed"] is False


def test_lane_and_replicate_time_gates_reject_a_single_bad_lane_replicate() -> None:
    result = evaluate_qualification_v2(
        _records(
            passed=lambda _lane, _replicate, _ordinal, _arm: True,
            wall=lambda lane, replicate, _ordinal, arm: (
                "30"
                if (lane, replicate, arm) == ("warm-prefix", 2, "proxy")
                else "10"
                if arm == "direct"
                else "5"
            )
        )
    )

    assert result["replicates"]["warm-prefix"]["2"]["proxy_to_direct_penalized_mean_ratio_ppm"] == 3_000_000
    assert result["gates"]["unconditional_time_to_valid"] is False


def test_conditional_diagnostic_is_passed_when_each_lane_meets_the_frozen_floor() -> None:
    result = evaluate_qualification_v2(_records())

    assert result["conditional_latency"] == {
        "status": "passed",
        "lanes": {"cold": "passed", "warm-prefix": "passed"},
    }
    assert result["gates"]["conditional_latency_diagnostic"] == "passed"


def test_public_summaries_include_frozen_index_penalized_percentiles_and_gate_details() -> None:
    result = evaluate_qualification_v2(_records())

    pooled = result["pooled"]
    assert pooled["direct_penalized_p50_wall_us"] == 10_000_000
    assert pooled["direct_penalized_p95_wall_us"] == 100_000_000
    assert pooled["direct_penalized_p99_wall_us"] == 100_000_000
    assert pooled["proxy_penalized_p50_wall_us"] == 8_000_000
    assert pooled["proxy_penalized_p95_wall_us"] == 8_000_000
    assert pooled["proxy_penalized_p99_wall_us"] == 8_000_000
    assert result["gate_details"] == {
        "quality": {
            "lane_pass": {"cold": True, "warm-prefix": True},
            "replicate_pass": {
                "cold": {"1": True, "2": True, "3": True, "4": True},
                "warm-prefix": {"1": True, "2": True, "3": True, "4": True},
            },
            "passing_replicate_count_by_lane": {"cold": 4, "warm-prefix": 4},
        },
        "time_to_valid": {
            "lane_pass": {"cold": True, "warm-prefix": True},
            "replicate_pass": {
                "cold": {"1": True, "2": True, "3": True, "4": True},
                "warm-prefix": {"1": True, "2": True, "3": True, "4": True},
            },
            "passing_replicate_count_by_lane": {"cold": 4, "warm-prefix": 4},
        },
    }


def test_conditional_diagnostic_is_failed_when_sufficient_rows_exceed_p95_limit() -> None:
    result = evaluate_qualification_v2(
        _records(wall=lambda _lane, _replicate, _ordinal, arm: "10" if arm == "direct" else "30")
    )

    assert result["conditional_latency"]["status"] == "failed"
    assert result["gates"]["conditional_latency_diagnostic"] == "failed"


def test_conditional_diagnostic_is_unavailable_below_the_frozen_floor() -> None:
    result = evaluate_qualification_v2(
        _records(
            passed=lambda lane, replicate, ordinal, arm: not (
                lane == "cold" and (replicate < 4 or ordinal <= 9) and arm == "proxy"
            )
        )
    )

    assert result["lanes"]["cold"]["both_valid_count"] == 21
    assert result["conditional_latency"]["status"] == "unavailable"


def test_result_contract_exposes_all_fixed_v2_values() -> None:
    assert evaluate_qualification_v2(_records())["contract"] == {
        "case_count": 30,
        "lanes": ["cold", "warm-prefix"],
        "replicates_per_lane": 4,
        "arm_order_per_replicate": ["direct", "proxy"],
        "quality_safety_noninferiority_ppm": -50_000,
        "quality_efficacy_benefit_ppm": 100_000,
        "min_quality_noninferior_replicates": 3,
        "mcnemar_alpha_ppm": 25_000,
        "time_pooled_max_ratio_ppm": 800_000,
        "time_lane_max_ratio_ppm": 900_000,
        "time_replicate_max_ratio_ppm": 900_000,
        "min_time_passing_replicates": 3,
        "conditional_min_both_valid_rows": 22,
        "conditional_max_p95_ratio_ppm": 1_250_000,
    }


def test_exact_one_sided_mcnemar_counts_the_proxy_favoring_tail() -> None:
    def passed(lane: str, replicate: int, ordinal: int, arm: Arm) -> bool:
        if (lane, replicate, ordinal) in {("cold", 1, 1), ("cold", 1, 2)}:
            return arm == "proxy"
        if (lane, replicate, ordinal) == ("cold", 1, 3):
            return arm == "direct"
        return True

    result = evaluate_qualification_v2(_records(passed=passed))

    assert result["mcnemar"] == {
        "proxy_only_success_count": 2,
        "direct_only_success_count": 1,
        "discordant_pair_count": 3,
        "one_sided_tail_numerator": 4,
        "one_sided_tail_denominator": 8,
        "supports_proxy_benefit": False,
    }
