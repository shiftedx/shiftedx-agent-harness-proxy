"""Pure aggregate evaluator for the versioned v2 qualification contract.

This module intentionally does not read ledgers or write reports.  Its caller
must first authenticate and validate private evidence, including the required
direct-then-proxy evidence chain for every lane and replicate, then supply
only the safe, matched row facts represented by :class:`V2OutcomeRecord`.  In
particular, a benchmark failure is data: it is retained in both the quality
denominator and the deadline-penalized time-to-valid-outcome calculation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from math import comb
from typing import Literal

Arm = Literal["direct", "proxy"]
_LANES = ("cold", "warm-prefix")
_CASE_COUNT = 22
_REPLICATES_PER_LANE = 4
_CONDITIONAL_MIN_BOTH_VALID_ROWS = 22
_QUALITY_SAFETY_NONINFERIORITY_PPM = -50_000
_QUALITY_EFFICACY_BENEFIT_PPM = 100_000
_MIN_QUALITY_NONINFERIOR_REPLICATES = 3
_MCNEMAR_ALPHA_PPM = 25_000
_TIME_POOLED_MAX_RATIO_PPM = 800_000
_TIME_LANE_MAX_RATIO_PPM = 900_000
_TIME_REPLICATE_MAX_RATIO_PPM = 900_000
_MIN_TIME_PASSING_REPLICATES = 3
_CONDITIONAL_MAX_P95_RATIO_PPM = 1_250_000


class QualificationV2Failure(ValueError):
    """A stable, content-free evidence failure."""


@dataclass(frozen=True)
class V2OutcomeRecord:
    """One already-validated, payload-free outcome in the fixed cohort."""

    case_ordinal: int
    cache_lane: str
    replicate: int
    arm: Arm
    passed: bool
    wall_s: Decimal
    deadline_s: Decimal
    critical_integrity_violation: bool


def evaluate_qualification_v2(records: Sequence[V2OutcomeRecord]) -> dict[str, object]:
    """Evaluate fixed, complete matched evidence without exposing case IDs.

    The primary time measure is a capped loss: a valid outcome contributes its
    measured wall time and every invalid outcome contributes its pre-registered
    deadline.  It is therefore a truthful ``time to valid outcome within the
    declared deadline`` measure, not an estimate of a user's future retries.
    """

    matched = _validate_and_pair(records)

    pooled = _summarize_pairs(tuple(matched.values()))
    lanes: dict[str, dict[str, object]] = {}
    replicate_summaries: dict[str, dict[str, object]] = {}
    lane_quality_ok = True
    lane_time_ok = True
    conditional_by_lane: dict[str, str] = {}
    quality_wins_by_lane: dict[str, int] = {}
    time_wins_by_lane: dict[str, int] = {}
    quality_replicate_passes: dict[str, dict[str, bool]] = {}
    time_replicate_passes: dict[str, dict[str, bool]] = {}

    for lane in _LANES:
        lane_pairs = tuple(pair for key, pair in matched.items() if key[0] == lane)
        lane_summary = _summarize_pairs(lane_pairs)
        lanes[lane] = lane_summary
        lane_quality_ok = lane_quality_ok and _quality_delta_at_least(lane_summary, 0)
        lane_time_ok = lane_time_ok and _ratio_at_most(
            lane_summary, _TIME_LANE_MAX_RATIO_PPM
        )
        conditional_by_lane[lane] = _conditional_status(lane_summary)

        rep_output: dict[str, object] = {}
        quality_wins = 0
        time_wins = 0
        quality_replicates: dict[str, bool] = {}
        time_replicates: dict[str, bool] = {}
        for replicate in range(1, _REPLICATES_PER_LANE + 1):
            summary = _summarize_pairs(
                tuple(pair for key, pair in matched.items() if key[:2] == (lane, replicate))
            )
            rep_output[str(replicate)] = summary
            quality_passed = _quality_delta_at_least(summary, 0)
            time_passed = _ratio_at_most(summary, _TIME_REPLICATE_MAX_RATIO_PPM)
            quality_replicates[str(replicate)] = quality_passed
            time_replicates[str(replicate)] = time_passed
            if quality_passed:
                quality_wins += 1
            if time_passed:
                time_wins += 1
        replicate_summaries[lane] = rep_output
        quality_wins_by_lane[lane] = quality_wins
        time_wins_by_lane[lane] = time_wins
        quality_replicate_passes[lane] = quality_replicates
        time_replicate_passes[lane] = time_replicates

    mcnemar = _exact_one_sided_mcnemar(
        pooled["proxy_only_success_count"], pooled["direct_only_success_count"]
    )
    mcnemar_supports_benefit = _mcnemar_supports_proxy_benefit(
        mcnemar, _MCNEMAR_ALPHA_PPM
    )
    mcnemar = {**mcnemar, "supports_proxy_benefit": mcnemar_supports_benefit}
    quality_safety = (
        pooled["proxy_only_critical_integrity_violation_count"] == 0
        and _quality_delta_at_least(pooled, _QUALITY_SAFETY_NONINFERIORITY_PPM)
        and all(
            _quality_delta_at_least(lanes[lane], _QUALITY_SAFETY_NONINFERIORITY_PPM)
            for lane in _LANES
        )
    )
    quality_efficacy = (
        _quality_delta_at_least(pooled, _QUALITY_EFFICACY_BENEFIT_PPM)
        and lane_quality_ok
        and all(
            quality_wins_by_lane[lane] >= _MIN_QUALITY_NONINFERIOR_REPLICATES
            for lane in _LANES
        )
        and mcnemar_supports_benefit
    )
    unconditional_time = (
        _ratio_at_most(pooled, _TIME_POOLED_MAX_RATIO_PPM)
        and lane_time_ok
        and all(
            time_wins_by_lane[lane] >= _MIN_TIME_PASSING_REPLICATES
            for lane in _LANES
        )
    )
    conditional_status = _overall_conditional_status(conditional_by_lane)

    return {
        "schema_version": "2.0",
        "row_count_per_arm": pooled["row_count"],
        "contract": _contract(),
        "case_count": _CASE_COUNT,
        "lane_count": len(_LANES),
        "replicates_per_lane": _REPLICATES_PER_LANE,
        "pooled": _public_summary(pooled),
        "lanes": {lane: _public_summary(summary) for lane, summary in lanes.items()},
        "replicates": {
            lane: {
                replicate: _public_summary(summary)
                for replicate, summary in values.items()
                if isinstance(summary, dict)
            }
            for lane, values in replicate_summaries.items()
        },
        "mcnemar": mcnemar,
        "gates": {
            "quality_safety": quality_safety,
            "quality_efficacy": quality_efficacy,
            "unconditional_time_to_valid": unconditional_time,
            "conditional_latency_diagnostic": conditional_status,
            "promotion_passed": quality_safety and quality_efficacy and unconditional_time,
        },
        "conditional_latency": {"status": conditional_status, "lanes": conditional_by_lane},
        "gate_details": {
            "quality": {
                "lane_pass": {lane: _quality_delta_at_least(lanes[lane], 0) for lane in _LANES},
                "replicate_pass": quality_replicate_passes,
                "passing_replicate_count_by_lane": quality_wins_by_lane,
            },
            "time_to_valid": {
                "lane_pass": {
                    lane: _ratio_at_most(lanes[lane], _TIME_LANE_MAX_RATIO_PPM)
                    for lane in _LANES
                },
                "replicate_pass": time_replicate_passes,
                "passing_replicate_count_by_lane": time_wins_by_lane,
            },
        },
    }


def _validate_and_pair(
    records: Sequence[V2OutcomeRecord],
) -> dict[tuple[str, int, int], tuple[V2OutcomeRecord, V2OutcomeRecord]]:
    expected = _CASE_COUNT * len(_LANES) * _REPLICATES_PER_LANE * 2
    if len(records) != expected:
        raise QualificationV2Failure("qualification_v2_evidence_incomplete")
    raw: dict[tuple[str, int, int], dict[str, V2OutcomeRecord]] = {}
    case_deadlines: dict[int, Decimal] = {}
    for record in records:
        _validate_record(record)
        key = (record.cache_lane, record.replicate, record.case_ordinal)
        arms = raw.setdefault(key, {})
        if record.arm in arms:
            raise QualificationV2Failure("qualification_v2_duplicate_row")
        arms[record.arm] = record
        prior = case_deadlines.setdefault(record.case_ordinal, record.deadline_s)
        if prior != record.deadline_s:
            raise QualificationV2Failure("qualification_v2_pair_mismatch")

    paired: dict[tuple[str, int, int], tuple[V2OutcomeRecord, V2OutcomeRecord]] = {}
    for lane in _LANES:
        for replicate in range(1, _REPLICATES_PER_LANE + 1):
            for ordinal in range(1, _CASE_COUNT + 1):
                selected_arms = raw.get((lane, replicate, ordinal))
                if selected_arms is None or set(selected_arms) != {"direct", "proxy"}:
                    raise QualificationV2Failure("qualification_v2_evidence_incomplete")
                direct, proxy = selected_arms["direct"], selected_arms["proxy"]
                if direct.deadline_s != proxy.deadline_s:
                    raise QualificationV2Failure("qualification_v2_pair_mismatch")
                paired[(lane, replicate, ordinal)] = (direct, proxy)
    return paired


def _contract() -> dict[str, object]:
    return {
        "case_count": _CASE_COUNT,
        "lanes": list(_LANES),
        "replicates_per_lane": _REPLICATES_PER_LANE,
        "arm_order_per_replicate": ["direct", "proxy"],
        "quality_safety_noninferiority_ppm": _QUALITY_SAFETY_NONINFERIORITY_PPM,
        "quality_efficacy_benefit_ppm": _QUALITY_EFFICACY_BENEFIT_PPM,
        "min_quality_noninferior_replicates": _MIN_QUALITY_NONINFERIOR_REPLICATES,
        "mcnemar_alpha_ppm": _MCNEMAR_ALPHA_PPM,
        "time_pooled_max_ratio_ppm": _TIME_POOLED_MAX_RATIO_PPM,
        "time_lane_max_ratio_ppm": _TIME_LANE_MAX_RATIO_PPM,
        "time_replicate_max_ratio_ppm": _TIME_REPLICATE_MAX_RATIO_PPM,
        "min_time_passing_replicates": _MIN_TIME_PASSING_REPLICATES,
        "conditional_min_both_valid_rows": _CONDITIONAL_MIN_BOTH_VALID_ROWS,
        "conditional_max_p95_ratio_ppm": _CONDITIONAL_MAX_P95_RATIO_PPM,
    }


def _validate_record(record: V2OutcomeRecord) -> None:
    if (
        not isinstance(record, V2OutcomeRecord)
        or not _is_int(record.case_ordinal)
        or not 1 <= record.case_ordinal <= _CASE_COUNT
        or record.cache_lane not in _LANES
        or not _is_int(record.replicate)
        or not 1 <= record.replicate <= _REPLICATES_PER_LANE
        or record.arm not in {"direct", "proxy"}
        or not isinstance(record.passed, bool)
        or not isinstance(record.critical_integrity_violation, bool)
        or not _positive_finite_decimal(record.wall_s)
        or not _positive_finite_decimal(record.deadline_s)
        or (record.passed and record.wall_s > record.deadline_s)
    ):
        raise QualificationV2Failure("qualification_v2_row_invalid")


def _summarize_pairs(pairs: Sequence[tuple[V2OutcomeRecord, V2OutcomeRecord]]) -> dict[str, object]:
    if not pairs:
        raise QualificationV2Failure("qualification_v2_evidence_incomplete")
    direct_success = 0
    proxy_success = 0
    direct_only = 0
    proxy_only = 0
    proxy_only_critical_integrity_violations = 0
    direct_loss = Decimal(0)
    proxy_loss = Decimal(0)
    direct_penalized_walls: list[Decimal] = []
    proxy_penalized_walls: list[Decimal] = []
    both_valid_direct_walls: list[Decimal] = []
    both_valid_proxy_walls: list[Decimal] = []
    for direct, proxy in pairs:
        direct_success += int(direct.passed)
        proxy_success += int(proxy.passed)
        if direct.passed and not proxy.passed:
            direct_only += 1
        elif proxy.passed and not direct.passed:
            proxy_only += 1
        proxy_only_critical_integrity_violations += int(
            proxy.critical_integrity_violation and not direct.critical_integrity_violation
        )
        direct_penalized = direct.wall_s if direct.passed else direct.deadline_s
        proxy_penalized = proxy.wall_s if proxy.passed else proxy.deadline_s
        direct_loss += direct_penalized
        proxy_loss += proxy_penalized
        direct_penalized_walls.append(direct_penalized)
        proxy_penalized_walls.append(proxy_penalized)
        if direct.passed and proxy.passed:
            both_valid_direct_walls.append(direct.wall_s)
            both_valid_proxy_walls.append(proxy.wall_s)
    count = len(pairs)
    direct_p95 = _p95(both_valid_direct_walls)
    proxy_p95 = _p95(both_valid_proxy_walls)
    return {
        "row_count": count,
        "direct_valid_count": direct_success,
        "proxy_valid_count": proxy_success,
        "success_delta_ppm": _signed_rate_ppm(proxy_success - direct_success, count),
        "direct_only_success_count": direct_only,
        "proxy_only_success_count": proxy_only,
        "proxy_only_critical_integrity_violation_count": proxy_only_critical_integrity_violations,
        "both_valid_count": len(both_valid_direct_walls),
        "conditional_direct_p95_wall_us": _microseconds(direct_p95),
        "conditional_proxy_p95_wall_us": _microseconds(proxy_p95),
        "conditional_proxy_to_direct_p95_ratio_ppm": _ratio_ppm(proxy_p95, direct_p95),
        "direct_penalized_mean_wall_us": _mean_microseconds(direct_loss, count),
        "proxy_penalized_mean_wall_us": _mean_microseconds(proxy_loss, count),
        "proxy_to_direct_penalized_mean_ratio_ppm": _ratio_ppm(proxy_loss, direct_loss),
        **_penalized_percentiles("direct", direct_penalized_walls),
        **_penalized_percentiles("proxy", proxy_penalized_walls),
        "_direct_loss": direct_loss,
        "_proxy_loss": proxy_loss,
    }


def _exact_one_sided_mcnemar(proxy_only: object, direct_only: object) -> dict[str, object]:
    if not _is_int(proxy_only) or not _is_int(direct_only):
        raise QualificationV2Failure("qualification_v2_internal_invalid")
    assert isinstance(proxy_only, int)
    assert isinstance(direct_only, int)
    if proxy_only < 0 or direct_only < 0:
        raise QualificationV2Failure("qualification_v2_internal_invalid")
    discordant = proxy_only + direct_only
    denominator = 1 << discordant
    numerator = sum(comb(discordant, value) for value in range(proxy_only, discordant + 1))
    # The caller compares this exact fraction to its immutable alpha.  A
    # decimal presentation is deliberately avoided, so no rounding changes a
    # decision at the boundary.
    return {
        "proxy_only_success_count": proxy_only,
        "direct_only_success_count": direct_only,
        "discordant_pair_count": discordant,
        "one_sided_tail_numerator": numerator,
        "one_sided_tail_denominator": denominator,
    }


def _quality_delta_at_least(summary: dict[str, object], threshold_ppm: int) -> bool:
    direct = _summary_int(summary, "direct_valid_count")
    proxy = _summary_int(summary, "proxy_valid_count")
    count = _summary_int(summary, "row_count")
    return (proxy - direct) * 1_000_000 >= threshold_ppm * count


def _ratio_at_most(summary: dict[str, object], threshold_ppm: int) -> bool:
    direct = _summary_decimal(summary, "_direct_loss")
    proxy = _summary_decimal(summary, "_proxy_loss")
    return proxy * Decimal(1_000_000) <= direct * Decimal(threshold_ppm)


def _conditional_status(summary: dict[str, object]) -> str:
    count = _summary_int(summary, "both_valid_count")
    ratio = summary["conditional_proxy_to_direct_p95_ratio_ppm"]
    if count < _CONDITIONAL_MIN_BOTH_VALID_ROWS:
        return "unavailable"
    if not isinstance(ratio, int):
        raise QualificationV2Failure("qualification_v2_internal_invalid")
    return "passed" if ratio <= _CONDITIONAL_MAX_P95_RATIO_PPM else "failed"


def _overall_conditional_status(states: dict[str, str]) -> str:
    if any(value == "unavailable" for value in states.values()):
        return "unavailable"
    if any(value == "failed" for value in states.values()):
        return "failed"
    if all(value == "passed" for value in states.values()):
        return "passed"
    raise QualificationV2Failure("qualification_v2_internal_invalid")


def _mcnemar_supports_proxy_benefit(mcnemar: dict[str, object], alpha_ppm: int) -> bool:
    numerator = _summary_int(mcnemar, "one_sided_tail_numerator")
    denominator = _summary_int(mcnemar, "one_sided_tail_denominator")
    return numerator * 1_000_000 < denominator * alpha_ppm


def _p95(values: Sequence[Decimal]) -> Decimal | None:
    if not values:
        return None
    return sorted(values)[(len(values) - 1) * 95 // 100]


def _penalized_percentiles(arm: str, values: Sequence[Decimal]) -> dict[str, int | None]:
    return {
        f"{arm}_penalized_p50_wall_us": _microseconds(_percentile(values, 500_000)),
        f"{arm}_penalized_p95_wall_us": _microseconds(_percentile(values, 950_000)),
        f"{arm}_penalized_p99_wall_us": _microseconds(_percentile(values, 990_000)),
    }


def _percentile(values: Sequence[Decimal], percentile_ppm: int) -> Decimal:
    if not values:
        raise QualificationV2Failure("qualification_v2_internal_invalid")
    return sorted(values)[(len(values) - 1) * percentile_ppm // 1_000_000]


def _ratio_ppm(numerator: Decimal | None, denominator: Decimal | None) -> int | None:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return int((numerator * Decimal(1_000_000) / denominator).to_integral_value(rounding=ROUND_CEILING))


def _mean_microseconds(total: Decimal, count: int) -> int:
    return int((total * Decimal(1_000_000) / Decimal(count)).to_integral_value(rounding=ROUND_CEILING))


def _microseconds(value: Decimal | None) -> int | None:
    if value is None:
        return None
    return int((value * Decimal(1_000_000)).to_integral_value(rounding=ROUND_CEILING))


def _signed_rate_ppm(numerator: int, denominator: int) -> int:
    return numerator * 1_000_000 // denominator


def _public_summary(summary: dict[str, object]) -> dict[str, object]:
    """Drop arithmetic-only totals before returning an aggregate projection."""

    return {key: value for key, value in summary.items() if not key.startswith("_")}


def _summary_int(summary: dict[str, object], key: str) -> int:
    value = summary.get(key)
    if not _is_int(value):
        raise QualificationV2Failure("qualification_v2_internal_invalid")
    assert isinstance(value, int)
    return value


def _summary_decimal(summary: dict[str, object], key: str) -> Decimal:
    value = summary.get(key)
    if not isinstance(value, Decimal):
        raise QualificationV2Failure("qualification_v2_internal_invalid")
    return value


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_finite_decimal(value: object) -> bool:
    return isinstance(value, Decimal) and value.is_finite() and value > 0
