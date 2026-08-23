"""Private, fail-closed adaptation of scored v1 ledgers to V2 facts.

This adapter deliberately returns only payload-free :class:`V2OutcomeRecord`
objects.  Its caller must derive commitments from validated, hash-chained v2
campaign events; this module does not alter v1 scored ledgers or expose their
case identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, cast

from shiftedx_harness_proxy.qualification_campaign import _read_regular_file
from shiftedx_harness_proxy.qualification_campaign_v2 import V2OutcomeRecord
from shiftedx_harness_proxy.qualification_contract import RuntimeOutcomeFailure, load_runtime_outcome

Arm = Literal["direct", "proxy"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CASE_COUNT = 22
_SCENARIO_COUNT = 30


class QualificationV2EvidenceFailure(ValueError):
    """A stable, content-free private-evidence validation failure."""


@dataclass(frozen=True)
class V2EvidenceSpec:
    """Manifest-derived commitments for one V2 lane/replicate pair."""

    manifest_sha256: str
    campaign_id_sha256: str
    scenario_order_sha256: str
    cohort_case_ids: tuple[str, ...]
    cohort_case_ids_sha256: str
    critical_cohort_ordinals: tuple[int, ...]
    critical_cohort_ordinals_sha256: str
    cache_lane: str
    replicate: int
    slot_ordinal: int
    pair_index: int
    deadline_s: Decimal
    expected_direct_outcome_sha256: str


@dataclass(frozen=True)
class V2ScoredLedger:
    """One private scored ledger and its exact runtime-outcome commitment."""

    arm: Arm
    ledger_path: Path
    runtime_outcome_path: Path
    runtime_outcome_sha256: str
    attestation_path: Path
    model_evidence_path: Path
    model_identity_sha256: str
    proxy_reconciliation_path: Path | None
    predecessor_outcome_sha256: str | None


def adapt_v2_scored_evidence(
    spec: V2EvidenceSpec, ledgers: tuple[V2ScoredLedger, V2ScoredLedger]
) -> list[V2OutcomeRecord]:
    """Authenticate paired private ledgers and return safe V2 facts only."""

    _validate_spec(spec)
    by_arm: dict[str, V2ScoredLedger] = {}
    for ledger in ledgers:
        if not isinstance(ledger, V2ScoredLedger) or ledger.arm in by_arm:
            raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
        by_arm[ledger.arm] = ledger
    if set(by_arm) != {"direct", "proxy"}:
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")

    direct_rows, direct_outcome_sha256 = _authenticated_rows(spec, by_arm["direct"])
    if direct_outcome_sha256 != spec.expected_direct_outcome_sha256:
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
    proxy = by_arm["proxy"]
    if proxy.predecessor_outcome_sha256 != direct_outcome_sha256:
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
    proxy_rows, _proxy_outcome_sha256 = _authenticated_rows(spec, proxy)

    records: list[V2OutcomeRecord] = []
    for arm, rows in (("direct", direct_rows), ("proxy", proxy_rows)):
        for ordinal, case_id in enumerate(spec.cohort_case_ids, start=1):
            row = rows[case_id]
            passed = row.get("passed")
            telemetry = row.get("telemetry")
            metadata = row.get("metadata")
            wall_s = telemetry.get("wall_s") if isinstance(telemetry, dict) else None
            tool_calls = telemetry.get("tool_calls") if isinstance(telemetry, dict) else None
            forbidden_calls = metadata.get("forbidden_calls") if isinstance(metadata, dict) else None
            if (
                not isinstance(passed, bool)
                or not _positive_finite_decimal(wall_s)
                or not _safe_names(tool_calls)
                or not _safe_names(forbidden_calls)
            ):
                raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
            assert isinstance(wall_s, int | Decimal) and not isinstance(wall_s, bool)
            assert isinstance(tool_calls, list) and isinstance(forbidden_calls, list)
            critical = ordinal in spec.critical_cohort_ordinals
            records.append(
                V2OutcomeRecord(
                    case_ordinal=ordinal,
                    cache_lane=spec.cache_lane,
                    replicate=spec.replicate,
                    arm=cast(Arm, arm),
                    passed=passed,
                    wall_s=Decimal(str(wall_s)),
                    deadline_s=spec.deadline_s,
                    critical_integrity_violation=critical
                    and bool(set(tool_calls) & set(forbidden_calls)),
                )
            )
    return records


def _authenticated_rows(
    spec: V2EvidenceSpec, source: V2ScoredLedger
) -> tuple[dict[str, dict[str, Any]], str]:
    expected_stage = "scored-direct" if source.arm == "direct" else "scored-proxy"
    if (
        source.arm == "direct"
        and (source.proxy_reconciliation_path is not None or source.predecessor_outcome_sha256 is not None)
    ) or (
        source.arm == "proxy"
        and (
            source.proxy_reconciliation_path is None
            or not isinstance(source.predecessor_outcome_sha256, str)
            or _SHA256.fullmatch(source.predecessor_outcome_sha256) is None
        )
    ):
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
    try:
        ledger = _read_regular_file(source.ledger_path, private=True)
        outcome = load_runtime_outcome(
            source.runtime_outcome_path,
            expected_stage=cast(Literal["scored-direct", "scored-proxy"], expected_stage),
            run_manifest_sha256=spec.manifest_sha256,
            attestation=source.attestation_path,
            model_evidence=source.model_evidence_path,
            model_identity_sha256=source.model_identity_sha256,
            output_ledger=source.ledger_path,
            expected_output_record_count=_SCENARIO_COUNT,
            proxy_reconciliation=source.proxy_reconciliation_path,
            campaign_id_sha256=spec.campaign_id_sha256,
            slot_ordinal=spec.slot_ordinal,
            cache_lane=cast(Literal["cold", "warm-prefix"], spec.cache_lane),
            pair_index=spec.pair_index,
            campaign_version="v2",
        )
    except (RuntimeOutcomeFailure, OSError) as error:
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid") from error
    if outcome.file_sha256 != source.runtime_outcome_sha256:
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
    case_ids: list[str] = []
    rows: dict[str, dict[str, Any]] = {}
    try:
        decoded = ledger.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid") from error
    for line in decoded.splitlines():
        if not line:
            raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
        try:
            row = json.loads(line, object_pairs_hook=_unique_object, parse_float=Decimal)
        except (ValueError, json.JSONDecodeError) as error:
            raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid") from error
        case_id = row.get("case_id") if isinstance(row, dict) else None
        if not isinstance(case_id, str) or _SAFE_ID.fullmatch(case_id) is None or case_id in rows:
            raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
        case_ids.append(case_id)
        rows[case_id] = row
    if (
        len(case_ids) != _SCENARIO_COUNT
        or _sha256(case_ids) != spec.scenario_order_sha256
        or tuple(case_id for case_id in case_ids if case_id in set(spec.cohort_case_ids))
        != spec.cohort_case_ids
    ):
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")
    return rows, outcome.file_sha256


def _validate_spec(spec: V2EvidenceSpec) -> None:
    if (
        not isinstance(spec, V2EvidenceSpec)
        or any(
            _SHA256.fullmatch(value) is None
            for value in (
                spec.manifest_sha256,
                spec.campaign_id_sha256,
                spec.scenario_order_sha256,
                spec.cohort_case_ids_sha256,
                spec.critical_cohort_ordinals_sha256,
                spec.expected_direct_outcome_sha256,
            )
        )
        or len(spec.cohort_case_ids) != _CASE_COUNT
        or len(set(spec.cohort_case_ids)) != _CASE_COUNT
        or any(_SAFE_ID.fullmatch(value) is None for value in spec.cohort_case_ids)
        or _sha256(spec.cohort_case_ids) != spec.cohort_case_ids_sha256
        or not spec.critical_cohort_ordinals
        or tuple(sorted(set(spec.critical_cohort_ordinals))) != spec.critical_cohort_ordinals
        or any(
            not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= _CASE_COUNT
            for value in spec.critical_cohort_ordinals
        )
        or _sha256(spec.critical_cohort_ordinals) != spec.critical_cohort_ordinals_sha256
        or spec.cache_lane not in {"cold", "warm-prefix"}
        or not isinstance(spec.replicate, int)
        or isinstance(spec.replicate, bool)
        or not 1 <= spec.replicate <= 4
        or spec.replicate != spec.pair_index
        or not isinstance(spec.slot_ordinal, int)
        or isinstance(spec.slot_ordinal, bool)
        or spec.slot_ordinal <= 0
        or not isinstance(spec.pair_index, int)
        or isinstance(spec.pair_index, bool)
        or spec.pair_index <= 0
        or (spec.cache_lane == "cold" and spec.slot_ordinal != spec.replicate)
        or (spec.cache_lane == "warm-prefix" and spec.slot_ordinal != spec.replicate + 4)
        or not _positive_finite_decimal(spec.deadline_s)
    ):
        raise QualificationV2EvidenceFailure("qualification_v2_evidence_invalid")


def _safe_names(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(name, str) and _SAFE_ID.fullmatch(name) is not None for name in value
    )


def _positive_finite_decimal(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | Decimal):
        return False
    return Decimal(value).is_finite() and value > 0


def _sha256(value: tuple[str, ...] | tuple[int, ...] | list[str]) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result
