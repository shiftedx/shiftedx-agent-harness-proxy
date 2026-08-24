#!/usr/bin/env python3
"""Export an allowlist-only public result from a frozen v2 campaign outcome."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from shiftedx_harness_proxy.qualification_campaign_v2 import _contract

_SHA256_LENGTH = 64
_MAX_OUTCOME_BYTES = 1024 * 1024
_FINAL_REPORT_SCHEMA = "shiftedx-final-qualification-report-v1"
_FINAL_DECISIONS = {"PROMOTE", "DO NOT PROMOTE", "BLOCKED"}
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "prompt",
        "prompts",
        "transcript",
        "transcripts",
        "message",
        "messages",
        "output",
        "outputs",
        "response",
        "responses",
        "tool_call",
        "tool_calls",
        "tool_argument",
        "tool_arguments",
        "tool_result",
        "tool_results",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "endpoint",
        "endpoints",
        "host",
        "hosts",
        "hostname",
        "path",
        "paths",
        "tenant",
        "tenants",
        "scenario",
        "scenarios",
        "scenario_id",
        "scenario_ids",
    }
)
_SUMMARY_KEYS = (
    "row_count",
    "direct_valid_count",
    "proxy_valid_count",
    "success_delta_ppm",
    "both_valid_count",
    "direct_only_success_count",
    "proxy_only_success_count",
    "proxy_only_critical_integrity_violation_count",
    "direct_penalized_mean_wall_us",
    "proxy_penalized_mean_wall_us",
    "proxy_to_direct_penalized_mean_ratio_ppm",
    "direct_penalized_p50_wall_us",
    "direct_penalized_p95_wall_us",
    "direct_penalized_p99_wall_us",
    "proxy_penalized_p50_wall_us",
    "proxy_penalized_p95_wall_us",
    "proxy_penalized_p99_wall_us",
    "conditional_direct_p95_wall_us",
    "conditional_proxy_p95_wall_us",
    "conditional_proxy_to_direct_p95_ratio_ppm",
)
_LIMITATIONS = [
    "Measures valid agent outcomes and deadline-penalized time to a valid outcome, not raw inference "
    "throughput or token latency.",
    "The fixed direct-then-proxy sequence is not a randomized causal comparison.",
    "Conditional matched latency is a diagnostic; promotion is determined by the stated quality and "
    "time-to-valid gates.",
]


class PublicQualificationExportError(ValueError):
    """A stable, content-free public-export failure."""


def public_qualification_result(
    outcome_bytes: bytes, final_report_bytes: bytes, operational_evidence_bytes: bytes
) -> dict[str, object]:
    """Project a reviewed, hash-bound final v2 decision; never copy source objects."""

    if not 0 < len(outcome_bytes) <= _MAX_OUTCOME_BYTES:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    try:
        outcome = json.loads(outcome_bytes, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PublicQualificationExportError("public_qualification_outcome_invalid") from None
    if not isinstance(outcome, dict):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")

    _require_exact(outcome, "schema_version", "2.0")
    _require_exact(outcome, "record_type", "qualification_campaign_outcome")
    _require_exact(outcome, "status", "scored_complete")
    decision = _require_one_of(outcome, "scored_decision", {"scored_passed", "scored_failed"})
    failure_category = outcome.get("failure_category")
    if not (failure_category is None or _is_safe_category(failure_category)):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    manifest_sha256 = _require_sha256(outcome, "campaign_manifest_sha256")
    head_event_sha256 = _require_sha256(outcome, "head_event_sha256")
    contract = _contract()
    expected_case_count = contract.get("case_count")
    expected_lanes = contract.get("lanes")
    expected_replicates = contract.get("replicates_per_lane")
    if (
        type(expected_case_count) is not int
        or not isinstance(expected_lanes, list)
        or not all(isinstance(lane, str) for lane in expected_lanes)
        or type(expected_replicates) is not int
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    expected_slot_count = len(expected_lanes) * expected_replicates
    counts = {
        key: _require_nonnegative_int(outcome, key)
        for key in ("event_count", "slot_count", "scored_stage_count", "scored_model_instance_count")
    }
    if counts != {
        "event_count": 1 + 2 * expected_slot_count,
        "slot_count": expected_slot_count,
        "scored_stage_count": 2 * expected_slot_count,
        "scored_model_instance_count": 2 * expected_slot_count,
    }:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    reconciliations = _require_sha256_list(outcome, "proxy_reconciliation_sha256s", length=expected_slot_count)
    evaluator = _require_object(outcome, "evaluator")
    _require_exact(evaluator, "schema_version", "2.0")
    if {
        "row_count_per_arm": _require_nonnegative_int(evaluator, "row_count_per_arm"),
        "case_count": _require_nonnegative_int(evaluator, "case_count"),
        "lane_count": _require_nonnegative_int(evaluator, "lane_count"),
        "replicates_per_lane": _require_nonnegative_int(evaluator, "replicates_per_lane"),
    } != {
        "row_count_per_arm": expected_case_count * expected_slot_count,
        "case_count": expected_case_count,
        "lane_count": len(expected_lanes),
        "replicates_per_lane": expected_replicates,
    }:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    if _require_object(evaluator, "contract") != contract:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    gates = _gates(_require_object(evaluator, "gates"))
    if gates["promotion_passed"] != (
        gates["quality_safety"] and gates["quality_efficacy"] and gates["unconditional_time_to_valid"]
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    if (decision == "scored_passed") != gates["promotion_passed"]:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    if (failure_category is None) != (decision == "scored_passed"):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    conditional_latency = _conditional_latency(_require_object(evaluator, "conditional_latency"), gates, expected_lanes)
    pooled = _summary(_require_object(evaluator, "pooled"))
    lanes = _lanes(_require_object(evaluator, "lanes"), expected_lanes)
    mcnemar = _mcnemar(_require_object(evaluator, "mcnemar"))
    final_report = _final_report(
        final_report_bytes,
        outcome_bytes=outcome_bytes,
        manifest_sha256=manifest_sha256,
        lanes=expected_lanes,
    )
    operational_gates = _operational_evidence(
        operational_evidence_bytes,
        expected_sha256=final_report["operational_evidence_sha256"],
        manifest_sha256=manifest_sha256,
        outcome_sha256=hashlib.sha256(outcome_bytes).hexdigest(),
        head_event_sha256=head_event_sha256,
    )
    if final_report["operational_gates"] != operational_gates:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    _validate_final_decision(
        final_report,
        scored_passed=decision == "scored_passed",
        scored_gates=gates,
        operational_gates=operational_gates,
    )

    result: dict[str, object] = {
        "schema_version": "shiftedx-public-qualification-result-v1",
        "record_type": "public_qualification_result",
        "provenance": {
            "source_outcome_sha256": hashlib.sha256(outcome_bytes).hexdigest(),
            "campaign_manifest_sha256": manifest_sha256,
            "head_event_sha256": head_event_sha256,
            "proxy_reconciliation_sha256s": reconciliations,
            "operational_evidence_sha256": final_report["operational_evidence_sha256"],
        },
        "qualification": {
            "status": "scored_complete",
            "scored_decision": decision,
            "final_decision": final_report["final_decision"],
            "failure_category": failure_category,
            **counts,
            "evaluator_contract": contract,
            "gates": gates,
            "conditional_latency": conditional_latency,
            "pooled": pooled,
            "lanes": lanes,
            "mcnemar": mcnemar,
        },
        "operational": {
            "gates": operational_gates,
            "decode": final_report["decode"],
            "amplification": final_report["amplification"],
            "reconciliation": final_report["reconciliation"],
        },
        "limitations": _LIMITATIONS,
    }
    _assert_public_safe_json(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--final-report", type=Path, required=True)
    parser.add_argument("--operational-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = public_qualification_result(
            _read_frozen(args.outcome), _read_frozen(args.final_report), _read_frozen(args.operational_evidence)
        )
        payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        _assert_public_safe_json(payload)
        _write_no_clobber(args.output, payload)
    except (OSError, PublicQualificationExportError):
        raise SystemExit("public_qualification_export_failed") from None
    return 0


def _read_frozen(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise OSError("outcome path invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= _MAX_OUTCOME_BYTES:
            raise OSError("outcome file invalid")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise OSError("outcome file truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_no_clobber(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.parent.is_symlink():
        raise OSError("output path invalid")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("public result partial write")
        offset += written


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _require_object(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return value


def _require_exact_keys(document: dict[str, Any], expected: set[str]) -> None:
    if set(document) != expected:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")


def _load_json(payload: bytes) -> dict[str, Any]:
    if not 0 < len(payload) <= _MAX_OUTCOME_BYTES:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    try:
        document = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PublicQualificationExportError("public_qualification_outcome_invalid") from None
    if not isinstance(document, dict):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return document


def _require_exact(document: dict[str, Any], key: str, expected: object) -> None:
    if document.get(key) != expected:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")


def _require_one_of(document: dict[str, Any], key: str, expected: set[str]) -> str:
    value = document.get(key)
    if not isinstance(value, str) or value not in expected:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return value


def _require_nonnegative_int(document: dict[str, Any], key: str) -> int:
    value = document.get(key)
    if type(value) is not int or value < 0:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return value


def _require_sha256(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return value


def _require_sha256_list(document: dict[str, Any], key: str, *, length: int) -> list[str]:
    values = document.get(key)
    if not isinstance(values, list) or len(values) != length:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    result: list[str] = []
    for value in values:
        result.append(_require_sha256({key: value}, key))
    if len(set(result)) != length:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return result


def _gates(document: dict[str, Any]) -> dict[str, bool | str]:
    result: dict[str, bool | str] = {}
    for key in ("quality_safety", "quality_efficacy", "unconditional_time_to_valid", "promotion_passed"):
        value = document.get(key)
        if type(value) is not bool:
            raise PublicQualificationExportError("public_qualification_outcome_invalid")
        result[key] = value
    result["conditional_latency_diagnostic"] = _require_one_of(
        document, "conditional_latency_diagnostic", {"passed", "failed", "unavailable"}
    )
    return result


def _conditional_latency(
    document: dict[str, Any], gates: dict[str, bool | str], expected_lanes: list[str]
) -> dict[str, object]:
    status = _require_one_of(document, "status", {"passed", "failed", "unavailable"})
    lanes = document.get("lanes")
    if not isinstance(lanes, dict) or set(lanes) != set(expected_lanes):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    lane_states = {
        lane: _require_one_of(lanes, lane, {"passed", "failed", "unavailable"}) for lane in expected_lanes
    }
    if status != gates["conditional_latency_diagnostic"] or status != _overall_conditional_status(lane_states):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return {"status": status, "lanes": lane_states}


def _overall_conditional_status(lanes: dict[str, str]) -> str:
    if "unavailable" in lanes.values():
        return "unavailable"
    if "failed" in lanes.values():
        return "failed"
    return "passed"


def _summary(document: dict[str, Any]) -> dict[str, int]:
    result = {key: _require_nonnegative_int(document, key) for key in _SUMMARY_KEYS}
    if result["direct_valid_count"] > result["row_count"] or result["proxy_valid_count"] > result["row_count"]:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return result


def _lanes(document: dict[str, Any], expected_lanes: list[str]) -> dict[str, dict[str, int]]:
    if set(document) != set(expected_lanes):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return {lane: _summary(_require_object(document, lane)) for lane in expected_lanes}


def _mcnemar(document: dict[str, Any]) -> dict[str, int | bool]:
    result: dict[str, int | bool] = {
        key: _require_nonnegative_int(document, key)
        for key in ("direct_only_success_count", "proxy_only_success_count", "discordant_pair_count")
    }
    supports = document.get("supports_proxy_benefit")
    if (
        type(supports) is not bool
        or result["discordant_pair_count"]
        != result["direct_only_success_count"] + result["proxy_only_success_count"]
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    result["supports_proxy_benefit"] = supports
    return result


def _final_report(
    payload: bytes, *, outcome_bytes: bytes, manifest_sha256: str, lanes: list[str]
) -> dict[str, Any]:
    report = _load_json(payload)
    _require_exact_keys(
        report,
        {
            "schema_version",
            "record_type",
            "review_status",
            "final_decision",
            "scored_outcome_sha256",
            "campaign_manifest_sha256",
            "operational_evidence_sha256",
            "operational_gates",
            "decode",
            "amplification",
            "reconciliation",
        },
    )
    _require_exact(report, "schema_version", _FINAL_REPORT_SCHEMA)
    _require_exact(report, "record_type", "final_qualification_report")
    _require_exact(report, "review_status", "reviewed")
    _require_one_of(report, "final_decision", _FINAL_DECISIONS)
    if _require_sha256(report, "scored_outcome_sha256") != hashlib.sha256(outcome_bytes).hexdigest():
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    if _require_sha256(report, "campaign_manifest_sha256") != manifest_sha256:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    _require_sha256(report, "operational_evidence_sha256")
    gates = _operational_gates(_require_object(report, "operational_gates"))
    report["operational_gates"] = gates
    report["decode"] = _decode(_require_object(report, "decode"), lanes)
    report["amplification"] = _amplification(_require_object(report, "amplification"))
    report["reconciliation"] = _reconciliation(_require_object(report, "reconciliation"))
    return report


def _operational_evidence(
    payload: bytes,
    *,
    expected_sha256: object,
    manifest_sha256: str,
    outcome_sha256: str,
    head_event_sha256: str,
) -> dict[str, bool]:
    if not isinstance(expected_sha256, str) or hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    evidence = _load_json(payload)
    _require_exact(evidence, "schema_version", "operational_matrix_v1")
    if _require_sha256(evidence, "manifest_sha256") != manifest_sha256:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    campaign = _require_object(evidence, "qualification_campaign")
    _require_exact_keys(campaign, {"manifest_sha256", "outcome_sha256", "head_event_sha256"})
    if (
        _require_sha256(campaign, "manifest_sha256") != manifest_sha256
        or _require_sha256(campaign, "outcome_sha256") != outcome_sha256
        or _require_sha256(campaign, "head_event_sha256") != head_event_sha256
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    candidate = evidence.get("candidate_image")
    rollback = evidence.get("rollback_image")
    if not _is_digest_reference(candidate) or not _is_digest_reference(rollback) or candidate == rollback:
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    gates = _operational_gates(_require_object(evidence, "gates"))
    if evidence.get("passed") is not all(gates.values()):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return gates


def _operational_gates(document: dict[str, Any]) -> dict[str, bool]:
    if not document or not all(_is_safe_category(key) and type(value) is bool for key, value in document.items()):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return {key: document[key] for key in sorted(document)}


def _decode(document: dict[str, Any], lanes: list[str]) -> dict[str, dict[str, int | bool]]:
    if set(document) != set(lanes):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    result: dict[str, dict[str, int | bool]] = {}
    for lane in lanes:
        value = _require_object(document, lane)
        _require_exact_keys(
            value,
            {
                "direct_weighted_tokens_per_second_milli",
                "proxy_weighted_tokens_per_second_milli",
                "proxy_to_direct_ratio_ppm",
                "gate_passed",
            },
        )
        direct = _require_nonnegative_int(value, "direct_weighted_tokens_per_second_milli")
        proxy = _require_nonnegative_int(value, "proxy_weighted_tokens_per_second_milli")
        ratio = _require_nonnegative_int(value, "proxy_to_direct_ratio_ppm")
        passed = value.get("gate_passed")
        if direct == 0 or type(passed) is not bool or (ratio >= 900_000) != passed:
            raise PublicQualificationExportError("public_qualification_outcome_invalid")
        result[lane] = {
            "direct_weighted_tokens_per_second_milli": direct,
            "proxy_weighted_tokens_per_second_milli": proxy,
            "proxy_to_direct_ratio_ppm": ratio,
            "gate_passed": passed,
        }
    return result


def _amplification(document: dict[str, Any]) -> dict[str, int | bool]:
    _require_exact_keys(
        document,
        {
            "mean_upstream_calls_per_downstream_ppm",
            "max_upstream_calls_per_request",
            "configured_ceiling",
            "gate_passed",
        },
    )
    result = {key: _require_nonnegative_int(document, key) for key in document if key != "gate_passed"}
    passed = document.get("gate_passed")
    if (
        type(passed) is not bool
        or result["configured_ceiling"] == 0
        or (result["mean_upstream_calls_per_downstream_ppm"] <= 2_000_000
            and result["max_upstream_calls_per_request"] <= result["configured_ceiling"])
        != passed
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return {**result, "gate_passed": passed}


def _reconciliation(document: dict[str, Any]) -> dict[str, bool]:
    _require_exact_keys(document, {"scored_artifacts_bound", "operational_accounting_reconciled", "gate_passed"})
    values = {key: document.get(key) for key in document}
    if not all(type(value) is bool for value in values.values()):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    if values["gate_passed"] != (values["scored_artifacts_bound"] and values["operational_accounting_reconciled"]):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")
    return values  # type: ignore[return-value]


def _validate_final_decision(
    report: dict[str, Any],
    *,
    scored_passed: bool,
    scored_gates: dict[str, bool | str],
    operational_gates: dict[str, bool],
) -> None:
    if report["final_decision"] != "PROMOTE":
        return
    if not (
        scored_passed
        and all(value is True for key, value in scored_gates.items() if key != "conditional_latency_diagnostic")
        and all(operational_gates.values())
        and all(lane["gate_passed"] is True for lane in report["decode"].values())
        and report["amplification"]["gate_passed"] is True
        and report["reconciliation"]["gate_passed"] is True
    ):
        raise PublicQualificationExportError("public_qualification_outcome_invalid")


def _is_digest_reference(value: object) -> bool:
    return (
        isinstance(value, str)
        and "@sha256:" in value
        and len(value.rsplit("@sha256:", 1)[1]) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value.rsplit("@sha256:", 1)[1])
    )


def _assert_public_safe_json(payload: bytes) -> None:
    _scan_public_value(_load_json(payload))


def _scan_public_value(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_PUBLIC_KEYS:
                raise PublicQualificationExportError("public_qualification_outcome_invalid")
            _scan_public_value(nested)
    elif isinstance(value, list):
        for nested in value:
            _scan_public_value(nested)
    elif isinstance(value, str):
        lowered = value.casefold()
        private_prefixes = ("/users/", "/home/", "/private/", "/" + "tmp/", "/var/")
        if "://" in value or lowered.startswith(private_prefixes):
            raise PublicQualificationExportError("public_qualification_outcome_invalid")


def _is_safe_category(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 64
        and all(char.islower() or char.isdigit() or char == "_" for char in value)
    )


if __name__ == "__main__":
    raise SystemExit(main())
