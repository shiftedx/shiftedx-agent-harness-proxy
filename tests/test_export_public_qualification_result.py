from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


def _module():
    script = Path(__file__).parents[1] / "scripts" / "export_public_qualification_result.py"
    spec = importlib.util.spec_from_file_location("public_qualification_export", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(character: str) -> str:
    return character * 64


def _summary(*, direct_valid: int = 160, proxy_valid: int = 220) -> dict[str, int]:
    return {
        "row_count": 240,
        "direct_valid_count": direct_valid,
        "proxy_valid_count": proxy_valid,
        "success_delta_ppm": 250_000,
        "both_valid_count": 156,
        "direct_only_success_count": 4,
        "proxy_only_success_count": 64,
        "proxy_only_critical_integrity_violation_count": 0,
        "direct_penalized_mean_wall_us": 203_667_869,
        "proxy_penalized_mean_wall_us": 54_900_337,
        "proxy_to_direct_penalized_mean_ratio_ppm": 269_559,
        "direct_penalized_p50_wall_us": 7_222_078,
        "direct_penalized_p95_wall_us": 600_000_000,
        "direct_penalized_p99_wall_us": 600_000_000,
        "proxy_penalized_p50_wall_us": 4_954_788,
        "proxy_penalized_p95_wall_us": 600_000_000,
        "proxy_penalized_p99_wall_us": 600_000_000,
        "conditional_direct_p95_wall_us": 10_609_866,
        "conditional_proxy_p95_wall_us": 11_860_718,
        "conditional_proxy_to_direct_p95_ratio_ppm": 1_117_896,
    }


def _outcome() -> dict[str, object]:
    module = _module()
    return {
        "schema_version": "2.0",
        "record_type": "qualification_campaign_outcome",
        "status": "scored_complete",
        "scored_decision": "scored_passed",
        "failure_category": None,
        "campaign_manifest_sha256": _sha("a"),
        "head_event_sha256": _sha("b"),
        "event_count": 17,
        "slot_count": 8,
        "scored_stage_count": 16,
        "scored_model_instance_count": 16,
        "proxy_reconciliation_sha256s": [_sha(format(index, "x")) for index in range(1, 9)],
        "evaluator": {
            "schema_version": "2.0",
            "row_count_per_arm": 240,
            "case_count": 30,
            "lane_count": 2,
            "replicates_per_lane": 4,
            "contract": module._contract(),
            "gates": {
                "quality_safety": True,
                "quality_efficacy": True,
                "unconditional_time_to_valid": True,
                "conditional_latency_diagnostic": "passed",
                "promotion_passed": True,
            },
            "conditional_latency": {
                "status": "passed",
                "lanes": {"cold": "passed", "warm-prefix": "passed"},
            },
            "pooled": _summary(),
            "lanes": {
                "cold": _summary(direct_valid=84, proxy_valid=108),
                "warm-prefix": _summary(direct_valid=76, proxy_valid=112),
            },
            "mcnemar": {
                "direct_only_success_count": 4,
                "proxy_only_success_count": 64,
                "discordant_pair_count": 68,
                "supports_proxy_benefit": True,
            },
        },
    }


def _operational_evidence(
    *,
    manifest_sha256: str = _sha("a"),
    outcome_sha256: str | None = None,
    head_event_sha256: str = _sha("b"),
) -> dict[str, object]:
    return {
        "schema_version": "operational_matrix_v1",
        "manifest_sha256": manifest_sha256,
        "qualification_campaign": {
            "manifest_sha256": manifest_sha256,
            "outcome_sha256": outcome_sha256 or _sha("0"),
            "head_event_sha256": head_event_sha256,
        },
        "candidate_image": "registry.example/proxy@sha256:" + "c" * 64,
        "rollback_image": "registry.example/proxy@sha256:" + "d" * 64,
        "gates": {"candidate_ready": True, "privacy": True, "rollback": True},
        "passed": True,
    }


def _final_report(outcome: dict[str, object], operational: dict[str, object]) -> dict[str, object]:
    outcome_bytes = json.dumps(outcome, sort_keys=True).encode()
    operational_bytes = json.dumps(operational, sort_keys=True).encode()
    return {
        "schema_version": "shiftedx-final-qualification-report-v1",
        "record_type": "final_qualification_report",
        "review_status": "reviewed",
        "final_decision": "PROMOTE",
        "scored_outcome_sha256": hashlib.sha256(outcome_bytes).hexdigest(),
        "campaign_manifest_sha256": _sha("a"),
        "operational_evidence_sha256": hashlib.sha256(operational_bytes).hexdigest(),
        "operational_gates": operational["gates"],
        "decode": {
            "cold": {
                "direct_weighted_tokens_per_second_milli": 100_000,
                "proxy_weighted_tokens_per_second_milli": 95_000,
                "proxy_to_direct_ratio_ppm": 950_000,
                "gate_passed": True,
            },
            "warm-prefix": {
                "direct_weighted_tokens_per_second_milli": 100_000,
                "proxy_weighted_tokens_per_second_milli": 91_000,
                "proxy_to_direct_ratio_ppm": 910_000,
                "gate_passed": True,
            },
        },
        "amplification": {
            "mean_upstream_calls_per_downstream_ppm": 1_000_000,
            "max_upstream_calls_per_request": 1,
            "configured_ceiling": 7,
            "gate_passed": True,
        },
        "reconciliation": {
            "scored_artifacts_bound": True,
            "operational_accounting_reconciled": True,
            "gate_passed": True,
        },
    }


def _export(module, outcome: dict[str, object], report: dict[str, object], operational: dict[str, object]):
    outcome_bytes = json.dumps(outcome, sort_keys=True).encode()
    report_bytes = json.dumps(report, sort_keys=True).encode()
    operational_bytes = json.dumps(operational, sort_keys=True).encode()
    return module.public_qualification_result(outcome_bytes, report_bytes, operational_bytes)


def _bound_operational(outcome: dict[str, object]) -> dict[str, object]:
    outcome_sha256 = hashlib.sha256(json.dumps(outcome, sort_keys=True).encode()).hexdigest()
    return _operational_evidence(outcome_sha256=outcome_sha256)


def test_allowlist_only_export_excludes_private_sentinels_and_paths() -> None:
    module = _module()
    private_path = "/private/host/path"
    sentinel = "sentinel-secret-must-not-publish"  # noqa: S105 - privacy regression sentinel
    source = _outcome()
    source["private_payload"] = {"prompt": sentinel, "path": private_path}
    source["evaluator"]["raw_responses"] = [sentinel]  # type: ignore[index]
    operational = _bound_operational(source)
    report = _final_report(source, operational)

    result = _export(module, source, report, operational)

    exported = json.dumps(result, sort_keys=True)
    assert sentinel not in exported
    assert private_path not in exported
    assert "private_payload" not in exported
    assert "raw_responses" not in exported
    assert result["provenance"]["source_outcome_sha256"] == hashlib.sha256(
        json.dumps(source, sort_keys=True).encode()
    ).hexdigest()
    assert set(result["qualification"]["pooled"]) == set(module._SUMMARY_KEYS)
    assert result["qualification"]["pooled"]["direct_penalized_p99_wall_us"] == 600_000_000
    assert result["qualification"]["pooled"]["proxy_penalized_p99_wall_us"] == 600_000_000
    assert result["qualification"]["final_decision"] == "PROMOTE"
    assert result["operational"]["decode"]["cold"]["proxy_to_direct_ratio_ppm"] == 950_000


def test_exporter_fails_closed_for_missing_or_inconsistent_required_fields() -> None:
    module = _module()
    source = _outcome()
    del source["evaluator"]["pooled"]["proxy_valid_count"]  # type: ignore[index]
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, _final_report(source, _bound_operational(source)), _bound_operational(source))

    source = _outcome()
    source["scored_decision"] = "scored_failed"
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, _final_report(source, _bound_operational(source)), _bound_operational(source))


def test_exporter_rejects_scored_only_or_incomplete_or_wrong_hash_final_evidence() -> None:
    module = _module()
    source = _outcome()
    operational = _bound_operational(source)
    report = _final_report(source, operational)
    outcome_bytes = json.dumps(source, sort_keys=True).encode()

    with pytest.raises(TypeError):
        module.public_qualification_result(outcome_bytes)  # type: ignore[call-arg]

    del report["decode"]
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, report, operational)

    report = _final_report(source, operational)
    report["operational_evidence_sha256"] = _sha("f")
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, report, operational)

    report = _final_report(source, operational)
    operational["manifest_sha256"] = _sha("e")
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, report, operational)

    operational = _bound_operational(source)
    report = _final_report(source, operational)
    operational["qualification_campaign"]["outcome_sha256"] = _sha("e")
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, report, operational)

    operational = _bound_operational(source)
    report = _final_report(source, operational)
    operational["qualification_campaign"]["head_event_sha256"] = _sha("e")
    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        _export(module, source, report, operational)


def test_exporter_rejects_private_generated_artifact_content() -> None:
    module = _module()

    with pytest.raises(module.PublicQualificationExportError, match="public_qualification_outcome_invalid"):
        module._assert_public_safe_json(
            b'{"provenance":{"endpoint":"https://private.invalid","path":"/private/evidence"}}'
        )


def test_script_writes_absolute_no_clobber_public_json(tmp_path: Path) -> None:
    module = _module()
    outcome = tmp_path / "outcome.json"
    source = _outcome()
    operational = _bound_operational(source)
    final_report = _final_report(source, operational)
    outcome.write_text(json.dumps(source, sort_keys=True), encoding="utf-8")
    report_path = tmp_path / "final-report.json"
    report_path.write_text(json.dumps(final_report, sort_keys=True), encoding="utf-8")
    operational_path = tmp_path / "operational.json"
    operational_path.write_text(json.dumps(operational, sort_keys=True), encoding="utf-8")
    output = tmp_path / "public.json"

    assert (
        module.main(
            [
                "--outcome",
                str(outcome),
                "--final-report",
                str(report_path),
                "--operational-evidence",
                str(operational_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.stat().st_mode & 0o777 == 0o644
    published = json.loads(output.read_text(encoding="utf-8"))
    assert published["qualification"]["scored_decision"] == "scored_passed"
    with pytest.raises(SystemExit, match="public_qualification_export_failed"):
        module.main(
            [
                "--outcome",
                str(outcome),
                "--final-report",
                str(report_path),
                "--operational-evidence",
                str(operational_path),
                "--output",
                str(output),
            ]
        )
