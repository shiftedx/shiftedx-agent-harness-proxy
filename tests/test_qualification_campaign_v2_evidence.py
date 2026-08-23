from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from shiftedx_harness_proxy.qualification_campaign_v2_evidence import (
    QualificationV2EvidenceFailure,
    V2EvidenceSpec,
    V2ScoredLedger,
    adapt_v2_scored_evidence,
)
from shiftedx_harness_proxy.qualification_contract import ModelBoundaryRecord
from shiftedx_harness_proxy.qualification_reconciliation import (
    MetricsSnapshot,
    ModelOperationSummary,
    ProxyReconciliationSession,
    ReconciliationContext,
    ReconciliationIdentity,
    RequestAccountingRecord,
)

_ZERO_METRICS = MetricsSnapshot(*([0] * 15))


class _MetricsReader:
    def __init__(self, *snapshots: MetricsSnapshot) -> None:
        self._snapshots = list(snapshots)

    def snapshot(self) -> MetricsSnapshot:
        return self._snapshots.pop(0)


def _sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def _private_json(path: Path, value: object) -> bytes:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    return payload


def _case_ids() -> list[str]:
    return [f"case-{ordinal:02d}" for ordinal in range(1, 31)]


def _spec() -> V2EvidenceSpec:
    case_ids = _case_ids()
    cohort = tuple(case_ids[:22])
    critical = (1, 2)
    return V2EvidenceSpec(
        manifest_sha256="a" * 64,
        campaign_id_sha256="b" * 64,
        scenario_order_sha256=_sha256(case_ids),
        cohort_case_ids=cohort,
        cohort_case_ids_sha256=_sha256(cohort),
        critical_cohort_ordinals=critical,
        critical_cohort_ordinals_sha256=_sha256(critical),
        cache_lane="cold",
        replicate=1,
        slot_ordinal=1,
        pair_index=1,
        deadline_s=Decimal("600"),
        expected_direct_outcome_sha256="0" * 64,
    )


def _rows(*, direct: bool, forbidden_case: int | None = None) -> list[dict[str, object]]:
    return [
        {
            "case_id": case_id,
            "passed": not (direct and ordinal == 1),
            "telemetry": {"wall_s": 10, "tool_calls": ["delete_file"] if ordinal == forbidden_case else []},
            "metadata": {"forbidden_calls": ["delete_file"] if ordinal <= 2 else []},
        }
        for ordinal, case_id in enumerate(_case_ids(), start=1)
    ]


def _write_model_evidence(path: Path, spec: V2EvidenceSpec, stage: str) -> Path:
    _private_json(
        path,
        {
            "schema_version": "1.0",
            "record_type": "qualification_model_cache_evidence",
            "stage": stage,
            "status": "passed",
            "failure_category": None,
            "run_manifest_sha256": spec.manifest_sha256,
            "model_identity_sha256": "f" * 64,
            "model_contract_sha256": "1" * 64,
            "runtime_instance_sha256": "2" * 64,
            "live_before_sha256": "3" * 64,
            "live_after_sha256": "4" * 64,
            "request_window": {"before": 0, "after": 0, "delta": 0, "expected": 0, "successful_measured": 0},
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
    )
    return path


def _proxy_reconciliation(path: Path, spec: V2EvidenceSpec, attestation: Path, evidence: Path) -> Path:
    attestation_sha256 = hashlib.sha256(attestation.read_bytes()).hexdigest()
    evidence_sha256 = hashlib.sha256(evidence.read_bytes()).hexdigest()
    identity = ReconciliationIdentity(
        spec.manifest_sha256, spec.campaign_id_sha256, spec.slot_ordinal, "cold", spec.pair_index, attestation_sha256
    )
    context = ReconciliationContext(
        spec.manifest_sha256, spec.campaign_id_sha256, spec.slot_ordinal, "cold", spec.pair_index,
        attestation_sha256, evidence_sha256, "5" * 64, "6" * 64, "7" * 64,
    )
    after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    session = ProxyReconciliationSession.begin(
        identity, _MetricsReader(_ZERO_METRICS, after), campaign_version="v2"
    )
    observer = ModelBoundaryRecord(1, "8" * 64, {"compatibility": {"phase": "acquisition"}}, 200, None)
    request = RequestAccountingRecord(1, "succeeded", False, 1, 1, 1, 1, {"acquisition": 1, "finalization": 0}, 0, 0, 0)
    assert session.complete(context, [observer], [request], ModelOperationSummary(1, 0), path).status == "passed"
    return path


def _source(
    tmp_path: Path,
    spec: V2EvidenceSpec,
    arm: str,
    rows: list[dict[str, object]],
    predecessor_outcome_sha256: str | None = None,
) -> V2ScoredLedger:
    ledger_path = tmp_path / f"{arm}.jsonl"
    ledger = b"".join(json.dumps(row, separators=(",", ":"), sort_keys=True).encode() + b"\n" for row in rows)
    ledger_path.write_bytes(ledger)
    os.chmod(ledger_path, 0o600)
    attestation = tmp_path / f"{arm}-attestation.json"
    _private_json(attestation, {"model_identity_sha256": "f" * 64})
    stage = "score-direct" if arm == "direct" else "score-proxy"
    evidence = _write_model_evidence(tmp_path / f"{arm}-evidence.json", spec, stage)
    reconciliation = (
        _proxy_reconciliation(tmp_path / "proxy-reconciliation.json", spec, attestation, evidence)
        if arm == "proxy"
        else None
    )
    outcome = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_outcome",
        "stage": "scored-direct" if arm == "direct" else "scored-proxy",
        "status": "passed",
        "action_exit_code": 0,
        "failure_category": None,
        "run_manifest_sha256": spec.manifest_sha256,
        "attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "model_evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "output_ledger_sha256": hashlib.sha256(ledger).hexdigest(),
        "output_record_count": 30,
        "proxy_reconciliation_sha256": (
            None if reconciliation is None else hashlib.sha256(reconciliation.read_bytes()).hexdigest()
        ),
        "campaign_id_sha256": spec.campaign_id_sha256,
        "slot_ordinal": spec.slot_ordinal,
        "cache_lane": spec.cache_lane,
        "pair_index": spec.pair_index,
    }
    outcome_path = tmp_path / f"{arm}-outcome.json"
    serialized = _private_json(outcome_path, outcome)
    return V2ScoredLedger(
        arm, ledger_path, outcome_path, hashlib.sha256(serialized).hexdigest(), attestation, evidence, "f" * 64,
        reconciliation, predecessor_outcome_sha256,
    )


def _sources(
    tmp_path: Path, *, proxy_forbidden_case: int | None = None
) -> tuple[V2EvidenceSpec, tuple[V2ScoredLedger, V2ScoredLedger]]:
    spec = _spec()
    direct = _source(tmp_path, spec, "direct", _rows(direct=True))
    spec = replace(spec, expected_direct_outcome_sha256=direct.runtime_outcome_sha256)
    proxy = _source(
        tmp_path,
        spec,
        "proxy",
        _rows(direct=False, forbidden_case=proxy_forbidden_case),
        direct.runtime_outcome_sha256,
    )
    return spec, (direct, proxy)


def test_authenticated_evidence_retains_direct_failure_without_ids(tmp_path: Path) -> None:
    spec, sources = _sources(tmp_path)

    records = adapt_v2_scored_evidence(spec, sources)

    assert len(records) == 44
    assert records[0].arm == "direct"
    assert records[0].case_ordinal == 1
    assert records[0].passed is False
    assert records[0].deadline_s == Decimal("600")
    assert all("case_id" not in record.__dict__ for record in records)


@pytest.mark.parametrize("broken", ("order", "digest", "duplicate", "missing"))
def test_rejects_bad_order_digest_duplicate_or_missing_rows(tmp_path: Path, broken: str) -> None:
    spec, sources = _sources(tmp_path)
    direct, proxy = sources
    if broken == "digest":
        direct = replace(direct, runtime_outcome_sha256="f" * 64)
    else:
        rows = _rows(direct=True)
        if broken == "order":
            rows[0], rows[1] = rows[1], rows[0]
        elif broken == "duplicate":
            rows[-1] = rows[0]
        else:
            rows.pop()
        direct.ledger_path.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
        os.chmod(direct.ledger_path, 0o600)

    with pytest.raises(QualificationV2EvidenceFailure):
        adapt_v2_scored_evidence(spec, (direct, proxy))


def test_passing_forbidden_critical_case_flags_integrity_independently(tmp_path: Path) -> None:
    spec, sources = _sources(tmp_path, proxy_forbidden_case=1)

    records = adapt_v2_scored_evidence(spec, sources)

    proxy_first = next(record for record in records if record.arm == "proxy" and record.case_ordinal == 1)
    assert proxy_first.passed is True
    assert proxy_first.critical_integrity_violation is True


def test_failing_nonforbidden_case_does_not_flag_integrity(tmp_path: Path) -> None:
    spec, sources = _sources(tmp_path)

    records = adapt_v2_scored_evidence(spec, sources)

    direct_first = next(record for record in records if record.arm == "direct" and record.case_ordinal == 1)
    assert direct_first.passed is False
    assert direct_first.critical_integrity_violation is False


def test_rejects_proxy_predecessor_not_bound_to_authenticated_direct_outcome(tmp_path: Path) -> None:
    spec, (direct, proxy) = _sources(tmp_path)

    with pytest.raises(QualificationV2EvidenceFailure):
        adapt_v2_scored_evidence(spec, (direct, replace(proxy, predecessor_outcome_sha256="0" * 64)))


@pytest.mark.parametrize("artifact", ("attestation", "model_evidence"))
def test_rejects_tampered_referenced_artifact(tmp_path: Path, artifact: str) -> None:
    spec, (direct, proxy) = _sources(tmp_path)
    target = direct.attestation_path if artifact == "attestation" else direct.model_evidence_path
    _private_json(target, {"tampered": True})

    with pytest.raises(QualificationV2EvidenceFailure):
        adapt_v2_scored_evidence(spec, (direct, proxy))
