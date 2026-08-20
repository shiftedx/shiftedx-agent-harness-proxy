"""Deterministic proxy/model accounting reconciliation for qualification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from shiftedx_harness_proxy.qualification_contract import ModelBoundaryRecord
from shiftedx_harness_proxy.qualification_reconciliation import (
    MetricsSnapshot,
    ModelOperationSummary,
    ProxyReconciliationSession,
    ReconciliationContext,
    ReconciliationFailure,
    ReconciliationIdentity,
    RequestAccountingRecord,
    load_passed_proxy_reconciliation,
    read_request_accounting_ledger,
    write_request_accounting_ledger,
)

_ZERO_METRICS = MetricsSnapshot(
    downstream_requests=0,
    upstream_calls=0,
    blocked_duplicates=0,
    blocked_stalls=0,
    correction_turns=0,
    receipt_projections=0,
    local_projection_upstream_calls_avoided=0,
    errors=0,
    deadline_expiries=0,
    cancellations=0,
    phase_acquisition=0,
    phase_finalization=0,
    phase_schema_rejections=0,
    admission_rejections=0,
    rate_rejections=0,
)


class FakeMetricsReader:
    def __init__(self, *snapshots: MetricsSnapshot) -> None:
        self._snapshots = list(snapshots)

    def snapshot(self) -> MetricsSnapshot:
        return self._snapshots.pop(0)


class FailingAfterMetricsReader:
    def snapshot(self) -> MetricsSnapshot:
        if not hasattr(self, "_begun"):
            self._begun = True
            return _ZERO_METRICS
        raise RuntimeError("private endpoint and credential marker")


def _context(**changes: object) -> ReconciliationContext:
    value = ReconciliationContext(
        run_manifest_sha256="1" * 64,
        campaign_id_sha256="2" * 64,
        slot_ordinal=1,
        cache_lane="cold",
        pair_index=1,
        attestation_sha256="3" * 64,
        model_evidence_sha256="4" * 64,
        observer_ledger_sha256="5" * 64,
        request_ledger_sha256="6" * 64,
    )
    return replace(value, **changes)


def _identity(**changes: object) -> ReconciliationIdentity:
    value = ReconciliationIdentity(
        run_manifest_sha256="1" * 64,
        campaign_id_sha256="2" * 64,
        slot_ordinal=1,
        cache_lane="cold",
        pair_index=1,
        attestation_sha256="3" * 64,
    )
    return replace(value, **changes)


def _observer(sequence: int, phase: str = "acquisition", status_code: int | None = 200) -> ModelBoundaryRecord:
    return ModelBoundaryRecord(
        sequence=sequence,
        digest=str(sequence) * 64,
        fields={"compatibility": {"phase": phase}},
        status_code=status_code,
        cache=None,
    )


def _request(
    sequence: int,
    *,
    start: int | None,
    end: int | None,
    attempts: int,
    successful: int,
    acquisition: int,
    finalization: int = 0,
    retries: int = 0,
    outcome: str = "succeeded",
    local_projection: bool = False,
    blocked_duplicates: int = 0,
    blocked_stalls: int = 0,
) -> RequestAccountingRecord:
    return RequestAccountingRecord(
        sequence=sequence,
        outcome=outcome,
        local_projection=local_projection,
        attempt_sequence_start=start,
        attempt_sequence_end=end,
        attempt_count=attempts,
        successful_attempt_count=successful,
        phase_counts={"acquisition": acquisition, "finalization": finalization},
        retry_attempt_count=retries,
        blocked_duplicate_count=blocked_duplicates,
        blocked_stall_count=blocked_stalls,
    )


def _write_request_ledger(path: Path, records: list[RequestAccountingRecord]) -> None:
    path.write_text(
        "".join(
            json.dumps(
                {
                    "sequence": record.sequence,
                    "outcome": record.outcome,
                    "local_projection": record.local_projection,
                    "attempt_sequence_start": record.attempt_sequence_start,
                    "attempt_sequence_end": record.attempt_sequence_end,
                    "attempt_count": record.attempt_count,
                    "successful_attempt_count": record.successful_attempt_count,
                    "phase_counts": dict(record.phase_counts),
                    "retry_attempt_count": record.retry_attempt_count,
                    "blocked_duplicate_count": record.blocked_duplicate_count,
                    "blocked_stall_count": record.blocked_stall_count,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_request_ledger_reader_returns_only_contiguous_typed_safe_records(tmp_path: Path) -> None:
    path = tmp_path / "proxy-requests.jsonl"
    expected = [
        _request(1, start=1, end=1, attempts=1, successful=1, acquisition=1),
        _request(
            2,
            start=None,
            end=None,
            attempts=0,
            successful=0,
            acquisition=0,
            local_projection=True,
        ),
    ]
    _write_request_ledger(path, expected)

    assert read_request_accounting_ledger(path) == tuple(expected)


def test_request_ledger_writer_commits_exact_private_jsonl_once(tmp_path: Path) -> None:
    path = tmp_path / "proxy-requests.jsonl"
    records = [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)]

    write_request_accounting_ledger(path, records)

    assert path.stat().st_mode & 0o777 == 0o600
    assert read_request_accounting_ledger(path) == tuple(records)
    prior = path.read_bytes()
    with pytest.raises(ReconciliationFailure, match="^reconciliation_request_ledger_exists$"):
        write_request_accounting_ledger(path, records)
    assert path.read_bytes() == prior


@pytest.mark.parametrize("mutation", ["symlink", "duplicate", "sequence", "raw"])
def test_request_ledger_reader_rejects_untrusted_or_payload_bearing_rows(tmp_path: Path, mutation: str) -> None:
    path = tmp_path / "proxy-requests.jsonl"
    _write_request_ledger(path, [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)])
    if mutation == "symlink":
        target = tmp_path / "target.jsonl"
        path.replace(target)
        path.symlink_to(target)
    elif mutation == "duplicate":
        path.write_text('{"sequence":1,"sequence":2}\n', encoding="utf-8")
        path.chmod(0o600)
    elif mutation == "sequence":
        row = json.loads(path.read_text(encoding="utf-8"))
        row["sequence"] = 2
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        path.chmod(0o600)
    else:
        row = json.loads(path.read_text(encoding="utf-8"))
        row["private_prompt"] = "must-not-survive"
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        path.chmod(0o600)

    with pytest.raises(ReconciliationFailure, match="^reconciliation_request_ledger_invalid$") as raised:
        read_request_accounting_ledger(path)

    assert "must-not-survive" not in str(raised.value)


def test_begin_snapshots_zero_metrics_before_action_and_complete_binds_post_action_evidence(
    tmp_path: Path,
) -> None:
    after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    result = session.complete(
        _context(),
        [_observer(1)],
        [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)],
        ModelOperationSummary(requests_completed_delta=1, prime_count=0),
        artifact,
    )

    assert result.status == "passed"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["observer_ledger_sha256"] == "5" * 64
    assert document["request_ledger_sha256"] == "6" * 64
    loaded = load_passed_proxy_reconciliation(artifact, context=_context())
    assert loaded.file_sha256 == result.file_sha256


def test_decreased_post_action_metrics_retain_a_categorical_failed_artifact(tmp_path: Path) -> None:
    before = replace(_ZERO_METRICS, upstream_calls=2)
    after = replace(_ZERO_METRICS, upstream_calls=1)
    # A provider reset between the authenticated begin snapshot and completion
    # is represented as a lower aggregate counter at this boundary.
    session = ProxyReconciliationSession(_identity(), FakeMetricsReader(after), before)
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_metrics_decreased$"):
        session.complete(
            _context(),
            [],
            [],
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            artifact,
        )

    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["status"] == "failed"
    assert document["failure_category"] == "reconciliation_metrics_decreased"
    assert document["after_metrics_sha256"] is not None


def test_complete_rejects_post_action_evidence_context_that_drifts_from_pre_action_identity(
    tmp_path: Path,
) -> None:
    session = ProxyReconciliationSession.begin(
        _identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS)
    )

    with pytest.raises(ReconciliationFailure, match="^reconciliation_context_invalid$"):
        session.complete(
            _context(attestation_sha256="9" * 64),
            [],
            [],
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            tmp_path / "reconciliation.json",
        )


def test_cold_success_reconciles_one_request_operation_phase_and_model_completion(tmp_path: Path) -> None:
    after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    result = session.complete(
        _context(),
        [_observer(1)],
        [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)],
        ModelOperationSummary(requests_completed_delta=1, prime_count=0),
        artifact,
    )

    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert result.status == "passed"
    assert result.path == artifact
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert document == {
        "schema_version": "1.0",
        "record_type": "qualification_proxy_reconciliation",
        "status": "passed",
        "failure_category": None,
        "run_manifest_sha256": "1" * 64,
        "campaign_id_sha256": "2" * 64,
        "slot_ordinal": 1,
        "cache_lane": "cold",
        "pair_index": 1,
        "attestation_sha256": "3" * 64,
        "model_evidence_sha256": "4" * 64,
        "observer_ledger_sha256": "5" * 64,
        "request_ledger_sha256": "6" * 64,
        "before_metrics_sha256": "f6a36bd22ce6b8322810f9e122ae64591cc1e98d24c5a826ffe739c2caeedac4",
        "after_metrics_sha256": "935d1cba34b47336944892f26b1666ad813711aa417ac44fe3113b678751f6c8",
        "deltas": {
            "downstream_requests": 1,
            "upstream_calls": 1,
            "blocked_duplicates": 0,
            "blocked_stalls": 0,
            "correction_turns": 0,
            "receipt_projections": 0,
            "local_projection_upstream_calls_avoided": 0,
            "errors": 0,
            "deadline_expiries": 0,
            "cancellations": 0,
            "phase_acquisition": 1,
            "phase_finalization": 0,
            "phase_schema_rejections": 0,
            "admission_rejections": 0,
            "rate_rejections": 0,
        },
        "derived": {
            "request_count": 1,
            "attempt_count": 1,
            "successful_attempt_count": 1,
            "failed_attempt_count": 0,
            "acquisition_count": 1,
            "finalization_count": 0,
            "successful_corrections": 0,
            "total_retry_attempts": 0,
            "local_projection_count": 0,
            "failed_request_count": 0,
            "cancelled_request_count": 0,
            "deadline_request_count": 0,
            "prime_count": 0,
            "model_completed_delta": 1,
        },
        "checks": {
            "identity": True,
            "zero_before": True,
            "request_sequences": True,
            "attempt_partition": True,
            "phase_counts": True,
            "downstream": True,
            "upstream": True,
            "corrections": True,
            "projections": True,
            "errors": True,
            "model_operations": True,
        },
    }


def test_request_phase_mismatch_retains_only_categorical_failed_artifact(tmp_path: Path) -> None:
    after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_phase_counts_mismatch$"):
        session.complete(
            _context(),
            [_observer(1)],
            [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=0)],
            ModelOperationSummary(requests_completed_delta=1, prime_count=0),
            artifact,
        )

    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["status"] == "failed"
    assert document["failure_category"] == "reconciliation_phase_counts_mismatch"
    assert document["checks"]["phase_counts"] is False
    assert document["checks"]["request_sequences"] is True
    assert set(document) == {
        "schema_version",
        "record_type",
        "status",
        "failure_category",
        "run_manifest_sha256",
        "campaign_id_sha256",
        "slot_ordinal",
        "cache_lane",
        "pair_index",
        "attestation_sha256",
        "model_evidence_sha256",
        "observer_ledger_sha256",
        "request_ledger_sha256",
        "before_metrics_sha256",
        "after_metrics_sha256",
        "deltas",
        "derived",
        "checks",
    }


def test_request_sequences_must_be_contiguous_from_one(tmp_path: Path) -> None:
    after = replace(
        _ZERO_METRICS,
        downstream_requests=2,
        upstream_calls=1,
        phase_acquisition=1,
        receipt_projections=1,
        local_projection_upstream_calls_avoided=1,
    )
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_request_sequences_mismatch$"):
        session.complete(
            _context(),
            [_observer(1)],
            [
                _request(
                    1,
                    start=None,
                    end=None,
                    attempts=0,
                    successful=0,
                    acquisition=0,
                    local_projection=True,
                ),
                _request(3, start=1, end=1, attempts=1, successful=1, acquisition=1),
            ],
            ModelOperationSummary(requests_completed_delta=1, prime_count=0),
            artifact,
        )

    assert json.loads(artifact.read_text())["checks"]["request_sequences"] is False


def test_attempt_ranges_must_partition_every_observer_once_and_match_row_counts(tmp_path: Path) -> None:
    after = replace(_ZERO_METRICS, downstream_requests=2, upstream_calls=2, phase_acquisition=2)
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_attempt_partition_mismatch$"):
        session.complete(
            _context(),
            [_observer(1), _observer(2)],
            [
                _request(1, start=1, end=1, attempts=1, successful=1, acquisition=1),
                _request(2, start=1, end=1, attempts=1, successful=1, acquisition=1),
            ],
            ModelOperationSummary(requests_completed_delta=2, prime_count=0),
            artifact,
        )

    assert json.loads(artifact.read_text())["checks"]["attempt_partition"] is False


@pytest.mark.parametrize(
    ("cache_lane", "prime_count", "completed_delta"),
    [("cold", 1, 2), ("warm-prefix", 0, 1)],
)
def test_model_prime_count_must_match_the_frozen_cache_lane(
    tmp_path: Path, cache_lane: str, prime_count: int, completed_delta: int
) -> None:
    after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    session = ProxyReconciliationSession.begin(
        _identity(cache_lane=cache_lane), FakeMetricsReader(_ZERO_METRICS, after)
    )
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_model_operations_mismatch$"):
        session.complete(
            _context(cache_lane=cache_lane),
            [_observer(1)],
            [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)],
            ModelOperationSummary(requests_completed_delta=completed_delta, prime_count=prime_count),
            artifact,
        )

    assert json.loads(artifact.read_text())["checks"]["model_operations"] is False


def test_warm_prime_retry_and_local_projection_reconcile_without_counting_prime_as_proxy_upstream(
    tmp_path: Path,
) -> None:
    after = replace(
        _ZERO_METRICS,
        downstream_requests=2,
        upstream_calls=3,
        blocked_duplicates=2,
        blocked_stalls=1,
        correction_turns=1,
        receipt_projections=1,
        local_projection_upstream_calls_avoided=1,
        phase_acquisition=2,
        phase_finalization=1,
    )
    session = ProxyReconciliationSession.begin(
        _identity(slot_ordinal=4, cache_lane="warm-prefix"), FakeMetricsReader(_ZERO_METRICS, after)
    )
    artifact = tmp_path / "reconciliation.json"

    session.complete(
        _context(slot_ordinal=4, cache_lane="warm-prefix"),
        [_observer(1), _observer(2), _observer(3, "finalization")],
        [
            _request(
                1,
                start=1,
                end=3,
                attempts=3,
                successful=3,
                acquisition=2,
                finalization=1,
                retries=1,
                blocked_duplicates=2,
                blocked_stalls=1,
            ),
            _request(
                2,
                start=None,
                end=None,
                attempts=0,
                successful=0,
                acquisition=0,
                local_projection=True,
            ),
        ],
        ModelOperationSummary(requests_completed_delta=4, prime_count=1),
        artifact,
    )

    document = json.loads(artifact.read_text())
    assert document["status"] == "passed"
    assert document["deltas"]["upstream_calls"] == 3
    assert document["derived"] == {
        "request_count": 2,
        "attempt_count": 3,
        "successful_attempt_count": 3,
        "failed_attempt_count": 0,
        "acquisition_count": 2,
        "finalization_count": 1,
        "successful_corrections": 1,
        "total_retry_attempts": 1,
        "local_projection_count": 1,
        "failed_request_count": 0,
        "cancelled_request_count": 0,
        "deadline_request_count": 0,
        "prime_count": 1,
        "model_completed_delta": 4,
    }


@pytest.mark.parametrize(
    ("metric", "value", "check", "category"),
    [
        ("downstream_requests", 2, "downstream", "reconciliation_downstream_mismatch"),
        ("upstream_calls", 2, "upstream", "reconciliation_upstream_mismatch"),
        ("phase_acquisition", 0, "phase_counts", "reconciliation_phase_counts_mismatch"),
        ("phase_finalization", 1, "phase_counts", "reconciliation_phase_counts_mismatch"),
        ("correction_turns", 1, "corrections", "reconciliation_corrections_mismatch"),
        ("blocked_duplicates", 1, "corrections", "reconciliation_corrections_mismatch"),
        ("blocked_stalls", 1, "corrections", "reconciliation_corrections_mismatch"),
        ("receipt_projections", 1, "projections", "reconciliation_projections_mismatch"),
        (
            "local_projection_upstream_calls_avoided",
            1,
            "projections",
            "reconciliation_projections_mismatch",
        ),
        ("errors", 1, "errors", "reconciliation_errors_mismatch"),
        ("deadline_expiries", 1, "errors", "reconciliation_errors_mismatch"),
        ("cancellations", 1, "errors", "reconciliation_errors_mismatch"),
        ("phase_schema_rejections", 1, "errors", "reconciliation_errors_mismatch"),
        ("admission_rejections", 1, "errors", "reconciliation_errors_mismatch"),
        ("rate_rejections", 1, "errors", "reconciliation_errors_mismatch"),
    ],
)
def test_each_proxy_metric_delta_is_reconciled_to_safe_request_and_observer_evidence(
    tmp_path: Path, metric: str, value: int, check: str, category: str
) -> None:
    valid_after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    after = replace(valid_after, **{metric: value})
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match=f"^{category}$"):
        session.complete(
            _context(),
            [_observer(1)],
            [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)],
            ModelOperationSummary(requests_completed_delta=1, prime_count=0),
            artifact,
        )

    assert json.loads(artifact.read_text())["checks"][check] is False


@pytest.mark.parametrize("status_code", [None, 500])
def test_failed_or_unobserved_model_operation_retains_unavailable_total_category(
    tmp_path: Path, status_code: int | None
) -> None:
    after = replace(
        _ZERO_METRICS,
        downstream_requests=1,
        upstream_calls=1,
        errors=1,
        phase_acquisition=1,
    )
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^model_operation_total_unavailable$"):
        session.complete(
            _context(),
            [_observer(1, status_code=status_code)],
            [
                _request(
                    1,
                    start=1,
                    end=1,
                    attempts=1,
                    successful=0,
                    acquisition=1,
                    outcome="failed",
                )
            ],
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            artifact,
        )

    document = json.loads(artifact.read_text())
    assert document["failure_category"] == "model_operation_total_unavailable"
    assert document["checks"]["model_operations"] is False
    assert document["derived"]["failed_attempt_count"] == 1


def test_after_metrics_exception_retains_categorical_artifact_without_exception_text(tmp_path: Path) -> None:
    session = ProxyReconciliationSession.begin(_identity(), FailingAfterMetricsReader())
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_metrics_unavailable$") as raised:
        session.complete(
            _context(),
            [_observer(1)],
            [_request(1, start=1, end=1, attempts=1, successful=1, acquisition=1)],
            ModelOperationSummary(requests_completed_delta=1, prime_count=0),
            artifact,
        )

    serialized = artifact.read_text(encoding="utf-8")
    document = json.loads(serialized)
    assert str(raised.value) == "reconciliation_metrics_unavailable"
    assert document["status"] == "failed"
    assert document["failure_category"] == "reconciliation_metrics_unavailable"
    assert document["after_metrics_sha256"] is None
    assert "private endpoint" not in serialized
    assert "credential marker" not in serialized


@pytest.mark.parametrize(
    "changes",
    [
        {"run_manifest_sha256": "private-invalid-manifest"},
        {"campaign_id_sha256": "A" * 64},
        {"slot_ordinal": 0},
        {"slot_ordinal": 7},
        {"cache_lane": "ambient"},
        {"pair_index": 0},
        {"pair_index": 4},
    ],
)
def test_begin_rejects_invalid_identity_categorically_without_reading_metrics(changes: dict[str, object]) -> None:
    reader = FakeMetricsReader(_ZERO_METRICS)

    with pytest.raises(ReconciliationFailure, match="^reconciliation_context_invalid$") as raised:
        ProxyReconciliationSession.begin(_identity(**changes), reader)

    assert str(raised.value) == "reconciliation_context_invalid"
    assert len(reader._snapshots) == 1


def test_begin_requires_every_allowlisted_proxy_counter_to_be_zero() -> None:
    before = replace(_ZERO_METRICS, phase_schema_rejections=1)

    with pytest.raises(ReconciliationFailure, match="^reconciliation_metrics_not_zero$"):
        ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(before))


@pytest.mark.parametrize("value", [-1, True])
def test_metrics_snapshot_rejects_negative_and_boolean_counter_values(value: int) -> None:
    before = replace(_ZERO_METRICS, upstream_calls=value)

    with pytest.raises(ReconciliationFailure, match="^reconciliation_metrics_invalid$"):
        ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(before))


def test_retry_exhaustion_counts_attempts_but_not_success_only_correction_or_block_metrics(tmp_path: Path) -> None:
    after = replace(
        _ZERO_METRICS,
        downstream_requests=1,
        upstream_calls=3,
        errors=1,
        phase_acquisition=3,
    )
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    session.complete(
        _context(),
        [_observer(1), _observer(2), _observer(3)],
        [
            _request(
                1,
                start=1,
                end=3,
                attempts=3,
                successful=3,
                acquisition=3,
                retries=2,
                outcome="failed",
                blocked_duplicates=2,
                blocked_stalls=1,
            )
        ],
        ModelOperationSummary(requests_completed_delta=3, prime_count=0),
        artifact,
    )

    document = json.loads(artifact.read_text())
    assert document["status"] == "passed"
    assert document["derived"]["total_retry_attempts"] == 2
    assert document["derived"]["successful_corrections"] == 0
    assert document["deltas"]["blocked_duplicates"] == 0


def test_cancelled_and_deadline_requests_reconcile_exact_error_subcounters(tmp_path: Path) -> None:
    after = replace(
        _ZERO_METRICS,
        downstream_requests=2,
        upstream_calls=2,
        errors=2,
        deadline_expiries=1,
        cancellations=1,
        phase_acquisition=2,
    )
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    session.complete(
        _context(),
        [_observer(1), _observer(2)],
        [
            _request(
                1,
                start=1,
                end=1,
                attempts=1,
                successful=1,
                acquisition=1,
                outcome="cancelled",
            ),
            _request(
                2,
                start=2,
                end=2,
                attempts=1,
                successful=1,
                acquisition=1,
                outcome="deadline",
            ),
        ],
        ModelOperationSummary(requests_completed_delta=2, prime_count=0),
        artifact,
    )

    document = json.loads(artifact.read_text())
    assert document["checks"]["errors"] is True
    assert document["derived"]["cancelled_request_count"] == 1
    assert document["derived"]["deadline_request_count"] == 1


def test_untyped_request_record_is_rejected_without_retaining_raw_fields(tmp_path: Path) -> None:
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS))
    artifact = tmp_path / "reconciliation.json"
    raw_record = {"private_prompt": "must-never-survive"}

    with pytest.raises(ReconciliationFailure, match="^reconciliation_request_record_invalid$"):
        session.complete(
            _context(),
            [],
            cast(Any, [raw_record]),
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            artifact,
        )

    serialized = artifact.read_text(encoding="utf-8")
    assert json.loads(serialized)["failure_category"] == "reconciliation_request_record_invalid"
    assert "must-never-survive" not in serialized
    assert "private_prompt" not in serialized


@pytest.mark.parametrize("symlink", [False, True])
def test_artifact_is_no_clobber_and_never_follows_an_existing_symlink(tmp_path: Path, symlink: bool) -> None:
    target = tmp_path / "prior.json"
    target.write_text('{"private":"prior-evidence"}\n', encoding="utf-8")
    target.chmod(0o600)
    artifact = tmp_path / "reconciliation.json"
    if symlink:
        artifact.symlink_to(target)
    else:
        artifact.write_text('{"private":"prior-evidence"}\n', encoding="utf-8")
        artifact.chmod(0o600)
        target = artifact
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS))

    with pytest.raises(ReconciliationFailure, match="^reconciliation_artifact_exists$"):
        session.complete(_context(), [], [], ModelOperationSummary(requests_completed_delta=0, prime_count=0), artifact)

    assert target.read_text(encoding="utf-8") == '{"private":"prior-evidence"}\n'


def test_success_result_hashes_exact_immutable_artifact_bytes_and_session_completes_once(tmp_path: Path) -> None:
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS))
    artifact = tmp_path / "reconciliation.json"

    result = session.complete(
        _context(), [], [], ModelOperationSummary(requests_completed_delta=0, prime_count=0), artifact
    )

    assert result.file_sha256 == hashlib.sha256(artifact.read_bytes()).hexdigest()
    with pytest.raises(ReconciliationFailure, match="^reconciliation_complete_once$"):
        session.complete(
            _context(),
            [],
            [],
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            tmp_path / "second",
        )
    assert not (tmp_path / "second").exists()


def test_artifact_requires_an_existing_private_mode_0700_parent(tmp_path: Path) -> None:
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    public_parent.chmod(0o755)
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS))

    with pytest.raises(ReconciliationFailure, match="^reconciliation_artifact_parent_invalid$"):
        session.complete(
            _context(),
            [],
            [],
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            public_parent / "reconciliation.json",
        )

    assert not (public_parent / "reconciliation.json").exists()


@pytest.mark.parametrize(
    "summary",
    [
        ModelOperationSummary(requests_completed_delta=-1, prime_count=0),
        ModelOperationSummary(requests_completed_delta=cast(Any, True), prime_count=0),
        ModelOperationSummary(requests_completed_delta=0, prime_count=2),
    ],
)
def test_model_operation_summary_is_strict_nonnegative_and_prime_is_zero_or_one(
    tmp_path: Path, summary: ModelOperationSummary
) -> None:
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_model_summary_invalid$"):
        session.complete(_context(), [], [], summary, artifact)

    assert json.loads(artifact.read_text())["failure_category"] == "reconciliation_model_summary_invalid"


def test_untyped_observer_is_rejected_without_retaining_raw_fields(tmp_path: Path) -> None:
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, _ZERO_METRICS))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match="^reconciliation_observer_record_invalid$"):
        session.complete(
            _context(),
            cast(Any, [{"response": "private-model-output"}]),
            [],
            ModelOperationSummary(requests_completed_delta=0, prime_count=0),
            artifact,
        )

    assert "private-model-output" not in artifact.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("record", "category"),
    [
        (
            _request(
                1,
                start=1,
                end=1,
                attempts=1,
                successful=1,
                acquisition=1,
                local_projection=True,
            ),
            "reconciliation_attempt_partition_mismatch",
        ),
        (
            _request(1, start=1, end=1, attempts=1, successful=0, acquisition=1),
            "reconciliation_attempt_partition_mismatch",
        ),
        (
            _request(1, start=1, end=1, attempts=1, successful=1, acquisition=1, retries=1),
            "reconciliation_phase_counts_mismatch",
        ),
        (
            replace(
                _request(1, start=1, end=1, attempts=1, successful=1, acquisition=1),
                outcome=cast(Any, "private-outcome"),
            ),
            "reconciliation_request_record_invalid",
        ),
        (
            replace(
                _request(1, start=1, end=1, attempts=1, successful=1, acquisition=1),
                blocked_duplicate_count=-1,
            ),
            "reconciliation_request_record_invalid",
        ),
        (
            replace(
                _request(1, start=1, end=1, attempts=1, successful=1, acquisition=1),
                phase_counts={"acquisition": 1, "finalization": 0, "private": 9},
            ),
            "reconciliation_request_record_invalid",
        ),
    ],
)
def test_request_record_invariants_fail_closed_with_stable_categories(
    tmp_path: Path, record: RequestAccountingRecord, category: str
) -> None:
    after = replace(_ZERO_METRICS, downstream_requests=1, upstream_calls=1, phase_acquisition=1)
    session = ProxyReconciliationSession.begin(_identity(), FakeMetricsReader(_ZERO_METRICS, after))
    artifact = tmp_path / "reconciliation.json"

    with pytest.raises(ReconciliationFailure, match=f"^{category}$"):
        session.complete(
            _context(),
            [_observer(1)],
            [record],
            ModelOperationSummary(requests_completed_delta=1, prime_count=0),
            artifact,
        )

    assert json.loads(artifact.read_text())["failure_category"] == category
