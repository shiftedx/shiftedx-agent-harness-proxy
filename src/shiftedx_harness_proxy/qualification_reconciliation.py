"""Privacy-safe reconciliation of one supervised proxy qualification window.

The public module is intentionally narrow: callers provide immutable hash-only
context, a metrics snapshot reader, safe observer records, and safe per-request
accounting.  The session emits one no-clobber reconciliation artifact and never
accepts or retains prompts, responses, credentials, endpoints, or paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

from .qualification_contract import ModelBoundaryRecord

CacheLane = Literal["cold", "warm-prefix"]
RequestOutcome = Literal["succeeded", "failed", "cancelled", "deadline"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FAILURE_CATEGORY = re.compile(r"^[a-z0-9_]+$")
_METRIC_KEYS = (
    "downstream_requests",
    "upstream_calls",
    "blocked_duplicates",
    "blocked_stalls",
    "correction_turns",
    "receipt_projections",
    "local_projection_upstream_calls_avoided",
    "errors",
    "deadline_expiries",
    "cancellations",
    "phase_acquisition",
    "phase_finalization",
    "phase_schema_rejections",
    "admission_rejections",
    "rate_rejections",
)
_DERIVED_KEYS = (
    "request_count",
    "attempt_count",
    "successful_attempt_count",
    "failed_attempt_count",
    "acquisition_count",
    "finalization_count",
    "successful_corrections",
    "total_retry_attempts",
    "local_projection_count",
    "failed_request_count",
    "cancelled_request_count",
    "deadline_request_count",
    "prime_count",
    "model_completed_delta",
)
_CHECK_KEYS = (
    "identity",
    "zero_before",
    "request_sequences",
    "attempt_partition",
    "phase_counts",
    "downstream",
    "upstream",
    "corrections",
    "projections",
    "errors",
    "model_operations",
)
_REQUEST_RECORD_KEYS = frozenset(
    {
        "sequence",
        "outcome",
        "local_projection",
        "attempt_sequence_start",
        "attempt_sequence_end",
        "attempt_count",
        "successful_attempt_count",
        "phase_counts",
        "retry_attempt_count",
        "blocked_duplicate_count",
        "blocked_stall_count",
    }
)
_MAX_PRIVATE_LEDGER_BYTES = 1024 * 1024
_MAX_REQUEST_RECORDS = 10000


class ReconciliationFailure(RuntimeError):
    """Stable categorical failure which cannot contain private input."""

    def __init__(self, category: str) -> None:
        safe = category if _FAILURE_CATEGORY.fullmatch(category) is not None else "reconciliation_internal"
        super().__init__(safe)
        self.category = safe


@dataclass(frozen=True)
class ReconciliationIdentity:
    """Identity available before the proxy treatment starts.

    The three evidence-ledger hashes deliberately do not belong here: they
    cannot exist until the child has run.  ``ProxyReconciliationSession``
    snapshots zero metrics against this immutable identity, then requires the
    matching complete context before it observes post-action metrics.
    """

    run_manifest_sha256: str
    campaign_id_sha256: str
    slot_ordinal: int
    cache_lane: CacheLane
    pair_index: int
    attestation_sha256: str


@dataclass(frozen=True)
class ReconciliationContext:
    """Immutable complete hash-only identity of one campaign slot."""

    run_manifest_sha256: str
    campaign_id_sha256: str
    slot_ordinal: int
    cache_lane: CacheLane
    pair_index: int
    attestation_sha256: str
    model_evidence_sha256: str
    observer_ledger_sha256: str
    request_ledger_sha256: str


@dataclass(frozen=True)
class MetricsSnapshot:
    """Exact aggregate proxy counters accepted by reconciliation v1."""

    downstream_requests: int
    upstream_calls: int
    blocked_duplicates: int
    blocked_stalls: int
    correction_turns: int
    receipt_projections: int
    local_projection_upstream_calls_avoided: int
    errors: int
    deadline_expiries: int
    cancellations: int
    phase_acquisition: int
    phase_finalization: int
    phase_schema_rejections: int
    admission_rejections: int
    rate_rejections: int

    def to_dict(self) -> dict[str, int]:
        return cast(dict[str, int], asdict(self))


class MetricsReader(Protocol):
    """Hardened adapter seam for one exact allowlisted metrics snapshot."""

    def snapshot(self) -> MetricsSnapshot: ...


@dataclass(frozen=True)
class RequestAccountingRecord:
    """Safe per-downstream-request accounting with no request or response data."""

    sequence: int
    outcome: RequestOutcome
    local_projection: bool
    attempt_sequence_start: int | None
    attempt_sequence_end: int | None
    attempt_count: int
    successful_attempt_count: int
    phase_counts: Mapping[str, int]
    retry_attempt_count: int
    blocked_duplicate_count: int
    blocked_stall_count: int


@dataclass(frozen=True)
class ModelOperationSummary:
    """Safe MTPLX operation delta for the same reconciliation window."""

    requests_completed_delta: int
    prime_count: int


@dataclass(frozen=True)
class ReconciliationResult:
    """Hash-only identity of one retained reconciliation artifact."""

    path: Path
    file_sha256: str
    status: Literal["passed", "failed"]


@dataclass(frozen=True)
class PassedProxyReconciliation:
    """Validated immutable passed reconciliation artifact identity."""

    path: Path
    file_sha256: str
    context: ReconciliationContext


def read_request_accounting_ledger(path: Path) -> tuple[RequestAccountingRecord, ...]:
    """Read one immutable runner request ledger without admitting payload-bearing rows."""

    try:
        serialized = _read_private_regular_file(path)
        if not serialized:
            return ()
        if not serialized.endswith(b"\n"):
            raise ValueError
        lines = serialized.splitlines()
        if len(lines) > _MAX_REQUEST_RECORDS or any(not line for line in lines):
            raise ValueError
        records: list[RequestAccountingRecord] = []
        for line in lines:
            value = json.loads(line, object_pairs_hook=_unique_object)
            if not isinstance(value, dict) or set(value) != _REQUEST_RECORD_KEYS:
                raise ValueError
            record = RequestAccountingRecord(
                sequence=value["sequence"],
                outcome=value["outcome"],
                local_projection=value["local_projection"],
                attempt_sequence_start=value["attempt_sequence_start"],
                attempt_sequence_end=value["attempt_sequence_end"],
                attempt_count=value["attempt_count"],
                successful_attempt_count=value["successful_attempt_count"],
                phase_counts=value["phase_counts"],
                retry_attempt_count=value["retry_attempt_count"],
                blocked_duplicate_count=value["blocked_duplicate_count"],
                blocked_stall_count=value["blocked_stall_count"],
            )
            if not _valid_request_scalars(record):
                raise ValueError
            records.append(record)
        if not _request_sequences_match(records):
            raise ValueError
        return tuple(records)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ReconciliationFailure("reconciliation_request_ledger_invalid") from None


def write_request_accounting_ledger(
    path: Path, records: Sequence[RequestAccountingRecord]
) -> None:
    """Atomically retain the runner's exact payload-free request accounting ledger.

    This is deliberately the sole serialization seam for these records.  The
    paired runner and runtime both use the same typed validation and private
    no-clobber writer as the reconciliation reader, so a writer/reader schema
    cannot drift into admitting a request body or another high-cardinality
    field.
    """

    values = tuple(records)
    if (
        len(values) > _MAX_REQUEST_RECORDS
        or not _request_sequences_match(values)
        or not all(_valid_request_scalars(value) for value in values)
    ):
        raise ReconciliationFailure("reconciliation_request_ledger_invalid")
    payload = b"".join(
        (
            _canonical(
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
                }
            ).encode("utf-8")
            + b"\n"
        )
        for record in values
    )
    if len(payload) > _MAX_PRIVATE_LEDGER_BYTES:
        raise ReconciliationFailure("reconciliation_request_ledger_invalid")
    _atomic_write_private_payload(
        path,
        payload,
        exists_category="reconciliation_request_ledger_exists",
        parent_category="reconciliation_request_ledger_parent_invalid",
        write_category="reconciliation_request_ledger_write_failed",
    )


def load_passed_proxy_reconciliation(
    path: Path, *, context: ReconciliationContext | None = None
) -> PassedProxyReconciliation:
    """Load exactly one passed reconciliation artifact bound to its full final context."""

    try:
        if context is not None:
            _validate_context(context)
        serialized = _read_private_regular_file(path)
        document = json.loads(serialized, object_pairs_hook=_unique_object)
    except (ReconciliationFailure, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ReconciliationFailure("reconciliation_artifact_invalid") from None
    actual_context = _artifact_context(document)
    if actual_context is None or not _valid_passed_artifact(document, actual_context):
        raise ReconciliationFailure("reconciliation_artifact_invalid")
    if context is not None and actual_context != context:
        raise ReconciliationFailure("reconciliation_artifact_invalid")
    return PassedProxyReconciliation(path, hashlib.sha256(serialized).hexdigest(), actual_context)


class ProxyReconciliationSession:
    """One begin/complete reconciliation transaction for a dedicated proxy."""

    def __init__(
        self, identity: ReconciliationIdentity, metrics_reader: MetricsReader, before: MetricsSnapshot
    ) -> None:
        self._identity = identity
        self._metrics_reader = metrics_reader
        self._before = before
        self._completed = False

    @classmethod
    def begin(
        cls, identity: ReconciliationIdentity, metrics_reader: MetricsReader
    ) -> ProxyReconciliationSession:
        """Validate immutable identity and require a fresh zero-counter proxy."""

        _validate_identity(identity)
        before = _snapshot(metrics_reader)
        if any(before.to_dict().values()):
            raise ReconciliationFailure("reconciliation_metrics_not_zero")
        return cls(identity, metrics_reader, before)

    def complete(
        self,
        context: ReconciliationContext,
        observer_records: Sequence[ModelBoundaryRecord],
        request_records: Sequence[RequestAccountingRecord],
        model_summary: ModelOperationSummary,
        artifact_path: Path,
    ) -> ReconciliationResult:
        """Reconcile the window exactly once and retain an immutable artifact."""

        if self._completed:
            raise ReconciliationFailure("reconciliation_complete_once")
        self._completed = True
        _validate_context(context)
        if not _context_matches_identity(context, self._identity):
            raise ReconciliationFailure("reconciliation_context_invalid")
        before_values = self._before.to_dict()
        try:
            after = _snapshot(self._metrics_reader)
        except ReconciliationFailure as error:
            derived = _derive_or_empty(observer_records, request_records, model_summary)
            record = _artifact_record(
                context,
                status="failed",
                failure_category=error.category,
                before=self._before,
                after=None,
                deltas={key: 0 for key in _METRIC_KEYS},
                derived=derived,
                checks={key: key in {"identity", "zero_before"} for key in _CHECK_KEYS},
            )
            _write_artifact(artifact_path, record)
            raise ReconciliationFailure(error.category) from None
        after_values = after.to_dict()
        deltas = {key: after_values[key] - before_values[key] for key in _METRIC_KEYS}
        if any(value < 0 for value in deltas.values()):
            record = _artifact_record(
                context,
                status="failed",
                failure_category="reconciliation_metrics_decreased",
                before=self._before,
                after=after,
                deltas=deltas,
                derived=_derive_or_empty(observer_records, request_records, model_summary),
                checks={key: key in {"identity", "zero_before"} for key in _CHECK_KEYS},
            )
            _write_artifact(artifact_path, record)
            raise ReconciliationFailure("reconciliation_metrics_decreased")
        input_failure = _input_failure_category(observer_records, request_records, model_summary)
        if input_failure is not None:
            record = _artifact_record(
                context,
                status="failed",
                failure_category=input_failure,
                before=self._before,
                after=after,
                deltas=deltas,
                derived={key: 0 for key in _DERIVED_KEYS},
                checks={key: key in {"identity", "zero_before"} for key in _CHECK_KEYS},
            )
            _write_artifact(artifact_path, record)
            raise ReconciliationFailure(input_failure)
        derived = _derive(observer_records, request_records, model_summary)
        checks = _checks(context, deltas, derived, observer_records, request_records)
        failure_category: str | None
        if not _model_operation_total_available(observer_records):
            checks["model_operations"] = False
            failure_category = "model_operation_total_unavailable"
        else:
            failure_category = _failed_check_category(checks)
        record = _artifact_record(
            context,
            status="passed" if failure_category is None else "failed",
            failure_category=failure_category,
            before=self._before,
            after=after,
            deltas=deltas,
            derived=derived,
            checks=checks,
        )
        serialized = _write_artifact(artifact_path, record)
        if failure_category is not None:
            raise ReconciliationFailure(failure_category)
        return ReconciliationResult(artifact_path, hashlib.sha256(serialized).hexdigest(), "passed")


def _validate_identity(identity: ReconciliationIdentity) -> None:
    if (
        type(identity) is not ReconciliationIdentity
        or any(
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
            for value in (
                identity.run_manifest_sha256,
                identity.campaign_id_sha256,
                identity.attestation_sha256,
            )
        )
        or not _positive_int(identity.slot_ordinal)
        or identity.slot_ordinal > 6
        or identity.cache_lane not in {"cold", "warm-prefix"}
        or not _positive_int(identity.pair_index)
        or identity.pair_index > 3
    ):
        raise ReconciliationFailure("reconciliation_context_invalid")


def _validate_context(context: ReconciliationContext) -> None:
    if type(context) is not ReconciliationContext:
        raise ReconciliationFailure("reconciliation_context_invalid")
    _validate_identity(
        ReconciliationIdentity(
            run_manifest_sha256=context.run_manifest_sha256,
            campaign_id_sha256=context.campaign_id_sha256,
            slot_ordinal=context.slot_ordinal,
            cache_lane=context.cache_lane,
            pair_index=context.pair_index,
            attestation_sha256=context.attestation_sha256,
        )
    )
    if any(
        not isinstance(value, str) or _SHA256.fullmatch(value) is None
        for value in (
            context.model_evidence_sha256,
            context.observer_ledger_sha256,
            context.request_ledger_sha256,
        )
    ):
        raise ReconciliationFailure("reconciliation_context_invalid")


def _context_matches_identity(context: ReconciliationContext, identity: ReconciliationIdentity) -> bool:
    return (
        context.run_manifest_sha256 == identity.run_manifest_sha256
        and context.campaign_id_sha256 == identity.campaign_id_sha256
        and context.slot_ordinal == identity.slot_ordinal
        and context.cache_lane == identity.cache_lane
        and context.pair_index == identity.pair_index
        and context.attestation_sha256 == identity.attestation_sha256
    )


def _valid_passed_artifact(value: object, context: ReconciliationContext) -> bool:
    if not isinstance(value, dict) or set(value) != {
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
    }:
        return False
    if (
        value.get("schema_version") != "1.0"
        or value.get("record_type") != "qualification_proxy_reconciliation"
        or value.get("status") != "passed"
        or value.get("failure_category") is not None
        or value.get("run_manifest_sha256") != context.run_manifest_sha256
        or value.get("campaign_id_sha256") != context.campaign_id_sha256
        or value.get("slot_ordinal") != context.slot_ordinal
        or value.get("cache_lane") != context.cache_lane
        or value.get("pair_index") != context.pair_index
        or value.get("attestation_sha256") != context.attestation_sha256
        or value.get("model_evidence_sha256") != context.model_evidence_sha256
        or value.get("observer_ledger_sha256") != context.observer_ledger_sha256
        or value.get("request_ledger_sha256") != context.request_ledger_sha256
        or not _sha256(value.get("before_metrics_sha256"))
        or not _sha256(value.get("after_metrics_sha256"))
    ):
        return False
    deltas = value.get("deltas")
    derived = value.get("derived")
    checks = value.get("checks")
    return (
        isinstance(deltas, dict)
        and set(deltas) == set(_METRIC_KEYS)
        and all(_nonnegative_int(item) for item in deltas.values())
        and isinstance(derived, dict)
        and set(derived) == set(_DERIVED_KEYS)
        and all(_nonnegative_int(item) for item in derived.values())
        and isinstance(checks, dict)
        and set(checks) == set(_CHECK_KEYS)
        and all(item is True for item in checks.values())
    )


def _artifact_context(value: object) -> ReconciliationContext | None:
    if not isinstance(value, dict):
        return None
    try:
        context = ReconciliationContext(
            run_manifest_sha256=value["run_manifest_sha256"],
            campaign_id_sha256=value["campaign_id_sha256"],
            slot_ordinal=value["slot_ordinal"],
            cache_lane=value["cache_lane"],
            pair_index=value["pair_index"],
            attestation_sha256=value["attestation_sha256"],
            model_evidence_sha256=value["model_evidence_sha256"],
            observer_ledger_sha256=value["observer_ledger_sha256"],
            request_ledger_sha256=value["request_ledger_sha256"],
        )
        _validate_context(context)
    except (KeyError, ReconciliationFailure, TypeError):
        return None
    return context


def _read_private_regular_file(path: Path) -> bytes:
    """Read one bounded mode-0600 file through a stable nofollow descriptor."""

    descriptor: int | None = None
    try:
        if not path.is_absolute():
            raise OSError
        listed = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(listed.st_mode) or stat.S_IMODE(listed.st_mode) != 0o600:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (listed.st_dev, listed.st_ino)
            or opened.st_size < 0
            or opened.st_size > _MAX_PRIVATE_LEDGER_BYTES
        ):
            raise OSError
        chunks: list[bytes] = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) != opened.st_size:
            raise OSError
        return value
    except OSError:
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _snapshot(reader: MetricsReader) -> MetricsSnapshot:
    try:
        value = reader.snapshot()
        if type(value) is not MetricsSnapshot or set(value.to_dict()) != set(_METRIC_KEYS):
            raise ReconciliationFailure("reconciliation_metrics_invalid")
        if any(not _nonnegative_int(item) for item in value.to_dict().values()):
            raise ReconciliationFailure("reconciliation_metrics_invalid")
        return value
    except ReconciliationFailure:
        raise
    except Exception:
        raise ReconciliationFailure("reconciliation_metrics_unavailable") from None


def _derive(
    observer_records: Sequence[ModelBoundaryRecord],
    request_records: Sequence[RequestAccountingRecord],
    model_summary: ModelOperationSummary,
) -> dict[str, int]:
    if type(model_summary) is not ModelOperationSummary:
        raise ReconciliationFailure("reconciliation_model_summary_invalid")
    observers = tuple(observer_records)
    requests = tuple(request_records)
    phases = [cast(Mapping[str, object], item.fields).get("compatibility") for item in observers]
    acquisition = sum(
        1 for value in phases if isinstance(value, Mapping) and value.get("phase") == "acquisition"
    )
    finalization = sum(
        1 for value in phases if isinstance(value, Mapping) and value.get("phase") == "finalization"
    )
    succeeded_attempts = sum(
        1 for item in observers if isinstance(item.status_code, int) and 200 <= item.status_code < 300
    )
    derived = {
        "request_count": len(requests),
        "attempt_count": len(observers),
        "successful_attempt_count": succeeded_attempts,
        "failed_attempt_count": len(observers) - succeeded_attempts,
        "acquisition_count": acquisition,
        "finalization_count": finalization,
        "successful_corrections": sum(
            item.retry_attempt_count for item in requests if item.outcome == "succeeded"
        ),
        "total_retry_attempts": sum(item.retry_attempt_count for item in requests),
        "local_projection_count": sum(item.local_projection for item in requests),
        "failed_request_count": sum(item.outcome == "failed" for item in requests),
        "cancelled_request_count": sum(item.outcome == "cancelled" for item in requests),
        "deadline_request_count": sum(item.outcome == "deadline" for item in requests),
        "prime_count": model_summary.prime_count,
        "model_completed_delta": model_summary.requests_completed_delta,
    }
    if set(derived) != set(_DERIVED_KEYS):
        raise ReconciliationFailure("reconciliation_internal")
    return derived


def _input_failure_category(
    observer_records: Sequence[ModelBoundaryRecord],
    request_records: Sequence[RequestAccountingRecord],
    model_summary: ModelOperationSummary,
) -> str | None:
    if type(model_summary) is not ModelOperationSummary or (
        not _nonnegative_int(model_summary.requests_completed_delta)
        or not _nonnegative_int(model_summary.prime_count)
        or model_summary.prime_count not in {0, 1}
    ):
        return "reconciliation_model_summary_invalid"
    if any(not _valid_observer(record, expected) for expected, record in enumerate(observer_records, start=1)):
        return "reconciliation_observer_record_invalid"
    if any(not _valid_request_scalars(record) for record in request_records):
        return "reconciliation_request_record_invalid"
    return None


def _derive_or_empty(
    observer_records: Sequence[ModelBoundaryRecord],
    request_records: Sequence[RequestAccountingRecord],
    model_summary: ModelOperationSummary,
) -> dict[str, int]:
    try:
        return _derive(observer_records, request_records, model_summary)
    except Exception:
        return {key: 0 for key in _DERIVED_KEYS}


def _checks(
    context: ReconciliationContext,
    deltas: Mapping[str, int],
    derived: Mapping[str, int],
    observer_records: Sequence[ModelBoundaryRecord],
    request_records: Sequence[RequestAccountingRecord],
) -> dict[str, bool]:
    return {
        "identity": True,
        "zero_before": True,
        "request_sequences": _request_sequences_match(request_records),
        "attempt_partition": _attempt_partition_matches(observer_records, request_records),
        "phase_counts": _phase_counts_match(observer_records, request_records)
        and deltas["phase_acquisition"] == derived["acquisition_count"]
        and deltas["phase_finalization"] == derived["finalization_count"],
        "downstream": deltas["downstream_requests"] == derived["request_count"],
        "upstream": deltas["upstream_calls"] == derived["attempt_count"],
        "corrections": deltas["correction_turns"] == derived["successful_corrections"]
        and deltas["blocked_duplicates"]
        == sum(record.blocked_duplicate_count for record in request_records if record.outcome == "succeeded")
        and deltas["blocked_stalls"]
        == sum(record.blocked_stall_count for record in request_records if record.outcome == "succeeded"),
        "projections": deltas["receipt_projections"]
        == deltas["local_projection_upstream_calls_avoided"]
        == derived["local_projection_count"],
        "errors": deltas["errors"]
        == derived["failed_request_count"]
        + derived["cancelled_request_count"]
        + derived["deadline_request_count"]
        and deltas["cancellations"] == derived["cancelled_request_count"]
        and deltas["deadline_expiries"] == derived["deadline_request_count"]
        and deltas["phase_schema_rejections"] == 0
        and deltas["admission_rejections"] == 0
        and deltas["rate_rejections"] == 0,
        "model_operations": derived["prime_count"] == (1 if context.cache_lane == "warm-prefix" else 0)
        and derived["model_completed_delta"]
        == derived["prime_count"] + derived["successful_attempt_count"],
    }


def _request_sequences_match(request_records: Sequence[RequestAccountingRecord]) -> bool:
    return all(
        type(record) is RequestAccountingRecord
        and _positive_int(record.sequence)
        and record.sequence == expected
        for expected, record in enumerate(request_records, start=1)
    )


def _attempt_partition_matches(
    observer_records: Sequence[ModelBoundaryRecord], request_records: Sequence[RequestAccountingRecord]
) -> bool:
    observers = tuple(observer_records)
    if not all(_valid_observer(observer, expected) for expected, observer in enumerate(observers, start=1)):
        return False
    next_attempt = 1
    for record in request_records:
        if not _valid_request_scalars(record):
            return False
        if record.local_projection:
            if (
                record.outcome != "succeeded"
                or record.attempt_sequence_start is not None
                or record.attempt_sequence_end is not None
                or record.attempt_count != 0
                or record.successful_attempt_count != 0
                or record.retry_attempt_count != 0
                or any(record.phase_counts.values())
            ):
                return False
            continue
        if (
            record.attempt_sequence_start != next_attempt
            or not _positive_int(record.attempt_sequence_end)
            or cast(int, record.attempt_sequence_end) < next_attempt
        ):
            return False
        end = cast(int, record.attempt_sequence_end)
        selected = observers[next_attempt - 1 : end]
        if len(selected) != end - next_attempt + 1 or record.attempt_count != len(selected):
            return False
        successful = sum(
            isinstance(observer.status_code, int) and 200 <= observer.status_code < 300 for observer in selected
        )
        if record.successful_attempt_count != successful:
            return False
        next_attempt = end + 1
    return next_attempt == len(observers) + 1


def _valid_observer(record: ModelBoundaryRecord, expected_sequence: int) -> bool:
    if (
        type(record) is not ModelBoundaryRecord
        or record.sequence != expected_sequence
        or isinstance(record.sequence, bool)
        or not isinstance(record.digest, str)
        or _SHA256.fullmatch(record.digest) is None
        or not isinstance(record.fields, dict)
        or not (
            record.status_code is None
            or isinstance(record.status_code, int)
            and not isinstance(record.status_code, bool)
            and 100 <= record.status_code <= 599
        )
    ):
        return False
    compatibility = record.fields.get("compatibility")
    return isinstance(compatibility, Mapping) and compatibility.get("phase") in {"acquisition", "finalization"}


def _valid_request_scalars(record: object) -> bool:
    if type(record) is not RequestAccountingRecord:
        return False
    try:
        invalid = (
            record.outcome not in {"succeeded", "failed", "cancelled", "deadline"}
            or not isinstance(record.local_projection, bool)
            or set(record.phase_counts) != {"acquisition", "finalization"}
            or not _positive_int(record.sequence)
            or (record.attempt_sequence_start is None) != (record.attempt_sequence_end is None)
            or record.attempt_sequence_start is not None
            and not _positive_int(record.attempt_sequence_start)
            or record.attempt_sequence_end is not None
            and not _positive_int(record.attempt_sequence_end)
        )
        phase_values = tuple(record.phase_counts.values())
    except (AttributeError, TypeError):
        return False
    if invalid:
        return False
    counts = (
        record.attempt_count,
        record.successful_attempt_count,
        record.retry_attempt_count,
        record.blocked_duplicate_count,
        record.blocked_stall_count,
        *phase_values,
    )
    return all(_nonnegative_int(value) for value in counts) and record.successful_attempt_count <= record.attempt_count


def _phase_counts_match(
    observer_records: Sequence[ModelBoundaryRecord], request_records: Sequence[RequestAccountingRecord]
) -> bool:
    observers = tuple(observer_records)
    for record in request_records:
        if type(record) is not RequestAccountingRecord or set(record.phase_counts) != {
            "acquisition",
            "finalization",
        }:
            return False
        if record.local_projection:
            selected: tuple[ModelBoundaryRecord, ...] = ()
        elif (
            not _positive_int(record.attempt_sequence_start)
            or not _positive_int(record.attempt_sequence_end)
            or cast(int, record.attempt_sequence_end) < cast(int, record.attempt_sequence_start)
        ):
            return False
        else:
            selected = observers[
                cast(int, record.attempt_sequence_start) - 1 : cast(int, record.attempt_sequence_end)
            ]
        counts = {"acquisition": 0, "finalization": 0}
        for observer in selected:
            compatibility = observer.fields.get("compatibility")
            phase = compatibility.get("phase") if isinstance(compatibility, Mapping) else None
            if phase not in counts:
                return False
            if phase == "acquisition":
                counts["acquisition"] += 1
            else:
                counts["finalization"] += 1
        if dict(record.phase_counts) != counts:
            return False
        distinct_phases = sum(value > 0 for value in counts.values())
        if record.retry_attempt_count != record.attempt_count - distinct_phases:
            return False
    return True


def _failed_check_category(checks: Mapping[str, bool]) -> str | None:
    categories = {
        "identity": "reconciliation_identity_mismatch",
        "zero_before": "reconciliation_metrics_not_zero",
        "request_sequences": "reconciliation_request_sequences_mismatch",
        "attempt_partition": "reconciliation_attempt_partition_mismatch",
        "phase_counts": "reconciliation_phase_counts_mismatch",
        "downstream": "reconciliation_downstream_mismatch",
        "upstream": "reconciliation_upstream_mismatch",
        "corrections": "reconciliation_corrections_mismatch",
        "projections": "reconciliation_projections_mismatch",
        "errors": "reconciliation_errors_mismatch",
        "model_operations": "reconciliation_model_operations_mismatch",
    }
    return next((categories[key] for key in _CHECK_KEYS if not checks[key]), None)


def _model_operation_total_available(observer_records: Sequence[ModelBoundaryRecord]) -> bool:
    return all(
        isinstance(record.status_code, int)
        and not isinstance(record.status_code, bool)
        and 200 <= record.status_code < 300
        for record in observer_records
    )


def _artifact_record(
    context: ReconciliationContext,
    *,
    status: Literal["passed", "failed"],
    failure_category: str | None,
    before: MetricsSnapshot,
    after: MetricsSnapshot | None,
    deltas: Mapping[str, int],
    derived: Mapping[str, int],
    checks: Mapping[str, bool],
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "record_type": "qualification_proxy_reconciliation",
        "status": status,
        "failure_category": failure_category,
        "run_manifest_sha256": context.run_manifest_sha256,
        "campaign_id_sha256": context.campaign_id_sha256,
        "slot_ordinal": context.slot_ordinal,
        "cache_lane": context.cache_lane,
        "pair_index": context.pair_index,
        "attestation_sha256": context.attestation_sha256,
        "model_evidence_sha256": context.model_evidence_sha256,
        "observer_ledger_sha256": context.observer_ledger_sha256,
        "request_ledger_sha256": context.request_ledger_sha256,
        "before_metrics_sha256": _canonical_sha256(before.to_dict()),
        "after_metrics_sha256": _canonical_sha256(after.to_dict()) if after is not None else None,
        "deltas": {key: deltas[key] for key in _METRIC_KEYS},
        "derived": {key: derived[key] for key in _DERIVED_KEYS},
        "checks": {key: checks[key] for key in _CHECK_KEYS},
    }


def _write_artifact(path: Path, record: Mapping[str, object]) -> bytes:
    payload = (_canonical(record) + "\n").encode("utf-8")
    return _atomic_write_private_payload(
        path,
        payload,
        exists_category="reconciliation_artifact_exists",
        parent_category="reconciliation_artifact_parent_invalid",
        write_category="reconciliation_artifact_write_failed",
    )


def _atomic_write_private_payload(
    path: Path,
    payload: bytes,
    *,
    exists_category: str,
    parent_category: str,
    write_category: str,
) -> bytes:
    """Create exactly one descriptor-bound mode-0600 private file.

    A hard-link commit preserves immutable/no-clobber semantics on the opened
    parent directory.  The descriptor and inode comparisons close rename and
    symlink races without trusting a pathname after it has been checked.
    """

    if len(payload) > _MAX_PRIVATE_LEDGER_BYTES:
        raise ReconciliationFailure(write_category)
    directory: int | None = None
    temporary: int | None = None
    target: int | None = None
    temporary_name: str | None = None
    try:
        parent_status = path.parent.lstat()
        if (
            not path.is_absolute()
            or path.parent.is_symlink()
            or not stat.S_ISDIR(parent_status.st_mode)
            or stat.S_IMODE(parent_status.st_mode) != 0o700
        ):
            raise ReconciliationFailure(parent_category)
        directory = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        opened_parent = os.fstat(directory)
        if (opened_parent.st_dev, opened_parent.st_ino) != (parent_status.st_dev, parent_status.st_ino):
            raise ReconciliationFailure(parent_category)
        for nonce in range(128):
            candidate = f".{path.name}.{os.getpid()}.{nonce}"
            try:
                temporary = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory,
                )
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if temporary is None or temporary_name is None:
            raise ReconciliationFailure(write_category)
        os.fchmod(temporary, 0o600)
        _write_all(temporary, payload)
        os.fsync(temporary)
        source_status = os.fstat(temporary)
        os.link(temporary_name, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        target = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        target_status = os.fstat(target)
        if (
            not stat.S_ISREG(target_status.st_mode)
            or stat.S_IMODE(target_status.st_mode) != 0o600
            or (target_status.st_dev, target_status.st_ino) != (source_status.st_dev, source_status.st_ino)
            or _read_all(target) != payload
        ):
            raise ReconciliationFailure(write_category)
        os.unlink(temporary_name, dir_fd=directory)
        temporary_name = None
        os.fsync(directory)
        return payload
    except FileExistsError:
        raise ReconciliationFailure(exists_category) from None
    except ReconciliationFailure:
        raise
    except OSError:
        raise ReconciliationFailure(write_category) from None
    finally:
        if target is not None:
            os.close(target)
        if temporary is not None:
            os.close(temporary)
        if directory is not None:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=directory)
            os.close(directory)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        offset += os.write(descriptor, payload[offset:])


def _read_all(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 65536):
        chunks.append(chunk)
    return b"".join(chunks)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive_int(value: object) -> bool:
    return _nonnegative_int(value) and cast(int, value) > 0
