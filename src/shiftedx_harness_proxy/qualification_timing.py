"""Private, exact qualification timing evidence.

The timing ledger is intentionally a *v2* private artifact. It uses integer
values from :func:`time.perf_counter_ns` and has two exact partitions:

``downstream_wall_ns = admission_wait_ns + body_read_ns + policy_exclusive_ns
+ sum(attempt.wall_ns) + response_finalize_ns + other_measured_ns``

and, for every upstream attempt:

``wall_ns = upstream_slot_wait_ns + transport.total_ns``

``transport.total_ns = pool_wait_ns + connect_ns + request_write_ns +
response_header_wait_ns + response_read_ns + other_ns``

Unavailable diagnostic phases are explicit ``null`` values with a categorical
source. They are never silently converted to zero: a measured ``other_ns``
partition owns the whole unattributable outer-monotonic interval. Timing rows
bind request-accounting rows and observer slices, never reconciliation rows,
so the evidence hash graph is acyclic.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import re
import stat
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

_MAX_BYTES = 1024 * 1024
_MAX_ROWS = 10_000
_OUTCOMES = frozenset({"succeeded", "failed", "cancelled", "deadline"})
_INTERVENTIONS = frozenset(
    {"pass_through", "phase_split", "correction", "blocked_call_recovery", "projection", "bounded_failure"}
)
_PHASES = frozenset({"acquisition", "finalization", "terminal"})
_CACHE_LANES = frozenset({"cold", "warm-prefix", "unavailable"})
_CACHE_RESULTS = frozenset({"hit", "miss", "unavailable"})
_ARMS = frozenset({"direct", "proxy"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCES = frozenset(
    {
        "outer_monotonic",
        "httpcore_1_0_9_trace",
        "httpx_0_28_1_pool_phase_unavailable",
        "httpx_0_28_1_reuse_unproven",
        "non_streaming_response",
        "model_boundary_unavailable",
        "paired_counterfactual",
        "not_observable",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "pair_ordinal",
        "arm",
        "request_accounting_row_sha256",
        "observer_slice_sha256",
        "outcome",
        "intervention_class",
        "cache_lane",
        "downstream_wall_ns",
        "admission_wait_ns",
        "body_read_ns",
        "policy_exclusive_ns",
        "response_finalize_ns",
        "other_measured_ns",
        "attempts",
        "local_projection",
        "avoided_immediate_upstream_calls",
        "correction_count",
        "blocked_duplicate_count",
        "blocked_stall_count",
        "retry_attempt_count",
        "phase_counts",
        "model_time_avoided_ns",
        "model_time_avoided_availability",
    }
)
_ATTEMPT_KEYS = frozenset(
    {
        "sequence",
        "request_sequence",
        "observer_digest",
        "phase",
        "status",
        "wall_ns",
        "upstream_slot_wait_ns",
        "transport",
        "ttft_ns",
        "ttft_availability",
        "model_time_ns",
        "model_time_availability",
        "decode_ns",
        "decode_availability",
        "cache_lane",
        "cache_result",
    }
)
_TRANSPORT_KEYS = frozenset(
    {
        "total_ns",
        "pool_wait_ns",
        "connect_ns",
        "request_write_ns",
        "response_header_wait_ns",
        "response_read_ns",
        "other_ns",
        "pool_wait_availability",
        "connect_availability",
        "request_write_availability",
        "response_header_wait_availability",
        "response_read_availability",
        "other_availability",
        "connection_reuse",
        "connection_reuse_availability",
    }
)
_CAPTURE_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "sequence",
        "outcome",
        "downstream_wall_ns",
        "admission_wait_ns",
        "body_read_ns",
        "policy_exclusive_ns",
        "response_finalize_ns",
        "other_measured_ns",
        "attempts",
        "local_projection",
        "avoided_immediate_upstream_calls",
        "correction_count",
        "blocked_duplicate_count",
        "blocked_stall_count",
        "retry_attempt_count",
        "phase_counts",
    }
)
_CAPTURE_ATTEMPT_KEYS = frozenset(_ATTEMPT_KEYS - {"request_sequence", "observer_digest", "cache_lane", "cache_result"})


class TimingFailure(RuntimeError):
    """Categorical failure that never includes private evidence values."""


def canonical_json(value: object) -> bytes:
    """Canonical bytes used by private evidence writers and linkage hashes."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def request_accounting_row_sha256(record: Mapping[str, object]) -> str:
    """Hash the exact existing canonical request-accounting row."""

    return canonical_sha256(dict(record))


def observer_slice_sha256(records: Sequence[Mapping[str, object]]) -> str:
    """Hash canonical observer rows in their exact downstream-request order."""

    return hashlib.sha256(b"".join(canonical_json(dict(row)) + b"\n" for row in records)).hexdigest()


def measured(source: str) -> dict[str, str]:
    return {"state": "measured", "source": source}


def unavailable(source: str) -> dict[str, str]:
    return {"state": "unavailable", "source": source}


def unavailable_transport(total_ns: int) -> dict[str, object]:
    """An exact outer interval with unproven HTTPX phase/reuse details."""

    _require_nonnegative(total_ns)
    return {
        "total_ns": total_ns,
        "pool_wait_ns": None,
        "connect_ns": None,
        "request_write_ns": None,
        "response_header_wait_ns": None,
        "response_read_ns": None,
        "other_ns": total_ns,
        "pool_wait_availability": unavailable("httpx_0_28_1_pool_phase_unavailable"),
        "connect_availability": unavailable("not_observable"),
        "request_write_availability": unavailable("not_observable"),
        "response_header_wait_availability": unavailable("not_observable"),
        "response_read_availability": unavailable("not_observable"),
        "other_availability": measured("outer_monotonic"),
        "connection_reuse": None,
        "connection_reuse_availability": unavailable("httpx_0_28_1_reuse_unproven"),
    }


@dataclass
class HttpxTraceDurations:
    """Safe httpcore 1.0.9 trace timing boundaries; trace payloads are discarded."""

    started: dict[str, int] = field(default_factory=dict)
    completed: dict[str, int] = field(default_factory=dict)

    async def callback(self, name: str, _info: dict[str, Any]) -> None:
        now = time.perf_counter_ns()
        base = name.rsplit(".", 1)[0]
        if name.endswith(".started"):
            self.started.setdefault(base, now)
        elif name.endswith((".complete", ".failed")):
            self.completed[base] = now

    def _duration(self, *names: str) -> int | None:
        for name in names:
            start = self.started.get(name)
            end = self.completed.get(name)
            if start is not None and end is not None and end >= start:
                return end - start
        return None

    def transport(self, total_ns: int) -> dict[str, object]:
        """Use only event families present in the pinned stack; no reuse inference."""

        _require_nonnegative(total_ns)
        connect = self._duration("connection.connect_tcp", "socks5.connect_tcp")
        header_write = self._duration("http11.send_request_headers", "http2.send_request_headers")
        body_write = self._duration("http11.send_request_body", "http2.send_request_body")
        request_write = None if header_write is None and body_write is None else (header_write or 0) + (body_write or 0)
        headers = self._duration("http11.receive_response_headers", "http2.receive_response_headers")
        read = self._duration("http11.receive_response_body", "http2.receive_response_body")
        known = sum(value for value in (connect, request_write, headers, read) if value is not None)
        # HTTP core executes these tracing spans sequentially. A custom client
        # that reports impossible overlaps is treated as categorically absent.
        if known > total_ns:
            return unavailable_transport(total_ns)
        return {
            "total_ns": total_ns,
            "pool_wait_ns": None,
            "connect_ns": connect,
            "request_write_ns": request_write,
            "response_header_wait_ns": headers,
            "response_read_ns": read,
            "other_ns": total_ns - known,
            "pool_wait_availability": unavailable("httpx_0_28_1_pool_phase_unavailable"),
            "connect_availability": measured("httpcore_1_0_9_trace")
            if connect is not None
            else unavailable("not_observable"),
            "request_write_availability": measured("httpcore_1_0_9_trace")
            if request_write is not None
            else unavailable("not_observable"),
            # Header receipt is not TTFT. TTFT stays unavailable for this
            # non-streaming compatibility contract.
            "response_header_wait_availability": measured("httpcore_1_0_9_trace")
            if headers is not None
            else unavailable("not_observable"),
            "response_read_availability": measured("httpcore_1_0_9_trace")
            if read is not None
            else unavailable("not_observable"),
            "other_availability": measured("outer_monotonic"),
            "connection_reuse": "fresh" if connect is not None else None,
            "connection_reuse_availability": measured("httpcore_1_0_9_trace")
            if connect is not None
            else unavailable("httpx_0_28_1_reuse_unproven"),
        }


@dataclass
class _CapturedAttempt:
    sequence: int
    phase: str
    upstream_slot_wait_ns: int
    started_ns: int
    status: str = "failed"
    transport: dict[str, object] | None = None

    def finalize(self) -> dict[str, object]:
        total = time.perf_counter_ns() - self.started_ns
        transport = self.transport or unavailable_transport(total)
        return {
            "sequence": self.sequence,
            "phase": self.phase,
            "status": self.status,
            "wall_ns": self.upstream_slot_wait_ns + int(transport["total_ns"]),
            "upstream_slot_wait_ns": self.upstream_slot_wait_ns,
            "transport": transport,
            "ttft_ns": None,
            "ttft_availability": unavailable("non_streaming_response"),
            "model_time_ns": None,
            "model_time_availability": unavailable("model_boundary_unavailable"),
            "decode_ns": None,
            "decode_availability": unavailable("model_boundary_unavailable"),
        }


@dataclass
class RequestTiming:
    """One request-local capture; it never persists request content or identity."""

    started_ns: int = field(default_factory=time.perf_counter_ns)
    admission_wait_ns: int = 0
    body_read_ns: int = 0
    service_wall_ns: int = 0
    response_finalize_ns: int = 0
    attempts: list[_CapturedAttempt] = field(default_factory=list)
    correction_count: int = 0
    blocked_duplicate_count: int = 0
    blocked_stall_count: int = 0
    retry_attempt_count: int = 0
    phase_counts: dict[str, int] = field(default_factory=lambda: {name: 0 for name in _PHASES})
    local_projection: bool = False
    avoided_immediate_upstream_calls: int = 0

    def record_admission_wait(self, duration_ns: int) -> None:
        self.admission_wait_ns += _require_nonnegative(duration_ns)

    def record_body_read(self, duration_ns: int) -> None:
        self.body_read_ns += _require_nonnegative(duration_ns)

    def record_service_wall(self, duration_ns: int) -> None:
        self.service_wall_ns += _require_nonnegative(duration_ns)

    def record_response_finalize(self, duration_ns: int) -> None:
        self.response_finalize_ns += _require_nonnegative(duration_ns)

    def record_interventions(
        self,
        *,
        correction_count: int,
        blocked_duplicate_count: int,
        blocked_stall_count: int,
        retry_attempt_count: int,
        local_projection: bool,
        avoided_immediate_upstream_calls: int,
    ) -> None:
        if not all(
            _nonnegative(value)
            for value in (
                correction_count,
                blocked_duplicate_count,
                blocked_stall_count,
                retry_attempt_count,
                avoided_immediate_upstream_calls,
            )
        ) or not isinstance(local_projection, bool):
            raise TimingFailure("qualification_timing_ledger_invalid")
        self.correction_count = correction_count
        self.blocked_duplicate_count = blocked_duplicate_count
        self.blocked_stall_count = blocked_stall_count
        self.retry_attempt_count = retry_attempt_count
        self.local_projection = local_projection
        self.avoided_immediate_upstream_calls = avoided_immediate_upstream_calls

    def begin_attempt(self, phase: str | None, upstream_slot_wait_ns: int) -> _CapturedAttempt:
        normalized = phase if phase in _PHASES else "terminal"
        attempt = _CapturedAttempt(
            sequence=len(self.attempts) + 1,
            phase=normalized,
            upstream_slot_wait_ns=_require_nonnegative(upstream_slot_wait_ns),
            started_ns=time.perf_counter_ns(),
        )
        self.attempts.append(attempt)
        self.phase_counts[normalized] += 1
        return attempt

    def capture(self, outcome: Literal["succeeded", "failed", "cancelled", "deadline"]) -> dict[str, object]:
        attempts = [attempt.finalize() for attempt in self.attempts]
        attempt_wall = sum(int(item["wall_ns"]) for item in attempts)
        policy_exclusive = self.service_wall_ns - attempt_wall
        if policy_exclusive < 0:
            raise TimingFailure("qualification_timing_unexplained_delta")
        wall = time.perf_counter_ns() - self.started_ns
        known = self.admission_wait_ns + self.body_read_ns + self.service_wall_ns + self.response_finalize_ns
        if known > wall:
            raise TimingFailure("qualification_timing_unexplained_delta")
        return {
            "schema_version": "2.0",
            "record_type": "qualification_timing_capture",
            "sequence": 0,
            "outcome": outcome,
            "downstream_wall_ns": wall,
            "admission_wait_ns": self.admission_wait_ns,
            "body_read_ns": self.body_read_ns,
            "policy_exclusive_ns": policy_exclusive,
            "response_finalize_ns": self.response_finalize_ns,
            "other_measured_ns": wall - known,
            "attempts": attempts,
            "local_projection": self.local_projection,
            "avoided_immediate_upstream_calls": self.avoided_immediate_upstream_calls,
            "correction_count": self.correction_count,
            "blocked_duplicate_count": self.blocked_duplicate_count,
            "blocked_stall_count": self.blocked_stall_count,
            "retry_attempt_count": self.retry_attempt_count,
            "phase_counts": dict(sorted(self.phase_counts.items())),
        }


_CURRENT_REQUEST: contextvars.ContextVar[RequestTiming | None] = contextvars.ContextVar(
    "shiftedx_qualification_timing_request", default=None
)
_CURRENT_ATTEMPT: contextvars.ContextVar[_CapturedAttempt | None] = contextvars.ContextVar(
    "shiftedx_qualification_timing_attempt", default=None
)


def begin_request_timing() -> tuple[RequestTiming, contextvars.Token[RequestTiming | None]]:
    value = RequestTiming()
    return value, _CURRENT_REQUEST.set(value)


def end_request_timing(token: contextvars.Token[RequestTiming | None]) -> None:
    _CURRENT_REQUEST.reset(token)


def current_request_timing() -> RequestTiming | None:
    return _CURRENT_REQUEST.get()


def begin_upstream_attempt(phase: str | None, upstream_slot_wait_ns: int) -> tuple[_CapturedAttempt | None, Any]:
    request = current_request_timing()
    if request is None:
        return None, None
    attempt = request.begin_attempt(phase, upstream_slot_wait_ns)
    return attempt, _CURRENT_ATTEMPT.set(attempt)


def end_upstream_attempt(token: Any, *, status: str) -> None:
    attempt = _CURRENT_ATTEMPT.get()
    if attempt is not None:
        attempt.status = status if status in _OUTCOMES else "failed"
    if token is not None:
        _CURRENT_ATTEMPT.reset(token)


def current_upstream_attempt() -> _CapturedAttempt | None:
    return _CURRENT_ATTEMPT.get()


def attach_httpx_trace() -> HttpxTraceDurations | None:
    return HttpxTraceDurations() if current_upstream_attempt() is not None else None


def set_httpx_transport(trace: HttpxTraceDurations | None, total_ns: int) -> None:
    attempt = current_upstream_attempt()
    request = current_request_timing()
    if attempt is not None and request is not None:
        attempt.transport = trace.transport(total_ns) if trace is not None else unavailable_transport(total_ns)


class PrivateTimingSink:
    """Append strict capture rows to one pre-reserved, private file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._next_sequence = len(read_timing_capture_ledger(path)) + 1

    def append(self, capture: Mapping[str, object]) -> None:
        row = dict(capture)
        with self._lock:
            row["sequence"] = self._next_sequence
            _validate_capture_row(row)
            _append_private(self.path, canonical_json(row) + b"\n")
            self._next_sequence += 1


def reserve_timing_capture_ledger(path: Path) -> None:
    _write_new_private(path, b"", exists_category="qualification_timing_ledger_exists")


def read_timing_capture_ledger(path: Path) -> tuple[dict[str, object], ...]:
    try:
        rows = [json.loads(line, object_pairs_hook=_unique_object) for line in _read_private(path).splitlines()]
        if len(rows) > _MAX_ROWS:
            raise ValueError
        for expected, row in enumerate(rows, 1):
            if not isinstance(row, dict) or row.get("sequence") != expected:
                raise ValueError
            _validate_capture_row(row)
        return tuple(rows)
    except (OSError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError, TimingFailure):
        raise TimingFailure("qualification_timing_ledger_invalid") from None


def write_timing_ledger(path: Path, rows: Iterable[dict[str, object]]) -> None:
    values = list(rows)
    _validate_rows(values)
    payload = b"".join(canonical_json(value) + b"\n" for value in values)
    if len(payload) > _MAX_BYTES:
        raise TimingFailure("qualification_timing_ledger_invalid")
    _write_new_private(path, payload, exists_category="qualification_timing_ledger_exists")


def read_timing_ledger(path: Path) -> tuple[dict[str, object], ...]:
    try:
        rows = [json.loads(line, object_pairs_hook=_unique_object) for line in _read_private(path).splitlines()]
        _validate_rows(rows)
        return tuple(rows)
    except (OSError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError, TimingFailure):
        raise TimingFailure("qualification_timing_ledger_invalid") from None


def bind_capture_row(
    capture: Mapping[str, object],
    *,
    sequence: int,
    pair_ordinal: int,
    arm: Literal["direct", "proxy"],
    request_accounting_row: Mapping[str, object],
    observer_rows: Sequence[Mapping[str, object]],
    cache_lane: str,
    intervention_class: str,
    model_time_avoided_ns: int | None = None,
    model_time_avoided_source: str = "not_observable",
) -> dict[str, object]:
    """Bind a raw capture to exact pre-existing row/slice evidence.

    ``observer_rows`` are ordered existing ledger rows. No reconciliation hash
    can be supplied here by design.
    """

    raw = dict(capture)
    _validate_capture_row(raw)
    attempts = raw["attempts"]
    if not isinstance(attempts, list) or len(attempts) != len(observer_rows):
        raise TimingFailure("qualification_timing_ledger_invalid")
    bound_attempts: list[dict[str, object]] = []
    for ordinal, (attempt, observer) in enumerate(zip(attempts, observer_rows, strict=True), 1):
        if not isinstance(attempt, Mapping) or not isinstance(observer, Mapping):
            raise TimingFailure("qualification_timing_ledger_invalid")
        digest = observer.get("digest")
        if not _sha256(digest) or attempt.get("sequence") != ordinal:
            raise TimingFailure("qualification_timing_ledger_invalid")
        phase = _observer_phase(observer.get("fields"))
        if attempt.get("phase") != phase:
            raise TimingFailure("qualification_timing_ledger_invalid")
        bound_attempts.append(
            {
                **dict(attempt),
                "request_sequence": sequence,
                "observer_digest": digest,
                "phase": phase,
                "status": _observer_status(observer.get("response")),
                "cache_lane": cache_lane,
                "cache_result": _observer_cache_result(observer.get("response")),
            }
        )
    row = {
        "schema_version": "2.0",
        "sequence": sequence,
        "pair_ordinal": pair_ordinal,
        "arm": arm,
        "request_accounting_row_sha256": request_accounting_row_sha256(request_accounting_row),
        "observer_slice_sha256": observer_slice_sha256(observer_rows),
        "outcome": raw["outcome"],
        "intervention_class": intervention_class,
        "cache_lane": cache_lane,
        "downstream_wall_ns": raw["downstream_wall_ns"],
        "admission_wait_ns": raw["admission_wait_ns"],
        "body_read_ns": raw["body_read_ns"],
        "policy_exclusive_ns": raw["policy_exclusive_ns"],
        "response_finalize_ns": raw["response_finalize_ns"],
        "other_measured_ns": raw["other_measured_ns"],
        "attempts": bound_attempts,
        "local_projection": raw["local_projection"],
        "avoided_immediate_upstream_calls": raw["avoided_immediate_upstream_calls"],
        "correction_count": raw["correction_count"],
        "blocked_duplicate_count": raw["blocked_duplicate_count"],
        "blocked_stall_count": raw["blocked_stall_count"],
        "retry_attempt_count": raw["retry_attempt_count"],
        "phase_counts": raw["phase_counts"],
        "model_time_avoided_ns": model_time_avoided_ns,
        "model_time_avoided_availability": measured("paired_counterfactual")
        if model_time_avoided_ns is not None
        else unavailable(model_time_avoided_source),
    }
    _validate_row(row)
    return row


def verify_timing_ledger_linkage(
    rows: Sequence[Mapping[str, object]],
    request_accounting_rows: Sequence[Mapping[str, object]],
    observer_rows: Sequence[Mapping[str, object]],
) -> None:
    """Prove every final timing row binds the exact accounting row and observer slice.

    This is deliberately a one-way proof: reconciliation consumes the timing
    ledger's file hash later, but timing rows never contain a reconciliation
    hash.  Callers supply the already-read, ordered private evidence rows.
    """

    values = [dict(row) for row in rows]
    _validate_rows(values)
    accounting = [dict(row) for row in request_accounting_rows]
    observers = [dict(row) for row in observer_rows]
    if len(values) != len(accounting):
        raise TimingFailure("qualification_timing_ledger_invalid")
    for expected, (row, request) in enumerate(zip(values, accounting, strict=True), 1):
        if (
            request.get("sequence") != expected
            or row["sequence"] != expected
            or row["request_accounting_row_sha256"] != request_accounting_row_sha256(request)
        ):
            raise TimingFailure("qualification_timing_ledger_invalid")
        start = request.get("attempt_sequence_start")
        end = request.get("attempt_sequence_end")
        count = request.get("attempt_count")
        local_projection = request.get("local_projection")
        if not _nonnegative(count) or not isinstance(local_projection, bool):
            raise TimingFailure("qualification_timing_ledger_invalid")
        if local_projection or count == 0:
            selected: list[dict[str, object]] = []
            if start is not None or end is not None:
                raise TimingFailure("qualification_timing_ledger_invalid")
        else:
            if not _positive(start) or not _positive(end) or int(end) < int(start):
                raise TimingFailure("qualification_timing_ledger_invalid")
            selected = observers[int(start) - 1 : int(end)]
            if len(selected) != int(count):
                raise TimingFailure("qualification_timing_ledger_invalid")
        attempts = row["attempts"]
        if (
            not isinstance(attempts, list)
            or len(attempts) != len(selected)
            or row["observer_slice_sha256"] != observer_slice_sha256(selected)
        ):
            raise TimingFailure("qualification_timing_ledger_invalid")
        for attempt, observer in zip(attempts, selected, strict=True):
            if not isinstance(attempt, Mapping) or attempt.get("observer_digest") != observer.get("digest"):
                raise TimingFailure("qualification_timing_ledger_invalid")


def summarize_timing(path: Path, *, direct_timing_path: Path | None = None) -> dict[str, object]:
    """Produce an aggregate-only projection with no row identifiers or hashes."""

    rows = read_timing_ledger(path)
    direct_rows = read_timing_ledger(direct_timing_path) if direct_timing_path is not None else ()
    walls = [int(row["downstream_wall_ns"]) for row in rows]
    threshold = _percentiles(walls)["p95_wall_ns"]
    buckets: dict[tuple[str, str], list[dict[str, object]]] = {}
    for row in rows:
        buckets.setdefault((str(row["intervention_class"]), str(row["cache_lane"])), []).append(row)
    by_lane: dict[str, dict[str, dict[str, object]]] = {}
    for (intervention, lane), values in sorted(buckets.items()):
        by_lane.setdefault(intervention, {})[lane] = _bucket(values, threshold)
    attempts = [item for row in rows for item in _as_list(row["attempts"])]
    model_values = [
        int(item["model_time_ns"])
        for item in attempts
        if isinstance(item, Mapping) and item.get("model_time_ns") is not None
    ]
    avoided_values = [int(row["model_time_avoided_ns"]) for row in rows if row.get("model_time_avoided_ns") is not None]
    return {
        "record_count": len(rows),
        "retained_wall_ns": sum(walls),
        "unexplained_ns": 0,
        "wall_ns": _percentiles(walls),
        "by_intervention_cache_lane": by_lane,
        "tail_threshold_ns": threshold,
        "attempts": {
            "model_attempts": len(attempts),
            "model_attempts_avoided": sum(int(row["avoided_immediate_upstream_calls"]) for row in rows),
            "model_time_ns": _available_sum(model_values, "model_boundary_unavailable"),
            "model_time_avoided_ns": _available_sum(avoided_values, "paired_counterfactual"),
        },
        "matched_pass_through": _matched_pass_through(rows, direct_rows),
        "slowest_buckets": [
            {
                "intervention_class": intervention,
                "cache_lane": lane,
                "count": len(values),
                "p95_wall_ns": _percentiles([int(value["downstream_wall_ns"]) for value in values])["p95_wall_ns"],
            }
            for (intervention, lane), values in sorted(
                buckets.items(),
                key=lambda item: _percentiles([int(value["downstream_wall_ns"]) for value in item[1]])["p95_wall_ns"],
                reverse=True,
            )
        ],
    }


def _matched_pass_through(
    proxy_rows: Sequence[dict[str, object]], direct_rows: Sequence[dict[str, object]]
) -> dict[str, object]:
    if not direct_rows:
        unavailable_value = _unavailable_value("direct_timing_ledger_unavailable")
        return {
            "count": 0,
            "added_wall_ns": unavailable_value,
            "added_ttft_ns": _unavailable_value("direct_timing_ledger_unavailable"),
            "attempts_added": _unavailable_value("direct_timing_ledger_unavailable"),
            "model_time_added_ns": _unavailable_value("direct_timing_ledger_unavailable"),
        }
    direct = {
        (int(row["pair_ordinal"]), str(row["cache_lane"])): row
        for row in direct_rows
        if row["arm"] == "direct" and row["intervention_class"] == "pass_through"
    }
    pairs = [
        (row, direct[(int(row["pair_ordinal"]), str(row["cache_lane"]))])
        for row in proxy_rows
        if row["arm"] == "proxy"
        and row["intervention_class"] == "pass_through"
        and (int(row["pair_ordinal"]), str(row["cache_lane"])) in direct
    ]
    walls = [int(proxy["downstream_wall_ns"]) - int(direct_row["downstream_wall_ns"]) for proxy, direct_row in pairs]
    ttft: list[int] = []
    model: list[int] = []
    for proxy, direct_row in pairs:
        proxy_ttft, direct_ttft = _first_ttft(proxy), _first_ttft(direct_row)
        if proxy_ttft is not None and direct_ttft is not None:
            ttft.append(proxy_ttft - direct_ttft)
        proxy_model, direct_model = _row_model_time(proxy), _row_model_time(direct_row)
        if proxy_model is not None and direct_model is not None:
            model.append(proxy_model - direct_model)
    return {
        "count": len(pairs),
        "added_wall_ns": _available_percentiles(walls, "matched_pass_through_unavailable"),
        "added_ttft_ns": _available_percentiles(ttft, "ttft_unavailable"),
        "attempts_added": _available_sum(
            [len(_as_list(proxy["attempts"])) - len(_as_list(direct_row["attempts"])) for proxy, direct_row in pairs],
            "matched_pass_through_unavailable",
        ),
        "model_time_added_ns": _available_sum(model, "model_boundary_unavailable"),
    }


def _first_ttft(row: Mapping[str, object]) -> int | None:
    attempts = _as_list(row.get("attempts"))
    if not attempts or not isinstance(attempts[0], Mapping):
        return None
    value = attempts[0].get("ttft_ns")
    return int(value) if value is not None else None


def _row_model_time(row: Mapping[str, object]) -> int | None:
    attempts = _as_list(row.get("attempts"))
    values = [
        int(item["model_time_ns"])
        for item in attempts
        if isinstance(item, Mapping) and item.get("model_time_ns") is not None
    ]
    return sum(values) if values and len(values) == len(attempts) else None


def _bucket(rows: Sequence[dict[str, object]], threshold: int) -> dict[str, object]:
    walls = [int(row["downstream_wall_ns"]) for row in rows]
    tail = [wall for wall in walls if wall >= threshold]
    return {
        "count": len(walls),
        **_percentiles(walls),
        "tail_record_count": len(tail),
        "tail_wall_ns": sum(tail),
        "tail_excess_ns": sum(max(wall - threshold, 0) for wall in walls),
    }


def _percentiles(values: Sequence[int]) -> dict[str, int]:
    if not values:
        return {"p50_wall_ns": 0, "p95_wall_ns": 0, "p99_wall_ns": 0}
    ordered = sorted(values)
    return {
        "p50_wall_ns": ordered[int((len(ordered) - 1) * 0.50)],
        "p95_wall_ns": ordered[int((len(ordered) - 1) * 0.95)],
        "p99_wall_ns": ordered[int((len(ordered) - 1) * 0.99)],
    }


def _available_percentiles(values: Sequence[int], source: str) -> dict[str, object]:
    return (
        {"availability": measured("paired_counterfactual"), **_percentiles(values)}
        if values
        else _unavailable_value(source)
    )


def _available_sum(values: Sequence[int], source: str) -> dict[str, object]:
    return (
        {"availability": measured("paired_counterfactual"), "value_ns": sum(values)}
        if values
        else _unavailable_value(source)
    )


def _unavailable_value(source: str) -> dict[str, object]:
    return {"availability": unavailable(source), "value_ns": None}


def _validate_rows(rows: list[dict[str, object]]) -> None:
    if len(rows) > _MAX_ROWS:
        raise TimingFailure("qualification_timing_ledger_invalid")
    ordinals: set[int] = set()
    for sequence, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("sequence") != sequence:
            raise TimingFailure("qualification_timing_ledger_invalid")
        _validate_row(row)
        pair_ordinal = int(row["pair_ordinal"])
        if pair_ordinal in ordinals:
            raise TimingFailure("qualification_timing_ledger_invalid")
        ordinals.add(pair_ordinal)


def _validate_row(row: Mapping[str, object]) -> None:
    if (
        set(row) != _REQUEST_KEYS
        or row.get("schema_version") != "2.0"
        or row.get("arm") not in _ARMS
        or row.get("outcome") not in _OUTCOMES
        or row.get("intervention_class") not in _INTERVENTIONS
        or row.get("cache_lane") not in _CACHE_LANES
        or not isinstance(row.get("local_projection"), bool)
        or not _positive(row.get("sequence"))
        or not _positive(row.get("pair_ordinal"))
        or not _sha256(row.get("request_accounting_row_sha256"))
        or not _sha256(row.get("observer_slice_sha256"))
    ):
        raise TimingFailure("qualification_timing_ledger_invalid")
    number_keys = (
        "downstream_wall_ns",
        "admission_wait_ns",
        "body_read_ns",
        "policy_exclusive_ns",
        "response_finalize_ns",
        "other_measured_ns",
        "avoided_immediate_upstream_calls",
        "correction_count",
        "blocked_duplicate_count",
        "blocked_stall_count",
        "retry_attempt_count",
    )
    if not all(_nonnegative(row.get(key)) for key in number_keys):
        raise TimingFailure("qualification_timing_ledger_invalid")
    phases = row.get("phase_counts")
    attempts = row.get("attempts")
    if (
        not isinstance(phases, dict)
        or set(phases) != _PHASES
        or not all(_nonnegative(value) for value in phases.values())
        or not isinstance(attempts, list)
    ):
        raise TimingFailure("qualification_timing_ledger_invalid")
    total = sum(
        int(row[key])
        for key in (
            "admission_wait_ns",
            "body_read_ns",
            "policy_exclusive_ns",
            "response_finalize_ns",
            "other_measured_ns",
        )
    )
    actual_phases = {phase: 0 for phase in _PHASES}
    for sequence, attempt in enumerate(attempts, 1):
        if (
            not isinstance(attempt, dict)
            or attempt.get("sequence") != sequence
            or attempt.get("request_sequence") != row["sequence"]
        ):
            raise TimingFailure("qualification_timing_ledger_invalid")
        _validate_attempt(attempt)
        total += int(attempt["wall_ns"])
        actual_phases[str(attempt["phase"])] += 1
    if phases != actual_phases:
        raise TimingFailure("qualification_timing_ledger_invalid")
    if total != row["downstream_wall_ns"]:
        raise TimingFailure("qualification_timing_unexplained_delta")
    _validate_nullable(row.get("model_time_avoided_ns"), row.get("model_time_avoided_availability"))
    if row["local_projection"]:
        if (
            row["outcome"] != "succeeded"
            or row["intervention_class"] != "projection"
            or attempts
            or any(phases.values())
            or any(
                int(row[key])
                for key in ("correction_count", "blocked_duplicate_count", "blocked_stall_count", "retry_attempt_count")
            )
            or row["avoided_immediate_upstream_calls"] != 1
            or row["model_time_avoided_ns"] is not None
            and row["model_time_avoided_availability"] != measured("paired_counterfactual")
        ):
            raise TimingFailure("qualification_timing_ledger_invalid")
    elif row["avoided_immediate_upstream_calls"] != 0:
        raise TimingFailure("qualification_timing_ledger_invalid")


def _validate_attempt(attempt: Mapping[str, object]) -> None:
    if (
        set(attempt) != _ATTEMPT_KEYS
        or attempt.get("phase") not in _PHASES
        or attempt.get("status") not in _OUTCOMES
        or attempt.get("cache_lane") not in _CACHE_LANES
        or attempt.get("cache_result") not in _CACHE_RESULTS
        or not _positive(attempt.get("sequence"))
        or not _positive(attempt.get("request_sequence"))
        or not _sha256(attempt.get("observer_digest"))
        or not _nonnegative(attempt.get("wall_ns"))
        or not _nonnegative(attempt.get("upstream_slot_wait_ns"))
    ):
        raise TimingFailure("qualification_timing_ledger_invalid")
    transport = attempt.get("transport")
    _validate_transport(transport)
    assert isinstance(transport, Mapping)
    if int(attempt["wall_ns"]) != int(attempt["upstream_slot_wait_ns"]) + int(transport["total_ns"]):
        raise TimingFailure("qualification_timing_unexplained_delta")
    for value, availability in (
        (attempt.get("ttft_ns"), attempt.get("ttft_availability")),
        (attempt.get("model_time_ns"), attempt.get("model_time_availability")),
        (attempt.get("decode_ns"), attempt.get("decode_availability")),
    ):
        _validate_nullable(value, availability)


def _validate_transport(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != _TRANSPORT_KEYS or not _nonnegative(value.get("total_ns")):
        raise TimingFailure("qualification_timing_ledger_invalid")
    total = 0
    for name in ("pool_wait", "connect", "request_write", "response_header_wait", "response_read", "other"):
        duration = value.get(f"{name}_ns")
        _validate_nullable(duration, value.get(f"{name}_availability"))
        if duration is not None:
            total += int(duration)
    if (
        total != value["total_ns"]
        or value.get("other_ns") is None
        or not _availability(value.get("other_availability"), "measured")
    ):
        raise TimingFailure("qualification_timing_unexplained_delta")
    reuse = value.get("connection_reuse")
    if reuse not in {None, "fresh", "reused"}:
        raise TimingFailure("qualification_timing_ledger_invalid")
    if reuse is None:
        if not _availability(value.get("connection_reuse_availability"), "unavailable"):
            raise TimingFailure("qualification_timing_ledger_invalid")
    elif not _availability(value.get("connection_reuse_availability"), "measured"):
        raise TimingFailure("qualification_timing_ledger_invalid")
    if reuse == "fresh" and value.get("connect_ns") is None:
        raise TimingFailure("qualification_timing_ledger_invalid")


def _validate_capture_row(row: Mapping[str, object]) -> None:
    if (
        set(row) != _CAPTURE_KEYS
        or row.get("schema_version") != "2.0"
        or row.get("record_type") != "qualification_timing_capture"
        or not _nonnegative(row.get("sequence"))
        or row.get("outcome") not in _OUTCOMES
    ):
        raise TimingFailure("qualification_timing_ledger_invalid")
    attempts = row.get("attempts")
    if not isinstance(attempts, list) or any(
        not isinstance(item, Mapping) or set(item) != _CAPTURE_ATTEMPT_KEYS for item in attempts
    ):
        raise TimingFailure("qualification_timing_ledger_invalid")
    final = {
        "schema_version": "2.0",
        "sequence": 1,
        "pair_ordinal": 1,
        "arm": "proxy",
        "request_accounting_row_sha256": "0" * 64,
        "observer_slice_sha256": "0" * 64,
        "outcome": row["outcome"],
        "intervention_class": "projection" if row.get("local_projection") else "pass_through",
        "cache_lane": "cold",
        "downstream_wall_ns": row.get("downstream_wall_ns"),
        "admission_wait_ns": row.get("admission_wait_ns"),
        "body_read_ns": row.get("body_read_ns"),
        "policy_exclusive_ns": row.get("policy_exclusive_ns"),
        "response_finalize_ns": row.get("response_finalize_ns"),
        "other_measured_ns": row.get("other_measured_ns"),
        "attempts": [
            {
                **dict(item),
                "request_sequence": 1,
                "observer_digest": "0" * 64,
                "cache_lane": "cold",
                "cache_result": "unavailable",
            }
            for item in attempts
        ],
        "local_projection": row.get("local_projection"),
        "avoided_immediate_upstream_calls": row.get("avoided_immediate_upstream_calls"),
        "correction_count": row.get("correction_count"),
        "blocked_duplicate_count": row.get("blocked_duplicate_count"),
        "blocked_stall_count": row.get("blocked_stall_count"),
        "retry_attempt_count": row.get("retry_attempt_count"),
        "phase_counts": row.get("phase_counts"),
        "model_time_avoided_ns": None,
        "model_time_avoided_availability": unavailable("not_observable"),
    }
    _validate_row(final)


def _validate_nullable(value: object, availability: object) -> None:
    if value is None:
        if not _availability(availability, "unavailable"):
            raise TimingFailure("qualification_timing_ledger_invalid")
    elif not _nonnegative(value) or not _availability(availability, "measured"):
        raise TimingFailure("qualification_timing_ledger_invalid")


def _availability(value: object, state: str) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == {"state", "source"}
        and value.get("state") == state
        and value.get("source") in _SOURCES
    )


def _observer_phase(fields: object) -> str:
    compatibility = fields.get("compatibility") if isinstance(fields, Mapping) else None
    phase = compatibility.get("phase") if isinstance(compatibility, Mapping) else None
    if phase not in _PHASES:
        raise TimingFailure("qualification_timing_ledger_invalid")
    return str(phase)


def _observer_status(response: object) -> str:
    status = response.get("status_code") if isinstance(response, Mapping) else None
    return "succeeded" if isinstance(status, int) and 200 <= status < 300 else "failed"


def _observer_cache_result(response: object) -> str:
    cache = response.get("cache") if isinstance(response, Mapping) else None
    source = cache.get("cache_source") if isinstance(cache, Mapping) else None
    return "miss" if source == "none" else "hit" if source in {"ram", "ssd"} else "unavailable"


def _append_private(path: Path, payload: bytes) -> None:
    descriptor: int | None = None
    try:
        listed = path.lstat()
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISREG(listed.st_mode)
            or stat.S_IMODE(listed.st_mode) != 0o600
            or listed.st_size + len(payload) > _MAX_BYTES
        ):
            raise OSError
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (listed.st_dev, listed.st_ino)
        ):
            raise OSError
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except OSError:
        raise TimingFailure("qualification_timing_ledger_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_new_private(path: Path, payload: bytes, *, exists_category: str) -> None:
    descriptor: int | None = None
    try:
        if not path.is_absolute() or path.parent.is_symlink() or len(payload) > _MAX_BYTES:
            raise OSError
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except FileExistsError:
        raise TimingFailure(exists_category) from None
    except OSError:
        raise TimingFailure("qualification_timing_ledger_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_private(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        listed = path.lstat()
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISREG(listed.st_mode)
            or stat.S_IMODE(listed.st_mode) != 0o600
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (listed.st_dev, listed.st_ino)
            or opened.st_size > _MAX_BYTES
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
        payload = b"".join(chunks)
        if len(payload) != opened.st_size or (payload and not payload.endswith(b"\n")):
            raise OSError
        return payload
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("private evidence partial write")
        offset += written


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _nonnegative(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive(value: object) -> bool:
    return _nonnegative(value) and int(value) > 0


def _require_nonnegative(value: object) -> int:
    if not _nonnegative(value):
        raise TimingFailure("qualification_timing_ledger_invalid")
    return int(value)
