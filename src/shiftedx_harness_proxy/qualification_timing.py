"""Private, allowlisted timing evidence for qualification-only latency diagnosis.

This module deliberately accepts integer milliseconds only.  A request row is
valid only when its retained downstream wall time is exactly partitioned into
proxy-owned time and the ordered model-attempt wall times; unavailable
transport partitions stay explicit ``null`` and never become invented values.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable


_MAX_BYTES = 1024 * 1024
_MAX_ROWS = 10_000
_OUTCOMES = {"succeeded", "failed", "cancelled", "deadline"}
_INTERVENTIONS = {"pass_through", "phase_split", "correction", "blocked_call_recovery", "projection", "bounded_failure"}
_PHASES = {"acquisition", "finalization", "terminal"}
_CACHE_LANES = {"cold", "warm-prefix", "unavailable"}
_CACHE_RESULTS = {"hit", "miss", "unavailable"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TimingFailure(RuntimeError):
    """Categorical failure that never includes private evidence values."""


def write_timing_ledger(path: Path, rows: Iterable[dict[str, object]]) -> None:
    """Write one fresh mode-0600 private ledger after exact reconciliation."""

    values = list(rows)
    _validate_rows(values)
    payload = b"".join(_canonical(value) + b"\n" for value in values)
    if len(payload) > _MAX_BYTES:
        raise TimingFailure("qualification_timing_ledger_invalid")
    _write_new_private(path, payload)


def read_timing_ledger(path: Path) -> tuple[dict[str, object], ...]:
    """Read and validate a bounded private timing ledger without payload fields."""

    try:
        listed = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(listed.st_mode) or stat.S_IMODE(listed.st_mode) != 0o600:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_size > _MAX_BYTES:
                raise OSError
            data = os.read(descriptor, opened.st_size + 1)
        finally:
            os.close(descriptor)
        if len(data) != opened.st_size or (data and not data.endswith(b"\n")):
            raise ValueError
        rows = [json.loads(line, object_pairs_hook=_unique_object) for line in data.splitlines()]
        _validate_rows(rows)
        return tuple(rows)
    except (OSError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError, TimingFailure):
        raise TimingFailure("qualification_timing_ledger_invalid") from None


def summarize_timing(path: Path) -> dict[str, object]:
    """Return aggregate-only diagnostics; intentionally excludes row identities."""

    rows = read_timing_ledger(path)
    grouped: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault(str(row["intervention_class"]), []).append(row)
    by_intervention = {
        key: _bucket(values)
        for key, values in sorted(grouped.items())
    }
    by_cache_lane: dict[str, dict[str, object]] = {}
    for lane in _CACHE_LANES:
        values = [row for row in rows if row["cache_lane"] == lane]
        if values:
            by_cache_lane[lane] = _bucket(values)
    walls = [int(row["downstream_wall_ms"]) for row in rows]
    attempts = [attempt for row in rows for attempt in row["attempts"]]  # type: ignore[index]
    return {
        "record_count": len(rows),
        "retained_wall_ms": sum(walls),
        "unexplained_wall_ms": 0,
        "wall_ms": _percentiles(walls),
        "by_intervention": by_intervention,
        "by_cache_lane": by_cache_lane,
        "attempts": {
            "model_attempts": len(attempts),
            "model_attempts_avoided": sum(bool(row["local_projection"]) for row in rows),
            "model_time_ms": sum(int(attempt["wall_ms"]) for attempt in attempts),
            "model_time_avoided_ms": sum(int(row["downstream_wall_ms"]) for row in rows if row["local_projection"]),
        },
        "slowest_buckets": [
            {"intervention_class": key, "cache_lane": lane, "p95_wall_ms": _percentiles(values)["p95_wall_ms"], "count": len(values)}
            for key, lane, values in sorted(
                ((key, lane, [int(row["downstream_wall_ms"]) for row in rows if row["intervention_class"] == key and row["cache_lane"] == lane])
                 for key in _INTERVENTIONS for lane in _CACHE_LANES),
                key=lambda item: _percentiles(item[2])["p95_wall_ms"] if item[2] else -1,
                reverse=True,
            ) if values
        ],
    }


def _validate_rows(rows: list[dict[str, object]]) -> None:
    if len(rows) > _MAX_ROWS:
        raise TimingFailure("qualification_timing_ledger_invalid")
    for expected, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("sequence") != expected:
            raise TimingFailure("qualification_timing_ledger_invalid")
        _validate_row(row)


def _validate_row(row: dict[str, object]) -> None:
    required = {"sequence", "request_ledger_sha256", "observer_ledger_sha256", "model_evidence_sha256", "reconciliation_sha256", "outcome", "intervention_class", "cache_lane", "downstream_wall_ms", "policy_ms", "admission_ms", "transport_ms", "attempts", "local_projection"}
    if set(row) != required or row["outcome"] not in _OUTCOMES or row["intervention_class"] not in _INTERVENTIONS or row["cache_lane"] not in _CACHE_LANES or not isinstance(row["local_projection"], bool):
        raise TimingFailure("qualification_timing_ledger_invalid")
    if not all(isinstance(row[key], str) and _SHA256.fullmatch(str(row[key])) for key in ("request_ledger_sha256", "observer_ledger_sha256", "model_evidence_sha256", "reconciliation_sha256")):
        raise TimingFailure("qualification_timing_ledger_invalid")
    ints = (row["sequence"], row["downstream_wall_ms"], row["policy_ms"])
    if not all(_nonnegative(value) for value in ints) or not _nullable_ms(row["admission_ms"]) or not _nullable_ms(row["transport_ms"]):
        raise TimingFailure("qualification_timing_ledger_invalid")
    attempts = row["attempts"]
    if not isinstance(attempts, list):
        raise TimingFailure("qualification_timing_ledger_invalid")
    if row["local_projection"] and (attempts or row["intervention_class"] != "projection" or row["outcome"] != "succeeded"):
        raise TimingFailure("qualification_timing_ledger_invalid")
    total = int(row["policy_ms"]) + (row["admission_ms"] or 0) + (row["transport_ms"] or 0)
    for expected, attempt in enumerate(attempts, 1):
        if not isinstance(attempt, dict) or attempt.get("sequence") != expected or attempt.get("request_sequence") != row["sequence"]:
            raise TimingFailure("qualification_timing_ledger_invalid")
        _validate_attempt(attempt)
        total += int(attempt["wall_ms"])
    if total != row["downstream_wall_ms"]:
        raise TimingFailure("qualification_timing_unexplained_delta")


def _validate_attempt(attempt: dict[str, object]) -> None:
    required = {"sequence", "request_sequence", "observer_digest", "phase", "status", "wall_ms", "ttft_ms", "decode_ms", "cache_lane", "cache_result", "transport"}
    if set(attempt) != required or attempt["phase"] not in _PHASES or attempt["status"] not in _OUTCOMES or attempt["cache_lane"] not in _CACHE_LANES or attempt["cache_result"] not in _CACHE_RESULTS:
        raise TimingFailure("qualification_timing_ledger_invalid")
    if not isinstance(attempt["observer_digest"], str) or _SHA256.fullmatch(attempt["observer_digest"]) is None:
        raise TimingFailure("qualification_timing_ledger_invalid")
    if not all(_nullable_ms(attempt[key]) for key in ("wall_ms", "ttft_ms", "decode_ms")) or attempt["wall_ms"] is None:
        raise TimingFailure("qualification_timing_ledger_invalid")
    transport = attempt["transport"]
    keys = {"connection", "connect_ms", "pool_wait_ms", "request_write_ms", "response_header_ms", "response_read_ms"}
    if not isinstance(transport, dict) or set(transport) != keys or transport["connection"] not in {"fresh", "reused", "unavailable"} or not all(_nullable_ms(transport[key]) for key in keys - {"connection"}):
        raise TimingFailure("qualification_timing_ledger_invalid")


def _bucket(rows: list[dict[str, object]]) -> dict[str, object]:
    walls = [int(row["downstream_wall_ms"]) for row in rows]
    return {"count": len(rows), **_percentiles(walls), "tail_contribution_ms": max(walls, default=0)}


def _percentiles(values: list[int]) -> dict[str, int]:
    if not values:
        return {"p50_wall_ms": 0, "p95_wall_ms": 0, "p99_wall_ms": 0}
    ordered = sorted(values)
    def at(percent: int) -> int:
        return ordered[(len(ordered) * percent + 99) // 100 - 1]
    return {"p50_wall_ms": at(50), "p95_wall_ms": at(95), "p99_wall_ms": at(99)}


def _nonnegative(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _nullable_ms(value: object) -> bool:
    return value is None or _nonnegative(value)


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _write_new_private(path: Path, payload: bytes) -> None:
    descriptor: int | None = None
    try:
        if not path.is_absolute() or path.parent.is_symlink():
            raise OSError
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    except FileExistsError:
        raise TimingFailure("qualification_timing_ledger_exists") from None
    except OSError:
        raise TimingFailure("qualification_timing_ledger_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
