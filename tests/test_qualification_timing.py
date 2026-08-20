from __future__ import annotations

import json
import hashlib
import importlib.util
from pathlib import Path

import pytest


def _attempt(sequence: int, *, phase: str = "acquisition", wall_ms: int = 30) -> dict[str, object]:
    return {
        "sequence": sequence,
        "request_sequence": 1,
        "observer_digest": hashlib.sha256(f"observer-{sequence}".encode()).hexdigest(),
        "phase": phase,
        "status": "succeeded",
        "wall_ms": wall_ms,
        "ttft_ms": 10,
        "decode_ms": 20,
        "cache_lane": "cold",
        "cache_result": "unavailable",
        "transport": {"connection": "unavailable", "connect_ms": None, "pool_wait_ms": None,
                      "request_write_ms": None, "response_header_ms": None, "response_read_ms": None},
    }


def _request(*, wall_ms: int = 50, attempts: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "sequence": 1,
        "request_ledger_sha256": "a" * 64,
        "observer_ledger_sha256": "b" * 64,
        "model_evidence_sha256": "c" * 64,
        "reconciliation_sha256": "d" * 64,
        "outcome": "succeeded",
        "intervention_class": "phase_split",
        "cache_lane": "cold",
        "downstream_wall_ms": wall_ms,
        "policy_ms": 5,
        "admission_ms": None,
        "transport_ms": None,
        "attempts": attempts if attempts is not None else [_attempt(1)],
        "local_projection": False,
    }


def test_timing_ledger_rejects_unexplained_wall_time_delta(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import TimingFailure, write_timing_ledger

    with pytest.raises(TimingFailure, match="^qualification_timing_unexplained_delta$"):
        write_timing_ledger(tmp_path / "timing.jsonl", [_request(wall_ms=50)])


@pytest.mark.parametrize("mutator", [
    lambda row: row.pop("attempts"),
    lambda row: row.update(attempts=[_attempt(1), _attempt(1)]),
    lambda row: row.update(attempts=[_attempt(2)]),
    lambda row: row.update(attempts=[_attempt(1, wall_ms=-1)]),
])
def test_timing_ledger_rejects_missing_duplicate_reordered_malformed_and_partial_rows(tmp_path: Path, mutator) -> None:
    from shiftedx_harness_proxy.qualification_timing import TimingFailure, write_timing_ledger

    row = _request(wall_ms=35, attempts=[_attempt(1, wall_ms=30)])
    mutator(row)
    with pytest.raises(TimingFailure):
        write_timing_ledger(tmp_path / "timing.jsonl", [row])


@pytest.mark.parametrize("outcome", ["failed", "cancelled", "deadline"])
def test_timing_ledger_retains_exact_failure_and_cancellation_rows(tmp_path: Path, outcome: str) -> None:
    from shiftedx_harness_proxy.qualification_timing import read_timing_ledger, write_timing_ledger

    row = _request(wall_ms=35, attempts=[{**_attempt(1, wall_ms=30), "status": outcome}])
    row["outcome"] = outcome
    path = tmp_path / "timing.jsonl"
    write_timing_ledger(path, [row])
    assert read_timing_ledger(path)[0]["outcome"] == outcome


def test_timing_ledger_projects_safe_aggregate_only_summary_and_local_projection(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import summarize_timing, write_timing_ledger

    phase_split = _request(wall_ms=35, attempts=[_attempt(1, wall_ms=30)])
    projection = {
        **_request(wall_ms=7, attempts=[]),
        "sequence": 2,
        "intervention_class": "projection",
        "policy_ms": 7,
        "local_projection": True,
    }
    ledger = tmp_path / "timing.jsonl"
    write_timing_ledger(ledger, [phase_split, projection])
    summary = summarize_timing(ledger)

    assert ledger.stat().st_mode & 0o777 == 0o600
    assert summary["retained_wall_ms"] == 42
    assert summary["unexplained_wall_ms"] == 0
    assert summary["attempts"]["model_attempts"] == 1
    assert summary["attempts"]["model_attempts_avoided"] == 1
    assert summary["by_intervention"]["projection"]["p95_wall_ms"] == 7
    assert "sequence" not in json.dumps(summary)


def test_public_summary_script_refuses_to_clobber_and_exposes_no_row_identifiers(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import write_timing_ledger

    ledger = tmp_path / "timing.jsonl"
    write_timing_ledger(ledger, [_request(wall_ms=35, attempts=[_attempt(1, wall_ms=30)])])
    script = Path(__file__).parents[1] / "scripts" / "summarize_public_latency.py"
    spec = importlib.util.spec_from_file_location("summary", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "summary.json"
    assert module.main(["--timing-ledger", str(ledger), "--output", str(output)]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert "sequence" not in output.read_text()
    with pytest.raises(SystemExit, match="qualification_timing_summary_failed"):
        module.main(["--timing-ledger", str(ledger), "--output", str(output)])
