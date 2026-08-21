from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

from shiftedx_harness_proxy.qualification_timing import (
    TimingFailure,
    bind_capture_row,
    canonical_json,
    observer_slice_sha256,
    request_accounting_row_sha256,
    unavailable,
    unavailable_transport,
    write_timing_ledger,
)


def _availability(source: str = "not_observable") -> dict[str, str]:
    return unavailable(source)


def _observer(sequence: int = 1, *, phase: str = "acquisition", status: int | None = 200) -> dict[str, object]:
    return {
        "record_type": "qualification_model_boundary",
        "sequence": sequence,
        "digest": hashlib.sha256(f"observer-{sequence}".encode()).hexdigest(),
        "fields": {"compatibility": {"phase": phase}},
        "response": {"status_code": status, "cache": None},
    }


def _attempt(
    sequence: int = 1,
    *,
    request_sequence: int = 1,
    phase: str = "acquisition",
    wall_ns: int = 30,
    slot_wait_ns: int = 10,
    ttft_ns: int | None = None,
    model_time_ns: int | None = None,
) -> dict[str, object]:
    transport = unavailable_transport(wall_ns - slot_wait_ns)
    return {
        "sequence": sequence,
        "request_sequence": request_sequence,
        "observer_digest": hashlib.sha256(f"observer-{sequence}".encode()).hexdigest(),
        "phase": phase,
        "status": "succeeded",
        "wall_ns": wall_ns,
        "upstream_slot_wait_ns": slot_wait_ns,
        "transport": transport,
        "ttft_ns": ttft_ns,
        "ttft_availability": {"state": "measured", "source": "paired_counterfactual"}
        if ttft_ns is not None
        else _availability("non_streaming_response"),
        "model_time_ns": model_time_ns,
        "model_time_availability": {"state": "measured", "source": "paired_counterfactual"}
        if model_time_ns is not None
        else _availability("model_boundary_unavailable"),
        "decode_ns": None,
        "decode_availability": _availability("model_boundary_unavailable"),
        "cache_lane": "cold",
        "cache_result": "unavailable",
    }


def _request(
    *,
    sequence: int = 1,
    pair_ordinal: int = 1,
    arm: str = "proxy",
    attempts: list[dict[str, object]] | None = None,
    outcome: str = "succeeded",
    intervention: str = "pass_through",
    local_projection: bool = False,
    correction_count: int = 0,
    blocked_duplicate_count: int = 0,
    blocked_stall_count: int = 0,
    retry_attempt_count: int = 0,
    other_measured_ns: int = 1,
) -> dict[str, object]:
    selected = attempts if attempts is not None else [_attempt(request_sequence=sequence)]
    phase_counts = {"acquisition": 0, "finalization": 0, "terminal": 0}
    for attempt in selected:
        phase_counts[str(attempt["phase"])] += 1
    components = 1 + 2 + 3 + 4 + other_measured_ns
    wall = components + sum(int(attempt["wall_ns"]) for attempt in selected)
    return {
        "schema_version": "2.0",
        "sequence": sequence,
        "pair_ordinal": pair_ordinal,
        "arm": arm,
        "request_accounting_row_sha256": "a" * 64,
        "observer_slice_sha256": "b" * 64,
        "outcome": outcome,
        "intervention_class": intervention,
        "cache_lane": "cold",
        "downstream_wall_ns": wall,
        "admission_wait_ns": 1,
        "body_read_ns": 2,
        "policy_exclusive_ns": 3,
        "response_finalize_ns": 4,
        "other_measured_ns": other_measured_ns,
        "attempts": selected,
        "local_projection": local_projection,
        "avoided_immediate_upstream_calls": 1 if local_projection else 0,
        "correction_count": correction_count,
        "blocked_duplicate_count": blocked_duplicate_count,
        "blocked_stall_count": blocked_stall_count,
        "retry_attempt_count": retry_attempt_count,
        "phase_counts": phase_counts,
        "model_time_avoided_ns": None,
        "model_time_avoided_availability": _availability(),
    }


def _capture(*, attempts: list[dict[str, object]] | None = None, **overrides: object) -> dict[str, object]:
    selected = attempts if attempts is not None else []
    phase_counts = {"acquisition": 0, "finalization": 0, "terminal": 0}
    for attempt in selected:
        phase_counts[str(attempt["phase"])] += 1
    components = 1 + 2 + 3 + 4 + 5
    row: dict[str, object] = {
        "schema_version": "2.0",
        "record_type": "qualification_timing_capture",
        "sequence": 1,
        "outcome": "succeeded",
        "downstream_wall_ns": components + sum(int(attempt["wall_ns"]) for attempt in selected),
        "admission_wait_ns": 1,
        "body_read_ns": 2,
        "policy_exclusive_ns": 3,
        "response_finalize_ns": 4,
        "other_measured_ns": 5,
        "attempts": selected,
        "local_projection": False,
        "avoided_immediate_upstream_calls": 0,
        "correction_count": 0,
        "blocked_duplicate_count": 0,
        "blocked_stall_count": 0,
        "retry_attempt_count": 0,
        "phase_counts": phase_counts,
    }
    row.update(overrides)
    return row


def _capture_attempt(*, phase: str = "acquisition", wall_ns: int = 30) -> dict[str, object]:
    return {
        "sequence": 1,
        "phase": phase,
        "status": "succeeded",
        "wall_ns": wall_ns,
        "upstream_slot_wait_ns": 10,
        "transport": unavailable_transport(wall_ns - 10),
        "ttft_ns": None,
        "ttft_availability": _availability("non_streaming_response"),
        "model_time_ns": None,
        "model_time_availability": _availability("model_boundary_unavailable"),
        "decode_ns": None,
        "decode_availability": _availability("model_boundary_unavailable"),
    }


def test_timing_ledger_rejects_legacy_millisecond_schema_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(TimingFailure, match="^qualification_timing_ledger_invalid$"):
        write_timing_ledger(
            tmp_path / "timing.jsonl",
            [
                {
                    "sequence": 1,
                    "downstream_wall_ms": 35,
                    "policy_ms": 5,
                    "attempts": [],
                }
            ],
        )


def test_timing_ledger_accepts_exact_monotonic_nanosecond_partition(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import read_timing_ledger

    path = tmp_path / "timing.jsonl"
    row = _request()
    write_timing_ledger(path, [row])
    assert read_timing_ledger(path) == (row,)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row.pop("body_read_ns"),
        lambda row: row.update(attempts=[_attempt(), _attempt()]),
        lambda row: row.update(attempts=[{**_attempt(), "sequence": 2}]),
        lambda row: row["attempts"][0]["transport"].update(other_ns=None),
        lambda row: row["attempts"][0].update(ttft_ns=0),
    ],
)
def test_timing_ledger_rejects_missing_duplicate_reordered_malformed_and_partial_rows(tmp_path: Path, mutator) -> None:
    row = _request()
    mutator(row)
    with pytest.raises(TimingFailure):
        write_timing_ledger(tmp_path / "timing.jsonl", [row])


def test_timing_ledger_rejects_unexplained_nanosecond_delta(tmp_path: Path) -> None:
    row = _request()
    row["downstream_wall_ns"] = int(row["downstream_wall_ns"]) + 1
    with pytest.raises(TimingFailure, match="^qualification_timing_unexplained_delta$"):
        write_timing_ledger(tmp_path / "timing.jsonl", [row])


def test_local_projection_requires_zero_attempts_phases_corrections_and_paired_model_counterfactual(
    tmp_path: Path,
) -> None:
    projection = _request(attempts=[], intervention="projection", local_projection=True)
    projection["downstream_wall_ns"] = 11
    projection["phase_counts"] = {"acquisition": 0, "finalization": 0, "terminal": 0}
    write_timing_ledger(tmp_path / "timing.jsonl", [projection])
    bad = {**projection, "correction_count": 1}
    with pytest.raises(TimingFailure):
        write_timing_ledger(tmp_path / "bad.jsonl", [bad])
    supported = {
        **projection,
        "model_time_avoided_ns": 1,
        "model_time_avoided_availability": {"state": "measured", "source": "paired_counterfactual"},
    }
    write_timing_ledger(tmp_path / "supported.jsonl", [supported])
    fabricated = {
        **projection,
        "model_time_avoided_ns": 1,
        "model_time_avoided_availability": {"state": "measured", "source": "model_boundary_unavailable"},
    }
    with pytest.raises(TimingFailure):
        write_timing_ledger(tmp_path / "fabricated.jsonl", [fabricated])


@pytest.mark.parametrize("outcome", ["failed", "cancelled", "deadline"])
def test_failure_cancellation_and_deadline_retain_pre_failure_interventions(tmp_path: Path, outcome: str) -> None:
    row = _request(
        outcome=outcome,
        intervention="bounded_failure",
        correction_count=1,
        blocked_duplicate_count=2,
        blocked_stall_count=3,
        retry_attempt_count=4,
    )
    write_timing_ledger(tmp_path / f"{outcome}.jsonl", [row])


def test_phase_split_rows_are_exact_and_response_headers_are_not_ttft(tmp_path: Path) -> None:
    first = _attempt(phase="acquisition", wall_ns=30)
    second = _attempt(2, phase="finalization", wall_ns=31)
    row = _request(attempts=[first, second])
    write_timing_ledger(tmp_path / "phase-split.jsonl", [row])
    assert first["transport"]["response_header_wait_ns"] is None
    assert first["ttft_ns"] is None


def test_exact_hash_linkage_binds_existing_accounting_row_and_ordered_observer_slice(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import verify_timing_ledger_linkage

    accounting = {
        "sequence": 1,
        "outcome": "succeeded",
        "local_projection": False,
        "attempt_sequence_start": 1,
        "attempt_sequence_end": 1,
        "attempt_count": 1,
    }
    observer = _observer()
    capture = _capture(attempts=[_capture_attempt()])
    row = bind_capture_row(
        capture,
        sequence=1,
        pair_ordinal=4,
        arm="proxy",
        request_accounting_row=accounting,
        observer_rows=[observer],
        cache_lane="cold",
        intervention_class="pass_through",
    )
    assert row["request_accounting_row_sha256"] == request_accounting_row_sha256(accounting)
    assert row["observer_slice_sha256"] == observer_slice_sha256([observer])
    assert "reconciliation_sha256" not in row
    write_timing_ledger(tmp_path / "timing.jsonl", [row])
    verify_timing_ledger_linkage([row], [accounting], [observer])
    with pytest.raises(TimingFailure):
        verify_timing_ledger_linkage([row], [accounting], [{**observer, "digest": "f" * 64}])


def test_public_summary_matches_private_direct_proxy_pass_through_by_safe_ordinal(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import summarize_timing

    direct = _request(arm="direct")
    direct["attempts"][0]["ttft_ns"] = 10
    direct["attempts"][0]["ttft_availability"] = {"state": "measured", "source": "paired_counterfactual"}
    proxy = _request(arm="proxy", other_measured_ns=21)
    proxy["attempts"][0]["ttft_ns"] = 14
    proxy["attempts"][0]["ttft_availability"] = {"state": "measured", "source": "paired_counterfactual"}
    direct_path = tmp_path / "direct.jsonl"
    proxy_path = tmp_path / "proxy.jsonl"
    write_timing_ledger(direct_path, [direct])
    write_timing_ledger(proxy_path, [proxy])
    summary = summarize_timing(proxy_path, direct_timing_path=direct_path)
    assert summary["matched_pass_through"]["count"] == 1
    assert summary["matched_pass_through"]["added_wall_ns"]["p50_wall_ns"] == 20
    assert summary["matched_pass_through"]["added_ttft_ns"]["p50_wall_ns"] == 4
    assert "pair_ordinal" not in json.dumps(summary)
    assert "request_accounting_row_sha256" not in json.dumps(summary)


def test_summary_uses_floor_percentiles_and_allowlisted_aggregate_fields(tmp_path: Path) -> None:
    from shiftedx_harness_proxy.qualification_timing import summarize_timing

    rows = []
    for sequence, remainder in enumerate((1, 2, 3, 4), 1):
        rows.append(_request(sequence=sequence, pair_ordinal=sequence, other_measured_ns=remainder))
    ledger = tmp_path / "timing.jsonl"
    write_timing_ledger(ledger, rows)
    summary = summarize_timing(ledger)
    assert summary["wall_ns"]["p50_wall_ns"] == 42
    assert {"tail_record_count", "tail_wall_ns", "tail_excess_ns"} <= set(
        summary["by_intervention_cache_lane"]["pass_through"]["cold"]
    )
    serialized = json.dumps(summary)
    for forbidden in ("sequence", "pair_ordinal", "observer_digest", "sha256", "endpoint", "prompt"):
        assert forbidden not in serialized


def test_private_writers_reject_duplicate_keys_no_clobber_and_partial_writes(tmp_path: Path, monkeypatch) -> None:
    from shiftedx_harness_proxy import qualification_timing as timing

    path = tmp_path / "timing.jsonl"
    write_timing_ledger(path, [_request()])
    with pytest.raises(TimingFailure, match="qualification_timing_ledger_exists"):
        write_timing_ledger(path, [_request()])
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_bytes(b'{"sequence":1,"sequence":2}\n')
    os.chmod(malformed, 0o600)
    with pytest.raises(TimingFailure):
        timing.read_timing_ledger(malformed)
    writes: list[int] = []
    original = timing.os.write

    def partial(descriptor: int, payload: bytes) -> int:
        writes.append(len(payload))
        return original(descriptor, payload[: max(1, len(payload) // 2)])

    monkeypatch.setattr(timing.os, "write", partial)
    partial_path = tmp_path / "partial.jsonl"
    write_timing_ledger(partial_path, [_request()])
    assert len(writes) > 1
    assert timing.read_timing_ledger(partial_path)


def test_public_summary_script_refuses_to_clobber_and_never_exposes_rows(tmp_path: Path) -> None:
    ledger = tmp_path / "timing.jsonl"
    write_timing_ledger(ledger, [_request()])
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


def test_canonical_hash_inputs_are_stable_and_never_row_payloads() -> None:
    accounting = {"b": 2, "a": 1}
    assert request_accounting_row_sha256(accounting) == hashlib.sha256(canonical_json({"a": 1, "b": 2})).hexdigest()
