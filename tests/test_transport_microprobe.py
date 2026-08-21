from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_script():
    script = Path(__file__).parents[1] / "scripts" / "transport_microprobe.py"
    spec = importlib.util.spec_from_file_location("transport_microprobe", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_local_microprobe_reports_only_aggregate_pool_mechanism_evidence(tmp_path: Path) -> None:
    module = _load_script()
    output = tmp_path / "transport-microprobe.json"

    assert (
        module.main(
            [
                "--requests",
                "6",
                "--concurrency",
                "1",
                "--request-spacing-ms",
                "0",
                "--current-keepalive-expiry-seconds",
                "5",
                "--declared-keepalive-expiry-seconds",
                "0",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "transport_microprobe_v1"
    assert report["scope"] == "local_http_pool_mechanism_only"
    assert report["production_latency_claim"] is False
    assert report["workload"] == {"request_count": 6, "concurrency": 1, "request_spacing_ms": 0}
    assert report["trace_connection_reuse"] == "no_reused_connection_event_in_httpx_0_28_1_trace"
    assert [case["keepalive_expiry_seconds"] for case in report["cases"]] == [5.0, 0.0]
    for case in report["cases"]:
        assert case["response_count"] == 6
        assert 1 <= case["fresh_connection_count"] <= 6
        assert case["server_observed_reused_request_count"] == 6 - case["fresh_connection_count"]
        assert case["client_wall_ns"]["p50_ns"] > 0
        assert case["client_wall_ns"]["p95_ns"] >= case["client_wall_ns"]["p50_ns"]
        headers = case["response_header_wait_ns"]
        assert headers["measured_count"] == 6
        assert headers["unavailable_count"] == 0
        assert headers["p50_ns"] >= 0
        assert headers["p95_ns"] >= headers["p50_ns"]
        reuse = case["trace_connection_reuse_counts"]
        assert reuse["fresh_count"] + reuse["reused_count"] + reuse["unavailable_count"] == 6
        assert reuse["reused_count"] == 0
    serialized = json.dumps(report)
    for forbidden in ("127.0.0.1", "endpoint", "request_body", "response_body"):
        assert forbidden not in serialized


def test_microprobe_rejects_unbounded_workload(tmp_path: Path) -> None:
    module = _load_script()

    try:
        module.main(["--requests", "129", "--output", str(tmp_path / "report.json")])
    except SystemExit as error:
        assert str(error) == "transport_microprobe_failed"
    else:  # pragma: no cover - assertion makes the intended public behavior explicit.
        raise AssertionError("unbounded request count was accepted")
