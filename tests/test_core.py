from shiftedx_harness_proxy import AgentHarness, ToolRoles, receipt_status
from shiftedx_harness_proxy.core import bare_json_issue


def test_structured_status_takes_priority_over_incidental_error_words() -> None:
    assert (
        receipt_status('{"status":"healthy","message":"No errors detected","error_budget":"99.9%"}')
        == "success"
    )
    assert receipt_status('{"error":"index unavailable","retryable":false}') == "failure"
    assert receipt_status("11 passed, 1 failed: backoff") == "failure"
    assert receipt_status("Patch rejected: guard absent") == "failure"


def test_duplicates_are_epoch_scoped_and_mutation_requires_verification() -> None:
    state = AgentHarness("fix", available_tools={"read_file", "apply_patch", "run_tests"})
    read = {"path": "/repo/a.py"}
    state.record("read_file", read, "source")
    assert state.duplicate("read_file", read) is not None

    state.record("apply_patch", {"patch": "x"}, "Patch applied.")
    assert state.pending_verification
    assert state.duplicate("read_file", read) is None
    assert "verification" in (state.terminal_issue('{"status":"passed"}') or "")

    state.record("run_tests", {}, "2 passed")
    assert state.terminal_issue('{"status":"passed"}') is None


def test_failed_verification_persists_through_investigation_and_stalls_at_three() -> None:
    state = AgentHarness(
        "repair", available_tools={"run_tests", "read_file", "file_search", "apply_patch"}
    )
    state.record("run_tests", {}, "1 failed")
    state.record("file_search", {"query": "bug"}, "/repo/a.py")
    state.record("read_file", {"path": "/repo/a.py"}, "source")
    state.record("read_file", {"path": "/repo/test_a.py"}, "tests")

    assert "run_tests" in state.open_failures
    assert state.stalled_result("file_search") is not None
    assert state.terminal_issue('{"status":"passed"}') is not None


def test_failed_investigation_receipts_do_not_advance_stall_threshold() -> None:
    state = AgentHarness(
        "repair", available_tools={"run_tests", "read_file", "file_search", "apply_patch"}
    )
    state.record("run_tests", {}, "1 failed")
    state.record("read_file", {"path": "missing"}, '{"status":"not_found"}')
    state.record("file_search", {"query": "bug"}, "a.py")
    state.record("read_file", {"path": "a.py"}, "source")
    assert state.stalled_result("file_search") is None
    state.record("read_file", {"path": "test_a.py"}, "tests")
    assert state.stalled_result("file_search") is not None


def test_tool_roles_are_configurable_without_changing_compatibility_defaults() -> None:
    roles = ToolRoles().with_annotation("deploy", "mutation").with_annotation("probe", "verification")
    state = AgentHarness("deploy", available_tools={"deploy", "probe"}, roles=roles)
    state.record("deploy", {}, "ok")
    assert state.pending_verification
    state.record("probe", {}, '{"status":"healthy"}')
    assert not state.pending_verification


def test_projection_requires_complete_typed_successful_receipt() -> None:
    state = AgentHarness(
        "health",
        required_json_keys=("status", "workers"),
        required_json_types={"status": "string", "workers": "integer"},
    )
    state.record("read_logs", {}, '{"status":"nominal","workers":8,"message":"ok"}')
    assert state.project_final("read_logs", '{"status":"nominal","workers":8}') == (
        '{"status":"nominal","workers":8}'
    )

    missing = AgentHarness(
        "health",
        required_json_keys=("status", "workers"),
        required_json_types={"status": "string", "workers": "integer"},
    )
    missing.record("read_logs", {}, '{"status":"nominal"}')
    assert missing.project_final("read_logs", '{"status":"nominal"}') is None

    failed = AgentHarness("health", required_json_keys=("status",))
    failed.record("read_logs", {}, '{"status":"failed"}')
    assert failed.project_final("read_logs", '{"status":"failed"}') is None
    assert bare_json_issue('{"workers":"8"}', ("workers",), {"workers": "integer"})
