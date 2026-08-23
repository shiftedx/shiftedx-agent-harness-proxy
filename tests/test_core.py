from shiftedx_harness_proxy import AgentHarness, ToolRoles, receipt_status
from shiftedx_harness_proxy.core import HARNESS_SYSTEM_SUFFIX, bare_json_issue


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


def test_blocked_duplicate_is_explicitly_not_a_client_execution() -> None:
    state = AgentHarness("recover", available_tools={"run_tests"})
    arguments = {"target": "original"}
    prior = state.record("run_tests", arguments, "1 failed")

    blocked = state.blocked_result(prior)

    assert '"execution_status":"blocked_not_executed"' in blocked
    assert "did not reach the client executor" in blocked
    assert (
        "Only downstream-visible assistant tool-call IDs paired with client-supplied role=tool "
        "results count as executed"
    ) in HARNESS_SYSTEM_SUFFIX


def test_structured_failed_execution_claim_must_match_client_visible_receipts() -> None:
    state = AgentHarness("recover", available_tools={"run_tests", "apply_patch"})
    state.record("run_tests", {"target": "original"}, "1 failed")
    state.record("apply_patch", {}, "Patch applied.")
    state.record("run_tests", {"target": "recovered"}, "8 passed")

    assert "must be 1" in (
        state.terminal_issue('{"failed_executions":2,"recovery_verified":true}') or ""
    )
    assert state.terminal_issue(
        '{"failed_executions":1,"recovery_verified":true}'
    ) is None


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
    assert state.project_final("read_logs", '{"status":"nominal","workers":8}') is None
    assert state.projection_shadow_candidate(
        "read_logs", '{"status":"nominal","workers":8}'
    ).reason == "exact_primitive_object"

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
