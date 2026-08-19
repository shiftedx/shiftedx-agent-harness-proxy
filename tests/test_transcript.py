import pytest

from shiftedx_harness_proxy.core import ToolRoles
from shiftedx_harness_proxy.transcript import (
    PolicyAnnotationError,
    prepare_tools,
    reconstruct,
    response_schema_contract,
)


def _call(call_id: str, name: str, arguments: str) -> dict:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def test_reconstructs_receipts_only_from_paired_visible_call_ids() -> None:
    messages = [
        {"role": "user", "content": "repair"},
        {"role": "assistant", "tool_calls": [_call("a", "read_file", '{"path":"a.py"}')]},
        {"role": "tool", "tool_call_id": "a", "content": "source"},
        {"role": "assistant", "tool_calls": [_call("b", "apply_patch", '{"patch":"x"}')]},
        {"role": "tool", "tool_call_id": "b", "content": "Patch applied."},
    ]
    rebuilt = reconstruct(
        messages,
        available_tools={"read_file", "apply_patch", "run_tests"},
        roles=ToolRoles(),
        contract=response_schema_contract(None),
        require_receipt=True,
    )
    assert not rebuilt.degraded
    assert [receipt.tool for receipt in rebuilt.harness.receipts] == ["read_file", "apply_patch"]
    assert rebuilt.harness.epoch == 1
    assert rebuilt.harness.pending_verification


def test_orphan_or_unmatched_calls_signal_degraded_state_without_fabricating_receipts() -> None:
    rebuilt = reconstruct(
        [
            {"role": "tool", "tool_call_id": "missing", "content": "ok"},
            {"role": "assistant", "tool_calls": [_call("pending", "read_file", "{}")]},
        ],
        available_tools={"read_file"},
        roles=ToolRoles(),
        contract=response_schema_contract(None),
        require_receipt=True,
    )
    assert rebuilt.degraded
    assert set(rebuilt.warnings) == {"orphan_tool_result", "unmatched_tool_call"}
    assert rebuilt.harness.receipts == []


def test_annotations_configure_roles_and_are_stripped_without_losing_unknown_fields() -> None:
    tools, roles, extension_used = prepare_tools(
        [
            {
                "type": "function",
                "x-shiftedx-role": "mutation",
                "vendor-extension": {"keep": True},
                "function": {"name": "deploy", "description": "ship", "parameters": {}},
            }
        ],
        ToolRoles(),
    )
    assert "x-shiftedx-role" not in tools[0]
    assert tools[0]["vendor-extension"] == {"keep": True}
    assert "deploy" in roles.mutation
    assert not extension_used


def test_protected_roles_reject_untrusted_downgrades_but_allow_custom_tool_annotations() -> None:
    tools, roles, extension_used = prepare_tools(
        [
            {
                "type": "function",
                "x-shiftedx-role": "verification",
                "function": {"name": "custom_check", "parameters": {}},
            }
        ],
        ToolRoles(),
    )
    assert "x-shiftedx-role" not in tools[0]
    assert "custom_check" in roles.verification
    assert not extension_used

    for name, role in (("apply_patch", "other"), ("run_tests", "investigation")):
        with pytest.raises(PolicyAnnotationError) as raised:
            prepare_tools(
                [
                    {
                        "type": "function",
                        "x-shiftedx-role": role,
                        "function": {"name": name, "parameters": {}},
                    }
                ],
                ToolRoles(),
            )
        assert raised.value.code == "protected_role_override_denied"


def test_role_annotations_fail_closed_for_conflicts_and_malformed_values() -> None:
    conflicting = {
        "type": "function",
        "x-shiftedx-role": "mutation",
        "function": {"name": "custom", "x-shiftedx-role": "other", "parameters": {}},
    }
    with pytest.raises(PolicyAnnotationError) as conflict:
        prepare_tools([conflicting], ToolRoles())
    assert conflict.value.code == "conflicting_role_annotation"

    for malformed_role in (["mutation"], None):
        malformed = {"type": "function", "function": {"name": "custom", "parameters": {}}}
        malformed["x-shiftedx-role"] = malformed_role
        with pytest.raises(PolicyAnnotationError) as invalid:
            prepare_tools([malformed], ToolRoles())
        assert invalid.value.code == "invalid_role_annotation"


def test_standard_response_schema_derives_all_declared_primitive_keys() -> None:
    contract = response_schema_contract(
        {
            "type": "json_schema",
            "json_schema": {
                "name": "result",
                "schema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "tests": {"type": "integer"},
                    },
                    "required": ["status", "tests"],
                    "additionalProperties": False,
                },
            },
        }
    )
    assert contract.keys == ("status", "tests")
    assert contract.types == {"status": "string", "tests": "integer"}
