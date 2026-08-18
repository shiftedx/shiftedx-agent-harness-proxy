"""OpenAI transcript and schema adaptation at the proxy trust boundary."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from .core import AgentHarness, ToolRoles

JsonObject = dict[str, Any]
_PRIMITIVE_TYPES = {"string", "integer", "number", "boolean"}


@dataclass(frozen=True)
class SchemaContract:
    keys: tuple[str, ...] | None
    types: dict[str, str]


@dataclass(frozen=True)
class Reconstruction:
    harness: AgentHarness
    degraded: bool
    warnings: tuple[str, ...]
    latest_tool: str | None = None
    latest_result: str | None = None


def _tool_name(tool: JsonObject) -> str:
    function = tool.get("function")
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        raise ValueError("Every tool must contain function.name")
    name = function["name"]
    assert isinstance(name, str)
    return name


def prepare_tools(raw_tools: Any, configured_roles: ToolRoles) -> tuple[list[JsonObject], ToolRoles]:
    """Strip proxy role annotations while retaining every unrelated upstream field."""
    if raw_tools is None:
        return [], configured_roles
    if not isinstance(raw_tools, list):
        raise ValueError("tools must be an array")
    forwarded = copy.deepcopy(raw_tools)
    roles = configured_roles
    for tool in forwarded:
        if not isinstance(tool, dict):
            raise ValueError("Every tool must be an object")
        name = _tool_name(tool)
        top_role = tool.pop("x-shiftedx-role", None)
        function = tool.get("function")
        assert isinstance(function, dict)
        function_role = function.pop("x-shiftedx-role", None)
        if top_role is not None and function_role is not None and top_role != function_role:
            raise ValueError(f"Conflicting x-shiftedx-role annotations for {name}")
        role = function_role if function_role is not None else top_role
        if role is not None:
            if not isinstance(role, str):
                raise ValueError(f"x-shiftedx-role for {name} must be a string")
            roles = roles.with_annotation(name, role.strip().lower())
    return forwarded, roles


def response_schema_contract(response_format: Any) -> SchemaContract:
    """Derive the conservative primitive object contract supported by v1 projection."""
    if not isinstance(response_format, dict) or response_format.get("type") != "json_schema":
        return SchemaContract(None, {})
    wrapper = response_format.get("json_schema")
    schema = wrapper.get("schema") if isinstance(wrapper, dict) else None
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return SchemaContract(None, {})
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return SchemaContract(None, {})
    types: dict[str, str] = {}
    for key, definition in properties.items():
        if not isinstance(key, str) or not isinstance(definition, dict):
            return SchemaContract(None, {})
        type_name = definition.get("type")
        if type_name not in _PRIMITIVE_TYPES:
            return SchemaContract(None, {})
        types[key] = type_name
    return SchemaContract(tuple(properties), types)


def _arguments(call: JsonObject) -> dict[str, Any]:
    function = call.get("function")
    if not isinstance(function, dict):
        raise ValueError("tool call is missing function")
    raw = function.get("arguments", {})
    value = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(value, dict):
        raise ValueError("tool call arguments must decode to an object")
    return value


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, separators=(",", ":"), ensure_ascii=True)


def reconstruct(
    messages: Any,
    *,
    available_tools: set[str],
    roles: ToolRoles,
    contract: SchemaContract,
    require_receipt: bool,
) -> Reconstruction:
    """Rebuild receipt state only from call IDs paired with later visible tool messages."""
    if not isinstance(messages, list):
        raise ValueError("messages must be an array")
    goal = next(
        (
            _content_text(message.get("content", ""))
            for message in reversed(messages)
            if isinstance(message, dict) and message.get("role") == "user"
        ),
        "",
    )
    harness = AgentHarness(
        goal,
        available_tools=available_tools,
        required_json_keys=contract.keys,
        required_json_types=contract.types,
        require_receipt=require_receipt,
        roles=roles,
    )
    pending: dict[str, tuple[str, dict[str, Any]]] = {}
    warnings: list[str] = []
    latest_tool: str | None = None
    latest_result: str | None = None

    for message in messages:
        if not isinstance(message, dict):
            warnings.append("non_object_message")
            continue
        if message.get("role") == "assistant":
            calls = message.get("tool_calls") or []
            if not isinstance(calls, list):
                warnings.append("invalid_tool_calls")
                continue
            for call in calls:
                if not isinstance(call, dict):
                    warnings.append("invalid_tool_call")
                    continue
                call_id = call.get("id")
                function = call.get("function")
                name = function.get("name") if isinstance(function, dict) else None
                if not isinstance(call_id, str) or not call_id or not isinstance(name, str):
                    warnings.append("invalid_tool_call")
                    continue
                if call_id in pending:
                    warnings.append("duplicate_tool_call_id")
                    continue
                try:
                    arguments = _arguments(call)
                except (ValueError, json.JSONDecodeError, TypeError):
                    warnings.append("invalid_tool_arguments")
                    continue
                pending[call_id] = (name, arguments)
        elif message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or call_id not in pending:
                warnings.append("orphan_tool_result")
                continue
            name, arguments = pending.pop(call_id)
            result = _content_text(message.get("content", ""))
            harness.record(name, arguments, result)
            latest_tool, latest_result = name, result

    if pending:
        warnings.append("unmatched_tool_call")
    return Reconstruction(
        harness=harness,
        degraded=bool(warnings),
        warnings=tuple(dict.fromkeys(warnings)),
        latest_tool=latest_tool,
        latest_result=latest_result,
    )
