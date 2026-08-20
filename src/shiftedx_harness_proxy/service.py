"""Bounded non-streaming Chat Completions policy loop."""

from __future__ import annotations

import copy
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .cache_policy import (
    ClientCacheNamespaceError,
    ServerCacheNamespace,
    reject_client_cache_namespaces,
)
from .config import Settings, configured_roles
from .core import HARNESS_SYSTEM_SUFFIX, AgentHarness, bare_json_issue, normalize_bare_json
from .errors import ProxyError, UpstreamFailure
from .projection_accounting import LOCAL_PROJECTION_EXTENSION, local_projection_accounting
from .provider_capabilities import CapabilityPhase, outbound_payload, requires_phase_split, upstream_phase
from .transcript import (
    PolicyAnnotationError,
    Reconstruction,
    SchemaContract,
    prepare_tools,
    reconstruct,
    response_schema_contract,
)
from .transport import Upstream

JsonObject = dict[str, Any]
REQUIRE_RECEIPT_EXTENSION = "x-shiftedx-require-receipt"


@dataclass(frozen=True)
class PolicyTelemetry:
    profile: str
    blocked_duplicates: int
    blocked_stalls: int
    corrections: int
    upstream_calls: int
    policy_wall_ms: float
    receipt_projections: int = 0
    local_projection_upstream_calls_avoided: int = 0
    degraded_state: bool = False
    policy_extensions_used: int = 0


@dataclass(frozen=True)
class ChatResult:
    body: JsonObject
    telemetry: PolicyTelemetry


class ChatService:
    def __init__(
        self,
        settings: Settings,
        upstream: Upstream,
    ) -> None:
        self.settings = settings
        self.upstream = upstream
        self.base_roles = configured_roles(settings)
        self.cache_namespace_fields = settings.cache_namespace_fields()

    async def complete(
        self,
        payload: JsonObject,
        request_headers: dict[str, str],
        *,
        harness_enabled: bool = True,
        policy_extensions_allowed: bool = False,
        trusted_policy_extension_used: bool = False,
        server_cache_namespace: ServerCacheNamespace | None = None,
    ) -> ChatResult:
        started = time.perf_counter()
        _validate_chat_payload(payload, harness_enabled=harness_enabled)
        try:
            reject_client_cache_namespaces(
                payload,
                mode=self.settings.upstream_cache_capability_mode,
                denied_fields=self.cache_namespace_fields,
                server_namespace=server_cache_namespace,
            )
        except ClientCacheNamespaceError as exc:
            raise ProxyError(
                400,
                "untrusted_cache_namespace",
                "Client-selected cache namespaces are not supported by this upstream profile.",
            ) from exc
        if payload.get("stream") is True:
            raise ProxyError(400, "streaming_not_supported", "stream=true is not supported by this proxy version.")

        forwarded = copy.deepcopy(payload)
        has_receipt_override = REQUIRE_RECEIPT_EXTENSION in forwarded
        require_receipt_override = forwarded.pop(REQUIRE_RECEIPT_EXTENSION, None)
        if has_receipt_override and not isinstance(require_receipt_override, bool):
            raise ProxyError(
                400,
                "invalid_receipt_override",
                f"{REQUIRE_RECEIPT_EXTENSION} must be a boolean when present.",
            )
        if require_receipt_override is False and not policy_extensions_allowed:
            raise ProxyError(
                403,
                "receipt_override_denied",
                "Receipt requirements cannot be disabled by this principal.",
            )
        try:
            tools, roles, role_extension_used = prepare_tools(
                forwarded.get("tools"),
                self.base_roles,
                policy_extensions_allowed=policy_extensions_allowed,
            )
        except PolicyAnnotationError as exc:
            raise ProxyError(exc.status_code, exc.code, str(exc)) from exc
        except ValueError as exc:
            raise ProxyError(400, "invalid_tools", str(exc)) from exc
        if "tools" in forwarded:
            forwarded["tools"] = tools
        policy_extension_used = (
            trusted_policy_extension_used or role_extension_used or require_receipt_override is False
        )

        contract = response_schema_contract(forwarded.get("response_format"))
        if (
            self.settings.upstream_tool_response_capability_mode == "phase_split"
            and tools
            and "response_format" in forwarded
            and not contract.strict_primitive_object
        ):
            raise ProxyError(
                400,
                "unsupported_phase_split_schema",
                "The selected upstream capability mode cannot safely enforce this response schema with tools.",
            )
        use_phase_split = requires_phase_split(
            self.settings.upstream_tool_response_capability_mode,
            has_tools=bool(tools),
            has_response_format="response_format" in forwarded,
            strict_schema_supported=contract.strict_primitive_object,
        )
        if not harness_enabled:
            if use_phase_split:
                return await self._complete_phase_split_without_harness(
                    forwarded,
                    request_headers,
                    started=started,
                    contract=contract,
                    policy_extension_used=policy_extension_used,
                )
            return _off_result(
                await self.upstream.chat(forwarded, request_headers),
                started,
                1,
                policy_extension_used,
            )
        available = {_tool_name(tool) for tool in tools}
        require_receipt = (
            self.settings.require_receipt_when_tools_present
            if require_receipt_override is None
            else require_receipt_override
        )
        try:
            rebuilt = reconstruct(
                forwarded["messages"],
                available_tools=available,
                roles=roles,
                contract=contract,
                require_receipt=bool(tools) and require_receipt,
            )
        except ValueError as exc:
            raise ProxyError(400, "invalid_messages", str(exc)) from exc
        harness = rebuilt.harness

        projection = _project_latest_if_current(forwarded["messages"], rebuilt)
        if projection is not None:
            body = _projected_response(str(forwarded.get("model", "")), projection)
            return ChatResult(
                body,
                _telemetry(
                    started,
                    harness,
                    0,
                    rebuilt,
                    receipt_projections=1,
                    local_projection_upstream_calls_avoided=1,
                    policy_extensions_used=int(policy_extension_used),
                ),
            )

        working_messages = _inject_harness(copy.deepcopy(forwarded["messages"]), harness, rebuilt)
        upstream_calls = 0
        internal_retries = 0
        phase: CapabilityPhase | None = "acquisition" if use_phase_split else None

        while upstream_calls < self.settings.max_upstream_calls:
            if use_phase_split and harness.force_finalize:
                phase = "finalization"
            attempt_payload = outbound_payload(forwarded, working_messages, phase=phase)
            if harness.force_finalize and not use_phase_split:
                attempt_payload["tool_choice"] = "none"
            with upstream_phase(phase):
                response = await self.upstream.chat(attempt_payload, request_headers)
            upstream_calls += 1
            message = _response_message(response)
            calls = message.get("tool_calls") or []

            if calls:
                if not isinstance(calls, list):
                    raise UpstreamFailure("upstream_malformed_tool_calls")
                if phase == "finalization":
                    if harness.terminal_corrections >= 2 or internal_retries >= self.settings.max_internal_retries:
                        break
                    internal_retries += 1
                    working_messages.append(
                        {
                            "role": "user",
                            "content": harness.correction(
                                "The finalization response cannot contain tool calls."
                            ),
                        }
                    )
                    continue
                rejected = _rejected_results(calls, harness)
                if not rejected:
                    return ChatResult(
                        _without_reserved_projection_marker(response),
                        _telemetry(
                            started,
                            harness,
                            upstream_calls,
                            rebuilt,
                            policy_extensions_used=int(policy_extension_used),
                        ),
                    )
                if internal_retries >= self.settings.max_internal_retries:
                    break
                internal_retries += 1
                working_messages.append(_assistant_turn(message, calls))
                for index, call in enumerate(calls):
                    call_id = call.get("id") if isinstance(call, dict) else None
                    if not isinstance(call_id, str) or not call_id:
                        call_id = f"shiftedx-invalid-{index}"
                    result = rejected.get(index) or json.dumps(
                        {
                            "shiftedx_harness": "response_withheld_due_to_blocked_sibling",
                            "instruction": "Reissue this call in a separate safe turn if it is still needed.",
                        },
                        separators=(",", ":"),
                    )
                    working_messages.append({"role": "tool", "tool_call_id": call_id, "content": result})
                working_messages.append({"role": "user", "content": harness.render()})
                continue

            content = message.get("content")
            if not isinstance(content, str):
                content = "" if content is None else json.dumps(content, separators=(",", ":"))
            normalized, changed = normalize_bare_json(content)
            if changed:
                message["content"] = normalized
                content = normalized
            issue = harness.terminal_issue(content)
            if issue is None:
                if phase == "acquisition":
                    phase = "finalization"
                    continue
                return ChatResult(
                    _without_reserved_projection_marker(response),
                    _telemetry(
                        started,
                        harness,
                        upstream_calls,
                        rebuilt,
                        policy_extensions_used=int(policy_extension_used),
                    ),
                )
            if harness.terminal_corrections >= 2 or internal_retries >= self.settings.max_internal_retries:
                break
            internal_retries += 1
            working_messages.append({"role": "assistant", "content": content})
            working_messages.append({"role": "user", "content": harness.correction(issue)})

        raise ProxyError(
            502,
            "harness_retry_exhausted",
            "The harness could not obtain a safe response within configured bounds.",
        )

    async def _complete_phase_split_without_harness(
        self,
        forwarded: JsonObject,
        request_headers: dict[str, str],
        *,
        started: float,
        contract: SchemaContract,
        policy_extension_used: bool,
    ) -> ChatResult:
        """Translate grammar phases without injecting harness state into opt-out traffic."""
        working_messages = copy.deepcopy(forwarded["messages"])
        phase: CapabilityPhase = "acquisition"
        upstream_calls = 0
        retries = 0
        while upstream_calls < self.settings.max_upstream_calls:
            attempt_payload = outbound_payload(forwarded, working_messages, phase=phase)
            with upstream_phase(phase):
                response = await self.upstream.chat(attempt_payload, request_headers)
            upstream_calls += 1
            message = _response_message(response)
            calls = message.get("tool_calls") or []
            if calls:
                if not isinstance(calls, list):
                    raise UpstreamFailure("upstream_malformed_tool_calls")
                if phase == "acquisition":
                    return _off_result(response, started, upstream_calls, policy_extension_used)
                if retries >= self.settings.max_internal_retries:
                    break
                retries += 1
                continue
            if phase == "acquisition":
                phase = "finalization"
                continue
            if _terminal_schema_issue(message, contract) is None:
                return _off_result(response, started, upstream_calls, policy_extension_used)
            if retries >= self.settings.max_internal_retries:
                break
            retries += 1
        raise ProxyError(
            502,
            "harness_retry_exhausted",
            "The harness could not obtain a safe response within configured bounds.",
        )


def _tool_name(tool: JsonObject) -> str:
    function = tool.get("function")
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        raise ProxyError(400, "invalid_tools", "Every tool must contain function.name.")
    return str(function["name"])


def _off_result(
    response: JsonObject, started: float, upstream_calls: int, policy_extension_used: bool
) -> ChatResult:
    return ChatResult(
        _without_reserved_projection_marker(response),
        PolicyTelemetry(
            "off",
            0,
            0,
            0,
            upstream_calls,
            (time.perf_counter() - started) * 1000,
            policy_extensions_used=int(policy_extension_used),
        ),
    )


def _terminal_schema_issue(message: JsonObject, contract: SchemaContract) -> str | None:
    content = message.get("content")
    if not isinstance(content, str):
        content = "" if content is None else json.dumps(content, separators=(",", ":"))
        message["content"] = content
    normalized, changed = normalize_bare_json(content)
    if changed:
        message["content"] = normalized
        content = normalized
    return bare_json_issue(content, contract.keys, contract.types)


def _validate_chat_payload(payload: JsonObject, *, harness_enabled: bool) -> None:
    """Validate proxy-consumed Chat Completions fields before any upstream call."""
    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ProxyError(400, "invalid_model", "model must be a non-empty string.")
    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise ProxyError(400, "invalid_messages", "messages must be an array.")
    for message in messages:
        _validate_message(message)
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise ProxyError(400, "invalid_stream", "stream must be a JSON boolean.")
    if harness_enabled and "n" in payload:
        n = payload["n"]
        if not isinstance(n, int) or isinstance(n, bool) or n != 1:
            raise ProxyError(400, "multiple_choices_not_supported", "Harness mode requires n=1.")
    if "tools" in payload:
        _validate_tool_schemas(payload["tools"])
    if "response_format" in payload:
        _validate_response_format(payload["response_format"])


def _validate_message(message: Any) -> None:
    if not isinstance(message, dict):
        raise ProxyError(400, "invalid_messages", "Every message must be an object.")
    role = message.get("role")
    if role not in {"system", "user", "assistant", "tool"}:
        raise ProxyError(400, "invalid_messages", "Every message role must be supported by v1.")
    content = message.get("content")
    if role in {"system", "user", "tool"} and "content" not in message:
        raise ProxyError(400, "invalid_messages", "System, user, and tool messages require content.")
    if role in {"system", "user", "tool"} and not isinstance(content, str | list):
        raise ProxyError(400, "invalid_messages", "Message content must be a string or content-part array.")
    if role == "assistant" and content is not None and not isinstance(content, str | list):
        raise ProxyError(400, "invalid_messages", "Assistant content must be a string, content-part array, or null.")
    if isinstance(content, list):
        _validate_content_parts(content)
    if "name" in message and (not isinstance(message["name"], str) or not message["name"].strip()):
        raise ProxyError(400, "invalid_messages", "Message name must be a non-empty string when present.")
    if role == "tool":
        call_id = message.get("tool_call_id")
        if not isinstance(call_id, str) or not call_id:
            raise ProxyError(400, "invalid_messages", "Tool messages require a non-empty tool_call_id.")
    if "tool_calls" in message:
        if role != "assistant" or not isinstance(message["tool_calls"], list):
            raise ProxyError(400, "invalid_messages", "tool_calls is supported only as an assistant array.")
        for call in message["tool_calls"]:
            _validate_tool_call(call)
    if role == "assistant" and not _has_usable_assistant_content(content):
        calls = message.get("tool_calls")
        if not isinstance(calls, list) or not calls:
            raise ProxyError(
                400,
                "invalid_messages",
                "Assistant messages require content or a non-empty valid tool_calls array.",
            )


def _validate_content_parts(parts: list[Any]) -> None:
    if not parts or any(
        not isinstance(part, dict)
        or not isinstance(part.get("type"), str)
        or not part["type"].strip()
        for part in parts
    ):
        raise ProxyError(
            400,
            "invalid_messages",
            "Content-part arrays must contain objects with non-empty string types.",
        )


def _has_usable_assistant_content(content: Any) -> bool:
    if isinstance(content, str):
        return bool(content.strip())
    return isinstance(content, list) and bool(content)


def _validate_tool_call(call: Any) -> None:
    if not isinstance(call, dict):
        raise ProxyError(400, "invalid_messages", "Every tool call must be an object.")
    function = call.get("function")
    if (
        not isinstance(call.get("id"), str)
        or not call["id"]
        or call.get("type") != "function"
        or not isinstance(function, dict)
        or not isinstance(function.get("name"), str)
        or not function["name"].strip()
        or not isinstance(function.get("arguments"), str)
    ):
        raise ProxyError(400, "invalid_messages", "Assistant tool calls must be complete function calls.")


def _validate_tool_schemas(tools: Any) -> None:
    if not isinstance(tools, list):
        raise ProxyError(400, "invalid_tools", "tools must be an array.")
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if (
            not isinstance(tool, dict)
            or tool.get("type") != "function"
            or not isinstance(function, dict)
            or not isinstance(function.get("name"), str)
            or not function["name"].strip()
            or ("parameters" in function and not isinstance(function["parameters"], dict))
        ):
            raise ProxyError(400, "invalid_tools", "Every tool must be a function schema with function.name.")


def _validate_response_format(response_format: Any) -> None:
    if not isinstance(response_format, dict):
        raise ProxyError(400, "invalid_response_format", "response_format must be an object.")
    type_name = response_format.get("type")
    if not isinstance(type_name, str) or not type_name.strip():
        raise ProxyError(400, "invalid_response_format", "response_format.type must be a non-empty string.")
    if type_name != "json_schema":
        return
    wrapper = response_format.get("json_schema")
    if not isinstance(wrapper, dict):
        raise ProxyError(400, "invalid_response_format", "json_schema response_format requires an object wrapper.")
    schema = wrapper.get("schema")
    if not isinstance(schema, dict):
        raise ProxyError(400, "invalid_response_format", "json_schema response_format requires an object schema.")
    if schema.get("type") == "object" and "properties" in schema and not isinstance(schema["properties"], dict):
        raise ProxyError(
            400,
            "invalid_response_format",
            "json_schema object properties must be an object when present.",
        )


def _inject_harness(messages: list[Any], harness: AgentHarness, rebuilt: Reconstruction) -> list[Any]:
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "system" and isinstance(message.get("content"), str):
            if HARNESS_SYSTEM_SUFFIX not in message["content"]:
                message["content"] += HARNESS_SYSTEM_SUFFIX
            break
    else:
        messages.insert(0, {"role": "system", "content": HARNESS_SYSTEM_SUFFIX.strip()})
    state = harness.render()
    if rebuilt.degraded:
        state += " Transcript state is degraded due to incomplete or invalid call/result pairing."
    messages.append({"role": "user", "content": state})
    return messages


def _response_message(response: JsonObject) -> JsonObject:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise UpstreamFailure("upstream_malformed_completion")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise UpstreamFailure("upstream_malformed_completion")
    return message


def _assistant_turn(message: JsonObject, calls: list[Any]) -> JsonObject:
    turn: JsonObject = {"role": "assistant", "content": message.get("content") or "", "tool_calls": calls}
    return turn


def _call_arguments(call: JsonObject) -> tuple[str, dict[str, Any]]:
    function = call.get("function")
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        raise ValueError("invalid function")
    raw = function.get("arguments", {})
    arguments = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(arguments, dict):
        raise ValueError("arguments are not an object")
    return str(function["name"]), arguments


def _rejected_results(calls: list[Any], harness: AgentHarness) -> dict[int, str]:
    rejected: dict[int, str] = {}
    every_rejection_can_finalize = True
    for index, raw_call in enumerate(calls):
        if not isinstance(raw_call, dict):
            harness.last_action_blocked = True
            every_rejection_can_finalize = False
            rejected[index] = '{"shiftedx_harness":"invalid_tool_call"}'
            continue
        try:
            name, arguments = _call_arguments(raw_call)
        except (ValueError, TypeError, json.JSONDecodeError):
            harness.last_action_blocked = True
            every_rejection_can_finalize = False
            rejected[index] = '{"shiftedx_harness":"invalid_tool_arguments"}'
            continue
        stalled = harness.stalled_result(name)
        prior = harness.duplicate(name, arguments) if stalled is None else None
        if stalled is not None:
            every_rejection_can_finalize = False
            rejected[index] = stalled
        elif prior is not None:
            rejected[index] = harness.blocked_result(prior)
            if prior.status != "success" or harness.pending_verification or harness.open_failures:
                every_rejection_can_finalize = False
    harness.force_finalize = bool(rejected) and len(rejected) == len(calls) and every_rejection_can_finalize
    return rejected


def _project_latest_if_current(messages: Any, rebuilt: Reconstruction) -> str | None:
    if (
        not isinstance(messages, list)
        or not messages
        or not isinstance(messages[-1], dict)
        or messages[-1].get("role") != "tool"
        or rebuilt.latest_tool is None
        or rebuilt.latest_result is None
    ):
        return None
    return rebuilt.harness.project_final(rebuilt.latest_tool, rebuilt.latest_result)


def _projected_response(model: str, content: str) -> JsonObject:
    return {
        "id": f"chatcmpl-shiftedx-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        LOCAL_PROJECTION_EXTENSION: local_projection_accounting(),
    }


def _without_reserved_projection_marker(response: JsonObject) -> JsonObject:
    """Reserve the proxy-owned marker so an upstream cannot spoof Local Projection."""
    sanitized = dict(response)
    sanitized.pop(LOCAL_PROJECTION_EXTENSION, None)
    return sanitized


def _telemetry(
    started: float,
    harness: AgentHarness,
    upstream_calls: int,
    rebuilt: Reconstruction,
    *,
    receipt_projections: int = 0,
    local_projection_upstream_calls_avoided: int = 0,
    policy_extensions_used: int = 0,
) -> PolicyTelemetry:
    return PolicyTelemetry(
        profile=self_profile(harness),
        blocked_duplicates=harness.blocked_duplicates,
        blocked_stalls=harness.blocked_stalls,
        corrections=harness.terminal_corrections,
        upstream_calls=upstream_calls,
        policy_wall_ms=(time.perf_counter() - started) * 1000,
        receipt_projections=receipt_projections,
        local_projection_upstream_calls_avoided=local_projection_upstream_calls_avoided,
        degraded_state=rebuilt.degraded,
        policy_extensions_used=policy_extensions_used,
    )


def self_profile(_harness: AgentHarness) -> str:
    return "shiftedx-harness-v1"
