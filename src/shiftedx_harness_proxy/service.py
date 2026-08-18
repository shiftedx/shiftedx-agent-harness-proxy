"""Bounded non-streaming Chat Completions policy loop."""

from __future__ import annotations

import copy
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .config import Settings, configured_roles
from .core import HARNESS_SYSTEM_SUFFIX, AgentHarness, normalize_bare_json
from .errors import ProxyError, UpstreamFailure
from .transcript import Reconstruction, prepare_tools, reconstruct, response_schema_contract
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
    degraded_state: bool = False


@dataclass(frozen=True)
class ChatResult:
    body: JsonObject
    telemetry: PolicyTelemetry


class ChatService:
    def __init__(self, settings: Settings, upstream: Upstream) -> None:
        self.settings = settings
        self.upstream = upstream
        self.base_roles = configured_roles(settings)

    async def complete(
        self,
        payload: JsonObject,
        request_headers: dict[str, str],
        *,
        harness_enabled: bool = True,
    ) -> ChatResult:
        started = time.perf_counter()
        if payload.get("stream") is True:
            raise ProxyError(400, "streaming_not_supported", "stream=true is not supported by this proxy version.")
        if "messages" not in payload:
            raise ProxyError(400, "invalid_request", "messages is required.")

        forwarded = copy.deepcopy(payload)
        has_receipt_override = REQUIRE_RECEIPT_EXTENSION in forwarded
        require_receipt_override = forwarded.pop(REQUIRE_RECEIPT_EXTENSION, None)
        if has_receipt_override and not isinstance(require_receipt_override, bool):
            raise ProxyError(
                400,
                "invalid_request",
                f"{REQUIRE_RECEIPT_EXTENSION} must be a boolean when present.",
            )
        try:
            tools, roles = prepare_tools(forwarded.get("tools"), self.base_roles)
        except ValueError as exc:
            raise ProxyError(400, "invalid_tools", str(exc)) from exc
        if "tools" in forwarded:
            forwarded["tools"] = tools

        if not harness_enabled:
            body = await self.upstream.chat(forwarded, request_headers)
            return ChatResult(
                body,
                PolicyTelemetry("off", 0, 0, 0, 1, (time.perf_counter() - started) * 1000),
            )
        if payload.get("n", 1) != 1:
            raise ProxyError(400, "multiple_choices_not_supported", "Harness mode requires n=1.")

        contract = response_schema_contract(forwarded.get("response_format"))
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
                _telemetry(started, harness, 0, rebuilt, receipt_projections=1),
            )

        working_messages = _inject_harness(copy.deepcopy(forwarded["messages"]), harness, rebuilt)
        forwarded["messages"] = working_messages
        upstream_calls = 0
        internal_retries = 0

        while upstream_calls < self.settings.max_upstream_calls:
            if harness.force_finalize:
                forwarded["tool_choice"] = "none"
            response = await self.upstream.chat(forwarded, request_headers)
            upstream_calls += 1
            message = _response_message(response)
            calls = message.get("tool_calls") or []

            if calls:
                if not isinstance(calls, list):
                    raise UpstreamFailure("upstream_malformed_tool_calls")
                rejected = _rejected_results(calls, harness)
                if not rejected:
                    return ChatResult(response, _telemetry(started, harness, upstream_calls, rebuilt))
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
                return ChatResult(response, _telemetry(started, harness, upstream_calls, rebuilt))
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


def _tool_name(tool: JsonObject) -> str:
    function = tool.get("function")
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        raise ProxyError(400, "invalid_tools", "Every tool must contain function.name.")
    return str(function["name"])


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
    }


def _telemetry(
    started: float,
    harness: AgentHarness,
    upstream_calls: int,
    rebuilt: Reconstruction,
    *,
    receipt_projections: int = 0,
) -> PolicyTelemetry:
    return PolicyTelemetry(
        profile=self_profile(harness),
        blocked_duplicates=harness.blocked_duplicates,
        blocked_stalls=harness.blocked_stalls,
        corrections=harness.terminal_corrections,
        upstream_calls=upstream_calls,
        policy_wall_ms=(time.perf_counter() - started) * 1000,
        receipt_projections=receipt_projections,
        degraded_state=rebuilt.degraded,
    )


def self_profile(_harness: AgentHarness) -> str:
    return "shiftedx-harness-v1"
