"""Policy-safe OpenAI Chat Completions validate-then-replay SSE."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from .errors import ProxyError

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class ReplayOptions:
    include_usage: bool = False


def prepare_replay_request(payload: JsonObject) -> tuple[JsonObject, ReplayOptions | None]:
    """Consume downstream streaming controls and return the buffered policy request."""
    if payload.get("stream") is not True:
        return payload, None
    options = payload.get("stream_options", {})
    if not isinstance(options, dict):
        raise ProxyError(400, "invalid_stream_options", "stream_options must be an object when present.")
    include_usage = options.get("include_usage", False)
    if not isinstance(include_usage, bool):
        raise ProxyError(
            400,
            "invalid_stream_options",
            "stream_options.include_usage must be a JSON boolean when present.",
        )
    buffered = copy.deepcopy(payload)
    buffered.pop("stream", None)
    buffered.pop("stream_options", None)
    return buffered, ReplayOptions(include_usage=include_usage)


def replay_completion(completion: JsonObject, options: ReplayOptions) -> bytes:
    """Serialize one already-approved completion as standards-compatible SSE."""
    choices = completion.get("choices")
    if not isinstance(choices, list):
        raise ProxyError(502, "upstream_malformed_completion", "The upstream completion is malformed.")
    events: list[JsonObject] = []
    for raw_choice in choices:
        if not isinstance(raw_choice, dict):
            raise ProxyError(502, "upstream_malformed_completion", "The upstream completion is malformed.")
        message = raw_choice.get("message")
        if not isinstance(message, dict):
            raise ProxyError(502, "upstream_malformed_completion", "The upstream completion is malformed.")
        index = raw_choice.get("index", 0)
        delta = {
            key: copy.deepcopy(value)
            for key, value in message.items()
            if key not in {"refusal", "tool_calls"} and value is not None
        }
        tool_calls = message.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, list) or not all(isinstance(call, dict) for call in tool_calls):
                raise ProxyError(502, "upstream_malformed_completion", "The upstream completion is malformed.")
            delta["tool_calls"] = [
                {"index": index, **copy.deepcopy(call)} for index, call in enumerate(tool_calls)
            ]
        if message.get("refusal") is not None:
            delta["refusal"] = copy.deepcopy(message["refusal"])
        events.append(_chunk(completion, index=index, delta=delta, finish_reason=None))
        events.append(
            _chunk(
                completion,
                index=index,
                delta={},
                finish_reason=raw_choice.get("finish_reason"),
            )
        )
    if options.include_usage and isinstance(completion.get("usage"), dict):
        usage_event = _chunk_base(completion)
        usage_event["choices"] = []
        usage_event["usage"] = copy.deepcopy(completion["usage"])
        events.append(usage_event)
    serialized = b"".join(
        b"data: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode() + b"\n\n"
        for event in events
    )
    return serialized + b"data: [DONE]\n\n"


def _chunk(completion: JsonObject, *, index: object, delta: JsonObject, finish_reason: object) -> JsonObject:
    event = _chunk_base(completion)
    event["choices"] = [{"index": index, "delta": delta, "finish_reason": finish_reason}]
    return event


def _chunk_base(completion: JsonObject) -> JsonObject:
    event: JsonObject = {
        "id": completion.get("id"),
        "object": "chat.completion.chunk",
        "model": completion.get("model"),
    }
    for key in ("created", "system_fingerprint", "service_tier", "x-shiftedx-projection-v1"):
        if key in completion:
            event[key] = copy.deepcopy(completion[key])
    return event
