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


def replay_completion(
    completion: JsonObject, options: ReplayOptions, *, max_bytes: int | None = None
) -> tuple[bytes, ...]:
    """Serialize one already-approved completion as standards-compatible SSE."""
    if not isinstance(completion.get("id"), str) or not completion["id"]:
        raise _malformed_completion()
    if not isinstance(completion.get("model"), str) or not completion["model"]:
        raise _malformed_completion()
    choices = completion.get("choices")
    if not isinstance(choices, list) or not choices:
        raise _malformed_completion()
    chunks: list[bytes] = []
    total_bytes = 0

    def append(event: JsonObject) -> None:
        nonlocal total_bytes
        chunk = b"data: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode() + b"\n\n"
        total_bytes += len(chunk)
        if max_bytes is not None and total_bytes > max_bytes:
            raise ProxyError(
                502,
                "upstream_response_too_large",
                "The upstream response exceeds the configured response size limit.",
            )
        chunks.append(chunk)

    for raw_choice in choices:
        if not isinstance(raw_choice, dict):
            raise _malformed_completion()
        message = raw_choice.get("message")
        if not isinstance(message, dict):
            raise _malformed_completion()
        index = raw_choice.get("index")
        finish_reason = raw_choice.get("finish_reason")
        if isinstance(index, bool) or not isinstance(index, int):
            raise _malformed_completion()
        if not isinstance(finish_reason, str) or not finish_reason:
            raise _malformed_completion()
        delta = {
            key: copy.deepcopy(value)
            for key, value in message.items()
            if key not in {"refusal", "tool_calls"} and value is not None
        }
        tool_calls = message.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, list) or not all(isinstance(call, dict) for call in tool_calls):
                raise _malformed_completion()
            delta["tool_calls"] = [
                {"index": index, **copy.deepcopy(call)} for index, call in enumerate(tool_calls)
            ]
        if message.get("refusal") is not None:
            delta["refusal"] = copy.deepcopy(message["refusal"])
        append(_chunk(completion, index=index, delta=delta, finish_reason=None))
        append(
            _chunk(
                completion,
                index=index,
                delta={},
                finish_reason=finish_reason,
            )
        )
    if options.include_usage and isinstance(completion.get("usage"), dict):
        usage_event = _chunk_base(completion)
        usage_event["choices"] = []
        usage_event["usage"] = copy.deepcopy(completion["usage"])
        append(usage_event)
    done = b"data: [DONE]\n\n"
    if max_bytes is not None and total_bytes + len(done) > max_bytes:
        raise ProxyError(
            502,
            "upstream_response_too_large",
            "The upstream response exceeds the configured response size limit.",
        )
    return (*chunks, done)


def _malformed_completion() -> ProxyError:
    return ProxyError(502, "upstream_malformed_completion", "The upstream completion is malformed.")


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
