import asyncio
import threading
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse

app = FastAPI()

_PHASE_SPLIT_MODEL = "phase-split-smoke"
_MALFORMED_STREAM_BLOCKED_FRAGMENT = "blocked-fragment-must-not-be-released"
_PHASE_SPLIT_TOOLS = [{"type": "function", "function": {"name": "read_file", "parameters": {}}}]
_PHASE_SPLIT_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "smoke_result",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {"status": {"type": "string"}},
            "required": ["status"],
            "additionalProperties": False,
        },
    },
}
_phase_split_step = 0
_ledger_lock = threading.Lock()
_ledger: dict[str, Any] = {"requests": 0, "proxied_attempts": 0, "active": 0, "max_active": 0, "attempts": {}}


def _observe_request(request_id: str | None) -> None:
    with _ledger_lock:
        _ledger["requests"] += 1
        if request_id is not None:
            attempts = _ledger["attempts"]
            attempts[request_id] = attempts.get(request_id, 0) + 1
            if request_id.startswith("shiftedx-"):
                _ledger["proxied_attempts"] += 1
        _ledger["active"] += 1
        _ledger["max_active"] = max(_ledger["max_active"], _ledger["active"])


def _finish_request() -> None:
    with _ledger_lock:
        _ledger["active"] -= 1


@app.post("/v1/qualification/reset")
async def reset_ledger() -> dict[str, str]:
    with _ledger_lock:
        _ledger.update({"requests": 0, "proxied_attempts": 0, "active": 0, "max_active": 0, "attempts": {}})
    return {"status": "reset"}


@app.get("/v1/qualification/ledger")
async def ledger() -> dict[str, Any]:
    with _ledger_lock:
        return {
            "requests": _ledger["requests"],
            "proxied_attempts": _ledger["proxied_attempts"],
            "active": _ledger["active"],
            "max_active": _ledger["max_active"],
            "attempts": dict(_ledger["attempts"]),
        }


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    return {"object": "list", "data": [{"id": "fake-model", "object": "model"}]}


@app.post("/v1/chat/completions")
async def chat(payload: dict[str, Any], request: Request) -> Any:
    _observe_request(request.headers.get("x-request-id"))
    try:
        return await _chat(payload)
    finally:
        _finish_request()


async def _chat(payload: dict[str, Any]):  # type: ignore[no-untyped-def]
    if payload.get("model") == _PHASE_SPLIT_MODEL:
        return _phase_split_response(payload)
    model = payload.get("model")
    if model == "fault-429":
        raise HTTPException(status_code=429, detail="qualification_rate_limited")
    if model == "fault-500":
        raise HTTPException(status_code=500, detail="qualification_server_error")
    if model == "fault-malformed":
        return PlainTextResponse("not-json", media_type="text/plain")
    if model == "fault-malformed-stream":
        async def malformed_events() -> AsyncIterator[bytes]:
            # A valid-looking early delta followed by invalid JSON proves the proxy
            # does not release a blocked fragment before it validates the stream.
            yield (
                b'data: {"id":"chatcmpl-malformed","object":"chat.completion.chunk",'
                b'"model":"fake-model","choices":[{"index":0,"delta":{"content":"'
                + _MALFORMED_STREAM_BLOCKED_FRAGMENT.encode()
                + b'"},"finish_reason":null}]}\n\n'
            )
            yield b'data: {"id":"chatcmpl-malformed","choices":[\n\n'

        return StreamingResponse(malformed_events(), media_type="text/event-stream")
    if model == "fault-timeout":
        delay = payload.get("qualification_delay_seconds", 4)
        if isinstance(delay, bool) or not isinstance(delay, int | float) or not 0 < delay <= 3601:
            raise HTTPException(status_code=422, detail="qualification_timeout_delay_invalid")
        await asyncio.sleep(delay)
    if model == "fault-disconnect":

        async def disconnected() -> AsyncIterator[bytes]:
            yield b'{"id":"partial"'
            raise RuntimeError("qualification_disconnect")

        return StreamingResponse(disconnected(), media_type="application/json")
    if model == "slow-response":
        await asyncio.sleep(0.4)
    if model == "slow-success":
        await asyncio.sleep(1.5)
    if model == "slow-stream":
        await asyncio.sleep(0.25)
    content = "fake upstream ready"
    if model == "oversized-response":
        content = "x" * 4096
    completion = {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 0,
        "model": model or "fake-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }
    if payload.get("stream") is True:

        async def events() -> AsyncIterator[bytes]:
            yield (
                b'data: {"id":"chatcmpl-fake","object":"chat.completion.chunk",'
                b'"model":"fake-model","choices":[{"index":0,"delta":{"content":'
                b'"fake upstream ready"},"finish_reason":null}]}\n\n'
            )
            yield (
                b'data: {"id":"chatcmpl-fake","object":"chat.completion.chunk",'
                b'"model":"fake-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
            )
            yield b"data: [DONE]\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")
    return completion


def _phase_split_response(payload: dict[str, Any]) -> dict[str, Any]:
    global _phase_split_step
    if _phase_split_step == 0:
        if (
            payload.get("tools") != _PHASE_SPLIT_TOOLS
            or payload.get("tool_choice") != "auto"
            or "response_format" in payload
        ):
            raise HTTPException(status_code=422, detail="smoke_phase_split_acquisition_invalid")
        _phase_split_step = 1
        return {
            "id": "chatcmpl-smoke-acquisition",
            "object": "chat.completion",
            "model": _PHASE_SPLIT_MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "smoke-repeat",
                                "type": "function",
                                "function": {"name": "read_file", "arguments": "{}"},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
    if (
        _phase_split_step != 1
        or payload.get("response_format") != _PHASE_SPLIT_RESPONSE_FORMAT
        or any(name in payload for name in ("tools", "tool_choice", "parallel_tool_calls"))
    ):
        raise HTTPException(status_code=422, detail="smoke_phase_split_finalization_invalid")
    _phase_split_step = 2
    return {
        "id": "chatcmpl-smoke-finalization",
        "object": "chat.completion",
        "model": _PHASE_SPLIT_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": '{"status":"ready"}'},
                "finish_reason": "stop",
            }
        ],
    }
