from typing import Any

from fastapi import FastAPI, HTTPException

app = FastAPI()

_PHASE_SPLIT_MODEL = "phase-split-smoke"
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


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    return {"object": "list", "data": [{"id": "fake-model", "object": "model"}]}


@app.post("/v1/chat/completions")
async def chat(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("model") == _PHASE_SPLIT_MODEL:
        return _phase_split_response(payload)
    content = "fake upstream ready"
    if payload.get("model") == "oversized-response":
        content = "x" * 4096
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 0,
        "model": payload.get("model", "fake-model"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


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
