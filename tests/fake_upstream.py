from typing import Any

from fastapi import FastAPI

app = FastAPI()


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    return {"object": "list", "data": [{"id": "fake-model", "object": "model"}]}


@app.post("/v1/chat/completions")
async def chat(payload: dict[str, Any]) -> dict[str, Any]:
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
