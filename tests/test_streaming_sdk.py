from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx2
import pytest
import uvicorn
from openai import AsyncOpenAI, OpenAI

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings


class CompletionUpstream:
    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        return {
            "id": "chatcmpl-sdk",
            "object": "chat.completion",
            "model": payload["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "SDK compatible"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
        }

    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        return {"object": "list", "data": []}

    async def combined_tool_terminal_schema_supported(self) -> bool:
        return False

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


@contextmanager
def running_app() -> Iterator[str]:
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), CompletionUpstream())
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("test server did not start")
    try:
        yield f"http://127.0.0.1:{port}/v1"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("test server did not stop")


def test_openai_sync_sdk_assembles_validate_then_replay_stream() -> None:
    with running_app() as base_url:
        with OpenAI(base_url=base_url, api_key="test", max_retries=0) as client:
            stream = client.chat.completions.create(
                model="model",
                messages=[{"role": "user", "content": "hello"}],
                stream=True,
                stream_options={"include_usage": True},
            )
            chunks = list(stream)

    assert "".join(chunk.choices[0].delta.content or "" for chunk in chunks if chunk.choices) == (
        "SDK compatible"
    )
    assert next(chunk for chunk in chunks if not chunk.choices).usage.total_tokens == 4


@pytest.mark.asyncio
async def test_openai_async_sdk_assembles_validate_then_replay_stream() -> None:
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), CompletionUpstream())
    http_client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://proxy")
    client = AsyncOpenAI(
        base_url="http://proxy/v1",
        api_key="test",
        max_retries=0,
        http_client=http_client,
    )
    async with app.router.lifespan_context(app):
        stream = await client.chat.completions.create(
            model="model",
            messages=[{"role": "user", "content": "hello"}],
            stream=True,
            stream_options={"include_usage": True},
        )
        chunks = [chunk async for chunk in stream]
    await client.close()

    assert "".join(chunk.choices[0].delta.content or "" for chunk in chunks if chunk.choices) == (
        "SDK compatible"
    )
    assert next(chunk for chunk in chunks if not chunk.choices).usage.total_tokens == 4
