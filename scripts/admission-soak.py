"""Deterministic admission soak with real HTTP connections for CI and smoke."""

from __future__ import annotations

import asyncio
import json
import resource
import sys
from collections.abc import Callable

import httpx

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings


class TcpUpstream:
    """A real TCP upstream that measures concurrent open HTTP connections."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.active = 0
        self.maximum_open_connections = 0
        self.started = asyncio.Event()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.active += 1
        self.maximum_open_connections = max(self.maximum_open_connections, self.active)
        self.started.set()
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            content_length = next(
                (
                    int(line.split(b":", 1)[1].strip())
                    for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            if content_length:
                await reader.readexactly(content_length)
            await self.release.wait()
            body = json.dumps(
                {"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": "ok"}}]}
            ).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            self.active -= 1
            writer.close()
            await writer.wait_closed()


def _rss_bytes() -> int:
    scale = 1 if sys.platform == "darwin" else 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale


async def _wait_until(predicate: Callable[[], bool], *, timeout: float = 1) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("soak condition did not become true")
        await asyncio.sleep(0.001)


async def _run() -> None:
    upstream = TcpUpstream()
    server = await asyncio.start_server(upstream.handle, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    settings = Settings(
        upstream_base_url=f"http://127.0.0.1:{port}/v1",
        admission_limit=4,
        admission_wait_seconds=0.02,
        concurrency_limit=2,
        concurrency_wait_seconds=1,
        principal_concurrency_limit=8,
        principal_rate_limit=20,
        total_request_deadline_seconds=2,
    )
    app = create_app(settings)
    before = _rss_bytes()
    payload = {"model": "model", "messages": [{"role": "user", "content": ""}]}
    base = json.dumps(payload, separators=(",", ":")).encode()
    payload["messages"][0]["content"] = "x" * (settings.max_request_bytes - len(base))
    body = json.dumps(payload, separators=(",", ":")).encode()
    assert len(body) <= settings.max_request_bytes
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://proxy"
            ) as client:
                for _ in range(3):
                    upstream.release.clear()
                    upstream.started.clear()
                    admitted = [
                        asyncio.create_task(
                            client.post(
                                "/v1/chat/completions",
                                content=body,
                                headers={"Content-Type": "application/json"},
                            )
                        )
                        for _ in range(4)
                    ]
                    await _wait_until(lambda: app.state.admission.snapshot().active == settings.admission_limit)
                    await _wait_until(lambda: upstream.active == settings.concurrency_limit)
                    overloaded = await client.post(
                        "/v1/chat/completions", content=body, headers={"Content-Type": "application/json"}
                    )
                    assert overloaded.status_code == 429
                    assert overloaded.headers["retry-after"] == "1"
                    upstream.release.set()
                    responses = await asyncio.gather(*admitted)
                    assert all(response.status_code == 200 for response in responses)
                    assert app.state.admission.snapshot().active == 0
                    assert app.state.admission.snapshot().upstream_active == 0
    finally:
        server.close()
        await server.wait_closed()
    assert upstream.maximum_open_connections <= settings.concurrency_limit
    envelope = max(64 * 1024 * 1024, settings.max_request_bytes * settings.admission_limit * 8)
    delta = _rss_bytes() - before
    assert delta <= envelope
    print(f"admission_soak rss_delta_bytes={delta} max_open_connections={upstream.maximum_open_connections}")


if __name__ == "__main__":
    asyncio.run(_run())
