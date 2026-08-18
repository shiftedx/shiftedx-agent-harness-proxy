from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.transport import HttpxUpstream


class EchoUpstream:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        return {
            "id": "chatcmpl",
            "object": "chat.completion",
            "model": payload.get("model"),
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
            ],
        }

    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        return {"object": "list", "data": [{"id": "model", "object": "model"}]}

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_http_surface_auth_health_streaming_and_unknown_request_passthrough() -> None:
    upstream = EchoUpstream()
    settings = Settings(
        upstream_base_url="http://upstream/v1",
        proxy_api_key=SecretStr("downstream-secret"),
        telemetry_enabled=True,
    )
    app = create_app(settings, upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            assert (await client.get("/healthz")).status_code == 200
            assert (await client.post("/v1/chat/completions", json={})).status_code == 401
            headers = {"Authorization": "Bearer downstream-secret"}
            streamed = await client.post(
                "/v1/chat/completions",
                headers=headers,
                json={"model": "model", "messages": [], "stream": True},
            )
            assert streamed.status_code == 400
            response = await client.post(
                "/v1/chat/completions",
                headers=headers,
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "seed": 42,
                    "vendor_extension": {"preserve": True},
                },
            )
            assert response.status_code == 200
            assert response.headers["x-shiftedx-upstream-calls"] == "1"
            assert upstream.requests[-1]["seed"] == 42
            assert upstream.requests[-1]["vendor_extension"] == {"preserve": True}
            assert (await client.get("/readyz")).json() == {"status": "ready"}
            metrics = await client.get("/metrics", headers=headers)
            assert "shiftedx_proxy_downstream_requests_total 1" in metrics.text


@pytest.mark.asyncio
async def test_downstream_authorization_is_never_forwarded_upstream() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            },
        )

    settings = Settings(
        upstream_base_url="http://upstream/v1",
        upstream_api_key=SecretStr("upstream-secret"),
        proxy_api_key=SecretStr("downstream-secret"),
    )
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = HttpxUpstream(settings, mock_client)
    app = create_app(settings, upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer downstream-secret", "Cookie": "private=value"},
                json={"model": "model", "messages": [{"role": "user", "content": "hello"}]},
            )
    await mock_client.aclose()
    assert response.status_code == 200
    assert captured["authorization"] == "Bearer upstream-secret"
    assert "cookie" not in captured


@pytest.mark.asyncio
async def test_request_size_and_opt_out_are_denied_by_default() -> None:
    upstream = EchoUpstream()
    settings = Settings(upstream_base_url="http://upstream/v1", max_request_bytes=1024)
    app = create_app(settings, upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            too_large = await client.post(
                "/v1/chat/completions",
                content=b"{" + b"x" * 2048 + b"}",
                headers={"content-type": "application/json"},
            )
            opt_out = await client.post(
                "/v1/chat/completions",
                headers={"X-Shiftedx-Harness": "off"},
                json={"model": "model", "messages": []},
            )
    assert too_large.status_code == 413
    assert opt_out.status_code == 403


@pytest.mark.asyncio
async def test_incomplete_transcript_is_signaled_and_proxy_annotations_are_not_forwarded() -> None:
    class ToolUpstream(EchoUpstream):
        async def chat(
            self, payload: dict[str, Any], request_headers: dict[str, str]
        ) -> dict[str, Any]:
            self.requests.append(payload)
            return {
                "id": "chatcmpl",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "safe",
                                    "type": "function",
                                    "function": {"name": "inspect", "arguments": "{}"},
                                }
                            ],
                        }
                    }
                ],
            }

    upstream = ToolUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [
                        {"role": "user", "content": "inspect"},
                        {"role": "tool", "tool_call_id": "missing", "content": "orphan"},
                    ],
                    "tools": [
                        {
                            "type": "function",
                            "x-shiftedx-role": "investigation",
                            "vendor_extension": "keep",
                            "function": {"name": "inspect", "parameters": {}},
                        }
                    ],
                },
            )
    assert response.status_code == 200
    assert response.headers["x-shiftedx-state"] == "degraded"
    assert "x-shiftedx-role" not in upstream.requests[0]["tools"][0]
    assert upstream.requests[0]["tools"][0]["vendor_extension"] == "keep"
