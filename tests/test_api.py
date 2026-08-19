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
            assert (await client.get("/v1/models")).status_code == 401
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


@pytest.mark.asyncio
async def test_policy_extensions_require_a_server_configured_authenticated_capability() -> None:
    upstream = EchoUpstream()
    settings = Settings(
        upstream_base_url="http://upstream/v1",
        deployment_profile="production",
        proxy_api_key=SecretStr("ordinary-client"),
        trusted_policy_extension_api_keys=SecretStr("trusted-extension"),
    )
    app = create_app(settings, upstream)
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "refuse"}],
        "tools": [
            {
                "type": "function",
                "function": {"name": "apply_patch", "parameters": {}},
            }
        ],
        "x-shiftedx-require-receipt": False,
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            ordinary = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer ordinary-client"},
                json=payload,
            )
            forged_header = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer ordinary-client",
                    "X-Shiftedx-Policy-Extension": "trusted",
                },
                json=payload,
            )
            trusted = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer trusted-extension"},
                json=payload,
            )
            metrics = await client.get("/metrics", headers={"Authorization": "Bearer ordinary-client"})
    assert ordinary.status_code == 403
    assert ordinary.json()["error"]["code"] == "receipt_override_denied"
    assert forged_header.status_code == 403
    assert trusted.status_code == 200
    assert "x-shiftedx-require-receipt" not in upstream.requests[-1]
    assert "shiftedx_proxy_policy_extension_allows_total 1" in metrics.text
    assert "shiftedx_proxy_policy_extension_denials_total 2" in metrics.text


@pytest.mark.asyncio
async def test_harness_opt_out_requires_server_enablement_and_a_trusted_principal() -> None:
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(dict(request.headers))
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl",
                "choices": [
                    {"message": {"role": "assistant", "content": "first"}},
                    {"message": {"role": "assistant", "content": "second"}},
                ],
            },
        )

    settings = Settings(
        upstream_base_url="http://upstream/v1",
        deployment_profile="production",
        proxy_api_key=SecretStr("ordinary-client"),
        trusted_policy_extension_api_keys=SecretStr("trusted-extension"),
        allow_harness_opt_out=True,
    )
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(settings, HttpxUpstream(settings, mock_client))
    payload = {"model": "model", "messages": [], "n": 2}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            ordinary = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer ordinary-client",
                    "X-Shiftedx-Harness": "off",
                },
                json=payload,
            )
            forged_header = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer ordinary-client",
                    "X-Shiftedx-Harness": "off",
                    "X-Shiftedx-Policy-Extension": "trusted",
                },
                json=payload,
            )
            assert captured == []
            trusted = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer trusted-extension",
                    "X-Shiftedx-Harness": "off",
                },
                json=payload,
            )
            metrics = await client.get("/metrics", headers={"Authorization": "Bearer ordinary-client"})
    await mock_client.aclose()

    assert ordinary.status_code == 403
    assert ordinary.json()["error"]["code"] == "harness_opt_out_denied"
    assert forged_header.status_code == 403
    assert forged_header.json()["error"]["code"] == "harness_opt_out_denied"
    assert trusted.status_code == 200
    assert len(captured) == 1
    assert captured[0].get("x-shiftedx-harness") is None
    assert captured[0].get("x-shiftedx-policy-extension") is None
    assert captured[0].get("authorization") is None
    assert "shiftedx_proxy_policy_extension_allows_total 1" in metrics.text
    assert "shiftedx_proxy_policy_extension_denials_total 2" in metrics.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("annotation", "expected_code"),
    [
        ({"x-shiftedx-role": "other"}, "protected_role_override_denied"),
        (
            {"x-shiftedx-role": "investigation", "name": "run_tests"},
            "protected_role_override_denied",
        ),
        (
            {
                "x-shiftedx-role": "mutation",
                "function_role": "verification",
            },
            "conflicting_role_annotation",
        ),
        ({"x-shiftedx-role": "not-a-role"}, "invalid_role_annotation"),
    ],
)
async def test_policy_annotation_client_errors_are_stable(
    annotation: dict[str, str], expected_code: str
) -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    tool: dict[str, Any] = {
        "type": "function",
        "function": {"name": annotation.get("name", "apply_patch"), "parameters": {}},
    }
    if "x-shiftedx-role" in annotation:
        tool["x-shiftedx-role"] = annotation["x-shiftedx-role"]
    if "function_role" in annotation:
        tool["function"]["x-shiftedx-role"] = annotation["function_role"]
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "model", "messages": [], "tools": [tool]},
            )
    assert response.status_code == (403 if expected_code.endswith("denied") else 400)
    assert response.json()["error"]["code"] == expected_code
    assert upstream.requests == []
