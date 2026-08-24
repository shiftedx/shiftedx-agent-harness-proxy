import httpx
import pytest
from pydantic import SecretStr

from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.errors import UpstreamFailure, UpstreamTimeout
from shiftedx_harness_proxy.provider_capabilities import (
    COMBINED_CAPABILITY_SCHEMA_VERSION,
    COMBINED_TOOL_TERMINAL_CONTRACT_ID,
)
from shiftedx_harness_proxy.transport import UPSTREAM_KEEPALIVE_EXPIRY_SECONDS, HttpxUpstream


@pytest.mark.asyncio
async def test_owned_client_declares_pinned_keepalive_expiry() -> None:
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"))

    pool = upstream.client._transport._pool  # type: ignore[attr-defined]
    assert UPSTREAM_KEEPALIVE_EXPIRY_SECONDS == 5.0
    assert pool._keepalive_expiry == UPSTREAM_KEEPALIVE_EXPIRY_SECONDS  # type: ignore[attr-defined]

    await upstream.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 400, 429, 500])
async def test_upstream_redirects_and_error_bodies_become_stable_safe_errors(status: int) -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(status, text='{"secret":"must-not-leak"}')
        )
    )
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"), client)
    with pytest.raises(UpstreamFailure) as raised:
        await upstream.chat({"messages": []}, {})
    assert "must-not-leak" not in raised.value.message
    await client.aclose()


@pytest.mark.asyncio
async def test_malformed_upstream_json_is_rejected() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, text="not-json"))
    )
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"), client)
    with pytest.raises(UpstreamFailure) as raised:
        await upstream.chat({"messages": []}, {})
    assert raised.value.code == "upstream_malformed_json"
    await client.aclose()


@pytest.mark.asyncio
async def test_combined_capability_probe_is_bounded_and_does_not_forward_request_headers() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured.update(request.headers)
        return httpx.Response(
            200,
            json={
                "schema_version": COMBINED_CAPABILITY_SCHEMA_VERSION,
                "runtime": {"name": "mtplx", "version": "2.9.0", "source_revision": "a" * 40},
                "features": {
                    "combined_tool_terminal_schema": {
                        "supported": True,
                        "contract_id": COMBINED_TOOL_TERMINAL_CONTRACT_ID,
                    }
                }
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"), client)

    assert await upstream.combined_tool_terminal_schema_supported()
    assert captured["path"] == "/v1/mtplx/app/capabilities"
    assert "x-request-id" not in captured
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "document",
    [
        {},
        {"features": {"combined_tool_terminal_schema": {"supported": False}}},
        {
            "features": {
                "combined_tool_terminal_schema": {
                    "supported": True,
                    "contract_id": "native_tool_or_strict_json_schema:v2",
                }
            }
        },
        {"features": {"combined_tool_terminal_schema": []}},
    ],
)
async def test_combined_capability_probe_fails_closed_for_unusable_documents(
    document: dict[str, object],
) -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=document))
    )
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"), client)

    assert not await upstream.combined_tool_terminal_schema_supported()
    await client.aclose()


@pytest.mark.asyncio
async def test_upstream_response_size_is_bounded_while_streaming() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * 2048))
    )
    upstream = HttpxUpstream(
        Settings(upstream_base_url="http://upstream/v1", max_upstream_response_bytes=1024), client
    )
    with pytest.raises(UpstreamFailure) as raised:
        await upstream.chat({"messages": []}, {})
    assert raised.value.code == "upstream_response_too_large"
    await client.aclose()


@pytest.mark.asyncio
async def test_timeout_is_distinct_and_headers_are_allowlisted() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        raise httpx.ReadTimeout("slow", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = Settings(
        upstream_base_url="http://upstream/v1", upstream_api_key=SecretStr("upstream-key")
    )
    upstream = HttpxUpstream(settings, client)
    with pytest.raises(UpstreamTimeout):
        await upstream.chat(
            {"messages": []},
            {
                "Authorization": "Bearer downstream-key",
                "Cookie": "session=private",
                "X-Request-ID": "safe-id",
            },
        )
    assert captured["authorization"] == "Bearer upstream-key"
    assert captured["x-request-id"] == "safe-id"
    assert "cookie" not in captured
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_after", ["3601", "1.5", "tomorrow"])
async def test_unsafe_retry_after_is_not_forwarded(retry_after: str) -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(429, headers={"Retry-After": retry_after})
        )
    )
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"), client)
    with pytest.raises(UpstreamFailure) as raised:
        await upstream.chat({"messages": []}, {})
    assert raised.value.status_code == 429
    assert raised.value.code == "upstream_rate_limited"
    assert "Retry-After" not in raised.value.headers
    await client.aclose()


@pytest.mark.asyncio
async def test_disconnect_is_a_stable_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("peer disconnected", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = HttpxUpstream(Settings(upstream_base_url="http://upstream/v1"), client)
    with pytest.raises(UpstreamFailure) as raised:
        await upstream.chat({"messages": []}, {})
    assert raised.value.status_code == 502
    assert raised.value.code == "upstream_connection_error"
    await client.aclose()
