"""Bounded transport to the process-fixed upstream."""

from __future__ import annotations

import json
from typing import Any, Protocol

import httpx

from .config import Settings
from .errors import UpstreamFailure, UpstreamTimeout

JsonObject = dict[str, Any]
FORWARDED_REQUEST_HEADERS = frozenset(
    {"openai-organization", "openai-project", "x-request-id"}
)


class Upstream(Protocol):
    async def chat(self, payload: JsonObject, request_headers: dict[str, str]) -> JsonObject: ...

    async def models(self, request_headers: dict[str, str]) -> JsonObject: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


class HttpxUpstream:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.upstream_timeout_seconds),
            limits=httpx.Limits(
                max_connections=settings.concurrency_limit,
                max_keepalive_connections=settings.concurrency_limit,
            ),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def _headers(self, downstream: dict[str, str]) -> dict[str, str]:
        headers = {
            key: value
            for key, value in downstream.items()
            if key.lower() in FORWARDED_REQUEST_HEADERS
        }
        if self.settings.upstream_api_key is not None:
            headers["Authorization"] = f"Bearer {self.settings.upstream_api_key.get_secret_value()}"
        return headers

    async def _request(self, method: str, endpoint: str, **kwargs: Any) -> JsonObject:
        try:
            async with self.client.stream(
                method, self.settings.upstream_url(endpoint), follow_redirects=False, **kwargs
            ) as response:
                if response.is_redirect or response.status_code >= 400:
                    raise UpstreamFailure("upstream_http_error")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.settings.max_upstream_response_bytes:
                        raise UpstreamFailure("upstream_response_too_large")
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout() from exc
        except httpx.HTTPError as exc:
            raise UpstreamFailure("upstream_connection_error") from exc
        try:
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UpstreamFailure("upstream_malformed_json") from exc
        if not isinstance(value, dict):
            raise UpstreamFailure("upstream_malformed_json")
        return value

    async def chat(self, payload: JsonObject, request_headers: dict[str, str]) -> JsonObject:
        return await self._request(
            "POST",
            "chat/completions",
            json=payload,
            headers=self._headers(request_headers),
        )

    async def models(self, request_headers: dict[str, str]) -> JsonObject:
        return await self._request("GET", "models", headers=self._headers(request_headers))

    async def ready(self) -> bool:
        try:
            await self.models({})
        except (UpstreamFailure, UpstreamTimeout):
            return False
        return True

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()
