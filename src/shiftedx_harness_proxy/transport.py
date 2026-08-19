"""Bounded transport to the process-fixed upstream."""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

import httpx

from .config import Settings
from .errors import UpstreamFailure, UpstreamTimeout

JsonObject = dict[str, Any]
FORWARDED_REQUEST_HEADERS = frozenset({"x-request-id"})
_SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SAFE_ACCOUNTING = re.compile(r"[0-9]{1,12}(?:ms|s|m|h)?")
_SAFE_RETRY_AFTER = re.compile(r"[0-9]{1,4}")
_MAX_RETRY_AFTER_SECONDS = 3600


def _safe_upstream_headers(headers: httpx.Headers, status_code: int) -> dict[str, str]:
    """Select bounded response metadata without exposing upstream-controlled headers."""
    safe: dict[str, str] = {}
    if status_code == 429:
        retry_after = headers.get("retry-after")
        if retry_after is not None and _SAFE_RETRY_AFTER.fullmatch(retry_after):
            seconds = int(retry_after)
            if seconds <= _MAX_RETRY_AFTER_SECONDS:
                safe["Retry-After"] = str(seconds)
    upstream_request_id = headers.get("x-request-id") or headers.get("openai-request-id")
    if upstream_request_id is not None and _SAFE_REQUEST_ID.fullmatch(upstream_request_id):
        safe["X-Shiftedx-Upstream-Request-ID"] = upstream_request_id
    for name in (
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-reset-requests",
    ):
        value = headers.get(name)
        if value is not None and _SAFE_ACCOUNTING.fullmatch(value):
            safe[f"X-Shiftedx-Upstream-{name.removeprefix('x-').title()}"] = value
    return safe


def _upstream_http_failure(response: httpx.Response) -> UpstreamFailure:
    """Translate only status and bounded safe metadata; never read an error body."""
    status = response.status_code
    headers = _safe_upstream_headers(response.headers, status)
    if status == 400:
        return UpstreamFailure("upstream_bad_request", status_code=400, headers=headers)
    if status in {401, 403}:
        return UpstreamFailure("upstream_authentication_failed", headers=headers)
    if status == 404:
        return UpstreamFailure("upstream_not_found", headers=headers)
    if status == 409:
        return UpstreamFailure("upstream_conflict", status_code=409, headers=headers)
    if status == 422:
        return UpstreamFailure("upstream_unprocessable", status_code=422, headers=headers)
    if status == 429:
        return UpstreamFailure("upstream_rate_limited", status_code=429, headers=headers)
    if status >= 500 or response.is_redirect:
        return UpstreamFailure("upstream_server_error", headers=headers)
    return UpstreamFailure("upstream_http_error", headers=headers)


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
                    raise _upstream_http_failure(response)
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
