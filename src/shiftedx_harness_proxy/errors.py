"""Public-safe proxy errors."""

from __future__ import annotations

from collections.abc import Mapping


class ProxyError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = dict(headers or {})


class UpstreamTimeout(ProxyError):
    def __init__(self) -> None:
        super().__init__(504, "upstream_timeout", "The configured upstream timed out.")


class UpstreamFailure(ProxyError):
    def __init__(
        self,
        code: str = "upstream_error",
        *,
        status_code: int = 502,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code,
            code,
            "The configured upstream returned an unusable response.",
            headers=headers,
        )
