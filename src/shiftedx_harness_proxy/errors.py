"""Public-safe proxy errors."""

from __future__ import annotations


class ProxyError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class UpstreamTimeout(ProxyError):
    def __init__(self) -> None:
        super().__init__(504, "upstream_timeout", "The configured upstream timed out.")


class UpstreamFailure(ProxyError):
    def __init__(self, code: str = "upstream_error") -> None:
        super().__init__(502, code, "The configured upstream returned an unusable response.")
