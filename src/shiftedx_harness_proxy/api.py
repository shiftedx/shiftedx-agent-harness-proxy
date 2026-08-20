"""FastAPI surface with bounded, redacted request handling."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import uuid
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from starlette.requests import ClientDisconnect

from .admission import AdmissionController, BoundedUpstream
from .cache_policy import ServerCacheNamespace
from .config import Settings
from .errors import ProxyError
from .provider_capabilities import CapabilityPhase
from .service import ChatResult, ChatService
from .transport import HttpxUpstream, Upstream

LOGGER = logging.getLogger("shiftedx_harness_proxy")
_SAFE_CORRELATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass
class Counters:
    downstream_requests: int = 0
    upstream_calls: int = 0
    blocked_duplicates: int = 0
    blocked_stalls: int = 0
    correction_turns: int = 0
    receipt_projections: int = 0
    local_projection_upstream_calls_avoided: int = 0
    errors: int = 0
    policy_extension_allows: int = 0
    policy_extension_denials: int = 0
    cache_namespace_rejections: int = 0
    deadline_expiries: int = 0
    cancellations: int = 0
    phase_acquisition: int = 0
    phase_finalization: int = 0
    phase_schema_rejections: int = 0

    def observe_admitted_request(self) -> None:
        self.downstream_requests += 1

    def observe_upstream_attempt(self, phase: CapabilityPhase | None) -> None:
        self.upstream_calls += 1
        if phase is None:
            return
        if phase == "acquisition":
            self.phase_acquisition += 1
        else:
            self.phase_finalization += 1

    def observe(self, result: ChatResult) -> None:
        telemetry = result.telemetry
        self.blocked_duplicates += telemetry.blocked_duplicates
        self.blocked_stalls += telemetry.blocked_stalls
        self.correction_turns += telemetry.corrections
        self.receipt_projections += telemetry.receipt_projections
        self.local_projection_upstream_calls_avoided += telemetry.local_projection_upstream_calls_avoided
        self.policy_extension_allows += telemetry.policy_extensions_used

    def render(self, admission: AdmissionController) -> str:
        counters = {
            "shiftedx_proxy_downstream_requests_total": self.downstream_requests,
            "shiftedx_proxy_upstream_calls_total": self.upstream_calls,
            "shiftedx_proxy_blocked_duplicates_total": self.blocked_duplicates,
            "shiftedx_proxy_blocked_stalls_total": self.blocked_stalls,
            "shiftedx_proxy_correction_turns_total": self.correction_turns,
            "shiftedx_proxy_receipt_projections_total": self.receipt_projections,
            "shiftedx_proxy_local_projection_upstream_calls_avoided_total": (
                self.local_projection_upstream_calls_avoided
            ),
            "shiftedx_proxy_errors_total": self.errors,
            "shiftedx_proxy_policy_extension_allows_total": self.policy_extension_allows,
            "shiftedx_proxy_policy_extension_denials_total": self.policy_extension_denials,
            "shiftedx_proxy_cache_namespace_rejections_total": self.cache_namespace_rejections,
            "shiftedx_proxy_request_deadline_expiries_total": self.deadline_expiries,
            "shiftedx_proxy_downstream_cancellations_total": self.cancellations,
            "shiftedx_proxy_phase_acquisition_total": self.phase_acquisition,
            "shiftedx_proxy_phase_finalization_total": self.phase_finalization,
            "shiftedx_proxy_phase_schema_rejections_total": self.phase_schema_rejections,
        }
        snapshot = admission.snapshot()
        counters.update(
            {
                "shiftedx_proxy_admission_rejections_total": snapshot.admission_rejections,
                "shiftedx_proxy_principal_rate_rejections_total": snapshot.rate_rejections,
            }
        )
        gauges = {
            "shiftedx_proxy_downstream_active": snapshot.active,
            "shiftedx_proxy_downstream_queued": snapshot.queued,
            "shiftedx_proxy_upstream_active": snapshot.upstream_active,
        }
        return "".join(
            f"# TYPE {key} counter\n{key} {value}\n" for key, value in counters.items()
        ) + "".join(f"# TYPE {key} gauge\n{key} {value}\n" for key, value in gauges.items())


def create_app(settings: Settings, upstream: Upstream | None = None) -> FastAPI:
    base_transport = upstream or HttpxUpstream(settings)
    admission = AdmissionController(settings)
    counters = Counters()
    transport = BoundedUpstream(base_transport, admission, attempt_observer=counters.observe_upstream_attempt)
    service = ChatService(settings, transport)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        await transport.close()

    app = FastAPI(
        title="Shiftedx Agent Harness Proxy",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.upstream = transport
    app.state.admission = admission
    app.state.counters = counters

    if origins := settings.allowed_origins():
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Shiftedx-Harness", "X-Request-ID"],
        )

    @app.exception_handler(ProxyError)
    async def proxy_error_handler(request: Request, exc: ProxyError) -> JSONResponse:
        counters.errors += 1
        if exc.code in {
            "receipt_override_denied",
            "protected_role_override_denied",
            "harness_opt_out_denied",
        }:
            counters.policy_extension_denials += 1
        if exc.code == "untrusted_cache_namespace":
            counters.cache_namespace_rejections += 1
        if exc.code == "unsupported_phase_split_schema":
            counters.phase_schema_rejections += 1
        if exc.code == "request_deadline_exceeded":
            counters.deadline_expiries += 1
        if exc.code == "downstream_disconnected":
            counters.cancellations += 1
        correlation_id = getattr(request.state, "correlation_id", None) or _new_correlation_id(request)
        LOGGER.warning("proxy_request_failed code=%s correlation_id=%s", exc.code, correlation_id)
        headers = {"X-Request-ID": correlation_id, **exc.headers}
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"message": exc.message, "type": "shiftedx_proxy_error", "code": exc.code}},
            headers=headers,
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/readyz")
    async def readyz() -> Response:
        if await transport.ready():
            return JSONResponse({"status": "ready"})
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "message": "The configured upstream is not reachable.",
                    "type": "shiftedx_proxy_error",
                    "code": "upstream_not_ready",
                }
            },
        )

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        _authenticate(request, settings)
        if not settings.metrics_enabled:
            raise ProxyError(404, "metrics_disabled", "Metrics are disabled.")
        return PlainTextResponse(counters.render(admission), media_type="text/plain; version=0.0.4")

    @app.get("/v1/models")
    async def models(request: Request) -> Response:
        correlation_id = _set_correlation_id(request)
        principal = _authenticate(request, settings)
        deadline_at = _deadline_at(settings)
        try:
            async with asyncio.timeout_at(deadline_at):
                async with admission.admit(principal.budget_key):
                    value = await transport.models(_forwarded_request_headers(request, correlation_id))
                    response = JSONResponse(value, headers={"X-Request-ID": correlation_id})
                    _ensure_before_deadline(deadline_at)
                    return response
        except TimeoutError as exc:
            raise ProxyError(504, "request_deadline_exceeded", "The request exceeded its total time limit.") from exc

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> Response:
        correlation_id = _set_correlation_id(request)
        principal = _authenticate(request, settings)
        deadline_at = _deadline_at(settings)
        try:
            async with asyncio.timeout_at(deadline_at):
                async with admission.admit(principal.budget_key):
                    counters.observe_admitted_request()
                    payload = await _read_payload(request, settings)
                    harness_header = request.headers.get("x-shiftedx-harness")
                    if harness_header is not None and harness_header.strip().lower() != "off":
                        raise ProxyError(400, "invalid_harness_opt_out", "X-Shiftedx-Harness supports only off.")
                    opt_out = harness_header is not None
                    if opt_out and not settings.allow_harness_opt_out:
                        raise ProxyError(403, "harness_opt_out_disabled", "Harness opt-out is disabled.")
                    if opt_out and not principal.policy_extensions_allowed:
                        raise ProxyError(
                            403,
                            "harness_opt_out_denied",
                            "Harness opt-out is not authorized for this principal.",
                        )
                    result = await _complete_while_connected(
                        request,
                        service.complete(
                            payload,
                            _forwarded_request_headers(request, correlation_id),
                            harness_enabled=not opt_out,
                            policy_extensions_allowed=principal.policy_extensions_allowed,
                            trusted_policy_extension_used=opt_out,
                            server_cache_namespace=principal.server_cache_namespace,
                        ),
                    )
                    headers = _telemetry_headers(result, settings)
                    headers["X-Request-ID"] = correlation_id
                    response = JSONResponse(result.body, headers=headers)
                    _ensure_before_deadline(deadline_at)
                    counters.observe(result)
                    return response
        except TimeoutError as exc:
            raise ProxyError(504, "request_deadline_exceeded", "The request exceeded its total time limit.") from exc
        except asyncio.CancelledError:
            counters.cancellations += 1
            raise

    return app


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    policy_extensions_allowed: bool = False
    server_cache_namespace: ServerCacheNamespace | None = None
    budget_key: str | None = None


def _authenticate(request: Request, settings: Settings) -> AuthenticatedPrincipal:
    supplied = request.headers.get("authorization", "")
    trusted_capabilities = settings.trusted_policy_extension_keys()
    if any(
        hmac.compare_digest(supplied.encode(), f"Bearer {capability}".encode())
        for capability in trusted_capabilities
    ):
        return AuthenticatedPrincipal(
            policy_extensions_allowed=True,
            budget_key=settings.principal_budget_key(supplied),
        )
    if settings.proxy_api_key is None and not trusted_capabilities:
        return AuthenticatedPrincipal()
    expected = (
        f"Bearer {settings.proxy_api_key.get_secret_value()}"
        if settings.proxy_api_key is not None
        else ""
    )
    if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise ProxyError(401, "authentication_failed", "A valid proxy bearer token is required.")
    return AuthenticatedPrincipal(budget_key=settings.principal_budget_key(supplied))


def _new_correlation_id(request: Request) -> str:
    candidate = request.headers.get("x-request-id", "")
    if _SAFE_CORRELATION_ID.fullmatch(candidate):
        return candidate
    return f"shiftedx-{uuid.uuid4().hex}"


def _set_correlation_id(request: Request) -> str:
    correlation_id = _new_correlation_id(request)
    request.state.correlation_id = correlation_id
    return correlation_id


def _forwarded_request_headers(request: Request, correlation_id: str) -> dict[str, str]:
    """Forward only the proxy-owned correlation ID to the credentialed upstream."""
    del request
    return {"x-request-id": correlation_id}


def _deadline_at(settings: Settings) -> float:
    return asyncio.get_running_loop().time() + settings.total_request_deadline_seconds


def _ensure_before_deadline(deadline_at: float) -> None:
    if asyncio.get_running_loop().time() > deadline_at:
        raise TimeoutError


async def _read_payload(request: Request, settings: Settings) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise ProxyError(400, "invalid_content_length", "Content-Length is invalid.") from exc
        if declared_length > settings.max_request_bytes:
            raise ProxyError(413, "request_too_large", "Request body exceeds MAX_REQUEST_BYTES.")
    chunks: list[bytes] = []
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > settings.max_request_bytes:
                raise ProxyError(413, "request_too_large", "Request body exceeds MAX_REQUEST_BYTES.")
            chunks.append(chunk)
    except ClientDisconnect as exc:
        raise ProxyError(499, "downstream_disconnected", "The downstream client disconnected.") from exc
    try:
        payload = json.loads(b"".join(chunks))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProxyError(400, "invalid_json", "Request body must be a JSON object.") from exc
    if not isinstance(payload, dict):
        raise ProxyError(400, "invalid_json", "Request body must be a JSON object.")
    return payload


async def _complete_while_connected(
    request: Request, work: Coroutine[Any, Any, ChatResult]
) -> ChatResult:
    task = asyncio.create_task(work)
    try:
        while not task.done():
            await asyncio.wait({task}, timeout=0.05)
            if not task.done() and await request.is_disconnected():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
                raise ProxyError(499, "downstream_disconnected", "The downstream client disconnected.")
        return await task
    except asyncio.CancelledError:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        raise


def _telemetry_headers(result: ChatResult, settings: Settings) -> dict[str, str]:
    telemetry = result.telemetry
    headers: dict[str, str] = {}
    if telemetry.degraded_state:
        headers["X-Shiftedx-State"] = "degraded"
    if settings.telemetry_enabled:
        headers.update(
            {
                "X-Shiftedx-Harness-Profile": telemetry.profile,
                "X-Shiftedx-Blocked-Duplicates": str(telemetry.blocked_duplicates),
                "X-Shiftedx-Blocked-Stalls": str(telemetry.blocked_stalls),
                "X-Shiftedx-Corrections": str(telemetry.corrections),
                "X-Shiftedx-Upstream-Calls": str(telemetry.upstream_calls),
                "X-Shiftedx-Policy-Wall-Ms": f"{telemetry.policy_wall_ms:.3f}",
            }
        )
    return headers
