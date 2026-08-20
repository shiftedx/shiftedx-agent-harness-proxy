"""Lifecycle reconciliation for aggregate request and upstream-attempt metrics."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import Any

import httpx
import pytest
from starlette.requests import Request

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.errors import ProxyError
from shiftedx_harness_proxy.transport import HttpxUpstream

JsonObject = dict[str, Any]


def settings(**overrides: Any) -> Settings:
    values: JsonObject = {
        "upstream_base_url": "http://upstream/v1",
        "admission_limit": 4,
        "admission_wait_seconds": 0.01,
        "concurrency_limit": 2,
        "concurrency_wait_seconds": 0.01,
        "principal_concurrency_limit": 4,
        "principal_rate_limit": 10,
        "principal_rate_window_seconds": 1,
        "total_request_deadline_seconds": 1,
        "max_internal_retries": 2,
        "max_upstream_calls": 4,
    }
    values.update(overrides)
    return Settings(**values)


def completion(content: str = "ok") -> JsonObject:
    return {"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": content}}]}


class ScriptedUpstream:
    def __init__(self, outcomes: list[JsonObject | BaseException]) -> None:
        self.outcomes = deque(outcomes)
        self.calls: list[JsonObject] = []
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def chat(self, payload: JsonObject, request_headers: dict[str, str]) -> JsonObject:
        del request_headers
        self.calls.append(payload)
        self.started.set()
        outcome = self.outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def models(self, request_headers: dict[str, str]) -> JsonObject:
        del request_headers
        return {"object": "list", "data": []}

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class WaitingUpstream(ScriptedUpstream):
    def __init__(self) -> None:
        super().__init__([])

    async def chat(self, payload: JsonObject, request_headers: dict[str, str]) -> JsonObject:
        del request_headers
        self.calls.append(payload)
        self.started.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return completion()


class PhaseSplitUpstream(ScriptedUpstream):
    async def chat(self, payload: JsonObject, request_headers: dict[str, str]) -> JsonObject:
        del request_headers
        self.calls.append(payload)
        self.started.set()
        if "tools" in payload:
            return {
                "id": "chatcmpl",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "again",
                                    "type": "function",
                                    "function": {"name": "read_file", "arguments": '{"path":"a.py"}'},
                                }
                            ],
                        }
                    }
                ],
            }
        return completion('{"status":"done"}')


def metric_values(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if line.startswith("shiftedx_proxy_"):
            name, value = line.split()
            values[name] = int(value)
    return values


async def metrics(client: httpx.AsyncClient) -> dict[str, int]:
    return metric_values((await client.get("/metrics")).text)


async def post(app: Any, payload: JsonObject, **kwargs: Any) -> tuple[httpx.Response, dict[str, int]]:
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", json=payload, **kwargs)
            return response, await metrics(client)


def chat_payload() -> JsonObject:
    return {"model": "model", "messages": [{"role": "user", "content": "synthetic"}]}


def strict_schema() -> JsonObject:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "result",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
                "additionalProperties": False,
            },
        },
    }


def assert_ledger(values: dict[str, int], *, requests: int, attempts: int, calls: int) -> None:
    assert values["shiftedx_proxy_downstream_requests_total"] == requests
    assert values["shiftedx_proxy_upstream_calls_total"] == attempts == calls


def correction_turns_sent(upstream: ScriptedUpstream) -> int:
    """Count retry turns in the authoritative fake-server request ledger."""
    return sum(
        any(
            message.get("role") == "user"
            and isinstance(message.get("content"), str)
            and message["content"].startswith("[shiftedx harness correction]")
            for message in request["messages"]
            if isinstance(message, dict)
        )
        for request in upstream.calls
    )


@pytest.mark.asyncio
async def test_success_and_passthrough_reconcile_to_the_authoritative_upstream_ledger() -> None:
    upstream = ScriptedUpstream([completion()])
    response, values = await post(create_app(settings(), upstream), chat_payload())

    assert response.status_code == 200
    assert_ledger(values, requests=1, attempts=1, calls=len(upstream.calls))
    assert values["shiftedx_proxy_errors_total"] == 0
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0
    assert values["shiftedx_proxy_phase_acquisition_total"] == 0
    assert values["shiftedx_proxy_phase_finalization_total"] == 0


@pytest.mark.asyncio
async def test_local_projection_is_admitted_but_has_zero_upstream_attempts() -> None:
    upstream = ScriptedUpstream([])
    payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "synthetic"},
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "v", "type": "function", "function": {"name": "run_tests", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "v", "content": "14 passed"},
        ],
        "tools": [{"type": "function", "function": {"name": "run_tests", "parameters": {}}}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "result",
                "schema": {
                    "type": "object",
                    "properties": {"status": {"type": "string"}, "tests": {"type": "integer"}},
                },
            },
        },
    }
    response, values = await post(create_app(settings(), upstream), payload)

    assert response.status_code == 200
    assert_ledger(values, requests=1, attempts=0, calls=len(upstream.calls))
    assert values["shiftedx_proxy_receipt_projections_total"] == 1
    assert values["shiftedx_proxy_local_projection_upstream_calls_avoided_total"] == 1
    assert values["shiftedx_proxy_errors_total"] == 0
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [b"not-json", b'{"model":"","messages":[]}'])
async def test_admitted_body_and_validation_errors_count_once_without_an_attempt(content: bytes) -> None:
    upstream = ScriptedUpstream([])
    app = create_app(settings(), upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", content=content)
            values = await metrics(client)

    assert response.status_code == 400
    assert_ledger(values, requests=1, attempts=0, calls=len(upstream.calls))
    assert values["shiftedx_proxy_errors_total"] == 1
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
async def test_admission_and_principal_rate_rejections_are_outside_the_admitted_denominator() -> None:
    upstream = ScriptedUpstream([completion()])
    app = create_app(settings(admission_limit=1, principal_rate_limit=2), upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            async with app.state.admission.admit(None):
                admission_rejected = await client.post("/v1/chat/completions", json=chat_payload())
            accepted = await client.post("/v1/chat/completions", json=chat_payload())
            rate_rejected = await client.post("/v1/chat/completions", json=chat_payload())
            values = await metrics(client)

    assert admission_rejected.status_code == rate_rejected.status_code == 429
    assert accepted.status_code == 200
    assert_ledger(values, requests=1, attempts=1, calls=len(upstream.calls))
    assert values["shiftedx_proxy_admission_rejections_total"] == 1
    assert values["shiftedx_proxy_principal_rate_rejections_total"] == 1
    assert values["shiftedx_proxy_errors_total"] == 2
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
async def test_phase_attempt_counters_only_follow_started_acquisition_and_finalization_calls() -> None:
    upstream = PhaseSplitUpstream([])
    payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "synthetic"},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "old",
                        "type": "function",
                        "function": {"name": "read_file", "arguments": '{"path":"a.py"}'},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "old", "content": "source"},
        ],
        "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
        "response_format": strict_schema(),
    }
    response, values = await post(
        create_app(settings(upstream_tool_response_capability_mode="phase_split"), upstream), payload
    )

    assert response.status_code == 200
    assert_ledger(values, requests=1, attempts=2, calls=len(upstream.calls))
    assert values["shiftedx_proxy_phase_acquisition_total"] == 1
    assert values["shiftedx_proxy_phase_finalization_total"] == 1


@pytest.mark.asyncio
async def test_retry_exhaustion_counts_every_started_attempt() -> None:
    upstream = ScriptedUpstream([completion("not-json"), completion("not-json"), completion("not-json")])
    payload = {**chat_payload(), "response_format": strict_schema()}
    response, values = await post(create_app(settings(), upstream), payload)

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "harness_retry_exhausted"
    assert_ledger(values, requests=1, attempts=3, calls=len(upstream.calls))
    assert correction_turns_sent(upstream) == 2
    assert values["shiftedx_proxy_upstream_calls_total"] == 1 + correction_turns_sent(upstream)
    # Successful-policy telemetry deliberately does not report corrections from an exhausted request.
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_errors_total"] == 1
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    ["rate_limited", "server_error", "malformed_json", "timeout", "connection_failure"],
)
async def test_httpx_failure_attempts_reconcile_after_delegate_starts(kind: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if kind == "rate_limited":
            return httpx.Response(429, request=request)
        if kind == "server_error":
            return httpx.Response(500, request=request)
        if kind == "malformed_json":
            return httpx.Response(200, content=b"not-json", request=request)
        if kind == "timeout":
            raise httpx.ReadTimeout("synthetic", request=request)
        raise httpx.ConnectError("synthetic", request=request)

    configured = settings()
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response, values = await post(create_app(configured, HttpxUpstream(configured, client)), chat_payload())
    await client.aclose()

    assert response.status_code in {429, 502, 504}
    assert_ledger(values, requests=1, attempts=1, calls=calls)
    assert values["shiftedx_proxy_errors_total"] == 1
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
async def test_malformed_completion_counts_the_started_attempt() -> None:
    upstream = ScriptedUpstream([{"id": "chatcmpl", "choices": "not-a-list"}])
    response, values = await post(create_app(settings(), upstream), chat_payload())

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_malformed_completion"
    assert_ledger(values, requests=1, attempts=1, calls=len(upstream.calls))
    assert values["shiftedx_proxy_errors_total"] == 1
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
async def test_failed_upstream_slot_acquisition_is_not_an_attempt_or_phase() -> None:
    upstream = ScriptedUpstream([completion("acquisition")])
    app = create_app(
        settings(
            concurrency_limit=1,
            concurrency_wait_seconds=0.001,
            upstream_tool_response_capability_mode="phase_split",
        ),
        upstream,
    )
    payload = {
        **chat_payload(),
        "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
        "response_format": strict_schema(),
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            async with app.state.admission.upstream_slot():
                response = await client.post("/v1/chat/completions", json=payload)
            values = await metrics(client)

    assert response.status_code == 503
    assert_ledger(values, requests=1, attempts=0, calls=len(upstream.calls))
    assert values["shiftedx_proxy_phase_acquisition_total"] == 0
    assert values["shiftedx_proxy_phase_finalization_total"] == 0


def chat_endpoint(app: Any) -> Callable[[Request], Awaitable[Any]]:
    return next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/v1/chat/completions")


def request_with_events(app: Any, events: list[JsonObject]) -> Request:
    async def receive() -> JsonObject:
        return events.pop(0)

    return Request(
        {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": [], "app": app, "state": {}},
        receive=receive,
    )


@pytest.mark.asyncio
async def test_body_disconnect_is_admitted_once_without_an_attempt() -> None:
    app = create_app(settings(), ScriptedUpstream([]))
    request = request_with_events(app, [{"type": "http.disconnect"}])
    with pytest.raises(ProxyError, match="disconnected") as raised:
        await chat_endpoint(app)(request)
    response = await app.exception_handlers[ProxyError](request, raised.value)

    assert response.status_code == 499
    assert app.state.counters.downstream_requests == 1
    assert app.state.counters.upstream_calls == 0
    assert app.state.counters.errors == 1
    assert app.state.counters.cancellations == 1


@pytest.mark.asyncio
async def test_inflight_disconnect_and_external_cancellation_retain_the_started_attempt() -> None:
    upstream = WaitingUpstream()
    app = create_app(settings(), upstream)
    encoded = json.dumps(chat_payload()).encode()
    request = request_with_events(
        app,
        [
            {"type": "http.request", "body": encoded, "more_body": False},
            {"type": "http.disconnect"},
        ],
    )
    with pytest.raises(ProxyError, match="disconnected") as raised:
        await chat_endpoint(app)(request)
    response = await app.exception_handlers[ProxyError](request, raised.value)
    assert response.status_code == 499
    assert upstream.cancelled.is_set()
    assert app.state.counters.downstream_requests == app.state.counters.upstream_calls == 1
    assert app.state.counters.errors == app.state.counters.cancellations == 1

    external_upstream = WaitingUpstream()
    external_app = create_app(settings(), external_upstream)
    async with external_app.router.lifespan_context(external_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=external_app), base_url="http://proxy"
        ) as client:
            task = asyncio.create_task(client.post("/v1/chat/completions", json=chat_payload()))
            await external_upstream.started.wait()
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    assert external_upstream.cancelled.is_set()
    assert external_app.state.counters.downstream_requests == external_app.state.counters.upstream_calls == 1
    assert external_app.state.counters.cancellations == 1
    assert external_app.state.counters.errors == 0


@pytest.mark.asyncio
async def test_total_deadline_counts_the_started_attempt_before_cancellation() -> None:
    upstream = WaitingUpstream()
    app = create_app(settings(total_request_deadline_seconds=0.02), upstream)
    response, values = await post(app, chat_payload())

    assert response.status_code == 504
    assert upstream.cancelled.is_set()
    assert_ledger(values, requests=1, attempts=1, calls=len(upstream.calls))
    assert values["shiftedx_proxy_errors_total"] == 1
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0


@pytest.mark.asyncio
async def test_mixed_request_ledger_has_exact_request_attempt_error_and_projection_deltas() -> None:
    """One mixed window prevents successful responses from double-counting later failures."""
    upstream = ScriptedUpstream([completion(), {"id": "chatcmpl", "choices": "not-a-list"}])
    app = create_app(settings(), upstream)
    projection_payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "synthetic"},
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "v", "type": "function", "function": {"name": "run_tests", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "v", "content": "14 passed"},
        ],
        "tools": [{"type": "function", "function": {"name": "run_tests", "parameters": {}}}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "result",
                "schema": {
                    "type": "object",
                    "properties": {"status": {"type": "string"}, "tests": {"type": "integer"}},
                },
            },
        },
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            success = await client.post("/v1/chat/completions", json=chat_payload())
            projection = await client.post("/v1/chat/completions", json=projection_payload)
            validation = await client.post("/v1/chat/completions", content=b"not-json")
            malformed = await client.post("/v1/chat/completions", json=chat_payload())
            values = await metrics(client)

    assert [response.status_code for response in (success, projection, validation, malformed)] == [200, 200, 400, 502]
    assert_ledger(values, requests=4, attempts=2, calls=len(upstream.calls))
    assert values["shiftedx_proxy_errors_total"] == 2
    assert values["shiftedx_proxy_receipt_projections_total"] == 1
    assert values["shiftedx_proxy_local_projection_upstream_calls_avoided_total"] == 1
    assert values["shiftedx_proxy_correction_turns_total"] == 0
    assert values["shiftedx_proxy_downstream_cancellations_total"] == 0
