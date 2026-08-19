import asyncio
import time
from contextlib import suppress
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from starlette.requests import ClientDisconnect

from shiftedx_harness_proxy.admission import AdmissionController, BoundedUpstream
from shiftedx_harness_proxy.api import Counters, _complete_while_connected, _read_payload, create_app
from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.errors import ProxyError


class SlowUpstream:
    def __init__(self, release: asyncio.Event | None = None) -> None:
        self.release = release
        self.started = asyncio.Event()
        self.active = 0
        self.maximum_active = 0
        self.cancelled = asyncio.Event()

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        del payload, request_headers
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.started.set()
        try:
            if self.release is not None:
                await self.release.wait()
            else:
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        finally:
            self.active -= 1
        return {"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        del request_headers
        return {"object": "list", "data": []}

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class SlowModelsUpstream(SlowUpstream):
    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        del request_headers
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.started.set()
        try:
            assert self.release is not None
            await self.release.wait()
        finally:
            self.active -= 1
        return {"object": "list", "data": []}


def settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "upstream_base_url": "http://upstream/v1",
        "admission_limit": 4,
        "admission_wait_seconds": 0.02,
        "concurrency_limit": 2,
        "concurrency_wait_seconds": 0.02,
        "principal_concurrency_limit": 1,
        "principal_rate_limit": 10,
        "principal_rate_window_seconds": 0.02,
        "total_request_deadline_seconds": 1,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_admission_rejects_before_body_work_and_releases_every_gate() -> None:
    controller = AdmissionController(settings(admission_limit=1, principal_concurrency_limit=4))
    async with controller.admit(None):
        with pytest.raises(ProxyError) as raised:
            async with controller.admit(None):
                pass
        assert raised.value.code == "admission_overloaded"
        assert raised.value.headers == {"Retry-After": "1"}
        assert controller.snapshot().active == 1
    assert controller.snapshot().active == 0
    assert controller.snapshot().queued == 0


@pytest.mark.asyncio
async def test_principal_concurrency_distinguishes_keys_and_does_not_prune_active_budget() -> None:
    controller = AdmissionController(settings(principal_rate_window_seconds=0.01))
    async with controller.admit("opaque-a"):
        await asyncio.sleep(0.02)
        async with controller.admit("opaque-b"):
            assert controller.snapshot().active == 2
        with pytest.raises(ProxyError) as raised:
            async with controller.admit("opaque-a"):
                pass
        assert raised.value.code == "principal_concurrency_limited"
    assert controller.snapshot().active == 0
    assert controller.snapshot().queued == 0


@pytest.mark.asyncio
async def test_principal_rate_budget_is_opaque_and_bounded() -> None:
    controller = AdmissionController(settings(principal_rate_limit=1, principal_rate_window_seconds=1))
    async with controller.admit("opaque-a"):
        pass
    with pytest.raises(ProxyError) as raised:
        async with controller.admit("opaque-a"):
            pass
    assert raised.value.code == "principal_rate_limited"
    assert raised.value.headers == {"Retry-After": "1"}
    async with controller.admit("opaque-b"):
        pass


@pytest.mark.asyncio
async def test_upstream_slot_is_per_operation_and_releases_after_cancellation() -> None:
    release = asyncio.Event()
    delegate = SlowUpstream(release)
    controller = AdmissionController(settings(concurrency_limit=1))
    upstream = BoundedUpstream(delegate, controller)
    task = asyncio.create_task(upstream.chat({}, {}))
    await delegate.started.wait()
    assert controller.snapshot().upstream_active == 1
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
    assert delegate.cancelled.is_set()
    assert controller.snapshot().upstream_active == 0


@pytest.mark.asyncio
async def test_upstream_operation_overload_has_a_bounded_retry_hint() -> None:
    controller = AdmissionController(settings(concurrency_limit=1))
    async with controller.upstream_slot():
        with pytest.raises(ProxyError) as raised:
            async with controller.upstream_slot():
                pass
    assert raised.value.code == "upstream_concurrency_limited"
    assert raised.value.status_code == 503
    assert raised.value.headers == {"Retry-After": "1"}


@pytest.mark.asyncio
async def test_global_fallback_has_its_own_rate_budget() -> None:
    controller = AdmissionController(
        settings(principal_budget_mode="global", principal_rate_limit=1, principal_rate_window_seconds=1)
    )
    async with controller.admit(None):
        pass
    with pytest.raises(ProxyError) as raised:
        async with controller.admit(None):
            pass
    assert raised.value.code == "principal_rate_limited"


@pytest.mark.asyncio
async def test_same_principal_waiters_do_not_starve_a_distinct_principal() -> None:
    controller = AdmissionController(settings(admission_limit=2, principal_concurrency_limit=1))
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold(key: str) -> None:
        async with controller.admit(key):
            entered.set()
            await release.wait()

    first = asyncio.create_task(hold("opaque-a"))
    await entered.wait()
    waiting_same_principal = asyncio.create_task(hold("opaque-a"))
    await asyncio.sleep(0)
    async with controller.admit("opaque-b"):
        assert controller.snapshot().active == 2
    release.set()
    await first
    await waiting_same_principal


@pytest.mark.asyncio
async def test_configured_ordinary_and_trusted_principals_have_distinct_budgets() -> None:
    release = asyncio.Event()
    upstream = SlowUpstream(release)
    production_settings = Settings(
        upstream_base_url="http://upstream/v1",
        deployment_profile="production",
        proxy_api_key=SecretStr("ordinary-key"),
        trusted_policy_extension_api_keys=SecretStr("trusted-key"),
        admission_limit=3,
        admission_wait_seconds=0.02,
        concurrency_limit=2,
        concurrency_wait_seconds=1,
        principal_concurrency_limit=1,
        principal_rate_limit=10,
        total_request_deadline_seconds=1,
    )
    app = create_app(production_settings, upstream)
    payload = {"model": "model", "messages": []}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            ordinary = asyncio.create_task(
                client.post("/v1/chat/completions", headers={"Authorization": "Bearer ordinary-key"}, json=payload)
            )
            await upstream.started.wait()
            same_principal = await client.post(
                "/v1/chat/completions", headers={"Authorization": "Bearer ordinary-key"}, json=payload
            )
            trusted = asyncio.create_task(
                client.post("/v1/chat/completions", headers={"Authorization": "Bearer trusted-key"}, json=payload)
            )
            for _ in range(20):
                if app.state.admission.snapshot().active == 2:
                    break
                await asyncio.sleep(0.001)
            assert app.state.admission.snapshot().active == 2
            release.set()
            assert (await ordinary).status_code == 200
            assert (await trusted).status_code == 200
    assert same_principal.status_code == 429
    assert same_principal.json()["error"]["code"] == "principal_concurrency_limited"


@pytest.mark.asyncio
async def test_models_share_the_authenticated_principal_admission_budget() -> None:
    release = asyncio.Event()
    upstream = SlowModelsUpstream(release)
    production_settings = Settings(
        upstream_base_url="http://upstream/v1",
        deployment_profile="production",
        proxy_api_key=SecretStr("ordinary-key"),
        admission_limit=3,
        admission_wait_seconds=0.02,
        concurrency_limit=2,
        concurrency_wait_seconds=1,
        principal_concurrency_limit=1,
        principal_rate_limit=10,
        total_request_deadline_seconds=1,
    )
    app = create_app(production_settings, upstream)
    headers = {"Authorization": "Bearer ordinary-key"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            first = asyncio.create_task(client.get("/v1/models", headers=headers))
            await upstream.started.wait()
            rejected = await client.get("/v1/models", headers=headers)
            assert rejected.status_code == 429
            assert rejected.json()["error"]["code"] == "principal_concurrency_limited"
            release.set()
            assert (await first).status_code == 200
    assert app.state.admission.snapshot().active == 0
    assert app.state.admission.snapshot().queued == 0
    assert app.state.admission.snapshot().upstream_active == 0


def test_metrics_are_prompt_free_and_use_true_gauges() -> None:
    controller = AdmissionController(settings())
    controller.admission_rejections = 1
    controller.rate_rejections = 1
    counters = Counters(deadline_expiries=1, cancellations=1)
    metrics = counters.render(controller)
    assert "# TYPE shiftedx_proxy_downstream_active gauge" in metrics
    assert "# TYPE shiftedx_proxy_downstream_queued gauge" in metrics
    assert "# TYPE shiftedx_proxy_upstream_active gauge" in metrics
    assert "shiftedx_proxy_downstream_active 0" in metrics
    assert "shiftedx_proxy_downstream_queued 0" in metrics
    assert "shiftedx_proxy_upstream_active 0" in metrics
    assert "shiftedx_proxy_request_deadline_expiries_total 1" in metrics
    assert "shiftedx_proxy_downstream_cancellations_total 1" in metrics
    assert "shiftedx_proxy_admission_rejections_total 1" in metrics
    assert "shiftedx_proxy_principal_rate_rejections_total 1" in metrics
    for forbidden in ("ordinary-key", "opaque-a", "prompt", "tool_call", "hello"):
        assert forbidden not in metrics


class DisconnectingRequest:
    headers: dict[str, str] = {}

    async def is_disconnected(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_inflight_disconnect_waits_for_cancelled_work_cleanup() -> None:
    cleaned = asyncio.Event()

    async def work() -> None:
        try:
            await asyncio.sleep(10)
        finally:
            cleaned.set()

    with pytest.raises(ProxyError, match="disconnected"):
        await _complete_while_connected(DisconnectingRequest(), work())
    assert cleaned.is_set()


class BodyDisconnectingRequest:
    headers: dict[str, str] = {}

    async def stream(self):
        raise ClientDisconnect()
        yield b""  # pragma: no cover - establishes the async-generator type


@pytest.mark.asyncio
async def test_body_disconnect_maps_to_safe_error() -> None:
    with pytest.raises(ProxyError) as raised:
        await _read_payload(BodyDisconnectingRequest(), settings())
    assert raised.value.code == "downstream_disconnected"


@pytest.mark.asyncio
async def test_total_deadline_covers_slow_upstream_and_cleans_admission() -> None:
    upstream = SlowUpstream()
    app = create_app(settings(total_request_deadline_seconds=0.02), upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post("/v1/chat/completions", json={"model": "model", "messages": []})
            metrics = await client.get("/metrics")
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "request_deadline_exceeded"
    assert upstream.cancelled.is_set()
    assert app.state.admission.snapshot().active == 0
    assert app.state.admission.snapshot().upstream_active == 0
    assert "shiftedx_proxy_request_deadline_expiries_total 1" in metrics.text


@pytest.mark.asyncio
async def test_admission_rejection_does_not_consume_a_queued_request_body() -> None:
    release = asyncio.Event()
    upstream = SlowUpstream(release)
    app = create_app(settings(admission_limit=1, principal_concurrency_limit=8), upstream)
    body_touched = asyncio.Event()

    async def body() -> Any:
        body_touched.set()
        yield b'{"model":"model","messages":[]}'

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            first = asyncio.create_task(client.post("/v1/chat/completions", json={"model": "model", "messages": []}))
            await upstream.started.wait()
            rejected = await client.post(
                "/v1/chat/completions", content=body(), headers={"Content-Type": "application/json"}
            )
            assert rejected.status_code == 429
            assert rejected.json()["error"]["code"] == "admission_overloaded"
            assert not body_touched.is_set()
            release.set()
            assert (await first).status_code == 200


@pytest.mark.asyncio
async def test_total_deadline_covers_a_slow_body_before_any_upstream_work() -> None:
    upstream = SlowUpstream(asyncio.Event())
    app = create_app(settings(total_request_deadline_seconds=0.02), upstream)

    async def slow_body() -> Any:
        await asyncio.sleep(10)
        yield b'{"model":"model","messages":[]}'

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions", content=slow_body(), headers={"Content-Type": "application/json"}
            )
    assert response.status_code == 504
    assert upstream.active == 0
    assert app.state.admission.snapshot().active == 0


class RetryingUpstream(SlowUpstream):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        del payload, request_headers
        self.calls += 1
        try:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return {"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": "not json"}}]}


@pytest.mark.asyncio
async def test_total_deadline_is_not_reset_between_terminal_corrections() -> None:
    upstream = RetryingUpstream()
    app = create_app(settings(total_request_deadline_seconds=0.16), upstream)
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "return JSON"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"schema": {"type": "object", "properties": {"status": {"type": "string"}}}},
        },
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            started = time.monotonic()
            response = await client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 504
    assert upstream.calls >= 2
    assert upstream.cancelled.is_set()
    assert app.state.admission.snapshot().active == 0
    assert time.monotonic() - started < 0.19
