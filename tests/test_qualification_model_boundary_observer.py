from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import httpx
import pytest

from shiftedx_harness_proxy.qualification_observer import (
    QualificationObserverConfig,
    QualificationObserverConfigurationError,
    _append_observation,
    create_observer_app,
    load_observer_config,
)


def _config(tmp_path) -> QualificationObserverConfig:
    return QualificationObserverConfig(
        upstream_url="http://model.invalid/v1",
        ledger=tmp_path / "observer.jsonl",
        host="127.0.0.1",
        port=18092,
        instance_sha256=hashlib.sha256(b"observer-instance").hexdigest(),
    )


def test_observer_retains_only_model_boundary_component_hashes(tmp_path) -> None:
    config = _config(tmp_path)
    app = create_observer_app(config)
    _append_observation(
        app.state.qualification_observer,
        {
            "messages": [
                {"role": "system", "content": "private system marker"},
                {"role": "user", "content": "private prompt marker"},
            ],
            "tools": [{"type": "function", "function": {"name": "private_tool"}}],
            "temperature": 0.0,
            "top_p": 0.95,
            "top_k": 20,
            "thinking": {"enabled": True},
            "reasoning_effort": "medium",
            "max_tokens": 1024,
        },
        status_code=200,
        response_payload={
            "mtplx_stats": {
                "prompt_tokens": 17,
                "cached_tokens": 0,
                "new_prefill_tokens": 17,
                "cache_source": "none",
                "ssd_cache_hit": False,
                "ssd_cached_tokens": 0,
                "session_cache_hit": False,
                "request_session_bank_bypass": True,
                "session_postcommit_snapshot": {"stored": False},
            }
        },
    )
    _append_observation(
        app.state.qualification_observer,
        {"model": "model", "messages": []},
        status_code=None,
        response_payload=None,
    )

    rows = [json.loads(line) for line in config.ledger.read_text().splitlines()]
    row = rows[0]
    assert set(row) == {"record_type", "sequence", "digest", "fields", "response"}
    assert row["record_type"] == "qualification_model_boundary"
    assert row["sequence"] == 1
    assert row["fields"]["compatibility"] == {
        "mode": "phase_split",
        "version": "shiftedx-phase-plan-v1",
        "phase": "acquisition",
    }
    assert [item["sequence"] for item in rows] == [1, 2]
    assert rows[1]["fields"]["compatibility"]["phase"] == "terminal"
    assert row["response"] == {
        "status_code": 200,
        "cache": {
            "prompt_tokens": 17,
            "cached_tokens": 0,
            "new_prefill_tokens": 17,
            "cache_source": "none",
            "ssd_cache_hit": False,
            "ssd_cached_tokens": 0,
            "session_cache_hit": False,
            "request_session_bank_bypass": True,
            "postcommit_stored": False,
        },
    }
    assert os.stat(config.ledger).st_mode & 0o777 == 0o600
    serialized = config.ledger.read_text()
    assert "private system marker" not in serialized
    assert "private prompt marker" not in serialized
    assert "private_tool" not in serialized


@pytest.mark.asyncio
async def test_observer_health_is_bound_to_its_supervisor_instance(tmp_path) -> None:
    config = _config(tmp_path)
    app = create_observer_app(config)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://observer") as client:
            response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "live", "instance_sha256": config.instance_sha256}


@pytest.mark.asyncio
async def test_observer_forwards_only_authorization_and_keeps_chat_payload_out_of_ledger(tmp_path) -> None:
    config = _config(tmp_path)
    app = create_observer_app(config)
    forwarded: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        forwarded.append(request)
        return httpx.Response(
            200,
            json={"object": "list"}
            if request.url.path.endswith("models")
            else {
                "choices": [{"message": {"content": "private model output"}}],
                "mtplx_stats": {
                    "prompt_tokens": 5,
                    "cached_tokens": 0,
                    "new_prefill_tokens": 5,
                    "cache_source": "none",
                    "ssd_cache_hit": False,
                    "ssd_cached_tokens": 0,
                    "session_cache_hit": False,
                    "request_session_bank_bypass": True,
                    "session_postcommit_snapshot": {"stored": False},
                    "private_diagnostic": "do not retain",
                },
            },
        )

    async with app.router.lifespan_context(app):
        await app.state.client.aclose()
        app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(upstream), base_url="http://upstream")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://observer") as client:
            chat = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer private-forwarded-token", "X-Unsafe": "do-not-forward"},
                json={"model": "model", "messages": [{"role": "user", "content": "private prompt"}]},
            )
            models = await client.get("/v1/models", headers={"Authorization": "Bearer private-forwarded-token"})
        await app.state.client.aclose()

    assert chat.status_code == models.status_code == 200
    assert [request.url.path for request in forwarded] == ["/v1/chat/completions", "/v1/models"]
    assert all(request.headers.get("authorization") == "Bearer private-forwarded-token" for request in forwarded)
    assert all("x-unsafe" not in request.headers for request in forwarded)
    serialized = config.ledger.read_text(encoding="utf-8")
    assert "private prompt" not in serialized
    assert "private-forwarded-token" not in serialized
    assert "private model output" not in serialized
    assert "private_diagnostic" not in serialized
    row = json.loads(serialized)
    assert row["response"]["status_code"] == 200
    assert row["response"]["cache"]["request_session_bank_bypass"] is True


@pytest.mark.asyncio
async def test_observer_records_null_response_evidence_before_transport_error(tmp_path) -> None:
    config = _config(tmp_path)
    app = create_observer_app(config)

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private transport detail", request=request)

    async with app.router.lifespan_context(app):
        await app.state.client.aclose()
        app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(unavailable))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://observer",
        ) as client:
            with pytest.raises(httpx.ConnectError):
                await client.post(
                    "/v1/chat/completions",
                    json={"model": "model", "messages": [{"role": "user", "content": "private"}]},
                )
        await app.state.client.aclose()

    row = json.loads(config.ledger.read_text(encoding="utf-8"))
    assert row["response"] == {"status_code": None, "cache": None}
    assert "private transport detail" not in config.ledger.read_text(encoding="utf-8")


def test_observer_import_is_configuration_isolated_until_explicit_load(monkeypatch) -> None:
    monkeypatch.delenv("QUALIFICATION_OBSERVER_UPSTREAM", raising=False)
    monkeypatch.delenv("QUALIFICATION_OBSERVER_LEDGER", raising=False)
    monkeypatch.delenv("QUALIFICATION_OBSERVER_HOST", raising=False)
    monkeypatch.delenv("QUALIFICATION_OBSERVER_PORT", raising=False)
    monkeypatch.delenv("QUALIFICATION_OBSERVER_INSTANCE_SHA256", raising=False)

    with pytest.raises(QualificationObserverConfigurationError, match="configuration_invalid"):
        load_observer_config()

    wrapper = Path(__file__).parents[1] / "scripts" / "qualification_model_boundary_observer.py"
    spec = importlib.util.spec_from_file_location("qualification_observer_wrapper", wrapper)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main is not None


@pytest.mark.parametrize(
    "override",
    [
        {"QUALIFICATION_OBSERVER_UPSTREAM": "http://user:password@model.invalid/v1"},
        {"QUALIFICATION_OBSERVER_UPSTREAM": "http://model.invalid/v1?private=value"},
        {"QUALIFICATION_OBSERVER_HOST": "0.0." + "0.0"},
        {"QUALIFICATION_OBSERVER_PORT": "0"},
        {"QUALIFICATION_OBSERVER_INSTANCE_SHA256": "not-a-hash"},
    ],
)
def test_observer_rejects_noncanonical_private_wiring(tmp_path, override) -> None:
    ledger = tmp_path / "observer.jsonl"
    environment = {
        "QUALIFICATION_OBSERVER_UPSTREAM": "http://model.invalid/v1",
        "QUALIFICATION_OBSERVER_LEDGER": str(ledger),
        "QUALIFICATION_OBSERVER_HOST": "127.0.0.1",
        "QUALIFICATION_OBSERVER_PORT": "18092",
        "QUALIFICATION_OBSERVER_INSTANCE_SHA256": "a" * 64,
        **override,
    }

    with pytest.raises(QualificationObserverConfigurationError, match="configuration_invalid"):
        load_observer_config(environment)


def test_observer_never_reuses_or_overwrites_a_ledger(tmp_path) -> None:
    config = _config(tmp_path)
    config.ledger.write_text('{"private":"prior evidence"}\n', encoding="utf-8")

    with pytest.raises(QualificationObserverConfigurationError, match="configuration_invalid"):
        load_observer_config(
            {
                "QUALIFICATION_OBSERVER_UPSTREAM": config.upstream_url,
                "QUALIFICATION_OBSERVER_LEDGER": str(config.ledger),
                "QUALIFICATION_OBSERVER_HOST": config.host,
                "QUALIFICATION_OBSERVER_PORT": str(config.port),
                "QUALIFICATION_OBSERVER_INSTANCE_SHA256": config.instance_sha256,
            }
        )

    assert config.ledger.read_text(encoding="utf-8") == '{"private":"prior evidence"}\n'
