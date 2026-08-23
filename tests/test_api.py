import asyncio
import json
import logging
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.qualification_timing import (
    PrivateTimingSink,
    read_timing_capture_ledger,
    reserve_timing_capture_ledger,
)
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

    async def combined_tool_terminal_schema_supported(self) -> bool:
        return False

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class CombinedCapabilityUpstream(EchoUpstream):
    def __init__(self, *, supported: bool) -> None:
        super().__init__()
        self.supported = supported
        self.capability_probes = 0

    async def combined_tool_terminal_schema_supported(self) -> bool:
        self.capability_probes += 1
        return self.supported


class RichCompletionUpstream(EchoUpstream):
    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        return {
            "id": "chatcmpl-rich",
            "object": "chat.completion",
            "created": 1_700_000_000,
            "model": "model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": "Need the file.",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "read_file", "arguments": '{"path":"a.py"}'},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }


class ScriptedCompletionUpstream(EchoUpstream):
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        super().__init__()
        self.responses = responses

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        return self.responses.pop(0)


class PhaseSplitUpstream(EchoUpstream):
    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
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
        return {
            "id": "chatcmpl",
            "choices": [
                {"message": {"role": "assistant", "content": '{"status":"done"}'}}
            ],
        }


class OptOutPhaseSplitUpstream(EchoUpstream):
    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        content = "acquisition terminal" if "tools" in payload else '```json\n{"status":"done"}\n```'
        return {"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": content}}]}


class ObjectFinalizationUpstream(EchoUpstream):
    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        content: Any = "acquisition terminal" if "tools" in payload else {"status": "done"}
        return {"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": content}}]}


@pytest.mark.asyncio
async def test_injected_private_timing_sink_captures_chat_lifecycle_without_public_surface(tmp_path) -> None:
    ledger = tmp_path / "timing-captures.jsonl"
    reserve_timing_capture_ledger(ledger)
    app = create_app(
        Settings(upstream_base_url="http://upstream/v1"),
        EchoUpstream(),
        timing_sink=PrivateTimingSink(ledger),
    )

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "model", "messages": [{"role": "user", "content": "hello"}]},
            )

    assert response.status_code == 200
    assert not [name for name in response.headers if "timing" in name.lower()]
    captures = read_timing_capture_ledger(ledger)
    assert len(captures) == 1
    capture = captures[0]
    assert capture["outcome"] == "succeeded"
    assert capture["body_read_ns"] > 0
    assert capture["admission_wait_ns"] >= 0
    assert capture["response_finalize_ns"] >= 0
    assert len(capture["attempts"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("supported", [True, False])
async def test_combined_mode_readiness_requires_exact_capability_support(supported: bool) -> None:
    upstream = CombinedCapabilityUpstream(supported=supported)
    app = create_app(
        Settings(
            upstream_base_url="http://upstream/v1",
            upstream_tool_response_capability_mode="combined_v1",
        ),
        upstream,
    )

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.get("/readyz")

    assert response.status_code == (200 if supported else 503)
    assert upstream.capability_probes == 1
    if supported:
        assert response.json() == {"status": "ready"}
    else:
        assert response.json()["error"]["code"] == "upstream_not_ready"


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
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                    "stream_options": {"include_usage": True},
                },
            )
            assert streamed.status_code == 200
            assert streamed.headers["content-type"].startswith("text/event-stream")
            assert streamed.headers["cache-control"] == "no-cache"
            assert streamed.headers["x-shiftedx-stream-mode"] == "validate-then-replay"
            events = [line.removeprefix("data: ") for line in streamed.text.splitlines() if line]
            assert events[-1] == "[DONE]"
            chunks = [json.loads(event) for event in events[:-1]]
            assert chunks == [
                {
                    "id": "chatcmpl",
                    "object": "chat.completion.chunk",
                    "model": "model",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": "ok"},
                            "finish_reason": None,
                        }
                    ],
                },
                {
                    "id": "chatcmpl",
                    "object": "chat.completion.chunk",
                    "model": "model",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                },
            ]
            assert "stream" not in upstream.requests[-1]
            assert "stream_options" not in upstream.requests[-1]
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
            assert "shiftedx_proxy_downstream_requests_total 2" in metrics.text
            assert "shiftedx_proxy_stream_replays_total 1" in metrics.text


@pytest.mark.asyncio
async def test_local_projection_marker_and_accounting_do_not_depend_on_telemetry_headers() -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1", telemetry_enabled=False), upstream)
    payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "report"},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "v",
                        "type": "function",
                        "function": {"name": "run_tests", "arguments": "{}"},
                    }
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
            response = await client.post("/v1/chat/completions", json=payload)
            metrics = await client.get("/metrics")
    assert response.status_code == 200
    assert response.json()["x-shiftedx-projection-v1"]["origin"] == "local_projection"
    assert response.json()["usage"] == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    assert "x-shiftedx-upstream-calls" not in response.headers
    assert upstream.requests == []
    assert "shiftedx_proxy_receipt_projections_total 1" in metrics.text
    assert "shiftedx_proxy_local_projection_upstream_calls_avoided_total 1" in metrics.text


@pytest.mark.asyncio
async def test_streamed_local_projection_keeps_its_truthful_origin_and_zero_usage() -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1", telemetry_enabled=False), upstream)
    payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "report"},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "v",
                        "type": "function",
                        "function": {"name": "run_tests", "arguments": "{}"},
                    }
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
        "stream": True,
        "stream_options": {"include_usage": True},
    }

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", json=payload)

    events = [line.removeprefix("data: ") for line in response.text.splitlines() if line]
    chunks = [json.loads(event) for event in events[:-1]]
    assert response.status_code == 200
    assert chunks[0]["x-shiftedx-projection-v1"]["origin"] == "local_projection"
    assert chunks[-1]["usage"] == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_stream_replay_preserves_reasoning_tool_calls_finish_reason_and_usage() -> None:
    upstream = RichCompletionUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "Inspect the file."}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                },
            }
        ],
        "stream": True,
        "stream_options": {"include_usage": True},
    }

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 200
    events = [line.removeprefix("data: ") for line in response.text.splitlines() if line]
    chunks = [json.loads(event) for event in events[:-1]]
    assert chunks[0]["choices"] == [
        {
            "index": 0,
            "delta": {
                "role": "assistant",
                "content": "",
                "reasoning_content": "Need the file.",
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "read_file", "arguments": '{"path":"a.py"}'},
                    }
                ],
            },
            "finish_reason": None,
        }
    ]
    assert chunks[1]["choices"] == [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
    assert chunks[2]["choices"] == []
    assert chunks[2]["usage"] == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    assert events[-1] == "[DONE]"


@pytest.mark.asyncio
async def test_stream_replay_paces_complete_sse_events_for_fragmented_downstream_reads() -> None:
    """A blocked downstream write must not let replay queue later SSE events."""
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), EchoUpstream())
    first_write = asyncio.Event()
    release_write = asyncio.Event()
    body_chunks: list[bytes] = []
    received_request = False

    async def receive() -> dict[str, Any]:
        nonlocal received_request
        if not received_request:
            received_request = True
            return {
                "type": "http.request",
                "body": json.dumps(
                    {
                        "model": "model",
                        "messages": [{"role": "user", "content": "hello"}],
                        "stream": True,
                    }
                ).encode(),
                "more_body": False,
            }
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        if message["type"] != "http.response.body" or not message.get("body"):
            return
        body_chunks.append(message["body"])
        if len(body_chunks) == 1:
            first_write.set()
            await release_write.wait()

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions",
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    task = asyncio.create_task(app(scope, receive, send))
    await asyncio.wait_for(first_write.wait(), timeout=1)

    assert len(body_chunks) == 1
    assert body_chunks[0].count(b"data: ") == 1
    assert body_chunks[0].endswith(b"\n\n")

    release_write.set()
    await asyncio.wait_for(task, timeout=1)
    assert b"".join(body_chunks).endswith(b"data: [DONE]\n\n")


@pytest.mark.asyncio
async def test_stream_replay_disconnect_stops_after_the_current_sse_event() -> None:
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), EchoUpstream())
    first_write = asyncio.Event()
    body_chunks: list[bytes] = []
    received_request = False

    async def receive() -> dict[str, Any]:
        nonlocal received_request
        if not received_request:
            received_request = True
            return {
                "type": "http.request",
                "body": b'{"model":"model","messages":[{"role":"user","content":"hello"}],"stream":true}',
                "more_body": False,
            }
        await first_write.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            body_chunks.append(message["body"])
            first_write.set()
            await asyncio.Event().wait()

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions",
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }

    await asyncio.wait_for(app(scope, receive, send), timeout=1)
    assert len(body_chunks) == 1


@pytest.mark.asyncio
async def test_stream_replay_is_bounded_before_sse_headers_are_sent() -> None:
    upstream = ScriptedCompletionUpstream(
        [
            {
                "id": "chatcmpl-large",
                "model": "model",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "x" * 1024},
                        "finish_reason": "stop",
                    }
                ],
            }
        ]
    )
    app = create_app(
        Settings(upstream_base_url="http://upstream/v1", max_upstream_response_bytes=1024), upstream
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
            )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_response_too_large"
    assert "x-shiftedx-stream-mode" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "completion",
    [
        {
            "model": "model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
        },
        {
            "id": "chatcmpl",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
        },
        {
            "id": "chatcmpl",
            "model": "model",
            "choices": [
                {
                    "index": "zero",
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
        },
        {
            "id": "chatcmpl",
            "model": "model",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "ok"}}
            ],
        },
    ],
)
async def test_malformed_optional_stream_fields_fail_before_sse_headers(
    completion: dict[str, Any],
) -> None:
    upstream = ScriptedCompletionUpstream([completion])
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
            )

    assert response.status_code == 502
    assert response.headers["content-type"].startswith("application/json")
    assert "x-shiftedx-stream-mode" not in response.headers
    assert response.json()["error"]["code"] == "upstream_malformed_completion"
    assert "data:" not in response.text


@pytest.mark.asyncio
async def test_stream_replay_never_releases_a_withheld_tool_batch() -> None:
    def tool_call(call_id: str, path: str) -> dict[str, Any]:
        return {
            "id": call_id,
            "type": "function",
            "function": {"name": "read_file", "arguments": json.dumps({"path": path})},
        }

    def completion(*calls: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": "chatcmpl-tools",
            "object": "chat.completion",
            "model": "model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "", "tool_calls": list(calls)},
                    "finish_reason": "tool_calls",
                }
            ],
        }

    upstream = ScriptedCompletionUpstream(
        [
            completion(tool_call("allowed-first", "b.py"), tool_call("blocked", "a.py")),
            completion(tool_call("allowed-reissued", "b.py")),
        ]
    )
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "inspect"},
            {"role": "assistant", "tool_calls": [tool_call("old", "a.py")]},
            {"role": "tool", "tool_call_id": "old", "content": "source"},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                },
            }
        ],
        "stream": True,
    }

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 200
    assert "allowed-reissued" in response.text
    assert "allowed-first" not in response.text
    assert "blocked" not in response.text
    assert len(upstream.requests) == 2


@pytest.mark.asyncio
async def test_http_phase_split_uses_two_safe_payload_phases_and_aggregate_only_counters() -> None:
    upstream = PhaseSplitUpstream()
    app = create_app(
        Settings(upstream_base_url="http://upstream/v1", upstream_tool_response_capability_mode="phase_split"),
        upstream,
    )
    schema = {
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
    payload = {
        "model": "model",
        "messages": [
            {"role": "user", "content": "inspect"},
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
        "response_format": schema,
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", json=payload)
            metrics = await client.get("/metrics")
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == '{"status":"done"}'
    assert "response_format" not in upstream.requests[0]
    assert upstream.requests[0]["tools"] == payload["tools"]
    assert upstream.requests[1]["response_format"] == schema
    assert "tools" not in upstream.requests[1]
    assert "tool_choice" not in upstream.requests[1]
    assert "shiftedx_proxy_phase_acquisition_total 1" in metrics.text
    assert "shiftedx_proxy_phase_finalization_total 1" in metrics.text
    assert "shiftedx_proxy_phase_schema_rejections_total 0" in metrics.text


@pytest.mark.asyncio
async def test_http_phase_split_complex_schema_fails_closed_without_echoing_or_upstream_call() -> None:
    upstream = EchoUpstream()
    app = create_app(
        Settings(upstream_base_url="http://upstream/v1", upstream_tool_response_capability_mode="phase_split"),
        upstream,
    )
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "answer"}],
        "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "result",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {"items": {"type": "array", "items": {"type": "string"}}},
                    "required": ["items"],
                    "additionalProperties": False,
                },
            },
        },
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post("/v1/chat/completions", json=payload)
            metrics = await client.get("/metrics")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_phase_split_schema"
    assert "items" not in response.text
    assert upstream.requests == []
    assert "shiftedx_proxy_phase_schema_rejections_total 1" in metrics.text


@pytest.mark.asyncio
async def test_http_phase_split_harness_opt_out_still_uses_safe_two_phase_translation() -> None:
    upstream = OptOutPhaseSplitUpstream()
    settings = Settings(
        upstream_base_url="http://upstream/v1",
        allow_harness_opt_out=True,
        trusted_policy_extension_api_keys=SecretStr("trusted-extension"),
        upstream_tool_response_capability_mode="phase_split",
    )
    app = create_app(settings, upstream)
    schema = {
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
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "answer"}],
        "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
        "response_format": schema,
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer trusted-extension", "X-Shiftedx-Harness": "off"},
                json=payload,
            )
            rejected = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer trusted-extension", "X-Shiftedx-Harness": "off"},
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "answer"}],
                    "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {"name": "result", "strict": True, "schema": {"type": "array"}},
                    },
                },
            )
            metrics = await client.get("/metrics", headers={"Authorization": "Bearer trusted-extension"})
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == '{"status":"done"}'
    assert upstream.requests[0]["messages"] == payload["messages"]
    assert upstream.requests[0]["tools"] == payload["tools"]
    assert "response_format" not in upstream.requests[0]
    assert upstream.requests[1]["response_format"] == schema
    assert "tools" not in upstream.requests[1]
    assert "tool_choice" not in upstream.requests[1]
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "unsupported_phase_split_schema"
    assert len(upstream.requests) == 2
    assert "shiftedx_proxy_phase_acquisition_total 1" in metrics.text
    assert "shiftedx_proxy_phase_finalization_total 1" in metrics.text
    assert "shiftedx_proxy_phase_schema_rejections_total 1" in metrics.text


@pytest.mark.asyncio
async def test_http_phase_split_harness_opt_out_releases_canonical_object_finalization_content() -> None:
    upstream = ObjectFinalizationUpstream()
    settings = Settings(
        upstream_base_url="http://upstream/v1",
        allow_harness_opt_out=True,
        trusted_policy_extension_api_keys=SecretStr("trusted-extension"),
        upstream_tool_response_capability_mode="phase_split",
    )
    app = create_app(settings, upstream)
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "answer"}],
        "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
        "response_format": {
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
        },
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer trusted-extension", "X-Shiftedx-Harness": "off"},
                json=payload,
            )
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == '{"status":"done"}'


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
                headers={
                    "Authorization": "Bearer downstream-secret",
                    "Cookie": "private=value",
                    "X-Shiftedx-Cache-Namespace": "opaque-header-value",
                },
                json={"model": "model", "messages": [{"role": "user", "content": "hello"}]},
            )
    await mock_client.aclose()
    assert response.status_code == 200
    assert captured["authorization"] == "Bearer upstream-secret"
    assert "cookie" not in captured
    assert "x-shiftedx-cache-namespace" not in captured


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
async def test_cache_namespace_controls_are_rejected_for_both_authenticated_principals(
    caplog: pytest.LogCaptureFixture,
) -> None:
    upstream = EchoUpstream()
    settings = Settings(
        upstream_base_url="http://upstream/v1",
        deployment_profile="production",
        proxy_api_key=SecretStr("ordinary-client"),
        trusted_policy_extension_api_keys=SecretStr("trusted-extension"),
    )
    app = create_app(settings, upstream)
    namespace_value = "opaque-namespace-test-value"
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": "hello"}],
        "cache_salt": namespace_value,
    }
    caplog.set_level(logging.WARNING, logger="shiftedx_harness_proxy")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            ordinary = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer ordinary-client"},
                json=payload,
            )
            trusted = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer trusted-extension"},
                json=payload,
            )
            metrics = await client.get("/metrics", headers={"Authorization": "Bearer ordinary-client"})
    assert ordinary.status_code == trusted.status_code == 400
    assert ordinary.json() == trusted.json()
    assert ordinary.json()["error"]["code"] == "untrusted_cache_namespace"
    assert ordinary.json()["error"]["message"] == (
        "Client-selected cache namespaces are not supported by this upstream profile."
    )
    assert namespace_value not in ordinary.text
    assert "cache_salt" not in ordinary.text
    assert namespace_value not in caplog.text
    assert "cache_salt" not in caplog.text
    assert "x-shiftedx-harness-profile" not in ordinary.headers
    assert upstream.requests == []
    assert "shiftedx_proxy_cache_namespace_rejections_total 2" in metrics.text


@pytest.mark.asyncio
async def test_unknown_cache_profile_rejects_before_the_upstream_call() -> None:
    upstream = EchoUpstream()
    app = create_app(
        Settings(upstream_base_url="http://upstream/v1", upstream_cache_capability_mode="unknown"),
        upstream,
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "promptCacheKey": ["any", "value", "type"],
                },
            )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "untrusted_cache_namespace"
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_duplicate_cache_namespace_spellings_receive_the_same_stable_rejection() -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    first_value = "first-opaque-namespace"
    second_value = "second-opaque-namespace"
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "cache_salt": first_value,
                    "Cache-Salt": second_value,
                },
            )
    assert response.status_code == 400
    assert response.json()["error"] == {
        "message": "Client-selected cache namespaces are not supported by this upstream profile.",
        "type": "shiftedx_proxy_error",
        "code": "untrusted_cache_namespace",
    }
    assert first_value not in response.text
    assert second_value not in response.text
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_cache_policy_preserves_nested_lookalikes_and_unrelated_top_level_fields() -> None:
    upstream = EchoUpstream()
    app = create_app(
        Settings(
            upstream_base_url="http://upstream/v1",
            upstream_cache_namespace_fields="provider_cache_scope",
        ),
        upstream,
    )
    preserved = {"number": 7, "items": [None, True, {"cache_salt": "nested-value"}]}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            configured = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "Provider-CacheScope": {"not": "forwarded"},
                },
            )
            permitted = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "model",
                    "messages": [
                        {
                            "role": "user",
                            "content": "hello",
                            "prompt_cache_key": "nested-lookalike",
                        }
                    ],
                    "vendor_extension": preserved,
                },
            )
    assert configured.status_code == 400
    assert configured.json()["error"]["code"] == "untrusted_cache_namespace"
    assert permitted.status_code == 200
    assert len(upstream.requests) == 1
    assert upstream.requests[0]["vendor_extension"] == preserved
    assert any(
        message.get("prompt_cache_key") == "nested-lookalike"
        for message in upstream.requests[0]["messages"]
        if isinstance(message, dict)
    )


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({}, "invalid_model"),
        ({"model": "", "messages": []}, "invalid_model"),
        ({"model": "model"}, "invalid_messages"),
        ({"model": "model", "messages": "not-an-array"}, "invalid_messages"),
        ({"model": "model", "messages": [{"role": "unknown", "content": "x"}]}, "invalid_messages"),
        ({"model": "model", "messages": [{"role": "user"}]}, "invalid_messages"),
        ({"model": "model", "messages": [{"role": "user", "content": []}]}, "invalid_messages"),
        (
            {"model": "model", "messages": [{"role": "user", "content": ["not-an-object"]}]},
            "invalid_messages",
        ),
        (
            {"model": "model", "messages": [{"role": "user", "content": [{}]}]},
            "invalid_messages",
        ),
        ({"model": "model", "messages": [{"role": "assistant", "content": None}]}, "invalid_messages"),
        ({"model": "model", "messages": [{"role": "assistant", "tool_calls": []}]}, "invalid_messages"),
        ({"model": "model", "messages": [], "stream": 1}, "invalid_stream"),
        (
            {"model": "model", "messages": [], "stream": True, "stream_options": []},
            "invalid_stream_options",
        ),
        (
            {
                "model": "model",
                "messages": [],
                "stream": True,
                "stream_options": {"include_usage": 1},
            },
            "invalid_stream_options",
        ),
        ({"model": "model", "messages": [], "n": True}, "multiple_choices_not_supported"),
        ({"model": "model", "messages": [], "n": 2}, "multiple_choices_not_supported"),
        ({"model": "model", "messages": [], "tools": [{"type": "function"}]}, "invalid_tools"),
        (
            {
                "model": "model",
                "messages": [],
                "x-shiftedx-require-receipt": 1,
            },
            "invalid_receipt_override",
        ),
        ({"model": "model", "messages": [], "response_format": "json_schema"}, "invalid_response_format"),
        (
            {"model": "model", "messages": [], "response_format": {"type": "json_schema"}},
            "invalid_response_format",
        ),
        (
            {
                "model": "model",
                "messages": [],
                "response_format": {"type": "json_schema", "json_schema": {"schema": []}},
            },
            "invalid_response_format",
        ),
        (
            {
                "model": "model",
                "messages": [],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"schema": {"type": "object", "properties": []}},
                },
            },
            "invalid_response_format",
        ),
    ],
)
async def test_invalid_chat_completions_fields_fail_locally(
    payload: dict[str, Any], code: str
) -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == code
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_invalid_harness_extension_fails_before_an_upstream_call() -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"X-Shiftedx-Harness": "maybe"},
                json={"model": "model", "messages": []},
            )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_harness_opt_out"
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_unknown_well_formed_content_part_and_response_format_are_preserved() -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    payload = {
        "model": "model",
        "messages": [{"role": "user", "content": [{"type": "future_input", "value": "hello"}]}],
        "response_format": {"type": "future_format", "provider_option": {"keep": True}},
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200
    assert upstream.requests[0]["response_format"] == payload["response_format"]
    assert upstream.requests[0]["messages"][1]["content"] == payload["messages"][0]["content"]


@pytest.mark.asyncio
async def test_correlation_id_is_validated_propagated_and_returned() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(
            200,
            json={"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    settings = Settings(upstream_base_url="http://upstream/v1")
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(settings, HttpxUpstream(settings, mock_client))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            safe = await client.post(
                "/v1/chat/completions",
                headers={"X-Request-ID": "client.trace-1"},
                json={"model": "model", "messages": []},
            )
            unsafe = await client.post(
                "/v1/chat/completions",
                headers={"X-Request-ID": "not safe"},
                json={"model": "model", "messages": []},
            )
    await mock_client.aclose()
    assert safe.headers["x-request-id"] == "client.trace-1"
    assert unsafe.headers["x-request-id"].startswith("shiftedx-")
    assert captured["x-request-id"] == unsafe.headers["x-request-id"]


@pytest.mark.asyncio
async def test_only_proxy_correlation_header_reaches_credentialed_upstream() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(
            200,
            json={"id": "chatcmpl", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    settings = Settings(upstream_base_url="http://upstream/v1", upstream_api_key=SecretStr("upstream-key"))
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(settings, HttpxUpstream(settings, mock_client))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer downstream-key",
                    "Cookie": "private=value",
                    "OpenAI-Organization": "org-downstream",
                    "OpenAI-Project": "proj-downstream",
                    "X-Request-ID": "client.trace-1",
                },
                json={"model": "model", "messages": []},
            )
    await mock_client.aclose()
    assert response.status_code == 200
    assert captured["authorization"] == "Bearer upstream-key"
    assert captured["x-request-id"] == "client.trace-1"
    assert "cookie" not in captured
    assert "openai-organization" not in captured
    assert "openai-project" not in captured


@pytest.mark.asyncio
async def test_invalid_correlation_id_is_not_emitted_as_log_structure(caplog: pytest.LogCaptureFixture) -> None:
    upstream = EchoUpstream()
    app = create_app(Settings(upstream_base_url="http://upstream/v1"), upstream)
    caplog.set_level(logging.WARNING, logger="shiftedx_harness_proxy")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"X-Request-ID": "not safe"},
                json={},
            )
    correlation_id = response.headers["x-request-id"]
    assert correlation_id.startswith("shiftedx-")
    assert f"correlation_id={correlation_id}" in caplog.text
    assert "correlation_id=not safe" not in caplog.text
    assert upstream.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("upstream_status", "downstream_status", "code"),
    [
        (400, 400, "upstream_bad_request"),
        (401, 502, "upstream_authentication_failed"),
        (403, 502, "upstream_authentication_failed"),
        (404, 502, "upstream_not_found"),
        (409, 409, "upstream_conflict"),
        (422, 422, "upstream_unprocessable"),
        (429, 429, "upstream_rate_limited"),
        (500, 502, "upstream_server_error"),
    ],
)
async def test_upstream_statuses_are_safe_and_mapped(
    upstream_status: int, downstream_status: int, code: str
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            upstream_status,
            text='{"secret":"must-not-leak"}',
            headers={
                "Retry-After": "5",
                "X-Request-ID": "upstream-request-1",
                "X-RateLimit-Remaining-Requests": "4",
                "Set-Cookie": "secret-cookie",
            },
        )

    settings = Settings(upstream_base_url="http://upstream/v1")
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(settings, HttpxUpstream(settings, mock_client))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            response = await client.post(
                "/v1/chat/completions", json={"model": "model", "messages": []}
            )
    await mock_client.aclose()
    assert response.status_code == downstream_status
    assert response.json()["error"]["code"] == code
    assert "must-not-leak" not in response.text
    assert "set-cookie" not in response.headers
    assert "authorization" not in response.headers
    assert response.headers["x-shiftedx-upstream-request-id"] == "upstream-request-1"
    if upstream_status == 429:
        assert response.headers["retry-after"] == "5"
        assert response.headers["x-shiftedx-upstream-Ratelimit-Remaining-Requests"] == "4"
    else:
        assert "retry-after" not in response.headers
