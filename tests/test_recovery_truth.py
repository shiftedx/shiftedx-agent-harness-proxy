from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings

JsonObject = dict[str, Any]


def tool_call(call_id: str, name: str, arguments: JsonObject) -> JsonObject:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments, sort_keys=True, separators=(",", ":")),
        },
    }


def completion(*, content: str = "", calls: list[JsonObject] | None = None) -> JsonObject:
    return {
        "id": "chatcmpl-recovery",
        "object": "chat.completion",
        "model": "model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content, "tool_calls": calls or []},
                "finish_reason": "tool_calls" if calls else "stop",
            }
        ],
    }


class RecoveryTruthUpstream:
    """A semantic fake that reproduces the ambiguity behind issue #47."""

    def __init__(self) -> None:
        self.requests: list[JsonObject] = []

    async def chat(self, payload: JsonObject, request_headers: dict[str, str]) -> JsonObject:
        del request_headers
        self.requests.append(payload)
        messages = payload["messages"]
        rendered = json.dumps(messages, sort_keys=True)
        if "duplicate_call_blocked" in rendered:
            if (
                "blocked_not_executed" in rendered
                and "did not reach the client executor" in rendered
            ):
                return completion(
                    calls=[tool_call("recovery", "apply_patch", {})]
                )
            return completion(content="Both failed actions executed; recovery complete.")

        tool_results = [
            message
            for message in messages
            if isinstance(message, dict) and message.get("role") == "tool"
        ]
        latest_id = tool_results[-1].get("tool_call_id") if tool_results else None
        if latest_id == "verification":
            grounded = "Only downstream-visible assistant tool-call IDs paired with client-supplied" in rendered
            failed_executions = 1 if grounded else 2
            return completion(
                content=json.dumps(
                    {"failed_executions": failed_executions, "recovery_verified": True},
                    separators=(",", ":"),
                )
            )
        if latest_id == "recovery":
            return completion(calls=[tool_call("verification", "run_tests", {})])
        return completion(calls=[tool_call("repeat", "run_tests", {"target": "original"})])

    async def models(self, request_headers: dict[str, str]) -> JsonObject:
        del request_headers
        return {"object": "list", "data": []}

    async def combined_tool_terminal_schema_supported(self) -> bool:
        return False

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def replay_message(response: httpx.Response) -> JsonObject:
    events = [line.removeprefix("data: ") for line in response.text.splitlines() if line]
    assert events[-1] == "[DONE]"
    chunks = [json.loads(event) for event in events[:-1]]
    return chunks[0]["choices"][0]["delta"]


@pytest.mark.asyncio
async def test_failed_repeat_recovers_once_and_final_claim_matches_client_execution_ledger() -> None:
    original = tool_call("original", "run_tests", {"target": "original"})
    messages: list[JsonObject] = [
        {"role": "user", "content": "Recover from the failed check."},
        {"role": "assistant", "content": "", "tool_calls": [original]},
        {"role": "tool", "tool_call_id": "original", "content": "1 failed"},
    ]
    tools = [
        {"type": "function", "function": {"name": "run_tests", "parameters": {}}},
        {"type": "function", "function": {"name": "apply_patch", "parameters": {}}},
    ]
    upstream = RecoveryTruthUpstream()
    app = create_app(
        Settings(upstream_base_url="http://upstream/v1", telemetry_enabled=True), upstream
    )
    client_executions = ["original"]

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            first = await client.post(
                "/v1/chat/completions",
                json={"model": "model", "messages": messages, "tools": tools, "stream": True},
            )
            assert first.status_code == 200, [
                {
                    "blocked": "duplicate_call_blocked" in json.dumps(request["messages"]),
                    "not_executed": "blocked_not_executed" in json.dumps(request["messages"]),
                    "attempt_messages": len(request["messages"]),
                }
                for request in upstream.requests
            ]
            recovery = replay_message(first)
            messages.extend(
                [
                    recovery,
                    {"role": "tool", "tool_call_id": "recovery", "content": "Patch applied."},
                ]
            )
            client_executions.append("recovery")

            second = await client.post(
                "/v1/chat/completions",
                json={"model": "model", "messages": messages, "tools": tools, "stream": True},
            )
            verification = replay_message(second)
            messages.extend(
                [
                    verification,
                    {"role": "tool", "tool_call_id": "verification", "content": "8 passed"},
                ]
            )
            client_executions.append("verification")

            third = await client.post(
                "/v1/chat/completions",
                json={"model": "model", "messages": messages, "tools": tools, "stream": True},
            )
            final = json.loads(replay_message(third)["content"])
            metrics = (await client.get("/metrics")).text

    assert first.status_code == second.status_code == third.status_code == 200
    assert first.headers["x-shiftedx-upstream-calls"] == "2"
    assert first.headers["x-shiftedx-blocked-duplicates"] == "1"
    assert first.headers["x-shiftedx-corrections"] == "0"
    assert client_executions == ["original", "recovery", "verification"]
    assert "repeat" not in client_executions
    assert final == {"failed_executions": 1, "recovery_verified": True}
    assert len(upstream.requests) == 4
    assert "shiftedx_proxy_downstream_requests_total 3" in metrics
    assert "shiftedx_proxy_upstream_calls_total 4" in metrics
    assert "shiftedx_proxy_blocked_duplicates_total 1" in metrics
    assert "shiftedx_proxy_correction_turns_total 0" in metrics
