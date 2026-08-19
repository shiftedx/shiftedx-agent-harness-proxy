import asyncio
import json
from typing import Any

import pytest

from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.errors import ProxyError
from shiftedx_harness_proxy.service import ChatService


def call(call_id: str, name: str, arguments: str) -> dict[str, Any]:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def completion(*, content: str = "", calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "id": "chatcmpl-upstream",
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


class ScriptedUpstream:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        return self.responses.pop(0)

    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        return {"object": "list", "data": []}

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def request(messages: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "model": "model",
        "messages": messages,
        "tools": [
            {"type": "function", "function": {"name": "read_file", "parameters": {}}},
            {"type": "function", "function": {"name": "apply_patch", "parameters": {}}},
            {"type": "function", "function": {"name": "run_tests", "parameters": {}}},
        ],
    }


@pytest.mark.asyncio
async def test_legitimate_tool_call_is_returned_byte_for_byte() -> None:
    proposed = completion(calls=[call("new", "read_file", '{"path":"a.py"}')])
    upstream = ScriptedUpstream([proposed])
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        request([{"role": "user", "content": "inspect"}]), {}
    )
    assert result.body == proposed
    assert result.telemetry.upstream_calls == 1


@pytest.mark.asyncio
async def test_ordinary_client_cannot_disable_the_receipt_requirement() -> None:
    upstream = ScriptedUpstream([completion(content="refused")])
    payload = request([{"role": "user", "content": "Do not perform the destructive action."}])
    payload["x-shiftedx-require-receipt"] = False

    with pytest.raises(ProxyError) as raised:
        await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(payload, {})

    assert raised.value.status_code == 403
    assert raised.value.code == "receipt_override_denied"
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_trusted_policy_extension_can_disable_receipt_requirement_and_is_stripped() -> None:
    upstream = ScriptedUpstream([completion(content="refused")])
    payload = request([{"role": "user", "content": "Do not perform the destructive action."}])
    payload["x-shiftedx-require-receipt"] = False

    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        payload, {}, policy_extensions_allowed=True
    )
    assert result.body["choices"][0]["message"]["content"] == "refused"
    assert "x-shiftedx-require-receipt" not in upstream.requests[0]
    assert result.telemetry.policy_extensions_used == 1


@pytest.mark.asyncio
async def test_receipt_requirement_extension_must_be_boolean() -> None:
    upstream = ScriptedUpstream([])
    payload = request([{"role": "user", "content": "inspect"}])
    payload["x-shiftedx-require-receipt"] = "false"

    with pytest.raises(ProxyError) as raised:
        await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(payload, {})

    assert raised.value.code == "invalid_receipt_override"
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_trusted_extension_can_reclassify_a_protected_tool_only_when_authorised() -> None:
    payload = request(
        [
            {"role": "user", "content": "repair"},
            {"role": "assistant", "tool_calls": [call("m", "apply_patch", '{"patch":"x"}')]},
            {"role": "tool", "tool_call_id": "m", "content": "Patch applied."},
        ]
    )
    payload["tools"][1]["function"]["x-shiftedx-role"] = "other"
    denied_upstream = ScriptedUpstream([])
    with pytest.raises(ProxyError) as denied:
        await ChatService(Settings(upstream_base_url="http://upstream/v1"), denied_upstream).complete(
            payload, {}
        )
    assert denied.value.code == "protected_role_override_denied"

    allowed_upstream = ScriptedUpstream([completion(content="done")])
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), allowed_upstream).complete(
        payload, {}, policy_extensions_allowed=True
    )
    assert result.body["choices"][0]["message"]["content"] == "done"
    assert result.telemetry.policy_extensions_used == 1
    assert "x-shiftedx-role" not in str(allowed_upstream.requests[0]["tools"])


@pytest.mark.asyncio
async def test_same_epoch_duplicate_never_reaches_client_and_is_retried_internally() -> None:
    duplicate = call("dup", "read_file", '{"path":"a.py"}')
    upstream = ScriptedUpstream([completion(calls=[duplicate]), completion(content="done")])
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        request(
            [
                {"role": "user", "content": "inspect"},
                {"role": "assistant", "tool_calls": [call("old", "read_file", '{"path":"a.py"}')]},
                {"role": "tool", "tool_call_id": "old", "content": "source"},
            ]
        ),
        {},
    )
    assert result.body["choices"][0]["message"]["tool_calls"] == []
    assert result.telemetry.blocked_duplicates == 1
    assert result.telemetry.upstream_calls == 2
    assert "duplicate_call_blocked" in str(upstream.requests[1]["messages"])


@pytest.mark.asyncio
async def test_identical_read_is_allowed_after_successful_mutation_opens_new_epoch() -> None:
    upstream = ScriptedUpstream([completion(calls=[call("new", "read_file", '{"path":"a.py"}')])])
    messages = [
        {"role": "user", "content": "repair"},
        {"role": "assistant", "tool_calls": [call("r", "read_file", '{"path":"a.py"}')]},
        {"role": "tool", "tool_call_id": "r", "content": "source"},
        {"role": "assistant", "tool_calls": [call("m", "apply_patch", '{"patch":"x"}')]},
        {"role": "tool", "tool_call_id": "m", "content": "Patch applied."},
    ]
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        request(messages), {}
    )
    assert result.body["choices"][0]["message"]["tool_calls"][0]["id"] == "new"
    assert result.telemetry.blocked_duplicates == 0


@pytest.mark.asyncio
async def test_terminal_correction_is_bounded_to_two_retries() -> None:
    upstream = ScriptedUpstream([completion(content="not json") for _ in range(3)])
    payload = {"model": "model", "messages": [{"role": "user", "content": "answer"}], "tools": []}
    payload["response_format"] = {
        "type": "json_schema",
        "json_schema": {
            "name": "result",
            "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        },
    }
    with pytest.raises(ProxyError) as raised:
        await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(payload, {})
    assert raised.value.code == "harness_retry_exhausted"
    assert len(upstream.requests) == 3


@pytest.mark.asyncio
async def test_valid_fenced_declared_json_is_normalized_without_a_correction_turn() -> None:
    upstream = ScriptedUpstream([completion(content='```json\n{"ok":true}\n```')])
    payload = {"model": "model", "messages": [{"role": "user", "content": "answer"}], "tools": []}
    payload["response_format"] = {
        "type": "json_schema",
        "json_schema": {
            "name": "result",
            "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        },
    }
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(payload, {})
    assert result.body["choices"][0]["message"]["content"] == '{"ok":true}'
    assert result.telemetry.corrections == 0


@pytest.mark.asyncio
async def test_mutation_prevents_terminal_answer_until_a_verifier_is_requested() -> None:
    upstream = ScriptedUpstream(
        [completion(content="done"), completion(calls=[call("verify", "run_tests", "{}")])]
    )
    messages = [
        {"role": "user", "content": "repair"},
        {"role": "assistant", "tool_calls": [call("mutation", "apply_patch", '{"patch":"x"}')]},
        {"role": "tool", "tool_call_id": "mutation", "content": "Patch applied."},
    ]
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        request(messages), {}
    )
    assert result.body["choices"][0]["message"]["tool_calls"][0]["id"] == "verify"
    assert result.telemetry.corrections == 1


@pytest.mark.asyncio
async def test_complete_typed_latest_receipt_projects_without_upstream_call() -> None:
    upstream = ScriptedUpstream([])
    payload = request(
        [
            {"role": "user", "content": "report"},
            {"role": "assistant", "tool_calls": [call("v", "run_tests", "{}")]},
            {"role": "tool", "tool_call_id": "v", "content": "14 passed"},
        ]
    )
    payload["response_format"] = {
        "type": "json_schema",
        "json_schema": {
            "name": "result",
            "schema": {
                "type": "object",
                "properties": {"status": {"type": "string"}, "tests": {"type": "integer"}},
            },
        },
    }
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(payload, {})
    assert result.body["choices"][0]["message"]["content"] == '{"status":"passed","tests":14}'
    assert result.telemetry.receipt_projections == 1
    assert upstream.requests == []


@pytest.mark.asyncio
async def test_blocked_parallel_sibling_is_withheld_then_can_be_reissued_unchanged() -> None:
    first_allowed = call("allowed-first", "read_file", '{"path":"b.py"}')
    blocked = call("blocked", "read_file", '{"path":"a.py"}')
    reissued = call("allowed-reissued", "read_file", '{"path":"b.py"}')
    upstream = ScriptedUpstream(
        [completion(calls=[first_allowed, blocked]), completion(calls=[reissued])]
    )
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        request(
            [
                {"role": "user", "content": "inspect"},
                {"role": "assistant", "tool_calls": [call("old", "read_file", '{"path":"a.py"}')]},
                {"role": "tool", "tool_call_id": "old", "content": "source"},
            ]
        ),
        {},
    )
    returned = result.body["choices"][0]["message"]["tool_calls"]
    assert returned == [reissued]
    internal_messages = upstream.requests[1]["messages"]
    assert "response_withheld_due_to_blocked_sibling" in str(internal_messages)
    assert upstream.requests[1].get("tool_choice") != "none"
    assert result.telemetry.blocked_duplicates == 1


@pytest.mark.asyncio
async def test_controlled_opt_out_preserves_multiple_choice_requests() -> None:
    response = {
        "id": "chatcmpl-upstream",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "a"}},
            {"index": 1, "message": {"role": "assistant", "content": "b"}},
        ],
    }
    upstream = ScriptedUpstream([response])
    payload = {"model": "model", "messages": [{"role": "user", "content": "answer"}], "n": 2}
    result = await ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream).complete(
        payload, {}, harness_enabled=False
    )
    assert result.body == response
    assert upstream.requests[0]["n"] == 2


class DuplicateThenFinishUpstream(ScriptedUpstream):
    def __init__(self) -> None:
        super().__init__([])

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append(payload)
        if "duplicate_call_blocked" in str(payload["messages"]):
            return completion(content="done")
        previous = next(
            message
            for message in payload["messages"]
            if message.get("role") == "assistant" and message.get("tool_calls")
        )
        arguments = previous["tool_calls"][0]["function"]["arguments"]
        path = json.loads(arguments)["path"]
        await asyncio.sleep(0)
        return completion(calls=[call(f"repeat-{path}", "read_file", arguments)])


@pytest.mark.asyncio
async def test_concurrent_requests_reconstruct_isolated_receipt_state() -> None:
    upstream = DuplicateThenFinishUpstream()
    service = ChatService(Settings(upstream_base_url="http://upstream/v1"), upstream)

    async def run(path: str):
        return await service.complete(
            request(
                [
                    {"role": "user", "content": f"inspect {path}"},
                    {
                        "role": "assistant",
                        "tool_calls": [call(f"old-{path}", "read_file", json.dumps({"path": path}))],
                    },
                    {"role": "tool", "tool_call_id": f"old-{path}", "content": f"source {path}"},
                ]
            ),
            {},
        )

    first, second = await asyncio.gather(run("a.py"), run("b.py"))
    assert first.telemetry.blocked_duplicates == 1
    assert second.telemetry.blocked_duplicates == 1
    assert len(upstream.requests) == 4
