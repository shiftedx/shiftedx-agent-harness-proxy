#!/usr/bin/env python3
"""Run a sanitized stock-Hermes validate-then-replay qualification smoke."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI

from shiftedx_harness_proxy.api import create_app
from shiftedx_harness_proxy.config import Settings

JsonObject = dict[str, Any]


class ProtocolLedger:
    def __init__(self) -> None:
        self.downstream_requests: list[JsonObject] = []
        self.upstream_requests: list[JsonObject] = []

    def observe_downstream(self, payload: JsonObject) -> None:
        self.downstream_requests.append(payload)

    def observe_upstream(self, payload: JsonObject) -> None:
        self.upstream_requests.append(payload)

    def evidence(self) -> JsonObject:
        streaming = [
            request for request in self.downstream_requests if request.get("stream") is True
        ]
        first_stream = streaming[0] if streaming else {}
        later = self.upstream_requests[1:]
        tool_results = [
            message
            for request in later
            for message in request.get("messages", [])
            if isinstance(message, dict) and message.get("role") == "tool"
        ]
        return {
            "downstream_request_count": len(self.downstream_requests),
            "downstream_stream_request_count": len(streaming),
            "upstream_request_count": len(self.upstream_requests),
            "downstream_stream_requested": bool(streaming),
            "downstream_stream_options_include_usage": (
                isinstance(first_stream.get("stream_options"), dict)
                and first_stream["stream_options"].get("include_usage") is True
            ),
            "upstream_stream_controls_removed": bool(self.upstream_requests)
            and all(
                "stream" not in request and "stream_options" not in request
                for request in self.upstream_requests
            ),
            "tool_result_observed": len(tool_results) == 1,
            "tool_result_matches_call": bool(tool_results)
            and tool_results[0].get("tool_call_id") == "qualify_call",
        }


def upstream_app(ledger: ProtocolLedger) -> FastAPI:
    app = FastAPI()

    @app.get("/v1/models")
    async def models() -> JsonObject:
        return {"object": "list", "data": [{"id": "qualify-model", "object": "model"}]}

    @app.post("/v1/chat/completions")
    async def chat(payload: JsonObject) -> JsonObject:
        ledger.observe_upstream(payload)
        has_tool_result = any(
            isinstance(message, dict) and message.get("role") == "tool"
            for message in payload.get("messages", [])
        )
        if not has_tool_result:
            return {
                "id": "chatcmpl-qualify-tool",
                "object": "chat.completion",
                "model": "qualify-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "qualify_call",
                                    "type": "function",
                                    "function": {
                                        "name": "read_file",
                                        "arguments": '{"path":"README.md","line_end":1}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        return {
            "id": "chatcmpl-qualify-terminal",
            "object": "chat.completion",
            "model": "qualify-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "42"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }

    return app


@contextmanager
def running_server(app: Any) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("qualification server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("qualification server did not stop")


def write_isolated_config(home: Path, proxy_base_url: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        "\n".join(
            [
                "model:",
                "  default: qualify-model",
                "  provider: qualification-proxy",
                "providers:",
                "  qualification-proxy:",
                f"    api: {proxy_base_url}/v1",
                "    transport: chat_completions",
                "    default_model: qualify-model",
                "    discover_models: false",
                "    models:",
                "      - qualify-model",
                "display:",
                "  streaming: false",
                "",
            ]
        ),
        encoding="utf-8",
    )


def capture_downstream_requests(app: FastAPI, ledger: ProtocolLedger) -> None:
    @app.middleware("http")
    async def capture(request: Any, call_next: Any) -> Any:
        if request.url.path == "/v1/chat/completions":
            ledger.observe_downstream(await request.json())
        return await call_next(request)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hermes", default="hermes")
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()

    version = subprocess.run(  # noqa: S603 - the operator selects the Hermes executable.
        [args.hermes, "--version"], capture_output=True, check=True, text=True, timeout=10
    ).stdout.splitlines()[0]
    ledger = ProtocolLedger()
    with running_server(upstream_app(ledger)) as upstream_base_url:
        proxy = create_app(Settings(upstream_base_url=f"{upstream_base_url}/v1"))
        capture_downstream_requests(proxy, ledger)
        with running_server(proxy) as proxy_base_url:
            with tempfile.TemporaryDirectory(prefix="hermes-streaming-qualification-") as raw_home:
                home = Path(raw_home)
                write_isolated_config(home, proxy_base_url)
                env = os.environ.copy()
                env["HERMES_HOME"] = str(home)
                run = subprocess.run(  # noqa: S603 - the operator selects the Hermes executable.
                    [
                        args.hermes,
                        "chat",
                        "--query",
                        "Read the first line of README.md with the available file tool, then answer exactly 42.",
                        "--toolsets",
                        "file",
                        "--provider",
                        "qualification-proxy",
                        "--model",
                        "qualify-model",
                        "--quiet",
                        "--ignore-rules",
                        "--source",
                        "tool",
                        "--max-turns",
                        "4",
                        "--run-budget",
                        "30",
                    ],
                    capture_output=True,
                    env=env,
                    text=True,
                    timeout=45,
                )
            evidence = {
                "schema_version": "1.0",
                "hermes_version": version,
                "hermes_exit_code": run.returncode,
                "terminal_answer_observed": "42" in run.stdout,
                "stream_replay_count": proxy.state.counters.stream_replays,
                **ledger.evidence(),
            }
            evidence["passed"] = all(
                [
                    run.returncode == 0,
                    evidence["terminal_answer_observed"],
                    evidence["downstream_stream_requested"],
                    evidence["downstream_stream_options_include_usage"],
                    evidence["upstream_stream_controls_removed"],
                    evidence["stream_replay_count"]
                    == evidence["downstream_stream_request_count"],
                    evidence["tool_result_observed"],
                    evidence["tool_result_matches_call"],
                ]
            )
            rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
            if args.evidence_out is not None:
                args.evidence_out.write_text(rendered, encoding="utf-8")
            print(rendered, end="")
            if not evidence["passed"] and run.stderr:
                print("Hermes qualification failed; inspect the private process stderr.", file=os.sys.stderr)
            return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
