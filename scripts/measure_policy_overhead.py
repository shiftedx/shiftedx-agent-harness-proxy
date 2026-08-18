from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import time
from datetime import UTC, datetime
from typing import Any

from shiftedx_harness_proxy.config import Settings
from shiftedx_harness_proxy.service import ChatService


def completion(content: str = "ok") -> dict[str, Any]:
    return {
        "id": "chatcmpl-scripted",
        "object": "chat.completion",
        "model": "scripted",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
        ],
    }


class ImmediateUpstream:
    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        return completion()

    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        return {"object": "list", "data": []}

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


async def measure(iterations: int) -> dict[str, Any]:
    service = ChatService(Settings(upstream_base_url="http://scripted/v1"), ImmediateUpstream())
    payload = {"model": "scripted", "messages": [{"role": "user", "content": "hello"}]}
    durations: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        await service.complete(payload, {})
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "schema_version": "1.0",
        "measured_at": datetime.now(UTC).isoformat(),
        "platform": platform.machine(),
        "python": platform.python_version(),
        "iterations": iterations,
        "scripted_upstream": True,
        "upstream_calls_per_request": 1,
        "latency_ms": {
            "p50": round(statistics.median(durations), 4),
            "p95": round(percentile(durations, 0.95), 4),
            "max": round(max(durations), 4),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000)
    args = parser.parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be positive")
    print(json.dumps(asyncio.run(measure(args.iterations)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
