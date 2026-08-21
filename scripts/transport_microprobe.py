#!/usr/bin/env python3
"""Measure local HTTP keep-alive pooling mechanics without a production latency claim."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NoReturn, cast

import httpx

from shiftedx_harness_proxy.qualification_timing import HttpxTraceDurations

_MAX_REQUESTS = 128
_MAX_CONCURRENCY = 16
_MAX_SPACING_MS = 1_000
_MAX_RUNTIME_SECONDS = 60.0
_DEFAULT_RUNTIME_SECONDS = 10.0
_REQUEST_TIMEOUT_SECONDS = 2.0


class _BoundedParser(argparse.ArgumentParser):
    """Keep malformed invocation failures categorical and free of incidental detail."""

    def error(self, _message: str) -> NoReturn:
        raise ValueError


@dataclass
class _ProbeState:
    """Thread-safe aggregate counters, intentionally with no request payloads."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    connection_count: int = 0
    response_count: int = 0

    def connected(self) -> None:
        with self.lock:
            self.connection_count += 1

    def responded(self) -> None:
        with self.lock:
            self.response_count += 1

    def snapshot(self) -> tuple[int, int]:
        with self.lock:
            return self.connection_count, self.response_count


class _ProbeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, state: _ProbeState) -> None:
        super().__init__(("127.0.0.1", 0), _ProbeHandler)
        self.state = state


class _ProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def _state(self) -> _ProbeState:
        return cast(_ProbeState, cast(Any, self.server).state)

    def setup(self) -> None:
        super().setup()
        self._state.connected()

    def do_GET(self) -> None:  # noqa: N802 - HTTP server callback spelling.
        if self.path != "/probe":
            self.send_error(404)
            return
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._state.responded()

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress server logs so the output channel stays aggregate-only JSON."""


def _positive_int(value: str, *, maximum: int) -> int:
    parsed = int(value)
    if not 1 <= parsed <= maximum:
        raise ValueError
    return parsed


def _nonnegative_int(value: str, *, maximum: int) -> int:
    parsed = int(value)
    if not 0 <= parsed <= maximum:
        raise ValueError
    return parsed


def _expiry(value: str) -> float:
    parsed = float(value)
    if parsed < 0 or parsed > _MAX_RUNTIME_SECONDS:
        raise ValueError
    return parsed


async def _issue_requests(
    *,
    url: str,
    request_count: int,
    concurrency: int,
    request_spacing_ms: int,
    keepalive_expiry_seconds: float,
    max_runtime_seconds: float,
) -> list[dict[str, object]]:
    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=concurrency,
        keepalive_expiry=keepalive_expiry_seconds,
    )
    semaphore = asyncio.Semaphore(concurrency)
    transports: list[dict[str, object]] = []
    async with httpx.AsyncClient(
        limits=limits,
        timeout=httpx.Timeout(_REQUEST_TIMEOUT_SECONDS),
        follow_redirects=False,
        trust_env=False,
    ) as client:

        async def one_request(index: int) -> None:
            if request_spacing_ms:
                await asyncio.sleep((index * request_spacing_ms) / 1_000)
            async with semaphore:
                trace = HttpxTraceDurations()
                started_ns = time.perf_counter_ns()
                response = await client.get(url, extensions={"trace": trace.callback})
                response.raise_for_status()
                transports.append(trace.transport(time.perf_counter_ns() - started_ns))

        await asyncio.wait_for(
            asyncio.gather(*(one_request(index) for index in range(request_count))),
            timeout=max_runtime_seconds,
        )
    return transports


def _floor_percentiles(values: list[int]) -> dict[str, int]:
    if not values:
        raise RuntimeError("local_probe_counts_invalid")
    ordered = sorted(values)
    return {
        "p50_ns": ordered[int((len(ordered) - 1) * 0.50)],
        "p95_ns": ordered[int((len(ordered) - 1) * 0.95)],
    }


def _response_header_summary(transports: list[dict[str, object]]) -> dict[str, int | None]:
    measured_values: list[int] = []
    for transport in transports:
        value = transport.get("response_header_wait_ns")
        availability = transport.get("response_header_wait_availability")
        if isinstance(value, int) and isinstance(availability, dict) and availability.get("state") == "measured":
            measured_values.append(value)
    return {
        "measured_count": len(measured_values),
        "unavailable_count": len(transports) - len(measured_values),
        "p50_ns": _floor_percentiles(measured_values)["p50_ns"] if measured_values else None,
        "p95_ns": _floor_percentiles(measured_values)["p95_ns"] if measured_values else None,
    }


def _trace_reuse_counts(transports: list[dict[str, object]]) -> dict[str, int]:
    counts = {"fresh_count": 0, "reused_count": 0, "unavailable_count": 0}
    for transport in transports:
        reuse = transport.get("connection_reuse")
        if reuse == "fresh":
            counts["fresh_count"] += 1
        elif reuse == "reused":
            counts["reused_count"] += 1
        else:
            counts["unavailable_count"] += 1
    return counts


def _run_case(
    *,
    label: str,
    keepalive_expiry_seconds: float,
    request_count: int,
    concurrency: int,
    request_spacing_ms: int,
    max_runtime_seconds: float,
) -> dict[str, object]:
    state = _ProbeState()
    server = _ProbeServer(state)
    host, port = server.server_address[:2]
    host_text = host.decode("ascii") if isinstance(host, bytes) else host
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        transports = asyncio.run(
            _issue_requests(
                url=f"http://{host_text}:{port}/probe",
                request_count=request_count,
                concurrency=concurrency,
                request_spacing_ms=request_spacing_ms,
                keepalive_expiry_seconds=keepalive_expiry_seconds,
                max_runtime_seconds=max_runtime_seconds,
            )
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    fresh_connections, responses = state.snapshot()
    if responses != request_count or len(transports) != request_count or not 1 <= fresh_connections <= responses:
        raise RuntimeError("local_probe_counts_invalid")
    client_wall_ns = [value for transport in transports if isinstance((value := transport.get("total_ns")), int)]
    if len(client_wall_ns) != request_count:
        raise RuntimeError("local_probe_counts_invalid")
    return {
        "label": label,
        "keepalive_expiry_seconds": keepalive_expiry_seconds,
        "response_count": responses,
        "fresh_connection_count": fresh_connections,
        "server_observed_reused_request_count": responses - fresh_connections,
        "client_wall_ns": _floor_percentiles(client_wall_ns),
        # Header receipt is a traceable HTTP phase, not token TTFT.
        "response_header_wait_ns": _response_header_summary(transports),
        "trace_connection_reuse_counts": _trace_reuse_counts(transports),
    }


def _write_new_file(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.parent.is_symlink():
        raise OSError("unsafe output path")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("partial output write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = _BoundedParser(description=__doc__)
    parser.add_argument("--requests", type=lambda value: _positive_int(value, maximum=_MAX_REQUESTS), default=12)
    parser.add_argument("--concurrency", type=lambda value: _positive_int(value, maximum=_MAX_CONCURRENCY), default=2)
    parser.add_argument(
        "--request-spacing-ms", type=lambda value: _nonnegative_int(value, maximum=_MAX_SPACING_MS), default=0
    )
    parser.add_argument("--current-keepalive-expiry-seconds", type=_expiry, default=httpx.Limits().keepalive_expiry)
    parser.add_argument("--declared-keepalive-expiry-seconds", type=_expiry, default=0.0)
    parser.add_argument("--max-runtime-seconds", type=float, default=_DEFAULT_RUNTIME_SECONDS)
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        if not 0 < args.max_runtime_seconds <= _MAX_RUNTIME_SECONDS:
            raise ValueError
        current_expiry = args.current_keepalive_expiry_seconds
        if current_expiry is None:
            raise ValueError
        cases = [
            _run_case(
                label="current_pool_default",
                keepalive_expiry_seconds=current_expiry,
                request_count=args.requests,
                concurrency=args.concurrency,
                request_spacing_ms=args.request_spacing_ms,
                max_runtime_seconds=args.max_runtime_seconds,
            ),
            _run_case(
                label="declared_keepalive_expiry",
                keepalive_expiry_seconds=args.declared_keepalive_expiry_seconds,
                request_count=args.requests,
                concurrency=args.concurrency,
                request_spacing_ms=args.request_spacing_ms,
                max_runtime_seconds=args.max_runtime_seconds,
            ),
        ]
        report = {
            "schema_version": "transport_microprobe_v1",
            "scope": "local_http_pool_mechanism_only",
            "production_latency_claim": False,
            "trace_connection_reuse": "no_reused_connection_event_in_httpx_0_28_1_trace",
            "workload": {
                "request_count": args.requests,
                "concurrency": args.concurrency,
                "request_spacing_ms": args.request_spacing_ms,
            },
            "cases": cases,
        }
        _write_new_file(args.output, json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
    except (OSError, RuntimeError, ValueError, httpx.HTTPError, TimeoutError):
        raise SystemExit("transport_microprobe_failed") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
