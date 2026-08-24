#!/usr/bin/env python3
# ruff: noqa: S603, S607, S104
"""Run bounded, exact-image operational evidence on dedicated local ports only.

This is qualification evidence, not a public benchmark: it writes one private,
aggregate-only JSON document and never starts, stops, or contacts Ornith.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, NoReturn

import httpx

import shiftedx_harness_proxy.qualification_runtime as qualification_runtime
from shiftedx_harness_proxy.qualification_campaign import (
    _read_regular_file,
    advance_qualification_campaign,
)

_TIMEOUT_SECONDS = 8.0
_READY_TIMEOUT_SECONDS = 30.0
_ROLLBACK_TIMEOUT_SECONDS = 60.0
_LATENCY_SAMPLES = 50
_PASS_THROUGH_SAMPLES = 8
_SECRET = "operational-secret-never-log"  # noqa: S105 - deliberate leak sentinel, never persisted.
_PROXY_KEY = "operational-proxy-key"  # noqa: S105 - ephemeral local smoke credential.
_UPSTREAM_KEY = "operational-upstream-key"  # noqa: S105 - ephemeral local smoke credential.
_ENDPOINT_MARKER = "https://operational.invalid/tenant"  # noqa: S105 - leak sentinel.
_PATH_MARKER = "/private/operational-marker"  # noqa: S105 - leak sentinel.
_MALFORMED_STREAM_BLOCKED_FRAGMENT = b"blocked-fragment-must-not-be-released"
_MAX_BODY_BYTES = 1_000_000
_FAULT_TIMEOUT_MARGIN_SECONDS = 5.0
_SAFE_STAGE_ERRORS = (OSError, RuntimeError, ValueError, subprocess.SubprocessError, json.JSONDecodeError)
_FAULT_EXPECTED_STATUSES = {
    "fault-429": 429,
    "fault-500": 502,
    "fault-malformed": 502,
    "fault-timeout": 504,
    "fault-disconnect": 502,
    "fault-malformed-stream": 502,
}


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise ValueError("operational_matrix_arguments_invalid")


def _stage(name: str, action: Any) -> Any:
    """Attach a content-free phase label without changing a qualification gate."""
    try:
        return action()
    except _SAFE_STAGE_ERRORS as error:
        detail = str(error)
        category = detail if re.fullmatch(r"[a-z0-9_]+", detail) else type(error).__name__.lower()
        raise RuntimeError(f"stage_{name}_{category}") from None


def _digest_image(value: str) -> str:
    if "@sha256:" not in value or len(value.rsplit("@sha256:", 1)[1]) != 64:
        raise ValueError("digest_pinned_image_required")
    digest = value.rsplit("@sha256:", 1)[1]
    if any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("digest_pinned_image_required")
    return value


def _manifest_images(path: Path) -> tuple[str, str, str]:
    """Return the manifest SHA plus exact candidate and approved rollback refs."""
    try:
        raw = path.read_bytes()
        runtime = json.loads(raw)["qualification_runtime"]
        image = runtime["image"]
        rollback = runtime["rollback"]
        if set(image) != {"reference", "digest", "uid", "gid"} or set(rollback) != {
            "reference",
            "digest",
            "source_commit",
            "workflow_url",
            "approval_designation",
            "approval_evidence_url",
        }:
            raise ValueError
        candidate = _digest_image(image["reference"])
        predecessor = _digest_image(rollback["reference"])
        if image["digest"] != candidate.rsplit("@", 1)[1] or rollback["digest"] != predecessor.rsplit("@", 1)[1]:
            raise ValueError
        if candidate == predecessor or rollback["approval_designation"] != "approved-predecessor":
            raise ValueError
    except (KeyError, OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("operational_manifest_invalid") from error
    return hashlib.sha256(raw).hexdigest(), candidate, predecessor


def _manifest_launch(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        proxy = json.loads(path.read_bytes())["qualification_runtime"]["proxy"]
        limits = {name: proxy[name] for name in ("cpus", "memory_bytes", "pids_limit", "stop_timeout_seconds")}
        settings = proxy["settings"]
        required = {
            "admission_limit",
            "principal_concurrency_limit",
            "concurrency_limit",
            "total_request_deadline_seconds",
            "upstream_timeout_seconds",
            "max_upstream_calls",
        }
        if set(limits) != {"cpus", "memory_bytes", "pids_limit", "stop_timeout_seconds"} or not required <= set(
            settings
        ):
            raise ValueError
        if not isinstance(limits["cpus"], int | float) or any(
            not isinstance(limits[name], int) or limits[name] <= 0
            for name in ("memory_bytes", "pids_limit", "stop_timeout_seconds")
        ):
            raise ValueError
        if not isinstance(settings["max_upstream_calls"], int) or not 1 <= settings["max_upstream_calls"] <= 25:
            raise ValueError
        if (
            not isinstance(settings["upstream_timeout_seconds"], int | float)
            or isinstance(settings["upstream_timeout_seconds"], bool)
            or not 0 < settings["upstream_timeout_seconds"] <= 3600
        ):
            raise ValueError
    except (KeyError, OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("operational_manifest_invalid") from error
    return limits, {name: settings[name] for name in required}


def _campaign_action_not_allowed(_request: Any) -> int:
    raise RuntimeError("campaign_action_not_allowed")


def _completed_scored_campaign(manifest: Path, campaign_dir: Path, manifest_sha256: str) -> dict[str, str]:
    """Reuse the campaign's strict verifier; never advance or rerun a completed campaign."""
    advance = advance_qualification_campaign(
        manifest,
        campaign_dir,
        stage_runner=qualification_runtime.QualificationCampaignStageRunner(action=_campaign_action_not_allowed),
        readiness_probe=qualification_runtime.QualificationCampaignReadinessProbe(),
    )
    if (
        advance.kind != "campaign_scored_complete"
        or advance.campaign_outcome_sha256 is None
        or advance.event_sha256 is None
    ):
        raise RuntimeError("scored_campaign_not_complete")
    try:
        outcome = _read_regular_file(campaign_dir / "qualification-campaign-outcome.json", private=True)
        document = json.loads(outcome)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("scored_campaign_invalid") from None
    if (
        not isinstance(document, dict)
        or document.get("status") != "scored_complete"
        or document.get("campaign_manifest_sha256") != manifest_sha256
        or hashlib.sha256(outcome).hexdigest() != advance.campaign_outcome_sha256
        or document.get("head_event_sha256") != advance.event_sha256
    ):
        raise RuntimeError("scored_campaign_invalid")
    return {
        "manifest_sha256": manifest_sha256,
        "outcome_sha256": advance.campaign_outcome_sha256,
        "head_event_sha256": advance.event_sha256,
    }


def _fault_timeout_delay(settings: dict[str, Any]) -> tuple[float, float]:
    timeout = settings["upstream_timeout_seconds"]
    if not isinstance(timeout, int | float) or isinstance(timeout, bool) or not 0 < timeout <= 3600:
        raise ValueError("operational_manifest_invalid")
    return float(timeout) + 1, float(timeout) + _FAULT_TIMEOUT_MARGIN_SECONDS


def _image_identity(image: str) -> dict[str, str]:
    raw = _run(["docker", "image", "inspect", image, "--format", "{{json .}}"])
    document = json.loads(raw)
    repo_digests = document.get("RepoDigests")
    image_id = document.get("Id")
    if not isinstance(repo_digests, list) or image not in repo_digests or not isinstance(image_id, str):
        raise RuntimeError("docker_image_identity_invalid")
    return {
        "reference": image,
        "id": image_id,
        "os": str(document.get("Os", "")),
        "architecture": str(document.get("Architecture", "")),
    }


def _percentile_ms(values: list[float], percentile: float) -> float:
    if not values:
        raise RuntimeError("latency_samples_missing")
    ordered = sorted(values)
    return round(ordered[round((len(ordered) - 1) * percentile)], 3)


def _pass_through_threshold_ms(direct_wall_p95_ms: float) -> float:
    return max(15, round(direct_wall_p95_ms * 0.05, 3))


def _safe_write_new(path: Path, document: dict[str, Any]) -> None:
    if not path.is_absolute() or path.parent.is_symlink():
        raise OSError("unsafe_evidence_path")
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run(command: list[str], *, timeout: float = _TIMEOUT_SECONDS) -> str:
    return subprocess.run(  # noqa: S603 - fixed argv, never a shell.
        command, check=True, capture_output=True, text=True, timeout=timeout
    ).stdout


def _base(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def _http(
    base: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = _TIMEOUT_SECONDS,
) -> tuple[int, bytes, float]:
    started = time.perf_counter()
    try:
        with httpx.Client(base_url=base, timeout=timeout, trust_env=False) as client:
            response = client.request("POST" if payload is not None else "GET", path, json=payload, headers=headers)
        data = response.content
        if len(data) > _MAX_BODY_BYTES:
            raise RuntimeError("response_body_exceeds_bound")
        return response.status_code, data, (time.perf_counter() - started) * 1_000
    except httpx.HTTPError as error:
        raise RuntimeError("local_http_failed") from error


def _client_http(
    client: httpx.Client, path: str, *, payload: dict[str, Any], headers: dict[str, str]
) -> tuple[int, bytes, float]:
    """One warmed-client request; used only for the proxy-local latency lane."""
    started = time.perf_counter()
    try:
        response = client.post(path, json=payload, headers=headers)
    except httpx.HTTPError as error:
        raise RuntimeError("local_http_failed") from error
    data = response.content
    if len(data) > _MAX_BODY_BYTES:
        raise RuntimeError("response_body_exceeds_bound")
    return response.status_code, data, (time.perf_counter() - started) * 1_000


def _await_status(base: str, path: str, expected: int, *, timeout: float) -> float:
    started = time.perf_counter()
    while time.perf_counter() - started < timeout:
        try:
            status, _body, _elapsed = _http(base, path, timeout=1)
            if status == expected:
                return round((time.perf_counter() - started) * 1_000, 3)
        except RuntimeError:
            pass
        time.sleep(0.1)
    raise RuntimeError("readiness_timeout")


def _await_ready(base: str, *, timeout: float) -> float:
    return _await_status(base, "/readyz", 200, timeout=timeout)


def _await_upstream(base: str) -> None:
    _await_status(base, "/v1/models", 200, timeout=_READY_TIMEOUT_SECONDS)


def _start_upstream(port: int) -> subprocess.Popen[str]:
    process = subprocess.Popen(  # noqa: S603, S607, S104 - Docker gateway needs a host bind.
        ["uv", "run", "python", "-m", "uvicorn", "tests.fake_upstream:app", "--host", "0.0.0.0", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    _await_upstream(_base(port))
    return process


def _stop_process(process: subprocess.Popen[str]) -> None:
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()


def _stream_ttft(base: str, *, headers: dict[str, str]) -> tuple[float, int, bool]:
    started = time.perf_counter()
    with httpx.Client(base_url=base, timeout=_TIMEOUT_SECONDS, trust_env=False) as client:
        request_payload = {"model": "fake-model", "messages": [{"role": "user", "content": _SECRET}], "stream": True}
        with client.stream("POST", "/v1/chat/completions", json=request_payload, headers=headers) as response:
            iterator = response.iter_raw()
            first = next(iterator, b"")
            ttft_ms = (time.perf_counter() - started) * 1_000
            stream_payload = first + b"".join(iterator)
    return (
        ttft_ms,
        response.status_code,
        stream_payload.count(b"data: [DONE]") == 1 and b"fake upstream ready" in stream_payload,
    )


def _cancel_stream(base: str, ledger_base: str, *, headers: dict[str, str]) -> str:
    request_id = f"shiftedx-cancel-{secrets.token_hex(8)}"
    body = json.dumps(
        {"model": "fault-timeout", "messages": [{"role": "user", "content": _SECRET}], "stream": True}
    ).encode()
    host, port = base.removeprefix("http://").split(":")
    request = (
        b"POST /v1/chat/completions HTTP/1.1\r\n"
        + (
            f"Host: {host}\r\nAuthorization: {headers['Authorization']}\r\nX-Request-ID: {request_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        + body
    )
    with socket.create_connection((host, int(port)), timeout=_TIMEOUT_SECONDS) as connection:
        connection.sendall(request)
        _await_ledger_attempt(ledger_base, request_id)
    return request_id


def _metric_values(body: bytes) -> dict[str, float]:
    values: dict[str, float] = {}
    for line in body.decode("utf-8", "replace").splitlines():
        pieces = line.split()
        if len(pieces) == 2 and pieces[0].startswith("shiftedx_proxy_"):
            try:
                values[pieces[0]] = float(pieces[1])
            except ValueError:
                continue
    return values


def _metrics(base: str, headers: dict[str, str]) -> dict[str, float]:
    status, body, _elapsed = _http(base, "/metrics", headers=headers)
    if status != 200:
        raise RuntimeError("metrics_unavailable")
    return _metric_values(body)


def _ledger(base: str) -> dict[str, Any]:
    status, body, _elapsed = _http(base, "/v1/qualification/ledger")
    if status != 200:
        raise RuntimeError("upstream_ledger_unavailable")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise RuntimeError("upstream_ledger_invalid")
    return document


def _reset_ledger(base: str) -> None:
    status, _body, _elapsed = _http(base, "/v1/qualification/reset", payload={})
    if status != 200:
        raise RuntimeError("upstream_ledger_reset_failed")


def _await_ledger_attempt(base: str, request_id: str) -> None:
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _ledger(base).get("attempts", {}).get(request_id) == 1:
            return
        time.sleep(0.02)
    raise RuntimeError("upstream_attempt_not_observed")


def _reconciles(
    metrics_before: dict[str, float], metrics_after: dict[str, float], ledger: dict[str, Any], max_upstream_calls: int
) -> dict[str, Any]:
    attempts = ledger.get("attempts")
    upstream_attempts = ledger.get("proxied_attempts")
    downstream = (
        metrics_after["shiftedx_proxy_downstream_requests_total"]
        - metrics_before["shiftedx_proxy_downstream_requests_total"]
    )
    proxy_attempts = (
        metrics_after["shiftedx_proxy_upstream_calls_total"] - metrics_before["shiftedx_proxy_upstream_calls_total"]
    )
    max_per_request = max(attempts.values(), default=0) if isinstance(attempts, dict) else None
    valid = (
        isinstance(attempts, dict)
        and isinstance(upstream_attempts, int)
        and downstream > 0
        and proxy_attempts == upstream_attempts
        and upstream_attempts / downstream <= 2
        and all(isinstance(value, int) and value <= max_upstream_calls for value in attempts.values())
    )
    return {
        "reconciled": valid,
        "downstream_delta": downstream,
        "proxy_upstream_delta": proxy_attempts,
        "authoritative_upstream_attempts": upstream_attempts,
        "mean_upstream_attempts_per_downstream": round(upstream_attempts / downstream, 6)
        if isinstance(upstream_attempts, int) and downstream > 0
        else None,
        "upstream_attempt_ratio_ppm": round(upstream_attempts * 1_000_000 / downstream)
        if isinstance(upstream_attempts, int) and downstream > 0
        else None,
        "max_attempts_per_request": max_per_request,
        "max_active": ledger.get("max_active"),
    }


def _run_reconciled_phase(
    proxy_base: str,
    ledger_base: str,
    headers: dict[str, str],
    action: Any,
    max_upstream_calls: int,
) -> tuple[Any, dict[str, Any]]:
    """Bound one action by a fresh upstream ledger and matching proxy counters."""
    if _ledger(ledger_base).get("active") != 0:
        raise RuntimeError("ledger_reset_while_active")
    _reset_ledger(ledger_base)
    before = _metrics(proxy_base, headers)
    result = action()
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        after = _metrics(proxy_base, headers)
        ledger = _ledger(ledger_base)
        if _phase_idle(after, ledger):
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("phase_not_idle")
    accounting = _reconciles(before, after, ledger, max_upstream_calls)
    return result, {
        **accounting,
        "gauges_clear": True,
        "ledger_active": ledger.get("active"),
    }


def _phase_idle(metrics: dict[str, float], ledger: dict[str, Any]) -> bool:
    return (
        all(
            metrics.get(name, -1) == 0
            for name in (
                "shiftedx_proxy_downstream_active",
                "shiftedx_proxy_downstream_queued",
                "shiftedx_proxy_upstream_active",
            )
        )
        and ledger.get("active") == 0
    )


def _start_proxy(
    *,
    image: str,
    proxy_port: int,
    upstream_port: int,
    container: str,
    label: str,
    secret_dir: Path,
    limits: dict[str, Any],
    settings: dict[str, Any],
) -> None:
    _run(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            container,
            "--label",
            f"shiftedx.qualification.run={label}",
            "--label",
            "shiftedx.qualification.component=operational-matrix",
            "--user",
            "10001:10001",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(limits["pids_limit"]),
            "--cpus",
            str(limits["cpus"]),
            "--memory",
            str(limits["memory_bytes"]),
            "--stop-timeout",
            str(limits["stop_timeout_seconds"]),
            "--add-host",
            "host.docker.internal:host-gateway",
            "--mount",
            f"type=bind,src={secret_dir},dst=/run/secrets,readonly",
            "--publish",
            f"127.0.0.1:{proxy_port}:8090",
            "--env",
            "DEPLOYMENT_PROFILE=production",
            "--env",
            f"UPSTREAM_BASE_URL=http://host.docker.internal:{upstream_port}/v1",
            "--env",
            "UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE=phase_split",
            "--env",
            f"ADMISSION_LIMIT={settings['admission_limit']}",
            "--env",
            f"PRINCIPAL_CONCURRENCY_LIMIT={settings['principal_concurrency_limit']}",
            "--env",
            f"CONCURRENCY_LIMIT={settings['concurrency_limit']}",
            "--env",
            "ADMISSION_WAIT_SECONDS=0.05",
            "--env",
            f"TOTAL_REQUEST_DEADLINE_SECONDS={settings['total_request_deadline_seconds']}",
            "--env",
            f"UPSTREAM_TIMEOUT_SECONDS={settings['upstream_timeout_seconds']}",
            "--env",
            f"MAX_UPSTREAM_CALLS={settings['max_upstream_calls']}",
            image,
        ]
    )


def _remove_container(container: str) -> None:
    subprocess.run(  # noqa: S603, S607 - fixed Docker CLI and label-scoped generated name.
        ["docker", "rm", "--force", container], capture_output=True, text=True, check=False, timeout=_TIMEOUT_SECONDS
    )


def _parse_docker_memory_bytes(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGT]?i?B)?", value.strip())
    if match is None:
        raise RuntimeError("docker_stat_invalid")
    multiplier = {None: 1, "B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}[match.group(2)]
    return float(match.group(1)) * multiplier


def _snapshot(container: str) -> dict[str, Any]:
    stats = json.loads(_run(["docker", "stats", "--no-stream", "--format", "{{json .}}", container]))
    inspect = json.loads(_run(["docker", "inspect", container]))[0]
    return {
        "stats": {
            "cpu_percent": float(str(stats.get("CPUPerc", "")).removesuffix("%")),
            "memory_bytes": _parse_docker_memory_bytes(str(stats.get("MemUsage", "")).split(" / ", 1)[0]),
            "pids": int(str(stats.get("PIDs", ""))),
        },
        "restart_count": inspect["RestartCount"],
        "oom_killed": inspect["State"]["OOMKilled"],
        "limits": {
            "memory_bytes": inspect["HostConfig"]["Memory"],
            "pids_limit": inspect["HostConfig"]["PidsLimit"],
            "nano_cpus": inspect["HostConfig"]["NanoCpus"],
        },
    }


def _resource_ok(samples: list[dict[str, Any]], limits: dict[str, Any]) -> bool:
    first_memory = samples[0]["stats"]["memory_bytes"]
    for sample in samples:
        stats = sample["stats"]
        if (
            sample["oom_killed"] is not False
            or sample["limits"]
            != {
                "memory_bytes": limits["memory_bytes"],
                "pids_limit": limits["pids_limit"],
                "nano_cpus": int(float(limits["cpus"]) * 1_000_000_000),
            }
            or stats["memory_bytes"] > limits["memory_bytes"]
            or stats["pids"] > limits["pids_limit"]
            or stats["cpu_percent"] > float(limits["cpus"]) * 110
            or stats["memory_bytes"] > first_memory * 2
            or sample["restart_count"] != 0
        ):
            return False
    return True


def _faults(base: str, headers: dict[str, str], settings: dict[str, Any]) -> dict[str, Any]:
    observed: dict[str, int] = {}
    for model in _FAULT_EXPECTED_STATUSES:
        if model == "fault-malformed-stream":
            continue
        payload: dict[str, Any] = {"model": model, "messages": [{"role": "user", "content": _SECRET}]}
        timeout = 4.0
        if model == "fault-timeout":
            delay, timeout = _fault_timeout_delay(settings)
            payload["qualification_delay_seconds"] = delay
        status, _body, _elapsed = _http(
            base,
            "/v1/chat/completions",
            payload=payload,
            headers=headers,
            timeout=timeout,
        )
        observed[model] = status
    malformed_status, malformed_body, _elapsed = _http(
        base,
        "/v1/chat/completions",
        payload={"model": "fault-malformed-stream", "messages": [{"role": "user", "content": _SECRET}], "stream": True},
        headers=headers,
    )
    malformed = {
        "status": malformed_status,
        "done_count": malformed_body.count(b"data: [DONE]"),
        "released_blocked_fragment": _MALFORMED_STREAM_BLOCKED_FRAGMENT in malformed_body,
    }
    observed["fault-malformed-stream"] = malformed_status
    return {"statuses": observed, "malformed_stream": malformed}


def _overload(base: str, headers: dict[str, str], workers: int) -> dict[str, int]:
    def one() -> int:
        return _http(
            base,
            "/v1/chat/completions",
            payload={"model": "slow-response", "messages": [{"role": "user", "content": _SECRET}]},
            headers=headers,
        )[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        statuses = list(executor.map(lambda _unused: one(), range(workers)))
    return {
        "accepted": statuses.count(200),
        "overload_429": statuses.count(429),
        "other": len(statuses) - statuses.count(200) - statuses.count(429),
    }


def _sustained_load(base: str, headers: dict[str, str]) -> dict[str, int]:
    statuses = [
        _http(
            base,
            "/v1/chat/completions",
            payload={"model": "fake-model", "messages": [{"role": "user", "content": _SECRET}]},
            headers=headers,
        )[0]
        for _ in range(20)
    ]
    return {"denominator": len(statuses), "successful": statuses.count(200)}


def _latency(proxy_base: str, direct_base: str, headers: dict[str, str]) -> dict[str, float]:
    direct_ttft: list[float] = []
    proxy_ttft: list[float] = []
    direct_wall: list[float] = []
    pass_through_wall: list[float] = []
    proxy_total: list[float] = []
    with httpx.Client(base_url=proxy_base, timeout=_TIMEOUT_SECONDS, trust_env=False) as client:
        warm_status, _warm_body, _warm_elapsed = _client_http(
            client,
            "/v1/chat/completions",
            payload={"model": "fake-model", "messages": [{"role": "user", "content": "warm"}]},
            headers=headers,
        )
        if warm_status != 200:
            raise RuntimeError("latency_warmup_failed")
        for _ in range(_LATENCY_SAMPLES):
            proxy_status, _body, proxy_ms = _client_http(
                client,
                "/v1/chat/completions",
                payload={"model": "fake-model", "messages": [{"role": "user", "content": "immediate"}]},
                headers=headers,
            )
            if proxy_status != 200:
                raise RuntimeError("latency_request_failed")
            proxy_total.append(proxy_ms)
    rate_window_started = time.perf_counter()
    time.sleep(60.5)
    rate_window_wait_ms = round((time.perf_counter() - rate_window_started) * 1_000, 3)
    for _ in range(_PASS_THROUGH_SAMPLES):
        direct_status, _body, direct_ms = _http(
            direct_base,
            "/v1/chat/completions",
            payload={"model": "fake-model", "messages": [{"role": "user", "content": _SECRET}]},
        )
        proxy_status, _body, proxy_ms = _http(
            proxy_base,
            "/v1/chat/completions",
            payload={"model": "fake-model", "messages": [{"role": "user", "content": _SECRET}]},
            headers=headers,
        )
        if direct_status != 200 or proxy_status != 200:
            raise RuntimeError(f"latency_request_failed_{direct_status}_{proxy_status}")
        direct_wall.append(direct_ms)
        pass_through_wall.append(proxy_ms - direct_ms)
        direct_value, direct_stream_status, direct_ok = _stream_ttft(direct_base, headers={})
        proxy_value, proxy_stream_status, proxy_ok = _stream_ttft(proxy_base, headers=headers)
        if direct_stream_status != 200 or proxy_stream_status != 200 or not (direct_ok and proxy_ok):
            raise RuntimeError("sse_contract_failed")
        direct_ttft.append(direct_value)
        proxy_ttft.append(proxy_value)
    direct_wall_p95 = _percentile_ms(direct_wall, 0.95)
    result = {
        "proxy_total_p50_ms": _percentile_ms(proxy_total, 0.50),
        "proxy_total_p95_ms": _percentile_ms(proxy_total, 0.95),
        "proxy_total_p99_ms": _percentile_ms(proxy_total, 0.99),
        "proxy_total_max_ms": round(max(proxy_total), 3),
        "proxy_total_samples": len(proxy_total),
        "rate_window_wait_ms": rate_window_wait_ms,
        "direct_to_proxy_added_wall_p95_ms": _percentile_ms(pass_through_wall, 0.95),
        "direct_wall_p95_ms": direct_wall_p95,
        "pass_through_wall_threshold_ms": _pass_through_threshold_ms(direct_wall_p95),
        "direct_sse_ttft_p95_ms": _percentile_ms(direct_ttft, 0.95),
        "proxy_sse_ttft_p95_ms": _percentile_ms(proxy_ttft, 0.95),
    }
    result["sse_ttft_added_p95_ms"] = round(result["proxy_sse_ttft_p95_ms"] - result["direct_sse_ttft_p95_ms"], 3)
    return result


def _slow_reader(base: str, headers: dict[str, str]) -> dict[str, Any]:
    started = time.perf_counter()
    payload = {"model": "slow-stream", "messages": [{"role": "user", "content": "slow reader"}], "stream": True}
    with httpx.Client(base_url=base, timeout=_TIMEOUT_SECONDS, trust_env=False) as client:
        with client.stream("POST", "/v1/chat/completions", json=payload, headers=headers) as response:
            chunks: list[bytes] = []
            for chunk in response.iter_raw():
                chunks.append(chunk)
                time.sleep(0.04)
    body = b"".join(chunks)
    return {
        "status": response.status_code,
        "elapsed_ms": round((time.perf_counter() - started) * 1_000, 3),
        "semantic_valid": b"fake upstream ready" in body and body.count(b"data: [DONE]") == 1,
        "done_count": body.count(b"data: [DONE]"),
    }


def _graceful_restart(candidate_base: str, ledger_base: str, headers: dict[str, str], container: str) -> dict[str, Any]:
    request_id = f"shiftedx-graceful-{secrets.token_hex(8)}"

    def slow() -> tuple[int, bytes, float]:
        return _http(
            candidate_base,
            "/v1/chat/completions",
            payload={"model": "slow-success", "messages": [{"role": "user", "content": "graceful"}]},
            headers={**headers, "X-Request-ID": request_id},
            timeout=_READY_TIMEOUT_SECONDS,
        )

    if _ledger(ledger_base).get("active") != 0:
        raise RuntimeError("restart_with_active_ledger")
    _reset_ledger(ledger_base)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(slow)
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            state = _ledger(ledger_base)
            if state.get("attempts", {}).get(request_id) == 1 and state.get("active") == 1:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("graceful_request_not_active")
        started = time.perf_counter()
        _run(["docker", "stop", "--time", "20", container], timeout=_READY_TIMEOUT_SECONDS)
        status, body, _elapsed = future.result(timeout=_READY_TIMEOUT_SECONDS)
    _run(["docker", "start", container], timeout=_READY_TIMEOUT_SECONDS)
    ready_ms = _await_ready(candidate_base, timeout=_READY_TIMEOUT_SECONDS)
    smoke_status, _smoke_body, _smoke_elapsed = _http(
        candidate_base,
        "/v1/chat/completions",
        payload={"model": "fake-model", "messages": [{"role": "user", "content": "smoke"}]},
        headers=headers,
    )
    finished = _ledger(ledger_base)
    return {
        "elapsed_ms": round((time.perf_counter() - started) * 1_000, 3),
        "ready_ms": ready_ms,
        "slow_status": status,
        "slow_valid": b"fake upstream ready" in body,
        "slow_attempts": finished.get("attempts", {}).get(request_id),
        "smoke_status": smoke_status,
        "ledger_active": finished.get("active"),
    }


def _privacy_ok(
    container: str, evidence: dict[str, Any], public_samples: list[bytes], private_values: tuple[str, ...]
) -> bool:
    logs = _run(["docker", "logs", container])
    inspect = _run(["docker", "inspect", container])
    serialized = json.dumps(evidence, sort_keys=True)
    public = b"\n".join(public_samples).decode("utf-8", "replace")
    return all(
        value not in logs and value not in inspect and value not in serialized and value not in public
        for value in private_values
    )


def _run_matrix(
    candidate: str,
    rollback: str,
    manifest_sha256: str,
    output: Path,
    ports: tuple[int, int, int],
    limits: dict[str, Any],
    settings: dict[str, Any],
    campaign: dict[str, str],
) -> dict[str, Any]:
    upstream_port, candidate_port, rollback_port = ports
    run_id = secrets.token_hex(12)
    candidate_name = f"shiftedx-operational-candidate-{run_id}"
    rollback_name = f"shiftedx-operational-rollback-{run_id}"
    temporary = Path(tempfile.mkdtemp(prefix="shiftedx-operational-"))
    upstream: subprocess.Popen[str] | None = None
    candidate_base = _base(candidate_port)
    rollback_base = _base(rollback_port)
    direct_base = _base(upstream_port)
    headers = {"Authorization": f"Bearer {_PROXY_KEY}"}
    try:
        secrets_dir = temporary / "secrets"
        secrets_dir.mkdir(mode=0o755)
        (secrets_dir / "proxy_api_key").write_text(_PROXY_KEY, encoding="ascii")
        (secrets_dir / "upstream_api_key").write_text(_UPSTREAM_KEY, encoding="ascii")
        os.chmod(secrets_dir / "proxy_api_key", 0o444)
        os.chmod(secrets_dir / "upstream_api_key", 0o444)
        upstream = _stage("startup_recovery", lambda: _start_upstream(upstream_port))
        _stage(
            "startup_recovery",
            lambda: _start_proxy(
                image=candidate,
                proxy_port=candidate_port,
                upstream_port=upstream_port,
                container=candidate_name,
                label=run_id,
                secret_dir=secrets_dir,
                limits=limits,
                settings=settings,
            ),
        )
        initial_ready_ms = _stage(
            "startup_recovery", lambda: _await_ready(candidate_base, timeout=_READY_TIMEOUT_SECONDS)
        )
        _stop_process(upstream)
        upstream = None
        lost_status, _body, _elapsed = _stage("startup_recovery", lambda: _http(candidate_base, "/readyz"))
        recovery_started = time.perf_counter()
        upstream = _stage("startup_recovery", lambda: _start_upstream(upstream_port))
        recovery_ready_ms = _stage(
            "startup_recovery", lambda: _await_ready(candidate_base, timeout=_READY_TIMEOUT_SECONDS)
        )
        recovery_status, _body, _elapsed = _stage(
            "startup_recovery",
            lambda: _http(
                candidate_base,
                "/v1/chat/completions",
                payload={"model": "fake-model", "messages": [{"role": "user", "content": _SECRET}]},
                headers=headers,
            ),
        )
        recovery_elapsed_ms = round((time.perf_counter() - recovery_started) * 1_000, 3)
        resources_before = _stage("resources", lambda: _snapshot(candidate_name))
        latency, latency_phase = _stage(
            "latency",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _latency(candidate_base, direct_base, headers),
                settings["max_upstream_calls"],
            ),
        )
        sustained, sustained_phase = _stage(
            "sustained",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _sustained_load(candidate_base, headers),
                settings["max_upstream_calls"],
            ),
        )
        resources_during = _stage("resources", lambda: _snapshot(candidate_name))
        overload, overload_phase = _stage(
            "overload",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _overload(candidate_base, headers, int(settings["principal_concurrency_limit"]) + 1),
                settings["max_upstream_calls"],
            ),
        )
        faults, faults_phase = _stage(
            "faults",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _faults(candidate_base, headers, settings),
                settings["max_upstream_calls"],
            ),
        )
        slow_reader, slow_reader_phase = _stage(
            "slow_reader",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _slow_reader(candidate_base, headers),
                settings["max_upstream_calls"],
            ),
        )
        if _stage("cancellation", lambda: _ledger(direct_base)).get("active") != 0:
            raise RuntimeError("ledger_reset_while_active")
        _stage("cancellation", lambda: _reset_ledger(direct_base))
        cancellation_before = _stage("cancellation", lambda: _metrics(candidate_base, headers))
        cancellation_request_id = _stage(
            "cancellation", lambda: _cancel_stream(candidate_base, direct_base, headers=headers)
        )
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            cancellation_after = _stage("cancellation", lambda: _metrics(candidate_base, headers))
            cancellation_ledger = _stage("cancellation", lambda: _ledger(direct_base))
            if cancellation_after["shiftedx_proxy_downstream_cancellations_total"] - cancellation_before[
                "shiftedx_proxy_downstream_cancellations_total"
            ] == 1 and _phase_idle(cancellation_after, cancellation_ledger):
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("cancellation_not_reconciled")
        cancellation_accounting = {
            "downstream_delta": (
                cancellation_after["shiftedx_proxy_downstream_requests_total"]
                - cancellation_before["shiftedx_proxy_downstream_requests_total"]
            ),
            "proxy_upstream_delta": (
                cancellation_after["shiftedx_proxy_upstream_calls_total"]
                - cancellation_before["shiftedx_proxy_upstream_calls_total"]
            ),
            "cancellation_delta": (
                cancellation_after["shiftedx_proxy_downstream_cancellations_total"]
                - cancellation_before["shiftedx_proxy_downstream_cancellations_total"]
            ),
            "authoritative_upstream_attempts": cancellation_ledger.get("proxied_attempts"),
            "ledger_request_attempts": cancellation_ledger.get("attempts", {}).get(cancellation_request_id),
            "ledger_active": cancellation_ledger.get("active"),
            "gauges_clear": _phase_idle(cancellation_after, cancellation_ledger),
        }
        privacy_payload = {
            "model": "fake-model",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"{_SECRET}|{_ENDPOINT_MARKER}|{_PATH_MARKER}|tenant=operational|"
                        "tool_arg=marker|tool_result=marker"
                    ),
                }
            ],
        }
        privacy_result, privacy_phase = _stage(
            "privacy",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _http(candidate_base, "/v1/chat/completions", payload=privacy_payload, headers=headers),
                settings["max_upstream_calls"],
            ),
        )
        privacy_status, privacy_body, _privacy_elapsed = privacy_result
        privacy_sentinels = tuple(f"operational-privacy-{secrets.token_hex(16)}" for _ in range(2))
        privacy_error_result, privacy_error_phase = _stage(
            "privacy",
            lambda: _run_reconciled_phase(
                candidate_base,
                direct_base,
                headers,
                lambda: _http(
                    candidate_base,
                    "/v1/chat/completions",
                    payload={
                        "model": "fault-500",
                        "messages": [{"role": "user", "content": "|".join(privacy_sentinels)}],
                    },
                    headers=headers,
                ),
                settings["max_upstream_calls"],
            ),
        )
        privacy_error_status, privacy_error_body, _privacy_error_elapsed = privacy_error_result
        _metrics_status, metrics_body, _metrics_elapsed = _stage(
            "privacy", lambda: _http(candidate_base, "/metrics", headers=headers)
        )
        graceful = _stage(
            "graceful_restart", lambda: _graceful_restart(candidate_base, direct_base, headers, candidate_name)
        )
        resources = _stage("resources", lambda: _snapshot(candidate_name))
        resource_samples = [resources_before, resources_during, resources]
        evidence: dict[str, Any] = {
            "schema_version": "operational_matrix_v1",
            "scope": "private_exact_image_dedicated_ports",
            "manifest_sha256": manifest_sha256,
            "candidate_image": candidate,
            "rollback_image": rollback,
            "qualification_campaign": campaign,
            "image_identity": {"candidate": _image_identity(candidate), "rollback": _image_identity(rollback)},
            "gates": {
                "candidate_ready": initial_ready_ms <= _READY_TIMEOUT_SECONDS * 1_000,
                "transient_upstream_recovery": (
                    lost_status != 200
                    and recovery_status == 200
                    and recovery_elapsed_ms <= _READY_TIMEOUT_SECONDS * 1_000
                ),
                "restart_ready": graceful["elapsed_ms"] <= _READY_TIMEOUT_SECONDS * 1_000,
                "graceful_inflight_restart": (
                    graceful["slow_status"] == 200
                    and graceful["slow_valid"]
                    and graceful["slow_attempts"] == 1
                    and graceful["smoke_status"] == 200
                    and graceful["ledger_active"] == 0
                    and graceful["elapsed_ms"] <= _READY_TIMEOUT_SECONDS * 1_000
                ),
                "load_overload": overload["accepted"] >= 1 and overload["overload_429"] >= 1 and overload["other"] == 0,
                "sustained_load": sustained["successful"] / sustained["denominator"] >= 0.99,
                "upstream_concurrency": overload_phase["max_active"] <= settings["concurrency_limit"],
                "faults": faults["statuses"] == _FAULT_EXPECTED_STATUSES,
                "metrics_accounting": all(
                    phase["reconciled"] and phase["gauges_clear"]
                    for phase in (
                        latency_phase,
                        sustained_phase,
                        overload_phase,
                        faults_phase,
                        slow_reader_phase,
                        privacy_phase,
                        privacy_error_phase,
                    )
                ),
                "cancellation": (
                    cancellation_accounting["cancellation_delta"] == 1
                    and cancellation_accounting["downstream_delta"] == 1
                    and cancellation_accounting["proxy_upstream_delta"] == 1
                    and cancellation_accounting["authoritative_upstream_attempts"] == 1
                    and cancellation_accounting["ledger_request_attempts"] == 1
                    and cancellation_accounting["ledger_active"] == 0
                    and cancellation_accounting["gauges_clear"]
                ),
                "privacy_probe": privacy_status == 200 and privacy_error_status == 502,
                "proxy_only_processing": latency["proxy_total_p95_ms"] < 15 and latency["proxy_total_p99_ms"] < 30,
                "pass_through_wall": (
                    latency["direct_to_proxy_added_wall_p95_ms"] <= latency["pass_through_wall_threshold_ms"]
                ),
                "sse_ttft": latency["sse_ttft_added_p95_ms"] <= max(15, latency["direct_sse_ttft_p95_ms"] * 0.05),
                "sse_valid": (
                    slow_reader["status"] == 200 and slow_reader["semantic_valid"] and slow_reader["done_count"] == 1
                ),
                "sse_malformed_rejected": (
                    faults["malformed_stream"]["status"] == 502
                    and faults["malformed_stream"]["done_count"] == 0
                    and faults["malformed_stream"]["released_blocked_fragment"] is False
                ),
                "resources": _resource_ok(resource_samples, limits),
            },
            "latency_ms": latency,
            "readiness_ms": {
                "initial": initial_ready_ms,
                "transient_recovery": recovery_ready_ms,
                "transient_recovery_elapsed": recovery_elapsed_ms,
                "restart": graceful["ready_ms"],
                "restart_elapsed": graceful["elapsed_ms"],
            },
            "overload": overload,
            "sustained_load": sustained,
            "fault_statuses": faults["statuses"],
            "malformed_stream_evidence": faults["malformed_stream"],
            "privacy_error_status": privacy_error_status,
            "metrics_delta": {
                key: cancellation_after.get(key, 0) - cancellation_before.get(key, 0)
                for key in (
                    "shiftedx_proxy_downstream_requests_total",
                    "shiftedx_proxy_upstream_calls_total",
                    "shiftedx_proxy_errors_total",
                    "shiftedx_proxy_downstream_cancellations_total",
                )
            },
            "cancellation_accounting": cancellation_accounting,
            "upstream_ledger": {
                "phases": {
                    "latency": latency_phase,
                    "sustained": sustained_phase,
                    "overload": overload_phase,
                    "faults": faults_phase,
                    "slow_reader": slow_reader_phase,
                    "privacy": privacy_phase,
                    "privacy_error": privacy_error_phase,
                    "cancellation": cancellation_accounting,
                },
            },
            "cancellation_request_id_sha256": hashlib.sha256(cancellation_request_id.encode()).hexdigest(),
            "graceful_restart": graceful,
            "slow_reader": slow_reader,
            "resource_samples": {"before": resources_before, "during": resources_during, "after": resources},
            "cancellation_exercised": True,
        }
        evidence["gates"]["privacy"] = _stage(
            "privacy",
            lambda: _privacy_ok(
                candidate_name,
                evidence,
                [privacy_body, privacy_error_body, metrics_body],
                (_SECRET, _PROXY_KEY, _UPSTREAM_KEY, _ENDPOINT_MARKER, _PATH_MARKER, *privacy_sentinels),
            ),
        )
        _remove_container(candidate_name)
        rollback_started = time.perf_counter()
        _stage(
            "rollback",
            lambda: _start_proxy(
                image=rollback,
                proxy_port=rollback_port,
                upstream_port=upstream_port,
                container=rollback_name,
                label=run_id,
                secret_dir=secrets_dir,
                limits=limits,
                settings=settings,
            ),
        )
        rollback_ready_ms = _stage("rollback", lambda: _await_ready(rollback_base, timeout=_ROLLBACK_TIMEOUT_SECONDS))
        rollback_status, _body, _elapsed = _stage(
            "rollback",
            lambda: _http(
                rollback_base,
                "/v1/chat/completions",
                payload={"model": "fake-model", "messages": [{"role": "user", "content": _SECRET}]},
                headers=headers,
            ),
        )
        rollback_elapsed_ms = round((time.perf_counter() - rollback_started) * 1_000, 3)
        evidence["gates"]["privacy"] = bool(evidence["gates"]["privacy"]) and _stage(
            "privacy",
            lambda: _privacy_ok(
                rollback_name,
                evidence,
                [privacy_body, privacy_error_body, metrics_body],
                (_SECRET, _PROXY_KEY, _UPSTREAM_KEY, _ENDPOINT_MARKER, _PATH_MARKER, *privacy_sentinels),
            ),
        )
        evidence["rollback"] = {
            "ready_ms": rollback_ready_ms,
            "elapsed_ms": rollback_elapsed_ms,
            "smoke_status": rollback_status,
        }
        evidence["gates"]["rollback"] = (
            rollback_status == 200 and rollback_elapsed_ms <= _ROLLBACK_TIMEOUT_SECONDS * 1_000
        )
        evidence["passed"] = all(bool(value) for value in evidence["gates"].values())
        _safe_write_new(output, evidence)
        return evidence
    finally:
        _remove_container(candidate_name)
        _remove_container(rollback_name)
        if upstream is not None:
            _stop_process(upstream)
        shutil.rmtree(temporary, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--candidate-image", required=True, type=_digest_image)
    parser.add_argument("--rollback-image", required=True, type=_digest_image)
    parser.add_argument("--campaign-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upstream-port", default=18100, type=int)
    parser.add_argument("--candidate-port", default=18190, type=int)
    parser.add_argument("--rollback-port", default=18191, type=int)
    try:
        args = parser.parse_args(argv)
        if len({args.upstream_port, args.candidate_port, args.rollback_port}) != 3 or 8000 in {
            args.upstream_port,
            args.candidate_port,
            args.rollback_port,
        }:
            raise ValueError("dedicated_non_ornith_ports_required")
        manifest_sha256, candidate, rollback = _manifest_images(args.manifest)
        limits, settings = _manifest_launch(args.manifest)
        if candidate != args.candidate_image or rollback != args.rollback_image:
            raise ValueError("manifest_image_binding_mismatch")
        campaign = _completed_scored_campaign(args.manifest, args.campaign_dir, manifest_sha256)
        result = _run_matrix(
            candidate,
            rollback,
            manifest_sha256,
            args.output,
            (args.upstream_port, args.candidate_port, args.rollback_port),
            limits,
            settings,
            campaign,
        )
        return 0 if result["passed"] else 3
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        if "args" in locals() and isinstance(args.output, Path) and not args.output.exists():
            _safe_write_new(
                args.output.with_suffix(".failure.json"),
                {"schema_version": "operational_matrix_failure_v1", "category": f"{type(error).__name__}:{error}"},
            )
        print(f"operational_matrix_failed:{type(error).__name__}:{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
