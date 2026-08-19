from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

import httpx


def _production_environment(port: int, secret: str | None) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("PROXY_API_KEY", "UPSTREAM_API_KEY"):
        environment.pop(name, None)
    environment.update(
        {
            "DEPLOYMENT_PROFILE": "production",
            "UPSTREAM_BASE_URL": "http://127.0.0.1:1/v1",
            "LISTEN_HOST": "127.0.0.1",
            "LISTEN_PORT": str(port),
            "LOG_LEVEL": "WARNING",
        }
    )
    if secret is not None:
        environment["PROXY_API_KEY"] = secret
    return environment


def _unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@contextmanager
def _production_server(secret: str) -> Iterator[tuple[str, subprocess.Popen[str]]]:
    port = _unused_port()
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", "shiftedx_harness_proxy.main"],
        env=_production_environment(port, secret),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"production server exited early: {stdout}\n{stderr}")
        try:
            if httpx.get(f"{base_url}/healthz", timeout=0.2).status_code == 200:
                break
        except httpx.TransportError:
            time.sleep(0.05)
    else:
        raise AssertionError("production server did not become live")
    try:
        yield base_url, process
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_production_startup_fails_before_listening_without_credentials() -> None:
    port = _unused_port()
    result = subprocess.run(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", "shiftedx_harness_proxy.main"],
        env=_production_environment(port, None),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode != 0
    assert "requires PROXY_API_KEY" in result.stderr


def test_production_startup_does_not_print_malformed_credentials() -> None:
    port = _unused_port()
    malformed_secret = "do not print this credential"  # noqa: S105 - isolated invalid test value
    result = subprocess.run(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", "shiftedx_harness_proxy.main"],
        env=_production_environment(port, malformed_secret),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode != 0
    assert malformed_secret not in result.stdout
    assert malformed_secret not in result.stderr


def test_production_network_rejects_unauthenticated_models_and_completions() -> None:
    secret = "network-smoke-secret"  # noqa: S105 - isolated test credential
    with _production_server(secret) as (base_url, process):
        models = httpx.get(f"{base_url}/v1/models")
        completion = httpx.post(
            f"{base_url}/v1/chat/completions",
            json={"model": "model", "messages": []},
        )
        assert models.status_code == 401
        assert completion.status_code == 401
        assert secret not in models.text
        assert secret not in completion.text
        assert process.poll() is None
