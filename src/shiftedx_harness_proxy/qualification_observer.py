"""Private, hash-only observer for qualification proxy-to-model traffic.

The observer is deliberately outside the proxy's public API.  Its only durable
output is a new private JSONL ledger of allowlisted model-boundary hashes; it
does not retain request bodies, credentials, model output, or endpoint data.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from .qualification_contract import model_boundary_record

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class QualificationObserverConfigurationError(RuntimeError):
    """Raised without echoing a private URL or ledger path."""


@dataclass(frozen=True)
class QualificationObserverConfig:
    """Validated private observer wiring supplied only by the runtime supervisor."""

    upstream_url: str
    ledger: Path
    host: str
    port: int
    instance_sha256: str


@dataclass
class _ObserverState:
    config: QualificationObserverConfig
    next_sequence: int = 1


def load_observer_config(env: Mapping[str, str] | None = None) -> QualificationObserverConfig:
    """Read strictly validated observer-only environment without printing sensitive inputs."""

    source = os.environ if env is None else env
    upstream_url = _safe_http_url(source.get("QUALIFICATION_OBSERVER_UPSTREAM", ""))
    ledger_value = source.get("QUALIFICATION_OBSERVER_LEDGER", "")
    host = source.get("QUALIFICATION_OBSERVER_HOST", "")
    port = _port(source.get("QUALIFICATION_OBSERVER_PORT", ""))
    instance_sha256 = source.get("QUALIFICATION_OBSERVER_INSTANCE_SHA256", "")
    if not ledger_value:
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid")
    ledger = Path(ledger_value)
    config = QualificationObserverConfig(upstream_url, ledger, host, port, instance_sha256)
    _validate_observer_config(config)
    return config


def create_observer_app(config: QualificationObserverConfig) -> FastAPI:
    """Create an observer app and atomically reserve its fresh private ledger."""

    _validate_observer_config(config)
    _create_fresh_ledger(config.ledger)
    state = _ObserverState(config=config)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.client = httpx.AsyncClient(timeout=httpx.Timeout(600.0), trust_env=False)
        try:
            yield
        finally:
            await app.state.client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.qualification_observer = state

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "live", "instance_sha256": state.config.instance_sha256}

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> Response:
        try:
            payload = await request.json()
        except Exception:
            return Response(status_code=400)
        if not isinstance(payload, dict):
            return Response(status_code=400)
        try:
            response = await request.app.state.client.post(
                f"{state.config.upstream_url}/chat/completions",
                json=payload,
                headers=_forwarded_headers(request),
            )
        except Exception:
            _append_observation(state, payload, status_code=None, response_payload=None)
            raise
        try:
            response_payload: Any = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            response_payload = None
        _append_observation(
            state,
            payload,
            status_code=response.status_code,
            response_payload=response_payload,
        )
        return Response(
            response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
        )

    @app.get("/v1/models")
    async def models(request: Request) -> Response:
        response = await request.app.state.client.get(
            f"{state.config.upstream_url}/models", headers=_forwarded_headers(request)
        )
        return Response(
            response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
        )

    return app


def run_observer(config: QualificationObserverConfig) -> None:
    """Run the private observer with its manifest-derived loopback bind."""

    uvicorn.run(create_observer_app(config), host=config.host, port=config.port, access_log=False, log_level="warning")


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point intentionally limited to supervisor-supplied environment."""

    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        config = load_observer_config()
        run_observer(config)
    except QualificationObserverConfigurationError as error:
        raise SystemExit(error.args[0]) from error
    return 0


def _append_observation(
    state: _ObserverState,
    payload: dict[str, Any],
    *,
    status_code: int | None,
    response_payload: Any,
) -> None:
    record = model_boundary_record(
        payload,
        sequence=state.next_sequence,
        status_code=status_code,
        response=response_payload,
    ).to_dict()
    serialized = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor: int | None = None
    try:
        file_status = state.config.ledger.lstat()
        if (
            state.config.ledger.is_symlink()
            or not stat.S_ISREG(file_status.st_mode)
            or stat.S_IMODE(file_status.st_mode) != 0o600
        ):
            raise QualificationObserverConfigurationError("qualification_observer_ledger_invalid")
        descriptor = os.open(
            state.config.ledger,
            os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        )
        _write_all(descriptor, serialized)
        os.fsync(descriptor)
    except OSError as error:
        raise QualificationObserverConfigurationError("qualification_observer_ledger_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    state.next_sequence += 1


def _create_fresh_ledger(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except FileExistsError as error:
        raise QualificationObserverConfigurationError("qualification_observer_ledger_exists") from error
    except OSError as error:
        raise QualificationObserverConfigurationError("qualification_observer_ledger_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        written += os.write(descriptor, data[written:])


def _safe_http_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid")
    try:
        _ = parsed.port
    except ValueError as error:
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid") from error
    return value.rstrip("/")


def _validate_observer_config(config: QualificationObserverConfig) -> None:
    _safe_http_url(config.upstream_url)
    if (
        config.host not in {"127.0.0.1", "::1"}
        or not isinstance(config.port, int)
        or isinstance(config.port, bool)
        or not 1 <= config.port <= 65535
        or _SHA256.fullmatch(config.instance_sha256) is None
    ):
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid")
    try:
        parent_status = config.ledger.parent.lstat()
        if (
            config.ledger.exists()
            or config.ledger.is_symlink()
            or not stat.S_ISDIR(parent_status.st_mode)
            or config.ledger.parent.is_symlink()
        ):
            raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid")
    except OSError as error:
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid") from error


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid") from error
    if not 1 <= port <= 65535:
        raise QualificationObserverConfigurationError("qualification_observer_configuration_invalid")
    return port


def _forwarded_headers(request: Request) -> dict[str, str]:
    authorization = request.headers.get("authorization")
    return {"authorization": authorization} if authorization is not None else {}


if __name__ == "__main__":
    raise SystemExit(main())
