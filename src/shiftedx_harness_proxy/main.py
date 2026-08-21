"""Console entry point."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import uvicorn

from .api import create_app
from .config import Settings
from .qualification_timing import PrivateTimingSink, TimingFailure

_QUALIFICATION_TIMING_CAPTURE_PATH = "/run/qualification/capture.jsonl"


def run() -> None:
    settings = Settings()  # type: ignore[call-arg]
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    timing_sink = None
    capture_path = os.environ.get("QUALIFICATION_TIMING_CAPTURE_PATH")
    if capture_path is not None:
        # This is intentionally an equality check, rather than a configurable
        # path.  The runtime reserves and verifies this one private inode.
        if capture_path != _QUALIFICATION_TIMING_CAPTURE_PATH:
            raise SystemExit("qualification_timing_capture_invalid")
        try:
            timing_sink = PrivateTimingSink(Path(_QUALIFICATION_TIMING_CAPTURE_PATH))
        except TimingFailure:
            raise SystemExit("qualification_timing_capture_invalid") from None
    uvicorn.run(
        create_app(settings, timing_sink=timing_sink),
        host=settings.listen_host,
        port=settings.listen_port,
        log_level=settings.log_level.lower(),
        access_log=True,
        limit_concurrency=settings.server_connection_limit,
        backlog=settings.server_backlog,
        timeout_graceful_shutdown=15,
    )


if __name__ == "__main__":
    run()
