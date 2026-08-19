"""Console entry point."""

from __future__ import annotations

import logging

import uvicorn

from .api import create_app
from .config import Settings


def run() -> None:
    settings = Settings()  # type: ignore[call-arg]
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    uvicorn.run(
        create_app(settings),
        host=settings.listen_host,
        port=settings.listen_port,
        log_level=settings.log_level.lower(),
        access_log=True,
        timeout_graceful_shutdown=15,
    )


if __name__ == "__main__":
    run()
