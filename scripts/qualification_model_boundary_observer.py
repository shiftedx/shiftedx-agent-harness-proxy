#!/usr/bin/env python3
"""Private transparent observer for qualification proxy-to-model traffic.

It forwards Chat Completions unchanged while appending only safe component hashes
to a fresh private ledger. It is deliberately a qualification-only tool, not a
production provider abstraction or proxy feature.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from shiftedx_harness_proxy.qualification_contract import model_boundary_fingerprint

UPSTREAM = os.environ.get("QUALIFICATION_OBSERVER_UPSTREAM", "").rstrip("/")
LEDGER = Path(os.environ.get("QUALIFICATION_OBSERVER_LEDGER", ""))

if not UPSTREAM or not LEDGER.name:
    raise RuntimeError("QUALIFICATION_OBSERVER_UPSTREAM and QUALIFICATION_OBSERVER_LEDGER are required")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
client = httpx.AsyncClient(timeout=httpx.Timeout(600.0), trust_env=False)


def _append_observation(payload: dict[str, Any]) -> None:
    fingerprint = model_boundary_fingerprint(payload)
    record = {
        "record_type": "qualification_model_boundary",
        "digest": fingerprint.digest,
        "fields": fingerprint.fields,
    }
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


@app.post("/v1/chat/completions")
async def chat(request: Request) -> Response:
    payload = await request.json()
    if not isinstance(payload, dict):
        return Response(status_code=400)
    _append_observation(payload)
    headers = {"content-type": "application/json"}
    authorization = request.headers.get("authorization")
    if authorization is not None:
        headers["authorization"] = authorization
    response = await client.post(f"{UPSTREAM}/chat/completions", json=payload, headers=headers)
    return Response(response.content, status_code=response.status_code, media_type=response.headers.get("content-type"))


@app.get("/v1/models")
async def models(request: Request) -> Response:
    headers = {"authorization": request.headers.get("authorization", "")}
    response = await client.get(f"{UPSTREAM}/models", headers=headers)
    return Response(response.content, status_code=response.status_code, media_type=response.headers.get("content-type"))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=18092, access_log=False, log_level="warning")
