"""Stable accounting facts for completions projected without model work."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

JsonObject = dict[str, Any]

LOCAL_PROJECTION_EXTENSION = "x-shiftedx-projection-v1"
def local_projection_accounting() -> JsonObject:
    """Return a fresh protocol extension for a locally projected completion."""
    return {
        "origin": "local_projection",
        "upstream_calls": 0,
        "upstream_model_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "client_input_tokenization": {"available": False, "tokens": None},
    }


def _is_exact_local_projection_marker(marker: object) -> bool:
    if not isinstance(marker, dict) or set(marker) != {
        "origin",
        "upstream_calls",
        "upstream_model_usage",
        "client_input_tokenization",
    }:
        return False
    if type(marker["origin"]) is not str or marker["origin"] != "local_projection":
        return False
    if type(marker["upstream_calls"]) is not int:
        return False
    if marker["upstream_calls"] != 0:
        return False
    usage = marker["upstream_model_usage"]
    if not isinstance(usage, dict) or set(usage) != {"prompt_tokens", "completion_tokens", "total_tokens"}:
        return False
    if any(type(value) is not int or value != 0 for value in usage.values()):
        return False
    tokenization = marker["client_input_tokenization"]
    return (
        isinstance(tokenization, dict)
        and set(tokenization) == {"available", "tokens"}
        and type(tokenization["available"]) is bool
        and tokenization["available"] is False
        and tokenization["tokens"] is None
    )


def public_projection_summary(completions: Iterable[object]) -> JsonObject:
    """Produce the only projection facts permitted in a public benchmark ledger.

    Inputs must be completion records returned by the proxy, after its upstream
    normalization. This function intentionally reads only the exact
    local-projection marker and never copies input fields.
    """
    completion_records = 0
    local_projections = 0
    for completion in completions:
        if not isinstance(completion, dict):
            raise ValueError("Public projection summaries require completion objects")
        completion_records += 1
        marker = completion.get(LOCAL_PROJECTION_EXTENSION)
        if marker is None:
            continue
        if not _is_exact_local_projection_marker(marker):
            raise ValueError("Local projection accounting marker is invalid")
        local_projections += 1
    return {
        "schema_version": "shiftedx-public-projection-summary-v1",
        "completion_records": completion_records,
        "local_projections": local_projections,
        "upstream_calls_avoided": local_projections,
        "local_projection_upstream_model_usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
        "local_projection_client_input_tokenization": {
            "available": False,
            "records": local_projections,
        },
    }
