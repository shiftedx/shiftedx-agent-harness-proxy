"""Narrow, translation-only upstream capability planning."""

from __future__ import annotations

import copy
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Literal

JsonObject = dict[str, Any]
ToolResponseCapabilityMode = Literal["passthrough", "phase_split", "combined_v1"]
CapabilityPhase = Literal["acquisition", "finalization"]
COMBINED_TOOL_TERMINAL_CONTRACT_ID = "native_tool_or_strict_json_schema:v1"
COMBINED_CAPABILITY_SCHEMA_VERSION = "1.0"
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_RUNTIME_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[+.-][0-9A-Za-z.-]+)?$")

# This is deliberately process-local accounting context, not request payload metadata.
# BoundedUpstream reads it only after it owns an upstream slot, immediately before
# delegating the operation.
_upstream_phase: ContextVar[CapabilityPhase | None] = ContextVar("upstream_phase", default=None)


@contextmanager
def upstream_phase(phase: CapabilityPhase | None) -> Iterator[None]:
    """Scope non-serialized phase context to one planned upstream operation."""
    token: Token[CapabilityPhase | None] = _upstream_phase.set(phase)
    try:
        yield
    finally:
        _upstream_phase.reset(token)


def current_upstream_phase() -> CapabilityPhase | None:
    """Return phase context for the currently executing upstream operation."""
    return _upstream_phase.get()


def requires_phase_split(
    mode: ToolResponseCapabilityMode,
    *,
    has_tools: bool,
    has_response_format: bool,
    strict_schema_supported: bool,
) -> bool:
    """Return whether a request can safely use the two-phase grammar translation."""
    return mode == "phase_split" and has_tools and has_response_format and strict_schema_supported


def requires_combined_capability(
    mode: ToolResponseCapabilityMode,
    *,
    has_tools: bool,
    has_response_format: bool,
    strict_schema_supported: bool,
) -> bool:
    """Return whether this request uses the native combined upstream grammar."""
    return mode == "combined_v1" and has_tools and has_response_format and strict_schema_supported


def combined_tool_terminal_schema_supported(document: Any) -> bool:
    """Accept only the exact, versioned upstream combined-grammar signal."""
    if not isinstance(document, dict) or document.get("schema_version") != COMBINED_CAPABILITY_SCHEMA_VERSION:
        return False
    runtime = document.get("runtime")
    if (
        not isinstance(runtime, dict)
        or runtime.get("name") != "mtplx"
        or not isinstance(runtime.get("version"), str)
        or _RUNTIME_VERSION.fullmatch(runtime["version"]) is None
        or not isinstance(runtime.get("source_revision"), str)
        or _SOURCE_REVISION.fullmatch(runtime["source_revision"]) is None
    ):
        return False
    features = document.get("features")
    if not isinstance(features, dict):
        return False
    capability = features.get("combined_tool_terminal_schema")
    return (
        isinstance(capability, dict)
        and capability.get("supported") is True
        and capability.get("contract_id") == COMBINED_TOOL_TERMINAL_CONTRACT_ID
    )


def outbound_payload(
    base_payload: JsonObject,
    messages: list[Any],
    *,
    phase: CapabilityPhase | None,
) -> JsonObject:
    """Build a fresh payload for one upstream attempt without making policy decisions."""
    payload = copy.deepcopy(base_payload)
    payload["messages"] = copy.deepcopy(messages)
    if phase == "acquisition":
        payload.pop("response_format", None)
    elif phase == "finalization":
        payload.pop("tools", None)
        payload.pop("tool_choice", None)
        payload.pop("parallel_tool_calls", None)
    return payload
