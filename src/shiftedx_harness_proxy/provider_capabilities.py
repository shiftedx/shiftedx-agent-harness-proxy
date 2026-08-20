"""Narrow, translation-only upstream capability planning."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Literal

JsonObject = dict[str, Any]
ToolResponseCapabilityMode = Literal["passthrough", "phase_split"]
CapabilityPhase = Literal["acquisition", "finalization"]

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
