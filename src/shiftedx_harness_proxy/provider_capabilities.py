"""Narrow, translation-only upstream capability planning."""

from __future__ import annotations

import copy
from typing import Any, Literal

JsonObject = dict[str, Any]
ToolResponseCapabilityMode = Literal["passthrough", "phase_split"]
CapabilityPhase = Literal["acquisition", "finalization"]


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
