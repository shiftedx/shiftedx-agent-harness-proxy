"""Conservative Local Projection eligibility and shadow comparison.

The decision objects retain canonical values only for in-process comparison.  Their
``to_safe_dict`` methods intentionally expose aggregate-safe booleans and stable
reason categories, never receipt identifiers or terminal content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import AgentHarness

_PRIMITIVE_TYPES = frozenset({"string", "integer", "number", "boolean"})
_PROVEN_VERIFICATION_SUMMARY = re.compile(r"\s*(\d+)\s+passed\s*", re.IGNORECASE)


@dataclass(frozen=True)
class CanonicalProjection:
    """The parsed terminal value and declared primitive-object schema."""

    value: dict[str, Any]
    declared_schema: tuple[tuple[str, str], ...]

    def content(self) -> str:
        return json.dumps(self.value, separators=(",", ":"))


@dataclass(frozen=True)
class ProjectionDecision:
    eligible: bool
    reason: str
    candidate: CanonicalProjection | None = None

    def to_safe_dict(self) -> dict[str, bool | str]:
        return {"eligible": self.eligible, "reason": self.reason}


@dataclass(frozen=True)
class ProjectionShadowEvaluation:
    eligible: bool
    agreement: bool | None
    reason: str

    def to_safe_dict(self) -> dict[str, bool | str | None]:
        return {"eligible": self.eligible, "agreement": self.agreement, "reason": self.reason}


def decide_local_projection(
    harness: AgentHarness,
    name: str,
    result: str,
    *,
    transcript_degraded: bool = False,
    blocked_unresolved_action: bool = False,
) -> ProjectionDecision:
    """Return a categorical, side-effect-free decision for the proven projection rule."""
    if transcript_degraded:
        return _rejected("transcript_degraded")
    if blocked_unresolved_action or harness.last_action_blocked:
        return _rejected("blocked_unresolved_action")
    if harness.pending_verification:
        return _rejected("pending_verification")
    if harness.open_failures:
        return _rejected("open_failure")
    if not harness.receipts:
        return _rejected("no_receipt")
    latest = harness.receipts[-1]
    if latest.epoch != harness.epoch:
        return _rejected("stale_receipt")
    if latest.status != "success":
        return _rejected("receipt_not_success")
    if harness.available_tools and name not in harness.available_tools:
        return _rejected("unknown_tool_result")
    if latest.tool != name:
        return _rejected("nonlatest_receipt")

    schema = _declared_schema(harness)
    if schema is None:
        return _rejected("unsupported_schema")
    proven = _proven_verification_candidate(harness, name, result, schema)
    if proven is not None:
        return ProjectionDecision(True, "eligible", proven)
    value = _parse_exact_terminal(result, schema)
    if isinstance(value, str):
        return _rejected(value)
    return ProjectionDecision(True, "eligible", CanonicalProjection(value, schema))


def evaluate_projection_shadow(
    decision: ProjectionDecision, actual_model_terminal: str | None
) -> ProjectionShadowEvaluation:
    """Compare a candidate with an actual terminal without emitting either value."""
    if not decision.eligible or decision.candidate is None:
        return ProjectionShadowEvaluation(False, None, decision.reason)
    if actual_model_terminal is None:
        return ProjectionShadowEvaluation(True, None, "model_terminal_missing")
    actual = _parse_exact_terminal(actual_model_terminal, decision.candidate.declared_schema)
    if isinstance(actual, str):
        return ProjectionShadowEvaluation(True, False, "model_terminal_invalid")
    if actual == decision.candidate.value:
        return ProjectionShadowEvaluation(True, True, "exact_agreement")
    return ProjectionShadowEvaluation(True, False, "terminal_mismatch")


def _rejected(reason: str) -> ProjectionDecision:
    return ProjectionDecision(False, reason)


def _declared_schema(harness: AgentHarness) -> tuple[tuple[str, str], ...] | None:
    keys = harness.required_json_keys
    types = harness.required_json_types
    if keys is None or not keys or len(set(keys)) != len(keys) or set(keys) != set(types):
        return None
    if any(type_name not in _PRIMITIVE_TYPES for type_name in types.values()):
        return None
    return tuple((key, types[key]) for key in keys)


def _proven_verification_candidate(
    harness: AgentHarness,
    name: str,
    result: str,
    schema: tuple[tuple[str, str], ...],
) -> CanonicalProjection | None:
    if name not in harness.roles.verification or schema != (("status", "string"), ("tests", "integer")):
        return None
    match = _PROVEN_VERIFICATION_SUMMARY.fullmatch(result)
    if match is None:
        return None
    return CanonicalProjection({"status": "passed", "tests": int(match.group(1))}, schema)


def _parse_exact_terminal(
    content: str, schema: tuple[tuple[str, str], ...]
) -> dict[str, Any] | str:
    try:
        value = json.loads(
            content,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        return "malformed_tool_result"
    if not isinstance(value, dict):
        return "terminal_not_object"
    keys = tuple(key for key, _ in schema)
    if set(value) != set(keys):
        return "schema_keys_mismatch"
    for key, type_name in schema:
        if not _matches_type(value[key], type_name):
            return "schema_type_mismatch"
    return {key: value[key] for key in keys}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> Any:
    raise ValueError("non-finite JSON number")


def _matches_type(value: Any, type_name: str) -> bool:
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    return False
