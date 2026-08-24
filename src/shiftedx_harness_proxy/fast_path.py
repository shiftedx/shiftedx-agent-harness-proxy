"""Shadow-only eligibility and parity checks for a future intervention fast path.

The module deliberately contains no bypass.  ``shadow`` records only a bounded,
hash-only proof that removing the versioned harness mutation would leave the
same model-boundary request.  Promotion remains unavailable until an immutable
signed authority and model-backed corpus are supplied.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from .core import HARNESS_SYSTEM_SUFFIX
from .transcript import Reconstruction

JsonObject = dict[str, Any]
FastPathMode = Literal["disabled", "shadow", "enabled"]
FAST_PATH_CONTRACT_ID: Literal["server_harness_passthrough_no_policy_work:v1"] = (
    "server_harness_passthrough_no_policy_work:v1"
)
HARNESS_MUTATION_ID: Literal["shiftedx_harness_v1:system_suffix_and_state_prompt:v1"] = (
    "shiftedx_harness_v1:system_suffix_and_state_prompt:v1"
)
FastPathDecisionReason = Literal[
    "mode_disabled",
    "harness_disabled",
    "receipt_extension_present",
    "tools_present",
    "response_format_present",
    "tool_choice_present",
    "parallel_tool_calls_present",
    "transcript_degraded",
    "receipt_present",
    "pending_verification",
    "open_failure",
    "blocked_action",
    "correction_or_finalization",
    "local_projection_available",
    "phase_split_required",
    "combined_capability_required",
    "eligible",
]
FastPathShadowReason = Literal[
    "non_message_payload_mismatch",
    "messages_invalid",
    "harness_mutation_mismatch",
    "exact_harness_mutation",
]


@dataclass(frozen=True)
class FastPathDecision:
    """A categorical eligibility result without request content."""

    eligible: bool
    reason: FastPathDecisionReason

    def to_safe_dict(self) -> dict[str, bool | str]:
        return {"eligible": self.eligible, "reason": self.reason}


@dataclass(frozen=True)
class FastPathShadowResult:
    """Hash-only result of comparing the normal and candidate payloads."""

    eligible: bool
    equivalent: bool
    reason: FastPathShadowReason
    candidate_payload_sha256: str
    normal_payload_sha256: str
    fast_path_contract_id: Literal["server_harness_passthrough_no_policy_work:v1"] = FAST_PATH_CONTRACT_ID
    harness_mutation_id: Literal["shiftedx_harness_v1:system_suffix_and_state_prompt:v1"] = HARNESS_MUTATION_ID

    def to_safe_dict(self) -> dict[str, bool | str]:
        return {
            "eligible": self.eligible,
            "equivalent": self.equivalent,
            "reason": self.reason,
            "candidate_payload_sha256": self.candidate_payload_sha256,
            "normal_payload_sha256": self.normal_payload_sha256,
            "fast_path_contract_id": self.fast_path_contract_id,
            "harness_mutation_id": self.harness_mutation_id,
        }


class FastPathObserver(Protocol):
    """Private, injectable sink for hash-only shadow decisions."""

    def record(self, result: FastPathShadowResult) -> None: ...


@dataclass
class InMemoryFastPathObserver:
    """Test-only observer.  It retains only fixed-size hashes and categories."""

    records: list[FastPathShadowResult] = field(default_factory=list)

    def record(self, result: FastPathShadowResult) -> None:
        self.records.append(result)


def classify_fast_path(
    *,
    mode: FastPathMode,
    harness_enabled: bool,
    has_receipt_extension: bool,
    normalized_tools: list[JsonObject],
    has_response_format: bool,
    has_tool_choice: bool,
    has_parallel_tool_calls: bool,
    rebuilt: Reconstruction,
    local_projection_available: bool,
    uses_phase_split: bool,
    uses_combined_capability: bool,
) -> FastPathDecision:
    """Classify the only candidate class safe enough for shadow comparison.

    This function deliberately treats every omitted policy fact as ineligible.
    It takes no client-selected fast-path signal.
    """

    if mode != "shadow":
        return FastPathDecision(False, "mode_disabled")
    if not harness_enabled:
        return FastPathDecision(False, "harness_disabled")
    if has_receipt_extension:
        return FastPathDecision(False, "receipt_extension_present")
    if normalized_tools:
        return FastPathDecision(False, "tools_present")
    if has_response_format:
        return FastPathDecision(False, "response_format_present")
    if has_tool_choice:
        return FastPathDecision(False, "tool_choice_present")
    if has_parallel_tool_calls:
        return FastPathDecision(False, "parallel_tool_calls_present")
    if rebuilt.degraded:
        return FastPathDecision(False, "transcript_degraded")
    harness = rebuilt.harness
    if harness.receipts:
        return FastPathDecision(False, "receipt_present")
    if harness.pending_verification:
        return FastPathDecision(False, "pending_verification")
    if harness.open_failures:
        return FastPathDecision(False, "open_failure")
    if harness.last_action_blocked or harness.blocked_duplicates or harness.blocked_stalls:
        return FastPathDecision(False, "blocked_action")
    if harness.terminal_corrections or harness.force_finalize:
        return FastPathDecision(False, "correction_or_finalization")
    if local_projection_available:
        return FastPathDecision(False, "local_projection_available")
    if uses_phase_split:
        return FastPathDecision(False, "phase_split_required")
    if uses_combined_capability:
        return FastPathDecision(False, "combined_capability_required")
    return FastPathDecision(True, "eligible")


def compare_fast_path_shadow(
    candidate_payload: JsonObject,
    normal_payload: JsonObject,
    rebuilt: Reconstruction,
) -> FastPathShadowResult:
    """Prove that normal differs only by the existing versioned mutation.

    Payloads stay in-process for comparison.  The returned artifact has no
    request body, message content, tool data, or response data.
    """

    candidate_hash = _payload_sha256(candidate_payload)
    normal_hash = _payload_sha256(normal_payload)
    candidate_without_messages = _without_messages(candidate_payload)
    normal_without_messages = _without_messages(normal_payload)
    if candidate_without_messages != normal_without_messages:
        return FastPathShadowResult(
            True, False, "non_message_payload_mismatch", candidate_hash, normal_hash
        )
    candidate_messages = candidate_payload.get("messages")
    normal_messages = normal_payload.get("messages")
    if not isinstance(candidate_messages, list) or not isinstance(normal_messages, list):
        return FastPathShadowResult(True, False, "messages_invalid", candidate_hash, normal_hash)
    expected = _apply_versioned_harness_mutation(candidate_messages, rebuilt)
    if normal_messages != expected:
        return FastPathShadowResult(True, False, "harness_mutation_mismatch", candidate_hash, normal_hash)
    return FastPathShadowResult(True, True, "exact_harness_mutation", candidate_hash, normal_hash)


def _apply_versioned_harness_mutation(messages: list[Any], rebuilt: Reconstruction) -> list[Any]:
    expected = copy.deepcopy(messages)
    for message in expected:
        if isinstance(message, dict) and message.get("role") == "system" and isinstance(message.get("content"), str):
            if HARNESS_SYSTEM_SUFFIX not in message["content"]:
                message["content"] += HARNESS_SYSTEM_SUFFIX
            break
    else:
        expected.insert(0, {"role": "system", "content": HARNESS_SYSTEM_SUFFIX.strip()})
    state = rebuilt.harness.render()
    if rebuilt.degraded:
        state += " Transcript state is degraded due to incomplete or invalid call/result pairing."
    expected.append({"role": "user", "content": state})
    return expected


def _without_messages(payload: JsonObject) -> JsonObject:
    result = copy.deepcopy(payload)
    result.pop("messages", None)
    return result


def _payload_sha256(payload: JsonObject) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()
