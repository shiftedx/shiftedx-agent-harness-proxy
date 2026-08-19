"""Dependency-free harness policy core.

Adapted from Shiftedx Bench's ``shiftedx_bench.harness`` at revision
335e6694e4aec13e9370af8a993d8c8f14d7ffb5 under Apache-2.0.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

HARNESS_PROFILE = "shiftedx-harness-v1"
HARNESS_SYSTEM_SUFFIX = (
    "\n\nMaintain receipt-grounded work state. After failure, change the action or arguments. Never "
    "repeat an identical call in an unchanged state epoch. Successful reads do not resolve failed "
    "checks. Verify after mutation. Trust structured status over incidental words. Return the exact "
    "requested format without fences."
)
DEFAULT_MUTATION_TOOLS = frozenset(
    {"apply_patch", "edit_file", "str_replace_editor", "write_file"}
)
DEFAULT_VERIFICATION_TOOLS = frozenset({"run_tests", "run_checks", "verify", "check"})
DEFAULT_INVESTIGATION_TOOLS = frozenset(
    {"file_search", "read_file", "session_search", "read_logs"}
)
FAILURE_STATUSES = {"error", "failed", "failure", "rejected", "not_found"}
FAILURE_PATTERNS = (
    re.compile(r"^filenotfounderror\b", re.IGNORECASE),
    re.compile(r"^unknown tool\b", re.IGNORECASE),
    re.compile(r"^patch (?:rejected|does not)\b", re.IGNORECASE),
    re.compile(r"^dispatcher failure\b", re.IGNORECASE),
    re.compile(r"^error\s*:", re.IGNORECASE),
    re.compile(r"\b\d+\s+failed\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class ToolRoles:
    mutation: frozenset[str] = DEFAULT_MUTATION_TOOLS
    verification: frozenset[str] = DEFAULT_VERIFICATION_TOOLS
    investigation: frozenset[str] = DEFAULT_INVESTIGATION_TOOLS

    def configured_role(self, name: str) -> str | None:
        """Return the server role protecting ``name``, when it has one."""
        matches = tuple(
            role
            for role, names in (
                ("mutation", self.mutation),
                ("verification", self.verification),
                ("investigation", self.investigation),
            )
            if name in names
        )
        if len(matches) > 1:
            raise ValueError("Configured tool roles must assign each tool name to only one role")
        return matches[0] if matches else None

    def with_annotation(self, name: str, role: str) -> ToolRoles:
        """Return roles with one tool assigned exclusively to the annotated role."""
        if role not in {"mutation", "verification", "investigation", "other"}:
            raise ValueError(f"Unsupported x-shiftedx-role for {name}: {role}")
        mutation = set(self.mutation)
        verification = set(self.verification)
        investigation = set(self.investigation)
        for names in (mutation, verification, investigation):
            names.discard(name)
        if role != "other":
            {"mutation": mutation, "verification": verification, "investigation": investigation}[
                role
            ].add(name)
        return ToolRoles(frozenset(mutation), frozenset(verification), frozenset(investigation))


def canonical_signature(name: str, arguments: dict[str, Any]) -> str:
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(f"{name}\0{encoded}".encode()).hexdigest()[:12]
    return f"{name}:{digest}"


def receipt_status(result: str) -> str:
    """Classify a public tool result, prioritizing structured status and error fields."""
    text = result.strip()
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        value = None
    if isinstance(value, dict):
        status = str(value.get("status", "")).strip().lower()
        if status in FAILURE_STATUSES:
            return "failure"
        error = value.get("error")
        if error not in (None, False, "", 0, [], {}):
            return "failure"
        return "success"
    if any(pattern.search(text) for pattern in FAILURE_PATTERNS):
        return "failure"
    return "success"


def normalize_bare_json(content: str) -> tuple[str, bool]:
    text = content.strip()
    match = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.IGNORECASE | re.DOTALL)
    if match is None:
        return content, False
    candidate = match.group(1).strip()
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError:
        return content, False
    return (candidate, True) if isinstance(value, dict) else (content, False)


def _matches_json_type(value: Any, type_name: str) -> bool:
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    raise ValueError(f"Unsupported JSON type contract: {type_name}")


def bare_json_issue(
    content: str,
    required_keys: tuple[str, ...] | None = None,
    required_types: dict[str, str] | None = None,
) -> str | None:
    text = content.strip()
    if not text:
        return "The final answer is empty; return the requested bare JSON object."
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return "The final answer is not bare parseable JSON; remove fences and commentary."
    if not isinstance(value, dict):
        return "The final answer must be a JSON object."
    if required_keys is not None and set(value) != set(required_keys):
        return f"The final JSON must contain exactly these keys: {', '.join(required_keys)}."
    for key, type_name in (required_types or {}).items():
        if key in value and not _matches_json_type(value[key], type_name):
            return f"The final JSON key {key} must be a JSON {type_name}."
    return None


@dataclass(frozen=True)
class Receipt:
    receipt_id: int
    tool: str
    signature: str
    status: str
    epoch: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.receipt_id,
            "tool": self.tool,
            "signature": self.signature,
            "status": self.status,
            "epoch": self.epoch,
        }


@dataclass
class AgentHarness:
    goal: str
    available_tools: set[str] = field(default_factory=set)
    required_json_keys: tuple[str, ...] | None = None
    required_json_types: dict[str, str] = field(default_factory=dict)
    require_receipt: bool = True
    roles: ToolRoles = field(default_factory=ToolRoles)
    epoch: int = 0
    receipts: list[Receipt] = field(default_factory=list)
    pending_verification: bool = False
    blocked_duplicates: int = 0
    blocked_stalls: int = 0
    last_action_blocked: bool = False
    force_finalize: bool = False
    terminal_corrections: int = 0
    open_failures: dict[str, int] = field(default_factory=dict)
    investigations_since_failed_verification: int = 0

    def project_final(self, name: str, result: str) -> str | None:
        if (
            self.open_failures
            or self.pending_verification
            or not self.receipts
            or self.receipts[-1].status != "success"
        ):
            return None
        if name in self.roles.verification and self.required_json_keys == ("status", "tests"):
            match = re.fullmatch(r"\s*(\d+)\s+passed\s*", result, re.IGNORECASE)
            if match is not None:
                return json.dumps(
                    {"status": "passed", "tests": int(match.group(1))}, separators=(",", ":")
                )
        try:
            value = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(value, dict) or self.required_json_keys is None:
            return None
        if not set(self.required_json_keys).issubset(value):
            return None
        projected = {key: value[key] for key in self.required_json_keys}
        content = json.dumps(projected, separators=(",", ":"))
        return (
            None
            if bare_json_issue(content, self.required_json_keys, self.required_json_types)
            else content
        )

    def duplicate(self, name: str, arguments: dict[str, Any]) -> Receipt | None:
        signature = canonical_signature(name, arguments)
        return next(
            (
                receipt
                for receipt in reversed(self.receipts)
                if receipt.epoch == self.epoch and receipt.signature == signature
            ),
            None,
        )

    def record(self, name: str, arguments: dict[str, Any], result: str) -> Receipt:
        self.last_action_blocked = False
        self.force_finalize = False
        status = receipt_status(result)
        receipt = Receipt(
            receipt_id=len(self.receipts) + 1,
            tool=name,
            signature=canonical_signature(name, arguments),
            status=status,
            epoch=self.epoch,
        )
        self.receipts.append(receipt)
        if status == "failure" and name in self.roles.verification:
            self.open_failures[name] = receipt.receipt_id
            self.investigations_since_failed_verification = 0
        else:
            self.open_failures.pop(name, None)
            if status == "success" and name in self.roles.investigation and any(
                tool in self.roles.verification for tool in self.open_failures
            ):
                self.investigations_since_failed_verification += 1
        if status == "success" and name in self.roles.mutation:
            self.epoch += 1
            self.pending_verification = True
            self.investigations_since_failed_verification = 0
        elif name in self.roles.verification and self.pending_verification:
            self.pending_verification = False
        return receipt

    def blocked_result(self, prior: Receipt) -> str:
        self.blocked_duplicates += 1
        self.last_action_blocked = True
        self.force_finalize = (
            prior.status == "success" and not self.pending_verification and not self.open_failures
        )
        return json.dumps(
            {
                "shiftedx_harness": "duplicate_call_blocked",
                "prior_receipt": prior.receipt_id,
                "instruction": (
                    "The prior successful receipt is sufficient. Return the required final answer now."
                    if self.force_finalize
                    else "Diagnose the prior receipt and choose a changed action or arguments."
                ),
            },
            separators=(",", ":"),
        )

    def stalled_result(self, name: str) -> str | None:
        has_failed_verification = any(
            tool in self.roles.verification for tool in self.open_failures
        )
        has_mutation_tool = bool(self.available_tools & self.roles.mutation)
        if not (
            name in self.roles.investigation
            and has_failed_verification
            and has_mutation_tool
            and self.investigations_since_failed_verification >= 3
        ):
            return None
        self.blocked_stalls += 1
        self.last_action_blocked = True
        self.force_finalize = False
        return json.dumps(
            {
                "shiftedx_harness": "investigation_stall_blocked",
                "instruction": (
                    "A verification failure remains open and three successful investigation receipts are "
                    "already available. Use an available mutation tool, then rerun verification."
                ),
            },
            separators=(",", ":"),
        )

    def terminal_issue(self, content: str) -> str | None:
        if not self.receipts and self.require_receipt:
            return "No tool receipt supports completion; use the supplied tools first."
        if self.last_action_blocked and not self.force_finalize:
            return "The latest requested action was blocked; choose a changed action before finishing."
        if self.receipts and self.receipts[-1].status == "failure":
            return "The latest receipt failed; recover with a changed action before finishing."
        if self.open_failures:
            tools = ", ".join(sorted(self.open_failures))
            return f"Failed receipts remain unresolved for: {tools}. Recover and verify before finishing."
        if self.pending_verification:
            return "State changed after the last verification; run a verification tool before finishing."
        if self.required_json_keys is None:
            return None
        return bare_json_issue(content, self.required_json_keys, self.required_json_types)

    def correction(self, issue: str) -> str:
        self.terminal_corrections += 1
        return (
            f"[shiftedx harness correction]\n{issue}\n"
            "Continue from the verified receipts; do not restart completed work."
        )

    def render(self) -> str:
        recent = self.receipts[-3:]
        receipt_text = ", ".join(
            f"R{item.receipt_id}:{item.tool}={item.status}@e{item.epoch}" for item in recent
        ) or "none"
        verification = "required" if self.pending_verification else "clear"
        unresolved = ",".join(sorted(self.open_failures)) or "none"
        if self.pending_verification and self.available_tools & self.roles.verification:
            next_action = "Run a verification tool now; do not inspect or mutate again first."
        elif (
            any(tool in self.roles.verification for tool in self.open_failures)
            and self.investigations_since_failed_verification >= 3
            and self.available_tools & self.roles.mutation
        ):
            next_action = (
                "A failed verification is diagnosed; use a mutation tool next, then rerun verification."
            )
        else:
            next_action = "Use receipts; change approach after failure; finish in the exact requested format."
        if self.force_finalize:
            next_action = "Evidence is sufficient; return the required final answer now without another tool call."
        return (
            "[shiftedx harness] "
            f"epoch={self.epoch} verify={verification} open={unresolved} receipts={receipt_text}. "
            f"Next: {next_action}"
        )
