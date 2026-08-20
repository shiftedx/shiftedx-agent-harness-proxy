"""Privacy-safe request planning and evidence for paired qualification only.

This module deliberately has no provider client abstraction.  It describes the
one grammar translation required by the qualification runner and reduces its
evidence to fixed labels, counts, and SHA-256 digests.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

JsonObject = dict[str, Any]
Phase = Literal["acquisition", "finalization", "terminal"]

COMPATIBILITY_MODE = "phase_split"
COMPATIBILITY_VERSION = "shiftedx-phase-plan-v1"
BENCHMARK_REVISION = "335e6694e4aec13e9370af8a993d8c8f14d7ffb5"
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class PreflightFailure(RuntimeError):
    """Raised before the runner is permitted to create a scored row."""


@dataclass(frozen=True)
class SafeFingerprint:
    """A hash-only contract fingerprint suitable for an allowlisted ledger."""

    boundary: str
    digest: str
    fields: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"boundary": self.boundary, "digest": self.digest, "fields": self.fields}


@dataclass(frozen=True)
class PreflightObservation:
    """Sanitized outcome of one arm/path preflight execution."""

    arm: Literal["direct", "proxy"]
    tool_required: bool
    native_acquisition_tool_calls: int
    phases: tuple[str, ...]
    terminal_schema_valid: bool
    downstream: SafeFingerprint
    model_facing: tuple[SafeFingerprint, ...]
    proxy_phase_counts: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "record_type": "paired_preflight",
            "scored": False,
            "arm": self.arm,
            "path": "tool_required" if self.tool_required else "no_tool_terminal",
            "native_acquisition_tool_calls": self.native_acquisition_tool_calls,
            "phases": list(self.phases),
            "terminal_schema_valid": self.terminal_schema_valid,
            "downstream_contract": self.downstream.to_dict(),
            "model_facing_contracts": [item.to_dict() for item in self.model_facing],
            "proxy_phase_counts": self.proxy_phase_counts,
        }


class PhasePlanner:
    """The versioned, translation-only tool/schema compatibility planner."""

    mode = COMPATIBILITY_MODE
    version = COMPATIBILITY_VERSION

    def plan(self, payload: JsonObject, *, phase: Phase) -> JsonObject:
        """Return a model-facing payload while preserving the standard downstream one."""
        planned = copy.deepcopy(payload)
        if phase == "acquisition":
            planned.pop("response_format", None)
        elif phase == "finalization":
            planned.pop("tools", None)
            planned.pop("tool_choice", None)
            planned.pop("parallel_tool_calls", None)
        return planned

    def phases_for(self, payload: JsonObject) -> tuple[Phase, ...]:
        if payload.get("tools") and payload.get("response_format"):
            return ("acquisition", "finalization")
        return ("terminal",)


def request_fingerprints(
    payload: JsonObject,
    scenario_order: list[str],
    *,
    policy_delta: dict[str, bool],
    planner: PhasePlanner | None = None,
) -> tuple[SafeFingerprint, tuple[SafeFingerprint, ...]]:
    """Fingerprint downstream and planned model-facing contracts without payload retention."""
    planner = planner or PhasePlanner()
    downstream = contract_fingerprint(
        "downstream",
        payload,
        scenario_order,
        policy_delta=policy_delta,
        planner=planner,
        phase=None,
    )
    model_facing = tuple(
        contract_fingerprint(
            "model_facing",
            planner.plan(payload, phase=phase),
            scenario_order,
            policy_delta={},
            planner=planner,
            phase=phase,
        )
        for phase in planner.phases_for(payload)
    )
    return downstream, model_facing


def model_boundary_fingerprint(
    payload: JsonObject, *, scenario_order: list[str] | None = None
) -> SafeFingerprint:
    """Fingerprint fields actually visible at one model-facing request boundary.

    This intentionally excludes user turns, model output, tool arguments/results,
    endpoints, and credentials. A transparent qualification observer can emit
    this exact representation from proxy-to-model traffic without retaining a
    request body.
    """
    fields = _model_boundary_fields(payload)
    if scenario_order is not None:
        fields.update(_model_boundary_context(scenario_order))
    return SafeFingerprint("model_facing_observed", _sha256(fields), fields)


def read_model_boundary_observer_ledger(path: Path) -> tuple[SafeFingerprint, ...]:
    """Read a fresh private observer ledger without admitting payload-bearing fields."""
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise PreflightFailure("proxy model-boundary observer ledger is unavailable") from error
    expected_keys = set(_model_boundary_field_keys())
    fingerprints: list[SafeFingerprint] = []
    for row in rows:
        fields = row.get("fields") if isinstance(row, dict) else None
        digest = row.get("digest") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or row.get("record_type") != "qualification_model_boundary"
            or not isinstance(fields, dict)
            or set(fields) != expected_keys
            or not isinstance(digest, str)
            or digest != _sha256(fields)
        ):
            raise PreflightFailure("proxy model-boundary observer ledger is invalid")
        fingerprints.append(SafeFingerprint("model_facing_observed", digest, fields))
    return tuple(fingerprints)


def bind_model_boundary_context(
    fingerprints: tuple[SafeFingerprint, ...], scenario_order: list[str]
) -> tuple[SafeFingerprint, ...]:
    """Bind observer component hashes to the frozen planner/benchmark/order context."""
    context = _model_boundary_context(scenario_order)
    return tuple(
        SafeFingerprint(
            fingerprint.boundary,
            _sha256({**fingerprint.fields, **context}),
            {**fingerprint.fields, **context},
        )
        for fingerprint in fingerprints
    )


def _model_boundary_fields(payload: JsonObject) -> dict[str, Any]:
    return {
        "system_prompt_sha256": _sha256(
            next(
                (
                    message.get("content")
                    for message in payload.get("messages", [])
                    if isinstance(message, dict) and message.get("role") == "system"
                ),
                None,
            )
        ),
        "tool_schema_sha256": _sha256(payload.get("tools")),
        "tool_choice_policy": _safe_policy(payload.get("tool_choice")),
        "terminal_schema_sha256": _sha256(payload.get("response_format")),
        "sampler": {
            "temperature": payload.get("temperature"),
            "top_p": payload.get("top_p"),
            "top_k": payload.get("top_k"),
        },
        "reasoning": {
            "thinking_enabled": _thinking_enabled(payload.get("thinking")),
            "effort": _safe_policy(payload.get("reasoning_effort")),
        },
        "token_budget": payload.get("max_tokens"),
    }


def _model_boundary_field_keys() -> tuple[str, ...]:
    return (
        "system_prompt_sha256",
        "tool_schema_sha256",
        "tool_choice_policy",
        "terminal_schema_sha256",
        "sampler",
        "reasoning",
        "token_budget",
    )


def _model_boundary_context(scenario_order: list[str]) -> dict[str, Any]:
    return {
        "compatibility": {"mode": COMPATIBILITY_MODE, "version": COMPATIBILITY_VERSION},
        "benchmark_revision": BENCHMARK_REVISION,
        "scenario_order": {"sha256": _sha256(scenario_order), "count": len(scenario_order)},
    }


def qualification_contract_digest(
    payloads: list[JsonObject],
    scenario_order: list[str],
    *,
    policy_delta: dict[str, bool],
) -> str:
    """Bind a scored invocation to every selected scenario's safe contract."""
    planner = PhasePlanner()
    return _sha256(
        {
            "compatibility": {"mode": planner.mode, "version": planner.version},
            "benchmark_revision": BENCHMARK_REVISION,
            "scenario_order": {"sha256": _sha256(scenario_order), "count": len(scenario_order)},
            "contracts": [
                contract_fingerprint(
                    "downstream",
                    payload,
                    scenario_order,
                    policy_delta=policy_delta,
                    planner=planner,
                    phase=None,
                ).fields
                for payload in payloads
            ],
        }
    )


def contract_fingerprint(
    boundary: str,
    payload: JsonObject,
    scenario_order: list[str],
    *,
    policy_delta: dict[str, bool],
    planner: PhasePlanner,
    phase: Phase | None,
) -> SafeFingerprint:
    """Create an allowlisted representation, hashing all request-derived content."""
    system_prompt = next(
        (
            message.get("content")
            for message in payload.get("messages", [])
            if isinstance(message, dict) and message.get("role") == "system"
        ),
        None,
    )
    fields: dict[str, Any] = {
        "system_prompt_sha256": _sha256(system_prompt),
        "tool_schema_sha256": _sha256(payload.get("tools")),
        "tool_choice_policy": _safe_policy(payload.get("tool_choice")),
        "terminal_schema_sha256": _sha256(payload.get("response_format")),
        "sampler": {
            "temperature": payload.get("temperature"),
            "top_p": payload.get("top_p"),
            "top_k": payload.get("top_k"),
        },
        "reasoning": {
            "thinking_enabled": _thinking_enabled(payload.get("thinking")),
            "effort": _safe_policy(payload.get("reasoning_effort")),
        },
        "token_budget": payload.get("max_tokens"),
        "compatibility": {"mode": planner.mode, "version": planner.version, "phase": phase},
        "benchmark_revision": BENCHMARK_REVISION,
        "scenario_order": {"sha256": _sha256(scenario_order), "count": len(scenario_order)},
        "declared_policy_deltas": dict(sorted(policy_delta.items())),
    }
    return SafeFingerprint(boundary, _sha256({"boundary": boundary, "fields": fields}), fields)


def contract_mismatches(left: SafeFingerprint, right: SafeFingerprint) -> list[str]:
    """Return accidental field mismatch labels, excluding explicitly declared policy deltas."""
    if left.boundary != right.boundary:
        return ["boundary"]
    keys = sorted(set(left.fields) | set(right.fields))
    return [
        key
        for key in keys
        if key != "declared_policy_deltas" and left.fields.get(key) != right.fields.get(key)
    ]


def assert_preflight(observations: list[PreflightObservation]) -> None:
    """Fail closed unless both arms demonstrate equivalent safe phase behavior."""
    arms: tuple[Literal["direct", "proxy"], ...] = ("direct", "proxy")
    by_path = {
        (observation.arm, observation.tool_required): observation
        for observation in observations
    }
    for tool in (item for item in observations if item.tool_required):
        if tool.native_acquisition_tool_calls < 1:
            raise PreflightFailure(f"{tool.arm} emitted zero native acquisition tool calls")
    for arm in arms:
        if by_path.get((arm, True)) is None:
            raise PreflightFailure("paired preflight requires a tool-required path for both arms")
    required = [(arm, tool_required) for arm in arms for tool_required in (True, False)]
    if any(key not in by_path for key in required):
        raise PreflightFailure("paired preflight requires tool-required and no-tool terminal paths for both arms")
    for arm in arms:
        tool = by_path[(arm, True)]
        terminal = by_path[(arm, False)]
        if not tool.terminal_schema_valid or not terminal.terminal_schema_valid:
            raise PreflightFailure(f"{arm} terminal schema validation failed")
        if tuple(tool.phases) != ("acquisition", "finalization"):
            raise PreflightFailure(f"{arm} tool-required phase behavior differed")
        if tuple(terminal.phases) != ("terminal",):
            raise PreflightFailure(f"{arm} no-tool terminal phase behavior differed")
    for tool_required in (True, False):
        direct = by_path[("direct", tool_required)]
        proxy = by_path[("proxy", tool_required)]
        if direct.phases != proxy.phases:
            raise PreflightFailure("direct/proxy phase behavior differed")
        mismatch = contract_mismatches(direct.downstream, proxy.downstream)
        if mismatch:
            raise PreflightFailure(f"downstream contract mismatch: {', '.join(mismatch)}")
        if len(direct.model_facing) != len(proxy.model_facing):
            raise PreflightFailure("model-facing phase count differed")
        for direct_fingerprint, proxy_fingerprint in zip(direct.model_facing, proxy.model_facing, strict=True):
            mismatch = contract_mismatches(direct_fingerprint, proxy_fingerprint)
            if mismatch:
                raise PreflightFailure(f"model-facing contract mismatch: {', '.join(mismatch)}")
    proxy_tool = by_path[("proxy", True)]
    if proxy_tool.proxy_phase_counts != {"acquisition": 2, "finalization": 1}:
        raise PreflightFailure("proxy did not record equivalent acquisition/finalization behavior")


def write_preflight_ledger(
    output: Path,
    observations: list[PreflightObservation],
    *,
    source_commit: str,
    image_digest: str,
    contract_digests: dict[str, str],
    failure_reason: str | None = None,
) -> None:
    """Atomically retain safe evidence for both passed and failed preflights."""
    records = [item.to_dict() for item in observations]
    status = "passed"
    failure = failure_reason
    if failure is None:
        try:
            assert_preflight(observations)
        except PreflightFailure as error:
            status = "failed"
            failure = str(error)
    else:
        status = "failed"
    records.append(
        {
            "schema_version": "1.0",
            "record_type": "paired_preflight_summary",
            "scored": False,
            "status": status,
            "source_commit": source_commit,
            "image_digest": image_digest,
            "qualification_contract_digests": dict(sorted(contract_digests.items())),
            "failure": failure,
        }
    )
    _atomic_write_jsonl(output, records)
    if failure is not None:
        raise PreflightFailure(failure)


def require_scoring_gate(
    *,
    output: Path,
    preflight_ledger: Path,
    candidate_source_commit: str,
    candidate_image_digest: str,
    contract_digest: str,
    arm: Literal["direct", "proxy"],
) -> None:
    """Prohibit scored writes unless a matching paired preflight and immutable provenance exist."""
    if output.exists() and output.stat().st_size:
        raise SystemExit("refusing to append scored output; start a new output after preflight")
    summary = _ledger_summary(preflight_ledger)
    if (
        summary is None
        or summary.get("status") != "passed"
        or summary.get("source_commit") != candidate_source_commit
        or summary.get("image_digest") != candidate_image_digest
    ):
        raise SystemExit("scored mode requires a successful paired preflight ledger with matching provenance")
    if (summary.get("qualification_contract_digests") or {}).get(arm) != contract_digest:
        raise SystemExit("scored mode qualification contract does not match the paired preflight")
    require_candidate_provenance(candidate_source_commit, candidate_image_digest)


def require_candidate_provenance(candidate_source_commit: str, candidate_image_digest: str) -> None:
    """Require the local merged source and immutable image declared for the window."""
    if not _IMAGE_DIGEST.fullmatch(candidate_image_digest):
        raise SystemExit("--candidate-image-digest must be an immutable sha256 digest")
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required to verify --candidate-source-commit")
    current_commit = subprocess.run(  # noqa: S603 - resolved executable and fixed Git arguments
        [git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if candidate_source_commit != current_commit:
        raise SystemExit("--candidate-source-commit must exactly match the checked-out merged source")


def terminal_schema_valid(response: JsonObject, response_format: JsonObject | None) -> bool:
    """Validate the narrow strict primitive terminal schema required by the runner."""
    if response_format is None:
        return True
    schema = ((response_format.get("json_schema") or {}).get("schema"))
    if not isinstance(schema, dict):
        return False
    content = response.get("content")
    if not isinstance(content, str):
        return False
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return False
    if not isinstance(value, dict) or schema.get("additionalProperties") is not False:
        return False
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list) or set(value) != set(required):
        return False
    for key in required:
        property_schema = properties.get(key)
        if not isinstance(key, str) or not isinstance(property_schema, dict):
            return False
        if not _matches_primitive(value.get(key), property_schema.get("type")):
            return False
    return True


def _ledger_summary(path: Path) -> dict[str, Any] | None:
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError):
        return None
    return next(
        (row for row in reversed(rows) if row.get("record_type") == "paired_preflight_summary"), None
    )


def _atomic_write_jsonl(output: Path, records: list[dict[str, Any]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write("".join(_canonical(record) + "\n" for record in records))
    os.replace(temporary, output)


def _matches_primitive(value: Any, expected: Any) -> bool:
    return (
        (expected == "string" and isinstance(value, str))
        or (expected == "boolean" and isinstance(value, bool))
        or (expected == "integer" and isinstance(value, int) and not isinstance(value, bool))
        or (expected == "number" and isinstance(value, int | float) and not isinstance(value, bool))
    )


def _thinking_enabled(value: Any) -> bool | None:
    return value.get("enabled") if isinstance(value, dict) and isinstance(value.get("enabled"), bool) else None


def _safe_policy(value: Any) -> str | bool | int | float | None:
    return value if value is None or isinstance(value, str | bool | int | float) else None


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
