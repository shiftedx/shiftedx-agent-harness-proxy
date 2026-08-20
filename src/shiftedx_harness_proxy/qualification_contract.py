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
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .core import HARNESS_SYSTEM_SUFFIX

JsonObject = dict[str, Any]
Phase = Literal["acquisition", "finalization", "terminal"]

COMPATIBILITY_MODE = "phase_split"
COMPATIBILITY_VERSION = "shiftedx-phase-plan-v1"
BENCHMARK_REVISION = "335e6694e4aec13e9370af8a993d8c8f14d7ffb5"
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_FAILURE_CATEGORY = re.compile(r"^[a-z0-9_]+$")
_SAFE_POLICY_LITERALS = frozenset({"auto", "none", "required", "low", "medium", "high"})


class PreflightFailure(RuntimeError):
    """Raised before the runner is permitted to create a scored row."""


class RuntimeAttestationFailure(PreflightFailure):
    """Raised when qualification runtime evidence is missing or invalid."""


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


@dataclass(frozen=True)
class RuntimeAttestation:
    """Validated, allowlisted identity of one supervised qualification runtime."""

    stage: Literal["preflight", "scored_proxy"]
    source_commit: str
    image_digest: str
    run_manifest_sha256: str
    model_id_sha256: str
    benchmark_revision: str
    scenario_order_sha256: str
    scenario_order_count: int
    runtime_contract_sha256: str
    runtime_instance_sha256: str
    checks: dict[str, bool]
    file_sha256: str


def load_runtime_attestation(
    path: Path,
    *,
    expected_stage: Literal["preflight", "scored_proxy"],
    source_commit: str,
    image_digest: str,
    run_manifest_sha256: str,
    model: str,
    scenario_order: list[str],
) -> RuntimeAttestation:
    """Load runtime evidence and bind it to the exact qualification invocation."""
    try:
        file_status = path.lstat()
        if not stat.S_ISREG(file_status.st_mode) or path.is_symlink():
            raise RuntimeAttestationFailure("runtime_attestation_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RuntimeAttestationFailure("runtime_attestation_invalid")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                serialized = handle.read()
        finally:
            os.close(descriptor)
        document = json.loads(serialized, object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeAttestationFailure("runtime_attestation_invalid") from error
    expected_order_sha256 = _sha256(scenario_order)
    expected_model_sha256 = _sha256(model)
    root_keys = {
        "schema_version",
        "record_type",
        "status",
        "stage",
        "source_commit",
        "image_digest",
        "run_manifest_sha256",
        "model_id_sha256",
        "benchmark_revision",
        "scenario_order",
        "runtime_contract_sha256",
        "runtime_instance_sha256",
        "checks",
    }
    check_keys = {
        "exact_image",
        "settings",
        "resources",
        "bind",
        "observer",
        "ready",
        "secret_roles_distinct",
    }
    checks = document.get("checks") if isinstance(document, dict) else None
    order_identity = document.get("scenario_order") if isinstance(document, dict) else None
    runtime_contract_sha256 = (
        document.get("runtime_contract_sha256") if isinstance(document, dict) else None
    )
    runtime_instance_sha256 = (
        document.get("runtime_instance_sha256") if isinstance(document, dict) else None
    )
    if (
        not isinstance(document, dict)
        or set(document) != root_keys
        or document.get("schema_version") != "1.0"
        or document.get("record_type") != "qualification_runtime_attestation"
        or document.get("status") != "passed"
        or document.get("stage") != expected_stage
        or _SOURCE_COMMIT.fullmatch(source_commit) is None
        or document.get("source_commit") != source_commit
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
        or document.get("image_digest") != image_digest
        or _SHA256_HEX.fullmatch(run_manifest_sha256) is None
        or document.get("run_manifest_sha256") != run_manifest_sha256
        or document.get("model_id_sha256") != expected_model_sha256
        or document.get("benchmark_revision") != BENCHMARK_REVISION
        or not isinstance(order_identity, dict)
        or set(order_identity) != {"sha256", "count"}
        or order_identity.get("sha256") != expected_order_sha256
        or not isinstance(order_identity.get("count"), int)
        or isinstance(order_identity.get("count"), bool)
        or order_identity.get("count") != len(scenario_order)
        or not isinstance(runtime_contract_sha256, str)
        or _SHA256_HEX.fullmatch(runtime_contract_sha256) is None
        or not isinstance(runtime_instance_sha256, str)
        or _SHA256_HEX.fullmatch(runtime_instance_sha256) is None
        or not isinstance(checks, dict)
        or set(checks) != check_keys
        or any(value is not True for value in checks.values())
    ):
        raise RuntimeAttestationFailure("runtime_attestation_invalid")
    return RuntimeAttestation(
        stage=expected_stage,
        source_commit=source_commit,
        image_digest=image_digest,
        run_manifest_sha256=run_manifest_sha256,
        model_id_sha256=expected_model_sha256,
        benchmark_revision=BENCHMARK_REVISION,
        scenario_order_sha256=expected_order_sha256,
        scenario_order_count=len(scenario_order),
        runtime_contract_sha256=runtime_contract_sha256,
        runtime_instance_sha256=runtime_instance_sha256,
        checks=checks,
        file_sha256=hashlib.sha256(serialized).hexdigest(),
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


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
    policy_delta: dict[str, Any],
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
    fields["declared_policy_deltas"] = _observed_harness_policy_delta(payload)
    if scenario_order is not None:
        fields.update(_model_boundary_context(scenario_order))
    return SafeFingerprint("model_facing_observed", _sha256(fields), fields)


def read_model_boundary_observer_ledger(
    path: Path, *, allow_missing: bool = False
) -> tuple[SafeFingerprint, ...]:
    """Read a fresh private observer ledger without admitting payload-bearing fields."""
    try:
        if not path.exists() and allow_missing:
            return ()
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise PreflightFailure("proxy model-boundary observer ledger is unavailable") from error
    expected_keys = set(_model_boundary_field_keys())
    fingerprints: list[SafeFingerprint] = []
    for expected_sequence, row in enumerate(rows, start=1):
        fields = row.get("fields") if isinstance(row, dict) else None
        digest = row.get("digest") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or set(row) != {"record_type", "sequence", "digest", "fields"}
            or row.get("record_type") != "qualification_model_boundary"
            or row.get("sequence") != expected_sequence
            or not isinstance(fields, dict)
            or set(fields) != expected_keys
            or not _safe_model_boundary_fields(fields)
            or not isinstance(digest, str)
            or digest != _sha256(fields)
        ):
            raise PreflightFailure("proxy model-boundary observer ledger is invalid")
        fingerprints.append(SafeFingerprint("model_facing_observed", digest, fields))
    return tuple(fingerprints)


def _safe_model_boundary_fields(fields: dict[str, Any]) -> bool:
    hash_fields = (
        "system_prompt_sha256",
        "base_system_prompt_sha256",
        "model_id_sha256",
        "tool_schema_sha256",
        "terminal_schema_sha256",
    )
    if any(not isinstance(fields[key], str) or not _SHA256_HEX.fullmatch(fields[key]) for key in hash_fields):
        return False
    sampler = fields["sampler"]
    if not isinstance(sampler, dict) or set(sampler) != {"temperature", "top_p", "top_k"}:
        return False
    if any(
        value is not None and (not isinstance(value, int | float) or isinstance(value, bool))
        for value in sampler.values()
    ):
        return False
    reasoning = fields["reasoning"]
    if not isinstance(reasoning, dict) or set(reasoning) != {"thinking_enabled", "effort"}:
        return False
    if reasoning["thinking_enabled"] is not None and not isinstance(reasoning["thinking_enabled"], bool):
        return False
    if not _safe_policy_value(reasoning["effort"]):
        return False
    if not _safe_policy_value(fields["tool_choice_policy"]):
        return False
    token_budget = fields["token_budget"]
    if token_budget is not None and (not isinstance(token_budget, int) or isinstance(token_budget, bool)):
        return False
    policy_delta = fields["declared_policy_deltas"]
    return policy_delta in ({}, _expected_harness_policy_delta(), {"harness_system_suffix_sha256": "invalid"})


def _safe_policy_value(value: Any) -> bool:
    return value is None or isinstance(value, bool | int | float) or (
        isinstance(value, str) and value in _SAFE_POLICY_LITERALS
    ) or (
        isinstance(value, dict)
        and set(value) == {"sha256"}
        and isinstance(value.get("sha256"), str)
        and _SHA256_HEX.fullmatch(value["sha256"]) is not None
    )


@dataclass
class ModelBoundaryObserverCursor:
    """Consume a fresh observer ledger in proxy-turn order without retaining payloads."""

    path: Path
    scenario_order: list[str]
    _cursor: int = 0
    _turns: list[tuple[SafeFingerprint, ...]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.path.exists() and self.path.stat().st_size:
            raise PreflightFailure("proxy model-boundary observer ledger is not fresh")

    @property
    def turns(self) -> tuple[tuple[SafeFingerprint, ...], ...]:
        return tuple(self._turns)

    def begin_turn(self) -> None:
        """Reject records not consumed by the preceding proxy turn."""
        observed = read_model_boundary_observer_ledger(self.path, allow_missing=True)
        if len(observed) != self._cursor:
            raise PreflightFailure("proxy model-boundary observer ledger has stale or missing records")

    def consume_turn(self, *, require_records: bool) -> tuple[SafeFingerprint, ...]:
        """Return exactly the records written during the current proxy turn."""
        observed = read_model_boundary_observer_ledger(self.path, allow_missing=True)
        if len(observed) < self._cursor:
            raise PreflightFailure("proxy model-boundary observer ledger was truncated")
        records = observed[self._cursor :]
        if require_records and not records:
            raise PreflightFailure("proxy model-boundary observer record count differed")
        self._cursor = len(observed)
        bound = bind_model_boundary_context(records, self.scenario_order)
        self._turns.append(bound)
        return bound

    def require_drained(self) -> None:
        """Reject observer records that appeared outside the runner's ordered turn sequence."""
        observed = read_model_boundary_observer_ledger(self.path, allow_missing=True)
        if len(observed) != self._cursor:
            raise PreflightFailure("proxy model-boundary observer ledger has unconsumed records")


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
    system_prompt = _system_prompt(payload)
    return {
        "system_prompt_sha256": _sha256(system_prompt),
        "base_system_prompt_sha256": _sha256(_normalized_base_system_prompt(system_prompt)),
        "model_id_sha256": _sha256(payload.get("model")),
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
        "base_system_prompt_sha256",
        "model_id_sha256",
        "tool_schema_sha256",
        "tool_choice_policy",
        "terminal_schema_sha256",
        "sampler",
        "reasoning",
        "token_budget",
        "declared_policy_deltas",
    )


def _system_prompt(payload: JsonObject) -> Any:
    return next(
        (
            message.get("content")
            for message in payload.get("messages", [])
            if isinstance(message, dict) and message.get("role") == "system"
        ),
        None,
    )


def _normalized_base_system_prompt(system_prompt: Any) -> Any:
    if _has_exact_harness_system_suffix(system_prompt):
        assert isinstance(system_prompt, str)
        return system_prompt[: -len(HARNESS_SYSTEM_SUFFIX)]
    return system_prompt


def _has_exact_harness_system_suffix(system_prompt: Any) -> bool:
    return (
        isinstance(system_prompt, str)
        and system_prompt.endswith(HARNESS_SYSTEM_SUFFIX)
        and system_prompt.count(HARNESS_SYSTEM_SUFFIX) == 1
    )


def _expected_harness_policy_delta() -> dict[str, str]:
    return {"harness_system_suffix_sha256": _sha256(HARNESS_SYSTEM_SUFFIX)}


def _observed_harness_policy_delta(payload: JsonObject) -> dict[str, str]:
    """Declare only the known exact proxy system suffix; all variants are invalid."""
    system_prompt = _system_prompt(payload)
    if _has_exact_harness_system_suffix(system_prompt):
        return _expected_harness_policy_delta()
    if isinstance(system_prompt, str) and HARNESS_SYSTEM_SUFFIX in system_prompt:
        return {"harness_system_suffix_sha256": "invalid"}
    return {}


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
    policy_delta: dict[str, Any],
    run_manifest_sha256: str,
) -> str:
    """Bind a scored invocation to every selected scenario's safe contract."""
    planner = PhasePlanner()
    validate_run_manifest_sha256(run_manifest_sha256)
    return _sha256(
        {
            "compatibility": {"mode": planner.mode, "version": planner.version},
            "benchmark_revision": BENCHMARK_REVISION,
            "scenario_order": {"sha256": _sha256(scenario_order), "count": len(scenario_order)},
            "run_manifest_sha256": run_manifest_sha256,
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
    policy_delta: dict[str, Any],
    planner: PhasePlanner,
    phase: Phase | None,
) -> SafeFingerprint:
    """Create an allowlisted representation, hashing all request-derived content."""
    fields: dict[str, Any] = {
        **_model_boundary_fields(payload),
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
    allowed_harness_system_delta = _is_allowed_harness_system_delta_pair(left, right)
    keys = sorted(set(left.fields) | set(right.fields))
    mismatches: list[str] = []
    for key in keys:
        if key == "declared_policy_deltas":
            if (
                left.boundary == "model_facing_observed"
                and left.fields.get(key) != right.fields.get(key)
                and not allowed_harness_system_delta
            ):
                mismatches.append(key)
        elif key == "system_prompt_sha256" and allowed_harness_system_delta:
            continue
        elif left.fields.get(key) != right.fields.get(key):
            mismatches.append(key)
    return mismatches


def _is_allowed_harness_system_delta_pair(left: SafeFingerprint, right: SafeFingerprint) -> bool:
    if left.boundary != "model_facing_observed" or right.boundary != "model_facing_observed":
        return False
    direct_delta: dict[str, str] = {}
    proxy_delta = _expected_harness_policy_delta()
    return (
        left.fields.get("declared_policy_deltas") == direct_delta
        and right.fields.get("declared_policy_deltas") == proxy_delta
    ) or (
        left.fields.get("declared_policy_deltas") == proxy_delta
        and right.fields.get("declared_policy_deltas") == direct_delta
    )


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
        _assert_harness_system_policy(arm, tool.model_facing)
        _assert_harness_system_policy(arm, terminal.model_facing)
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


def _assert_harness_system_policy(
    arm: Literal["direct", "proxy"], fingerprints: tuple[SafeFingerprint, ...]
) -> None:
    """Permit only the proxy's one exact, declared system-suffix mutation."""
    expected = _expected_harness_policy_delta() if arm == "proxy" else {}
    for fingerprint in fingerprints:
        # Legacy synthetic tests may use placeholder planned fingerprints. Real observer records
        # are always marked observed and must carry the explicit policy declaration.
        if fingerprint.boundary != "model_facing_observed":
            continue
        if fingerprint.fields.get("declared_policy_deltas") != expected:
            raise PreflightFailure("proxy harness system policy delta differed")


def write_preflight_ledger(
    output: Path,
    observations: list[PreflightObservation],
    *,
    source_commit: str,
    image_digest: str,
    contract_digests: dict[str, str],
    run_manifest_sha256: str,
    runtime_attestation: RuntimeAttestation | None = None,
    failure_reason: str | None = None,
) -> None:
    """Atomically retain safe evidence for both passed and failed preflights."""
    validate_run_manifest_sha256(run_manifest_sha256)
    records = [item.to_dict() for item in observations]
    status = "passed"
    failure = failure_reason
    raised_failure: str | None = None
    if failure is None:
        try:
            assert_preflight(observations)
        except PreflightFailure as error:
            status = "failed"
            failure = "preflight_contract_validation_failed"
            raised_failure = str(error)
    else:
        status = "failed"
        if not _FAILURE_CATEGORY.fullmatch(failure):
            failure = "preflight_internal_failure"
    records.append(
        {
            "schema_version": "1.0",
            "record_type": "paired_preflight_summary",
            "scored": False,
            "status": status,
            "source_commit": source_commit,
            "image_digest": image_digest,
            "run_manifest_sha256": run_manifest_sha256,
            "qualification_contract_digests": dict(sorted(contract_digests.items())),
            "arm_identity_digests": _arm_identity_digests(observations, run_manifest_sha256),
            "runtime_attestation_sha256": (
                runtime_attestation.file_sha256 if runtime_attestation is not None else None
            ),
            "runtime_contract_sha256": (
                runtime_attestation.runtime_contract_sha256 if runtime_attestation is not None else None
            ),
            "runtime_instance_sha256": (
                runtime_attestation.runtime_instance_sha256 if runtime_attestation is not None else None
            ),
            "failure": failure,
        }
    )
    _atomic_write_jsonl(output, records)
    if failure is not None:
        raise PreflightFailure(raised_failure or failure)


def require_scoring_gate(
    *,
    output: Path,
    preflight_ledger: Path,
    candidate_source_commit: str,
    candidate_image_digest: str,
    contract_digest: str,
    arm: Literal["direct", "proxy"],
    model: str,
    run_manifest_sha256: str,
    scenario_order: list[str] | None = None,
    runtime_attestation: Path | None = None,
) -> None:
    """Prohibit scored writes unless a matching paired preflight and immutable provenance exist."""
    if output.exists():
        raise SystemExit("refusing to append scored output; start a new output after preflight")
    try:
        validate_run_manifest_sha256(run_manifest_sha256)
    except PreflightFailure as error:
        raise SystemExit("--run-manifest-sha256 must be an immutable SHA-256") from error
    summary = _ledger_summary(preflight_ledger)
    if (
        summary is None
        or summary.get("status") != "passed"
        or summary.get("source_commit") != candidate_source_commit
        or summary.get("image_digest") != candidate_image_digest
    ):
        raise SystemExit("scored mode requires a successful paired preflight ledger with matching provenance")
    if summary.get("run_manifest_sha256") != run_manifest_sha256:
        raise SystemExit("scored mode run-manifest identity does not match the paired preflight")
    expected_identity = _identity_digest(_sha256(model), run_manifest_sha256)
    if (summary.get("arm_identity_digests") or {}).get(arm) != expected_identity:
        raise SystemExit("scored mode model identity does not match the paired preflight")
    if (summary.get("qualification_contract_digests") or {}).get(arm) != contract_digest:
        raise SystemExit("scored mode qualification contract does not match the paired preflight")
    try:
        if runtime_attestation is None or scenario_order is None:
            raise RuntimeAttestationFailure("runtime_attestation_invalid")
        attestation = load_runtime_attestation(
            runtime_attestation,
            expected_stage="preflight" if arm == "direct" else "scored_proxy",
            source_commit=candidate_source_commit,
            image_digest=candidate_image_digest,
            run_manifest_sha256=run_manifest_sha256,
            model=model,
            scenario_order=scenario_order,
        )
    except RuntimeAttestationFailure as error:
        raise SystemExit("scored mode requires a valid matching runtime attestation") from error
    if arm == "direct" and (
        summary.get("runtime_attestation_sha256") != attestation.file_sha256
        or summary.get("runtime_contract_sha256") != attestation.runtime_contract_sha256
        or summary.get("runtime_instance_sha256") != attestation.runtime_instance_sha256
    ):
        raise SystemExit("scored mode runtime attestation identity does not match the paired preflight")
    if arm == "proxy":
        if summary.get("runtime_contract_sha256") != attestation.runtime_contract_sha256:
            raise SystemExit("scored proxy runtime contract does not match the paired preflight")
        if summary.get("runtime_instance_sha256") == attestation.runtime_instance_sha256:
            raise SystemExit("scored proxy requires a fresh runtime instance")
    require_candidate_provenance(candidate_source_commit, candidate_image_digest)


def validate_run_manifest_sha256(run_manifest_sha256: str) -> None:
    if not _SHA256_HEX.fullmatch(run_manifest_sha256):
        raise PreflightFailure("run manifest SHA-256 is invalid")


def _arm_identity_digests(
    observations: list[PreflightObservation], run_manifest_sha256: str
) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for arm in ("direct", "proxy"):
        model_hashes = {
            fingerprint.fields.get("model_id_sha256")
            for observation in observations
            if observation.arm == arm
            for fingerprint in observation.model_facing
            if fingerprint.boundary == "model_facing_observed"
            and isinstance(fingerprint.fields.get("model_id_sha256"), str)
        }
        if len(model_hashes) != 1:
            result[arm] = None
            continue
        model_hash = next(iter(model_hashes))
        if not isinstance(model_hash, str):
            result[arm] = None
            continue
        result[arm] = _identity_digest(model_hash, run_manifest_sha256)
    return result


def _identity_digest(model_id_sha256: str, run_manifest_sha256: str) -> str:
    return _sha256(
        {
            "model_id_sha256": model_id_sha256,
            "run_manifest_sha256": run_manifest_sha256,
        }
    )


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
    if output.exists():
        raise PreflightFailure("refusing to overwrite an existing preflight ledger")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write("".join(_canonical(record) + "\n" for record in records))
        try:
            # link(2) gives this immutable evidence writer an atomic no-clobber commit.
            os.link(temporary, output)
        except FileExistsError as error:
            raise PreflightFailure("refusing to overwrite an existing preflight ledger") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _matches_primitive(value: Any, expected: Any) -> bool:
    return (
        (expected == "string" and isinstance(value, str))
        or (expected == "boolean" and isinstance(value, bool))
        or (expected == "integer" and isinstance(value, int) and not isinstance(value, bool))
        or (expected == "number" and isinstance(value, int | float) and not isinstance(value, bool))
    )


def _thinking_enabled(value: Any) -> bool | None:
    return value.get("enabled") if isinstance(value, dict) and isinstance(value.get("enabled"), bool) else None


def _safe_policy(value: Any) -> str | bool | int | float | dict[str, str] | None:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value if value in _SAFE_POLICY_LITERALS else {"sha256": _sha256(value)}
    return None


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
