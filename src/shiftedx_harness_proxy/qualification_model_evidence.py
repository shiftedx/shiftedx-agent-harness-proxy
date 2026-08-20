"""Fail-closed, hash-only identity and cache evidence for a local MTPLX server.

This module deliberately does not launch, stop, prime, or otherwise mutate a
model server.  A caller gives it a pinned private contract and the safe,
server-authored accounting records produced by its own requests.  The module
then proves that those records came from one quiescent, locally-owned MTPLX
instance and writes a single immutable, privacy-safe artifact.

The public surface is intentionally small: construct :class:`ModelEvidenceContract`,
call :meth:`ModelEvidenceSession.begin`, then call ``complete`` exactly once.
``ModelEvidenceProbe`` is the sole production/test seam; it must read only the
three documented safe model endpoints and process/listener metadata.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, TypeAlias, cast
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

EvidenceStage: TypeAlias = Literal["preflight", "score-direct", "score-proxy"]
CacheLane: TypeAlias = Literal["preflight", "cold", "warm-prefix"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_HTTP_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9\-._~+/=]{1,8192}$")
_FAILURE_CATEGORY = re.compile(r"^[a-z0-9_]+$")
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_ATTEMPT_KEYS = frozenset(
    {
        "request_digest",
        "status",
        "prompt_tokens",
        "cached_tokens",
        "new_prefill_tokens",
        "cache_source",
        "ssd_cache_hit",
        "ssd_cached_tokens",
        "session_cache_hit",
        "request_session_bank_bypass",
        "postcommit_stored",
    }
)
_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "stage",
        "status",
        "failure_category",
        "run_manifest_sha256",
        "model_identity_sha256",
        "model_contract_sha256",
        "runtime_instance_sha256",
        "live_before_sha256",
        "live_after_sha256",
        "request_window",
        "prime",
        "first_attempt",
        "checks",
    }
)
_CHECK_KEYS = ("contract", "live_before", "attempts", "request_window", "live_after")
_HEALTH_KEYS = frozenset(
    {
        "status",
        "startup_pid",
        "started_at",
        "instance_id",
        "active_requests",
        "foreground_requests",
        "requests_completed",
    }
)
_PROCESS_KEYS = frozenset(
    {
        "pid",
        "start_time",
        "executable_sha256",
        "command_sha256",
        "mtplx_distribution_sha256",
        "command_flags",
    }
)
_MTPLX_SETTINGS_KEYS = frozenset(
    {
        "ok",
        "reasoning",
        "enable_thinking",
        "preserve_thinking",
        "preserve_thinking_effective",
        "reasoning_history_mode",
        "reasoning_parser",
        "reasoning_effort",
        "generation_mode",
        "depth",
        "depth_max",
        "backend_id",
        "architecture_id",
        "model_family",
        "support_level",
        "model_controls",
        "reasoning_policy",
        "kv_quant_policy",
        "tune_policy",
        "context_window_policy",
        "sampling_defaults",
        "temperature",
        "top_p",
        "top_k",
        "presence_penalty",
        "frequency_penalty",
        "max_response_tokens",
        "stream_interval",
        "draft_control",
        "draft_temperature",
        "draft_top_p",
        "draft_top_k",
        "prefill_chunk_tokens",
        "api_key_required",
        "api_key_source",
        "tool_prompt_mode",
        "tool_contract_active",
        "tool_contract_policy_version",
        "chat_template_profile",
        "chat_template_hash",
        "metal_memory_caps",
        "ssd_session_cache",
        "ssd_session_cache_max_size",
        "ssd_session_cache_min_prefix_tokens",
        "paged_kv_quantization",
        "restart_required_settings",
        "ram_session_cache_policy",
        "ram_session_block_prefix_restore",
        "ram_session_cache_max_entries",
        "ram_session_cache_max_size",
        "ram_session_cache_per_session_max_size",
    }
)
_MODEL_CONTROLS_SAFE_KEYS = frozenset(
    {
        "reasoning",
        "thinking",
        "enable_thinking",
        "preserve_thinking",
        "generation_mode",
        "depth",
        "temperature",
        "top_p",
        "top_k",
        "tool_prompt_mode",
        "tool_contract_active",
        "supports_tools",
        "supports_thinking",
        "context_window",
    }
)
_SENSITIVE_SETTING_KEY = re.compile(r"(?:^model$|path|directory|(?:^|_)dir$|error|diagnostic|hardware|serial)")
_SENSITIVE_LAUNCH_MATERIAL = re.compile(
    r"(?:api[_-]?key|token|password|secret|credential|authorization|bearer)", re.IGNORECASE
)
_NUMERIC_TOKEN_LAUNCH_KEYS = frozenset(
    {
        "--max-response-tokens",
        "--max-tokens",
        "--prefill-chunk-tokens",
        "--ssd-session-cache-min-prefix-tokens",
        "--warmup-tokens",
    }
)
_READ_ONLY_COMMAND_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin",
    "LANG": "C",
    "LC_ALL": "C",
}
_HTTP_RESPONSE_MAX_BYTES = 1 << 20


class ModelEvidenceFailure(RuntimeError):
    """A stable failure category which never contains private data."""

    def __init__(self, category: str) -> None:
        safe_category = category if _FAILURE_CATEGORY.fullmatch(category) else "model_evidence_internal"
        super().__init__(safe_category)
        self.category = safe_category


@dataclass(frozen=True)
class ModelEvidenceContract:
    """Private, pinned model identity expected by one qualification stage.

    Paths stay in this in-memory contract.  The emitted evidence contains only
    canonical hashes derived from them, never a path, endpoint, model ID, or
    launch vector.
    """

    public_model_id: str
    stage_path: Path
    stage_revision: str
    identity_ledger: Path
    identity_ledger_sha256: str
    inspect_artifact: Path
    inspect_artifact_sha256: str
    runtime_executable: Path
    runtime_executable_sha256: str
    mtplx_distribution_root: Path
    mtplx_record: Path
    mtplx_version: str
    launch_command_sha256: str
    required_launch_flags: tuple[str, ...]
    host: str
    port: int
    health_contract_sha256: str
    settings_contract_sha256: str
    cache_lane: CacheLane


@dataclass(frozen=True)
class SafeAttemptRecord:
    """The exact safe accounting input accepted from the paired runner.

    It intentionally has no request body, response text, tool content,
    credential, endpoint, or local path field.  C2 can adapt its own typed row
    to this value without teaching the runner about server identity mechanics.
    """

    request_digest: str
    status: str
    prompt_tokens: int
    cached_tokens: int
    new_prefill_tokens: int
    cache_source: str
    ssd_cache_hit: bool
    ssd_cached_tokens: int
    session_cache_hit: bool
    request_session_bank_bypass: bool
    postcommit_stored: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SafeAttemptRecord:
        if set(value) != _ATTEMPT_KEYS:
            raise ModelEvidenceFailure("model_attempt_invalid")
        try:
            return cls(
                request_digest=cast(str, value["request_digest"]),
                status=cast(str, value["status"]),
                prompt_tokens=cast(int, value["prompt_tokens"]),
                cached_tokens=cast(int, value["cached_tokens"]),
                new_prefill_tokens=cast(int, value["new_prefill_tokens"]),
                cache_source=cast(str, value["cache_source"]),
                ssd_cache_hit=cast(bool, value["ssd_cache_hit"]),
                ssd_cached_tokens=cast(int, value["ssd_cached_tokens"]),
                session_cache_hit=cast(bool, value["session_cache_hit"]),
                request_session_bank_bypass=cast(bool, value["request_session_bank_bypass"]),
                postcommit_stored=cast(bool, value["postcommit_stored"]),
            )
        except (KeyError, TypeError):
            raise ModelEvidenceFailure("model_attempt_invalid") from None

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "request_digest": self.request_digest,
            "status": self.status,
            "prompt_tokens": self.prompt_tokens,
            "cached_tokens": self.cached_tokens,
            "new_prefill_tokens": self.new_prefill_tokens,
            "cache_source": self.cache_source,
            "ssd_cache_hit": self.ssd_cache_hit,
            "ssd_cached_tokens": self.ssd_cached_tokens,
            "session_cache_hit": self.session_cache_hit,
            "request_session_bank_bypass": self.request_session_bank_bypass,
            "postcommit_stored": self.postcommit_stored,
        }


@dataclass(frozen=True)
class ProbeSnapshot:
    """One read-only model/process snapshot supplied by a probe implementation."""

    health: Mapping[str, Any]
    models: Mapping[str, Any]
    settings: Mapping[str, Any]
    listener_owners: tuple[Mapping[str, Any], ...]


class ModelEvidenceProbe(Protocol):
    """The sole external seam used by the deep evidence session."""

    def snapshot(
        self,
        *,
        host: str,
        port: int,
        api_key: str | None,
        contract: ModelEvidenceContract,
    ) -> ProbeSnapshot: ...


@dataclass(frozen=True)
class ModelEvidenceResult:
    """Hash-only identity of a completed immutable evidence artifact."""

    path: Path
    file_sha256: str
    status: Literal["passed", "failed"]


def model_endpoint_contract_hashes(health: Mapping[str, Any], settings: Mapping[str, Any]) -> tuple[str, str]:
    """Return reproducible hashes of the exact safe MTPLX endpoint projections.

    This narrow helper is the manifest-freezing seam: callers may pass raw
    endpoint objects, but only two hashes leave it.  The dynamic startup and
    request counters are validated by the live session instead of becoming
    part of the health contract hash.
    """

    projected_health = _project_mtplx_health(health)
    projected_settings = _project_mtplx_settings(settings)
    return _canonical_sha256({"status": projected_health["status"]}), _canonical_sha256(projected_settings)


@dataclass(frozen=True)
class _ValidatedContract:
    contract_sha256: str
    identity_sha256: str
    distribution_sha256: str


@dataclass(frozen=True)
class _LiveIdentity:
    live_sha256: str
    stable_sha256: str
    runtime_instance_sha256: str
    requests_completed: int


class ModelEvidenceSession:
    """One immutable before/action-accounting/after model evidence transaction."""

    def __init__(
        self,
        *,
        contract: ModelEvidenceContract,
        stage: EvidenceStage,
        run_manifest_sha256: str,
        evidence_path: Path,
        credential_file: Path | None,
        probe: ModelEvidenceProbe,
        validated_contract: _ValidatedContract,
        api_key: str | None,
        before: _LiveIdentity,
    ) -> None:
        self._contract = contract
        self._stage = stage
        self._manifest_sha256 = run_manifest_sha256
        self._evidence_path = evidence_path
        self._credential_file = credential_file
        self._probe = probe
        self._validated_contract = validated_contract
        self._api_key = api_key
        self._before = before
        self._completed = False

    @property
    def model_contract_sha256(self) -> str:
        """Return the validated private-contract digest without exposing contract fields."""

        return self._validated_contract.contract_sha256

    @property
    def model_identity_sha256(self) -> str:
        """Return the cross-lane model identity digest without private fields."""

        return self._validated_contract.identity_sha256

    @property
    def runtime_instance_sha256(self) -> str:
        """Return the before-probe local instance digest without exposing process identity."""

        return self._before.runtime_instance_sha256

    @classmethod
    def begin(
        cls,
        contract: ModelEvidenceContract,
        *,
        stage: EvidenceStage,
        run_manifest_sha256: str,
        evidence_path: Path,
        credential_file: Path | None,
        probe: ModelEvidenceProbe | None = None,
    ) -> ModelEvidenceSession:
        """Validate the private contract and capture the immutable before state.

        The no-clobber target is rejected before any model request.  A failed
        ``begin`` has no after-state, so it deliberately writes no partial
        artifact; ``complete`` always attempts its after probe and writes a
        categorical failed artifact for post-action failures.
        """

        if (
            not isinstance(contract, ModelEvidenceContract)
            or not isinstance(evidence_path, Path)
            or credential_file is not None
            and not isinstance(credential_file, Path)
        ):
            raise ModelEvidenceFailure("model_contract_invalid")
        if evidence_path.exists() or evidence_path.is_symlink():
            raise ModelEvidenceFailure("model_evidence_exists")
        _validate_evidence_parent(evidence_path)
        if (
            not isinstance(stage, str)
            or stage not in {"preflight", "score-direct", "score-proxy"}
            or not isinstance(run_manifest_sha256, str)
            or _SHA256.fullmatch(run_manifest_sha256) is None
        ):
            raise ModelEvidenceFailure("model_contract_invalid")
        validated = _validate_contract(contract)
        api_key = _read_credential(credential_file) if credential_file is not None else None
        active_probe = probe or SystemModelEvidenceProbe()
        before = _probe_live(active_probe, contract, api_key, validated)
        if contract.cache_lane in {"cold", "warm-prefix"} and before.requests_completed != 0:
            raise ModelEvidenceFailure("model_cache_instance_not_fresh")
        return cls(
            contract=contract,
            stage=stage,
            run_manifest_sha256=run_manifest_sha256,
            evidence_path=evidence_path,
            credential_file=credential_file,
            probe=active_probe,
            validated_contract=validated,
            api_key=api_key,
            before=before,
        )

    def complete(
        self,
        attempt_records: Sequence[SafeAttemptRecord | Mapping[str, Any]],
        *,
        prime_record: SafeAttemptRecord | Mapping[str, Any] | None = None,
    ) -> ModelEvidenceResult:
        """Validate accounting and persist exactly one post-probe evidence record."""

        if self._completed:
            raise ModelEvidenceFailure("model_evidence_complete_once")
        self._completed = True
        attempts: tuple[SafeAttemptRecord, ...] = ()
        prime: SafeAttemptRecord | None = None
        expected_delta: int | None = None
        failure: ModelEvidenceFailure | None = None
        checks = {key: True for key in _CHECK_KEYS}
        try:
            attempts = _coerce_attempts(attempt_records)
            prime = _coerce_optional_attempt(prime_record)
            expected_delta = _validate_cache_invariants(self._contract.cache_lane, attempts, prime)
        except ModelEvidenceFailure as error:
            failure = error
            checks["attempts"] = False
            checks["request_window"] = False

        # Re-read the file without following it before the after probe.  This
        # detects a credential swap while never retaining it in an artifact.
        try:
            if self._credential_file is not None:
                refreshed_key = _read_credential(self._credential_file)
                if refreshed_key != self._api_key:
                    raise ModelEvidenceFailure("model_credential_invalid")
        except ModelEvidenceFailure as error:
            if failure is None:
                failure = error
            checks["live_after"] = False

        after: _LiveIdentity | None = None
        try:
            after = _probe_live(self._probe, self._contract, self._api_key, self._validated_contract)
            if after.stable_sha256 != self._before.stable_sha256:
                raise ModelEvidenceFailure("model_live_drift")
            request_delta = after.requests_completed - self._before.requests_completed
            if expected_delta is not None and request_delta != expected_delta:
                raise ModelEvidenceFailure("model_request_window_invalid")
        except ModelEvidenceFailure as error:
            if failure is None:
                failure = error
            if error.category == "model_request_window_invalid":
                checks["request_window"] = False
            else:
                checks["live_after"] = False

        if failure is not None:
            record = _evidence_record(
                stage=self._stage,
                status="failed",
                failure_category=failure.category,
                manifest_sha256=self._manifest_sha256,
                identity_sha256=self._validated_contract.identity_sha256,
                contract_sha256=self._validated_contract.contract_sha256,
                before=self._before,
                after=after,
                attempts=attempts,
                prime=prime,
                expected_delta=expected_delta,
                checks=checks,
            )
            _atomic_write_no_clobber(self._evidence_path, record)
            raise failure

        assert after is not None
        record = _evidence_record(
            stage=self._stage,
            status="passed",
            failure_category=None,
            manifest_sha256=self._manifest_sha256,
            identity_sha256=self._validated_contract.identity_sha256,
            contract_sha256=self._validated_contract.contract_sha256,
            before=self._before,
            after=after,
            attempts=attempts,
            prime=prime,
            expected_delta=expected_delta,
            checks=checks,
        )
        _atomic_write_no_clobber(self._evidence_path, record)
        return ModelEvidenceResult(
            path=self._evidence_path,
            file_sha256=hashlib.sha256(_read_private_file(self._evidence_path)).hexdigest(),
            status="passed",
        )


class ModelEvidenceCommandRunner(Protocol):
    """Read-only command seam for listener/process inspection."""

    def __call__(self, argv: tuple[str, ...], *, env: Mapping[str, str]) -> tuple[int, str]: ...


class SystemModelEvidenceProbe:
    """Production read-only probe for a local loopback MTPLX process.

    It makes only GET requests to the three approved paths.  Its command seam
    never surfaces command output in an exception or evidence artifact.
    """

    def __init__(
        self,
        *,
        http_get: Callable[[str, Mapping[str, str]], Mapping[str, Any]] | None = None,
        command_runner: ModelEvidenceCommandRunner | None = None,
    ) -> None:
        self._http_get = http_get or _http_get_json
        self._command_runner = command_runner or _run_read_only_command

    def snapshot(
        self,
        *,
        host: str,
        port: int,
        api_key: str | None,
        contract: ModelEvidenceContract,
    ) -> ProbeSnapshot:
        base = f"http://{_url_host(host)}:{port}"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key is not None else {}
        try:
            health = _project_mtplx_health(self._http_get(f"{base}/health", headers))
            models = _project_mtplx_models(self._http_get(f"{base}/v1/models", headers), contract.public_model_id)
            settings = _project_mtplx_settings(self._http_get(f"{base}/v1/mtplx/settings", headers))
            owners = self._listener_owners(host, port, contract)
        except ModelEvidenceFailure:
            raise
        except Exception:
            raise ModelEvidenceFailure("model_probe_failed") from None
        return ProbeSnapshot(health=health, models=models, settings=settings, listener_owners=owners)

    def _listener_owners(self, host: str, port: int, contract: ModelEvidenceContract) -> tuple[Mapping[str, Any], ...]:
        # lsof reports PIDs only; health.startup_pid is joined to the sole PID
        # later by _validate_live_snapshot.  This prevents an unrelated ready
        # listener from being mistaken for the qualified model.
        status, listed = self._command_runner(
            ("/usr/sbin/lsof", "-nP", f"-iTCP@{host}:{port}", "-sTCP:LISTEN", "-Fp"),
            env=_READ_ONLY_COMMAND_ENV,
        )
        if status != 0:
            raise ModelEvidenceFailure("model_listener_invalid")
        pids = tuple(int(line[1:]) for line in listed.splitlines() if line.startswith("p") and line[1:].isdigit())
        if len(pids) != 1:
            raise ModelEvidenceFailure("model_listener_invalid")
        pid = pids[0]
        command = _command_output(self._command_runner, ("/bin/ps", "-ww", "-p", str(pid), "-o", "command="))
        executable = _command_output(self._command_runner, ("/bin/ps", "-p", str(pid), "-o", "comm="))
        start_time = _command_output(self._command_runner, ("/bin/ps", "-p", str(pid), "-o", "lstart="))
        try:
            argv = tuple(shlex.split(command))
            if not argv:
                raise ValueError
            executable_path = Path(executable).resolve(strict=True)
            executable_sha256 = _file_sha256(executable_path)
            expected_executable = contract.runtime_executable.resolve(strict=True)
        except (OSError, ValueError):
            raise ModelEvidenceFailure("model_listener_invalid") from None
        if executable_path != expected_executable:
            raise ModelEvidenceFailure("model_listener_invalid")
        distribution_sha256 = _distribution_aggregate(contract)
        return (
            {
                "pid": pid,
                "start_time": start_time,
                "executable_sha256": executable_sha256,
                "command_sha256": _canonical_sha256(list(argv)),
                "mtplx_distribution_sha256": distribution_sha256,
                "command_flags": _semantic_flags(argv),
            },
        )


def _project_mtplx_health(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce the raw 2.7.1 health object to its safe identity/accounting core."""

    try:
        health = dict(value)
        startup_value = health.get("startup")
        if not isinstance(startup_value, Mapping):
            raise ModelEvidenceFailure("model_live_invalid")
        startup = dict(startup_value)
        pid = startup.get("pid")
        started_at = _normalize_started_at(startup.get("started_at"))
        if (
            health.get("ok") is not True
            or not _positive_int(pid)
            or not _nonnegative_int(health.get("active_requests"))
            or not _nonnegative_int(health.get("foreground_active"))
            or not _nonnegative_int(health.get("requests_completed"))
        ):
            raise ModelEvidenceFailure("model_live_invalid")
        launch_id = startup.get("launch_id")
        if launch_id is None:
            instance_id = _canonical_sha256({"pid": pid, "started_at": started_at})
        elif isinstance(launch_id, str) and _SAFE_TEXT.fullmatch(launch_id) is not None:
            instance_id = _canonical_sha256({"launch_id": launch_id})
        else:
            raise ModelEvidenceFailure("model_live_invalid")
        return {
            "status": "ok",
            "startup_pid": pid,
            "started_at": started_at,
            "instance_id": instance_id,
            "active_requests": health["active_requests"],
            "foreground_requests": health["foreground_active"],
            "requests_completed": health["requests_completed"],
        }
    except ModelEvidenceFailure:
        raise
    except (TypeError, ValueError):
        raise ModelEvidenceFailure("model_live_invalid") from None


def _normalize_started_at(value: Any) -> str:
    if isinstance(value, bool):
        raise ModelEvidenceFailure("model_live_invalid")
    if isinstance(value, str):
        if _SAFE_TEXT.fullmatch(value) is None:
            raise ModelEvidenceFailure("model_live_invalid")
        return value
    if isinstance(value, int | float):
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            raise ModelEvidenceFailure("model_live_invalid") from None
    raise ModelEvidenceFailure("model_live_invalid")


def _project_mtplx_models(value: Mapping[str, Any], public_model_id: str) -> dict[str, Any]:
    """Select exactly the qualified chat model and drop volatile model metadata."""

    try:
        models = dict(value)
        data = models.get("data")
        if models.get("object") != "list" or not isinstance(data, list):
            raise ModelEvidenceFailure("model_live_invalid")
        matches = [
            item
            for item in data
            if isinstance(item, Mapping) and item.get("object") == "model" and item.get("id") == public_model_id
        ]
        if len(matches) != 1:
            raise ModelEvidenceFailure("model_live_invalid")
        return {"data": [{"id": public_model_id}]}
    except ModelEvidenceFailure:
        raise
    except (TypeError, ValueError):
        raise ModelEvidenceFailure("model_live_invalid") from None


def _project_mtplx_settings(value: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze the reviewed 2.7.1 safe settings surface and ignore raw extras."""

    try:
        settings = dict(value)
        if settings.get("ok") is not True or not _MTPLX_SETTINGS_KEYS.issubset(settings):
            raise ModelEvidenceFailure("model_live_invalid")
        projected = {key: settings[key] for key in sorted(_MTPLX_SETTINGS_KEYS)}
        projected["model_controls"] = _project_model_controls(settings["model_controls"])
        if not _safe_mtplx_settings_value(projected):
            raise ModelEvidenceFailure("model_live_invalid")
        return projected
    except ModelEvidenceFailure:
        raise
    except (TypeError, ValueError):
        raise ModelEvidenceFailure("model_live_invalid") from None


def _project_model_controls(value: Any) -> dict[str, Any]:
    """Keep only reviewed non-path controls from MTPLX's mixed control object."""

    if not isinstance(value, Mapping):
        raise ModelEvidenceFailure("model_live_invalid")
    projected = {key: value[key] for key in sorted(_MODEL_CONTROLS_SAFE_KEYS & set(value))}
    if not _safe_mtplx_settings_value(projected):
        raise ModelEvidenceFailure("model_live_invalid")
    return projected


def _safe_mtplx_settings_value(value: Any, *, depth: int = 0) -> bool:
    if depth > 16:
        return False
    if value is None or isinstance(value, bool | int):
        return True
    if isinstance(value, float):
        return value == value and value not in {float("inf"), float("-inf")}
    if isinstance(value, str):
        return _SAFE_TEXT.fullmatch(value) is not None and not value.startswith(("/", "~/", "file://"))
    if isinstance(value, list):
        return len(value) <= 128 and all(_safe_mtplx_settings_value(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return (
            len(value) <= 128
            and all(
                isinstance(key, str)
                and _SAFE_TEXT.fullmatch(key) is not None
                and _SENSITIVE_SETTING_KEY.search(key) is None
                for key in value
            )
            and all(_safe_mtplx_settings_value(item, depth=depth + 1) for item in value.values())
        )
    return False


def _validate_contract(contract: ModelEvidenceContract) -> _ValidatedContract:
    try:
        if (
            not isinstance(contract.public_model_id, str)
            or _SAFE_TEXT.fullmatch(contract.public_model_id) is None
            or not _absolute_directory(contract.stage_path)
            or _REVISION.fullmatch(contract.stage_revision) is None
            or contract.mtplx_version != "2.7.1"
            or _SHA256.fullmatch(contract.identity_ledger_sha256) is None
            or _SHA256.fullmatch(contract.inspect_artifact_sha256) is None
            or _SHA256.fullmatch(contract.runtime_executable_sha256) is None
            or _SHA256.fullmatch(contract.launch_command_sha256) is None
            or _SHA256.fullmatch(contract.health_contract_sha256) is None
            or _SHA256.fullmatch(contract.settings_contract_sha256) is None
            or contract.cache_lane not in {"preflight", "cold", "warm-prefix"}
            or not _is_loopback_host(contract.host)
            or not _positive_port(contract.port)
        ):
            raise ModelEvidenceFailure("model_contract_invalid")
        _validate_private_artifact(contract.identity_ledger, contract.identity_ledger_sha256)
        _validate_private_artifact(contract.inspect_artifact, contract.inspect_artifact_sha256)
        _validate_runtime_executable(contract.runtime_executable, contract.runtime_executable_sha256)
        _validate_launch_semantics(contract)
        distribution_sha256 = _distribution_aggregate(contract)
        safe_identity = {
            "public_model_id_sha256": _canonical_sha256(contract.public_model_id),
            "stage_path_sha256": _canonical_sha256(str(contract.stage_path)),
            "stage_revision": contract.stage_revision,
            "identity_ledger_sha256": contract.identity_ledger_sha256,
            "inspect_artifact_sha256": contract.inspect_artifact_sha256,
            "runtime_executable_sha256": contract.runtime_executable_sha256,
            "mtplx_distribution_sha256": distribution_sha256,
            "mtplx_version": contract.mtplx_version,
            "launch_command_sha256": contract.launch_command_sha256,
            "required_launch_flags_sha256": _canonical_sha256(list(contract.required_launch_flags)),
            "host": contract.host,
            "port": contract.port,
            "health_contract_sha256": contract.health_contract_sha256,
            "settings_contract_sha256": contract.settings_contract_sha256,
        }
        safe_contract = {**safe_identity, "cache_lane": contract.cache_lane}
        return _ValidatedContract(
            contract_sha256=_canonical_sha256(safe_contract),
            identity_sha256=_canonical_sha256(safe_identity),
            distribution_sha256=distribution_sha256,
        )
    except ModelEvidenceFailure:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        raise ModelEvidenceFailure("model_contract_invalid") from None


def _absolute_directory(path: Path) -> bool:
    try:
        status = path.lstat()
    except OSError:
        return False
    return path.is_absolute() and not path.is_symlink() and stat.S_ISDIR(status.st_mode)


def _validate_private_artifact(path: Path, expected_sha256: str) -> None:
    serialized = _read_private_file(path)
    if not serialized or _file_sha256_bytes(serialized) != expected_sha256:
        raise ModelEvidenceFailure("model_contract_invalid")


def _validate_runtime_executable(path: Path, expected_sha256: str) -> None:
    try:
        if not path.is_absolute():
            raise ModelEvidenceFailure("model_contract_invalid")
        if _file_sha256(path, category="model_contract_invalid", require_executable=True) != expected_sha256:
            raise ModelEvidenceFailure("model_contract_invalid")
    except ModelEvidenceFailure:
        raise
    except OSError:
        raise ModelEvidenceFailure("model_contract_invalid") from None


def _validate_launch_semantics(contract: ModelEvidenceContract) -> None:
    flags = contract.required_launch_flags
    if (
        not isinstance(flags, tuple)
        or not flags
        or len(set(flags)) != len(flags)
        or any(
            not isinstance(value, str) or not value.startswith("--") or "\x00" in value or _unsafe_launch_flag(value)
            for value in flags
        )
    ):
        raise ModelEvidenceFailure("model_contract_invalid")
    expected = {
        f"--host={contract.host}",
        f"--port={contract.port}",
        "--ssd-session-cache=off",
    }
    if not expected.issubset(set(flags)):
        raise ModelEvidenceFailure("model_contract_invalid")


def _unsafe_launch_flag(value: str) -> bool:
    key, separator, flag_value = value.partition("=")
    if key == "--no-auth":
        return bool(separator)
    if key in _NUMERIC_TOKEN_LAUNCH_KEYS and separator and flag_value.isdigit():
        return False
    if key == "--chat-template-profile" and separator and flag_value == "tokenizer":
        return False
    return (
        key.startswith("--auth")
        or _SENSITIVE_LAUNCH_MATERIAL.search(key) is not None
        or (bool(flag_value) and _SENSITIVE_LAUNCH_MATERIAL.search(flag_value) is not None)
    )


def _distribution_aggregate(contract: ModelEvidenceContract) -> str:
    root = contract.mtplx_distribution_root
    record = contract.mtplx_record
    root_descriptor: int | None = None
    try:
        if not root.is_absolute() or not record.is_relative_to(root):
            raise ModelEvidenceFailure("model_package_invalid")
        record_parts = _record_path_parts(record.relative_to(root).as_posix())
        root_descriptor = _open_directory_nofollow(root, "model_package_invalid")
        record_bytes = _read_distribution_file(root_descriptor, record_parts)
        parsed_rows = list(csv.reader(record_bytes.decode("utf-8").splitlines()))
    except ModelEvidenceFailure:
        raise
    except (OSError, UnicodeDecodeError, csv.Error, ValueError):
        raise ModelEvidenceFailure("model_package_invalid") from None
    try:
        if not parsed_rows:
            raise ModelEvidenceFailure("model_package_invalid")
        verified: list[tuple[str, str]] = []
        ignored_external: list[tuple[str, str, str]] = []
        metadata: list[bytes] = []
        seen: set[str] = set()
        record_relative = PurePosixPath(*record_parts).as_posix()
        for row in parsed_rows:
            if len(row) != 3:
                raise ModelEvidenceFailure("model_package_invalid")
            relative, encoded_digest, byte_count = row
            if not relative or relative in seen:
                raise ModelEvidenceFailure("model_package_invalid")
            seen.add(relative)
            parts = _record_path_parts(relative, allow_console_script=True)
            if _is_console_script_record(parts):
                _validate_record_digest(encoded_digest, byte_count)
                # Standard installed distributions list their console script as
                # ../../../bin/<name>.  It is outside the pinned root: bind its
                # RECORD declaration, but never open it.
                ignored_external.append((relative, encoded_digest, byte_count))
                continue
            if "__pycache__" in parts:
                # Bytecode is intentionally not part of a pinned source aggregate.
                continue
            if relative == record_relative and not encoded_digest and not byte_count:
                continue
            _validate_record_digest(encoded_digest, byte_count)
            expected = _urlsafe_digest(encoded_digest.removeprefix("sha256="))
            actual_bytes = _read_distribution_file(root_descriptor, parts)
            if hashlib.sha256(actual_bytes).digest() != expected or len(actual_bytes) != int(byte_count):
                raise ModelEvidenceFailure("model_package_invalid")
            digest = hashlib.sha256(actual_bytes).hexdigest()
            verified.append((relative, digest))
            if relative.endswith(".dist-info/METADATA"):
                metadata.append(actual_bytes)
        if len(metadata) != 1 or not verified:
            raise ModelEvidenceFailure("model_package_invalid")
        metadata_fields = _metadata_fields(metadata[0].decode("utf-8"))
        if metadata_fields.get("Name") != "mtplx" or metadata_fields.get("Version") != "2.7.1":
            raise ModelEvidenceFailure("model_package_invalid")
        return _canonical_sha256(
            {
                "name": "mtplx",
                "version": "2.7.1",
                "files": sorted(verified),
                "ignored_record_entries": sorted(ignored_external),
            }
        )
    except ModelEvidenceFailure:
        raise
    except (OSError, UnicodeDecodeError, ValueError):
        raise ModelEvidenceFailure("model_package_invalid") from None
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)


def _record_path_parts(relative: str, *, allow_console_script: bool = False) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ModelEvidenceFailure("model_package_invalid")
    path = PurePosixPath(relative)
    parts = path.parts
    if path.is_absolute() or not parts:
        raise ModelEvidenceFailure("model_package_invalid")
    if _is_console_script_record(parts):
        if allow_console_script:
            return parts
        raise ModelEvidenceFailure("model_package_invalid")
    if any(part in {"", ".", ".."} for part in parts):
        raise ModelEvidenceFailure("model_package_invalid")
    return parts


def _is_console_script_record(parts: tuple[str, ...]) -> bool:
    return len(parts) == 5 and parts[:4] == ("..", "..", "..", "bin") and parts[4] not in {"", ".", ".."}


def _validate_record_digest(encoded_digest: str, byte_count: str) -> None:
    if not encoded_digest.startswith("sha256=") or not byte_count.isdigit():
        raise ModelEvidenceFailure("model_package_invalid")
    _urlsafe_digest(encoded_digest.removeprefix("sha256="))


def _open_directory_nofollow(path: Path, category: str) -> int:
    descriptor: int | None = None
    try:
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(status.st_mode):
            raise ModelEvidenceFailure(category)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
            raise ModelEvidenceFailure(category)
        result = descriptor
        descriptor = None
        return result
    except ModelEvidenceFailure:
        raise
    except OSError:
        raise ModelEvidenceFailure(category) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_distribution_file(root_descriptor: int, parts: tuple[str, ...]) -> bytes:
    current = os.dup(root_descriptor)
    try:
        for index, part in enumerate(parts):
            is_last = index == len(parts) - 1
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            if not is_last:
                flags |= getattr(os, "O_DIRECTORY", 0)
            following = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = following
            opened = os.fstat(current)
            if (not is_last and not stat.S_ISDIR(opened.st_mode)) or (is_last and not stat.S_ISREG(opened.st_mode)):
                raise ModelEvidenceFailure("model_package_invalid")
        chunks: list[bytes] = []
        while chunk := os.read(current, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    except ModelEvidenceFailure:
        raise
    except OSError:
        raise ModelEvidenceFailure("model_package_invalid") from None
    finally:
        os.close(current)


def _urlsafe_digest(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ModelEvidenceFailure("model_package_invalid")
    try:
        return base64.urlsafe_b64decode(value + "=")
    except ValueError:
        raise ModelEvidenceFailure("model_package_invalid") from None


def _metadata_fields(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in value.splitlines():
        if not line:
            break
        if ":" not in line:
            raise ModelEvidenceFailure("model_package_invalid")
        key, item = line.split(":", 1)
        if key in result or not item.startswith(" "):
            raise ModelEvidenceFailure("model_package_invalid")
        result[key] = item.strip()
    return result


def _probe_live(
    probe: ModelEvidenceProbe,
    contract: ModelEvidenceContract,
    api_key: str | None,
    validated: _ValidatedContract,
) -> _LiveIdentity:
    try:
        snapshot = probe.snapshot(host=contract.host, port=contract.port, api_key=api_key, contract=contract)
        return _validate_live_snapshot(contract, snapshot, validated.distribution_sha256)
    except ModelEvidenceFailure:
        raise
    except Exception:
        raise ModelEvidenceFailure("model_probe_failed") from None


def _validate_live_snapshot(
    contract: ModelEvidenceContract, snapshot: ProbeSnapshot, expected_distribution_sha256: str
) -> _LiveIdentity:
    health = dict(snapshot.health)
    models = dict(snapshot.models)
    settings = dict(snapshot.settings)
    if set(health) != _HEALTH_KEYS or set(models) != {"data"}:
        raise ModelEvidenceFailure("model_live_invalid")
    if not isinstance(settings, dict) or not _safe_json(settings):
        raise ModelEvidenceFailure("model_live_invalid")
    if (
        not isinstance(health["status"], str)
        or _SAFE_TEXT.fullmatch(health["status"]) is None
        or not _positive_int(health["startup_pid"])
        or not _safe_identity_text(health["started_at"])
        or not _safe_identity_text(health["instance_id"])
        or not _nonnegative_int(health["active_requests"])
        or not _nonnegative_int(health["foreground_requests"])
        or not _nonnegative_int(health["requests_completed"])
        or health["active_requests"] != 0
        or health["foreground_requests"] != 0
    ):
        raise ModelEvidenceFailure("model_live_invalid")
    # Only status is allowed into the public health contract.  Dynamic local
    # identity is bound separately by hashes and never serialized directly.
    if _canonical_sha256({"status": health["status"]}) != contract.health_contract_sha256:
        raise ModelEvidenceFailure("model_live_invalid")
    if _canonical_sha256(settings) != contract.settings_contract_sha256:
        raise ModelEvidenceFailure("model_live_invalid")
    data = models["data"]
    if (
        not isinstance(data, list)
        or len(data) != 1
        or not isinstance(data[0], dict)
        or set(data[0]) != {"id"}
        or data[0].get("id") != contract.public_model_id
    ):
        raise ModelEvidenceFailure("model_live_invalid")
    if len(snapshot.listener_owners) != 1:
        raise ModelEvidenceFailure("model_listener_invalid")
    owner = dict(snapshot.listener_owners[0])
    if set(owner) != _PROCESS_KEYS:
        raise ModelEvidenceFailure("model_listener_invalid")
    if (
        owner["pid"] != health["startup_pid"]
        or not _positive_int(owner["pid"])
        or not _safe_identity_text(owner["start_time"])
        or not all(
            isinstance(owner[name], str) and _SHA256.fullmatch(owner[name])
            for name in (
                "executable_sha256",
                "command_sha256",
                "mtplx_distribution_sha256",
            )
        )
        or owner["executable_sha256"] != contract.runtime_executable_sha256
        or owner["command_sha256"] != contract.launch_command_sha256
        or owner["mtplx_distribution_sha256"] != expected_distribution_sha256
        or not isinstance(owner["command_flags"], tuple)
        or not all(
            isinstance(flag, str) and flag.startswith("--") and "\x00" not in flag for flag in owner["command_flags"]
        )
        or owner["command_flags"] != contract.required_launch_flags
    ):
        raise ModelEvidenceFailure("model_listener_invalid")
    full = {
        "health": health,
        "models": models,
        "settings": settings,
        "listener": owner,
    }
    stable_health = {key: value for key, value in health.items() if key != "requests_completed"}
    stable = {"health": stable_health, "models": models, "settings": settings, "listener": owner}
    runtime = {
        "startup_pid": health["startup_pid"],
        "started_at": health["started_at"],
        "instance_id": health["instance_id"],
        "listener": owner,
    }
    return _LiveIdentity(
        live_sha256=_canonical_sha256(full),
        stable_sha256=_canonical_sha256(stable),
        runtime_instance_sha256=_canonical_sha256(runtime),
        requests_completed=health["requests_completed"],
    )


def _coerce_attempts(value: Sequence[SafeAttemptRecord | Mapping[str, Any]]) -> tuple[SafeAttemptRecord, ...]:
    try:
        if isinstance(value, str | bytes):
            raise ModelEvidenceFailure("model_attempt_invalid")
        records = tuple(_coerce_attempt(item) for item in value)
        for record in records:
            _validate_attempt(record)
        return records
    except ModelEvidenceFailure:
        raise
    except (TypeError, ValueError):
        raise ModelEvidenceFailure("model_attempt_invalid") from None


def _coerce_optional_attempt(
    value: SafeAttemptRecord | Mapping[str, Any] | None,
) -> SafeAttemptRecord | None:
    if value is None:
        return None
    result = _coerce_attempt(value)
    _validate_attempt(result)
    return result


def _coerce_attempt(value: SafeAttemptRecord | Mapping[str, Any]) -> SafeAttemptRecord:
    if isinstance(value, SafeAttemptRecord):
        return value
    if isinstance(value, Mapping):
        return SafeAttemptRecord.from_mapping(value)
    raise ModelEvidenceFailure("model_attempt_invalid")


def _validate_attempt(record: SafeAttemptRecord) -> None:
    if (
        not isinstance(record.request_digest, str)
        or _SHA256.fullmatch(record.request_digest) is None
        or not isinstance(record.status, str)
        or record.status not in {"succeeded", "failed"}
        or not isinstance(record.cache_source, str)
        or record.cache_source not in {"none", "ram", "ssd"}
        or any(
            not _nonnegative_int(value)
            for value in (
                record.prompt_tokens,
                record.cached_tokens,
                record.new_prefill_tokens,
                record.ssd_cached_tokens,
            )
        )
        or any(
            not isinstance(value, bool)
            for value in (
                record.ssd_cache_hit,
                record.session_cache_hit,
                record.request_session_bank_bypass,
                record.postcommit_stored,
            )
        )
    ):
        raise ModelEvidenceFailure("model_attempt_invalid")
    if record.prompt_tokens != record.cached_tokens + record.new_prefill_tokens:
        raise ModelEvidenceFailure("model_attempt_invalid")
    if record.cache_source == "none" and (record.cached_tokens != 0 or record.ssd_cached_tokens != 0):
        raise ModelEvidenceFailure("model_attempt_invalid")
    if record.ssd_cached_tokens > record.cached_tokens:
        raise ModelEvidenceFailure("model_attempt_invalid")
    if record.ssd_cache_hit is False and record.ssd_cached_tokens != 0:
        raise ModelEvidenceFailure("model_attempt_invalid")
    if record.cache_source == "ssd" and (record.ssd_cache_hit is not True or record.ssd_cached_tokens <= 0):
        raise ModelEvidenceFailure("model_attempt_invalid")


def _validate_cache_invariants(
    lane: CacheLane, attempts: tuple[SafeAttemptRecord, ...], prime: SafeAttemptRecord | None
) -> int:
    successful = tuple(item for item in attempts if item.status == "succeeded")
    if lane == "preflight":
        if prime is not None:
            raise ModelEvidenceFailure("model_cache_preflight_invalid")
        for item in successful:
            if (
                item.request_session_bank_bypass is not True
                or item.session_cache_hit is not False
                or item.ssd_cache_hit is not False
                or item.cached_tokens != 0
                or item.new_prefill_tokens != item.prompt_tokens
                or item.cache_source != "none"
                or item.ssd_cached_tokens != 0
                or item.postcommit_stored is True
            ):
                raise ModelEvidenceFailure("model_cache_preflight_invalid")
        return len(successful)
    if lane == "cold":
        if prime is not None:
            raise ModelEvidenceFailure("model_cache_cold_invalid")
        for item in successful:
            if (
                item.request_session_bank_bypass is not True
                or item.session_cache_hit is not False
                or item.ssd_cache_hit is not False
                or item.cached_tokens != 0
                or item.new_prefill_tokens != item.prompt_tokens
                or item.cache_source != "none"
                or item.ssd_cached_tokens != 0
                or item.postcommit_stored is True
            ):
                raise ModelEvidenceFailure("model_cache_cold_invalid")
        return len(successful)
    if lane == "warm-prefix":
        if prime is None or prime.status != "succeeded" or not attempts or attempts[0].status != "succeeded":
            raise ModelEvidenceFailure("model_cache_warm_invalid")
        first = attempts[0]
        if (
            prime.request_session_bank_bypass is not False
            or prime.cache_source != "none"
            or prime.cached_tokens != 0
            or prime.new_prefill_tokens != prime.prompt_tokens
            or prime.ssd_cache_hit is not False
            or prime.ssd_cached_tokens != 0
            or prime.session_cache_hit is not False
            or prime.request_digest != first.request_digest
            or first.cached_tokens <= 0
            or first.cache_source != "ram"
            or first.request_session_bank_bypass is not False
            or first.session_cache_hit is not True
            or first.ssd_cache_hit is not False
            or first.ssd_cached_tokens != 0
        ):
            raise ModelEvidenceFailure("model_cache_warm_invalid")
        return 1 + len(successful)
    raise ModelEvidenceFailure("model_contract_invalid")


def _evidence_record(
    *,
    stage: EvidenceStage,
    status: Literal["passed", "failed"],
    failure_category: str | None,
    manifest_sha256: str,
    identity_sha256: str,
    contract_sha256: str,
    before: _LiveIdentity,
    after: _LiveIdentity | None,
    attempts: tuple[SafeAttemptRecord, ...],
    prime: SafeAttemptRecord | None,
    expected_delta: int | None,
    checks: Mapping[str, bool],
) -> dict[str, Any]:
    first = attempts[0] if attempts else None
    successful = sum(1 for item in attempts if item.status == "succeeded")
    delta = after.requests_completed - before.requests_completed if after is not None else None
    record = {
        "schema_version": "1.0",
        "record_type": "qualification_model_cache_evidence",
        "stage": stage,
        "status": status,
        "failure_category": failure_category,
        "run_manifest_sha256": manifest_sha256,
        "model_identity_sha256": identity_sha256,
        "model_contract_sha256": contract_sha256,
        "runtime_instance_sha256": before.runtime_instance_sha256,
        "live_before_sha256": before.live_sha256,
        "live_after_sha256": after.live_sha256 if after is not None else None,
        "request_window": {
            "before": before.requests_completed,
            "after": after.requests_completed if after is not None else None,
            "delta": delta,
            "expected": expected_delta,
            "successful_measured": successful,
        },
        "prime": {
            "record_sha256": _canonical_sha256(prime.to_safe_dict()) if prime is not None else None,
            "count": 1 if prime is not None else 0,
            "request_digest": prime.request_digest if prime is not None else None,
        },
        "first_attempt": {
            "record_sha256": _canonical_sha256(first.to_safe_dict()) if first is not None else None,
            "status": first.status if first is not None else None,
            "measured_count": len(attempts),
            "successful_count": successful,
            "prompt_tokens": first.prompt_tokens if first is not None else None,
            "cached_tokens": first.cached_tokens if first is not None else None,
            "new_prefill_tokens": first.new_prefill_tokens if first is not None else None,
        },
        "checks": {key: checks[key] for key in _CHECK_KEYS},
    }
    if set(record) != _EVIDENCE_KEYS:
        raise ModelEvidenceFailure("model_evidence_internal")
    return record


def _read_credential(path: Path) -> str:
    descriptor: int | None = None
    try:
        file_status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(file_status.st_mode) or stat.S_IMODE(file_status.st_mode) != 0o600:
            raise ModelEvidenceFailure("model_credential_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened_status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or stat.S_IMODE(opened_status.st_mode) != 0o600
            or (opened_status.st_dev, opened_status.st_ino) != (file_status.st_dev, file_status.st_ino)
        ):
            raise ModelEvidenceFailure("model_credential_invalid")
        value = os.read(descriptor, 8193)
        if len(value) > 8192:
            raise ModelEvidenceFailure("model_credential_invalid")
        decoded = value.decode("ascii")
        if _HTTP_SAFE_TOKEN.fullmatch(decoded) is None:
            raise ModelEvidenceFailure("model_credential_invalid")
        return decoded
    except ModelEvidenceFailure:
        raise
    except (OSError, UnicodeDecodeError):
        raise ModelEvidenceFailure("model_credential_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_private_file(path: Path) -> bytes:
    return _read_regular_file(path, "model_contract_invalid", exact_mode=0o600)


def _read_regular_file(
    path: Path,
    category: str,
    *,
    exact_mode: int | None = None,
    require_executable: bool = False,
) -> bytes:
    descriptor: int | None = None
    try:
        file_status = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(file_status.st_mode)
            or (exact_mode is not None and stat.S_IMODE(file_status.st_mode) != exact_mode)
            or (require_executable and stat.S_IMODE(file_status.st_mode) & 0o111 == 0)
        ):
            raise ModelEvidenceFailure(category)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened_status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or (exact_mode is not None and stat.S_IMODE(opened_status.st_mode) != exact_mode)
            or (require_executable and stat.S_IMODE(opened_status.st_mode) & 0o111 == 0)
            or (opened_status.st_dev, opened_status.st_ino) != (file_status.st_dev, file_status.st_ino)
        ):
            raise ModelEvidenceFailure(category)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    except ModelEvidenceFailure:
        raise
    except OSError:
        raise ModelEvidenceFailure(category) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_evidence_parent(path: Path) -> None:
    if not path.is_absolute():
        raise ModelEvidenceFailure("model_evidence_parent_invalid")
    descriptor: int | None = None
    try:
        parent = path.parent
        status = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o700:
            raise ModelEvidenceFailure("model_evidence_parent_invalid")
        descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino)
        ):
            raise ModelEvidenceFailure("model_evidence_parent_invalid")
    except ModelEvidenceFailure:
        raise
    except OSError:
        raise ModelEvidenceFailure("model_evidence_parent_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_write_no_clobber(path: Path, record: Mapping[str, Any]) -> None:
    _validate_evidence_parent(path)
    if path.exists() or path.is_symlink():
        raise ModelEvidenceFailure("model_evidence_exists")
    payload = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    directory: int | None = None
    temporary: int | None = None
    target: int | None = None
    temporary_name: str | None = None
    try:
        directory = _open_directory_nofollow(path.parent, "model_evidence_parent_invalid")
        # Keep the temporary descriptor open through link+verification.  All
        # names are resolved by the trusted directory fd, never a mutable path.
        for nonce in range(128):
            name = f".{path.name}.{os.getpid()}.{nonce}"
            try:
                temporary = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory,
                )
                temporary_name = name
                break
            except FileExistsError:
                continue
        if temporary is None or temporary_name is None:
            raise ModelEvidenceFailure("model_evidence_write_failed")
        os.fchmod(temporary, 0o600)
        os.write(temporary, payload)
        os.fsync(temporary)
        temporary_status = os.fstat(temporary)
        os.link(temporary_name, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        target = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        target_status = os.fstat(target)
        if (
            not stat.S_ISREG(target_status.st_mode)
            or stat.S_IMODE(target_status.st_mode) != 0o600
            or (target_status.st_dev, target_status.st_ino) != (temporary_status.st_dev, temporary_status.st_ino)
        ):
            raise ModelEvidenceFailure("model_evidence_write_failed")
        target_payload = _read_descriptor(target)
        if hashlib.sha256(target_payload).digest() != hashlib.sha256(payload).digest():
            raise ModelEvidenceFailure("model_evidence_write_failed")
        os.unlink(temporary_name, dir_fd=directory)
        temporary_name = None
        os.fsync(directory)
    except FileExistsError:
        raise ModelEvidenceFailure("model_evidence_exists") from None
    except ModelEvidenceFailure:
        raise
    except OSError:
        raise ModelEvidenceFailure("model_evidence_write_failed") from None
    finally:
        if target is not None:
            os.close(target)
        if temporary is not None:
            os.close(temporary)
        if directory is not None:
            if temporary_name is not None:
                _best_effort_unlink(temporary_name, directory)
            os.close(directory)


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 65536):
        chunks.append(chunk)
    return b"".join(chunks)


def _best_effort_unlink(name: str, directory: int) -> None:
    with suppress(OSError):
        os.unlink(name, dir_fd=directory)


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        return None


def _http_get_json(url: str, headers: Mapping[str, str]) -> Mapping[str, Any]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or not _is_loopback_host(parsed.hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ModelEvidenceFailure("model_probe_failed")
    request = Request(url, headers=dict(headers), method="GET")  # noqa: S310 - validated loopback only
    opener = build_opener(ProxyHandler({}), _RejectRedirect())
    try:
        with opener.open(request, timeout=5.0) as response:  # noqa: S310 - fixed local read paths only
            if response.status != 200 or response.geturl() != url:
                raise ModelEvidenceFailure("model_probe_failed")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and (
                not content_length.isdigit() or int(content_length) > _HTTP_RESPONSE_MAX_BYTES
            ):
                raise ModelEvidenceFailure("model_probe_failed")
            body = response.read(_HTTP_RESPONSE_MAX_BYTES + 1)
            if len(body) > _HTTP_RESPONSE_MAX_BYTES:
                raise ModelEvidenceFailure("model_probe_failed")
            document = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except ModelEvidenceFailure:
        raise
    except Exception:
        raise ModelEvidenceFailure("model_probe_failed") from None
    if not isinstance(document, dict):
        raise ModelEvidenceFailure("model_probe_failed")
    return document


def _run_read_only_command(argv: tuple[str, ...], *, env: Mapping[str, str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed probe vectors only
            list(argv), capture_output=True, text=True, check=False, timeout=5.0, env=dict(env)
        )
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""
    return completed.returncode, completed.stdout


def _command_output(runner: ModelEvidenceCommandRunner, argv: tuple[str, ...]) -> str:
    status, output = runner(argv, env=_READ_ONLY_COMMAND_ENV)
    result = output.strip()
    if status != 0 or not result:
        raise ModelEvidenceFailure("model_listener_invalid")
    return result


def _semantic_flags(argv: tuple[str, ...]) -> tuple[str, ...]:
    flags: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item.startswith("--"):
            if "=" in item:
                flags.append(item)
            elif index + 1 < len(argv) and not argv[index + 1].startswith("--"):
                flags.append(f"{item}={argv[index + 1]}")
                index += 1
            else:
                flags.append(item)
        index += 1
    return tuple(flags)


def _safe_json(value: Any, *, depth: int = 0) -> bool:
    if depth > 16:
        return False
    if value is None or isinstance(value, bool | int | float):
        return not isinstance(value, float) or value == value
    if isinstance(value, str):
        return len(value) <= 512 and "\x00" not in value
    if isinstance(value, list):
        return len(value) <= 128 and all(_safe_json(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return (
            len(value) <= 128
            and all(isinstance(key, str) and _SAFE_TEXT.fullmatch(key) for key in value)
            and all(_safe_json(item, depth=depth + 1) for item in value.values())
        )
    return False


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _safe_identity_text(value: Any) -> bool:
    return isinstance(value, str) and _SAFE_TEXT.fullmatch(value) is not None


def _positive_port(value: Any) -> bool:
    return _positive_int(value) and value <= 65535


def _is_loopback_host(value: Any) -> bool:
    return value in {"127.0.0.1", "::1"}


def _file_sha256(path: Path, *, category: str = "model_listener_invalid", require_executable: bool = False) -> str:
    return _file_sha256_bytes(_read_regular_file(path, category, require_executable=require_executable))


def _file_sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host
