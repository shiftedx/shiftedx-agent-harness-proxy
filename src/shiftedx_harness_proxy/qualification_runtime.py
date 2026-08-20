"""Fail-closed private runtime supervision for paired qualification.

The public interface is deliberately small: a frozen manifest, a stage, a
private run directory, and an action which receives only a :class:`RuntimeLease`.
Docker, observer-process, secret-volume, and cleanup mechanics remain inside
this module so a benchmark caller cannot accidentally substitute a ready but
unapproved proxy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import FrameType
from typing import Any, Literal, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from pydantic import SecretStr

from .config import Settings
from .core import HARNESS_PROFILE
from .qualification_campaign import (
    CampaignSlot,
    ReadinessResult,
    StageInspection,
    StageRequest,
    StageResult,
)
from .qualification_contract import (
    BENCHMARK_REVISION,
    ModelBoundaryRecord,
    PreflightFailure,
    RuntimeOutcomeFailure,
    load_model_evidence,
    load_runtime_outcome,
    read_model_boundary_observer_records,
)
from .qualification_contract import (
    ModelEvidenceFailure as ModelEvidenceArtifactFailure,
)
from .qualification_model_evidence import (
    ModelEvidenceContract,
    ModelEvidenceSession,
    SafeAttemptRecord,
    SystemModelEvidenceProbe,
)
from .qualification_model_evidence import (
    ModelEvidenceFailure as ModelEvidenceSessionFailure,
)
from .qualification_reconciliation import (
    MetricsSnapshot,
    ModelOperationSummary,
    ProxyReconciliationSession,
    ReconciliationContext,
    ReconciliationFailure,
    ReconciliationIdentity,
    read_request_accounting_ledger,
)

RuntimeStage = Literal["preflight", "score-direct", "score-proxy"]
AttestationStage = Literal["preflight", "scored_proxy"]
OutcomeStage = Literal["preflight", "scored-direct", "scored-proxy"]
OutcomeStatus = Literal["passed", "failed", "interrupted"]
CampaignLane = Literal["preflight", "cold", "warm-prefix"]
LoopbackListenerState = Literal["listening", "refused", "indeterminate"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
_FAILURE_CATEGORY = re.compile(r"^[a-z0-9_]+$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HTTP_BEARER_TOKEN = re.compile(r"^[A-Za-z0-9\-._~+/]+={0,}$")
_SETTINGS_KEYS = frozenset(
    {
        "deployment_profile",
        "harness_profile",
        "upstream_tool_response_capability_mode",
        "upstream_cache_capability_mode",
        "telemetry_enabled",
        "metrics_enabled",
        "max_internal_retries",
        "max_upstream_calls",
        "upstream_timeout_seconds",
        "total_request_deadline_seconds",
        "server_connection_limit",
        "admission_limit",
        "principal_concurrency_limit",
        "concurrency_limit",
        "require_receipt_when_tools_present",
        "allow_harness_opt_out",
        "log_level",
    }
)
_SECTION_KEYS = frozenset(
    {
        "schema_version",
        "source_commit",
        "image",
        "model",
        "benchmark",
        "observer",
        "proxy",
        "credentials",
        "campaign",
    }
)
_CHECK_KEYS = (
    "exact_image",
    "settings",
    "resources",
    "bind",
    "observer",
    "ready",
    "secret_roles_distinct",
)
_LABEL_PREFIX = "io.shiftedx.qualification"
_CONTAINER_LISTEN_HOST = "0.0.0.0"  # noqa: S104 - proxy is published only on a loopback host binding
_MAX_HTTP_RESPONSE_BYTES = 1 << 20
# These are trusted locations, not a search path.  The small platform-specific
# allowlist supports the qualification hosts without permitting PATH lookup at
# command execution time.  Tests may replace this mapping with dedicated,
# absolute fixture executables.
if sys.platform == "darwin":
    _FROZEN_HOST_TOOLS: dict[str, tuple[Path, ...]] = {
        "docker": (Path("/usr/local/bin/docker"), Path("/opt/homebrew/bin/docker")),
        "git": (Path("/usr/bin/git"), Path("/opt/homebrew/bin/git"), Path("/usr/local/bin/git")),
    }
elif sys.platform.startswith("linux"):
    _FROZEN_HOST_TOOLS = {
        "docker": (Path("/usr/bin/docker"), Path("/usr/local/bin/docker")),
        "git": (Path("/usr/bin/git"), Path("/usr/local/bin/git")),
    }
else:
    _FROZEN_HOST_TOOLS = {"docker": (), "git": ()}


class QualificationRuntimeFailure(RuntimeError):
    """A categorical, non-sensitive runtime qualification failure."""

    def __init__(self, category: str) -> None:
        if _FAILURE_CATEGORY.fullmatch(category) is None:
            category = "runtime_internal_failure"
        super().__init__(category)
        self.category = category


class _RuntimeInterrupted(BaseException):
    """Internal signal marker; normal cleanup still runs in ``finally``."""


@dataclass
class _InterruptionScope:
    """Own the temporary handlers until cleanup and atomic outcome writing finish."""

    previous: dict[int, Any]
    cleanup_or_outcome: bool = False


@dataclass(frozen=True)
class CommandResult:
    """Captured command status without requiring callers to expose command output."""

    returncode: int
    stdout: str
    stderr: str


class _RejectRedirect(HTTPRedirectHandler):
    """Reject redirects before urllib can replay a bearer credential elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        del msg, newurl
        raise HTTPError(req.full_url, code, "redirect rejected", headers, fp)


def _frozen_host_command(
    argv: tuple[str, ...], *, env: dict[str, str] | None
) -> tuple[tuple[str, ...], dict[str, str] | None] | None:
    """Return a validated absolute Docker/Git vector with no inherited environment."""

    if not argv:
        return None
    requested = argv[0]
    tool_name = requested if requested in _FROZEN_HOST_TOOLS else Path(requested).name
    candidates: tuple[Path, ...] | None = _FROZEN_HOST_TOOLS.get(tool_name)
    if candidates is None:
        return argv, env

    # An explicit Docker/Git path is acceptable only when it is one of the
    # frozen locations.  This rejects an attacker-controlled absolute path as
    # well as a relative path such as ``./docker``.
    if requested != tool_name:
        explicit = Path(requested)
        if not explicit.is_absolute() or explicit not in candidates:
            return None
        candidates = (explicit,)

    executable = next((path for path in candidates if _is_trusted_host_tool(path)), None)
    if executable is None:
        return None
    return (str(executable), *argv[1:]), {}


def _is_trusted_host_tool(path: Path) -> bool:
    """Require an allowlisted absolute regular executable without PATH resolution."""

    if not path.is_absolute():
        return False
    try:
        status = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(status.st_mode) and os.access(path, os.X_OK)


def _safe_http_response(
    url: str, *, headers: dict[str, str] | None, timeout: float
) -> tuple[int, bytes | None]:
    """Issue one bounded, exact-URL request without proxy or redirect credential replay."""

    request = Request(url, headers=headers or {})  # noqa: S310 - callers validate private runtime URLs
    opener = build_opener(ProxyHandler({}), _RejectRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - exact URL is checked below
            status = getattr(response, "status", None)
            if not isinstance(status, int) or not 100 <= status <= 599 or response.geturl() != url:
                return 0, None
            if 300 <= status < 400:
                return 0, None
            payload = response.read(_MAX_HTTP_RESPONSE_BYTES + 1)
            if len(payload) > _MAX_HTTP_RESPONSE_BYTES:
                return 0, None
            return status, payload
    except HTTPError as error:
        if 300 <= error.code < 400:
            return 0, None
        return error.code, None
    except (OSError, UnicodeError, ValueError):
        return 0, None


class ManagedProcess(Protocol):
    """The small process seam used only by the supervisor implementation/tests."""

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


class RuntimeCommandRunner(Protocol):
    """Adapter for Docker commands, observer process lifecycle, and health probes."""

    def run(
        self, argv: tuple[str, ...], *, env: dict[str, str] | None = None, timeout: float | None = None
    ) -> CommandResult: ...

    def spawn(self, argv: tuple[str, ...], *, env: dict[str, str]) -> ManagedProcess: ...

    def http_status(self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 5.0) -> int: ...

    def http_json(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 5.0
    ) -> tuple[int, dict[str, Any] | None]: ...

    def loopback_listener_state(
        self, host: str, port: int, *, timeout: float = 1.0
    ) -> LoopbackListenerState: ...


class _ContainerMetricsReader:
    """Read one authenticated, exact metrics snapshot from the owned proxy only."""

    def __init__(self, runner: RuntimeCommandRunner, container_id: str, port: int) -> None:
        self._runner = runner
        self._container_id = container_id
        self._port = port

    def snapshot(self) -> MetricsSnapshot:
        code = _metrics_snapshot_program(self._port)
        result = self._runner.run(
            (
                "docker",
                "exec",
                "--user",
                "10001:10001",
                self._container_id,
                "python",
                "-c",
                code,
            )
        )
        if result.returncode != 0:
            raise ReconciliationFailure("reconciliation_metrics_unavailable")
        try:
            document = json.loads(result.stdout, object_pairs_hook=_unique_json_object)
            if not isinstance(document, dict) or set(document) != set(_METRICS_SNAPSHOT_FIELDS):
                raise ValueError
            values = [document[field] for field in _METRICS_SNAPSHOT_FIELDS]
            if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
                raise ValueError
            return MetricsSnapshot(**cast(dict[str, int], document))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            raise ReconciliationFailure("reconciliation_metrics_invalid") from None


_METRICS_SNAPSHOT_FIELDS = (
    "downstream_requests",
    "upstream_calls",
    "blocked_duplicates",
    "blocked_stalls",
    "correction_turns",
    "receipt_projections",
    "local_projection_upstream_calls_avoided",
    "errors",
    "deadline_expiries",
    "cancellations",
    "phase_acquisition",
    "phase_finalization",
    "phase_schema_rejections",
    "admission_rejections",
    "rate_rejections",
)


def _metrics_snapshot_program(port: int) -> str:
    """Return fixed in-container code with no ambient proxy or redirect trust."""

    metric_names = {
        "downstream_requests": "shiftedx_proxy_downstream_requests_total",
        "upstream_calls": "shiftedx_proxy_upstream_calls_total",
        "blocked_duplicates": "shiftedx_proxy_blocked_duplicates_total",
        "blocked_stalls": "shiftedx_proxy_blocked_stalls_total",
        "correction_turns": "shiftedx_proxy_correction_turns_total",
        "receipt_projections": "shiftedx_proxy_receipt_projections_total",
        "local_projection_upstream_calls_avoided": "shiftedx_proxy_local_projection_upstream_calls_avoided_total",
        "errors": "shiftedx_proxy_errors_total",
        "deadline_expiries": "shiftedx_proxy_request_deadline_expiries_total",
        "cancellations": "shiftedx_proxy_downstream_cancellations_total",
        "phase_acquisition": "shiftedx_proxy_phase_acquisition_total",
        "phase_finalization": "shiftedx_proxy_phase_finalization_total",
        "phase_schema_rejections": "shiftedx_proxy_phase_schema_rejections_total",
        "admission_rejections": "shiftedx_proxy_admission_rejections_total",
        "rate_rejections": "shiftedx_proxy_principal_rate_rejections_total",
    }
    return "\n".join(
        (
            "# qualification-reconciliation-metrics",
            "import json",
            "import urllib.error",
            "import urllib.request",
            "from shiftedx_harness_proxy.config import Settings",
            f"metrics_url = 'http://127.0.0.1:{port}/metrics'",
            f"metric_names = {metric_names!r}",
            "class _RejectRedirect(urllib.request.HTTPRedirectHandler):",
            "    def redirect_request(self, request, fp, code, msg, headers, newurl):",
            "        raise urllib.error.HTTPError(request.full_url, code, 'redirect rejected', headers, fp)",
            "settings = Settings()",
            "trusted = tuple(settings.trusted_policy_extension_keys())",
            "if len(trusted) != 1:",
            "    raise SystemExit(1)",
            "request = urllib.request.Request(metrics_url, headers={'Authorization': 'Bearer ' + trusted[0]})",
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect())",
            "try:",
            "    with opener.open(request, timeout=5) as response:",
            "        if response.status != 200 or response.geturl() != metrics_url:",
            "            raise ValueError",
            "        raw = response.read(1048577)",
            "    if len(raw) > 1048576:",
            "        raise ValueError",
            "    values = {}",
            "    wanted = {value: key for key, value in metric_names.items()}",
            "    for line in raw.decode('ascii').splitlines():",
            "        fields = line.split()",
            "        if len(fields) == 2 and fields[0] in wanted:",
            "            if fields[0] in values or not fields[1].isdigit():",
            "                raise ValueError",
            "            values[fields[0]] = int(fields[1])",
            "    if set(values) != set(wanted):",
            "        raise ValueError",
            "    result = {wanted[name]: values[name] for name in sorted(wanted)}",
            "    print(json.dumps(result, sort_keys=True, separators=(',', ':')))",
            "except (urllib.error.HTTPError, OSError, UnicodeError, ValueError):",
            "    raise SystemExit(1)",
        )
    )


class SubprocessRuntimeCommandRunner:
    """Production adapter. It never interpolates secret values into command arguments."""

    def run(
        self, argv: tuple[str, ...], *, env: dict[str, str] | None = None, timeout: float | None = None
    ) -> CommandResult:
        frozen = _frozen_host_command(argv, env=env)
        if frozen is None:
            return CommandResult(125, "", "")
        command, command_env = frozen
        try:
            completed = subprocess.run(  # noqa: S603 - fixed executable vectors are assembled internally
                list(command),
                capture_output=True,
                text=True,
                check=False,
                env=command_env,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return CommandResult(125, "", "")
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

    def spawn(self, argv: tuple[str, ...], *, env: dict[str, str]) -> ManagedProcess:
        return cast(
            ManagedProcess,
            subprocess.Popen(  # noqa: S603 - fixed observer module vector assembled internally
                list(argv), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ),
        )

    def http_status(self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 5.0) -> int:
        status, _payload = _safe_http_response(url, headers=headers, timeout=timeout)
        return status

    def http_json(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 5.0
    ) -> tuple[int, dict[str, Any] | None]:
        status, payload = _safe_http_response(url, headers=headers, timeout=timeout)
        if payload is None:
            return status, None
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return status, None
        return status, document if isinstance(document, dict) else None

    def loopback_listener_state(
        self, host: str, port: int, *, timeout: float = 1.0
    ) -> LoopbackListenerState:
        """Distinguish a refused loopback connection from all ambiguous failures."""

        try:
            connection = socket.create_connection((host, port), timeout=timeout)
        except ConnectionRefusedError:
            return "refused"
        except (OSError, ValueError):
            return "indeterminate"
        connection.close()
        return "listening"


class _RuntimeModelEvidenceProbe:
    """Adapt the supervisor's narrow runtime seam to C1's read-only probe seam."""

    def __init__(self, runner: RuntimeCommandRunner) -> None:
        self._runner = runner

    def snapshot(
        self,
        *,
        host: str,
        port: int,
        api_key: str | None,
        contract: ModelEvidenceContract,
    ) -> Any:
        # Keep the production probe on C1's hardened transport: it disables
        # ambient proxies, rejects redirects, and bounds response bytes. The
        # adapter below exists solely for the injected fake runtime seam.
        if isinstance(self._runner, SubprocessRuntimeCommandRunner):
            return SystemModelEvidenceProbe().snapshot(
                host=host,
                port=port,
                api_key=api_key,
                contract=contract,
            )
        prepare = getattr(self._runner, "prepare_model_evidence_contract", None)
        if callable(prepare):
            prepare(contract)

        def http_get(url: str, headers: Mapping[str, str]) -> Mapping[str, Any]:
            status, document = self._runner.http_json(url, headers=dict(headers), timeout=5.0)
            if status != 200 or document is None:
                raise ModelEvidenceSessionFailure("model_probe_failed")
            return document

        def command(argv: tuple[str, ...], *, env: Mapping[str, str]) -> tuple[int, str]:
            result = self._runner.run(argv, env=dict(env), timeout=5.0)
            return result.returncode, result.stdout

        return SystemModelEvidenceProbe(http_get=http_get, command_runner=command).snapshot(
            host=host,
            port=port,
            api_key=api_key,
            contract=contract,
        )


@dataclass(frozen=True)
class RuntimeLease:
    """The runner-facing qualification lease; it intentionally hides Docker/process details."""

    stage: RuntimeStage
    run_manifest_sha256: str
    source_commit: str
    image_digest: str
    model: str
    benchmark_revision: str
    agentic_set: str
    sampler_profile: Literal["corrected-parity-v1", "historical-aeon-v1"]
    scenario_order_sha256: str
    scenario_count: int
    benchmark_source_path: Path
    trial_run_id: str
    cache_lane: CampaignLane
    pair_index: int
    campaign_id_sha256: str
    slot_ordinal: int
    direct_base_url: str
    direct_api_key_file: Path | None
    proxy_base_url: str | None
    proxy_metrics_url: str | None
    proxy_api_key_file: Path | None
    observer_ledger: Path | None
    proxy_request_ledger: Path | None
    direct_model_attempt_ledger: Path | None
    prime_model_attempt_ledger: Path | None
    model_evidence_path: Path
    model_identity_sha256: str
    model_contract_sha256: str
    preflight_ledger: Path
    output_ledger: Path
    attestation_path: Path | None


@dataclass(frozen=True)
class Outcome:
    """Categorical action/cleanup result; it contains no routes, paths, or secret material."""

    stage: RuntimeStage
    status: OutcomeStatus
    action_exit_code: int | None
    failure_category: str | None
    attestation_path: Path | None
    outcome_path: Path | None
    model_runtime_instance_sha256: str | None
    proxy_reconciliation_sha256: str | None


@dataclass(frozen=True)
class _ImageSpec:
    reference: str
    digest: str
    uid: int
    gid: int


@dataclass(frozen=True)
class _ModelSpec:
    public_id: str
    upstream_url: str
    upstream_authenticated: bool
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
    health_contract_sha256: str
    settings_contract_sha256: str


@dataclass(frozen=True)
class _BenchmarkSpec:
    revision: str
    tree: str
    package: str
    checkout_path: Path
    interpreter_sha256: str
    agentic_set: str
    sampler_profile: Literal["corrected-parity-v1", "historical-aeon-v1"]
    scenario_order_sha256: str
    scenario_count: int


@dataclass(frozen=True)
class _ObserverSpec:
    host: str
    port: int
    container_url: str


@dataclass(frozen=True)
class _ProxySpec:
    host: str
    port: int
    container_port: int
    cpus: Decimal
    memory_bytes: int
    pids_limit: int
    stop_timeout_seconds: int
    settings: dict[str, Any]


@dataclass(frozen=True)
class _CredentialSpec:
    ordinary_proxy_api_key_file: Path
    qualification_policy_api_key_file: Path
    upstream_model_api_key_file: Path | None


@dataclass(frozen=True)
class _TrialSpec:
    run_id: str
    cache_lane: Literal["cold", "warm-prefix"]
    pair_index: int
    treatment_order: tuple[Literal["direct", "proxy"], Literal["direct", "proxy"]]


@dataclass(frozen=True)
class _CampaignSpec:
    """The immutable six-slot master-campaign identity, without exposing run IDs in evidence."""

    campaign_id: str
    campaign_id_sha256: str
    slots: tuple[_TrialSpec, ...]


@dataclass(frozen=True)
class _StageBinding:
    """One StageRequest-derived slot plus the sole campaign preflight directory."""

    campaign_id_sha256: str
    slot_ordinal: int
    cache_lane: CampaignLane
    pair_index: int
    run_id: str
    preflight_run_dir: Path


@dataclass(frozen=True)
class _RuntimeSpec:
    manifest_sha256: str
    source_commit: str
    image: _ImageSpec
    model: _ModelSpec
    benchmark: _BenchmarkSpec
    observer: _ObserverSpec
    proxy: _ProxySpec
    credentials: _CredentialSpec
    campaign: _CampaignSpec


def _stage_binding(
    spec: _RuntimeSpec,
    stage: RuntimeStage,
    private_run_dir: Path,
    stage_request: StageRequest,
) -> _StageBinding:
    """Derive the one allowed campaign slot and its shared preflight location.

    The caller supplies the campaign core's immutable next-stage request; there
    is no caller-selected trial or default scored slot.
    """

    if (
        stage_request.manifest_sha256 != spec.manifest_sha256
        or stage_request.stage != stage
        or stage_request.private_run_dir != private_run_dir
        or stage_request.outcome_path != _outcome_path(private_run_dir, stage)
        or not isinstance(stage_request.sequence, int)
        or isinstance(stage_request.sequence, bool)
    ):
        raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
    request_slot = stage_request.slot
    slots_dir = private_run_dir.parent
    if slots_dir.name != "slots":
        raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
    if stage == "preflight":
        expected = CampaignSlot(0, "preflight", 0, f"{spec.campaign.campaign_id}-preflight")
        if (
            stage_request.sequence != 1
            or request_slot != expected
            or private_run_dir.name != "00-preflight-pair0"
        ):
            raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
        return _StageBinding(
            spec.campaign.campaign_id_sha256,
            0,
            "preflight",
            0,
            expected.run_id,
            private_run_dir,
        )
    if request_slot.ordinal not in range(1, 7):
        raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
    expected_slot = spec.campaign.slots[request_slot.ordinal - 1]
    if (
        request_slot.cache_lane != expected_slot.cache_lane
        or request_slot.pair_index != expected_slot.pair_index
        or request_slot.run_id != expected_slot.run_id
        or private_run_dir.name
        != f"{request_slot.ordinal:02d}-{request_slot.cache_lane}-pair{request_slot.pair_index}"
    ):
        raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
    expected_sequence = 2 + (request_slot.ordinal - 1) * 2 + (0 if stage == "score-direct" else 1)
    if stage_request.sequence != expected_sequence:
        raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
    return _StageBinding(
        spec.campaign.campaign_id_sha256,
        request_slot.ordinal,
        request_slot.cache_lane,
        request_slot.pair_index,
        request_slot.run_id,
        slots_dir / "00-preflight-pair0",
    )


def supervise_qualification_runtime(
    *,
    manifest: Path,
    stage: RuntimeStage,
    private_run_dir: Path,
    action: Callable[[RuntimeLease], int],
    command_runner: RuntimeCommandRunner | None = None,
    stage_request: StageRequest,
) -> Outcome:
    """Lease a manifest-derived qualification runtime, invoke ``action``, then clean it.

    A successful proxy stage writes a fixed, hash-only attestation before the action begins.  The
    outcome is a separate no-clobber artifact written only after cleanup, so neither the attestation
    nor benchmark evidence is rewritten on failure.
    """

    runner = command_runner or SubprocessRuntimeCommandRunner()
    interruption_scope = _install_interruption_handlers()
    status: OutcomeStatus = "failed"
    failure_category: str | None = None
    action_exit_code: int | None = None
    attestation_path: Path | None = None
    outcome_path: Path | None = None
    observer: ManagedProcess | None = None
    container_id: str | None = None
    volume_name: str | None = None
    initializer_name: str | None = None
    proxy_name: str | None = None
    volume_attempted = False
    initializer_attempted = False
    proxy_attempted = False
    spec: _RuntimeSpec | None = None
    binding: _StageBinding | None = None
    instance: str | None = None
    model_session: ModelEvidenceSession | None = None
    proxy_reconciliation_sha256: str | None = None
    reconciliation_session: ProxyReconciliationSession | None = None

    try:
        _validate_stage(stage)
        _validate_private_run_dir(private_run_dir)
        spec = _load_runtime_spec(manifest, runner)
        binding = _stage_binding(spec, stage, private_run_dir, stage_request)
        candidate_outcome_path = _outcome_path(private_run_dir, stage)
        if candidate_outcome_path.exists() or candidate_outcome_path.is_symlink():
            raise QualificationRuntimeFailure("runtime_outcome_exists")
        outcome_path = candidate_outcome_path
        _validate_stage_evidence_absent(private_run_dir, stage, binding)
        if stage == "score-direct":
            attestation_path = _validate_existing_preflight_attestation(binding.preflight_run_dir, spec)
            _validate_prior_outcome(binding.preflight_run_dir, "preflight", spec, attestation_path, binding)
            _validate_credentials(spec.credentials, upstream_authenticated=spec.model.upstream_authenticated)
            model_session = _begin_model_evidence(runner, spec, stage, private_run_dir, binding)
            _require_distinct_scored_model_instance(
                binding.preflight_run_dir, spec, stage, model_session, binding
            )
            if _attestation_model_identity(attestation_path) != model_session.model_identity_sha256:
                raise QualificationRuntimeFailure("runtime_model_identity_mismatch")
            lease = _direct_lease(spec, stage, private_run_dir, attestation_path, model_session, binding)
            action_exit_code = _invoke_action(action, lease)
            try:
                _complete_model_evidence(model_session, spec, stage, private_run_dir, binding)
            except QualificationRuntimeFailure:
                # A nonzero child is already a categorical failed treatment.
                # Still retain C1's failed evidence, but do not mask the child
                # result with a consequent missing/incomplete attempt ledger.
                if action_exit_code == 0:
                    raise
            if action_exit_code == 0:
                _require_complete_output(lease.output_ledger, stage, spec)
                status = "passed"
            else:
                failure_category = "action_failed"
        else:
            if stage == "score-proxy":
                preflight_attestation = _validate_existing_preflight_attestation(binding.preflight_run_dir, spec)
                _validate_prior_outcome(
                    binding.preflight_run_dir, "preflight", spec, preflight_attestation, binding
                )
                _validate_prior_outcome(private_run_dir, "score-direct", spec, preflight_attestation, binding)
            _validate_credentials(spec.credentials, upstream_authenticated=spec.model.upstream_authenticated)
            model_session = _begin_model_evidence(runner, spec, stage, private_run_dir, binding)
            if (
                stage == "score-proxy"
                and _attestation_model_identity(preflight_attestation) != model_session.model_identity_sha256
            ):
                raise QualificationRuntimeFailure("runtime_model_identity_mismatch")
            if stage == "score-proxy":
                _require_distinct_scored_model_instance(
                    private_run_dir, spec, stage, model_session, binding
                )
            _assert_port_available(spec.proxy.host, spec.proxy.port, "proxy_port_unavailable")
            _assert_port_available(spec.observer.host, spec.observer.port, "observer_port_unavailable")
            instance = _instance_token(spec.manifest_sha256, stage)
            _assert_no_stale_owned_resources(runner, spec.manifest_sha256)
            image_id = _inspect_exact_image(runner, spec.image)
            volume_name = _volume_name(instance)
            initializer_name = _initializer_name(instance, stage)
            proxy_name = _container_name(instance, stage)
            _validate_credentials(spec.credentials, upstream_authenticated=spec.model.upstream_authenticated)
            volume_attempted = True
            _create_volume(runner, volume_name, spec.manifest_sha256, instance, stage)
            _validate_credentials(spec.credentials, upstream_authenticated=spec.model.upstream_authenticated)
            initializer_attempted = True
            _initialize_secrets(runner, spec, volume_name, initializer_name, instance, stage)
            observer_ledger = _observer_ledger_path(private_run_dir, stage)
            observer_identity = _observer_identity(spec.manifest_sha256, instance)
            observer = _start_observer(runner, spec, observer_ledger, observer_identity)
            _wait_for_observer(runner, spec.observer, observer_identity)
            _validate_fresh_observer_ledger(observer_ledger)
            proxy_attempted = True
            container_id = _launch_proxy(runner, spec, volume_name, proxy_name, instance, stage)
            _verify_proxy(
                runner,
                spec,
                image_id=image_id,
                container_id=container_id,
                volume_name=volume_name,
                instance=instance,
                stage=stage,
            )
            _wait_for_proxy(runner, spec.proxy)
            _verify_proxy_auth_and_metrics(runner, container_id, spec)
            _ensure_live(observer, runner, container_id, spec, image_id, volume_name, instance, stage)
            attestation_path = _attestation_path(private_run_dir, stage)
            _write_attestation(attestation_path, spec, stage, instance, image_id, model_session)
            lease = _proxy_lease(
                spec, stage, private_run_dir, observer_ledger, attestation_path, model_session, binding
            )
            if stage == "score-proxy":
                reconciliation_session = _begin_proxy_reconciliation(
                    runner, container_id, spec, binding, attestation_path
                )
            _validate_credentials(spec.credentials, upstream_authenticated=spec.model.upstream_authenticated)
            action_exit_code = _invoke_action(action, lease)
            _ensure_live(observer, runner, container_id, spec, image_id, volume_name, instance, stage)
            model_summary: ModelOperationSummary | None = None
            try:
                model_summary = _complete_model_evidence(model_session, spec, stage, private_run_dir, binding)
            except QualificationRuntimeFailure:
                # See the direct treatment branch: preserve the failed model
                # artifact without replacing a known child failure category.
                if action_exit_code == 0:
                    raise
            if stage == "score-proxy" and reconciliation_session is not None and model_summary is not None:
                try:
                    proxy_reconciliation_sha256 = _complete_proxy_reconciliation(
                        reconciliation_session,
                        spec,
                        binding,
                        attestation_path,
                        private_run_dir,
                        model_summary,
                    )
                except QualificationRuntimeFailure:
                    # A nonzero benchmark child is already a failed
                    # treatment.  Still retain the reconciliation module's
                    # categorical artifact when it can diagnose the same
                    # measured window, rather than masking the child status.
                    if action_exit_code == 0:
                        raise
            if action_exit_code == 0:
                if stage == "score-proxy" and (
                    reconciliation_session is None
                    or model_summary is None
                    or proxy_reconciliation_sha256 is None
                ):
                    raise QualificationRuntimeFailure("runtime_reconciliation_invalid")
                _require_complete_output(lease.output_ledger, stage, spec)
                status = "passed"
            else:
                failure_category = "action_failed"
    except _RuntimeInterrupted:
        status = "interrupted"
        failure_category = "runtime_interrupted"
    except KeyboardInterrupt:
        status = "interrupted"
        failure_category = "runtime_interrupted"
    except QualificationRuntimeFailure as error:
        failure_category = error.category
    except Exception:
        failure_category = "runtime_internal_failure"
    finally:
        interruption_scope.cleanup_or_outcome = True
        if _cleanup_runtime(
            runner,
            observer,
            proxy_name,
            initializer_name,
            volume_name,
            proxy_attempted=proxy_attempted,
            initializer_attempted=initializer_attempted,
            volume_attempted=volume_attempted,
            spec_manifest_sha256=spec.manifest_sha256 if spec is not None else None,
            instance=instance,
            stage=stage,
        ):
            status = "failed"
            failure_category = "runtime_cleanup_failed"
        completed_outcome_path = outcome_path
        if outcome_path is not None:
            # A failed reconciliation may already have retained its own
            # categorical artifact before raising.  Preserve its immutable
            # hash in the failed runtime outcome when possible; passed proxy
            # outcomes still require the helper's validated passed result.
            if stage == "score-proxy" and proxy_reconciliation_sha256 is None:
                reconciliation_path = _proxy_reconciliation_path(private_run_dir)
                if reconciliation_path.exists() or reconciliation_path.is_symlink():
                    try:
                        proxy_reconciliation_sha256 = _private_file_sha256(
                            reconciliation_path, "runtime_reconciliation_invalid"
                        )
                    except QualificationRuntimeFailure:
                        if status == "passed":
                            status = "failed"
                            failure_category = "runtime_reconciliation_invalid"
            (
                attestation_sha256,
                model_evidence_sha256,
                output_ledger_sha256,
                output_record_count,
                evidence_error,
            ) = _outcome_evidence(
                attestation_path,
                _model_evidence_path(private_run_dir, stage),
                _scored_ledger_path(private_run_dir, stage),
            )
            if evidence_error is not None and status == "passed":
                status = "failed"
                failure_category = evidence_error
            try:
                _write_outcome(
                    outcome_path,
                    stage,
                    status,
                    action_exit_code,
                    failure_category,
                    run_manifest_sha256=spec.manifest_sha256 if spec is not None else None,
                    attestation_sha256=attestation_sha256,
                    model_evidence_sha256=model_evidence_sha256,
                    output_ledger_sha256=output_ledger_sha256,
                    output_record_count=output_record_count,
                    proxy_reconciliation_sha256=proxy_reconciliation_sha256,
                    binding=binding,
                )
            except QualificationRuntimeFailure as error:
                status = "failed"
                failure_category = error.category
                completed_outcome_path = None
        _restore_interruption_handlers(interruption_scope)

    return Outcome(
        stage,
        status,
        action_exit_code,
        failure_category,
        attestation_path,
        completed_outcome_path,
        model_session.runtime_instance_sha256 if model_session is not None else None,
        proxy_reconciliation_sha256,
    )


class QualificationCampaignStageRunner:
    """Deep production adapter from one campaign request to one supervised stage.

    Callers receive only the campaign ``StageRunner`` protocol; this adapter
    owns path topology, strict durable-outcome inspection, and the private
    supervisor invocation.  In particular, it never accepts a stage or slot
    override from the CLI.
    """

    def __init__(
        self,
        *,
        action: Callable[[RuntimeLease], int],
        command_runner: RuntimeCommandRunner | None = None,
    ) -> None:
        self._action = action
        self._command_runner = command_runner

    def inspect(self, request: StageRequest) -> StageInspection:
        runner = self._command_runner or SubprocessRuntimeCommandRunner()
        try:
            spec = _load_runtime_spec(request.manifest, runner)
            binding = _stage_binding(spec, request.stage, request.private_run_dir, request)
        except QualificationRuntimeFailure:
            if request.outcome_path.exists() or request.outcome_path.is_symlink():
                return StageInspection("partial", None)
            return StageInspection("absent", None)
        reserved = _reserved_stage_paths(request.private_run_dir, request.stage, binding)
        if not (request.outcome_path.exists() or request.outcome_path.is_symlink()):
            return StageInspection("partial", None) if any(
                path.exists() or path.is_symlink() for path in reserved
            ) else StageInspection("absent", None)
        result = _inspect_durable_stage_outcome(request, spec, binding)
        return StageInspection("complete", result) if result is not None else StageInspection("partial", None)

    def run(self, request: StageRequest) -> StageResult:
        outcome = supervise_qualification_runtime(
            manifest=request.manifest,
            stage=request.stage,
            private_run_dir=request.private_run_dir,
            action=self._action,
            command_runner=self._command_runner,
            stage_request=request,
        )
        inspected = self.inspect(request)
        if inspected.state != "complete" or inspected.result is None:
            raise QualificationRuntimeFailure("runtime_stage_outcome_invalid")
        if inspected.result.status != outcome.status:
            raise QualificationRuntimeFailure("runtime_stage_outcome_invalid")
        return inspected.result


class QualificationCampaignReadinessProbe:
    """Read-only C1 before-probe for the sole next scored campaign slot."""

    def __init__(self, *, command_runner: RuntimeCommandRunner | None = None) -> None:
        self._command_runner = command_runner

    def probe(self, request: StageRequest) -> ReadinessResult:
        if request.stage == "preflight":
            raise QualificationRuntimeFailure("runtime_campaign_request_invalid")
        runner = self._command_runner or SubprocessRuntimeCommandRunner()
        try:
            spec = _load_runtime_spec(request.manifest, runner)
            binding = _stage_binding(spec, request.stage, request.private_run_dir, request)
            # Campaign core intentionally probes before it creates the slot
            # directory.  C1 begin is read-only, but it requires a trusted
            # mode-0700 parent for its no-clobber target, so use a unique
            # never-written sentinel under the already-owned ``slots`` parent.
            _validate_private_run_dir(request.private_run_dir.parent)
            _validate_credentials(spec.credentials, upstream_authenticated=spec.model.upstream_authenticated)
            if _model_readiness_state(runner, spec) == "offline":
                return ReadinessResult("restart_required", None)
            session = _begin_model_evidence(
                runner,
                spec,
                request.stage,
                request.private_run_dir,
                binding,
                evidence_path=request.private_run_dir.parent
                / f".readiness-{request.sequence}-model-cache-evidence.json",
            )
        except QualificationRuntimeFailure as error:
            if error.category == "model_cache_instance_not_fresh":
                return ReadinessResult("restart_required", None)
            raise
        return ReadinessResult("ready", session.runtime_instance_sha256)


def _model_readiness_state(
    runner: RuntimeCommandRunner,
    spec: _RuntimeSpec,
) -> Literal["offline", "responding"]:
    """Classify only a typed refused loopback connection as retryable."""

    parsed = urlsplit(spec.model.upstream_url)
    host = parsed.hostname
    port = parsed.port
    if host is None or port is None:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    try:
        state = runner.loopback_listener_state(host, port, timeout=1.0)
    except Exception as error:
        raise QualificationRuntimeFailure("model_listener_probe_failed") from error
    if state == "refused":
        return "offline"
    if state == "listening":
        return "responding"
    raise QualificationRuntimeFailure("model_listener_probe_failed")


def _reserved_stage_paths(
    private_run_dir: Path, stage: RuntimeStage, binding: _StageBinding
) -> tuple[Path, ...]:
    paths: list[Path] = [
        _outcome_path(private_run_dir, stage),
        _scored_ledger_path(private_run_dir, stage),
        _model_evidence_path(private_run_dir, stage),
    ]
    direct_attempt = _direct_attempt_ledger_path(private_run_dir, stage)
    if direct_attempt is not None:
        paths.append(direct_attempt)
    prime_attempt = _prime_attempt_ledger_path(private_run_dir, stage, binding.cache_lane)
    if prime_attempt is not None:
        paths.append(prime_attempt)
    if stage != "score-direct":
        paths.extend(
            (
                _attestation_path(private_run_dir, stage),
                _observer_ledger_path(private_run_dir, stage),
                _proxy_request_ledger_path(private_run_dir, stage),
            )
        )
    if stage == "score-proxy":
        paths.append(_proxy_reconciliation_path(private_run_dir))
    return tuple(paths)


def _stage_attestation_path(
    private_run_dir: Path, stage: RuntimeStage, binding: _StageBinding
) -> Path:
    return (
        _attestation_path(private_run_dir, stage)
        if stage != "score-direct"
        else _attestation_path(binding.preflight_run_dir, "preflight")
    )


def _inspect_durable_stage_outcome(
    request: StageRequest, spec: _RuntimeSpec, binding: _StageBinding
) -> StageResult | None:
    """Return one strict durable stage result, never inferring it from a filename."""

    try:
        serialized = _read_private_file(request.outcome_path, "runtime_stage_outcome_invalid")
        document = json.loads(serialized, object_pairs_hook=_unique_json_object)
    except (QualificationRuntimeFailure, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(document, dict) or not _valid_stage_outcome_document(document, request, spec, binding):
        return None
    status = cast(OutcomeStatus, document["status"])
    outcome_sha256 = hashlib.sha256(serialized).hexdigest()
    if status != "passed":
        return StageResult(
            status,
            cast(str, document["failure_category"]),
            request.outcome_path,
            outcome_sha256,
            None,
            None,
        )
    try:
        attestation_path = _stage_attestation_path(request.private_run_dir, request.stage, binding)
        model_identity_sha256 = _attestation_model_identity(attestation_path)
        evidence_stage = cast(Literal["preflight", "score-direct", "score-proxy"], {
            "preflight": "preflight",
            "score-direct": "score-direct",
            "score-proxy": "score-proxy",
        }[request.stage])
        model_evidence = load_model_evidence(
            _model_evidence_path(request.private_run_dir, request.stage),
            expected_stage=evidence_stage,
            run_manifest_sha256=spec.manifest_sha256,
            model_identity_sha256=model_identity_sha256,
        )
        loaded = load_runtime_outcome(
            request.outcome_path,
            expected_stage=_outcome_stage(request.stage),
            run_manifest_sha256=spec.manifest_sha256,
            attestation=attestation_path,
            model_evidence=_model_evidence_path(request.private_run_dir, request.stage),
            model_identity_sha256=model_identity_sha256,
            output_ledger=_scored_ledger_path(request.private_run_dir, request.stage),
            expected_output_record_count=(
                5 if request.stage == "preflight" else spec.benchmark.scenario_count
            ),
            proxy_reconciliation=(
                _proxy_reconciliation_path(request.private_run_dir)
                if request.stage == "score-proxy"
                else None
            ),
            campaign_id_sha256=binding.campaign_id_sha256,
            slot_ordinal=binding.slot_ordinal,
            cache_lane=binding.cache_lane,
            pair_index=binding.pair_index,
        )
    except (
        QualificationRuntimeFailure,
        RuntimeOutcomeFailure,
        ModelEvidenceArtifactFailure,
    ):
        return None
    return StageResult(
        "passed",
        None,
        request.outcome_path,
        loaded.file_sha256,
        model_evidence.runtime_instance_sha256,
        loaded.proxy_reconciliation_sha256,
    )


def _valid_stage_outcome_document(
    document: dict[str, Any], request: StageRequest, spec: _RuntimeSpec, binding: _StageBinding
) -> bool:
    root_keys = {
        "schema_version",
        "record_type",
        "stage",
        "status",
        "action_exit_code",
        "failure_category",
        "run_manifest_sha256",
        "attestation_sha256",
        "model_evidence_sha256",
        "output_ledger_sha256",
        "output_record_count",
        "proxy_reconciliation_sha256",
        "campaign_id_sha256",
        "slot_ordinal",
        "cache_lane",
        "pair_index",
    }
    status = document.get("status")
    action_exit_code = document.get("action_exit_code")
    failure_category = document.get("failure_category")
    optional_hashes = (
        document.get("attestation_sha256"),
        document.get("model_evidence_sha256"),
        document.get("output_ledger_sha256"),
        document.get("proxy_reconciliation_sha256"),
    )
    return (
        set(document) == root_keys
        and document.get("schema_version") == "1.0"
        and document.get("record_type") == "qualification_runtime_outcome"
        and document.get("stage") == _outcome_stage(request.stage)
        and status in {"passed", "failed", "interrupted"}
        and (action_exit_code is None or isinstance(action_exit_code, int) and not isinstance(action_exit_code, bool))
        and document.get("run_manifest_sha256") == spec.manifest_sha256
        and document.get("campaign_id_sha256") == binding.campaign_id_sha256
        and document.get("slot_ordinal") == binding.slot_ordinal
        and document.get("cache_lane") == binding.cache_lane
        and document.get("pair_index") == binding.pair_index
        and all(
            value is None or isinstance(value, str) and _SHA256.fullmatch(value) is not None
            for value in optional_hashes
        )
        and isinstance(document.get("output_record_count"), int)
        and not isinstance(document.get("output_record_count"), bool)
        and document["output_record_count"] >= 0
        and (
            status == "passed"
            and action_exit_code == 0
            and failure_category is None
            or status in {"failed", "interrupted"}
            and isinstance(failure_category, str)
            and _FAILURE_CATEGORY.fullmatch(failure_category) is not None
        )
    )


def _validate_stage(stage: RuntimeStage) -> None:
    if stage not in {"preflight", "score-direct", "score-proxy"}:
        raise QualificationRuntimeFailure("runtime_stage_invalid")


def _validate_private_run_dir(path: Path) -> None:
    try:
        file_status = path.lstat()
    except OSError as error:
        raise QualificationRuntimeFailure("private_run_dir_invalid") from error
    if not path.is_dir() or path.is_symlink() or stat.S_IMODE(file_status.st_mode) != 0o700:
        raise QualificationRuntimeFailure("private_run_dir_invalid")


def _load_runtime_spec(manifest: Path, runner: RuntimeCommandRunner) -> _RuntimeSpec:
    try:
        manifest_bytes = manifest.read_bytes()
        document = json.loads(manifest_bytes, object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise QualificationRuntimeFailure("runtime_manifest_invalid") from error
    if not isinstance(document, dict):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    section = document.get("qualification_runtime")
    if not isinstance(section, dict) or set(section) != _SECTION_KEYS:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    source_commit = _exact_string(section, "source_commit", _SOURCE_COMMIT)
    if section.get("schema_version") != "1.0":
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    image = _parse_image(section.get("image"))
    model = _parse_model(section.get("model"))
    benchmark = _parse_benchmark(section.get("benchmark"))
    _validate_benchmark_checkout(runner, benchmark)
    observer = _parse_observer(section.get("observer"))
    proxy = _parse_proxy(section.get("proxy"), observer)
    credentials = _parse_credentials(section.get("credentials"), model.upstream_authenticated)
    campaign = _parse_campaign(section.get("campaign"))
    _validate_settings(proxy.settings, observer.container_url, proxy.container_port, model.upstream_authenticated)
    return _RuntimeSpec(manifest_sha256, source_commit, image, model, benchmark, observer, proxy, credentials, campaign)


def _parse_image(value: Any) -> _ImageSpec:
    image = _exact_object(value, {"reference", "digest", "uid", "gid"})
    reference = _required_text(image.get("reference"))
    digest = _exact_string(image, "digest", _DIGEST)
    if (
        _IMAGE_REFERENCE.fullmatch(reference) is None
        or reference.count("@") != 1
        or not reference.endswith("@" + digest)
    ):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    uid = _positive_int(image.get("uid"))
    gid = _positive_int(image.get("gid"))
    if uid != 10001 or gid != 10001:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return _ImageSpec(reference, digest, uid, gid)


def _parse_model(value: Any) -> _ModelSpec:
    model = _exact_object(
        value,
        {
            "public_id",
            "upstream_url",
            "upstream_authenticated",
            "stage_path",
            "stage_revision",
            "identity_ledger",
            "identity_ledger_sha256",
            "inspect_artifact",
            "inspect_artifact_sha256",
            "runtime_executable",
            "runtime_executable_sha256",
            "mtplx_distribution_root",
            "mtplx_record",
            "mtplx_version",
            "launch_command_sha256",
            "required_launch_flags",
            "health_contract_sha256",
            "settings_contract_sha256",
        },
    )
    public_id = _required_text(model.get("public_id"))
    upstream_url = _safe_absolute_http_url(_required_text(model.get("upstream_url")))
    upstream = urlsplit(upstream_url)
    if upstream.scheme != "http" or upstream.hostname is None or upstream.port is None:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    _loopback_host(upstream.hostname)
    authenticated = model.get("upstream_authenticated")
    if not isinstance(authenticated, bool):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    flags = model.get("required_launch_flags")
    if (
        not isinstance(flags, list)
        or not flags
        or any(not isinstance(flag, str) or not flag for flag in flags)
        or len(set(flags)) != len(flags)
    ):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return _ModelSpec(
        public_id,
        upstream_url,
        authenticated,
        _absolute_path(model.get("stage_path")),
        _exact_string(model, "stage_revision", _SOURCE_COMMIT),
        _absolute_path(model.get("identity_ledger")),
        _exact_string(model, "identity_ledger_sha256", _SHA256),
        _absolute_path(model.get("inspect_artifact")),
        _exact_string(model, "inspect_artifact_sha256", _SHA256),
        _absolute_path(model.get("runtime_executable")),
        _exact_string(model, "runtime_executable_sha256", _SHA256),
        _absolute_path(model.get("mtplx_distribution_root")),
        _absolute_path(model.get("mtplx_record")),
        _required_text(model.get("mtplx_version")),
        _exact_string(model, "launch_command_sha256", _SHA256),
        tuple(flags),
        _exact_string(model, "health_contract_sha256", _SHA256),
        _exact_string(model, "settings_contract_sha256", _SHA256),
    )


def _parse_benchmark(value: Any) -> _BenchmarkSpec:
    benchmark = _exact_object(
        value,
        {
            "revision",
            "tree",
            "package",
            "checkout_path",
            "interpreter_sha256",
            "agentic_set",
            "sampler_profile",
            "scenario_order_sha256",
            "scenario_count",
        },
    )
    revision = _required_text(benchmark.get("revision"))
    if revision != BENCHMARK_REVISION:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    tree = _exact_string(benchmark, "tree", _SOURCE_COMMIT)
    package = benchmark.get("package")
    if package != "shiftedx-bench==0.5.1":
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    checkout_path = _absolute_path(benchmark.get("checkout_path"))
    interpreter_sha256 = _exact_string(benchmark, "interpreter_sha256", _SHA256)
    agentic_set = _required_text(benchmark.get("agentic_set"))
    if agentic_set not in {"core", "expanded", "repo"}:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    sampler_profile = benchmark.get("sampler_profile")
    if sampler_profile not in {"corrected-parity-v1", "historical-aeon-v1"}:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    order_hash = _exact_string(benchmark, "scenario_order_sha256", _SHA256)
    count = _positive_int(benchmark.get("scenario_count"))
    return _BenchmarkSpec(
        revision,
        tree,
        package,
        checkout_path,
        interpreter_sha256,
        agentic_set,
        sampler_profile,
        order_hash,
        count,
    )


def _parse_campaign(value: Any) -> _CampaignSpec:
    """Validate the frozen master campaign before any stage can reserve evidence.

    The operator-facing advance path supplies the current :class:`StageRequest`;
    the runtime only accepts slots from this exact ordered campaign, rather than
    a caller-selected trial object.
    """

    campaign = _exact_object(
        value,
        {
            "campaign_id",
            "slots",
            "stage_order",
            "treatment_order",
            "model_instance_policy",
            "failure_policy",
        },
    )
    campaign_id = _required_text(campaign.get("campaign_id"))
    raw_slots = campaign.get("slots")
    if (
        _RUN_ID.fullmatch(campaign_id) is None
        or campaign.get("stage_order") != ["preflight", "score-direct", "score-proxy"]
        or campaign.get("treatment_order") != ["direct", "proxy"]
        or campaign.get("model_instance_policy") != "fresh-per-scored-treatment"
        or campaign.get("failure_policy") != "terminal-no-rerun"
        or not isinstance(raw_slots, list)
        or len(raw_slots) != 6
    ):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    expected: tuple[tuple[Literal["cold", "warm-prefix"], int], ...] = (
        ("cold", 1),
        ("cold", 2),
        ("cold", 3),
        ("warm-prefix", 1),
        ("warm-prefix", 2),
        ("warm-prefix", 3),
    )
    slots: list[_TrialSpec] = []
    run_ids: set[str] = set()
    for raw, (lane, pair_index) in zip(raw_slots, expected, strict=True):
        slot = _exact_object(raw, {"cache_lane", "pair_index", "run_id"})
        run_id = _required_text(slot.get("run_id"))
        if (
            _RUN_ID.fullmatch(run_id) is None
            or run_id in run_ids
            or slot.get("cache_lane") != lane
            or slot.get("pair_index") != pair_index
        ):
            raise QualificationRuntimeFailure("runtime_manifest_invalid")
        run_ids.add(run_id)
        slots.append(_TrialSpec(run_id, lane, pair_index, ("direct", "proxy")))
    return _CampaignSpec(campaign_id, hashlib.sha256(campaign_id.encode("utf-8")).hexdigest(), tuple(slots))


def _validate_benchmark_checkout(runner: RuntimeCommandRunner, benchmark: _BenchmarkSpec) -> None:
    """Bind the child to one clean, pinned benchmark source tree and interpreter."""

    try:
        checkout_status = benchmark.checkout_path.lstat()
        source = benchmark.checkout_path / "src"
        source_status = source.lstat()
        executable_sha256 = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    except OSError as error:
        raise QualificationRuntimeFailure("runtime_benchmark_invalid") from error
    if (
        benchmark.checkout_path.is_symlink()
        or not stat.S_ISDIR(checkout_status.st_mode)
        or source.is_symlink()
        or not stat.S_ISDIR(source_status.st_mode)
        or executable_sha256 != benchmark.interpreter_sha256
    ):
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")
    head = runner.run(("git", "-C", str(benchmark.checkout_path), "rev-parse", "HEAD"))
    tree = runner.run(("git", "-C", str(benchmark.checkout_path), "rev-parse", "HEAD^{tree}"))
    clean = runner.run(("git", "-C", str(benchmark.checkout_path), "status", "--porcelain=v1", "--untracked-files=all"))
    if (
        head.returncode != 0
        or head.stdout.strip() != benchmark.revision
        or tree.returncode != 0
        or tree.stdout.strip() != benchmark.tree
        or clean.returncode != 0
        or clean.stdout.strip()
    ):
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")
    project = runner.run(("git", "-C", str(benchmark.checkout_path), "show", "HEAD:pyproject.toml"))
    _validate_tracked_benchmark_project(project, benchmark.package)
    package_init = runner.run(
        ("git", "-C", str(benchmark.checkout_path), "cat-file", "-e", "HEAD:src/shiftedx_bench/__init__.py")
    )
    if package_init.returncode != 0:
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")
    probe = runner.run(
        (sys.executable, "-I", "-S", "-c", _BENCHMARK_SOURCE_PROBE, str(source)),
    )
    document = _parse_command_json(probe.stdout, "runtime_benchmark_invalid")
    module = document.get("module")
    if probe.returncode != 0 or not isinstance(module, str) or not _is_path_beneath(Path(module), source):
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")


def _validate_tracked_benchmark_project(project: CommandResult, expected_package: str) -> None:
    if project.returncode != 0:
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")
    try:
        document = tomllib.loads(project.stdout)
    except tomllib.TOMLDecodeError as error:
        raise QualificationRuntimeFailure("runtime_benchmark_invalid") from error
    value = document.get("project")
    if not isinstance(value, dict) or value.get("name") != "shiftedx-bench" or value.get("version") != "0.5.1":
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")
    if f"shiftedx-bench=={value['version']}" != expected_package:
        raise QualificationRuntimeFailure("runtime_benchmark_invalid")


_BENCHMARK_SOURCE_PROBE = "\n".join(
    (
        "import importlib.util",
        "import json",
        "import pathlib",
        "import sys",
        "source = pathlib.Path(sys.argv[1]).resolve()",
        "sys.path[:] = [str(source)]",
        "spec = importlib.util.find_spec('shiftedx_bench')",
        "origin = spec.origin if spec is not None else None",
        "print(json.dumps({'module': str(pathlib.Path(origin).resolve()) if isinstance(origin, str) else None}, "
        "sort_keys=True, separators=(',', ':')))",
    )
)


def _benchmark_child_environment(source: Path) -> dict[str, str]:
    return {
        "PYTHONPATH": str(source),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _is_path_beneath(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except (OSError, ValueError):
        return False
    return True


def _parse_observer(value: Any) -> _ObserverSpec:
    observer = _exact_object(value, {"host", "port", "container_url"})
    host = _loopback_host(_required_text(observer.get("host")))
    port = _port(observer.get("port"))
    container_url = _safe_absolute_http_url(_required_text(observer.get("container_url")))
    parsed = urlsplit(container_url)
    if parsed.port != port:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return _ObserverSpec(host, port, container_url)


def _parse_proxy(value: Any, observer: _ObserverSpec) -> _ProxySpec:
    proxy = _exact_object(
        value,
        {
            "host",
            "port",
            "container_port",
            "cpus",
            "memory_bytes",
            "pids_limit",
            "stop_timeout_seconds",
            "settings",
        },
    )
    host = _loopback_host(_required_text(proxy.get("host")))
    port = _port(proxy.get("port"))
    container_port = _port(proxy.get("container_port"))
    if host == observer.host and port == observer.port:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    cpus = _positive_decimal(proxy.get("cpus"))
    memory_bytes = _positive_int(proxy.get("memory_bytes"))
    pids_limit = _positive_int(proxy.get("pids_limit"))
    stop_timeout_seconds = _positive_int(proxy.get("stop_timeout_seconds"))
    settings = _exact_object(proxy.get("settings"), _SETTINGS_KEYS)
    return _ProxySpec(host, port, container_port, cpus, memory_bytes, pids_limit, stop_timeout_seconds, settings)


def _parse_credentials(value: Any, upstream_authenticated: bool) -> _CredentialSpec:
    credentials = _exact_object(
        value,
        {
            "ordinary_proxy_api_key_file",
            "qualification_policy_api_key_file",
            "upstream_model_api_key_file",
        },
    )
    ordinary = _absolute_path(credentials.get("ordinary_proxy_api_key_file"))
    policy = _absolute_path(credentials.get("qualification_policy_api_key_file"))
    upstream_value = credentials.get("upstream_model_api_key_file")
    if upstream_authenticated:
        upstream = _absolute_path(upstream_value)
    elif upstream_value is None:
        upstream = None
    else:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return _CredentialSpec(ordinary, policy, upstream)


def _validate_settings(
    settings: dict[str, Any], observer_url: str, container_port: int, upstream_authenticated: bool
) -> None:
    if (
        settings["deployment_profile"] != "production"
        or settings["harness_profile"] != HARNESS_PROFILE
        or settings["upstream_tool_response_capability_mode"] != "phase_split"
        or settings["upstream_cache_capability_mode"] != "disabled"
        or settings["telemetry_enabled"] is not True
        or settings["metrics_enabled"] is not True
    ):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    try:
        Settings(
            upstream_base_url=observer_url,
            upstream_api_key=SecretStr("runtime-upstream-placeholder") if upstream_authenticated else None,
            proxy_api_key=SecretStr("runtime-ordinary-placeholder"),
            trusted_policy_extension_api_keys=SecretStr("runtime-policy-placeholder"),
            listen_host=_CONTAINER_LISTEN_HOST,
            listen_port=container_port,
            **settings,
        )
    except Exception as error:
        raise QualificationRuntimeFailure("runtime_manifest_invalid") from error


def _validate_credentials(credentials: _CredentialSpec, *, upstream_authenticated: bool) -> None:
    paths = [credentials.ordinary_proxy_api_key_file, credentials.qualification_policy_api_key_file]
    if upstream_authenticated:
        if credentials.upstream_model_api_key_file is None:
            raise QualificationRuntimeFailure("runtime_credential_invalid")
        paths.append(credentials.upstream_model_api_key_file)
    if len(set(paths)) != len(paths):
        raise QualificationRuntimeFailure("runtime_credential_invalid")
    values = [_read_credential(path) for path in paths]
    if len(set(values)) != len(values):
        raise QualificationRuntimeFailure("runtime_credential_invalid")


def _read_credential(path: Path) -> str:
    """Read one role credential without following a replacement symlink."""

    descriptor: int | None = None
    try:
        file_status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(file_status.st_mode) or stat.S_IMODE(file_status.st_mode) != 0o600:
            raise QualificationRuntimeFailure("runtime_credential_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened_status = os.fstat(descriptor)
        if not stat.S_ISREG(opened_status.st_mode) or stat.S_IMODE(opened_status.st_mode) != 0o600:
            raise QualificationRuntimeFailure("runtime_credential_invalid")
        value = os.read(descriptor, 8193)
        if len(value) > 8192:
            raise QualificationRuntimeFailure("runtime_credential_invalid")
        try:
            decoded = value.decode("ascii")
        except UnicodeDecodeError as error:
            raise QualificationRuntimeFailure("runtime_credential_invalid") from error
        if _HTTP_BEARER_TOKEN.fullmatch(decoded) is None:
            raise QualificationRuntimeFailure("runtime_credential_invalid")
        return decoded
    except QualificationRuntimeFailure:
        raise
    except OSError as error:
        raise QualificationRuntimeFailure("runtime_credential_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _assert_port_available(host: str, port: int, category: str) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
    except OSError as error:
        raise QualificationRuntimeFailure(category) from error
    finally:
        probe.close()


def _assert_no_stale_owned_resources(runner: RuntimeCommandRunner, manifest_sha256: str) -> None:
    """Reject prior supervisor-owned resources; never delete a stale run automatically."""

    manifest_label = f"{_LABEL_PREFIX}.manifest={manifest_sha256}"
    for argv in (
        (
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            "label=" + manifest_label,
        ),
        (
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            "label=" + manifest_label,
        ),
    ):
        result = runner.run(argv)
        if result.returncode != 0:
            raise QualificationRuntimeFailure("runtime_docker_unavailable")
        if result.stdout.strip():
            raise QualificationRuntimeFailure("runtime_stale_resources")


def _inspect_exact_image(runner: RuntimeCommandRunner, image: _ImageSpec) -> str:
    result = runner.run(("docker", "image", "inspect", "--format", "{{json .}}", image.reference))
    if result.returncode != 0:
        raise QualificationRuntimeFailure("runtime_image_unavailable")
    document = _parse_command_json(result.stdout, "runtime_image_unavailable")
    image_id = document.get("Id")
    config = document.get("Config")
    if (
        not isinstance(image_id, str)
        or _DIGEST.fullmatch(image_id) is None
        or document.get("Architecture") != "arm64"
        or not isinstance(config, dict)
        or config.get("User") != "10001:10001"
    ):
        raise QualificationRuntimeFailure("runtime_image_unavailable")
    return image_id


def _create_volume(
    runner: RuntimeCommandRunner, volume_name: str, manifest_sha256: str, instance: str, stage: RuntimeStage
) -> None:
    result = runner.run(
        (
            "docker",
            "volume",
            "create",
            "--label",
            f"{_LABEL_PREFIX}.manifest={manifest_sha256}",
            "--label",
            f"{_LABEL_PREFIX}.instance={instance}",
            "--label",
            f"{_LABEL_PREFIX}.stage={_attestation_stage(stage)}",
            "--label",
            f"{_LABEL_PREFIX}.resource=secrets-volume",
            volume_name,
        )
    )
    if result.returncode != 0:
        raise QualificationRuntimeFailure("runtime_volume_create_failed")


def _initialize_secrets(
    runner: RuntimeCommandRunner,
    spec: _RuntimeSpec,
    volume_name: str,
    initializer_name: str,
    instance: str,
    stage: RuntimeStage,
) -> None:
    source_mounts: list[tuple[Path, str]] = [
        (spec.credentials.ordinary_proxy_api_key_file, "proxy_api_key"),
        (spec.credentials.qualification_policy_api_key_file, "trusted_policy_extension_api_keys"),
    ]
    if spec.model.upstream_authenticated:
        assert spec.credentials.upstream_model_api_key_file is not None
        source_mounts.append((spec.credentials.upstream_model_api_key_file, "upstream_api_key"))
    script = _initializer_script(spec.model.upstream_authenticated)
    argv: list[str] = [
        "docker",
        "run",
        "--detach",
        "--pull",
        "never",
        "--name",
        initializer_name,
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges:true",
        "--label",
        f"{_LABEL_PREFIX}.manifest={spec.manifest_sha256}",
        "--label",
        f"{_LABEL_PREFIX}.instance={instance}",
        "--label",
        f"{_LABEL_PREFIX}.stage={_attestation_stage(stage)}",
        "--label",
        f"{_LABEL_PREFIX}.resource=initializer",
    ]
    for path, target_name in source_mounts:
        argv.extend(("--mount", f"type=bind,src={path},dst=/source/{target_name},readonly"))
    argv.extend(
        (
            "--mount",
            f"type=volume,src={volume_name},dst=/target",
            "--entrypoint",
            "/bin/sh",
            spec.image.reference,
            "-ceu",
            script,
        )
    )
    result = runner.run(tuple(argv))
    initializer_id = result.stdout.strip()
    if result.returncode != 0 or _SHA256.fullmatch(initializer_id) is None:
        raise QualificationRuntimeFailure("runtime_secret_initialize_failed")
    wait = runner.run(("docker", "container", "wait", initializer_id))
    if wait.returncode != 0 or wait.stdout.strip() != "0":
        raise QualificationRuntimeFailure("runtime_secret_initialize_failed")
    state_result = runner.run(("docker", "container", "inspect", "--format", "{{json .State}}", initializer_id))
    state = _parse_command_json(state_result.stdout, "runtime_secret_initialize_failed")
    if (
        state_result.returncode != 0
        or state.get("Running") is not False
        or state.get("ExitCode") != 0
        or not _owned_container(runner, initializer_name, spec.manifest_sha256, instance, stage, "initializer")
    ):
        raise QualificationRuntimeFailure("runtime_secret_initialize_failed")


def _initializer_script(upstream_authenticated: bool) -> str:
    names = ["proxy_api_key", "trusted_policy_extension_api_keys"]
    if upstream_authenticated:
        names.append("upstream_api_key")
    copy_lines = "\n".join(f"cp /source/{name} /target/{name}" for name in names)
    joined = " ".join(f"/target/{name}" for name in names)
    comparisons = "\n".join(
        f"! cmp -s /source/{left} /source/{right}" for index, left in enumerate(names) for right in names[index + 1 :]
    )
    ownership_checks = "\n".join(
        (
            "python - <<'PY'",
            "import os",
            "import stat",
            f"for name in {names!r}:",
            "    status = os.stat('/target/' + name)",
            "    assert status.st_uid == 10001 and status.st_gid == 10001",
            "    assert stat.S_IMODE(status.st_mode) == 0o400",
            "PY",
        )
    )
    return "\n".join(
        (
            "set -eu",
            "command -v cp >/dev/null",
            "command -v chmod >/dev/null",
            "command -v chown >/dev/null",
            "command -v cmp >/dev/null",
            "command -v python >/dev/null",
            "test -s /source/proxy_api_key",
            "test -s /source/trusted_policy_extension_api_keys",
            *(["test -s /source/upstream_api_key"] if upstream_authenticated else []),
            comparisons,
            copy_lines,
            f"chmod 0400 {joined}",
            f"chown 10001:10001 {joined}",
            ownership_checks,
        )
    )


def _start_observer(
    runner: RuntimeCommandRunner, spec: _RuntimeSpec, ledger: Path, observer_identity: str
) -> ManagedProcess:
    env = {
        "QUALIFICATION_OBSERVER_UPSTREAM": spec.model.upstream_url,
        "QUALIFICATION_OBSERVER_LEDGER": str(ledger),
        "QUALIFICATION_OBSERVER_HOST": spec.observer.host,
        "QUALIFICATION_OBSERVER_PORT": str(spec.observer.port),
        "QUALIFICATION_OBSERVER_INSTANCE_SHA256": observer_identity,
    }
    try:
        return runner.spawn((sys.executable, "-m", "shiftedx_harness_proxy.qualification_observer"), env=env)
    except Exception as error:
        raise QualificationRuntimeFailure("runtime_observer_start_failed") from error


def _wait_for_observer(runner: RuntimeCommandRunner, observer: _ObserverSpec, observer_identity: str) -> None:
    url = f"http://{_url_host(observer.host)}:{observer.port}/healthz"
    for _ in range(20):
        status, body = runner.http_json(url, timeout=1.0)
        if status == 200 and body == {"status": "live", "instance_sha256": observer_identity}:
            return
        time.sleep(0.05)
    raise QualificationRuntimeFailure("runtime_observer_unhealthy")


def _validate_fresh_observer_ledger(path: Path) -> None:
    """Require the owned observer to have atomically reserved a new private ledger."""

    try:
        file_status = path.lstat()
    except OSError as error:
        raise QualificationRuntimeFailure("runtime_observer_ledger_invalid") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(file_status.st_mode)
        or stat.S_IMODE(file_status.st_mode) != 0o600
        or file_status.st_size != 0
    ):
        raise QualificationRuntimeFailure("runtime_observer_ledger_invalid")


def _launch_proxy(
    runner: RuntimeCommandRunner,
    spec: _RuntimeSpec,
    volume_name: str,
    container_name: str,
    instance: str,
    stage: RuntimeStage,
) -> str:
    settings = spec.proxy.settings
    env_values = {
        "DEPLOYMENT_PROFILE": settings["deployment_profile"],
        "HARNESS_PROFILE": settings["harness_profile"],
        "UPSTREAM_BASE_URL": spec.observer.container_url,
        "UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE": settings["upstream_tool_response_capability_mode"],
        "UPSTREAM_CACHE_CAPABILITY_MODE": settings["upstream_cache_capability_mode"],
        "TELEMETRY_ENABLED": _env_bool(settings["telemetry_enabled"]),
        "METRICS_ENABLED": _env_bool(settings["metrics_enabled"]),
        "MAX_INTERNAL_RETRIES": str(settings["max_internal_retries"]),
        "MAX_UPSTREAM_CALLS": str(settings["max_upstream_calls"]),
        "UPSTREAM_TIMEOUT_SECONDS": str(settings["upstream_timeout_seconds"]),
        "TOTAL_REQUEST_DEADLINE_SECONDS": str(settings["total_request_deadline_seconds"]),
        "SERVER_CONNECTION_LIMIT": str(settings["server_connection_limit"]),
        "ADMISSION_LIMIT": str(settings["admission_limit"]),
        "PRINCIPAL_CONCURRENCY_LIMIT": str(settings["principal_concurrency_limit"]),
        "CONCURRENCY_LIMIT": str(settings["concurrency_limit"]),
        "REQUIRE_RECEIPT_WHEN_TOOLS_PRESENT": _env_bool(settings["require_receipt_when_tools_present"]),
        "ALLOW_HARNESS_OPT_OUT": _env_bool(settings["allow_harness_opt_out"]),
        "LOG_LEVEL": settings["log_level"],
        "LISTEN_HOST": _CONTAINER_LISTEN_HOST,
        "LISTEN_PORT": str(spec.proxy.container_port),
    }
    argv: list[str] = [
        "docker",
        "run",
        "--detach",
        "--pull",
        "never",
        "--name",
        container_name,
        "--init",
        "--stop-timeout",
        str(spec.proxy.stop_timeout_seconds),
        "--user",
        f"{spec.image.uid}:{spec.image.gid}",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(spec.proxy.pids_limit),
        "--cpus",
        _decimal_text(spec.proxy.cpus),
        "--memory",
        str(spec.proxy.memory_bytes),
        "--publish",
        f"{spec.proxy.host}:{spec.proxy.port}:{spec.proxy.container_port}",
        "--mount",
        f"type=volume,src={volume_name},dst=/run/secrets,readonly",
        "--label",
        f"{_LABEL_PREFIX}.manifest={spec.manifest_sha256}",
        "--label",
        f"{_LABEL_PREFIX}.instance={instance}",
        "--label",
        f"{_LABEL_PREFIX}.stage={_attestation_stage(stage)}",
        "--label",
        f"{_LABEL_PREFIX}.resource=proxy",
    ]
    for key, value in env_values.items():
        argv.extend(("--env", f"{key}={value}"))
    argv.append(spec.image.reference)
    result = runner.run(tuple(argv))
    container_id = result.stdout.strip()
    if result.returncode != 0 or _SHA256.fullmatch(container_id) is None:
        raise QualificationRuntimeFailure("runtime_proxy_launch_failed")
    return container_id


def _verify_proxy(
    runner: RuntimeCommandRunner,
    spec: _RuntimeSpec,
    *,
    image_id: str,
    container_id: str,
    volume_name: str,
    instance: str,
    stage: RuntimeStage,
) -> None:
    result = runner.run(("docker", "container", "inspect", "--format", "{{json .}}", container_id))
    if result.returncode != 0:
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    document = _parse_command_json(result.stdout, "runtime_inspect_drift")
    if document.get("State", {}).get("Running") is not True or document.get("Image") != image_id:
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    config = document.get("Config")
    host_config = document.get("HostConfig")
    mounts = document.get("Mounts")
    if not isinstance(config, dict) or not isinstance(host_config, dict) or not isinstance(mounts, list):
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    if config.get("User") != f"{spec.image.uid}:{spec.image.gid}":
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    labels = config.get("Labels")
    expected_labels = {
        f"{_LABEL_PREFIX}.manifest": spec.manifest_sha256,
        f"{_LABEL_PREFIX}.instance": instance,
        f"{_LABEL_PREFIX}.stage": _attestation_stage(stage),
        f"{_LABEL_PREFIX}.resource": "proxy",
    }
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected_labels.items()):
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    _verify_resources(host_config, spec.proxy)
    expected_mount = next(
        (
            mount
            for mount in mounts
            if isinstance(mount, dict)
            and mount.get("Type") == "volume"
            and mount.get("Name") == volume_name
            and mount.get("Destination") == "/run/secrets"
        ),
        None,
    )
    if not isinstance(expected_mount, dict) or expected_mount.get("RW") is not False:
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    _verify_port_binding(host_config, spec.proxy)
    _verify_proxy_environment(config.get("Env"), spec)
    volume_result = runner.run(("docker", "volume", "inspect", "--format", "{{json .}}", volume_name))
    if volume_result.returncode != 0:
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    volume = _parse_command_json(volume_result.stdout, "runtime_inspect_drift")
    volume_labels = volume.get("Labels")
    if not isinstance(volume_labels, dict) or any(
        volume_labels.get(key) != value
        for key, value in {
            **expected_labels,
            f"{_LABEL_PREFIX}.resource": "secrets-volume",
        }.items()
    ):
        raise QualificationRuntimeFailure("runtime_inspect_drift")


def _verify_resources(host_config: dict[str, Any], proxy: _ProxySpec) -> None:
    security_options = host_config.get("SecurityOpt")
    cap_drop = host_config.get("CapDrop")
    if (
        host_config.get("ReadonlyRootfs") is not True
        or not isinstance(cap_drop, list)
        or "ALL" not in cap_drop
        or not isinstance(security_options, list)
        or "no-new-privileges:true" not in security_options
        or host_config.get("PidsLimit") != proxy.pids_limit
        or host_config.get("StopTimeout") != proxy.stop_timeout_seconds
        or host_config.get("Memory") != proxy.memory_bytes
        or host_config.get("NanoCpus") != int(proxy.cpus * Decimal("1000000000"))
        or host_config.get("Init") is not True
    ):
        raise QualificationRuntimeFailure("runtime_inspect_drift")


def _verify_port_binding(host_config: dict[str, Any], proxy: _ProxySpec) -> None:
    bindings = host_config.get("PortBindings")
    if not isinstance(bindings, dict):
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    entries = bindings.get(f"{proxy.container_port}/tcp")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    if entries[0].get("HostIp") != proxy.host or entries[0].get("HostPort") != str(proxy.port):
        raise QualificationRuntimeFailure("runtime_inspect_drift")


def _verify_proxy_environment(value: Any, spec: _RuntimeSpec) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) or "=" not in item for item in value):
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    environment = dict(item.split("=", 1) for item in value)
    if any(key in environment for key in {"PROXY_API_KEY", "UPSTREAM_API_KEY", "TRUSTED_POLICY_EXTENSION_API_KEYS"}):
        raise QualificationRuntimeFailure("runtime_inspect_drift")
    expected = {
        "DEPLOYMENT_PROFILE": "production",
        "HARNESS_PROFILE": HARNESS_PROFILE,
        "LISTEN_HOST": _CONTAINER_LISTEN_HOST,
        "LISTEN_PORT": str(spec.proxy.container_port),
        "UPSTREAM_BASE_URL": spec.observer.container_url,
        "UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE": "phase_split",
        "UPSTREAM_CACHE_CAPABILITY_MODE": "disabled",
        "TELEMETRY_ENABLED": "true",
        "METRICS_ENABLED": "true",
    }
    if any(environment.get(key) != item for key, item in expected.items()):
        raise QualificationRuntimeFailure("runtime_inspect_drift")


def _wait_for_proxy(runner: RuntimeCommandRunner, proxy: _ProxySpec) -> None:
    health = f"http://{_url_host(proxy.host)}:{proxy.port}/healthz"
    ready = f"http://{_url_host(proxy.host)}:{proxy.port}/readyz"
    for _ in range(30):
        if runner.http_status(health, timeout=1.0) == 200 and runner.http_status(ready, timeout=1.0) == 200:
            return
        time.sleep(0.05)
    raise QualificationRuntimeFailure("runtime_proxy_unready")


def _verify_proxy_auth_and_metrics(runner: RuntimeCommandRunner, container_id: str, spec: _RuntimeSpec) -> None:
    """Check effective non-secret settings and trusted metrics access inside the candidate."""

    setting_names = tuple(sorted(_SETTINGS_KEYS))
    code = "\n".join(
        (
            "import json",
            "import urllib.error",
            "import urllib.request",
            "from shiftedx_harness_proxy.config import Settings",
            "settings = Settings()",
            "ordinary = settings.proxy_api_key.get_secret_value() if settings.proxy_api_key else None",
            "trusted_values = settings.trusted_policy_extension_keys()",
            "trusted = next(iter(trusted_values)) if len(trusted_values) == 1 else None",
            "upstream = settings.upstream_api_key.get_secret_value() if settings.upstream_api_key else None",
            f"metrics_url = 'http://127.0.0.1:{spec.proxy.container_port}/metrics'",
            "class _RejectRedirect(urllib.request.HTTPRedirectHandler):",
            "    def redirect_request(self, request, fp, code, msg, headers, newurl):",
            "        raise urllib.error.HTTPError(request.full_url, code, 'redirect rejected', headers, fp)",
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect())",
            "def metric_status(token):",
            "    if token is None:",
            "        return 0",
            "    try:",
            "        request = urllib.request.Request(metrics_url, headers={'Authorization': 'Bearer ' + token})",
            "        with opener.open(request, timeout=5) as response:",
            "            if response.geturl() != metrics_url or 300 <= response.status < 400:",
            "                return 0",
            "            return 200 if response.status == 200 and len(response.read(1048577)) <= 1048576 else 0",
            "    except (urllib.error.HTTPError, OSError, ValueError):",
            "        return 0",
            "result = {",
            f"    'settings': {{name: getattr(settings, name) for name in {setting_names!r}}},",
            "    'secret_roles_distinct': ordinary is not None and trusted is not None and ordinary != trusted"
            " and (upstream is None or (upstream != ordinary and upstream != trusted)),",
            "    'upstream_authenticated': upstream is not None,",
            "    'ordinary_authenticated': metric_status(ordinary) == 200,",
            "    'metrics_authenticated': metric_status(trusted) == 200,",
            "}",
            "print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':')))",
        )
    )
    # Credentials are read only inside the non-root container. This fixed program emits only booleans
    # and allowlisted setting values, never a credential, route, or request/response body.
    result = runner.run(("docker", "exec", "--user", "10001:10001", container_id, "python", "-c", code))
    if result.returncode != 0:
        raise QualificationRuntimeFailure("runtime_proxy_auth_failed")
    document = _parse_command_json(result.stdout, "runtime_proxy_auth_failed")
    if (
        set(document)
        != {
            "settings",
            "secret_roles_distinct",
            "upstream_authenticated",
            "ordinary_authenticated",
            "metrics_authenticated",
        }
        or document.get("settings") != spec.proxy.settings
        or document.get("secret_roles_distinct") is not True
        or document.get("upstream_authenticated") is not spec.model.upstream_authenticated
        or document.get("ordinary_authenticated") is not True
        or document.get("metrics_authenticated") is not True
    ):
        raise QualificationRuntimeFailure("runtime_proxy_auth_failed")


def _ensure_live(
    observer: ManagedProcess,
    runner: RuntimeCommandRunner,
    container_id: str,
    spec: _RuntimeSpec,
    image_id: str,
    volume_name: str,
    instance: str,
    stage: RuntimeStage,
) -> None:
    if observer.poll() is not None:
        raise QualificationRuntimeFailure("runtime_observer_stopped")
    _verify_proxy(
        runner,
        spec,
        image_id=image_id,
        container_id=container_id,
        volume_name=volume_name,
        instance=instance,
        stage=stage,
    )


def _invoke_action(action: Callable[[RuntimeLease], int], lease: RuntimeLease) -> int:
    try:
        result = action(lease)
    except _RuntimeInterrupted:
        raise
    except KeyboardInterrupt:
        raise
    except Exception as error:
        raise QualificationRuntimeFailure("runtime_action_failed") from error
    if not isinstance(result, int) or isinstance(result, bool):
        raise QualificationRuntimeFailure("runtime_action_invalid")
    return result


def _install_interruption_handlers() -> _InterruptionScope:
    previous: dict[int, Any] = {}
    scope = _InterruptionScope(previous)
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.getsignal(number)

            def interrupted(_number: int, _frame: FrameType | None) -> None:
                if scope.cleanup_or_outcome:
                    return
                raise _RuntimeInterrupted()

            signal.signal(number, interrupted)
    except ValueError:
        _restore_interruption_handlers(scope)
    return scope


def _restore_interruption_handlers(scope: _InterruptionScope) -> None:
    for number, handler in scope.previous.items():
        signal.signal(number, handler)


def _proxy_lease(
    spec: _RuntimeSpec,
    stage: RuntimeStage,
    private_run_dir: Path,
    observer_ledger: Path,
    attestation_path: Path,
    model_session: ModelEvidenceSession,
    binding: _StageBinding,
) -> RuntimeLease:
    return RuntimeLease(
        stage=stage,
        run_manifest_sha256=spec.manifest_sha256,
        source_commit=spec.source_commit,
        image_digest=spec.image.digest,
        model=spec.model.public_id,
        benchmark_revision=spec.benchmark.revision,
        agentic_set=spec.benchmark.agentic_set,
        sampler_profile=spec.benchmark.sampler_profile,
        scenario_order_sha256=spec.benchmark.scenario_order_sha256,
        scenario_count=spec.benchmark.scenario_count,
        benchmark_source_path=spec.benchmark.checkout_path / "src",
        trial_run_id=binding.run_id,
        cache_lane=binding.cache_lane,
        pair_index=binding.pair_index,
        campaign_id_sha256=binding.campaign_id_sha256,
        slot_ordinal=binding.slot_ordinal,
        direct_base_url=spec.model.upstream_url,
        direct_api_key_file=spec.credentials.upstream_model_api_key_file,
        proxy_base_url=f"http://{_url_host(spec.proxy.host)}:{spec.proxy.port}/v1",
        proxy_metrics_url=f"http://{_url_host(spec.proxy.host)}:{spec.proxy.port}/metrics",
        proxy_api_key_file=spec.credentials.qualification_policy_api_key_file,
        observer_ledger=observer_ledger,
        proxy_request_ledger=_proxy_request_ledger_path(private_run_dir, stage),
        direct_model_attempt_ledger=_direct_attempt_ledger_path(private_run_dir, stage),
        prime_model_attempt_ledger=_prime_attempt_ledger_path(private_run_dir, stage, binding.cache_lane),
        model_evidence_path=_model_evidence_path(private_run_dir, stage),
        model_identity_sha256=model_session.model_identity_sha256,
        model_contract_sha256=model_session.model_contract_sha256,
        preflight_ledger=_scored_ledger_path(binding.preflight_run_dir, "preflight"),
        output_ledger=_scored_ledger_path(private_run_dir, stage),
        attestation_path=attestation_path,
    )


def _direct_lease(
    spec: _RuntimeSpec,
    stage: RuntimeStage,
    private_run_dir: Path,
    attestation_path: Path,
    model_session: ModelEvidenceSession,
    binding: _StageBinding,
) -> RuntimeLease:
    return RuntimeLease(
        stage=stage,
        run_manifest_sha256=spec.manifest_sha256,
        source_commit=spec.source_commit,
        image_digest=spec.image.digest,
        model=spec.model.public_id,
        benchmark_revision=spec.benchmark.revision,
        agentic_set=spec.benchmark.agentic_set,
        sampler_profile=spec.benchmark.sampler_profile,
        scenario_order_sha256=spec.benchmark.scenario_order_sha256,
        scenario_count=spec.benchmark.scenario_count,
        benchmark_source_path=spec.benchmark.checkout_path / "src",
        trial_run_id=binding.run_id,
        cache_lane=binding.cache_lane,
        pair_index=binding.pair_index,
        campaign_id_sha256=binding.campaign_id_sha256,
        slot_ordinal=binding.slot_ordinal,
        direct_base_url=spec.model.upstream_url,
        direct_api_key_file=spec.credentials.upstream_model_api_key_file,
        proxy_base_url=None,
        proxy_metrics_url=None,
        proxy_api_key_file=None,
        observer_ledger=None,
        proxy_request_ledger=None,
        direct_model_attempt_ledger=_direct_attempt_ledger_path(private_run_dir, stage),
        prime_model_attempt_ledger=_prime_attempt_ledger_path(private_run_dir, stage, binding.cache_lane),
        model_evidence_path=_model_evidence_path(private_run_dir, stage),
        model_identity_sha256=model_session.model_identity_sha256,
        model_contract_sha256=model_session.model_contract_sha256,
        preflight_ledger=_scored_ledger_path(binding.preflight_run_dir, "preflight"),
        output_ledger=_scored_ledger_path(private_run_dir, stage),
        attestation_path=attestation_path,
    )


def _model_evidence_contract(
    spec: _RuntimeSpec, stage: RuntimeStage, binding: _StageBinding
) -> ModelEvidenceContract:
    """Construct C1's private contract from the strict manifest without exposing it."""

    parsed = urlsplit(spec.model.upstream_url)
    host = parsed.hostname
    port = parsed.port
    if host is None or port is None:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    lane: CampaignLane = "preflight" if stage == "preflight" else binding.cache_lane
    return ModelEvidenceContract(
        public_model_id=spec.model.public_id,
        stage_path=spec.model.stage_path,
        stage_revision=spec.model.stage_revision,
        identity_ledger=spec.model.identity_ledger,
        identity_ledger_sha256=spec.model.identity_ledger_sha256,
        inspect_artifact=spec.model.inspect_artifact,
        inspect_artifact_sha256=spec.model.inspect_artifact_sha256,
        runtime_executable=spec.model.runtime_executable,
        runtime_executable_sha256=spec.model.runtime_executable_sha256,
        mtplx_distribution_root=spec.model.mtplx_distribution_root,
        mtplx_record=spec.model.mtplx_record,
        mtplx_version=spec.model.mtplx_version,
        launch_command_sha256=spec.model.launch_command_sha256,
        required_launch_flags=spec.model.required_launch_flags,
        host=host,
        port=port,
        health_contract_sha256=spec.model.health_contract_sha256,
        settings_contract_sha256=spec.model.settings_contract_sha256,
        cache_lane=lane,
    )


def _begin_model_evidence(
    runner: RuntimeCommandRunner,
    spec: _RuntimeSpec,
    stage: RuntimeStage,
    private_run_dir: Path,
    binding: _StageBinding,
    *,
    evidence_path: Path | None = None,
) -> ModelEvidenceSession:
    try:
        return ModelEvidenceSession.begin(
            _model_evidence_contract(spec, stage, binding),
            stage=stage,
            run_manifest_sha256=spec.manifest_sha256,
            evidence_path=evidence_path or _model_evidence_path(private_run_dir, stage),
            credential_file=spec.credentials.upstream_model_api_key_file,
            probe=_RuntimeModelEvidenceProbe(runner),
        )
    except ModelEvidenceSessionFailure as error:
        raise QualificationRuntimeFailure(error.category) from None


def _require_distinct_scored_model_instance(
    private_run_dir: Path,
    spec: _RuntimeSpec,
    stage: Literal["score-direct", "score-proxy"],
    model_session: ModelEvidenceSession,
    binding: _StageBinding,
) -> None:
    """Require a restarted MTPLX instance for each measured scored treatment."""

    prior_stage: Literal["preflight", "score-direct"] = "preflight" if stage == "score-direct" else "score-direct"
    evidence_stage: Literal["preflight", "score-direct", "score-proxy"] = (
        "preflight" if prior_stage == "preflight" else "score-direct"
    )
    try:
        prior = load_model_evidence(
            _model_evidence_path(private_run_dir, prior_stage),
            expected_stage=evidence_stage,
            run_manifest_sha256=spec.manifest_sha256,
            model_identity_sha256=model_session.model_identity_sha256,
        )
    except ModelEvidenceArtifactFailure as error:
        raise QualificationRuntimeFailure("runtime_prior_model_evidence_invalid") from error
    if prior.runtime_instance_sha256 == model_session.runtime_instance_sha256:
        raise QualificationRuntimeFailure("runtime_model_instance_not_fresh")


def _adapt_model_attempt(record: ModelBoundaryRecord) -> SafeAttemptRecord:
    if 200 <= (record.status_code or 0) <= 299:
        if record.cache is None:
            raise QualificationRuntimeFailure("runtime_model_attempt_invalid")
        cache = record.cache
        return SafeAttemptRecord(
            request_digest=record.digest,
            status="succeeded",
            prompt_tokens=cache.prompt_tokens,
            cached_tokens=cache.cached_tokens,
            new_prefill_tokens=cache.new_prefill_tokens,
            cache_source=cache.cache_source,
            ssd_cache_hit=cache.ssd_cache_hit,
            ssd_cached_tokens=cache.ssd_cached_tokens,
            session_cache_hit=cache.session_cache_hit,
            request_session_bank_bypass=cache.request_session_bank_bypass,
            postcommit_stored=cache.postcommit_stored,
        )
    if record.cache is not None:
        raise QualificationRuntimeFailure("runtime_model_attempt_invalid") from None
    return SafeAttemptRecord(
        request_digest=record.digest,
        status="failed",
        prompt_tokens=0,
        cached_tokens=0,
        new_prefill_tokens=0,
        cache_source="none",
        ssd_cache_hit=False,
        ssd_cached_tokens=0,
        session_cache_hit=False,
        request_session_bank_bypass=False,
        postcommit_stored=False,
    )


def _stage_model_attempts(
    private_run_dir: Path,
    stage: RuntimeStage,
    lane: CampaignLane,
) -> tuple[tuple[SafeAttemptRecord, ...], SafeAttemptRecord | None]:
    try:
        if stage == "preflight":
            records = (
                *read_model_boundary_observer_records(_direct_attempt_ledger_path_required(private_run_dir, stage)),
                *read_model_boundary_observer_records(_observer_ledger_path(private_run_dir, stage)),
            )
        elif stage == "score-direct":
            records = read_model_boundary_observer_records(_direct_attempt_ledger_path_required(private_run_dir, stage))
        else:
            records = read_model_boundary_observer_records(_observer_ledger_path(private_run_dir, stage))
        attempts = tuple(_adapt_model_attempt(record) for record in records)
        prime_path = _prime_attempt_ledger_path(private_run_dir, stage, lane)
        if prime_path is None:
            return attempts, None
        prime_records = read_model_boundary_observer_records(prime_path)
        if len(prime_records) != 1:
            raise QualificationRuntimeFailure("runtime_model_attempt_invalid")
        return attempts, _adapt_model_attempt(prime_records[0])
    except (PreflightFailure, QualificationRuntimeFailure):
        raise QualificationRuntimeFailure("runtime_model_attempt_invalid") from None


def _complete_model_evidence(
    session: ModelEvidenceSession,
    spec: _RuntimeSpec,
    stage: RuntimeStage,
    private_run_dir: Path,
    binding: _StageBinding,
) -> ModelOperationSummary:
    """Complete C1 evidence and expose only its reconciliation-safe operation total.

    C1 itself verifies the model's observed ``requests_completed`` delta.  The
    reconciliation layer deliberately receives only the corresponding safe
    count derived from the typed attempt records, never a model endpoint,
    prompt, response, or model-process detail.
    """

    try:
        attempts, prime = _stage_model_attempts(private_run_dir, stage, binding.cache_lane)
        session.complete(attempts, prime_record=prime)
        return ModelOperationSummary(
            requests_completed_delta=sum(record.status == "succeeded" for record in attempts)
            + (1 if prime is not None else 0),
            prime_count=1 if prime is not None else 0,
        )
    except QualificationRuntimeFailure:
        # Force C1 to retain a categorical post-probe failure artifact even if
        # the runner ledger was missing, stale, or malformed.
        try:
            session.complete([{}])
        except ModelEvidenceSessionFailure as error:
            raise QualificationRuntimeFailure(error.category) from None
        raise QualificationRuntimeFailure("runtime_model_attempt_invalid") from None
    except ModelEvidenceSessionFailure as error:
        raise QualificationRuntimeFailure(error.category) from None


def _begin_proxy_reconciliation(
    runner: RuntimeCommandRunner,
    container_id: str,
    spec: _RuntimeSpec,
    binding: _StageBinding,
    attestation_path: Path,
) -> ProxyReconciliationSession:
    """Take the mandatory zero-metric snapshot immediately before a proxy child.

    The identity contains only pre-action material.  Ledger hashes are not
    available until after the child and model-evidence completion, so they are
    intentionally bound only by ``_complete_proxy_reconciliation``.
    """

    if binding.cache_lane not in {"cold", "warm-prefix"}:
        raise QualificationRuntimeFailure("runtime_reconciliation_invalid")
    cache_lane = cast(Literal["cold", "warm-prefix"], binding.cache_lane)
    try:
        identity = ReconciliationIdentity(
            run_manifest_sha256=spec.manifest_sha256,
            campaign_id_sha256=binding.campaign_id_sha256,
            slot_ordinal=binding.slot_ordinal,
            cache_lane=cache_lane,
            pair_index=binding.pair_index,
            attestation_sha256=_private_file_sha256(
                attestation_path, "runtime_reconciliation_invalid"
            ),
        )
        return ProxyReconciliationSession.begin(
            identity,
            _ContainerMetricsReader(runner, container_id, spec.proxy.container_port),
        )
    except (ReconciliationFailure, QualificationRuntimeFailure) as error:
        raise QualificationRuntimeFailure(error.category) from None


def _complete_proxy_reconciliation(
    session: ProxyReconciliationSession,
    spec: _RuntimeSpec,
    binding: _StageBinding,
    attestation_path: Path,
    private_run_dir: Path,
    model_summary: ModelOperationSummary,
) -> str:
    """Bind all post-action ledgers and retain the exact passed reconciliation.

    Readers are owned by their deep modules.  This supervisor only connects
    their typed, hash-safe products; it never parses runner JSONL or prompt
    material ad hoc.
    """

    if binding.cache_lane not in {"cold", "warm-prefix"}:
        raise QualificationRuntimeFailure("runtime_reconciliation_invalid")
    cache_lane = cast(Literal["cold", "warm-prefix"], binding.cache_lane)
    observer_path = _observer_ledger_path(private_run_dir, "score-proxy")
    request_path = _proxy_request_ledger_path(private_run_dir, "score-proxy")
    evidence_path = _model_evidence_path(private_run_dir, "score-proxy")
    try:
        context = ReconciliationContext(
            run_manifest_sha256=spec.manifest_sha256,
            campaign_id_sha256=binding.campaign_id_sha256,
            slot_ordinal=binding.slot_ordinal,
            cache_lane=cache_lane,
            pair_index=binding.pair_index,
            attestation_sha256=_private_file_sha256(
                attestation_path, "runtime_reconciliation_invalid"
            ),
            model_evidence_sha256=_private_file_sha256(
                evidence_path, "runtime_reconciliation_invalid"
            ),
            observer_ledger_sha256=_private_file_sha256(
                observer_path, "runtime_reconciliation_invalid"
            ),
            request_ledger_sha256=_private_file_sha256(
                request_path, "runtime_reconciliation_invalid"
            ),
        )
        result = session.complete(
            context,
            read_model_boundary_observer_records(observer_path),
            read_request_accounting_ledger(request_path),
            model_summary,
            _proxy_reconciliation_path(private_run_dir),
        )
    except (ReconciliationFailure, QualificationRuntimeFailure) as error:
        raise QualificationRuntimeFailure(error.category) from None
    except PreflightFailure:
        raise QualificationRuntimeFailure("runtime_reconciliation_invalid") from None
    if result.status != "passed" or _SHA256.fullmatch(result.file_sha256) is None:
        raise QualificationRuntimeFailure("runtime_reconciliation_invalid")
    return result.file_sha256


def _write_attestation(
    path: Path,
    spec: _RuntimeSpec,
    stage: RuntimeStage,
    instance: str,
    image_id: str,
    model_session: ModelEvidenceSession,
) -> None:
    runtime_contract_sha256 = _runtime_contract_sha256(spec, model_session.model_identity_sha256)
    record = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_attestation",
        "status": "passed",
        "stage": _attestation_stage(stage),
        "source_commit": spec.source_commit,
        "image_digest": spec.image.digest,
        "run_manifest_sha256": spec.manifest_sha256,
        "model_id_sha256": _canonical_sha256(spec.model.public_id),
        "benchmark_revision": spec.benchmark.revision,
        "scenario_order": {
            "sha256": spec.benchmark.scenario_order_sha256,
            "count": spec.benchmark.scenario_count,
        },
        "model_identity_sha256": model_session.model_identity_sha256,
        "runtime_contract_sha256": runtime_contract_sha256,
        "runtime_instance_sha256": _runtime_instance_sha256(stage, instance, image_id, runtime_contract_sha256),
        "checks": {key: True for key in _CHECK_KEYS},
    }
    _atomic_write_no_clobber(path, record)


def _write_outcome(
    path: Path,
    stage: RuntimeStage,
    status: OutcomeStatus,
    action_exit_code: int | None,
    failure_category: str | None,
    *,
    run_manifest_sha256: str | None,
    attestation_sha256: str | None,
    model_evidence_sha256: str | None,
    output_ledger_sha256: str | None,
    output_record_count: int,
    proxy_reconciliation_sha256: str | None,
    binding: _StageBinding | None,
) -> None:
    if failure_category is not None and _FAILURE_CATEGORY.fullmatch(failure_category) is None:
        failure_category = "runtime_internal_failure"
    record = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_outcome",
        "stage": _outcome_stage(stage),
        "status": status,
        "action_exit_code": action_exit_code,
        "failure_category": failure_category,
        "run_manifest_sha256": run_manifest_sha256,
        "attestation_sha256": attestation_sha256,
        "model_evidence_sha256": model_evidence_sha256,
        "output_ledger_sha256": output_ledger_sha256,
        "output_record_count": output_record_count,
        "proxy_reconciliation_sha256": proxy_reconciliation_sha256,
        "campaign_id_sha256": binding.campaign_id_sha256 if binding is not None else None,
        "slot_ordinal": binding.slot_ordinal if binding is not None else None,
        "cache_lane": binding.cache_lane if binding is not None else None,
        "pair_index": binding.pair_index if binding is not None else None,
    }
    _atomic_write_no_clobber(path, record)


def _outcome_evidence(
    attestation_path: Path | None, model_evidence_path: Path, output_ledger: Path
) -> tuple[str | None, str | None, str | None, int, str | None]:
    try:
        attestation_sha256 = (
            _private_file_sha256(attestation_path, "runtime_attestation_invalid") if attestation_path else None
        )
    except QualificationRuntimeFailure as error:
        return None, None, None, 0, error.category
    try:
        model_evidence_sha256 = _private_file_sha256(model_evidence_path, "runtime_model_evidence_invalid")
    except QualificationRuntimeFailure as error:
        return attestation_sha256, None, None, 0, error.category
    if not (output_ledger.exists() or output_ledger.is_symlink()):
        return attestation_sha256, model_evidence_sha256, None, 0, None
    try:
        output_ledger_sha256, output_record_count = _output_ledger_evidence(output_ledger)
    except QualificationRuntimeFailure as error:
        return attestation_sha256, model_evidence_sha256, None, 0, error.category
    return attestation_sha256, model_evidence_sha256, output_ledger_sha256, output_record_count, None


def _require_complete_output(path: Path, stage: RuntimeStage, spec: _RuntimeSpec) -> None:
    _digest, count = _output_ledger_evidence(path)
    expected = 5 if stage == "preflight" else spec.benchmark.scenario_count
    if count != expected:
        raise QualificationRuntimeFailure("runtime_output_ledger_incomplete")


def _output_ledger_evidence(path: Path) -> tuple[str, int]:
    serialized = _read_private_file(path, "runtime_output_ledger_invalid")
    if serialized and not serialized.endswith(b"\n"):
        raise QualificationRuntimeFailure("runtime_output_ledger_invalid")
    count = 0
    for line in serialized.splitlines():
        if not line:
            raise QualificationRuntimeFailure("runtime_output_ledger_invalid")
        try:
            value = json.loads(line, object_pairs_hook=_unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise QualificationRuntimeFailure("runtime_output_ledger_invalid") from error
        if not isinstance(value, dict):
            raise QualificationRuntimeFailure("runtime_output_ledger_invalid")
        count += 1
    return hashlib.sha256(serialized).hexdigest(), count


def _private_file_sha256(path: Path, category: str) -> str:
    return hashlib.sha256(_read_private_file(path, category)).hexdigest()


def _read_private_file(path: Path, category: str) -> bytes:
    descriptor: int | None = None
    try:
        file_status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(file_status.st_mode) or stat.S_IMODE(file_status.st_mode) != 0o600:
            raise QualificationRuntimeFailure(category)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened_status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or stat.S_IMODE(opened_status.st_mode) != 0o600
            or (opened_status.st_dev, opened_status.st_ino) != (file_status.st_dev, file_status.st_ino)
        ):
            raise QualificationRuntimeFailure(category)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except QualificationRuntimeFailure:
        raise
    except OSError as error:
        raise QualificationRuntimeFailure(category) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_write_no_clobber(path: Path, record: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise QualificationRuntimeFailure("runtime_evidence_exists")
    payload = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
            temporary.unlink()
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileExistsError as error:
            temporary.unlink(missing_ok=True)
            raise QualificationRuntimeFailure("runtime_evidence_exists") from error
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    except OSError as error:
        raise QualificationRuntimeFailure("runtime_evidence_write_failed") from error


def _validate_stage_evidence_absent(
    private_run_dir: Path, stage: RuntimeStage, binding: _StageBinding
) -> None:
    if any(
        path.exists() or path.is_symlink()
        for path in _reserved_stage_paths(private_run_dir, stage, binding)
    ):
        raise QualificationRuntimeFailure("runtime_evidence_exists")


def _validate_existing_preflight_attestation(private_run_dir: Path, spec: _RuntimeSpec) -> Path:
    path = _attestation_path(private_run_dir, "preflight")
    try:
        serialized = _read_private_file(path, "runtime_preflight_attestation_invalid")
        value = json.loads(serialized, object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise QualificationRuntimeFailure("runtime_preflight_attestation_invalid") from error
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
        "model_identity_sha256",
        "runtime_contract_sha256",
        "runtime_instance_sha256",
        "checks",
    }
    order = value.get("scenario_order") if isinstance(value, dict) else None
    checks = value.get("checks") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != root_keys
        or value.get("schema_version") != "1.0"
        or value.get("record_type") != "qualification_runtime_attestation"
        or value.get("status") != "passed"
        or value.get("stage") != "preflight"
        or value.get("source_commit") != spec.source_commit
        or value.get("image_digest") != spec.image.digest
        or value.get("run_manifest_sha256") != spec.manifest_sha256
        or value.get("model_id_sha256") != _canonical_sha256(spec.model.public_id)
        or value.get("benchmark_revision") != spec.benchmark.revision
        or not isinstance(order, dict)
        or order != {"sha256": spec.benchmark.scenario_order_sha256, "count": spec.benchmark.scenario_count}
        or not isinstance(value.get("model_identity_sha256"), str)
        or _SHA256.fullmatch(value["model_identity_sha256"]) is None
        or not isinstance(value.get("runtime_contract_sha256"), str)
        or _SHA256.fullmatch(value["runtime_contract_sha256"]) is None
        or not isinstance(value.get("runtime_instance_sha256"), str)
        or _SHA256.fullmatch(value["runtime_instance_sha256"]) is None
        or not isinstance(checks, dict)
        or set(checks) != set(_CHECK_KEYS)
        or any(item is not True for item in checks.values())
    ):
        raise QualificationRuntimeFailure("runtime_preflight_attestation_invalid")
    return path


def _attestation_model_identity(path: Path) -> str:
    try:
        value = json.loads(
            _read_private_file(path, "runtime_preflight_attestation_invalid"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise QualificationRuntimeFailure("runtime_preflight_attestation_invalid") from None
    identity = value.get("model_identity_sha256") if isinstance(value, dict) else None
    if not isinstance(identity, str) or _SHA256.fullmatch(identity) is None:
        raise QualificationRuntimeFailure("runtime_preflight_attestation_invalid")
    return identity


def _validate_prior_outcome(
    private_run_dir: Path,
    stage: Literal["preflight", "score-direct"],
    spec: _RuntimeSpec,
    attestation_path: Path,
    binding: _StageBinding,
) -> None:
    """Require immutable passed evidence before a later scored treatment begins."""

    path = _outcome_path(private_run_dir, stage)
    try:
        model_identity_sha256 = _attestation_model_identity(attestation_path)
        evidence_stage: Literal["preflight", "score-direct", "score-proxy"] = (
            "preflight" if stage == "preflight" else "score-direct"
        )
        prior_binding = (
            _StageBinding(
                binding.campaign_id_sha256,
                0,
                "preflight",
                0,
                f"{spec.campaign.campaign_id}-preflight",
                private_run_dir,
            )
            if stage == "preflight"
            else binding
        )
        load_runtime_outcome(
            path,
            expected_stage=_outcome_stage(stage),
            run_manifest_sha256=spec.manifest_sha256,
            attestation=attestation_path,
            model_evidence=_model_evidence_path(private_run_dir, stage),
            model_identity_sha256=model_identity_sha256,
            model_contract_sha256=None,
            output_ledger=_scored_ledger_path(private_run_dir, stage),
            expected_output_record_count=5 if stage == "preflight" else spec.benchmark.scenario_count,
            campaign_id_sha256=prior_binding.campaign_id_sha256,
            slot_ordinal=prior_binding.slot_ordinal,
            cache_lane=prior_binding.cache_lane,
            pair_index=prior_binding.pair_index,
        )
        # Keep the static stage mapping visible to type checking and future
        # schema changes: C1's output stage is part of the prior-evidence gate.
        load_model_evidence(
            _model_evidence_path(private_run_dir, stage),
            expected_stage=evidence_stage,
            run_manifest_sha256=spec.manifest_sha256,
            model_identity_sha256=model_identity_sha256,
        )
    except (
        QualificationRuntimeFailure,
        PreflightFailure,
        RuntimeOutcomeFailure,
        ModelEvidenceArtifactFailure,
    ):
        raise QualificationRuntimeFailure("runtime_prior_outcome_invalid") from None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _cleanup_runtime(
    runner: RuntimeCommandRunner,
    observer: ManagedProcess | None,
    proxy_name: str | None,
    initializer_name: str | None,
    volume_name: str | None,
    *,
    proxy_attempted: bool,
    initializer_attempted: bool,
    volume_attempted: bool,
    spec_manifest_sha256: str | None,
    instance: str | None,
    stage: RuntimeStage,
) -> bool:
    failed = False
    if observer is not None:
        try:
            if observer.poll() is None:
                observer.terminate()
                observer.wait(timeout=10)
        except Exception:
            try:
                observer.kill()
                observer.wait(timeout=5)
            except Exception:
                failed = True
    if proxy_name is not None and proxy_attempted:
        try:
            failed = failed or _remove_owned_container(
                runner,
                proxy_name,
                spec_manifest_sha256,
                instance,
                stage,
                "proxy",
            )
        except Exception:
            failed = True
    if initializer_name is not None and initializer_attempted:
        try:
            failed = failed or _remove_owned_container(
                runner,
                initializer_name,
                spec_manifest_sha256,
                instance,
                stage,
                "initializer",
            )
        except Exception:
            failed = True
    if volume_name is not None and volume_attempted:
        try:
            failed = failed or _remove_owned_volume(runner, volume_name, spec_manifest_sha256, instance, stage)
        except Exception:
            failed = True
    return failed


def _remove_owned_container(
    runner: RuntimeCommandRunner,
    name: str,
    manifest_sha256: str | None,
    instance: str | None,
    stage: RuntimeStage,
    resource: Literal["initializer", "proxy"],
) -> bool:
    """Delete only a predeclared resource after proving its exact labels, if it exists."""

    result = runner.run(("docker", "container", "inspect", "--format", "{{json .Config.Labels}}", name))
    if result.returncode != 0:
        return not _resource_is_absent(result)
    if not _owned_container_labels(result.stdout, manifest_sha256, instance, stage, resource):
        return True
    return runner.run(("docker", "rm", "--force", name)).returncode != 0


def _remove_owned_volume(
    runner: RuntimeCommandRunner,
    volume_name: str,
    manifest_sha256: str | None,
    instance: str | None,
    stage: RuntimeStage,
) -> bool:
    """Delete only the predeclared labelled secret volume, after both containers are resolved."""

    result = runner.run(("docker", "volume", "inspect", "--format", "{{json .Labels}}", volume_name))
    if result.returncode != 0:
        return not _resource_is_absent(result)
    if not _owned_volume_labels(result.stdout, manifest_sha256, instance, stage):
        return True
    return runner.run(("docker", "volume", "rm", volume_name)).returncode != 0


def _owned_container(
    runner: RuntimeCommandRunner,
    container_id: str,
    manifest_sha256: str | None,
    instance: str | None,
    stage: RuntimeStage,
    resource: Literal["initializer", "proxy"],
) -> bool:
    result = runner.run(("docker", "container", "inspect", "--format", "{{json .Config.Labels}}", container_id))
    if result.returncode != 0:
        return False
    return _owned_container_labels(result.stdout, manifest_sha256, instance, stage, resource)


def _resource_is_absent(result: CommandResult) -> bool:
    """Accept a Docker not-found response but fail closed for other cleanup inspection failures."""

    return result.returncode == 1 and "no such" in result.stderr.lower()


def _owned_container_labels(
    serialized: str,
    manifest_sha256: str | None,
    instance: str | None,
    stage: RuntimeStage,
    resource: Literal["initializer", "proxy"],
) -> bool:
    if manifest_sha256 is None or instance is None:
        return False
    value = _parse_command_json_or_none(serialized)
    return (
        isinstance(value, dict)
        and value.get(f"{_LABEL_PREFIX}.manifest") == manifest_sha256
        and value.get(f"{_LABEL_PREFIX}.instance") == instance
        and value.get(f"{_LABEL_PREFIX}.stage") == _attestation_stage(stage)
        and value.get(f"{_LABEL_PREFIX}.resource") == resource
    )


def _owned_volume_labels(
    serialized: str, manifest_sha256: str | None, instance: str | None, stage: RuntimeStage
) -> bool:
    if manifest_sha256 is None or instance is None:
        return False
    value = _parse_command_json_or_none(serialized)
    return (
        isinstance(value, dict)
        and value.get(f"{_LABEL_PREFIX}.manifest") == manifest_sha256
        and value.get(f"{_LABEL_PREFIX}.instance") == instance
        and value.get(f"{_LABEL_PREFIX}.stage") == _attestation_stage(stage)
        and value.get(f"{_LABEL_PREFIX}.resource") == "secrets-volume"
    )


def _runtime_contract_sha256(spec: _RuntimeSpec, model_identity_sha256: str) -> str:
    return _canonical_sha256(
        {
            "source_commit": spec.source_commit,
            "image_digest": spec.image.digest,
            "run_manifest_sha256": spec.manifest_sha256,
            "model_id_sha256": _canonical_sha256(spec.model.public_id),
            # This is intentionally lane/stage independent: the preflight
            # attestation authorizes both cold and warm scored slots.  C1's
            # full lane-specific model contract is bound by model evidence and
            # the runtime outcome instead.
            "model_identity_sha256": model_identity_sha256,
            "benchmark": {
                "revision": spec.benchmark.revision,
                "tree": spec.benchmark.tree,
                "package": spec.benchmark.package,
                "interpreter_sha256": spec.benchmark.interpreter_sha256,
                "agentic_set": spec.benchmark.agentic_set,
                "scenario_order": {
                    "sha256": spec.benchmark.scenario_order_sha256,
                    "count": spec.benchmark.scenario_count,
                },
            },
            "settings_sha256": _canonical_sha256(spec.proxy.settings),
            "routes_sha256": _canonical_sha256(
                {
                    "observer_host": spec.observer.host,
                    "observer_port": spec.observer.port,
                    "observer_container_url": spec.observer.container_url,
                    "proxy_host": spec.proxy.host,
                    "proxy_port": spec.proxy.port,
                    "proxy_container_port": spec.proxy.container_port,
                }
            ),
            "resources": {
                "uid": spec.image.uid,
                "gid": spec.image.gid,
                "cpus": _decimal_text(spec.proxy.cpus),
                "memory_bytes": spec.proxy.memory_bytes,
                "pids_limit": spec.proxy.pids_limit,
                "stop_timeout_seconds": spec.proxy.stop_timeout_seconds,
            },
            "auth_roles": {
                "ordinary": True,
                "qualification": True,
                "upstream": spec.model.upstream_authenticated,
            },
        }
    )


def _runtime_instance_sha256(stage: RuntimeStage, instance: str, image_id: str, runtime_contract_sha256: str) -> str:
    return _canonical_sha256(
        {
            "runtime_contract_sha256": runtime_contract_sha256,
            "stage": _attestation_stage(stage),
            "supervisor_instance": instance,
            "image_id": image_id,
            "attestation_schema": "1.0",
        }
    )


def _attestation_stage(stage: RuntimeStage) -> AttestationStage:
    if stage == "preflight":
        return "preflight"
    if stage == "score-proxy":
        return "scored_proxy"
    raise QualificationRuntimeFailure("runtime_stage_invalid")


def _outcome_stage(stage: RuntimeStage) -> OutcomeStage:
    outcomes: dict[RuntimeStage, OutcomeStage] = {
        "preflight": "preflight",
        "score-direct": "scored-direct",
        "score-proxy": "scored-proxy",
    }
    return outcomes[stage]


def _attestation_path(private_run_dir: Path, stage: RuntimeStage) -> Path:
    if stage == "preflight":
        return private_run_dir / "preflight-runtime-attestation.json"
    if stage == "score-proxy":
        return private_run_dir / "scored-proxy-runtime-attestation.json"
    raise QualificationRuntimeFailure("runtime_stage_invalid")


def _outcome_path(private_run_dir: Path, stage: RuntimeStage) -> Path:
    return private_run_dir / f"{_outcome_stage(stage)}-runtime-outcome.json"


def _observer_ledger_path(private_run_dir: Path, stage: RuntimeStage) -> Path:
    if stage == "preflight":
        return private_run_dir / "preflight-proxy-model-boundary.jsonl"
    if stage == "score-proxy":
        return private_run_dir / "scored-proxy-model-boundary.jsonl"
    raise QualificationRuntimeFailure("runtime_stage_invalid")


def _proxy_request_ledger_path(private_run_dir: Path, stage: RuntimeStage) -> Path:
    """Return the one runner-owned request-accounting ledger for a proxy stage."""

    if stage == "preflight":
        return private_run_dir / "preflight-proxy-requests.jsonl"
    if stage == "score-proxy":
        return private_run_dir / "scored-proxy-requests.jsonl"
    raise QualificationRuntimeFailure("runtime_stage_invalid")


def _proxy_reconciliation_path(private_run_dir: Path) -> Path:
    return private_run_dir / "scored-proxy-reconciliation.json"


def _direct_attempt_ledger_path(private_run_dir: Path, stage: RuntimeStage) -> Path | None:
    if stage == "preflight":
        return private_run_dir / "preflight-direct-model-boundary.jsonl"
    if stage == "score-direct":
        return private_run_dir / "scored-direct-model-boundary.jsonl"
    return None


def _direct_attempt_ledger_path_required(private_run_dir: Path, stage: RuntimeStage) -> Path:
    path = _direct_attempt_ledger_path(private_run_dir, stage)
    if path is None:
        raise QualificationRuntimeFailure("runtime_stage_invalid")
    return path


def _prime_attempt_ledger_path(
    private_run_dir: Path,
    stage: RuntimeStage,
    lane: CampaignLane,
) -> Path | None:
    if lane != "warm-prefix" or stage == "preflight":
        return None
    if stage == "score-direct":
        return private_run_dir / "scored-direct-prime-model-boundary.jsonl"
    if stage == "score-proxy":
        return private_run_dir / "scored-proxy-prime-model-boundary.jsonl"
    raise QualificationRuntimeFailure("runtime_stage_invalid")


def _model_evidence_path(private_run_dir: Path, stage: RuntimeStage) -> Path:
    return private_run_dir / f"{_outcome_stage(stage)}-model-cache-evidence.json"


def _scored_ledger_path(private_run_dir: Path, stage: RuntimeStage) -> Path:
    if stage == "preflight":
        return private_run_dir / "preflight.jsonl"
    if stage == "score-direct":
        return private_run_dir / "scored-direct.jsonl"
    if stage == "score-proxy":
        return private_run_dir / "scored-proxy.jsonl"
    raise QualificationRuntimeFailure("runtime_stage_invalid")


def _instance_token(manifest_sha256: str, stage: RuntimeStage) -> str:
    """Return a fresh opaque supervisor instance, never derived from a host path."""

    return _canonical_sha256(
        {"manifest": manifest_sha256, "stage": _attestation_stage(stage), "nonce": uuid.uuid4().hex}
    )[:24]


def _observer_identity(manifest_sha256: str, instance: str) -> str:
    """Bind the health endpoint to this supervisor without exposing private routing data."""

    return _canonical_sha256({"manifest": manifest_sha256, "instance": instance, "kind": "observer"})


def _volume_name(instance: str) -> str:
    return f"shiftedx-qualification-secrets-{instance}"


def _initializer_name(instance: str, stage: RuntimeStage) -> str:
    return f"shiftedx-qualification-initializer-{_attestation_stage(stage)}-{instance}"


def _container_name(instance: str, stage: RuntimeStage) -> str:
    return f"shiftedx-qualification-{_attestation_stage(stage)}-{instance}"


def _parse_command_json(value: str, category: str) -> dict[str, Any]:
    parsed = _parse_command_json_or_none(value)
    if not isinstance(parsed, dict):
        raise QualificationRuntimeFailure(category)
    return parsed


def _parse_command_json_or_none(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _exact_object(value: Any, keys: set[str] | frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return cast(dict[str, Any], value)


def _exact_string(value: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or pattern.fullmatch(candidate) is None:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return candidate


def _required_text(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return value


def _absolute_path(value: Any) -> Path:
    raw_path = _required_text(value)
    path = Path(raw_path)
    if not path.is_absolute() or "," in raw_path:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return path


def _safe_absolute_http_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    try:
        _ = parsed.port
    except ValueError as error:
        raise QualificationRuntimeFailure("runtime_manifest_invalid") from error
    return value.rstrip("/")


def _loopback_host(value: str) -> str:
    if value not in {"127.0.0.1", "::1"}:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return value


def _port(value: Any) -> int:
    result = _positive_int(value)
    if result > 65535:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return result


def _positive_int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return value


def _positive_decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise QualificationRuntimeFailure("runtime_manifest_invalid") from error
    if not decimal.is_finite() or decimal <= 0:
        raise QualificationRuntimeFailure("runtime_manifest_invalid")
    return decimal


def _decimal_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _env_bool(value: Any) -> str:
    return "true" if value is True else "false"


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host
