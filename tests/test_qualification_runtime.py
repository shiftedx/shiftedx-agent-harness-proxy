from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from base64 import urlsafe_b64encode
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import shiftedx_harness_proxy.qualification_runtime as runtime_module
from shiftedx_harness_proxy.qualification_campaign import (
    CampaignFailure,
    CampaignSlot,
    ReadinessResult,
    StageRequest,
    advance_qualification_campaign,
)
from shiftedx_harness_proxy.qualification_contract import (
    BENCHMARK_REVISION,
    CacheObservation,
    ModelBoundaryRecord,
    model_boundary_fingerprint,
    write_model_boundary_attempt_ledger,
)
from shiftedx_harness_proxy.qualification_model_evidence import model_endpoint_contract_hashes
from shiftedx_harness_proxy.qualification_reconciliation import (
    RequestAccountingRecord,
    write_request_accounting_ledger,
)
from shiftedx_harness_proxy.qualification_runtime import RuntimeLease


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _private_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def _record_row(root: Path, path: Path) -> str:
    digest = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode("ascii").rstrip("=")
    return f"{path.relative_to(root).as_posix()},sha256={digest},{path.stat().st_size}"


def _mtplx_settings() -> dict[str, object]:
    """Literal safe MTPLX 2.7.1 projection used by the fake read-only endpoint."""

    return {
        "ok": True,
        "reasoning": "auto",
        "enable_thinking": True,
        "preserve_thinking": "auto",
        "preserve_thinking_effective": True,
        "reasoning_history_mode": "preserve",
        "reasoning_parser": "qwen3",
        "reasoning_effort": "medium",
        "generation_mode": "mtp",
        "depth": 3,
        "depth_max": 8,
        "backend_id": "qwen3",
        "architecture_id": "qwen3",
        "model_family": "qwen",
        "support_level": "supported",
        "model_controls": {"reasoning": "native", "model_ref": "/private/model"},
        "reasoning_policy": {"enabled": True},
        "kv_quant_policy": {"mode": "none"},
        "tune_policy": {"enabled": False},
        "context_window_policy": {"maximum": 32768},
        "sampling_defaults": {"temperature": 0.0},
        "temperature": 0.0,
        "top_p": 0.95,
        "top_k": 20,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "max_response_tokens": 1024,
        "stream_interval": 1,
        "draft_control": {"enabled": True},
        "draft_temperature": 0.0,
        "draft_top_p": 0.95,
        "draft_top_k": 20,
        "prefill_chunk_tokens": 2048,
        "api_key_required": True,
        "api_key_source": "file",
        "tool_prompt_mode": "native",
        "tool_contract_active": True,
        "tool_contract_policy_version": "v1",
        "chat_template_profile": "default",
        "chat_template_hash": "a" * 64,
        "metal_memory_caps": {"applied": False},
        "ssd_session_cache": "off",
        "ssd_session_cache_max_size": "100GB",
        "ssd_session_cache_min_prefix_tokens": 512,
        "paged_kv_quantization": "none",
        "restart_required_settings": ["model"],
        "ram_session_cache_policy": "minimal",
        "ram_session_block_prefix_restore": False,
        "ram_session_cache_max_entries": 1,
        "ram_session_cache_max_size": "1G",
        "ram_session_cache_per_session_max_size": "1G",
    }


def _model_manifest_fields(tmp_path: Path) -> dict[str, object]:
    stage = tmp_path / "mtplx-stage"
    stage.mkdir()
    identity = _private_file(tmp_path / "mtplx-identity.json", b'{"identity":"safe"}\n')
    inspect = _private_file(tmp_path / "mtplx-inspect.json", b'{"inspect":"safe"}\n')
    distribution = tmp_path / "mtplx-site-packages"
    distribution.mkdir()
    dist_info = distribution / "mtplx-2.7.1.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: mtplx\nVersion: 2.7.1\n\n", encoding="utf-8")
    module = distribution / "mtplx.py"
    module.write_text("__version__ = '2.7.1'\n", encoding="utf-8")
    record = dist_info / "RECORD"
    record.write_text(
        "\n".join(
            (
                _record_row(distribution, module),
                _record_row(distribution, metadata),
                "mtplx-2.7.1.dist-info/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    runtime_executable = Path(sys.executable).resolve(strict=True)
    command = (
        str(runtime_executable),
        "--host",
        "127.0.0.1",
        "--port",
        "19999",
        "--no-auth",
        "--generation-mode",
        "mtp",
        "--depth",
        "3",
        "--temperature",
        "0",
        "--ssd-session-cache",
        "off",
    )
    health = {
        "ok": True,
        "active_requests": 0,
        "foreground_active": 0,
        "requests_completed": 0,
        "startup": {"pid": 444, "started_at": 1712345678.25, "launch_id": None},
    }
    health_hash, settings_hash = model_endpoint_contract_hashes(health, _mtplx_settings())
    return {
        "public_id": "private-model-id",
        "upstream_url": "http://127.0.0.1:19999/v1",
        "upstream_authenticated": True,
        "stage_path": str(stage),
        "stage_revision": "d" * 40,
        "identity_ledger": str(identity),
        "identity_ledger_sha256": hashlib.sha256(identity.read_bytes()).hexdigest(),
        "inspect_artifact": str(inspect),
        "inspect_artifact_sha256": hashlib.sha256(inspect.read_bytes()).hexdigest(),
        "runtime_executable": str(runtime_executable),
        "runtime_executable_sha256": hashlib.sha256(runtime_executable.read_bytes()).hexdigest(),
        "mtplx_distribution_root": str(distribution),
        "mtplx_record": str(record),
        "mtplx_version": "2.7.1",
        "launch_command_sha256": _canonical_sha256(list(command)),
        "required_launch_flags": [
            "--host=127.0.0.1",
            "--port=19999",
            "--no-auth",
            "--generation-mode=mtp",
            "--depth=3",
            "--temperature=0",
            "--ssd-session-cache=off",
        ],
        "health_contract_sha256": health_hash,
        "settings_contract_sha256": settings_hash,
    }


def _manifest(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    secrets = tmp_path / "private-credentials"
    secrets.mkdir(mode=0o700)
    values = {
        "ordinary_proxy_api_key_file": "dummy-ordinary-credential-value",
        "qualification_policy_api_key_file": "dummy-policy-credential-value",
        "upstream_model_api_key_file": "dummy-upstream-credential-value",
    }
    credential_paths: dict[str, str] = {}
    for field, value in values.items():
        path = secrets / field
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
        credential_paths[field] = str(path)
    benchmark = _benchmark_checkout(tmp_path)
    scenario_order = ["case-1", "case-2"]
    document = {
        "qualification_runtime": {
            "schema_version": "1.0",
            "source_commit": "a" * 40,
            "image": {
                "reference": "registry.invalid/shiftedx/proxy@sha256:" + "b" * 64,
                "digest": "sha256:" + "b" * 64,
                "uid": 10001,
                "gid": 10001,
            },
            "model": _model_manifest_fields(tmp_path),
            "benchmark": {
                "revision": benchmark["revision"],
                "tree": benchmark["tree"],
                "package": "shiftedx-bench==0.5.1",
                "checkout_path": benchmark["checkout_path"],
                "interpreter_sha256": benchmark["interpreter_sha256"],
                "agentic_set": "expanded",
                "sampler_profile": "corrected-parity-v1",
                "scenario_order_sha256": _canonical_sha256(scenario_order),
                "scenario_count": len(scenario_order),
            },
            "campaign": {
                "campaign_id": "qualification-campaign-1",
                "slots": [
                    {"cache_lane": "cold", "pair_index": 1, "run_id": "qualification-cold-pair-1"},
                    {"cache_lane": "cold", "pair_index": 2, "run_id": "qualification-cold-pair-2"},
                    {"cache_lane": "cold", "pair_index": 3, "run_id": "qualification-cold-pair-3"},
                    {
                        "cache_lane": "warm-prefix",
                        "pair_index": 1,
                        "run_id": "qualification-warm-pair-1",
                    },
                    {
                        "cache_lane": "warm-prefix",
                        "pair_index": 2,
                        "run_id": "qualification-warm-pair-2",
                    },
                    {
                        "cache_lane": "warm-prefix",
                        "pair_index": 3,
                        "run_id": "qualification-warm-pair-3",
                    },
                ],
                "stage_order": ["preflight", "score-direct", "score-proxy"],
                "treatment_order": ["direct", "proxy"],
                "model_instance_policy": "fresh-per-scored-treatment",
                "failure_policy": "terminal-no-rerun",
            },
            "observer": {
                "host": "127.0.0.1",
                "port": 18092,
                "container_url": "http://host.docker.internal:18092/v1",
            },
            "proxy": {
                "host": "127.0.0.1",
                "port": 19090,
                "container_port": 8090,
                "cpus": 1.0,
                "memory_bytes": 536870912,
                "pids_limit": 128,
                "stop_timeout_seconds": 20,
                "settings": {
                    "deployment_profile": "production",
                    "harness_profile": "shiftedx-harness-v1",
                    "upstream_tool_response_capability_mode": "phase_split",
                    "upstream_cache_capability_mode": "disabled",
                    "telemetry_enabled": True,
                    "metrics_enabled": True,
                    "max_internal_retries": 4,
                    "max_upstream_calls": 7,
                    "upstream_timeout_seconds": 120.0,
                    "total_request_deadline_seconds": 180.0,
                    "server_connection_limit": 24,
                    "admission_limit": 16,
                    "principal_concurrency_limit": 4,
                    "concurrency_limit": 32,
                    "require_receipt_when_tools_present": True,
                    "allow_harness_opt_out": False,
                    "log_level": "INFO",
                },
            },
            "credentials": credential_paths,
        }
    }
    path = tmp_path / "approved-manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _supervise(
    *,
    manifest: Path,
    stage: str,
    private_run_dir: Path,
    action,
    command_runner=None,
    cache_lane: str = "cold",
    pair_index: int = 1,
):
    """Exercise the internal per-stage primitive through an explicit StageRequest.

    Production reaches this primitive only through the campaign adapter.  The
    test adapter creates that same strict slot topology, then mirrors only
    fixture evidence into the historical compact assertion directory.
    """

    document = json.loads(manifest.read_text(encoding="utf-8"))
    runtime = document["qualification_runtime"]
    assert isinstance(runtime, dict)
    campaign = runtime["campaign"]
    assert isinstance(campaign, dict)
    manifest_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()
    slots_dir = private_run_dir / "slots"
    slots_dir.mkdir(mode=0o700, exist_ok=True)
    slots_dir.chmod(0o700)
    preflight_dir = slots_dir / "00-preflight-pair0"
    preflight_dir.mkdir(mode=0o700, exist_ok=True)
    preflight_dir.chmod(0o700)
    if stage == "preflight":
        slot = CampaignSlot(0, "preflight", 0, f"{campaign['campaign_id']}-preflight")
        sequence = 1
        stage_dir = preflight_dir
    else:
        slots = campaign["slots"]
        assert isinstance(slots, list)
        ordinal, selected = next(
            (index, value)
            for index, value in enumerate(slots, start=1)
            if isinstance(value, dict)
            and value.get("cache_lane") == cache_lane
            and value.get("pair_index") == pair_index
        )
        assert isinstance(selected, dict)
        slot = CampaignSlot(ordinal, cache_lane, pair_index, selected["run_id"])
        sequence = 2 + (ordinal - 1) * 2 + (0 if stage == "score-direct" else 1)
        stage_dir = slots_dir / f"{ordinal:02d}-{cache_lane}-pair{pair_index}"
        stage_dir.mkdir(mode=0o700, exist_ok=True)
        stage_dir.chmod(0o700)
        _sync_fixture_stage(private_run_dir, preflight_dir, "preflight")
        _sync_fixture_stage(private_run_dir, stage_dir, "scored-direct")
        _sync_fixture_stage(private_run_dir, stage_dir, "scored-proxy")
    _sync_fixture_stage(private_run_dir, stage_dir, "preflight" if stage == "preflight" else "")
    outcome_name = {
        "preflight": "preflight-runtime-outcome.json",
        "score-direct": "scored-direct-runtime-outcome.json",
        "score-proxy": "scored-proxy-runtime-outcome.json",
    }[stage]
    request = StageRequest(
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        sequence=sequence,
        slot=slot,
        stage=stage,
        private_run_dir=stage_dir,
        outcome_path=stage_dir / outcome_name,
    )
    result = runtime_module.supervise_qualification_runtime(
        manifest=manifest,
        stage=stage,
        private_run_dir=stage_dir,
        action=action,
        command_runner=command_runner,
        stage_request=request,
    )
    _mirror_fixture_stage(stage_dir, private_run_dir)
    return result


def _campaign_stage_request(
    manifest: Path,
    private_campaign_dir: Path,
    *,
    stage: str,
    cache_lane: str = "cold",
    pair_index: int = 1,
) -> StageRequest:
    """Build one exact core-derived request without a stage-selection fallback."""

    runtime = _manifest_document(manifest)["qualification_runtime"]
    assert isinstance(runtime, dict)
    campaign = runtime["campaign"]
    assert isinstance(campaign, dict)
    slots_dir = private_campaign_dir / "slots"
    slots_dir.mkdir(mode=0o700, exist_ok=True)
    slots_dir.chmod(0o700)
    manifest_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()
    outcome_names = {
        "preflight": "preflight-runtime-outcome.json",
        "score-direct": "scored-direct-runtime-outcome.json",
        "score-proxy": "scored-proxy-runtime-outcome.json",
    }
    assert stage in outcome_names
    if stage == "preflight":
        private_run_dir = slots_dir / "00-preflight-pair0"
        return StageRequest(
            manifest,
            manifest_sha256,
            1,
            CampaignSlot(0, "preflight", 0, f"{campaign['campaign_id']}-preflight"),
            "preflight",
            private_run_dir,
            private_run_dir / outcome_names[stage],
        )
    slots = campaign["slots"]
    assert isinstance(slots, list)
    ordinal, selected = next(
        (index, value)
        for index, value in enumerate(slots, start=1)
        if isinstance(value, dict)
        and value.get("cache_lane") == cache_lane
        and value.get("pair_index") == pair_index
    )
    assert isinstance(selected, dict)
    private_run_dir = slots_dir / f"{ordinal:02d}-{cache_lane}-pair{pair_index}"
    sequence = 2 + (ordinal - 1) * 2 + (0 if stage == "score-direct" else 1)
    return StageRequest(
        manifest,
        manifest_sha256,
        sequence,
        CampaignSlot(ordinal, cache_lane, pair_index, selected["run_id"]),
        stage,
        private_run_dir,
        private_run_dir / outcome_names[stage],
    )


def _fixture_stage_name(name: str, prefix: str) -> bool:
    if prefix == "preflight":
        return name == "preflight.jsonl" or name.startswith("preflight-")
    return bool(prefix) and name.startswith(prefix)


def _sync_fixture_stage(root: Path, target: Path, prefix: str) -> None:
    for source in root.iterdir():
        if source.is_file() and _fixture_stage_name(source.name, prefix):
            destination = target / source.name
            shutil.copyfile(source, destination)
            destination.chmod(source.stat().st_mode & 0o777)


def _mirror_fixture_stage(source_dir: Path, root: Path) -> None:
    for source in source_dir.iterdir():
        if source.is_file() and (
            source.name == "preflight.jsonl"
            or source.name.startswith(("preflight-", "scored-direct-", "scored-proxy-"))
            or source.name in {"scored-direct.jsonl", "scored-proxy.jsonl"}
        ):
            destination = root / source.name
            shutil.copyfile(source, destination)
            destination.chmod(source.stat().st_mode & 0o777)


def _benchmark_checkout(tmp_path: Path) -> dict[str, str]:
    """Create a minimal pinned source checkout rather than using an ambient package."""

    checkout = tmp_path / "shiftedx-bench-checkout"
    package_root = checkout / "src" / "shiftedx_bench"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("__all__ = []\n", encoding="utf-8")
    return {
        "revision": "335e6694e4aec13e9370af8a993d8c8f14d7ffb5",
        "tree": "c" * 40,
        "checkout_path": str(checkout),
        "interpreter_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
    }


def _tracked_benchmark_pyproject(*, version: str = "0.5.1") -> str:
    return "\n".join(
        (
            "[project]",
            'name = "shiftedx-bench"',
            f'version = "{version}"',
            "",
        )
    )


def _authoritative_benchmark_manifest(tmp_path: Path) -> tuple[Path, Path]:
    """Create a source-only committed Shiftedx Bench checkout for the public runtime seam."""

    manifest = _manifest(tmp_path)
    checkout = tmp_path / "authoritative-shiftedx-bench"
    package = checkout / "src" / "shiftedx_bench"
    package.mkdir(parents=True)
    (checkout / "pyproject.toml").write_text(
        "\n".join(
            (
                "[build-system]",
                'requires = ["hatchling>=1.27"]',
                'build-backend = "hatchling.build"',
                "",
                "[project]",
                'name = "shiftedx-bench"',
                'version = "0.5.1"',
                'requires-python = ">=3.11"',
                "",
                "[tool.hatch.build.targets.wheel]",
                'packages = ["src/shiftedx_bench"]',
                "",
            )
        ),
        encoding="utf-8",
    )
    (package / "__init__.py").write_text("__all__ = []\n", encoding="utf-8")
    for argv in (
        ("git", "init", str(checkout)),
        ("git", "-C", str(checkout), "add", "pyproject.toml", "src/shiftedx_bench/__init__.py"),
        (
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=Qualification Test",
            "-c",
            "user.email=qualification-test@example.invalid",
            "commit",
            "-m",
            "source fixture",
        ),
    ):
        subprocess.run(argv, check=True, capture_output=True, text=True)  # noqa: S603 - fixed test fixture vectors
    tree = subprocess.run(  # noqa: S603 - fixed test fixture vector
        ("git", "-C", str(checkout), "rev-parse", "HEAD^{tree}"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()  # noqa: S603 - fixed test fixture vector
    document = _manifest_document(manifest)
    benchmark = document["qualification_runtime"]["benchmark"]
    assert isinstance(benchmark, dict)
    benchmark.update(
        {
            "revision": BENCHMARK_REVISION,
            "tree": tree,
            "checkout_path": str(checkout),
            "interpreter_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        }
    )
    _store_manifest(manifest, document)
    return manifest, checkout


class _FakeProcess:
    def __init__(self, *, signal_on_terminate: bool = False) -> None:
        self.terminated = False
        self.waited = False
        self.exit_code: int | None = None
        self.signal_on_terminate = signal_on_terminate

    def poll(self) -> int | None:
        return self.exit_code

    def terminate(self) -> None:
        self.terminated = True
        if self.signal_on_terminate:
            os.kill(os.getpid(), signal.SIGTERM)

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.waited = True
        return 0

    def kill(self) -> None:
        self.terminated = True


def _zero_proxy_metrics() -> dict[str, int]:
    return {
        "downstream_requests": 0,
        "upstream_calls": 0,
        "blocked_duplicates": 0,
        "blocked_stalls": 0,
        "correction_turns": 0,
        "receipt_projections": 0,
        "local_projection_upstream_calls_avoided": 0,
        "errors": 0,
        "deadline_expiries": 0,
        "cancellations": 0,
        "phase_acquisition": 0,
        "phase_finalization": 0,
        "phase_schema_rejections": 0,
        "admission_rejections": 0,
        "rate_rejections": 0,
    }


class _FakeRuntimeRunner:
    _next_model_started_at = 1712345678

    def __init__(self, *, failure: str | None = None, drift: str | None = None) -> None:
        self.calls: list[tuple[str, tuple[str, ...], dict[str, str] | None]] = []
        self.observer = _FakeProcess(signal_on_terminate=failure == "signal_cleanup_observer")
        self.container_labels: dict[str, dict[str, str]] = {}
        self.volume_labels: dict[str, dict[str, str]] = {}
        self.volume_name = "expected-volume"
        self.failure = failure
        self.drift = drift
        self.container_running = True
        self.model_contract = None
        self.model_requests_completed = 0
        self.metrics_snapshots: list[dict[str, int]] = [_zero_proxy_metrics(), _zero_proxy_metrics()]
        self.metrics_reads = 0
        type(self)._next_model_started_at += 1
        self.model_started_at = float(type(self)._next_model_started_at)

    def prepare_model_evidence_contract(self, contract) -> None:
        self.model_contract = contract

    def _labels(self, argv: tuple[str, ...]) -> dict[str, str]:
        labels: dict[str, str] = {}
        for index, value in enumerate(argv[:-1]):
            if value == "--label":
                key, label_value = argv[index + 1].split("=", 1)
                labels[key] = label_value
        return labels

    def _capture_volume(self, argv: tuple[str, ...]) -> None:
        for value in argv:
            if value.startswith("type=volume,src="):
                self.volume_name = value.split(",", 2)[1].removeprefix("src=")

    def run(
        self, argv: tuple[str, ...], *, env: dict[str, str] | None = None, timeout: float | None = None
    ) -> SimpleNamespace:
        del timeout
        self.calls.append(("run", argv, env))
        if argv[0] == "/usr/sbin/lsof":
            return SimpleNamespace(returncode=0, stdout="p444\n", stderr="")
        if argv[0] == "/bin/ps":
            assert self.model_contract is not None
            if argv[-1] == "command=":
                command = " ".join(
                    (
                        str(self.model_contract.runtime_executable),
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "19999",
                        "--no-auth",
                        "--generation-mode",
                        "mtp",
                        "--depth",
                        "3",
                        "--temperature",
                        "0",
                        "--ssd-session-cache",
                        "off",
                    )
                )
                return SimpleNamespace(returncode=0, stdout=command + "\n", stderr="")
            if argv[-1] == "comm=":
                return SimpleNamespace(
                    returncode=0,
                    stdout=str(self.model_contract.runtime_executable) + "\n",
                    stderr="",
                )
            if argv[-1] == "lstart=":
                return SimpleNamespace(returncode=0, stdout="12345\n", stderr="")
        if argv[:4] == ("git", "-C", argv[2], "rev-parse"):
            if argv[-1] == "HEAD":
                target = "e" * 40 if self.failure == "benchmark_head" else "335e6694e4aec13e9370af8a993d8c8f14d7ffb5"
            else:
                target = "e" * 40 if self.failure == "benchmark_tree" else "c" * 40
            return SimpleNamespace(returncode=0, stdout=target + "\n", stderr="")
        if argv[:4] == ("git", "-C", argv[2], "status"):
            return SimpleNamespace(
                returncode=0,
                stdout=" M src/shiftedx_bench/__init__.py\n" if self.failure == "benchmark_dirty" else "",
                stderr="",
            )
        if argv[:4] == ("git", "-C", argv[2], "show"):
            return SimpleNamespace(
                returncode=0,
                stdout=_tracked_benchmark_pyproject(
                    version="0.5.0" if self.failure == "benchmark_project" else "0.5.1"
                ),
                stderr="",
            )
        if argv[:4] == (sys.executable, "-I", "-S", "-c"):
            assert env is None
            source = Path(argv[-1])
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "module": "/outside/shiftedx_bench/__init__.py"
                        if self.failure == "benchmark_source"
                        else str(source / "shiftedx_bench" / "__init__.py"),
                    }
                ),
                stderr="",
            )
        if argv[:3] == ("docker", "container", "ls") and self.failure == "stale":
            return SimpleNamespace(returncode=0, stdout="leftover-container\n", stderr="")
        if argv[:3] == ("docker", "image", "inspect"):
            if self.failure == "image":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            architecture = "amd64" if self.failure == "image_metadata" else "arm64"
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "Id": "sha256:" + "c" * 64,
                        "Architecture": architecture,
                        "Config": {"User": "10001:10001"},
                    }
                ),
                stderr="",
            )
        if argv[:3] == ("docker", "volume", "create"):
            if self.failure == "volume_create":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            self.volume_name = argv[-1]
            self.volume_labels[self.volume_name] = self._labels(argv)
            if self.failure == "signal_volume_create":
                os.kill(os.getpid(), signal.SIGTERM)
            return SimpleNamespace(returncode=0, stdout=self.volume_name + "\n", stderr="")
        if argv[:3] == ("docker", "run", "--detach"):
            if self.failure == "launch" and "--entrypoint" not in argv:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            name = argv[argv.index("--name") + 1]
            labels = self._labels(argv)
            identifier = "e" * 64 if "--entrypoint" in argv else "f" * 64
            self.container_labels[name] = labels
            self.container_labels[identifier] = labels
            self._capture_volume(argv)
            if (self.failure == "signal_initializer" and "--entrypoint" in argv) or (
                self.failure == "signal_launch" and "--entrypoint" not in argv
            ):
                os.kill(os.getpid(), signal.SIGTERM)
            if self.failure == "initializer" and "--entrypoint" in argv:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout=identifier + "\n", stderr="")
        if argv[:3] == ("docker", "container", "wait"):
            return SimpleNamespace(returncode=0, stdout="0\n", stderr="")
        if argv[:3] == ("docker", "container", "inspect"):
            if "{{json .Config.Labels}}" in argv:
                if self.failure == "cleanup_inspect":
                    return SimpleNamespace(returncode=125, stdout="", stderr="daemon unavailable")
                labels = self.container_labels.get(argv[-1])
                if labels is None:
                    return SimpleNamespace(returncode=1, stdout="", stderr="No such container")
                return SimpleNamespace(returncode=0, stdout=json.dumps(labels), stderr="")
            if "{{json .State}}" in argv:
                return SimpleNamespace(returncode=0, stdout=json.dumps({"Running": False, "ExitCode": 0}), stderr="")
            if self.failure == "inspect":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            labels = self.container_labels.get(argv[-1], {})
            document = _runtime_inspect(labels, self.volume_name, running=self.container_running)
            if self.drift == "resources":
                document["HostConfig"]["ReadonlyRootfs"] = False
            elif self.drift == "bind":
                document["HostConfig"]["PortBindings"] = {"8090/tcp": [{"HostIp": "0.0." + "0.0", "HostPort": "19090"}]}
            elif self.drift == "settings":
                document["Config"]["Env"] = ["DEPLOYMENT_PROFILE=development"]
            elif self.drift == "image":
                document["Image"] = "sha256:" + "d" * 64
            elif self.drift == "stop_timeout":
                document["HostConfig"]["StopTimeout"] = 1
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(document),
                stderr="",
            )
        if argv[:3] == ("docker", "volume", "inspect"):
            labels = self.volume_labels.get(argv[-1])
            if labels is None:
                return SimpleNamespace(returncode=1, stdout="", stderr="No such volume")
            if "{{json .Labels}}" in argv:
                return SimpleNamespace(returncode=0, stdout=json.dumps(labels), stderr="")
            return SimpleNamespace(returncode=0, stdout=json.dumps({"Labels": labels}), stderr="")
        if (
            argv[:3] == ("docker", "exec", "--user")
            and isinstance(argv[-1], str)
            and "qualification-reconciliation-metrics" in argv[-1]
        ):
            index = min(self.metrics_reads, len(self.metrics_snapshots) - 1)
            self.metrics_reads += 1
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(self.metrics_snapshots[index], sort_keys=True, separators=(",", ":")),
                stderr="",
            )
        if argv[:3] == ("docker", "exec", "--user"):
            if self.failure == "auth":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            settings = _manifest_settings()
            if self.failure == "effective_settings":
                settings["deployment_profile"] = "development"
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "settings": settings,
                        "secret_roles_distinct": True,
                        "upstream_authenticated": True,
                        "ordinary_authenticated": True,
                        "metrics_authenticated": True,
                    }
                ),
                stderr="",
            )
        if argv[:3] == ("docker", "rm", "--force") and self.failure == "cleanup_container":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if argv[:3] == ("docker", "rm", "--force") and self.failure == "signal_cleanup_container":
            os.kill(os.getpid(), signal.SIGTERM)
        if argv[:3] == ("docker", "rm", "--force"):
            labels = self.container_labels.pop(argv[-1], None)
            if labels is not None:
                for name, candidate in list(self.container_labels.items()):
                    if candidate is labels:
                        del self.container_labels[name]
        if argv[:3] == ("docker", "volume", "rm") and self.failure == "cleanup_volume":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if argv[:3] == ("docker", "volume", "rm") and self.failure == "signal_cleanup_volume":
            os.kill(os.getpid(), signal.SIGTERM)
        if argv[:3] == ("docker", "volume", "rm"):
            self.volume_labels.pop(argv[-1], None)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def spawn(self, argv: tuple[str, ...], *, env: dict[str, str]) -> _FakeProcess:
        self.calls.append(("spawn", argv, env))
        if self.failure == "observer_spawn":
            raise OSError("observer cannot start")
        ledger = Path(env["QUALIFICATION_OBSERVER_LEDGER"])
        ledger.touch(exist_ok=False)
        ledger.chmod(0o600)
        if self.failure == "observer_ledger":
            ledger.write_text("unexpected-record\n", encoding="utf-8")
        return self.observer

    def http_status(self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 5.0) -> int:
        del headers, timeout
        self.calls.append(("http", (url,), None))
        return 503 if self.failure == "proxy_ready" else 200

    def http_json(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 5.0
    ) -> tuple[int, dict[str, object] | None]:
        del headers, timeout
        self.calls.append(("http_json", (url,), None))
        if url.startswith("http://127.0.0.1:19999/"):
            assert self.model_contract is not None
            if url.endswith("/health"):
                return 200, {
                    "ok": True,
                    "active_requests": 0,
                    "foreground_active": 0,
                    "requests_completed": self.model_requests_completed,
                    "startup": {"pid": 444, "started_at": self.model_started_at, "launch_id": None},
                }
            if url.endswith("/v1/models"):
                return 200, {
                    "object": "list",
                    "data": [{"id": self.model_contract.public_model_id, "object": "model"}],
                }
            if url.endswith("/v1/mtplx/settings"):
                return 200, _mtplx_settings()
            raise AssertionError(url)
        if self.failure == "observer_ready":
            return 200, {"status": "live", "instance_sha256": "unrelated-ready-process"}
        observer_environment = next(call[2] for call in self.calls if call[0] == "spawn")
        assert observer_environment is not None
        return 200, {
            "status": "live",
            "instance_sha256": observer_environment["QUALIFICATION_OBSERVER_INSTANCE_SHA256"],
        }


class _SourceCheckoutRunner(_FakeRuntimeRunner):
    """Run only benchmark Git/Python probes locally; retain fake Docker lifecycle behavior."""

    def run(
        self, argv: tuple[str, ...], *, env: dict[str, str] | None = None, timeout: float | None = None
    ) -> SimpleNamespace:
        if argv[0] == "git" or argv[0] == sys.executable:
            self.calls.append(("run", argv, env))
            completed = subprocess.run(  # noqa: S603 - fixed test seam vectors
                argv,
                capture_output=True,
                check=False,
                env=env,
                text=True,
                timeout=timeout,
            )
            if argv[:4] == ("git", "-C", argv[2], "rev-parse") and argv[-1] == "HEAD":
                return SimpleNamespace(returncode=0, stdout=BENCHMARK_REVISION + "\n", stderr="")
            return SimpleNamespace(
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        return super().run(argv, env=env, timeout=timeout)


def _manifest_settings() -> dict[str, object]:
    return {
        "deployment_profile": "production",
        "harness_profile": "shiftedx-harness-v1",
        "upstream_tool_response_capability_mode": "phase_split",
        "upstream_cache_capability_mode": "disabled",
        "telemetry_enabled": True,
        "metrics_enabled": True,
        "max_internal_retries": 4,
        "max_upstream_calls": 7,
        "upstream_timeout_seconds": 120.0,
        "total_request_deadline_seconds": 180.0,
        "server_connection_limit": 24,
        "admission_limit": 16,
        "principal_concurrency_limit": 4,
        "concurrency_limit": 32,
        "require_receipt_when_tools_present": True,
        "allow_harness_opt_out": False,
        "log_level": "INFO",
    }


def _runtime_inspect(labels: dict[str, str], volume_name: str, *, running: bool = True) -> dict[str, object]:
    return {
        "State": {"Running": running},
        "Image": "sha256:" + "c" * 64,
        "Config": {
            "User": "10001:10001",
            "Env": [
                "DEPLOYMENT_PROFILE=production",
                "HARNESS_PROFILE=shiftedx-harness-v1",
                "LISTEN_HOST=0.0.0.0",
                "LISTEN_PORT=8090",
                "UPSTREAM_BASE_URL=http://host.docker.internal:18092/v1",
                "UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE=phase_split",
                "UPSTREAM_CACHE_CAPABILITY_MODE=disabled",
                "TELEMETRY_ENABLED=true",
                "METRICS_ENABLED=true",
            ],
            "Labels": labels,
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128,
            "StopTimeout": 20,
            "Memory": 536870912,
            "NanoCpus": 1000000000,
            "Init": True,
            "PortBindings": {"8090/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19090"}]},
        },
        "Mounts": [{"Type": "volume", "Name": volume_name, "Destination": "/run/secrets", "RW": False}],
    }


def test_preflight_supervisor_writes_safe_attestation_before_action_and_cleans(monkeypatch, tmp_path):
    manifest = _manifest(tmp_path)
    private_run_dir = tmp_path / "private-run"
    private_run_dir.mkdir(mode=0o700)
    private_run_dir.chmod(0o700)
    runner = _FakeRuntimeRunner()

    def action(lease) -> int:
        assert lease.proxy_base_url == "http://127.0.0.1:19090/v1"
        assert lease.attestation_path.exists()
        return _write_complete_ledger(lease)

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=runner,
    )

    assert outcome.status == "passed"
    attestation = json.loads((private_run_dir / "preflight-runtime-attestation.json").read_text())
    assert attestation["status"] == "passed"
    assert attestation["stage"] == "preflight"
    assert attestation["checks"] == {
        "exact_image": True,
        "settings": True,
        "resources": True,
        "bind": True,
        "observer": True,
        "ready": True,
        "secret_roles_distinct": True,
    }
    serialized = (private_run_dir / "preflight-runtime-attestation.json").read_text() + (
        private_run_dir / "preflight-runtime-outcome.json"
    ).read_text()
    assert "private-model-id" not in serialized
    assert "private-model.invalid" not in serialized
    assert str(tmp_path) not in serialized
    assert "dummy-ordinary-credential-value" not in serialized
    assert runner.observer.terminated and runner.observer.waited
    argv = "\n".join(" ".join(call[1]) for call in runner.calls if call[0] == "run")
    environments = "\n".join(
        "\n".join((call[2] or {}).values()) for call in runner.calls if call[0] in {"run", "spawn"}
    )
    assert "dummy-ordinary-credential-value" not in argv + environments
    assert "dummy-policy-credential-value" not in argv + environments
    assert "dummy-upstream-credential-value" not in argv + environments
    assert "FOWNER" not in argv
    assert "--pull never" in argv
    initializer = next(
        call[1]
        for call in runner.calls
        if call[0] == "run" and call[1][:3] == ("docker", "run", "--detach") and "--entrypoint" in call[1]
    )
    initializer_script = initializer[-1]
    assert initializer_script.index("cp /source/") < initializer_script.index("chmod 0400")
    assert initializer_script.index("chmod 0400") < initializer_script.index("chown 10001:10001")
    assert "status.st_uid == 10001" in initializer_script
    effective_settings_check = next(
        call[1][-1] for call in runner.calls if call[0] == "run" and call[1][:3] == ("docker", "exec", "--user")
    )
    compile(effective_settings_check, "qualification-effective-settings-check", "exec")
    assert any(call[1][:3] == ("docker", "rm", "--force") for call in runner.calls if call[0] == "run")
    assert any(call[1][:3] == ("docker", "volume", "rm") for call in runner.calls if call[0] == "run")


def test_in_container_metrics_probe_rejects_redirects_before_replaying_trusted_or_ordinary_key(
    monkeypatch, tmp_path
) -> None:
    """The emitted container probe must not follow a redirect with either credential role."""

    runner = _FakeRuntimeRunner()
    outcome = _supervise(
        manifest=_manifest(tmp_path),
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=_write_complete_ledger,
        command_runner=runner,
    )
    assert outcome.status == "passed"
    source = next(
        call[1][-1]
        for call in runner.calls
        if call[0] == "run" and call[1][:3] == ("docker", "exec", "--user")
    )

    class Secret:
        def __init__(self, value: str) -> None:
            self.value = value

        def get_secret_value(self) -> str:
            return self.value

    class Settings:
        proxy_api_key = Secret("ordinary-test-token")
        upstream_api_key = Secret("upstream-test-token")

        def trusted_policy_extension_keys(self) -> frozenset[str]:
            return frozenset({"trusted-test-token"})

        def __getattr__(self, _name: str) -> None:
            return None

    requests: list[urllib.request.Request] = []

    class RedirectingOpener:
        def __init__(self, handlers) -> None:
            self.redirect_handler = next(
                handler
                for handler in handlers
                if isinstance(handler, urllib.request.HTTPRedirectHandler)
            )

        def open(self, request, *, timeout: float):
            del timeout
            requests.append(request)
            return self.redirect_handler.redirect_request(
                request,
                None,
                302,
                "found",
                {},
                "http://redirect.invalid/metrics",
            )

    def fake_build_opener(*handlers):
        proxy_handler = next(handler for handler in handlers if isinstance(handler, urllib.request.ProxyHandler))
        assert proxy_handler.proxies == {}
        return RedirectingOpener(handlers)

    def unexpected_urlopen(*_args, **_kwargs):
        raise AssertionError("the metrics probe must use its no-proxy, no-redirect opener")

    monkeypatch.setattr("shiftedx_harness_proxy.config.Settings", Settings)
    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(urllib.request, "urlopen", unexpected_urlopen)
    exec(  # noqa: S102 - executes the fixed generated probe with a redirect-only fake opener
        compile(source, "qualification-in-container-metrics-probe", "exec"),
        {"__name__": "__main__"},
    )

    assert len(requests) == 2
    assert {request.get_header("Authorization") for request in requests} == {
        "Bearer ordinary-test-token",
        "Bearer trusted-test-token",
    }
    assert {request.full_url for request in requests} == {"http://127.0.0.1:8090/metrics"}


def test_subprocess_runtime_command_runner_freezes_host_tools_and_scrubs_ambient_environment(
    monkeypatch, tmp_path
) -> None:
    """Docker/Git commands cannot inherit proxy, credential, or context configuration."""

    calls: list[tuple[list[str], dict[str, object]]] = []
    docker = tmp_path / "docker"
    git = tmp_path / "git"
    for tool in (docker, git):
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tool.chmod(0o700)

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return SimpleNamespace(returncode=0, stdout="safe", stderr="")

    monkeypatch.setenv("DOCKER_HOST", "private-daemon-marker")
    monkeypatch.setenv("DOCKER_CONTEXT", "private-context-marker")
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy.invalid")
    monkeypatch.setenv("UPSTREAM_API_KEY", "private-upstream-token")
    monkeypatch.setattr(runtime_module, "_FROZEN_HOST_TOOLS", {"docker": (docker,), "git": (git,)})
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    command_runner = runtime_module.SubprocessRuntimeCommandRunner()

    assert command_runner.run(("docker", "version")).returncode == 0
    assert command_runner.run(("git", "rev-parse", "HEAD")).returncode == 0

    assert [argv for argv, _kwargs in calls] == [
        [str(docker), "version"],
        [str(git), "rev-parse", "HEAD"],
    ]
    for _argv, kwargs in calls:
        environment = kwargs["env"]
        assert environment == {}
        assert not {"DOCKER_HOST", "DOCKER_CONTEXT", "HTTPS_PROXY", "UPSTREAM_API_KEY"} & set(environment)


def test_subprocess_runtime_command_runner_fails_closed_when_no_pinned_tool_exists(monkeypatch, tmp_path) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return SimpleNamespace(returncode=0, stdout="unsafe", stderr="")

    monkeypatch.setattr(
        runtime_module,
        "_FROZEN_HOST_TOOLS",
        {"docker": (tmp_path / "missing-docker",), "git": (tmp_path / "missing-git",)},
    )
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    result = runtime_module.SubprocessRuntimeCommandRunner().run(("docker", "version"))

    assert result.returncode == 125
    assert calls == []


def test_subprocess_runtime_command_runner_rejects_an_unallowlisted_absolute_tool(monkeypatch, tmp_path) -> None:
    """An absolute caller-provided Docker path cannot bypass the frozen locations."""

    calls: list[tuple[list[str], dict[str, object]]] = []
    trusted = tmp_path / "trusted-docker"
    untrusted = tmp_path / "docker"
    for tool in (trusted, untrusted):
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tool.chmod(0o700)

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return SimpleNamespace(returncode=0, stdout="unsafe", stderr="")

    monkeypatch.setattr(runtime_module, "_FROZEN_HOST_TOOLS", {"docker": (trusted,), "git": ()})
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    result = runtime_module.SubprocessRuntimeCommandRunner().run((str(untrusted), "version"))

    assert result.returncode == 125
    assert calls == []


def test_runtime_private_evidence_reader_rejects_a_rename_swap(monkeypatch, tmp_path) -> None:
    """A lstat/open race cannot replace immutable evidence with another regular file."""

    evidence = _private_file(tmp_path / "preflight-runtime-attestation.json", b"first\n")
    replacement = _private_file(tmp_path / "replacement-runtime-attestation.json", b"second\n")
    original_open = runtime_module.os.open
    replaced = False

    def replace_before_open(path, *args, **kwargs):
        nonlocal replaced
        if not replaced and os.fspath(path) == os.fspath(evidence):
            replaced = True
            os.replace(replacement, evidence)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(runtime_module.os, "open", replace_before_open)
    with pytest.raises(runtime_module.QualificationRuntimeFailure, match="runtime_evidence_invalid"):
        runtime_module._read_private_file(evidence, "runtime_evidence_invalid")
    assert replaced is True


def _private_run(tmp_path: Path, name: str = "private-run") -> Path:
    path = tmp_path / name
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _write_complete_ledger(lease: RuntimeLease) -> int:
    count = 5 if lease.stage == "preflight" else lease.scenario_count
    lease.output_ledger.write_text(
        "".join(json.dumps({"record": index}, separators=(",", ":")) + "\n" for index in range(count)),
        encoding="utf-8",
    )
    lease.output_ledger.chmod(0o600)
    if lease.direct_model_attempt_ledger is not None:
        lease.direct_model_attempt_ledger.write_text("", encoding="utf-8")
        lease.direct_model_attempt_ledger.chmod(0o600)
    if lease.proxy_request_ledger is not None:
        write_request_accounting_ledger(lease.proxy_request_ledger, ())
    return 0


def _write_scored_output(lease: RuntimeLease) -> None:
    lease.output_ledger.write_text(
        "".join(json.dumps({"record": index}, separators=(",", ":")) + "\n" for index in range(lease.scenario_count)),
        encoding="utf-8",
    )
    lease.output_ledger.chmod(0o600)


def _model_attempt(
    sequence: int,
    cache: CacheObservation | None,
    *,
    status_code: int | None = 200,
) -> ModelBoundaryRecord:
    fingerprint = model_boundary_fingerprint(
        {
            "model": "private-model-id",
            "messages": [{"role": "user", "content": "private"}],
            # Reconciliation accepts the frozen two-phase proxy contract only.
            "tools": [{"type": "function", "function": {"name": "safe"}}],
        }
    )
    return ModelBoundaryRecord(sequence, fingerprint.digest, fingerprint.fields, status_code, cache)


def _cold_cache() -> CacheObservation:
    return CacheObservation(
        prompt_tokens=10,
        cached_tokens=0,
        new_prefill_tokens=10,
        cache_source="none",
        ssd_cache_hit=False,
        ssd_cached_tokens=0,
        session_cache_hit=False,
        request_session_bank_bypass=True,
        postcommit_stored=False,
    )


def _warm_prime_cache() -> CacheObservation:
    return CacheObservation(
        prompt_tokens=10,
        cached_tokens=0,
        new_prefill_tokens=10,
        cache_source="none",
        ssd_cache_hit=False,
        ssd_cached_tokens=0,
        session_cache_hit=False,
        request_session_bank_bypass=False,
        postcommit_stored=False,
    )


def _warm_hit_cache() -> CacheObservation:
    return CacheObservation(
        prompt_tokens=10,
        cached_tokens=5,
        new_prefill_tokens=5,
        cache_source="ram",
        ssd_cache_hit=False,
        ssd_cached_tokens=0,
        session_cache_hit=True,
        request_session_bank_bypass=False,
        postcommit_stored=True,
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_production_model_probe_uses_c1_hardened_transport_not_runtime_urlopen(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class Probe:
        def snapshot(self, **kwargs):
            calls.append(kwargs)
            return "safe-snapshot"

    monkeypatch.setattr(runtime_module, "SystemModelEvidenceProbe", Probe)
    contract = object()
    result = runtime_module._RuntimeModelEvidenceProbe(runtime_module.SubprocessRuntimeCommandRunner()).snapshot(
        host="127.0.0.1",
        port=19999,
        api_key=None,
        contract=contract,
    )

    assert result == "safe-snapshot"
    assert calls == [{"host": "127.0.0.1", "port": 19999, "api_key": None, "contract": contract}]


def test_post_cleanup_outcome_is_exact_hash_only_and_binds_complete_preflight_ledger(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )

    assert outcome.status == "passed"
    assert outcome.outcome_path is not None
    record = json.loads(outcome.outcome_path.read_text(encoding="utf-8"))
    assert set(record) == {
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
    assert record["stage"] == "preflight"
    assert record["status"] == "passed"
    assert record["action_exit_code"] == 0
    assert record["failure_category"] is None
    assert record["run_manifest_sha256"] == _sha256_file(manifest)
    assert record["attestation_sha256"] == _sha256_file(private_run_dir / "preflight-runtime-attestation.json")
    assert record["model_evidence_sha256"] == _sha256_file(private_run_dir / "preflight-model-cache-evidence.json")
    assert record["output_ledger_sha256"] == _sha256_file(private_run_dir / "preflight.jsonl")
    assert record["output_record_count"] == 5
    assert record["proxy_reconciliation_sha256"] is None
    assert record["slot_ordinal"] == 0
    assert record["cache_lane"] == "preflight"
    assert record["pair_index"] == 0
    assert stat.S_IMODE(outcome.outcome_path.stat().st_mode) == 0o600
    serialized = outcome.outcome_path.read_text(encoding="utf-8")
    assert str(tmp_path) not in serialized
    assert "qualification-run-1" not in serialized


def test_scoring_gate_rejects_a_preflight_without_a_passed_complete_outcome(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    (private_run_dir / "preflight-runtime-outcome.json").write_text("{}\n", encoding="utf-8")
    (private_run_dir / "preflight-runtime-outcome.json").chmod(0o600)

    outcome = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("score-direct must not run after invalid preflight outcome"),
        command_runner=_FakeRuntimeRunner(),
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_prior_outcome_invalid"


@pytest.mark.parametrize("preflight_result", ["failed", "incomplete", "hash-drift"])
def test_scoring_gate_rejects_failed_incomplete_or_hash_drifted_preflight_evidence(preflight_result, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    if preflight_result == "failed":

        def action(_lease) -> int:
            return 9
    elif preflight_result == "incomplete":

        def action(lease) -> int:
            lease.output_ledger.write_text('{"record":0}\n', encoding="utf-8")
            lease.output_ledger.chmod(0o600)
            return 0

    else:
        action = _write_complete_ledger
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=_FakeRuntimeRunner(),
    )
    if preflight_result in {"failed", "incomplete"}:
        assert preflight.status == "failed"
    else:
        assert preflight.status == "passed"
    if preflight_result == "hash-drift":
        ledger = private_run_dir / "preflight.jsonl"
        ledger.write_bytes(ledger.read_bytes() + b'{"record":99}\n')
        ledger.chmod(0o600)

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("invalid preflight evidence must block score-direct"),
        command_runner=_FakeRuntimeRunner(),
    )

    assert direct.failure_category == "runtime_prior_outcome_invalid"


def test_scored_treatment_needs_every_manifest_scenario_before_its_outcome_can_pass(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"

    def incomplete_action(lease: RuntimeLease) -> int:
        lease.output_ledger.write_text('{"record":0}\n', encoding="utf-8")
        lease.output_ledger.chmod(0o600)
        assert lease.direct_model_attempt_ledger is not None
        lease.direct_model_attempt_ledger.write_text("", encoding="utf-8")
        lease.direct_model_attempt_ledger.chmod(0o600)
        return 0

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=incomplete_action,
        command_runner=_FakeRuntimeRunner(),
    )

    assert direct.status == "failed"
    assert direct.failure_category == "runtime_output_ledger_incomplete"
    assert direct.outcome_path is not None
    outcome = json.loads(direct.outcome_path.read_text(encoding="utf-8"))
    assert outcome["status"] == "failed"
    assert outcome["output_record_count"] == 1


def test_model_evidence_begin_failure_blocks_action_before_proxy_setup(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    document = _manifest_document(manifest)
    runtime = document["qualification_runtime"]
    assert isinstance(runtime, dict)
    model = runtime["model"]
    assert isinstance(model, dict)
    model["identity_ledger_sha256"] = "0" * 64
    _store_manifest(manifest, document)
    private_run_dir = _private_run(tmp_path)
    runner = _FakeRuntimeRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("model evidence must begin before Docker or action"),
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "model_contract_invalid"
    assert _docker_commands(runner) == []
    assert not (private_run_dir / "preflight-model-cache-evidence.json").exists()
    assert outcome.outcome_path is not None
    record = json.loads(outcome.outcome_path.read_text(encoding="utf-8"))
    assert record["model_evidence_sha256"] is None


def test_cold_direct_stage_adapts_actual_attempt_ledger_into_passed_model_evidence(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    runner = _FakeRuntimeRunner()

    def action(lease: RuntimeLease) -> int:
        _write_scored_output(lease)
        assert lease.direct_model_attempt_ledger is not None
        write_model_boundary_attempt_ledger(lease.direct_model_attempt_ledger, [_model_attempt(1, _cold_cache())])
        runner.model_requests_completed += 1
        return 0

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=runner,
    )

    assert direct.status == "passed"
    evidence = json.loads((private_run_dir / "scored-direct-model-cache-evidence.json").read_text())
    assert evidence["status"] == "passed"
    assert evidence["request_window"]["expected"] == 1
    assert evidence["first_attempt"]["successful_count"] == 1


def test_warm_direct_stage_requires_and_binds_one_prime_before_its_first_hit(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    runner = _FakeRuntimeRunner()

    def action(lease: RuntimeLease) -> int:
        _write_scored_output(lease)
        assert lease.direct_model_attempt_ledger is not None
        assert lease.prime_model_attempt_ledger is not None
        write_model_boundary_attempt_ledger(lease.prime_model_attempt_ledger, [_model_attempt(1, _warm_prime_cache())])
        write_model_boundary_attempt_ledger(lease.direct_model_attempt_ledger, [_model_attempt(1, _warm_hit_cache())])
        runner.model_requests_completed += 2
        return 0

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=runner,
        cache_lane="warm-prefix",
    )

    assert direct.status == "passed"
    evidence = json.loads((private_run_dir / "scored-direct-model-cache-evidence.json").read_text())
    assert evidence["prime"]["count"] == 1
    assert evidence["request_window"]["expected"] == 2


def test_successful_model_attempt_without_cache_evidence_blocks_outcome(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    runner = _FakeRuntimeRunner()

    def action(lease: RuntimeLease) -> int:
        _write_scored_output(lease)
        assert lease.direct_model_attempt_ledger is not None
        write_model_boundary_attempt_ledger(lease.direct_model_attempt_ledger, [_model_attempt(1, None)])
        return 0

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=runner,
    )

    assert direct.status == "failed"
    assert direct.failure_category == "model_attempt_invalid"
    evidence = json.loads((private_run_dir / "scored-direct-model-cache-evidence.json").read_text())
    assert evidence["status"] == "failed"


def test_proxy_stage_adapts_only_its_fresh_observer_attempts(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert direct.status == "passed"
    runner = _FakeRuntimeRunner()

    def action(lease: RuntimeLease) -> int:
        assert lease.attestation_path is not None and lease.attestation_path.exists()
        runner.calls.append(("action", (), None))
        _write_scored_output(lease)
        assert lease.observer_ledger is not None
        assert lease.proxy_request_ledger is not None
        record = _model_attempt(1, _cold_cache()).to_dict()
        lease.observer_ledger.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        lease.observer_ledger.chmod(0o600)
        write_request_accounting_ledger(
            lease.proxy_request_ledger,
            (
                RequestAccountingRecord(
                    sequence=1,
                    outcome="succeeded",
                    local_projection=False,
                    attempt_sequence_start=1,
                    attempt_sequence_end=1,
                    attempt_count=1,
                    successful_attempt_count=1,
                    phase_counts={"acquisition": 1, "finalization": 0},
                    retry_attempt_count=0,
                    blocked_duplicate_count=0,
                    blocked_stall_count=0,
                ),
            ),
        )
        after = _zero_proxy_metrics()
        after.update(
            {
                "downstream_requests": 1,
                "upstream_calls": 1,
                "phase_acquisition": 1,
            }
        )
        runner.metrics_snapshots[1] = after
        runner.model_requests_completed += 1
        return 0

    proxy = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=runner,
    )

    assert proxy.status == "passed"
    evidence = json.loads((private_run_dir / "scored-proxy-model-cache-evidence.json").read_text())
    assert evidence["status"] == "passed"
    assert evidence["request_window"]["successful_measured"] == 1
    reconciliation = private_run_dir / "scored-proxy-reconciliation.json"
    assert stat.S_IMODE(reconciliation.stat().st_mode) == 0o600
    reconciliation_record = json.loads(reconciliation.read_text(encoding="utf-8"))
    assert reconciliation_record["status"] == "passed"
    assert proxy.outcome_path is not None
    runtime_outcome = json.loads(proxy.outcome_path.read_text(encoding="utf-8"))
    assert runtime_outcome["proxy_reconciliation_sha256"] == hashlib.sha256(
        reconciliation.read_bytes()
    ).hexdigest()
    scored_attestation = json.loads(
        (private_run_dir / "scored-proxy-runtime-attestation.json").read_text()
    )
    preflight_attestation = json.loads(
        (private_run_dir / "preflight-runtime-attestation.json").read_text()
    )
    assert scored_attestation["runtime_contract_sha256"] == preflight_attestation["runtime_contract_sha256"]
    metric_indices = [
        index
        for index, call in enumerate(runner.calls)
        if call[0] == "run"
        and call[1][:3] == ("docker", "exec", "--user")
        and "qualification-reconciliation-metrics" in call[1][-1]
    ]
    action_index = next(index for index, call in enumerate(runner.calls) if call[0] == "action")
    cleanup_index = next(
        index
        for index, call in enumerate(runner.calls)
        if call[0] == "run" and call[1][:3] == ("docker", "rm", "--force")
    )
    assert len(metric_indices) == 2
    assert metric_indices[0] < action_index < metric_indices[1] < cleanup_index


def test_warm_proxy_attestation_keeps_the_single_preflight_runtime_contract(tmp_path) -> None:
    """Lane-specific C1 proof must not drift the cross-stage runtime gate."""

    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    assert (
        _supervise(
            manifest=manifest,
            stage="preflight",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )
    direct_runner = _FakeRuntimeRunner()

    def direct_action(lease: RuntimeLease) -> int:
        _write_scored_output(lease)
        assert lease.direct_model_attempt_ledger is not None
        assert lease.prime_model_attempt_ledger is not None
        write_model_boundary_attempt_ledger(
            lease.prime_model_attempt_ledger, [_model_attempt(1, _warm_prime_cache())]
        )
        write_model_boundary_attempt_ledger(
            lease.direct_model_attempt_ledger, [_model_attempt(1, _warm_hit_cache())]
        )
        direct_runner.model_requests_completed += 2
        return 0

    assert (
        _supervise(
            manifest=manifest,
            stage="score-direct",
            private_run_dir=private_run_dir,
            action=direct_action,
            command_runner=direct_runner,
            cache_lane="warm-prefix",
        ).status
        == "passed"
    )
    proxy_runner = _FakeRuntimeRunner()

    def proxy_action(lease: RuntimeLease) -> int:
        _write_scored_output(lease)
        assert lease.observer_ledger is not None
        assert lease.proxy_request_ledger is not None
        assert lease.prime_model_attempt_ledger is not None
        write_model_boundary_attempt_ledger(
            lease.prime_model_attempt_ledger, [_model_attempt(1, _warm_prime_cache())]
        )
        observed = _model_attempt(1, _warm_hit_cache()).to_dict()
        lease.observer_ledger.write_text(
            json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        lease.observer_ledger.chmod(0o600)
        write_request_accounting_ledger(
            lease.proxy_request_ledger,
            (
                RequestAccountingRecord(
                    sequence=1,
                    outcome="succeeded",
                    local_projection=False,
                    attempt_sequence_start=1,
                    attempt_sequence_end=1,
                    attempt_count=1,
                    successful_attempt_count=1,
                    phase_counts={"acquisition": 1, "finalization": 0},
                    retry_attempt_count=0,
                    blocked_duplicate_count=0,
                    blocked_stall_count=0,
                ),
            ),
        )
        after = _zero_proxy_metrics()
        after.update({"downstream_requests": 1, "upstream_calls": 1, "phase_acquisition": 1})
        proxy_runner.metrics_snapshots[1] = after
        proxy_runner.model_requests_completed += 2
        return 0

    proxy = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=proxy_action,
        command_runner=proxy_runner,
        cache_lane="warm-prefix",
    )

    assert proxy.status == "passed"
    preflight = json.loads((private_run_dir / "preflight-runtime-attestation.json").read_text())
    scored = json.loads((private_run_dir / "scored-proxy-runtime-attestation.json").read_text())
    assert scored["runtime_contract_sha256"] == preflight["runtime_contract_sha256"]
    assert scored["model_identity_sha256"] == preflight["model_identity_sha256"]


def test_proxy_reconciliation_failure_retains_failed_artifact_and_blocks_passed_outcome(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    assert (
        _supervise(
            manifest=manifest,
            stage="preflight",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )
    assert (
        _supervise(
            manifest=manifest,
            stage="score-direct",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )
    runner = _FakeRuntimeRunner()
    after = _zero_proxy_metrics()
    after["downstream_requests"] = 1
    runner.metrics_snapshots[1] = after

    outcome = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "reconciliation_downstream_mismatch"
    reconciliation = private_run_dir / "scored-proxy-reconciliation.json"
    record = json.loads(reconciliation.read_text(encoding="utf-8"))
    assert record["status"] == "failed"
    assert outcome.outcome_path is not None
    runtime_outcome = json.loads(outcome.outcome_path.read_text(encoding="utf-8"))
    assert runtime_outcome["status"] == "failed"
    assert runtime_outcome["proxy_reconciliation_sha256"] == hashlib.sha256(
        reconciliation.read_bytes()
    ).hexdigest()


def test_proxy_nonzero_child_still_finalizes_its_safe_reconciliation_window(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    assert (
        _supervise(
            manifest=manifest,
            stage="preflight",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )
    assert (
        _supervise(
            manifest=manifest,
            stage="score-direct",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )

    def failed_child(lease: RuntimeLease) -> int:
        _write_complete_ledger(lease)
        return 7

    outcome = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=failed_child,
        command_runner=_FakeRuntimeRunner(),
    )

    assert (outcome.status, outcome.failure_category) == ("failed", "action_failed")
    reconciliation = private_run_dir / "scored-proxy-reconciliation.json"
    assert json.loads(reconciliation.read_text(encoding="utf-8"))["status"] == "passed"
    assert outcome.proxy_reconciliation_sha256 == hashlib.sha256(reconciliation.read_bytes()).hexdigest()


def test_score_proxy_requires_a_completed_direct_treatment_before_resources(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    runner = _FakeRuntimeRunner()

    proxy = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("score-proxy must require completed direct treatment"),
        command_runner=runner,
    )

    assert proxy.failure_category == "runtime_prior_outcome_invalid"
    assert _docker_commands(runner) == []


def test_scored_treatment_rejects_a_nonfresh_model_before_action_or_proxy_resources(tmp_path) -> None:
    """The supervisor requires an owned restart, not just a cache-mode assertion."""

    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    runner = _FakeRuntimeRunner()
    runner.model_requests_completed = 1

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("a nonfresh model must block the scored action"),
        command_runner=runner,
    )

    assert direct.failure_category == "model_cache_instance_not_fresh"
    assert _docker_commands(runner) == []


def test_scored_treatment_requires_a_dedicated_model_restart_even_with_zero_requests(tmp_path) -> None:
    """A zero counter alone cannot reuse the preflight process as a scored treatment."""

    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    runner = _FakeRuntimeRunner()
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=runner,
    )
    assert preflight.status == "passed"
    preflight_commands = list(_docker_commands(runner))

    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("a reused model must block the scored action"),
        command_runner=runner,
    )

    assert direct.failure_category == "runtime_model_instance_not_fresh"
    assert _docker_commands(runner) == preflight_commands


def _manifest_document(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _store_manifest(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def _docker_commands(runner: _FakeRuntimeRunner) -> list[tuple[str, ...]]:
    return [call[1] for call in runner.calls if call[0] == "run" and call[1][0] == "docker"]


@pytest.mark.parametrize(
    ("failure", "category", "expects_container_cleanup"),
    [
        ("image", "runtime_image_unavailable", False),
        ("image_metadata", "runtime_image_unavailable", False),
        ("volume_create", "runtime_volume_create_failed", False),
        ("initializer", "runtime_secret_initialize_failed", True),
        ("observer_spawn", "runtime_observer_start_failed", True),
        ("observer_ready", "runtime_observer_unhealthy", True),
        ("observer_ledger", "runtime_observer_ledger_invalid", True),
        ("launch", "runtime_proxy_launch_failed", True),
        ("inspect", "runtime_inspect_drift", True),
        ("proxy_ready", "runtime_proxy_unready", True),
        ("auth", "runtime_proxy_auth_failed", True),
        ("effective_settings", "runtime_proxy_auth_failed", True),
    ],
)
def test_setup_failures_never_invoke_action_and_clean_only_created_resources(
    monkeypatch, tmp_path, failure, category, expects_container_cleanup
) -> None:
    monkeypatch.setattr("shiftedx_harness_proxy.qualification_runtime.time.sleep", lambda _seconds: None)
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    runner = _FakeRuntimeRunner(failure=failure)
    action_calls: list[object] = []

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=lambda lease: action_calls.append(lease) or 0,
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == category
    assert action_calls == []
    assert (private_run_dir / "preflight-runtime-outcome.json").exists()
    commands = _docker_commands(runner)
    volume_should_be_cleaned = failure not in {"volume_create", "image", "image_metadata"}
    assert any(command[:3] == ("docker", "volume", "rm") for command in commands) is volume_should_be_cleaned
    assert any(command[:3] == ("docker", "rm", "--force") for command in commands) is expects_container_cleanup
    if failure not in {"image", "image_metadata", "volume_create", "initializer", "observer_spawn"}:
        assert runner.observer.terminated and runner.observer.waited
    if expects_container_cleanup:
        container_cleanup = next(
            index for index, command in enumerate(commands) if command[:3] == ("docker", "rm", "--force")
        )
        volume_cleanup = next(
            index for index, command in enumerate(commands) if command[:3] == ("docker", "volume", "rm")
        )
        assert container_cleanup < volume_cleanup


@pytest.mark.parametrize("drift", ["resources", "bind", "settings", "image", "stop_timeout"])
def test_inspect_drift_fails_closed_before_action_and_cleans(drift, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    runner = _FakeRuntimeRunner(drift=drift)

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("action must not run after inspect drift"),
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_inspect_drift"
    assert runner.observer.terminated
    assert any(command[:3] == ("docker", "rm", "--force") for command in _docker_commands(runner))
    assert any(command[:3] == ("docker", "volume", "rm") for command in _docker_commands(runner))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document["qualification_runtime"].__setitem__("unexpected", True),
        lambda document: document["qualification_runtime"]["proxy"].pop("settings"),
        lambda document: document["qualification_runtime"]["proxy"]["settings"].__setitem__(
            "deployment_profile", "development"
        ),
        lambda document: document["qualification_runtime"]["model"].__setitem__(
            "upstream_url", "http://model.invalid/v1?private=value"
        ),
        lambda document: document["qualification_runtime"]["credentials"].__setitem__(
            "ordinary_proxy_api_key_file", "/private/key,readonly"
        ),
    ],
)
def test_manifest_unknown_missing_or_runtime_drift_is_rejected_before_docker(mutate, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    document = _manifest_document(manifest)
    mutate(document)
    _store_manifest(manifest, document)
    runner = _FakeRuntimeRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("invalid manifest must not invoke action"),
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_manifest_invalid"
    assert _docker_commands(runner) == []


@pytest.mark.parametrize("location", ["root", "nested"])
def test_duplicate_json_manifest_keys_are_rejected_before_runtime_side_effects(location, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    runtime = _manifest_document(manifest)["qualification_runtime"]
    assert isinstance(runtime, dict)
    if location == "root":
        encoded = json.dumps(runtime, sort_keys=True, separators=(",", ":"))
        manifest.write_text(
            '{"qualification_runtime":' + encoded + ',"qualification_runtime":' + encoded + "}",
            encoding="utf-8",
        )
    else:
        serialized = manifest.read_text(encoding="utf-8")
        needle = '"package": "shiftedx-bench==0.5.1",'
        manifest.write_text(serialized.replace(needle, needle + needle, 1), encoding="utf-8")
    runner = _FakeRuntimeRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("duplicate manifest keys must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_manifest_invalid"
    assert _docker_commands(runner) == []


@pytest.mark.parametrize(
    "failure", ["benchmark_head", "benchmark_tree", "benchmark_dirty", "benchmark_project", "benchmark_source"]
)
def test_benchmark_identity_drift_is_rejected_before_runtime_resources(failure, tmp_path) -> None:
    runner = _FakeRuntimeRunner(failure=failure)

    outcome = _supervise(
        manifest=_manifest(tmp_path),
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("invalid benchmark identity must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_benchmark_invalid"
    assert _docker_commands(runner) == []


def test_tracked_source_checkout_without_installed_metadata_passes_in_isolation(tmp_path) -> None:
    manifest, checkout = _authoritative_benchmark_manifest(tmp_path)
    assert not list((checkout / "src").glob("*.dist-info"))
    runner = _SourceCheckoutRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=_write_complete_ledger,
        command_runner=runner,
    )

    assert outcome.status == "passed"
    source_probes = [call for call in runner.calls if call[0] == "run" and call[1][0] == sys.executable]
    assert len(source_probes) == 1
    assert source_probes[0][1][1:3] == ("-I", "-S")
    assert source_probes[0][2] is None


def test_untracked_sitecustomize_is_rejected_before_isolated_source_probe_can_execute(tmp_path) -> None:
    manifest, checkout = _authoritative_benchmark_manifest(tmp_path)
    marker = tmp_path / "sitecustomize-executed"
    (checkout / "src" / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    runner = _SourceCheckoutRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("untracked source must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_benchmark_invalid"
    assert not marker.exists()
    assert not [call for call in runner.calls if call[0] == "run" and call[1][0] == sys.executable]
    status_commands = [call[1] for call in runner.calls if call[0] == "run" and call[1][0] == "git"]
    assert any("--untracked-files=all" in command for command in status_commands)


@pytest.mark.parametrize(
    ("field", "value", "category"),
    [
        ("tree", None, "runtime_manifest_invalid"),
        ("revision", "f" * 40, "runtime_manifest_invalid"),
        ("package", "shiftedx-bench==0.5.0", "runtime_manifest_invalid"),
        ("checkout_path", "relative/shiftedx-bench", "runtime_manifest_invalid"),
        ("interpreter_sha256", "f" * 64, "runtime_benchmark_invalid"),
        ("scenario_count", 0, "runtime_manifest_invalid"),
    ],
)
def test_missing_or_unpinned_benchmark_identity_is_rejected_before_runtime_resources(
    field, value, category, tmp_path
) -> None:
    manifest = _manifest(tmp_path)
    document = _manifest_document(manifest)
    benchmark = document["qualification_runtime"]["benchmark"]
    assert isinstance(benchmark, dict)
    if value is None:
        benchmark.pop(field)
    else:
        benchmark[field] = value
    _store_manifest(manifest, document)
    runner = _FakeRuntimeRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("unpinned benchmark identity must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == category
    assert _docker_commands(runner) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "not a safe run id"),
        ("cache_lane", "mixed"),
        ("pair_index", 0),
        ("treatment_order", ["proxy", "direct"]),
        ("cache_proof_sha256", "not-a-digest"),
        ("unexpected", True),
    ],
)
def test_campaign_identity_is_strict_and_blocks_runtime_resources(field, value, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    document = _manifest_document(manifest)
    campaign = document["qualification_runtime"]["campaign"]
    assert isinstance(campaign, dict)
    if field in {"run_id", "cache_lane", "pair_index"}:
        slots = campaign["slots"]
        assert isinstance(slots, list) and isinstance(slots[0], dict)
        slots[0][field] = value
    else:
        campaign[field] = value
    _store_manifest(manifest, document)
    runner = _FakeRuntimeRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("invalid trial identity must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_manifest_invalid"
    assert _docker_commands(runner) == []


def test_campaign_stage_runner_inspects_absent_partial_failed_and_passed_outcomes(tmp_path) -> None:
    """Campaign recovery uses durable outcome validation, never filename inference."""

    manifest = _manifest(tmp_path)
    private_campaign_dir = _private_run(tmp_path, "private-campaign")
    stage_runner = runtime_module.QualificationCampaignStageRunner(
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    preflight = _campaign_stage_request(manifest, private_campaign_dir, stage="preflight")

    assert stage_runner.inspect(preflight).state == "absent"
    preflight.private_run_dir.mkdir(mode=0o700)
    preflight.private_run_dir.chmod(0o700)
    completed = stage_runner.run(preflight)

    assert completed.status == "passed"
    inspected = stage_runner.inspect(preflight)
    assert inspected.state == "complete"
    assert inspected.result == completed

    partial = _campaign_stage_request(
        manifest, private_campaign_dir, stage="score-direct", cache_lane="cold", pair_index=1
    )
    partial.private_run_dir.mkdir(mode=0o700)
    partial.private_run_dir.chmod(0o700)
    (partial.private_run_dir / "scored-direct.jsonl").write_text("{}\n", encoding="utf-8")
    (partial.private_run_dir / "scored-direct.jsonl").chmod(0o600)
    assert stage_runner.inspect(partial).state == "partial"

    failed_campaign_dir = _private_run(tmp_path, "failed-private-campaign")
    failed_request = _campaign_stage_request(manifest, failed_campaign_dir, stage="preflight")
    failed_request.private_run_dir.mkdir(mode=0o700)
    failed_request.private_run_dir.chmod(0o700)

    def failing_action(lease: RuntimeLease) -> int:
        _write_complete_ledger(lease)
        return 9

    failed_runner = runtime_module.QualificationCampaignStageRunner(
        action=failing_action,
        command_runner=_FakeRuntimeRunner(),
    )
    failed = failed_runner.run(failed_request)
    assert failed.status == "failed"
    assert failed.failure_category == "action_failed"
    assert failed_runner.inspect(failed_request) == runtime_module.StageInspection("complete", failed)


def test_campaign_advance_uses_runtime_adapter_and_binds_the_first_event(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_campaign_dir = _private_run(tmp_path, "advance-private-campaign")

    class Readiness:
        def probe(self, _request: StageRequest) -> ReadinessResult:
            # The sole preflight never calls readiness; retain a typed safe
            # fallback so this test proves the real campaign adapter surface.
            return ReadinessResult("ready", "a" * 64)

    advance = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ),
        readiness_probe=Readiness(),
    )

    assert advance.kind == "stage_completed"
    assert (advance.sequence, advance.stage, advance.status) == (1, "preflight", "passed")
    event = next((private_campaign_dir / "campaign-events").glob("*.json"))
    record = json.loads(event.read_text(encoding="utf-8"))
    assert record["slot_ordinal"] == 0
    assert record["cache_lane"] == "preflight"
    outcome_path = private_campaign_dir / "slots" / "00-preflight-pair0" / "preflight-runtime-outcome.json"
    assert record["runtime_outcome_sha256"] == hashlib.sha256(outcome_path.read_bytes()).hexdigest()
    assert record["campaign_id_sha256"] == hashlib.sha256(b"qualification-campaign-1").hexdigest()
    assert record["model_runtime_instance_sha256"] is not None


def test_campaign_readiness_returns_restart_required_for_a_stopped_model_without_slot_artifacts(tmp_path) -> None:
    """An intentional offline boundary is retryable, while live drift remains fail-closed."""

    manifest = _manifest(tmp_path)
    private_campaign_dir = _private_run(tmp_path, "offline-ready-private-campaign")
    first = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ),
        readiness_probe=runtime_module.QualificationCampaignReadinessProbe(command_runner=_FakeRuntimeRunner()),
    )
    assert first.kind == "stage_completed"

    class OfflineRunner(_FakeRuntimeRunner):
        def http_json(self, url, *, headers=None, timeout=5.0):
            if url.startswith("http://127.0.0.1:19999/"):
                return 0, None
            return super().http_json(url, headers=headers, timeout=timeout)

    offline = OfflineRunner()
    advance = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=lambda _lease: pytest.fail("offline readiness must not start a scored stage"),
            command_runner=offline,
        ),
        readiness_probe=runtime_module.QualificationCampaignReadinessProbe(command_runner=offline),
    )

    assert (advance.kind, advance.sequence, advance.stage) == ("restart_required", 2, "score-direct")
    assert not (private_campaign_dir / "slots" / "01-cold-pair1").exists()
    assert len(list((private_campaign_dir / "campaign-events").glob("*.json"))) == 1
    assert not list((private_campaign_dir / "slots").glob(".readiness-*-model-cache-evidence.json"))


def test_campaign_readiness_does_not_treat_a_responding_wrong_model_as_offline(tmp_path) -> None:
    """Only the hardened no-response signal is a retryable restart boundary."""

    manifest = _manifest(tmp_path)
    private_campaign_dir = _private_run(tmp_path, "wrong-model-private-campaign")
    first = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ),
        readiness_probe=runtime_module.QualificationCampaignReadinessProbe(command_runner=_FakeRuntimeRunner()),
    )
    assert first.kind == "stage_completed"

    class WrongLiveRunner(_FakeRuntimeRunner):
        def http_json(self, url, *, headers=None, timeout=5.0):
            if url.startswith("http://127.0.0.1:19999/"):
                return 503, None
            return super().http_json(url, headers=headers, timeout=timeout)

    wrong = WrongLiveRunner()
    with pytest.raises(CampaignFailure, match="campaign_readiness_probe_failed"):
        advance_qualification_campaign(
            manifest,
            private_campaign_dir,
            stage_runner=runtime_module.QualificationCampaignStageRunner(
                action=lambda _lease: pytest.fail("a responding wrong model must not start a scored stage"),
                command_runner=wrong,
            ),
            readiness_probe=runtime_module.QualificationCampaignReadinessProbe(command_runner=wrong),
        )

    assert not (private_campaign_dir / "slots" / "01-cold-pair1").exists()
    assert len(list((private_campaign_dir / "campaign-events").glob("*.json"))) == 1


def test_campaign_advances_a_full_first_pair_through_proxy_reconciliation(tmp_path) -> None:
    """The real adapter binds the pair-local direct result and proxy reconciliation."""

    manifest = _manifest(tmp_path)
    private_campaign_dir = _private_run(tmp_path, "first-pair-private-campaign")

    class PreflightReadiness:
        def probe(self, _request: StageRequest) -> ReadinessResult:
            return ReadinessResult("ready", "a" * 64)

    preflight_runner = _FakeRuntimeRunner()
    first = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=_write_complete_ledger,
            command_runner=preflight_runner,
        ),
        readiness_probe=PreflightReadiness(),
    )
    assert first.kind == "stage_completed"

    direct_runner = _FakeRuntimeRunner()
    second = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=_write_complete_ledger,
            command_runner=direct_runner,
        ),
        readiness_probe=runtime_module.QualificationCampaignReadinessProbe(
            command_runner=direct_runner
        ),
    )
    assert (second.kind, second.stage, second.status) == ("stage_completed", "score-direct", "passed")
    assert not list((private_campaign_dir / "slots").glob(".readiness-*-model-cache-evidence.json"))

    proxy_runner = _FakeRuntimeRunner()
    third = advance_qualification_campaign(
        manifest,
        private_campaign_dir,
        stage_runner=runtime_module.QualificationCampaignStageRunner(
            action=_write_complete_ledger,
            command_runner=proxy_runner,
        ),
        readiness_probe=runtime_module.QualificationCampaignReadinessProbe(
            command_runner=proxy_runner
        ),
    )

    assert (third.kind, third.sequence, third.stage, third.status) == (
        "stage_completed",
        3,
        "score-proxy",
        "passed",
    )
    slot = private_campaign_dir / "slots" / "01-cold-pair1"
    reconciliation = slot / "scored-proxy-reconciliation.json"
    proxy_outcome = slot / "scored-proxy-runtime-outcome.json"
    event = json.loads((private_campaign_dir / "campaign-events" / "0003.json").read_text(encoding="utf-8"))
    assert event["proxy_reconciliation_sha256"] == hashlib.sha256(reconciliation.read_bytes()).hexdigest()
    assert event["runtime_outcome_sha256"] == hashlib.sha256(proxy_outcome.read_bytes()).hexdigest()
    assert event["slot_ordinal"] == 1
    assert event["cache_lane"] == "cold"
    assert event["pair_index"] == 1


def test_supervisor_rejects_a_stage_request_outside_exact_campaign_topology(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    request = _campaign_stage_request(manifest, private_run_dir, stage="preflight")
    # The manifest-derived request remains valid, but the supervisor must not
    # accept a caller-substituted private directory outside ``slots``.
    invalid = StageRequest(
        request.manifest,
        request.manifest_sha256,
        request.sequence,
        request.slot,
        request.stage,
        private_run_dir,
        private_run_dir / "preflight-runtime-outcome.json",
    )
    runner = _FakeRuntimeRunner()

    outcome = runtime_module.supervise_qualification_runtime(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("invalid topology must block the child"),
        command_runner=runner,
        stage_request=invalid,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_campaign_request_invalid"
    assert _docker_commands(runner) == []


@pytest.mark.parametrize("kind", ["insecure", "equal", "symlink"])
def test_insecure_equal_or_symlinked_credentials_are_rejected_before_docker(kind, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    document = _manifest_document(manifest)
    credentials = document["qualification_runtime"]["credentials"]
    assert isinstance(credentials, dict)
    ordinary_path = Path(credentials["ordinary_proxy_api_key_file"])
    if kind == "insecure":
        ordinary_path.chmod(0o644)
    elif kind == "equal":
        credentials["qualification_policy_api_key_file"] = credentials["ordinary_proxy_api_key_file"]
        _store_manifest(manifest, document)
    else:
        replacement = ordinary_path.with_name("credential-target")
        replacement.write_text("different-dummy-secret", encoding="utf-8")
        replacement.chmod(0o600)
        ordinary_path.unlink()
        ordinary_path.symlink_to(replacement)
    runner = _FakeRuntimeRunner()

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("invalid credentials must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_credential_invalid"
    assert _docker_commands(runner) == []


@pytest.mark.parametrize("drift", ["mode", "symlink", "shared-value"])
def test_direct_stage_revalidates_credential_files_after_preflight(drift, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    credentials = _manifest_document(manifest)["qualification_runtime"]["credentials"]
    assert isinstance(credentials, dict)
    ordinary = Path(credentials["ordinary_proxy_api_key_file"])
    policy = Path(credentials["qualification_policy_api_key_file"])
    if drift == "mode":
        ordinary.chmod(0o644)
    elif drift == "symlink":
        replacement = ordinary.with_name("replacement-key")
        replacement.write_text("replacement-visible-token", encoding="utf-8")
        replacement.chmod(0o600)
        ordinary.unlink()
        ordinary.symlink_to(replacement)
    else:
        policy.write_text(ordinary.read_text(encoding="utf-8"), encoding="utf-8")
        policy.chmod(0o600)

    outcome = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("credential drift must block direct scoring"),
        command_runner=_FakeRuntimeRunner(),
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_credential_invalid"


def test_proxy_stage_revalidates_host_credentials_immediately_before_action(monkeypatch, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    assert (
        _supervise(
            manifest=manifest,
            stage="preflight",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )
    assert (
        _supervise(
            manifest=manifest,
            stage="score-direct",
            private_run_dir=private_run_dir,
            action=_write_complete_ledger,
            command_runner=_FakeRuntimeRunner(),
        ).status
        == "passed"
    )
    credentials = _manifest_document(manifest)["qualification_runtime"]["credentials"]
    assert isinstance(credentials, dict)
    ordinary = Path(credentials["ordinary_proxy_api_key_file"])
    policy = Path(credentials["qualification_policy_api_key_file"])
    import shiftedx_harness_proxy.qualification_runtime as runtime

    original_auth_check = runtime._verify_proxy_auth_and_metrics

    def drift_after_setup(*args) -> None:
        original_auth_check(*args)
        policy.write_text(ordinary.read_text(encoding="utf-8"), encoding="utf-8")
        policy.chmod(0o600)

    monkeypatch.setattr(runtime, "_verify_proxy_auth_and_metrics", drift_after_setup)

    outcome = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("credential drift before action must block proxy scoring"),
        command_runner=_FakeRuntimeRunner(),
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_credential_invalid"


@pytest.mark.parametrize(
    ("section", "expected_category"),
    [("proxy", "proxy_port_unavailable"), ("observer", "observer_port_unavailable")],
)
def test_occupied_ports_reject_unrelated_ready_processes_before_docker(tmp_path, section, expected_category) -> None:
    manifest = _manifest(tmp_path)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    try:
        document = _manifest_document(manifest)
        occupied_port = probe.getsockname()[1]
        document["qualification_runtime"][section]["port"] = occupied_port
        if section == "observer":
            document["qualification_runtime"]["observer"]["container_url"] = (
                f"http://host.docker.internal:{occupied_port}/v1"
            )
        _store_manifest(manifest, document)
        runner = _FakeRuntimeRunner()
        outcome = _supervise(
            manifest=manifest,
            stage="preflight",
            private_run_dir=_private_run(tmp_path),
            action=lambda _lease: pytest.fail("occupied port must not invoke action"),
            command_runner=runner,
        )
    finally:
        probe.close()

    assert outcome.failure_category == expected_category
    assert _docker_commands(runner) == []


def test_unrelated_observer_ready_response_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("shiftedx_harness_proxy.qualification_runtime.time.sleep", lambda _seconds: None)
    runner = _FakeRuntimeRunner(failure="observer_ready")
    outcome = _supervise(
        manifest=_manifest(tmp_path),
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("unrelated health response must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_observer_unhealthy"
    assert runner.observer.terminated


def test_action_nonzero_and_runtime_death_preserve_attestation_then_fail(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    runner = _FakeRuntimeRunner()
    action_attestations: list[Path] = []

    def action(lease) -> int:
        assert lease.attestation_path is not None and lease.attestation_path.exists()
        action_attestations.append(lease.attestation_path)
        return 23

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=action,
        command_runner=runner,
    )

    assert action_attestations
    assert outcome.status == "failed"
    assert outcome.action_exit_code == 23
    assert outcome.failure_category == "action_failed"
    assert action_attestations[0].exists()

    second_manifest = _manifest(tmp_path / "second")
    second_private_run = _private_run(tmp_path / "second")
    death_runner = _FakeRuntimeRunner()

    def interrupted_action(_lease) -> int:
        death_runner.observer.exit_code = 1
        return 0

    died = _supervise(
        manifest=second_manifest,
        stage="preflight",
        private_run_dir=second_private_run,
        action=interrupted_action,
        command_runner=death_runner,
    )
    assert died.failure_category == "runtime_observer_stopped"

    container_manifest = _manifest(tmp_path / "container")
    container_private_run = _private_run(tmp_path / "container")
    container_runner = _FakeRuntimeRunner()

    def container_died_action(_lease) -> int:
        container_runner.container_running = False
        return 0

    container_died = _supervise(
        manifest=container_manifest,
        stage="preflight",
        private_run_dir=container_private_run,
        action=container_died_action,
        command_runner=container_runner,
    )
    assert container_died.failure_category == "runtime_inspect_drift"


def test_signal_and_cleanup_failure_are_categorical_and_cleanup_is_scoped(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    signal_runner = _FakeRuntimeRunner()

    def interrupted_action(_lease) -> int:
        os.kill(os.getpid(), signal.SIGTERM)
        return 0

    interrupted = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=interrupted_action,
        command_runner=signal_runner,
    )
    assert interrupted.status == "interrupted"
    assert interrupted.failure_category == "runtime_interrupted"
    assert signal_runner.observer.terminated

    setup_manifest = _manifest(tmp_path / "setup-signal")
    setup_private_run = _private_run(tmp_path / "setup-signal")
    setup_runner = _FakeRuntimeRunner(failure="signal_initializer")
    setup_interrupted = _supervise(
        manifest=setup_manifest,
        stage="preflight",
        private_run_dir=setup_private_run,
        action=lambda _lease: pytest.fail("signal during setup must not invoke action"),
        command_runner=setup_runner,
    )
    assert setup_interrupted.status == "interrupted"
    assert setup_interrupted.failure_category == "runtime_interrupted"
    assert any(command[:3] == ("docker", "volume", "rm") for command in _docker_commands(setup_runner))

    cleanup_manifest = _manifest(tmp_path / "cleanup")
    cleanup_private_run = _private_run(tmp_path / "cleanup")
    cleanup_runner = _FakeRuntimeRunner(failure="cleanup_volume")
    cleanup = _supervise(
        manifest=cleanup_manifest,
        stage="preflight",
        private_run_dir=cleanup_private_run,
        action=lambda _lease: 0,
        command_runner=cleanup_runner,
    )
    assert cleanup.status == "failed"
    assert cleanup.failure_category == "runtime_cleanup_failed"
    assert any(command[:3] == ("docker", "volume", "rm") for command in _docker_commands(cleanup_runner))


@pytest.mark.parametrize(
    "boundary",
    ["signal_cleanup_observer", "signal_cleanup_container", "signal_cleanup_volume"],
)
def test_interruption_keeps_handlers_through_every_cleanup_boundary_and_ignores_repeats(boundary, tmp_path) -> None:
    runner = _FakeRuntimeRunner(failure=boundary)

    def interrupted_action(_lease) -> int:
        os.kill(os.getpid(), signal.SIGTERM)
        return 0

    outcome = _supervise(
        manifest=_manifest(tmp_path),
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=interrupted_action,
        command_runner=runner,
    )

    assert outcome.status == "interrupted"
    assert outcome.failure_category == "runtime_interrupted"
    assert outcome.outcome_path is not None
    record = json.loads(outcome.outcome_path.read_text(encoding="utf-8"))
    assert record["status"] == "interrupted"
    assert runner.observer.terminated
    commands = _docker_commands(runner)
    assert any(command[:3] == ("docker", "rm", "--force") for command in commands)
    assert any(command[:3] == ("docker", "volume", "rm") for command in commands)


@pytest.mark.parametrize(
    ("failure", "name_fragment"),
    [
        ("signal_initializer", "shiftedx-qualification-initializer-preflight-"),
        ("signal_launch", "shiftedx-qualification-preflight-"),
    ],
)
def test_interrupted_detached_resources_are_removed_by_predeclared_owned_names(
    failure, name_fragment, tmp_path
) -> None:
    runner = _FakeRuntimeRunner(failure=failure)
    manifest = _manifest(tmp_path)
    manifest_sha256 = _sha256_file(manifest)

    outcome = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("interrupted setup must not invoke action"),
        command_runner=runner,
    )

    assert outcome.status == "interrupted"
    detached = [command for command in _docker_commands(runner) if command[:3] == ("docker", "run", "--detach")]
    assert detached
    resource = next(command for command in detached if name_fragment in command[command.index("--name") + 1])
    name = resource[resource.index("--name") + 1]
    assert name_fragment in name
    assert f"io.shiftedx.qualification.manifest={manifest_sha256}" in resource
    cleanup = [command for command in _docker_commands(runner) if command[:3] == ("docker", "rm", "--force")]
    assert any(command[-1] == name for command in cleanup)
    cleanup_index = next(index for index, command in enumerate(_docker_commands(runner)) if command[-1:] == (name,))
    volume_index = next(
        index for index, command in enumerate(_docker_commands(runner)) if command[:3] == ("docker", "volume", "rm")
    )
    assert cleanup_index < volume_index


def test_interrupted_volume_create_is_resolved_by_its_predeclared_owned_name(tmp_path) -> None:
    runner = _FakeRuntimeRunner(failure="signal_volume_create")

    outcome = _supervise(
        manifest=_manifest(tmp_path),
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("interrupted setup must not invoke action"),
        command_runner=runner,
    )

    assert outcome.status == "interrupted"
    commands = _docker_commands(runner)
    volume_create = next(command for command in commands if command[:3] == ("docker", "volume", "create"))
    volume_name = volume_create[-1]
    assert any(command == ("docker", "volume", "rm", volume_name) for command in commands)
    assert not [command for command in commands if command[:3] == ("docker", "rm", "--force")]


def test_unresolved_owned_resource_during_cleanup_fails_the_stage(tmp_path) -> None:
    runner = _FakeRuntimeRunner()

    def action(lease: RuntimeLease) -> int:
        runner.failure = "cleanup_inspect"
        return _write_complete_ledger(lease)

    outcome = _supervise(
        manifest=_manifest(tmp_path),
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=action,
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_cleanup_failed"


def test_existing_evidence_is_never_clobbered_and_direct_stage_uses_preflight_attestation(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preexisting = private_run_dir / "preflight-runtime-attestation.json"
    preexisting.write_text("prior-private-evidence\n", encoding="utf-8")
    preexisting.chmod(0o600)
    blocked_runner = _FakeRuntimeRunner()

    blocked = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=lambda _lease: pytest.fail("existing evidence must block action"),
        command_runner=blocked_runner,
    )
    assert blocked.failure_category == "runtime_evidence_exists"
    assert preexisting.read_text(encoding="utf-8") == "prior-private-evidence\n"
    assert _docker_commands(blocked_runner) == []

    outcome_root = tmp_path / "existing-outcome"
    outcome_manifest = _manifest(outcome_root)
    outcome_private_run = _private_run(outcome_root)
    existing_outcome = outcome_private_run / "preflight-runtime-outcome.json"
    existing_outcome.write_text("prior-outcome\n", encoding="utf-8")
    existing_outcome.chmod(0o600)
    outcome_runner = _FakeRuntimeRunner()
    outcome_blocked = _supervise(
        manifest=outcome_manifest,
        stage="preflight",
        private_run_dir=outcome_private_run,
        action=lambda _lease: pytest.fail("existing outcome must block action"),
        command_runner=outcome_runner,
    )
    assert outcome_blocked.failure_category == "runtime_outcome_exists"
    assert existing_outcome.read_text(encoding="utf-8") == "prior-outcome\n"
    assert _docker_commands(outcome_runner) == []

    proxy_root = tmp_path / "missing-proxy-preflight"
    proxy_manifest = _manifest(proxy_root)
    proxy_private_run = _private_run(proxy_root)
    proxy_runner = _FakeRuntimeRunner()
    proxy_blocked = _supervise(
        manifest=proxy_manifest,
        stage="score-proxy",
        private_run_dir=proxy_private_run,
        action=lambda _lease: pytest.fail("proxy scoring requires the matching preflight attestation"),
        command_runner=proxy_runner,
    )
    assert proxy_blocked.failure_category == "runtime_preflight_attestation_invalid"
    assert _docker_commands(proxy_runner) == []

    clean_manifest = _manifest(tmp_path / "clean")
    clean_private_run = _private_run(tmp_path / "clean")
    preflight_runner = _FakeRuntimeRunner()
    passed = _supervise(
        manifest=clean_manifest,
        stage="preflight",
        private_run_dir=clean_private_run,
        action=_write_complete_ledger,
        command_runner=preflight_runner,
    )
    assert passed.status == "passed"
    direct_runner = _FakeRuntimeRunner()
    direct = _supervise(
        manifest=clean_manifest,
        stage="score-direct",
        private_run_dir=clean_private_run,
        action=lambda lease: (
            assert_direct_lease(lease),
            _write_complete_ledger(lease),
        )[1],
        command_runner=direct_runner,
    )
    assert direct.status == "passed"
    assert _docker_commands(direct_runner) == []
    assert (clean_private_run / "scored-direct-runtime-outcome.json").exists()


def assert_direct_lease(lease) -> None:
    assert lease.proxy_base_url is None
    assert lease.attestation_path is not None and lease.attestation_path.name == "preflight-runtime-attestation.json"
    assert lease.output_ledger.name == "scored-direct.jsonl"


def test_outcomes_and_attestations_are_private_mode_600_and_fresh_instances(tmp_path) -> None:
    first_root = tmp_path / "first"
    first_manifest = _manifest(first_root)
    first_private = _private_run(first_root)
    first = _supervise(
        manifest=first_manifest,
        stage="preflight",
        private_run_dir=first_private,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    second_root = tmp_path / "second"
    second_manifest = _manifest(second_root)
    second_private = _private_run(second_root)
    second = _supervise(
        manifest=second_manifest,
        stage="preflight",
        private_run_dir=second_private,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )

    assert first.status == second.status == "passed"
    first_attestation = json.loads((first_private / "preflight-runtime-attestation.json").read_text())
    second_attestation = json.loads((second_private / "preflight-runtime-attestation.json").read_text())
    assert first_attestation["runtime_instance_sha256"] != second_attestation["runtime_instance_sha256"]
    for path in (
        first_private / "preflight-runtime-attestation.json",
        first_private / "preflight-runtime-outcome.json",
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_scored_proxy_requires_preflight_then_uses_a_fresh_scored_attestation(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preflight = _supervise(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    direct = _supervise(
        manifest=manifest,
        stage="score-direct",
        private_run_dir=private_run_dir,
        action=_write_complete_ledger,
        command_runner=_FakeRuntimeRunner(),
    )
    assert direct.status == "passed"
    lease_seen: list[RuntimeLease] = []
    scored = _supervise(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=lambda lease: lease_seen.append(lease) or _write_complete_ledger(lease),
        command_runner=_FakeRuntimeRunner(),
    )

    assert scored.status == "passed"
    assert lease_seen[0].observer_ledger is not None
    assert lease_seen[0].observer_ledger.name == "scored-proxy-model-boundary.jsonl"
    attestation = json.loads((private_run_dir / "scored-proxy-runtime-attestation.json").read_text())
    assert attestation["stage"] == "scored_proxy"
    preflight_attestation = json.loads((private_run_dir / "preflight-runtime-attestation.json").read_text())
    assert attestation["runtime_instance_sha256"] != preflight_attestation["runtime_instance_sha256"]


def _load_runtime_cli():
    script = Path(__file__).parents[1] / "scripts" / "run_qualification_runtime.py"
    spec = importlib.util.spec_from_file_location("run_qualification_runtime", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lease(stage: str) -> RuntimeLease:
    return RuntimeLease(
        stage=stage,
        run_manifest_sha256="a" * 64,
        source_commit="b" * 40,
        image_digest="sha256:" + "c" * 64,
        model="approved-model",
        benchmark_revision="335e6694e4aec13e9370af8a993d8c8f14d7ffb5",
        agentic_set="expanded",
        sampler_profile="historical-aeon-v1",
        scenario_order_sha256="d" * 64,
        scenario_count=2,
        benchmark_source_path=Path("/private/benchmark/src"),
        trial_run_id="qualified-run",
        cache_lane="warm-prefix",
        pair_index=2,
        campaign_id_sha256="9" * 64,
        slot_ordinal=5,
        direct_base_url="https://private-model.invalid/v1",
        direct_api_key_file=Path("/private/direct-api-key"),
        proxy_base_url="http://127.0.0.1:19090/v1" if stage != "score-direct" else None,
        proxy_metrics_url="http://127.0.0.1:19090/metrics" if stage != "score-direct" else None,
        proxy_api_key_file=Path("/private/qualification-policy-key") if stage != "score-direct" else None,
        observer_ledger=Path("/private/observer.jsonl") if stage != "score-direct" else None,
        proxy_request_ledger=(
            Path("/private/preflight-proxy-requests.jsonl")
            if stage == "preflight"
            else Path("/private/scored-proxy-requests.jsonl")
            if stage == "score-proxy"
            else None
        ),
        direct_model_attempt_ledger=(
            Path("/private/preflight-direct-model-boundary.jsonl")
            if stage == "preflight"
            else Path("/private/scored-direct-model-boundary.jsonl")
            if stage == "score-direct"
            else None
        ),
        prime_model_attempt_ledger=(
            Path("/private/scored-direct-prime-model-boundary.jsonl")
            if stage == "score-direct"
            else Path("/private/scored-proxy-prime-model-boundary.jsonl")
            if stage == "score-proxy"
            else None
        ),
        model_evidence_path=Path(f"/private/{stage}-model-cache-evidence.json"),
        model_identity_sha256="e" * 64,
        model_contract_sha256="f" * 64,
        preflight_ledger=Path("/private/preflight.jsonl"),
        output_ledger=Path(f"/private/{stage}.jsonl"),
        attestation_path=Path("/private/runtime-attestation.json"),
    )


@pytest.mark.parametrize("stage", ["preflight", "score-direct", "score-proxy"])
def test_thin_cli_derives_fixed_child_argv_without_secret_values(stage) -> None:
    cli = _load_runtime_cli()
    argv = cli.paired_runner_argv(_lease(stage))
    serialized = "\n".join(argv)

    assert argv[0] == os.sys.executable
    assert "run_paired_agentic_trial.py" in argv[1]
    assert "--candidate-source-commit" in argv
    assert "--candidate-image-digest" in argv
    assert "--run-manifest-sha256" in argv
    assert argv[argv.index("--sampler-profile") + 1] == "historical-aeon-v1"
    assert argv[argv.index("--run-id") + 1] == "qualified-run"
    assert argv[argv.index("--cache-mode") + 1] == ("bypass" if stage == "preflight" else "warm-prefix")
    assert "private-secret-value" not in serialized
    assert "--model" in argv
    if stage == "preflight":
        assert "--paired-preflight" in argv
        assert "--direct-base-url" in argv
        assert "--proxy-base-url" in argv
        assert argv[argv.index("--direct-model-attempt-ledger") + 1] == (
            "/private/preflight-direct-model-boundary.jsonl"
        )
        assert argv[argv.index("--variant") + 1] == "warm-prefix-pair2-preflight-expanded"
    elif stage == "score-direct":
        assert "--proxy-policy" not in argv
        assert "--base-url" in argv
        assert argv[argv.index("--direct-model-attempt-ledger") + 1] == ("/private/scored-direct-model-boundary.jsonl")
        assert argv[argv.index("--variant") + 1] == "warm-prefix-pair2-direct-expanded"
        assert argv[argv.index("--preflight-runtime-outcome") + 1] == "/private/preflight-runtime-outcome.json"
    else:
        assert "--proxy-policy" in argv
        assert "--proxy-observer-ledger" in argv
        assert argv[argv.index("--variant") + 1] == "warm-prefix-pair2-proxy-expanded"
        assert argv[argv.index("--preflight-runtime-outcome") + 1] == "/private/preflight-runtime-outcome.json"
        assert argv[argv.index("--direct-runtime-outcome") + 1] == "/private/scored-direct-runtime-outcome.json"


def test_thin_cli_forces_preflight_bypass_even_for_a_warm_campaign() -> None:
    """Preflight must never seed the RAM prefix used by a later warm treatment."""

    cli = _load_runtime_cli()
    argv = cli.paired_runner_argv(_lease("preflight"))

    assert argv[argv.index("--cache-mode") + 1] == "bypass"


def test_thin_cli_runs_child_with_only_pinned_benchmark_source_environment(monkeypatch) -> None:
    cli = _load_runtime_cli()
    captured: list[dict[str, object]] = []

    def fake_run(argv, *, check, env):
        captured.append({"argv": argv, "check": check, "env": env})
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.invoke_paired_runner(_lease("score-direct")) == 0
    assert len(captured) == 2
    prime = captured[0]["argv"]
    assert "--cache-prime-only" in prime
    assert prime[prime.index("--cache-prime-arm") + 1] == "direct"
    assert prime[prime.index("--model-attempt-ledger") + 1] == ("/private/scored-direct-prime-model-boundary.jsonl")
    assert prime[prime.index("--base-url") + 1] == "https://private-model.invalid/v1"
    assert prime[prime.index("--sampler-profile") + 1] == "historical-aeon-v1"
    scored = captured[1]
    assert scored["check"] is False
    assert scored["env"] == {
        "PYTHONPATH": "/private/benchmark/src",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def test_thin_cli_cold_lane_uses_bypass_and_never_primes(monkeypatch) -> None:
    cli = _load_runtime_cli()
    captured: list[list[str]] = []

    def fake_run(argv, *, check, env):
        del check, env
        captured.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    lease = replace(_lease("score-direct"), cache_lane="cold", prime_model_attempt_ledger=None)

    assert cli.invoke_paired_runner(lease) == 0
    assert len(captured) == 1
    assert captured[0][captured[0].index("--cache-mode") + 1] == "bypass"
    assert "--cache-prime-only" not in captured[0]


def test_campaign_cli_advances_only_the_manifest_derived_next_stage(tmp_path) -> None:
    cli = _load_runtime_cli()
    calls: dict[str, object] = {}

    def campaign_advancer(manifest, private_campaign_dir, *, stage_runner, readiness_probe):
        calls.update(
            {
                "manifest": manifest,
                "private_campaign_dir": private_campaign_dir,
                "stage_runner": stage_runner,
                "readiness_probe": readiness_probe,
            }
        )
        return SimpleNamespace(kind="stage_completed")

    result = cli.main(
        ["--manifest", str(tmp_path / "manifest.json"), "--private-campaign-dir", str(tmp_path)],
        campaign_advancer=campaign_advancer,
    )

    assert result == 0
    assert set(calls) == {"manifest", "private_campaign_dir", "stage_runner", "readiness_probe"}
    assert calls["manifest"] == tmp_path / "manifest.json"
    assert calls["private_campaign_dir"] == tmp_path

    with pytest.raises(SystemExit, match="2"):
        cli.main(
            [
                "--manifest",
                str(tmp_path / "manifest.json"),
                "--private-campaign-dir",
                str(tmp_path),
                "--stage",
                "preflight",
            ],
            campaign_advancer=campaign_advancer,
        )


def test_campaign_cli_rejects_relative_campaign_dir_before_creating_campaign_state(tmp_path) -> None:
    """A relative run root would later produce rejected relative evidence paths."""

    cli = _load_runtime_cli()
    called = False

    def campaign_advancer(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("relative campaign paths must not reach the advancer")

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--manifest",
                str(tmp_path / "approved-manifest.json"),
                "--private-campaign-dir",
                "benchmark-reports/private/qualification.relative",
            ],
            campaign_advancer=campaign_advancer,
        )

    assert raised.value.code == 2
    assert called is False


def test_benchmarking_manifest_example_is_duplicate_rejecting_json_with_c1_model_contract() -> None:
    document = (Path(__file__).parents[1] / "docs" / "benchmarking.md").read_text(encoding="utf-8")
    assert 'PRIVATE_ROOT="$(pwd -P)/benchmark-reports/private"' in document
    assert 'CAMPAIGN_DIR="$(mktemp -d "$PRIVATE_ROOT"/qualification.XXXXXX)"' in document
    manifest_section = document.split("### Private manifest v1", 1)[1]
    encoded = manifest_section.split("```json\n", 1)[1].split("\n```", 1)[0]

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    parsed = json.loads(encoded, object_pairs_hook=unique_object)
    runtime = parsed["qualification_runtime"]
    assert isinstance(runtime, dict)
    model = runtime["model"]
    campaign = runtime["campaign"]
    assert isinstance(model, dict)
    assert isinstance(campaign, dict)
    assert set(model) == {
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
    }
    assert set(campaign) == {
        "campaign_id",
        "slots",
        "stage_order",
        "treatment_order",
        "model_instance_policy",
        "failure_policy",
    }
    assert len(campaign["slots"]) == 6
    assert "--ssd-session-cache=off" in model["required_launch_flags"]
    assert runtime["benchmark"]["scenario_count"] > 0
    assert "restart it from the exact frozen model" in document
    assert "Preflight always sends" in document


def test_private_manifest_documentation_is_valid_json_with_positive_scenario_count() -> None:
    documentation = (Path(__file__).parents[1] / "docs" / "benchmarking.md").read_text(encoding="utf-8")
    section = documentation.split("### Private manifest v1\n\n", 1)[1]
    serialized = section.split("```json\n", 1)[1].split("\n```", 1)[0]
    document = json.loads(serialized)

    assert set(document) == {"qualification_runtime"}
    runtime = document["qualification_runtime"]
    assert set(runtime) == {
        "schema_version",
        "source_commit",
        "image",
        "model",
        "benchmark",
        "campaign",
        "observer",
        "proxy",
        "credentials",
    }
    assert runtime["benchmark"]["scenario_count"] > 0
    assert runtime["campaign"]["treatment_order"] == ["direct", "proxy"]
