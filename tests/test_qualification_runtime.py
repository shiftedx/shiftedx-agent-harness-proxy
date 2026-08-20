from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import signal
import socket
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from shiftedx_harness_proxy.qualification_runtime import Outcome, RuntimeLease, supervise_qualification_runtime


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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
            "model": {
                "public_id": "private-model-id",
                "upstream_url": "http://private-model.invalid/v1",
                "upstream_authenticated": True,
            },
            "benchmark": {
                "revision": "335e6694e4aec13e9370af8a993d8c8f14d7ffb5",
                "agentic_set": "expanded",
                "scenario_order_sha256": _canonical_sha256(scenario_order),
                "scenario_count": len(scenario_order),
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


class _FakeProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.waited = False
        self.exit_code: int | None = None

    def poll(self) -> int | None:
        return self.exit_code

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.waited = True
        return 0

    def kill(self) -> None:
        self.terminated = True


class _FakeRuntimeRunner:
    def __init__(self, *, failure: str | None = None, drift: str | None = None) -> None:
        self.calls: list[tuple[str, tuple[str, ...], dict[str, str] | None]] = []
        self.observer = _FakeProcess()
        self.labels: dict[str, str] = {}
        self.volume_name = "expected-volume"
        self.failure = failure
        self.drift = drift
        self.container_running = True

    def _capture_labels(self, argv: tuple[str, ...]) -> None:
        for index, value in enumerate(argv[:-1]):
            if value == "--label":
                key, label_value = argv[index + 1].split("=", 1)
                self.labels[key] = label_value

    def _capture_volume(self, argv: tuple[str, ...]) -> None:
        for value in argv:
            if value.startswith("type=volume,src="):
                self.volume_name = value.split(",", 2)[1].removeprefix("src=")

    def run(
        self, argv: tuple[str, ...], *, env: dict[str, str] | None = None, timeout: float | None = None
    ) -> SimpleNamespace:
        del timeout
        self.calls.append(("run", argv, env))
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
            self._capture_labels(argv)
            self.volume_name = argv[-1]
            return SimpleNamespace(returncode=0, stdout=self.volume_name + "\n", stderr="")
        if argv[:3] == ("docker", "run", "--rm") and self.failure == "signal_initializer":
            os.kill(os.getpid(), signal.SIGTERM)
        if argv[:3] == ("docker", "run", "--rm") and self.failure == "initializer":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if argv[:3] == ("docker", "run", "--detach"):
            if self.failure == "launch":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            self._capture_labels(argv)
            self._capture_volume(argv)
            return SimpleNamespace(returncode=0, stdout="f" * 64 + "\n", stderr="")
        if argv[:3] == ("docker", "container", "inspect"):
            if "{{json .Config.Labels}}" in argv:
                return SimpleNamespace(returncode=0, stdout=json.dumps(self.labels), stderr="")
            if self.failure == "inspect":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            document = _runtime_inspect(self.labels, self.volume_name, running=self.container_running)
            if self.drift == "resources":
                document["HostConfig"]["ReadonlyRootfs"] = False
            elif self.drift == "bind":
                document["HostConfig"]["PortBindings"] = {
                    "8090/tcp": [{"HostIp": "0.0." + "0.0", "HostPort": "19090"}]
                }
            elif self.drift == "settings":
                document["Config"]["Env"] = ["DEPLOYMENT_PROFILE=development"]
            elif self.drift == "image":
                document["Image"] = "sha256:" + "d" * 64
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(document),
                stderr="",
            )
        if argv[:3] == ("docker", "volume", "inspect"):
            if "{{json .Labels}}" in argv:
                return SimpleNamespace(returncode=0, stdout=json.dumps(self.labels), stderr="")
            return SimpleNamespace(returncode=0, stdout=json.dumps({"Labels": self.labels}), stderr="")
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
        if argv[:3] == ("docker", "volume", "rm") and self.failure == "cleanup_volume":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
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
        if self.failure == "observer_ready":
            return 200, {"status": "live", "instance_sha256": "unrelated-ready-process"}
        observer_environment = next(call[2] for call in self.calls if call[0] == "spawn")
        assert observer_environment is not None
        return 200, {
            "status": "live",
            "instance_sha256": observer_environment["QUALIFICATION_OBSERVER_INSTANCE_SHA256"],
        }


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
        return 0

    outcome = supervise_qualification_runtime(
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
        call[1] for call in runner.calls if call[0] == "run" and call[1][:3] == ("docker", "run", "--rm")
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


def _private_run(tmp_path: Path, name: str = "private-run") -> Path:
    path = tmp_path / name
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


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
        ("initializer", "runtime_secret_initialize_failed", False),
        ("observer_spawn", "runtime_observer_start_failed", False),
        ("observer_ready", "runtime_observer_unhealthy", False),
        ("observer_ledger", "runtime_observer_ledger_invalid", False),
        ("launch", "runtime_proxy_launch_failed", False),
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

    outcome = supervise_qualification_runtime(
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


@pytest.mark.parametrize("drift", ["resources", "bind", "settings", "image"])
def test_inspect_drift_fails_closed_before_action_and_cleans(drift, tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    runner = _FakeRuntimeRunner(drift=drift)

    outcome = supervise_qualification_runtime(
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

    outcome = supervise_qualification_runtime(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("invalid manifest must not invoke action"),
        command_runner=runner,
    )

    assert outcome.status == "failed"
    assert outcome.failure_category == "runtime_manifest_invalid"
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

    outcome = supervise_qualification_runtime(
        manifest=manifest,
        stage="preflight",
        private_run_dir=_private_run(tmp_path),
        action=lambda _lease: pytest.fail("invalid credentials must not invoke action"),
        command_runner=runner,
    )

    assert outcome.failure_category == "runtime_credential_invalid"
    assert _docker_commands(runner) == []


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
        outcome = supervise_qualification_runtime(
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
    outcome = supervise_qualification_runtime(
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

    outcome = supervise_qualification_runtime(
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

    died = supervise_qualification_runtime(
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

    container_died = supervise_qualification_runtime(
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

    interrupted = supervise_qualification_runtime(
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
    setup_interrupted = supervise_qualification_runtime(
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
    cleanup = supervise_qualification_runtime(
        manifest=cleanup_manifest,
        stage="preflight",
        private_run_dir=cleanup_private_run,
        action=lambda _lease: 0,
        command_runner=cleanup_runner,
    )
    assert cleanup.status == "failed"
    assert cleanup.failure_category == "runtime_cleanup_failed"
    assert any(command[:3] == ("docker", "volume", "rm") for command in _docker_commands(cleanup_runner))


def test_existing_evidence_is_never_clobbered_and_direct_stage_uses_preflight_attestation(tmp_path) -> None:
    manifest = _manifest(tmp_path)
    private_run_dir = _private_run(tmp_path)
    preexisting = private_run_dir / "preflight-runtime-attestation.json"
    preexisting.write_text("prior-private-evidence\n", encoding="utf-8")
    preexisting.chmod(0o600)
    blocked_runner = _FakeRuntimeRunner()

    blocked = supervise_qualification_runtime(
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
    outcome_blocked = supervise_qualification_runtime(
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
    proxy_blocked = supervise_qualification_runtime(
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
    passed = supervise_qualification_runtime(
        manifest=clean_manifest,
        stage="preflight",
        private_run_dir=clean_private_run,
        action=lambda _lease: 0,
        command_runner=preflight_runner,
    )
    assert passed.status == "passed"
    direct_runner = _FakeRuntimeRunner()
    direct = supervise_qualification_runtime(
        manifest=clean_manifest,
        stage="score-direct",
        private_run_dir=clean_private_run,
        action=lambda lease: (
            assert_direct_lease(lease),
            0,
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
    first = supervise_qualification_runtime(
        manifest=first_manifest,
        stage="preflight",
        private_run_dir=first_private,
        action=lambda _lease: 0,
        command_runner=_FakeRuntimeRunner(),
    )
    second_root = tmp_path / "second"
    second_manifest = _manifest(second_root)
    second_private = _private_run(second_root)
    second = supervise_qualification_runtime(
        manifest=second_manifest,
        stage="preflight",
        private_run_dir=second_private,
        action=lambda _lease: 0,
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
    preflight = supervise_qualification_runtime(
        manifest=manifest,
        stage="preflight",
        private_run_dir=private_run_dir,
        action=lambda _lease: 0,
        command_runner=_FakeRuntimeRunner(),
    )
    assert preflight.status == "passed"
    lease_seen: list[RuntimeLease] = []
    scored = supervise_qualification_runtime(
        manifest=manifest,
        stage="score-proxy",
        private_run_dir=private_run_dir,
        action=lambda lease: lease_seen.append(lease) or 0,
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
        scenario_order_sha256="d" * 64,
        scenario_count=2,
        direct_base_url="https://private-model.invalid/v1",
        direct_api_key_file=Path("/private/direct-api-key"),
        proxy_base_url="http://127.0.0.1:19090/v1" if stage != "score-direct" else None,
        proxy_metrics_url="http://127.0.0.1:19090/metrics" if stage != "score-direct" else None,
        proxy_api_key_file=Path("/private/qualification-policy-key") if stage != "score-direct" else None,
        observer_ledger=Path("/private/observer.jsonl") if stage != "score-direct" else None,
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
    assert "private-secret-value" not in serialized
    assert "--model" in argv
    if stage == "preflight":
        assert "--paired-preflight" in argv
        assert "--direct-base-url" in argv
        assert "--proxy-base-url" in argv
    elif stage == "score-direct":
        assert "--proxy-policy" not in argv
        assert "--base-url" in argv
    else:
        assert "--proxy-policy" in argv
        assert "--proxy-observer-ledger" in argv


def test_thin_cli_only_passes_manifest_stage_and_private_directory_to_supervisor(tmp_path) -> None:
    cli = _load_runtime_cli()
    calls: dict[str, object] = {}

    def supervisor(**kwargs) -> Outcome:
        calls.update(kwargs)
        return Outcome(
            stage="preflight",
            status="passed",
            action_exit_code=0,
            failure_category=None,
            attestation_path=None,
            outcome_path=None,
        )

    result = cli.main(
        ["--manifest", str(tmp_path / "manifest.json"), "--stage", "preflight", "--private-run-dir", str(tmp_path)],
        supervisor=supervisor,
    )

    assert result == 0
    assert set(calls) == {"manifest", "stage", "private_run_dir", "action"}
    assert calls["action"] is cli.invoke_paired_runner
