from __future__ import annotations

import hashlib
import json
import stat
from base64 import urlsafe_b64encode
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from shiftedx_harness_proxy.qualification_model_evidence import (
    ModelEvidenceContract,
    ModelEvidenceFailure,
    ModelEvidenceSession,
    ProbeSnapshot,
    SafeAttemptRecord,
    SystemModelEvidenceProbe,
    model_endpoint_contract_hashes,
)


def _sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class _Probe:
    """Safe fake of the read-only MTPLX probe seam."""

    def __init__(self) -> None:
        self.before = _snapshot()
        self.after = _snapshot()
        self.calls: list[str] = []
        self.after_error: Exception | None = None
        self.expected_api_key: str | None = "model-api-token"

    def snapshot(
        self, *, host: str, port: int, api_key: str | None, contract: ModelEvidenceContract
    ) -> ProbeSnapshot:
        del contract
        assert host == "127.0.0.1"
        assert port == 8999
        assert api_key == self.expected_api_key
        self.calls.append("snapshot")
        if len(self.calls) > 1 and self.after_error is not None:
            raise self.after_error
        return self.before if len(self.calls) == 1 else self.after


def _snapshot(
    *,
    requests_completed: int = 7,
    executable_sha256: str = "a" * 64,
    distribution_sha256: str = "c" * 64,
) -> ProbeSnapshot:
    health = {
        "status": "ok",
        "startup_pid": 444,
        "started_at": "2026-08-20T00:00:00Z",
        "instance_id": "instance-safe-id",
        "active_requests": 0,
        "foreground_requests": 0,
        "requests_completed": requests_completed,
    }
    models = {"data": [{"id": "public-qualified-model"}]}
    settings = {"cache": {"enabled": True}, "safe_version": "2.7.1"}
    process = {
        "pid": 444,
        "start_time": "12345",
        "executable_sha256": executable_sha256,
        "command_sha256": "b" * 64,
        "mtplx_distribution_sha256": distribution_sha256,
        "command_flags": ("--host=127.0.0.1", "--port=8999", "--foreground"),
    }
    return ProbeSnapshot(
        health=health,
        models=models,
        settings=settings,
        listener_owners=(process,),
    )


def _real_mtplx_settings() -> dict[str, object]:
    """Literal safe 2.7.1 surface, independently of the probe implementation."""

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
        "model_controls": {"reasoning": "native"},
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
        "api_key_required": False,
        "api_key_source": "none",
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


def _raw_real_mtplx_health(*, requests_completed: int = 7) -> dict[str, object]:
    return {
        "ok": True,
        "active_requests": 0,
        "foreground_active": 0,
        "requests_completed": requests_completed,
        "startup": {
            "pid": 444,
            "started_at": 1712345678.25,
            "launch_id": None,
            "model_id": "private-serving-model",
            "chat_template_path": "/private/template.jinja",
        },
        "model": "private-serving-model",
        "model_path": "/private/model",
        "smart_fan_last_error": "private diagnostic",
        "hardware": {"serial": "private"},
    }


def _raw_real_mtplx_models() -> dict[str, object]:
    return {
        "object": "list",
        "data": [
            {
                "id": "public-qualified-model",
                "object": "model",
                "created": 1712345678,
                "owned_by": "private-owner",
                "capability": {"chat": True},
                "context_window": 32768,
                "model_path": "/private/model",
            },
            {
                "id": "unrelated-model",
                "object": "model",
                "created": 1,
                "owned_by": "other",
            },
        ],
    }


def _raw_real_mtplx_settings() -> dict[str, object]:
    settings = _real_mtplx_settings()
    settings.update(
        {
            "model": "private-serving-model",
            "ssd_session_cache_dir": "/private/cache",
            "diagnostic_last_error": "private diagnostic",
        }
    )
    return settings


def _real_command(contract: ModelEvidenceContract) -> tuple[str, ...]:
    return (
        str(contract.runtime_executable),
        "--host",
        "127.0.0.1",
        "--port",
        "8999",
        "--no-auth",
        "--generation-mode",
        "mtp",
        "--depth",
        "3",
        "--temperature",
        "0",
    )


def _real_semantic_flags() -> tuple[str, ...]:
    return (
        "--host=127.0.0.1",
        "--port=8999",
        "--no-auth",
        "--generation-mode=mtp",
        "--depth=3",
        "--temperature=0",
    )


def _private(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def _contract(tmp_path: Path, *, lane: str = "cold") -> ModelEvidenceContract:
    tmp_path.mkdir(parents=True, exist_ok=True)
    stage = tmp_path / "private-stage"
    stage.mkdir()
    identity = _private(tmp_path / "identity.json", b'{"identity":"safe"}\n')
    inspect = _private(tmp_path / "inspect.json", b'{"inspect":"safe"}\n')
    executable = tmp_path / "mtplx-python"
    executable.write_bytes(b"fake executable bytes")
    executable.chmod(0o700)
    package = tmp_path / "package"
    package.mkdir()
    metadata_dir = package / "mtplx-2.7.1.dist-info"
    metadata_dir.mkdir()
    metadata = metadata_dir / "METADATA"
    metadata.write_text("Name: mtplx\nVersion: 2.7.1\n\n", encoding="utf-8")
    record = metadata_dir / "RECORD"
    module = package / "mtplx.py"
    module.write_bytes(b"version = '2.7.1'\n")
    record.write_text(
        "\n".join(
            (
                _record_row(package, module),
                _record_row(package, metadata),
                "mtplx-2.7.1.dist-info/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    return ModelEvidenceContract(
        public_model_id="public-qualified-model",
        stage_path=stage,
        stage_revision="d" * 40,
        identity_ledger=identity,
        identity_ledger_sha256=_file_digest(identity),
        inspect_artifact=inspect,
        inspect_artifact_sha256=_file_digest(inspect),
        runtime_executable=executable,
        runtime_executable_sha256=_file_digest(executable),
        mtplx_distribution_root=package,
        mtplx_record=record,
        mtplx_version="2.7.1",
        launch_command_sha256="b" * 64,
        required_launch_flags=("--host=127.0.0.1", "--port=8999", "--foreground"),
        host="127.0.0.1",
        port=8999,
        health_contract_sha256=_sha256({"status": "ok"}),
        settings_contract_sha256=_sha256(_snapshot().settings),
        cache_lane=lane,
    )


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_row(root: Path, path: Path) -> str:
    digest = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode("ascii").rstrip("=")
    return f"{path.relative_to(root).as_posix()},sha256={digest},{path.stat().st_size}"


def _distribution_digest(contract: ModelEvidenceContract) -> str:
    root = contract.mtplx_distribution_root
    rows: list[tuple[str, str]] = []
    for line in contract.mtplx_record.read_text(encoding="utf-8").splitlines():
        relative, encoded, _size = line.split(",")
        if encoded:
            rows.append((relative, _file_digest(root / relative)))
    return _sha256({"name": "mtplx", "version": "2.7.1", "files": sorted(rows)})


def _probe_for(
    contract: ModelEvidenceContract, *, before_requests: int = 7, after_requests: int = 8
) -> _Probe:
    probe = _Probe()
    probe.before = _snapshot(
        requests_completed=before_requests,
        executable_sha256=contract.runtime_executable_sha256,
        distribution_sha256=_distribution_digest(contract),
    )
    probe.after = _snapshot(
        requests_completed=after_requests,
        executable_sha256=contract.runtime_executable_sha256,
        distribution_sha256=_distribution_digest(contract),
    )
    return probe


def _begin(
    tmp_path: Path,
    *,
    contract: ModelEvidenceContract | None = None,
    probe: _Probe | None = None,
    output: Path | None = None,
) -> tuple[ModelEvidenceSession, ModelEvidenceContract, _Probe, Path, Path]:
    selected = contract or _contract(tmp_path)
    credential = _private(tmp_path / "credential", b"model-api-token")
    selected_probe = probe or _probe_for(selected)
    selected_output = output or tmp_path / "evidence.json"
    session = ModelEvidenceSession.begin(
        selected,
        stage="score-direct",
        run_manifest_sha256="f" * 64,
        evidence_path=selected_output,
        credential_file=credential,
        probe=selected_probe,
    )
    return session, selected, selected_probe, selected_output, credential


def _failed_record(path: Path) -> dict[str, object]:
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["status"] == "failed"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    return record


def _attempt(
    *,
    digest: str = "e" * 64,
    status: str = "succeeded",
    prompt_tokens: int = 10,
    cached_tokens: int = 0,
    new_prefill_tokens: int = 10,
    cache_source: str = "none",
    ssd_cache_hit: bool = False,
    ssd_cached_tokens: int = 0,
    session_cache_hit: bool = False,
    request_session_bank_bypass: bool = True,
    postcommit_stored: bool = False,
) -> SafeAttemptRecord:
    return SafeAttemptRecord(
        request_digest=digest,
        status=status,
        prompt_tokens=prompt_tokens,
        cached_tokens=cached_tokens,
        new_prefill_tokens=new_prefill_tokens,
        cache_source=cache_source,
        ssd_cache_hit=ssd_cache_hit,
        ssd_cached_tokens=ssd_cached_tokens,
        session_cache_hit=session_cache_hit,
        request_session_bank_bypass=request_session_bank_bypass,
        postcommit_stored=postcommit_stored,
    )


def test_cold_session_writes_only_safe_hash_evidence(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    credential = _private(tmp_path / "credential", b"model-api-token")
    output = tmp_path / "evidence.json"
    probe = _probe_for(contract)

    session = ModelEvidenceSession.begin(
        contract,
        stage="score-direct",
        run_manifest_sha256="f" * 64,
        evidence_path=output,
        credential_file=credential,
        probe=probe,
    )
    result = session.complete([_attempt()])

    record = json.loads(output.read_text(encoding="utf-8"))
    assert result.path == output
    assert record["status"] == "passed"
    assert record["record_type"] == "qualification_model_cache_evidence"
    assert set(record) == {
        "schema_version",
        "record_type",
        "stage",
        "status",
        "failure_category",
        "run_manifest_sha256",
        "model_contract_sha256",
        "runtime_instance_sha256",
        "live_before_sha256",
        "live_after_sha256",
        "request_window",
        "prime",
        "first_attempt",
        "checks",
    }
    assert all(value is True for value in record["checks"].values())
    assert "model-api-token" not in output.read_text(encoding="utf-8")
    assert str(contract.stage_path) not in output.read_text(encoding="utf-8")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("public_model_id", ""),
        ("stage_revision", "not-a-revision"),
        ("mtplx_version", "2.7.2"),
        ("host", "192.0.2.1"),
        ("port", 0),
        ("identity_ledger_sha256", "0" * 64),
        ("runtime_executable_sha256", "0" * 64),
    ],
)
def test_begin_rejects_contract_drift_before_any_probe(tmp_path: Path, field: str, value: object) -> None:
    contract = _contract(tmp_path)
    bad = replace(contract, **{field: value})
    credential = _private(tmp_path / "credential", b"model-api-token")
    probe = _probe_for(contract)

    with pytest.raises(ModelEvidenceFailure, match="model_"):
        ModelEvidenceSession.begin(
            bad,
            stage="score-direct",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "evidence.json",
            credential_file=credential,
            probe=probe,
        )

    assert probe.calls == []


def test_begin_rejects_stage_artifact_mode_symlink_and_package_hash_drift(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    contract.identity_ledger.chmod(0o644)
    credential = _private(tmp_path / "credential", b"model-api-token")

    with pytest.raises(ModelEvidenceFailure, match="model_contract_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="preflight",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "one.json",
            credential_file=credential,
            probe=_probe_for(contract),
        )

    contract.identity_ledger.chmod(0o600)
    contract.mtplx_distribution_root.joinpath("mtplx.py").write_text("tampered", encoding="utf-8")
    with pytest.raises(ModelEvidenceFailure, match="model_package_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="preflight",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "two.json",
            credential_file=credential,
            probe=_probe_for(contract),
        )


def test_begin_rejects_symlinked_private_artifact_and_credential(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    target = _private(tmp_path / "target", b"private")
    contract.identity_ledger.unlink()
    contract.identity_ledger.symlink_to(target)
    credential = _private(tmp_path / "credential", b"model-api-token")

    with pytest.raises(ModelEvidenceFailure, match="model_contract_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="preflight",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "artifact.json",
            credential_file=credential,
            probe=_probe_for(contract),
        )

    contract = _contract(tmp_path / "credential-symlink")
    credential_target = _private(tmp_path / "credential-target", b"model-api-token")
    credential_link = tmp_path / "credential-link"
    credential_link.symlink_to(credential_target)
    with pytest.raises(ModelEvidenceFailure, match="model_credential_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="preflight",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "credential-artifact.json",
            credential_file=credential_link,
            probe=_probe_for(contract),
        )


def test_record_aggregate_ignores_pycache_but_rejects_metadata_version_drift(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    cache = contract.mtplx_distribution_root / "__pycache__"
    cache.mkdir()
    (cache / "untracked.cpython-311.pyc").write_bytes(b"untrusted bytecode")
    credential = _private(tmp_path / "credential", b"model-api-token")
    session = ModelEvidenceSession.begin(
        contract,
        stage="preflight",
        run_manifest_sha256="f" * 64,
        evidence_path=tmp_path / "pass.json",
        credential_file=credential,
        probe=_probe_for(contract, after_requests=7),
    )
    session.complete([])

    bad = _contract(tmp_path / "bad-metadata")
    metadata = bad.mtplx_distribution_root / "mtplx-2.7.1.dist-info" / "METADATA"
    metadata.write_text("Name: mtplx\nVersion: 2.7.2\n\n", encoding="utf-8")
    credential = _private(tmp_path / "bad-metadata" / "credential", b"model-api-token")
    with pytest.raises(ModelEvidenceFailure, match="model_package_invalid"):
        ModelEvidenceSession.begin(
            bad,
            stage="preflight",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "bad-metadata" / "artifact.json",
            credential_file=credential,
            probe=_probe_for(bad),
        )


@pytest.mark.parametrize("kind", ["health", "settings", "model", "runtime", "pid", "argv", "listener"])
def test_begin_rejects_wrong_live_identity(tmp_path: Path, kind: str) -> None:
    contract = _contract(tmp_path)
    probe = _probe_for(contract)
    health = dict(probe.before.health)
    models = dict(probe.before.models)
    settings = dict(probe.before.settings)
    owners = list(probe.before.listener_owners)
    if kind == "health":
        health["status"] = "wrong"
    elif kind == "settings":
        settings["safe_version"] = "wrong"
    elif kind == "model":
        models["data"] = [{"id": "wrong-model"}]
    elif kind == "runtime":
        owner = dict(owners[0])
        owner["executable_sha256"] = "0" * 64
        owners = [owner]
    elif kind == "pid":
        health["startup_pid"] = 445
    elif kind == "argv":
        owner = dict(owners[0])
        owner["command_flags"] = ("--host=127.0.0.1", "--port=8999")
        owners = [owner]
    else:
        owners.append(dict(owners[0]))
    probe.before = ProbeSnapshot(health=health, models=models, settings=settings, listener_owners=tuple(owners))
    credential = _private(tmp_path / "credential", b"model-api-token")

    with pytest.raises(ModelEvidenceFailure, match="model_(live|listener)_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="score-proxy",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "evidence.json",
            credential_file=credential,
            probe=probe,
        )


def test_complete_fails_closed_for_replacement_and_nonquiescence(tmp_path: Path) -> None:
    session, contract, probe, output, _credential = _begin(tmp_path)
    health = dict(probe.after.health)
    health["instance_id"] = "replacement-instance"
    probe.after = replace(probe.after, health=health)

    with pytest.raises(ModelEvidenceFailure, match="model_live_drift"):
        session.complete([_attempt()])

    record = _failed_record(output)
    assert record["failure_category"] == "model_live_drift"
    assert contract.public_model_id not in output.read_text(encoding="utf-8")


def test_complete_fails_closed_for_nonquiescent_after_probe(tmp_path: Path) -> None:
    session, _contract_value, probe, output, _credential = _begin(tmp_path)
    health = dict(probe.after.health)
    health["active_requests"] = 1
    probe.after = replace(probe.after, health=health)

    with pytest.raises(ModelEvidenceFailure, match="model_live_invalid"):
        session.complete([_attempt()])

    assert _failed_record(output)["failure_category"] == "model_live_invalid"


def test_complete_detects_intervening_request_count(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    probe = _probe_for(contract, after_requests=9)
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path, contract=contract, probe=probe)

    with pytest.raises(ModelEvidenceFailure, match="model_request_window_invalid"):
        session.complete([_attempt()])

    record = _failed_record(output)
    assert record["failure_category"] == "model_request_window_invalid"
    assert record["request_window"] == {
        "before": 7,
        "after": 9,
        "delta": 2,
        "expected": 1,
        "successful_measured": 1,
    }


@pytest.mark.parametrize(
    "invalid",
    [
        _attempt(cached_tokens=1, new_prefill_tokens=9, cache_source="ram", session_cache_hit=True),
        _attempt(request_session_bank_bypass=False),
        _attempt(postcommit_stored=True),
        _attempt(cache_source="raw prompt: private text"),
        _attempt(status="local_projection"),
    ],
)
def test_cold_cache_invariants_reject_hits_and_rawish_categories(
    tmp_path: Path, invalid: SafeAttemptRecord
) -> None:
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path)

    with pytest.raises(ModelEvidenceFailure, match="model_(cache_cold|attempt)_invalid"):
        session.complete([invalid])

    serialized = output.read_text(encoding="utf-8")
    assert "raw prompt: private text" not in serialized
    assert _failed_record(output)["status"] == "failed"
    assert _probe_value.calls == ["snapshot", "snapshot"]


def test_untyped_attempt_mapping_fails_categorically_without_retaining_raw_value(tmp_path: Path) -> None:
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path)
    invalid = _attempt().to_safe_dict()
    invalid["request_digest"] = "private prompt should never be accepted"

    with pytest.raises(ModelEvidenceFailure, match="model_attempt_invalid"):
        session.complete([invalid])

    serialized = output.read_text(encoding="utf-8")
    assert "private prompt should never be accepted" not in serialized
    assert _failed_record(output)["failure_category"] == "model_attempt_invalid"


def test_warm_prefix_requires_matching_prime_and_first_cache_hit(tmp_path: Path) -> None:
    contract = _contract(tmp_path, lane="warm-prefix")
    probe = _probe_for(contract, after_requests=9)
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path, contract=contract, probe=probe)
    prime = _attempt(
        digest="a" * 64,
        request_session_bank_bypass=False,
        postcommit_stored=True,
    )
    warmed = _attempt(
        digest="a" * 64,
        cached_tokens=6,
        new_prefill_tokens=4,
        cache_source="ram",
        session_cache_hit=True,
        request_session_bank_bypass=False,
    )

    result = session.complete([warmed], prime_record=prime)

    assert result.status == "passed"
    assert json.loads(output.read_text(encoding="utf-8"))["request_window"]["expected"] == 2


def test_warm_prefix_rejects_mismatched_prime_without_serializing_it(tmp_path: Path) -> None:
    contract = _contract(tmp_path, lane="warm-prefix")
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path, contract=contract)

    with pytest.raises(ModelEvidenceFailure, match="model_cache_warm_invalid"):
        session.complete(
            [
                _attempt(
                    digest="a" * 64,
                    cached_tokens=6,
                    new_prefill_tokens=4,
                    cache_source="ssd",
                    ssd_cache_hit=True,
                    ssd_cached_tokens=6,
                    request_session_bank_bypass=False,
                )
            ],
            prime_record=_attempt(digest="b" * 64),
        )

    assert _failed_record(output)["failure_category"] == "model_cache_warm_invalid"


def test_local_projection_is_zero_model_attempts_not_a_failure(tmp_path: Path) -> None:
    contract = _contract(tmp_path, lane="preflight")
    probe = _probe_for(contract, after_requests=7)
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path, contract=contract, probe=probe)

    result = session.complete([])

    record = json.loads(output.read_text(encoding="utf-8"))
    assert result.status == "passed"
    assert record["first_attempt"]["measured_count"] == 0
    assert record["request_window"]["delta"] == 0


def test_credentials_are_nofollow_mode_600_and_checked_again_before_after_probe(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    credential = _private(tmp_path / "credential", b"model-api-token")
    credential.chmod(0o644)
    probe = _probe_for(contract)
    with pytest.raises(ModelEvidenceFailure, match="model_credential_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="score-direct",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "bad.json",
            credential_file=credential,
            probe=probe,
        )
    assert probe.calls == []

    credential.chmod(0o600)
    session = ModelEvidenceSession.begin(
        contract,
        stage="score-direct",
        run_manifest_sha256="f" * 64,
        evidence_path=tmp_path / "drift.json",
        credential_file=credential,
        probe=_probe_for(contract),
    )
    credential.write_text("changed-token", encoding="utf-8")
    credential.chmod(0o600)
    with pytest.raises(ModelEvidenceFailure, match="model_credential_invalid"):
        session.complete([_attempt()])
    assert "changed-token" not in (tmp_path / "drift.json").read_text(encoding="utf-8")


def test_no_clobber_preserves_existing_evidence_before_probe(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    output = _private(tmp_path / "evidence.json", b'{"prior":"private evidence"}\n')
    credential = _private(tmp_path / "credential", b"model-api-token")
    probe = _probe_for(contract)

    with pytest.raises(ModelEvidenceFailure, match="model_evidence_exists"):
        ModelEvidenceSession.begin(
            contract,
            stage="score-direct",
            run_manifest_sha256="f" * 64,
            evidence_path=output,
            credential_file=credential,
            probe=probe,
        )

    assert output.read_bytes() == b'{"prior":"private evidence"}\n'
    assert probe.calls == []


def test_post_probe_failure_writes_categorical_artifact_without_exception_text(tmp_path: Path) -> None:
    session, _contract_value, probe, output, _credential = _begin(tmp_path)
    probe.after_error = RuntimeError("private endpoint /admin/sessions and token are unavailable")

    with pytest.raises(ModelEvidenceFailure, match="model_probe_failed"):
        session.complete([_attempt()])

    serialized = output.read_text(encoding="utf-8")
    assert "admin/sessions" not in serialized
    assert "are unavailable" not in serialized
    assert _failed_record(output)["failure_category"] == "model_probe_failed"


def test_no_clobber_preserves_an_existing_symlink(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    target = _private(tmp_path / "prior-target", b"prior private evidence")
    output = tmp_path / "evidence.json"
    output.symlink_to(target)
    credential = _private(tmp_path / "credential", b"model-api-token")
    probe = _probe_for(contract)

    with pytest.raises(ModelEvidenceFailure, match="model_evidence_exists"):
        ModelEvidenceSession.begin(
            contract,
            stage="score-direct",
            run_manifest_sha256="f" * 64,
            evidence_path=output,
            credential_file=credential,
            probe=probe,
        )

    assert output.is_symlink()
    assert target.read_bytes() == b"prior private evidence"


def test_system_probe_hits_only_the_approved_read_paths(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    command = (
        str(contract.runtime_executable),
        "--host=127.0.0.1",
        "--port=8999",
        "--foreground",
    )
    contract = replace(contract, launch_command_sha256=_sha256(list(command)))
    seen_urls: list[str] = []

    def http_get(url: str, headers: dict[str, str]) -> dict[str, object]:
        assert headers == {"Authorization": "Bearer model-api-token"}
        seen_urls.append(url)
        if url.endswith("/health"):
            return _raw_real_mtplx_health()
        if url.endswith("/v1/models"):
            return _raw_real_mtplx_models()
        if url.endswith("/v1/mtplx/settings"):
            return _raw_real_mtplx_settings()
        raise AssertionError("unsafe endpoint")

    def run(argv: tuple[str, ...]) -> tuple[int, str]:
        if argv[0] == "lsof":
            return 0, "p444\n"
        if argv[-1] == "command=":
            return 0, " ".join(command) + "\n"
        if argv[-1] == "comm=":
            return 0, str(contract.runtime_executable) + "\n"
        if argv[-1] == "lstart=":
            return 0, "12345\n"
        raise AssertionError(argv)

    snapshot = SystemModelEvidenceProbe(http_get=http_get, command_runner=run).snapshot(
        host="127.0.0.1", port=8999, api_key="model-api-token", contract=contract
    )

    assert len(snapshot.listener_owners) == 1
    assert [url.rsplit(":8999", 1)[1] for url in seen_urls] == ["/health", "/v1/models", "/v1/mtplx/settings"]


def test_system_probe_projects_literal_mtplx_271_shapes_without_retaining_private_fields(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    command = _real_command(contract)
    settings = _real_mtplx_settings()
    contract = replace(
        contract,
        launch_command_sha256=_sha256(list(command)),
        required_launch_flags=_real_semantic_flags(),
        settings_contract_sha256=_sha256(settings),
    )
    raw_health = _raw_real_mtplx_health()
    raw_models = _raw_real_mtplx_models()
    raw_settings = _raw_real_mtplx_settings()
    expected_health = {
        "status": "ok",
        "startup_pid": 444,
        "started_at": "1712345678.25",
        "instance_id": _sha256({"pid": 444, "started_at": "1712345678.25"}),
        "active_requests": 0,
        "foreground_requests": 0,
        "requests_completed": 7,
    }

    def http_get(url: str, headers: dict[str, str]) -> dict[str, object]:
        assert headers == {}
        if url.endswith("/health"):
            return raw_health
        if url.endswith("/v1/models"):
            return raw_models
        if url.endswith("/v1/mtplx/settings"):
            return raw_settings
        raise AssertionError("unsafe endpoint")

    def run(argv: tuple[str, ...]) -> tuple[int, str]:
        if argv[0] == "lsof":
            return 0, "p444\n"
        if argv[-1] == "command=":
            return 0, " ".join(command) + "\n"
        if argv[-1] == "comm=":
            return 0, str(contract.runtime_executable) + "\n"
        if argv[-1] == "lstart=":
            return 0, "12345\n"
        raise AssertionError(argv)

    snapshot = SystemModelEvidenceProbe(http_get=http_get, command_runner=run).snapshot(
        host="127.0.0.1", port=8999, api_key=None, contract=contract
    )

    assert snapshot.health == expected_health
    assert snapshot.models == {"data": [{"id": "public-qualified-model"}]}
    assert snapshot.settings == settings
    assert snapshot.listener_owners[0]["command_flags"] == _real_semantic_flags()
    serialized = json.dumps(
        {"health": snapshot.health, "models": snapshot.models, "settings": snapshot.settings}, sort_keys=True
    )
    assert "private-serving-model" not in serialized
    assert "/private/" not in serialized
    assert "private diagnostic" not in serialized


def test_real_schema_volatile_fields_do_not_change_projected_contract_hashes(tmp_path: Path) -> None:
    raw_health = _raw_real_mtplx_health()
    raw_models = _raw_real_mtplx_models()
    raw_settings = _raw_real_mtplx_settings()
    changed_health = deepcopy(raw_health)
    changed_models = deepcopy(raw_models)
    changed_settings = deepcopy(raw_settings)
    changed_health["model_path"] = "/different/private/model"
    changed_health["smart_fan_last_error"] = "different private diagnostic"
    changed_models["data"][0]["created"] = 9999999999  # type: ignore[index]
    changed_models["data"][0]["owned_by"] = "different-owner"  # type: ignore[index]
    changed_settings["model"] = "different-private-model"
    changed_settings["ssd_session_cache_dir"] = "/different/private/cache"
    changed_settings["diagnostic_last_error"] = "different private diagnostic"

    assert model_endpoint_contract_hashes(raw_health, raw_settings) == model_endpoint_contract_hashes(
        changed_health, changed_settings
    )
    assert model_endpoint_contract_hashes(raw_health, raw_settings) == (
        _sha256({"status": "ok"}),
        _sha256(_real_mtplx_settings()),
    )

    contract = _contract(tmp_path)
    command = _real_command(contract)
    contract = replace(contract, launch_command_sha256=_sha256(list(command)))

    def run(argv: tuple[str, ...]) -> tuple[int, str]:
        if argv[0] == "lsof":
            return 0, "p444\n"
        if argv[-1] == "command=":
            return 0, " ".join(command) + "\n"
        if argv[-1] == "comm=":
            return 0, str(contract.runtime_executable) + "\n"
        if argv[-1] == "lstart=":
            return 0, "12345\n"
        raise AssertionError(argv)

    def http_first(url: str, _headers: dict[str, str]) -> dict[str, object]:
        if url.endswith("/health"):
            return raw_health
        if url.endswith("/v1/models"):
            return raw_models
        return raw_settings

    def http_second(url: str, _headers: dict[str, str]) -> dict[str, object]:
        if url.endswith("/health"):
            return changed_health
        if url.endswith("/v1/models"):
            return changed_models
        return changed_settings

    first = SystemModelEvidenceProbe(http_get=http_first, command_runner=run).snapshot(
        host="127.0.0.1", port=8999, api_key=None, contract=contract
    )
    second = SystemModelEvidenceProbe(http_get=http_second, command_runner=run).snapshot(
        host="127.0.0.1", port=8999, api_key=None, contract=contract
    )
    assert first.models == second.models == {"data": [{"id": "public-qualified-model"}]}


def test_system_probe_allows_null_launch_id_but_rejects_missing_startup_identity(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    command = _real_command(contract)
    contract = replace(
        contract,
        launch_command_sha256=_sha256(list(command)),
        required_launch_flags=_real_semantic_flags(),
        settings_contract_sha256=_sha256(_real_mtplx_settings()),
    )
    raw_health = _raw_real_mtplx_health()
    raw_models = _raw_real_mtplx_models()
    raw_settings = _raw_real_mtplx_settings()

    def http_get(url: str, _headers: dict[str, str]) -> dict[str, object]:
        if url.endswith("/health"):
            return raw_health
        if url.endswith("/v1/models"):
            return raw_models
        return raw_settings

    def run(argv: tuple[str, ...]) -> tuple[int, str]:
        if argv[0] == "lsof":
            return 0, "p444\n"
        if argv[-1] == "command=":
            return 0, " ".join(command) + "\n"
        if argv[-1] == "comm=":
            return 0, str(contract.runtime_executable) + "\n"
        if argv[-1] == "lstart=":
            return 0, "12345\n"
        raise AssertionError(argv)

    probe = SystemModelEvidenceProbe(http_get=http_get, command_runner=run)
    assert probe.snapshot(host="127.0.0.1", port=8999, api_key=None, contract=contract).health["instance_id"]
    startup = raw_health["startup"]
    assert isinstance(startup, dict)
    del startup["launch_id"]
    assert probe.snapshot(host="127.0.0.1", port=8999, api_key=None, contract=contract).health["instance_id"]
    raw_health["startup"] = {"launch_id": None}
    with pytest.raises(ModelEvidenceFailure, match="model_live_invalid"):
        probe.snapshot(host="127.0.0.1", port=8999, api_key=None, contract=contract)


def test_unauthenticated_session_uses_no_credential_and_omits_authorization(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    probe = _probe_for(contract)
    probe.expected_api_key = None
    session = ModelEvidenceSession.begin(
        contract,
        stage="score-direct",
        run_manifest_sha256="f" * 64,
        evidence_path=tmp_path / "unauthenticated.json",
        credential_file=None,
        probe=probe,
    )

    assert session.complete([_attempt()]).status == "passed"
    assert probe.calls == ["snapshot", "snapshot"]


def test_launch_semantics_accept_real_space_separated_vector_without_foreground(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    flags = _real_semantic_flags()
    contract = replace(contract, required_launch_flags=flags)
    probe = _probe_for(contract)
    probe.expected_api_key = None
    owner = dict(probe.before.listener_owners[0])
    owner["command_flags"] = flags
    probe.before = replace(probe.before, listener_owners=(owner,))
    probe.after = replace(probe.after, listener_owners=(owner,))
    output = tmp_path / "semantics.json"

    session = ModelEvidenceSession.begin(
        contract,
        stage="score-direct",
        run_manifest_sha256="f" * 64,
        evidence_path=output,
        credential_file=None,
        probe=probe,
    )

    assert session.complete([_attempt()]).status == "passed"


def test_launch_semantics_reject_sensitive_flag_value(tmp_path: Path) -> None:
    contract = replace(
        _contract(tmp_path),
        required_launch_flags=(
            "--host=127.0.0.1",
            "--port=8999",
            "--api-key-file=/private/credential",
        ),
    )
    probe = _probe_for(contract)

    with pytest.raises(ModelEvidenceFailure, match="model_contract_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="score-direct",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "sensitive.json",
            credential_file=None,
            probe=probe,
        )


@pytest.mark.parametrize("flag", ["--auth-file=/private/keymaterial", "--model-id=sk-private-token"])
def test_launch_semantics_rejects_other_sensitive_flag_names_and_values(tmp_path: Path, flag: str) -> None:
    contract = replace(
        _contract(tmp_path),
        required_launch_flags=("--host=127.0.0.1", "--port=8999", flag),
    )

    credential = _private(tmp_path / "credential", b"model-api-token")
    with pytest.raises(ModelEvidenceFailure, match="model_contract_invalid"):
        ModelEvidenceSession.begin(
            contract,
            stage="score-direct",
            run_manifest_sha256="f" * 64,
            evidence_path=tmp_path / "sensitive-other.json",
            credential_file=credential,
            probe=_probe_for(contract),
        )


def test_warm_prefix_requires_a_nonbypass_storing_prime(tmp_path: Path) -> None:
    contract = _contract(tmp_path, lane="warm-prefix")
    probe = _probe_for(contract, after_requests=9)
    session, _contract_value, _probe_value, output, _credential = _begin(tmp_path, contract=contract, probe=probe)
    warmed = _attempt(
        digest="a" * 64,
        cached_tokens=6,
        new_prefill_tokens=4,
        cache_source="ram",
        session_cache_hit=True,
        request_session_bank_bypass=False,
    )

    with pytest.raises(ModelEvidenceFailure, match="model_cache_warm_invalid"):
        session.complete([warmed], prime_record=_attempt(digest="a" * 64))

    assert _failed_record(output)["failure_category"] == "model_cache_warm_invalid"
