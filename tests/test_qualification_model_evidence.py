from __future__ import annotations

import hashlib
import json
import stat
from base64 import urlsafe_b64encode
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

    def snapshot(self, *, host: str, port: int, api_key: str, contract: ModelEvidenceContract) -> ProbeSnapshot:
        del contract
        assert host == "127.0.0.1"
        assert port == 8999
        assert api_key == "model-api-token"
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
    prime = _attempt(digest="a" * 64)
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

    def http_get(url: str, api_key: str) -> dict[str, object]:
        assert api_key == "model-api-token"
        seen_urls.append(url)
        if url.endswith("/health"):
            return dict(_snapshot().health)
        if url.endswith("/v1/models"):
            return dict(_snapshot().models)
        if url.endswith("/v1/mtplx/settings"):
            return dict(_snapshot().settings)
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
