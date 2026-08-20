from __future__ import annotations

import hashlib
import json

import pytest

from shiftedx_harness_proxy.qualification_contract import (
    BENCHMARK_REVISION,
    CacheObservation,
    ModelBoundaryRecord,
    PreflightFailure,
    RuntimeAttestation,
    RuntimeAttestationFailure,
    RuntimeOutcome,
    RuntimeOutcomeFailure,
    load_runtime_attestation,
    load_runtime_outcome,
    model_boundary_fingerprint,
    read_model_boundary_observer_records,
    write_model_boundary_attempt_ledger,
)


def test_model_boundary_records_load_exact_safe_response_cache_projection(tmp_path) -> None:
    fingerprint = model_boundary_fingerprint(
        {
            "model": "private-model",
            "messages": [{"role": "user", "content": "private prompt"}],
            "metadata": {"cache_mode": "bypass"},
        }
    )
    cache = {
        "prompt_tokens": 31,
        "cached_tokens": 0,
        "new_prefill_tokens": 31,
        "cache_source": "none",
        "ssd_cache_hit": False,
        "ssd_cached_tokens": 0,
        "session_cache_hit": False,
        "request_session_bank_bypass": True,
        "postcommit_stored": False,
    }
    path = tmp_path / "attempts.jsonl"
    path.write_text(
        json.dumps(
            {
                "record_type": "qualification_model_boundary",
                "sequence": 1,
                "digest": fingerprint.digest,
                "fields": fingerprint.fields,
                "response": {"status_code": 200, "cache": cache},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    records = read_model_boundary_observer_records(path)

    assert records == (
        ModelBoundaryRecord(
            sequence=1,
            digest=fingerprint.digest,
            fields=fingerprint.fields,
            status_code=200,
            cache=CacheObservation(**cache),
        ),
    )
    assert "private-model" not in path.read_text(encoding="utf-8")
    assert "private prompt" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.update({"raw_response": {"content": "private output"}}),
        lambda row: row["response"].update({"diagnostic": "private diagnostic"}),
        lambda row: row["response"]["cache"].update({"cache_source": "disk"}),
        lambda row: row["response"]["cache"].update({"prompt_tokens": True}),
    ],
)
def test_model_boundary_records_reject_raw_or_malformed_response_evidence(tmp_path, mutation) -> None:
    fingerprint = model_boundary_fingerprint({"model": "model", "messages": []})
    row = {
        "record_type": "qualification_model_boundary",
        "sequence": 1,
        "digest": fingerprint.digest,
        "fields": fingerprint.fields,
        "response": {
            "status_code": 200,
            "cache": {
                "prompt_tokens": 1,
                "cached_tokens": 0,
                "new_prefill_tokens": 1,
                "cache_source": "none",
                "ssd_cache_hit": False,
                "ssd_cached_tokens": 0,
                "session_cache_hit": False,
                "request_session_bank_bypass": True,
                "postcommit_stored": False,
            },
        },
    }
    mutation(row)
    path = tmp_path / "attempts.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(PreflightFailure, match="observer ledger is invalid"):
        read_model_boundary_observer_records(path)


def test_model_boundary_attempt_writer_is_mode_0600_no_clobber_and_resequences(tmp_path) -> None:
    fingerprint = model_boundary_fingerprint({"model": "model", "messages": []})
    record = ModelBoundaryRecord(9, fingerprint.digest, fingerprint.fields, None, None)
    output = tmp_path / "attempts.jsonl"

    write_model_boundary_attempt_ledger(output, [record, record])

    assert output.stat().st_mode & 0o777 == 0o600
    assert [item.sequence for item in read_model_boundary_observer_records(output)] == [1, 2]
    prior = output.read_bytes()
    with pytest.raises(PreflightFailure, match="overwrite"):
        write_model_boundary_attempt_ledger(output, [record])
    assert output.read_bytes() == prior


def test_model_boundary_attempt_writer_rejects_symlink_without_touching_target(tmp_path) -> None:
    target = tmp_path / "prior.jsonl"
    target.write_text('{"private":"prior"}\n', encoding="utf-8")
    output = tmp_path / "attempts.jsonl"
    output.symlink_to(target)
    fingerprint = model_boundary_fingerprint({"model": "model", "messages": []})
    record = ModelBoundaryRecord(1, fingerprint.digest, fingerprint.fields, None, None)

    with pytest.raises(PreflightFailure, match="overwrite"):
        write_model_boundary_attempt_ledger(output, [record])

    assert target.read_text(encoding="utf-8") == '{"private":"prior"}\n'


def test_runtime_attestation_loads_exact_verified_identity(tmp_path) -> None:
    path = tmp_path / "runtime-attestation.json"
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_attestation",
        "status": "passed",
        "stage": "preflight",
        "source_commit": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "run_manifest_sha256": "c" * 64,
        "model_id_sha256": "18fb9fa0b971b807a1312d3702d18747a3b1b39a129df8c5d1a8f68d512bd1fd",
        "benchmark_revision": BENCHMARK_REVISION,
        "scenario_order": {
            "sha256": "e36906789ac1c1a27abe7e60762c17fa92b660e7e29920ed603b89914b99545c",
            "count": 2,
        },
        "runtime_contract_sha256": "d" * 64,
        "runtime_instance_sha256": "e" * 64,
        "checks": {
            "exact_image": True,
            "settings": True,
            "resources": True,
            "bind": True,
            "observer": True,
            "ready": True,
            "secret_roles_distinct": True,
        },
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(serialized)

    attestation = load_runtime_attestation(
        path,
        expected_stage="preflight",
        source_commit="a" * 40,
        image_digest="sha256:" + "b" * 64,
        run_manifest_sha256="c" * 64,
        model="model",
        scenario_order=["case-1", "case-2"],
    )

    assert isinstance(attestation, RuntimeAttestation)
    assert attestation.file_sha256 == hashlib.sha256(serialized).hexdigest()
    assert attestation.runtime_contract_sha256 == "d" * 64
    assert attestation.runtime_instance_sha256 == "e" * 64


def test_runtime_outcome_loads_exact_private_evidence_identity(tmp_path) -> None:
    attestation = tmp_path / "preflight-runtime-attestation.json"
    attestation.write_text('{"safe":"attestation"}\n', encoding="utf-8")
    attestation.chmod(0o600)
    output = tmp_path / "preflight.jsonl"
    output.write_text("".join(f'{{"record":{index}}}\n' for index in range(5)), encoding="utf-8")
    output.chmod(0o600)
    path = tmp_path / "preflight-runtime-outcome.json"
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_outcome",
        "stage": "preflight",
        "status": "passed",
        "action_exit_code": 0,
        "failure_category": None,
        "run_manifest_sha256": "c" * 64,
        "attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "output_ledger_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "output_record_count": 5,
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(serialized)
    path.chmod(0o600)

    outcome = load_runtime_outcome(
        path,
        expected_stage="preflight",
        run_manifest_sha256="c" * 64,
        attestation=attestation,
        output_ledger=output,
        expected_output_record_count=5,
    )

    assert isinstance(outcome, RuntimeOutcome)
    assert outcome.file_sha256 == hashlib.sha256(serialized).hexdigest()
    assert outcome.attestation_sha256 == document["attestation_sha256"]
    assert outcome.output_ledger_sha256 == document["output_ledger_sha256"]
    assert outcome.output_record_count == 5


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "2.0"),
        ("record_type", "private_runtime_dump"),
        ("stage", "scored-direct"),
        ("status", "failed"),
        ("action_exit_code", 1),
        ("action_exit_code", True),
        ("action_exit_code", 0.0),
        ("failure_category", "runtime_cleanup_failed"),
        ("run_manifest_sha256", "d" * 64),
        ("attestation_sha256", "e" * 64),
        ("output_ledger_sha256", "f" * 64),
        ("output_record_count", 4),
        ("output_record_count", True),
        ("output_record_count", 5.0),
        ("private_prompt", "must never survive validation"),
    ],
)
def test_runtime_outcome_rejects_any_non_allowlisted_or_nonpassing_field(
    tmp_path, field, replacement
) -> None:
    path, attestation, output, document = _runtime_outcome_fixture(tmp_path)
    document[field] = replacement
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(RuntimeOutcomeFailure, match="^runtime_outcome_invalid$") as raised:
        load_runtime_outcome(
            path,
            expected_stage="preflight",
            run_manifest_sha256="c" * 64,
            attestation=attestation,
            output_ledger=output,
            expected_output_record_count=5,
        )

    assert "must never survive validation" not in str(raised.value)


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "directory",
        "symlink",
        "insecure_mode",
        "duplicate_key",
        "malformed",
        "attestation_tampered",
        "attestation_symlink",
        "output_tampered",
        "output_insecure_mode",
        "output_incomplete",
    ],
)
def test_runtime_outcome_rejects_untrusted_or_tampered_private_evidence(tmp_path, kind) -> None:
    path, attestation, output, document = _runtime_outcome_fixture(tmp_path)
    if kind == "missing":
        path.unlink()
    elif kind == "directory":
        path.unlink()
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "outcome-target.json"
        path.replace(target)
        path.symlink_to(target)
    elif kind == "insecure_mode":
        path.chmod(0o644)
    elif kind == "duplicate_key":
        serialized = json.dumps(document, separators=(",", ":"))
        path.write_text('{"status":"failed",' + serialized[1:], encoding="utf-8")
        path.chmod(0o600)
    elif kind == "malformed":
        path.write_text("not-json", encoding="utf-8")
        path.chmod(0o600)
    elif kind == "attestation_tampered":
        attestation.write_text("tampered\n", encoding="utf-8")
    elif kind == "attestation_symlink":
        target = tmp_path / "attestation-target.json"
        attestation.replace(target)
        attestation.symlink_to(target)
    elif kind == "output_tampered":
        output.write_text(output.read_text(encoding="utf-8") + '{"extra":true}\n', encoding="utf-8")
    elif kind == "output_insecure_mode":
        output.chmod(0o644)
    else:
        output.write_text('{"record":0}\n' * 4, encoding="utf-8")

    with pytest.raises(RuntimeOutcomeFailure, match="^runtime_outcome_invalid$"):
        load_runtime_outcome(
            path,
            expected_stage="preflight",
            run_manifest_sha256="c" * 64,
            attestation=attestation,
            output_ledger=output,
            expected_output_record_count=5,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "2.0"),
        ("record_type", "private_runtime_dump"),
        ("status", "failed"),
        ("stage", "scored_proxy"),
        ("source_commit", "f" * 40),
        ("image_digest", "sha256:" + "f" * 64),
        ("run_manifest_sha256", "f" * 64),
        ("model_id_sha256", "f" * 64),
        ("benchmark_revision", "f" * 40),
        ("scenario_order", {"sha256": "f" * 64, "count": 2}),
        ("runtime_contract_sha256", "D" * 64),
        ("runtime_instance_sha256", "e" * 63),
        ("checks", {"exact_image": True}),
        ("private_prompt", "must never survive validation"),
    ],
)
def test_runtime_attestation_rejects_any_non_allowlisted_or_mismatched_field(
    tmp_path, field, replacement
) -> None:
    path = tmp_path / "runtime-attestation.json"
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_attestation",
        "status": "passed",
        "stage": "preflight",
        "source_commit": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "run_manifest_sha256": "c" * 64,
        "model_id_sha256": "18fb9fa0b971b807a1312d3702d18747a3b1b39a129df8c5d1a8f68d512bd1fd",
        "benchmark_revision": BENCHMARK_REVISION,
        "scenario_order": {
            "sha256": "e36906789ac1c1a27abe7e60762c17fa92b660e7e29920ed603b89914b99545c",
            "count": 2,
        },
        "runtime_contract_sha256": "d" * 64,
        "runtime_instance_sha256": "e" * 64,
        "checks": {
            "exact_image": True,
            "settings": True,
            "resources": True,
            "bind": True,
            "observer": True,
            "ready": True,
            "secret_roles_distinct": True,
        },
    }
    document[field] = replacement
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(RuntimeAttestationFailure, match="^runtime_attestation_invalid$") as raised:
        load_runtime_attestation(
            path,
            expected_stage="preflight",
            source_commit="a" * 40,
            image_digest="sha256:" + "b" * 64,
            run_manifest_sha256="c" * 64,
            model="model",
            scenario_order=["case-1", "case-2"],
        )

    assert "must never survive validation" not in str(raised.value)


def _valid_attestation_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_attestation",
        "status": "passed",
        "stage": "preflight",
        "source_commit": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "run_manifest_sha256": "c" * 64,
        "model_id_sha256": "18fb9fa0b971b807a1312d3702d18747a3b1b39a129df8c5d1a8f68d512bd1fd",
        "benchmark_revision": BENCHMARK_REVISION,
        "scenario_order": {
            "sha256": "e36906789ac1c1a27abe7e60762c17fa92b660e7e29920ed603b89914b99545c",
            "count": 2,
        },
        "runtime_contract_sha256": "d" * 64,
        "runtime_instance_sha256": "e" * 64,
        "checks": {
            "exact_image": True,
            "settings": True,
            "resources": True,
            "bind": True,
            "observer": True,
            "ready": True,
            "secret_roles_distinct": True,
        },
    }


def _runtime_outcome_fixture(tmp_path):
    attestation = tmp_path / "preflight-runtime-attestation.json"
    attestation.write_text('{"safe":"attestation"}\n', encoding="utf-8")
    attestation.chmod(0o600)
    output = tmp_path / "preflight.jsonl"
    output.write_text("".join(f'{{"record":{index}}}\n' for index in range(5)), encoding="utf-8")
    output.chmod(0o600)
    path = tmp_path / "preflight-runtime-outcome.json"
    document = {
        "schema_version": "1.0",
        "record_type": "qualification_runtime_outcome",
        "stage": "preflight",
        "status": "passed",
        "action_exit_code": 0,
        "failure_category": None,
        "run_manifest_sha256": "c" * 64,
        "attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "output_ledger_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "output_record_count": 5,
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)
    return path, attestation, output, document


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "duplicate_key", "malformed"])
def test_runtime_attestation_rejects_untrusted_file_shapes(tmp_path, kind) -> None:
    path = tmp_path / "runtime-attestation.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text(json.dumps(_valid_attestation_document()), encoding="utf-8")
        path.symlink_to(target)
    elif kind == "duplicate_key":
        serialized = json.dumps(_valid_attestation_document(), separators=(",", ":"))
        path.write_text('{"stage":"scored_proxy",' + serialized[1:], encoding="utf-8")
    elif kind == "malformed":
        path.write_text("not-json", encoding="utf-8")

    with pytest.raises(RuntimeAttestationFailure, match="^runtime_attestation_invalid$"):
        load_runtime_attestation(
            path,
            expected_stage="preflight",
            source_commit="a" * 40,
            image_digest="sha256:" + "b" * 64,
            run_manifest_sha256="c" * 64,
            model="model",
            scenario_order=["case-1", "case-2"],
        )


@pytest.mark.parametrize("field", ["source_commit", "image_digest", "run_manifest_sha256", "count"])
def test_runtime_attestation_rejects_malformed_identity_even_when_caller_repeats_it(tmp_path, field) -> None:
    path = tmp_path / "runtime-attestation.json"
    document = _valid_attestation_document()
    source_commit = "a" * 40
    image_digest = "sha256:" + "b" * 64
    run_manifest_sha256 = "c" * 64
    scenario_order = ["case-1", "case-2"]
    if field == "source_commit":
        source_commit = "private-source"
        document[field] = source_commit
    elif field == "image_digest":
        image_digest = "sha256:" + "B" * 64
        document[field] = image_digest
    elif field == "run_manifest_sha256":
        run_manifest_sha256 = "C" * 64
        document[field] = run_manifest_sha256
    else:
        scenario_order = ["case-1"]
        canonical_order = json.dumps(scenario_order, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        document["scenario_order"] = {
            "sha256": hashlib.sha256(canonical_order.encode()).hexdigest(),
            "count": True,
        }
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(RuntimeAttestationFailure, match="^runtime_attestation_invalid$"):
        load_runtime_attestation(
            path,
            expected_stage="preflight",
            source_commit=source_commit,
            image_digest=image_digest,
            run_manifest_sha256=run_manifest_sha256,
            model="model",
            scenario_order=scenario_order,
        )
