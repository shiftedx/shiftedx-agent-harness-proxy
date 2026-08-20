from __future__ import annotations

import hashlib
import json

import pytest

from shiftedx_harness_proxy.qualification_contract import (
    BENCHMARK_REVISION,
    RuntimeAttestation,
    RuntimeAttestationFailure,
    load_runtime_attestation,
)


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
