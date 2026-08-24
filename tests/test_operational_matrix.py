from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_script():
    script = Path(__file__).parents[1] / "scripts" / "run_operational_matrix.py"
    spec = importlib.util.spec_from_file_location("run_operational_matrix", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(path: Path, candidate: str, rollback: str) -> Path:
    document = {
        "qualification_runtime": {
            "image": {"reference": candidate, "digest": candidate.rsplit("@", 1)[1], "uid": 10001, "gid": 10001},
            "rollback": {
                "reference": rollback,
                "digest": rollback.rsplit("@", 1)[1],
                "approval_designation": "approved-predecessor",
                "source_commit": "a" * 40,
                "workflow_url": "https://github.com/example/repo/actions/runs/1",
                "approval_evidence_url": "https://api.github.com/repos/example/repo/issues/comments/1",
            },
        }
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_digest_pinning_rejects_tags_and_accepts_sha256() -> None:
    module = _load_script()
    image = "example/proxy@sha256:" + "a" * 64

    assert module._digest_image(image) == image
    with pytest.raises(ValueError, match="digest_pinned_image_required"):
        module._digest_image("example/proxy:latest")


def test_stage_rethrows_only_content_free_phase_category() -> None:
    module = _load_script()

    with pytest.raises(RuntimeError, match="stage_latency_local_http_failed"):
        module._stage("latency", lambda: (_ for _ in ()).throw(RuntimeError("local_http_failed")))
    with pytest.raises(RuntimeError, match="stage_privacy_valueerror"):
        module._stage("privacy", lambda: (_ for _ in ()).throw(ValueError("https://secret.invalid")))


def test_fault_timeout_derives_a_bounded_delay_from_manifest_timeout() -> None:
    module = _load_script()

    assert module._fault_timeout_delay({"upstream_timeout_seconds": 120}) == (121.0, 125.0)
    with pytest.raises(ValueError, match="operational_manifest_invalid"):
        module._fault_timeout_delay({"upstream_timeout_seconds": 0})
    with pytest.raises(ValueError, match="operational_manifest_invalid"):
        module._fault_timeout_delay({"upstream_timeout_seconds": 3601})


def test_manifest_launch_requires_and_returns_upstream_timeout_and_call_ceiling(tmp_path: Path) -> None:
    module = _load_script()
    path = tmp_path / "manifest.json"
    document = {
        "qualification_runtime": {
            "proxy": {
                "cpus": 1,
                "memory_bytes": 512 * 1024 * 1024,
                "pids_limit": 128,
                "stop_timeout_seconds": 20,
                "settings": {
                    "admission_limit": 16,
                    "principal_concurrency_limit": 4,
                    "concurrency_limit": 32,
                    "total_request_deadline_seconds": 180,
                    "upstream_timeout_seconds": 120,
                    "max_upstream_calls": 7,
                },
            }
        }
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    _limits, settings = module._manifest_launch(path)
    assert settings["upstream_timeout_seconds"] == 120
    assert settings["max_upstream_calls"] == 7
    del document["qualification_runtime"]["proxy"]["settings"]["max_upstream_calls"]
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="operational_manifest_invalid"):
        module._manifest_launch(path)


def test_phase_idle_requires_proxy_gauges_and_authoritative_ledger_to_drain_after_cancellation() -> None:
    module = _load_script()
    gauges = {
        "shiftedx_proxy_downstream_active": 0,
        "shiftedx_proxy_downstream_queued": 0,
        "shiftedx_proxy_upstream_active": 0,
    }

    assert not module._phase_idle(gauges, {"active": 1})
    assert not module._phase_idle({**gauges, "shiftedx_proxy_upstream_active": 1}, {"active": 0})
    assert module._phase_idle(gauges, {"active": 0})


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rollback: rollback.pop("approval_evidence_url"),
        lambda rollback: rollback.__setitem__("unexpected", True),
        lambda rollback: rollback.__setitem__("digest", "sha256:" + "c" * 64),
        lambda rollback: rollback.__setitem__("source_commit", "c" * 39),
        lambda rollback: rollback.__setitem__("workflow_url", "http://github.com/a/b/actions/runs/1"),
        lambda rollback: rollback.__setitem__("approval_designation", "candidate"),
        lambda rollback: rollback.__setitem__("approval_evidence_url", "http://github.com/a/b/issues/1"),
        lambda rollback: rollback.__setitem__("approval_evidence_url", "https://example.com/approval"),
    ],
)
def test_manifest_binds_candidate_and_approved_distinct_rollback(mutate, tmp_path: Path) -> None:
    module = _load_script()
    candidate = "example/proxy@sha256:" + "a" * 64
    rollback = "example/proxy@sha256:" + "b" * 64
    path = _manifest(tmp_path / "manifest.json", candidate, rollback)

    manifest_sha, actual_candidate, actual_rollback = module._manifest_images(path)

    assert len(manifest_sha) == 64
    assert actual_candidate == candidate
    assert actual_rollback == rollback
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document["qualification_runtime"]["rollback"])
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="operational_manifest_invalid"):
        module._manifest_images(path)


def test_private_evidence_writer_is_no_clobber_and_mode_600(tmp_path: Path) -> None:
    module = _load_script()
    target = tmp_path / "evidence.json"
    module._safe_write_new(target, {"schema_version": "test"})

    assert json.loads(target.read_text(encoding="utf-8")) == {"schema_version": "test"}
    assert os.stat(target).st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        module._safe_write_new(target, {"schema_version": "replacement"})


def test_metric_parser_and_percentile_are_aggregate_only() -> None:
    module = _load_script()
    values = module._metric_values(
        b"# TYPE shiftedx_proxy_downstream_requests_total counter\n"
        b"shiftedx_proxy_downstream_requests_total 4\n"
        b"not_a_metric ignored\n"
    )

    assert values == {"shiftedx_proxy_downstream_requests_total": 4.0}
    assert module._percentile_ms([1.0, 2.0, 3.0, 4.0], 0.95) == 4.0


def test_resource_snapshot_calculations_enforce_manifest_limits_and_no_oom_restart() -> None:
    module = _load_script()
    limits = {"cpus": 1, "memory_bytes": 512 * 1024 * 1024, "pids_limit": 128}
    sample = {
        "stats": {"cpu_percent": 4.2, "memory_bytes": 40 * 1024 * 1024, "pids": 2},
        "oom_killed": False,
        "limits": {"memory_bytes": limits["memory_bytes"], "pids_limit": 128, "nano_cpus": 1_000_000_000},
    }

    assert module._parse_docker_memory_bytes("1.5MiB") == 1.5 * 1024 * 1024
    assert module._resource_ok([{**sample, "restart_count": 0}, {**sample, "restart_count": 0}], limits)
    assert not module._resource_ok([{**sample, "restart_count": 0}, {**sample, "restart_count": 1}], limits)


def test_authoritative_ledger_reconciliation_records_exact_attempts_and_manifest_ceiling() -> None:
    module = _load_script()
    before = {
        "shiftedx_proxy_downstream_requests_total": 10.0,
        "shiftedx_proxy_upstream_calls_total": 20.0,
    }
    after = {
        "shiftedx_proxy_downstream_requests_total": 20.0,
        "shiftedx_proxy_upstream_calls_total": 25.0,
    }
    ledger = {"proxied_attempts": 5, "attempts": {"shiftedx-a": 1, "shiftedx-b": 4}}

    record = module._reconciles(before, after, ledger, 7)

    assert record == {
        "reconciled": True,
        "downstream_delta": 10.0,
        "proxy_upstream_delta": 5.0,
        "authoritative_upstream_attempts": 5,
        "mean_upstream_attempts_per_downstream": 0.5,
        "upstream_attempt_ratio_ppm": 500000,
        "max_attempts_per_request": 4,
        "max_active": None,
    }
    assert not module._reconciles(before, after, {"proxied_attempts": 6, "attempts": {}}, 7)["reconciled"]
    assert not module._reconciles(before, after, {"proxied_attempts": 5, "attempts": {"shiftedx-a": 8}}, 7)[
        "reconciled"
    ]


def test_latency_gate_uses_direct_matched_baseline_threshold() -> None:
    module = _load_script()

    assert module._pass_through_threshold_ms(40.0) == 15
    assert module._pass_through_threshold_ms(400.0) == 20.0


def test_main_rejects_ornith_port_without_starting_anything(tmp_path: Path) -> None:
    module = _load_script()
    image = "example/proxy@sha256:" + "b" * 64

    assert (
        module.main(
            [
                "--candidate-image",
                image,
                "--rollback-image",
                image,
                "--output",
                str(tmp_path / "out.json"),
                "--candidate-port",
                "8000",
            ]
        )
        == 2
    )


def test_completed_scored_campaign_binds_matching_private_outcome_before_operational_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    manifest_sha256 = "a" * 64
    head_event_sha256 = "b" * 64
    campaign = tmp_path / "campaign"
    campaign.mkdir(mode=0o700)
    outcome = campaign / "qualification-campaign-outcome.json"
    outcome.write_text(
        json.dumps(
            {
                "status": "scored_complete",
                "campaign_manifest_sha256": manifest_sha256,
                "head_event_sha256": head_event_sha256,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(outcome, 0o600)
    outcome_sha256 = hashlib.sha256(outcome.read_bytes()).hexdigest()
    monkeypatch.setattr(
        module,
        "advance_qualification_campaign",
        lambda *_args, **_kwargs: SimpleNamespace(
            kind="campaign_scored_complete",
            campaign_outcome_sha256=outcome_sha256,
            event_sha256=head_event_sha256,
        ),
    )

    assert module._completed_scored_campaign(tmp_path / "manifest.json", campaign, manifest_sha256) == {
        "manifest_sha256": manifest_sha256,
        "outcome_sha256": outcome_sha256,
        "head_event_sha256": head_event_sha256,
    }

    monkeypatch.setattr(
        module,
        "advance_qualification_campaign",
        lambda *_args, **_kwargs: SimpleNamespace(
            kind="campaign_scored_complete", campaign_outcome_sha256=outcome_sha256, event_sha256="c" * 64
        ),
    )
    with pytest.raises(RuntimeError, match="scored_campaign_invalid"):
        module._completed_scored_campaign(tmp_path / "manifest.json", campaign, manifest_sha256)


def test_privacy_gate_scans_public_error_bodies_for_unique_sentinels(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_script()
    monkeypatch.setattr(module, "_run", lambda *_args, **_kwargs: "")

    assert not module._privacy_ok(
        "candidate", {}, [b'{"detail":"unique-private-sentinel"}'], ("unique-private-sentinel",)
    )


def test_malformed_stream_exercises_early_fragment_without_done() -> None:
    path = Path(__file__).with_name("fake_upstream.py")
    spec = importlib.util.spec_from_file_location("fake_upstream_for_operational_test", path)
    assert spec and spec.loader
    fake_upstream = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fake_upstream
    spec.loader.exec_module(fake_upstream)

    async def body() -> bytes:
        response = await fake_upstream._chat({"model": "fault-malformed-stream", "stream": True})
        return b"".join([chunk async for chunk in response.body_iterator])

    payload = asyncio.run(body())

    assert fake_upstream._MALFORMED_STREAM_BLOCKED_FRAGMENT.encode() in payload
    assert b"data: [DONE]" not in payload
    assert payload.endswith(b'"choices":[\n\n')
