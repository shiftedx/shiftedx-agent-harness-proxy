"""Campaign-level no-rerun enforcement for the corrected qualification."""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from shiftedx_harness_proxy.qualification_campaign import (
    CampaignFailure,
    CampaignPosition,
    CampaignSlot,
    ReadinessResult,
    StageInspection,
    StageRequest,
    StageResult,
    advance_qualification_campaign,
)


def _campaign_manifest(path: Path) -> Path:
    slots = [
        {"cache_lane": lane, "pair_index": pair, "run_id": f"qualification-{lane}-{pair}"}
        for lane in ("cold", "warm-prefix")
        for pair in range(1, 4)
    ]
    document = {
        "qualification_runtime": {
            "campaign": {
                "campaign_id": "qualification-2026-08-20-r1",
                "slots": slots,
                "stage_order": ["preflight", "score-direct", "score-proxy"],
                "treatment_order": ["direct", "proxy"],
                "model_instance_policy": "fresh-per-scored-treatment",
                "failure_policy": "terminal-no-rerun",
            }
        }
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _private_campaign(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


class _ReadyProbe:
    def __init__(self, *, restart_sequences: set[int] | None = None) -> None:
        self.restart_sequences = restart_sequences or set()

    def probe(self, request: StageRequest) -> ReadinessResult:
        if request.sequence in self.restart_sequences:
            return ReadinessResult("restart_required", None)
        return ReadinessResult("ready", hashlib.sha256(f"instance-{request.sequence}".encode()).hexdigest())


class _FakeStageRunner:
    def __init__(
        self,
        *,
        statuses: dict[int, str] | None = None,
        partial_sequences: set[int] | None = None,
        crash_sequences: set[int] | None = None,
        fixed_instance_sha256: str | None = None,
        null_evidence_sequences: set[int] | None = None,
        failure_categories: dict[int, str] | None = None,
    ) -> None:
        self.requests: list[StageRequest] = []
        self.results: dict[Path, StageResult] = {}
        self.statuses = statuses or {}
        self.partial_sequences = partial_sequences or set()
        self.crash_sequences = crash_sequences or set()
        self.fixed_instance_sha256 = fixed_instance_sha256
        self.null_evidence_sequences = null_evidence_sequences or set()
        self.failure_categories = failure_categories or {}

    def inspect(self, request: StageRequest) -> StageInspection:
        if request.sequence in self.partial_sequences:
            return StageInspection("partial", None)
        result = self.results.get(request.outcome_path)
        if result is None:
            return StageInspection("partial" if request.outcome_path.exists() else "absent", None)
        try:
            data = request.outcome_path.read_bytes()
        except OSError:
            return StageInspection("partial", None)
        if hashlib.sha256(data).hexdigest() != result.outcome_sha256:
            return StageInspection("partial", None)
        return StageInspection("complete", result)

    def run(self, request: StageRequest) -> StageResult:
        self.requests.append(request)
        status = self.statuses.get(request.sequence, "passed")
        request.outcome_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "sequence": request.sequence,
                "slot": request.slot.ordinal,
                "stage": request.stage,
                "status": status,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        request.outcome_path.write_bytes(payload)
        os.chmod(request.outcome_path, 0o600)
        result = StageResult(
            status=status,  # type: ignore[arg-type]
            failure_category=None if status == "passed" else self.failure_categories.get(
                request.sequence, f"stage_{status}"
            ),
            outcome_path=request.outcome_path,
            outcome_sha256=hashlib.sha256(payload).hexdigest(),
            model_runtime_instance_sha256=(
                self.fixed_instance_sha256
                or hashlib.sha256(f"instance-{request.sequence}".encode()).hexdigest()
            ),
            proxy_reconciliation_sha256=(
                hashlib.sha256(f"reconciliation-{request.sequence}".encode()).hexdigest()
                if request.stage == "score-proxy"
                else None
            ),
        )
        if request.sequence in self.null_evidence_sequences:
            result = replace(
                result,
                model_runtime_instance_sha256=None,
                proxy_reconciliation_sha256=None,
            )
        self.results[request.outcome_path] = result
        if request.sequence in self.crash_sequences:
            self.crash_sequences.remove(request.sequence)
            raise RuntimeError("simulated adapter crash after durable outcome")
        return result


def test_first_advance_derives_one_campaign_preflight_and_writes_private_event(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()

    result = advance_qualification_campaign(
        manifest,
        private,
        stage_runner=runner,
        readiness_probe=_ReadyProbe(),
    )

    assert result.kind == "stage_completed"
    assert result.sequence == 1
    assert result.slot == CampaignPosition(0, "preflight", 0)
    assert not hasattr(result.slot, "run_id")
    assert result.stage == "preflight"
    assert len(runner.requests) == 1
    assert runner.requests[0].slot == CampaignSlot(
        0, "preflight", 0, "qualification-2026-08-20-r1-preflight"
    )
    event = private / "campaign-events" / "0001.json"
    assert event.is_file()
    assert event.stat().st_mode & 0o777 == 0o600


def test_scored_advance_waits_for_restart_then_runs_the_only_next_treatment(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()
    advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())

    waiting = advance_qualification_campaign(
        manifest,
        private,
        stage_runner=runner,
        readiness_probe=_ReadyProbe(restart_sequences={2}),
    )

    assert waiting.kind == "restart_required"
    assert waiting.sequence == 2
    assert waiting.slot == CampaignPosition(1, "cold", 1)
    assert waiting.stage == "score-direct"
    assert len(runner.requests) == 1
    assert not (private / "campaign-events" / "0002.json").exists()
    assert not (private / "slots" / "01-cold-pair1").exists()

    completed = advance_qualification_campaign(
        manifest,
        private,
        stage_runner=runner,
        readiness_probe=_ReadyProbe(),
    )
    assert completed.kind == "stage_completed"
    assert completed.sequence == 2
    assert completed.slot == CampaignPosition(1, "cold", 1)
    assert completed.stage == "score-direct"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda campaign: campaign.update(stage_order=["preflight", "score-proxy", "score-direct"]),
        lambda campaign: campaign.update(treatment_order=["proxy", "direct"]),
        lambda campaign: campaign.update(model_instance_policy="reuse"),
        lambda campaign: campaign.update(failure_policy="retry"),
        lambda campaign: campaign["slots"].reverse(),
        lambda campaign: campaign["slots"].pop(),
        lambda campaign: campaign["slots"][1].update(run_id=campaign["slots"][0]["run_id"]),
        lambda campaign: campaign.update(extra=True),
    ],
)
def test_manifest_freezes_exact_six_slot_order_and_policies(tmp_path: Path, mutation) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    document = json.loads(manifest.read_text(encoding="utf-8"))
    mutation(document["qualification_runtime"]["campaign"])
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CampaignFailure, match="campaign_manifest_invalid"):
        advance_qualification_campaign(
            manifest,
            _private_campaign(tmp_path / "campaign"),
            stage_runner=_FakeStageRunner(),
            readiness_probe=_ReadyProbe(),
        )


def test_duplicate_manifest_keys_are_rejected_before_stage_runner(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"qualification_runtime":{"campaign":{},"campaign":{}}}', encoding="utf-8")
    runner = _FakeStageRunner()

    with pytest.raises(CampaignFailure, match="campaign_manifest_invalid"):
        advance_qualification_campaign(
            manifest,
            _private_campaign(tmp_path / "campaign"),
            stage_runner=runner,
            readiness_probe=_ReadyProbe(),
        )
    assert runner.requests == []


def test_campaign_runs_one_preflight_then_six_direct_proxy_pairs_and_finalizes(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()

    results = [
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
        for _ in range(13)
    ]
    final = results[-1]
    repeated = advance_qualification_campaign(
        manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
    )

    assert [(item.slot.cache_lane, item.slot.pair_index, item.stage) for item in runner.requests] == [
        ("preflight", 0, "preflight"),
        *(item for lane in ("cold", "warm-prefix") for pair in range(1, 4) for item in (
            (lane, pair, "score-direct"),
            (lane, pair, "score-proxy"),
        )),
    ]
    assert final.kind == "campaign_passed"
    outcome = private / "qualification-campaign-outcome.json"
    assert outcome.stat().st_mode & 0o777 == 0o600
    assert repeated.kind == "campaign_passed"
    assert repeated.campaign_outcome_sha256 == final.campaign_outcome_sha256
    assert len(runner.requests) == 13
    document = json.loads(outcome.read_text(encoding="utf-8"))
    assert document["event_count"] == 13
    assert document["scored_stage_count"] == document["scored_model_instance_count"] == 12
    assert document["slot_count"] == len(document["proxy_reconciliation_sha256s"]) == 6


def test_final_outcome_is_idempotent_but_cannot_be_replaced(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()
    first = [
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
        for _ in range(13)
    ][-1]
    outcome = private / "qualification-campaign-outcome.json"
    inode = outcome.stat().st_ino

    repeated = advance_qualification_campaign(
        manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
    )

    assert repeated.campaign_outcome_sha256 == first.campaign_outcome_sha256
    assert outcome.stat().st_ino == inode
    document = json.loads(outcome.read_text(encoding="utf-8"))
    document["status"] = "failed"
    outcome.write_text(json.dumps(document), encoding="utf-8")
    os.chmod(outcome, 0o600)
    with pytest.raises(CampaignFailure, match="campaign_outcome_invalid"):
        advance_qualification_campaign(
            manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
        )


def test_complete_outcome_after_crash_is_chained_without_rerunning_stage(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner(crash_sequences={1})

    with pytest.raises(CampaignFailure, match="campaign_stage_runner_failed"):
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    assert len(runner.requests) == 1
    assert not (private / "campaign-events" / "0001.json").exists()

    recovered = advance_qualification_campaign(
        manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
    )
    assert recovered.kind == "stage_completed"
    assert len(runner.requests) == 1


def test_latest_event_head_crash_window_is_recovered_without_rerun(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()
    advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    head = private / "campaign-event-heads" / "0001.json"
    head.unlink()

    advanced = advance_qualification_campaign(
        manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
    )

    assert head.is_file()
    assert advanced.sequence == 2
    assert [request.sequence for request in runner.requests] == [1, 2]


@pytest.mark.parametrize("status", ["failed", "interrupted"])
def test_failed_or_interrupted_stage_is_terminal_and_never_reruns(tmp_path: Path, status: str) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner(statuses={1: status})

    failed = advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    repeated = advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())

    assert failed.kind == repeated.kind == "campaign_failed"
    assert len(runner.requests) == 1
    assert len(list((private / "campaign-events").glob("*.json"))) == 1


def test_failed_stage_can_end_before_instance_or_reconciliation_evidence_exists(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner(statuses={1: "failed"}, null_evidence_sequences={1})

    result = advance_qualification_campaign(
        manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
    )

    assert result.kind == "campaign_failed"
    assert result.failure_category == "stage_failed"


def test_failure_category_is_restricted_to_public_safe_tokens(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner(
        statuses={1: "failed"},
        failure_categories={1: "not-a-safe category"},
    )

    with pytest.raises(CampaignFailure, match="campaign_stage_outcome_invalid"):
        advance_qualification_campaign(
            manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
        )
    assert not (private / "campaign-events" / "0001.json").exists()


def test_partial_stage_is_chained_as_terminal_and_never_run(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner(partial_sequences={1})

    failed = advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    repeated = advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())

    assert failed.kind == repeated.kind == "campaign_failed"
    assert failed.failure_category == "campaign_partial_stage"
    assert runner.requests == []


@pytest.mark.parametrize("tamper", ["event_edit", "event_delete", "outcome_edit", "outcome_delete"])
def test_chain_rejects_edited_or_deleted_events_and_outcomes(tmp_path: Path, tamper: str) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()
    advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    event = private / "campaign-events" / "0001.json"
    outcome = runner.requests[0].outcome_path
    target = event if tamper.startswith("event") else outcome
    if tamper.endswith("edit"):
        target.write_bytes(target.read_bytes() + b" ")
        os.chmod(target, 0o600)
    else:
        target.unlink()

    with pytest.raises(CampaignFailure, match="campaign_event_chain_invalid"):
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    assert len(runner.requests) == 1


def test_chain_rejects_reordered_event_documents(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()
    for _ in range(2):
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    first = private / "campaign-events" / "0001.json"
    second = private / "campaign-events" / "0002.json"
    first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
    first.write_bytes(second_bytes)
    second.write_bytes(first_bytes)
    os.chmod(first, 0o600)
    os.chmod(second, 0o600)

    with pytest.raises(CampaignFailure, match="campaign_event_chain_invalid"):
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())


def test_manifest_mutation_after_first_event_is_rejected(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()
    advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["irrelevant_but_digest_bound"] = True
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CampaignFailure, match="campaign_event_chain_invalid"):
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe())


def test_private_campaign_directory_must_already_be_mode_0700(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = tmp_path / "campaign"
    private.mkdir(mode=0o755)
    os.chmod(private, 0o755)  # noqa: S103 - exercise rejection of an unsafe private directory

    with pytest.raises(CampaignFailure, match="campaign_private_dir_invalid"):
        advance_qualification_campaign(
            manifest, private, stage_runner=_FakeStageRunner(), readiness_probe=_ReadyProbe()
        )


class _SameInstanceProbe:
    def probe(self, _request: StageRequest) -> ReadinessResult:
        return ReadinessResult("ready", "a" * 64)


def test_all_twelve_scored_stages_require_unique_model_instances(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner(fixed_instance_sha256="a" * 64)
    advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_SameInstanceProbe())

    with pytest.raises(CampaignFailure, match="campaign_model_instance_invalid"):
        advance_qualification_campaign(manifest, private, stage_runner=runner, readiness_probe=_SameInstanceProbe())
    assert len(runner.requests) == 1


def test_concurrent_advances_cannot_run_the_same_stage_twice(tmp_path: Path) -> None:
    manifest = _campaign_manifest(tmp_path / "manifest.json")
    private = _private_campaign(tmp_path / "campaign")
    runner = _FakeStageRunner()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _index: advance_qualification_campaign(
                    manifest, private, stage_runner=runner, readiness_probe=_ReadyProbe()
                ),
                range(2),
            )
        )

    assert sorted(item.sequence for item in results if item.sequence is not None) == [1, 2]
    assert [request.sequence for request in runner.requests] == [1, 2]
