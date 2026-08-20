"""Append-only orchestration for one frozen corrected-qualification campaign.

The module deliberately knows nothing about Docker, model launch commands, or
benchmark payloads.  Adapters validate and execute one derived stage; this
module owns campaign order, immutable evidence chaining, and no-rerun policy.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

CacheLane = Literal["cold", "warm-prefix"]
CampaignLane = Literal["preflight", "cold", "warm-prefix"]
CampaignStage = Literal["preflight", "score-direct", "score-proxy"]
StageStatus = Literal["passed", "failed", "interrupted"]
AdvanceKind = Literal["stage_completed", "restart_required", "campaign_passed", "campaign_failed"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FAILURE_CATEGORY = re.compile(r"^[a-z0-9_]{1,64}$")
_STAGES: tuple[CampaignStage, ...] = ("preflight", "score-direct", "score-proxy")
_OUTCOME_NAMES: dict[CampaignStage, str] = {
    "preflight": "preflight-runtime-outcome.json",
    "score-direct": "scored-direct-runtime-outcome.json",
    "score-proxy": "scored-proxy-runtime-outcome.json",
}


class CampaignFailure(RuntimeError):
    """A public-safe categorical campaign failure."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True)
class CampaignSlot:
    ordinal: int
    cache_lane: CampaignLane
    pair_index: int
    run_id: str


@dataclass(frozen=True)
class CampaignPosition:
    """Public-safe campaign position with private run identifiers omitted."""

    ordinal: int
    cache_lane: CampaignLane
    pair_index: int


@dataclass(frozen=True)
class StageRequest:
    manifest: Path
    manifest_sha256: str
    sequence: int
    slot: CampaignSlot
    stage: CampaignStage
    private_run_dir: Path
    outcome_path: Path


@dataclass(frozen=True)
class StageResult:
    status: StageStatus
    failure_category: str | None
    outcome_path: Path
    outcome_sha256: str
    model_runtime_instance_sha256: str | None
    proxy_reconciliation_sha256: str | None


@dataclass(frozen=True)
class StageInspection:
    state: Literal["absent", "complete", "partial"]
    result: StageResult | None


@dataclass(frozen=True)
class ReadinessResult:
    state: Literal["ready", "restart_required"]
    model_runtime_instance_sha256: str | None


@dataclass(frozen=True)
class CampaignAdvance:
    kind: AdvanceKind
    sequence: int | None
    slot: CampaignPosition | None
    stage: CampaignStage | None
    status: StageStatus | None
    failure_category: str | None
    event_sha256: str | None
    campaign_outcome_sha256: str | None


class StageRunner(Protocol):
    def inspect(self, request: StageRequest) -> StageInspection: ...

    def run(self, request: StageRequest) -> StageResult: ...


class ReadinessProbe(Protocol):
    def probe(self, request: StageRequest) -> ReadinessResult: ...


@dataclass(frozen=True)
class _CampaignSpec:
    manifest_sha256: str
    campaign_id_sha256: str
    preflight: CampaignSlot
    slots: tuple[CampaignSlot, ...]


def advance_qualification_campaign(
    manifest: Path,
    private_campaign_dir: Path,
    *,
    stage_runner: StageRunner,
    readiness_probe: ReadinessProbe,
) -> CampaignAdvance:
    """Advance exactly the sole next campaign stage and append its immutable event."""

    _validate_private_campaign_dir(private_campaign_dir)
    spec = _load_campaign_spec(manifest)
    lock_path = private_campaign_dir / ".campaign.lock"
    descriptor = _open_lock(lock_path)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError:
            raise CampaignFailure("campaign_lock_invalid") from None
        events_dir = _private_subdirectory(private_campaign_dir / "campaign-events")
        heads_dir = _private_subdirectory(private_campaign_dir / "campaign-event-heads")
        slots_dir = _private_subdirectory(private_campaign_dir / "slots")
        events, used_instances = _load_events(spec, manifest, slots_dir, events_dir, heads_dir, stage_runner)
        if events and events[-1][0]["status"] != "passed":
            return _terminal_advance(spec, manifest, slots_dir, events[-1][0], events[-1][1])
        if len(events) == 13:
            return _complete_campaign(spec, private_campaign_dir, events, used_instances)
        request = _stage_request(spec, manifest, slots_dir, len(events) + 1)
        inspection = _inspect_stage(stage_runner, request)
        if inspection.state == "partial":
            if inspection.result is not None:
                raise CampaignFailure("campaign_stage_state_invalid")
            event = _partial_event_record(
                spec,
                request,
                previous_event_sha256=events[-1][1] if events else None,
            )
            event_sha256 = _write_event(events_dir, heads_dir, request.sequence, event)
            return CampaignAdvance(
                "campaign_failed",
                request.sequence,
                _public_position(request.slot),
                request.stage,
                "failed",
                "campaign_partial_stage",
                event_sha256,
                None,
            )
        if inspection.state == "complete":
            if inspection.result is None:
                raise CampaignFailure("campaign_stage_state_invalid")
            result = inspection.result
            _validate_stage_result(request, result)
        elif inspection.state == "absent" and inspection.result is None:
            expected_instance: str | None = None
            if request.stage != "preflight":
                readiness = _probe_readiness(readiness_probe, request)
                if readiness.state == "restart_required" and readiness.model_runtime_instance_sha256 is None:
                    return CampaignAdvance(
                        "restart_required",
                        request.sequence,
                        _public_position(request.slot),
                        request.stage,
                        None,
                        None,
                        None,
                        None,
                    )
                if (
                    readiness.state != "ready"
                    or readiness.model_runtime_instance_sha256 is None
                    or _SHA256.fullmatch(readiness.model_runtime_instance_sha256) is None
                    or readiness.model_runtime_instance_sha256 in used_instances
                ):
                    raise CampaignFailure("campaign_model_instance_invalid")
                expected_instance = readiness.model_runtime_instance_sha256
            _private_subdirectory(request.private_run_dir)
            result = _run_stage(stage_runner, request)
            _validate_stage_result(request, result)
            if (
                expected_instance is not None
                and result.model_runtime_instance_sha256 is not None
                and result.model_runtime_instance_sha256 != expected_instance
            ):
                raise CampaignFailure("campaign_model_instance_invalid")
        else:
            raise CampaignFailure("campaign_stage_state_invalid")
        if result.model_runtime_instance_sha256 is not None and result.model_runtime_instance_sha256 in used_instances:
            raise CampaignFailure("campaign_model_instance_reused")
        event = _event_record(
            spec,
            request,
            result,
            previous_event_sha256=events[-1][1] if events else None,
        )
        event_sha256 = _write_event(events_dir, heads_dir, request.sequence, event)
        if request.sequence == 13 and result.status == "passed":
            if result.model_runtime_instance_sha256 is None:
                raise CampaignFailure("campaign_model_instance_invalid")
            used_instances.add(result.model_runtime_instance_sha256)
            return _complete_campaign(
                spec,
                private_campaign_dir,
                [*events, (event, event_sha256)],
                used_instances,
            )
        kind: AdvanceKind = "stage_completed" if result.status == "passed" else "campaign_failed"
        return CampaignAdvance(
            kind=kind,
            sequence=request.sequence,
            slot=_public_position(request.slot),
            stage=request.stage,
            status=result.status,
            failure_category=result.failure_category,
            event_sha256=event_sha256,
            campaign_outcome_sha256=None,
        )
    finally:
        os.close(descriptor)


def _load_events(
    spec: _CampaignSpec,
    manifest: Path,
    slots_dir: Path,
    events_dir: Path,
    heads_dir: Path,
    stage_runner: StageRunner,
) -> tuple[list[tuple[dict[str, Any], str]], set[str]]:
    try:
        paths = sorted(events_dir.iterdir(), key=lambda item: item.name)
        head_paths = sorted(heads_dir.iterdir(), key=lambda item: item.name)
    except OSError:
        raise CampaignFailure("campaign_event_chain_invalid") from None
    expected_names = [f"{index:04d}.json" for index in range(1, len(paths) + 1)]
    head_names = [path.name for path in head_paths]
    if (
        [path.name for path in paths] != expected_names
        or len(paths) > 13
        or head_names not in (expected_names, expected_names[:-1])
    ):
        raise CampaignFailure("campaign_event_chain_invalid")
    events: list[tuple[dict[str, Any], str]] = []
    used_instances: set[str] = set()
    previous: str | None = None
    for sequence, path in enumerate(paths, start=1):
        try:
            serialized = _read_regular_file(path, private=True)
            event = json.loads(serialized, object_pairs_hook=_unique_object)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise CampaignFailure("campaign_event_chain_invalid") from None
        request = _stage_request(spec, manifest, slots_dir, sequence)
        if not isinstance(event, dict):
            raise CampaignFailure("campaign_event_chain_invalid")
        if event.get("failure_category") == "campaign_partial_stage":
            expected = _partial_event_record(spec, request, previous_event_sha256=previous)
        else:
            inspection = _inspect_stage(stage_runner, request)
            if inspection.state != "complete" or inspection.result is None:
                raise CampaignFailure("campaign_event_chain_invalid")
            _validate_stage_result(request, inspection.result)
            expected = _event_record(spec, request, inspection.result, previous_event_sha256=previous)
        if event != expected:
            raise CampaignFailure("campaign_event_chain_invalid")
        canonical = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if serialized != canonical:
            raise CampaignFailure("campaign_event_chain_invalid")
        digest = hashlib.sha256(serialized).hexdigest()
        head = {
            "schema_version": "1.0",
            "record_type": "qualification_campaign_event_head",
            "sequence": sequence,
            "event_sha256": digest,
        }
        head_path = heads_dir / f"{sequence:04d}.json"
        if head_path.exists() or head_path.is_symlink():
            try:
                head_bytes = _read_regular_file(head_path, private=True)
                head_document = json.loads(head_bytes, object_pairs_hook=_unique_object)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raise CampaignFailure("campaign_event_chain_invalid") from None
            if head_document != head:
                raise CampaignFailure("campaign_event_chain_invalid")
        elif sequence == len(paths):
            _atomic_write_no_clobber(head_path, head)
        else:
            raise CampaignFailure("campaign_event_chain_invalid")
        events.append((event, digest))
        previous = digest
        if event.get("failure_category") != "campaign_partial_stage":
            instance = event.get("model_runtime_instance_sha256")
            if instance is not None and (not isinstance(instance, str) or instance in used_instances):
                raise CampaignFailure("campaign_model_instance_reused")
            if instance is not None:
                used_instances.add(instance)
    return events, used_instances


def _stage_request(spec: _CampaignSpec, manifest: Path, slots_dir: Path, sequence: int) -> StageRequest:
    if sequence == 1:
        slot = spec.preflight
        stage: CampaignStage = "preflight"
    elif 2 <= sequence <= 13:
        offset = sequence - 2
        slot = spec.slots[offset // 2]
        stage = "score-direct" if offset % 2 == 0 else "score-proxy"
    else:
        raise CampaignFailure("campaign_event_chain_invalid")
    run_dir = slots_dir / _slot_directory_name(slot)
    return StageRequest(
        manifest=manifest,
        manifest_sha256=spec.manifest_sha256,
        sequence=sequence,
        slot=slot,
        stage=stage,
        private_run_dir=run_dir,
        outcome_path=run_dir / _OUTCOME_NAMES[stage],
    )


def _write_event(events_dir: Path, heads_dir: Path, sequence: int, event: dict[str, Any]) -> str:
    serialized = _atomic_write_no_clobber(events_dir / f"{sequence:04d}.json", event)
    digest = hashlib.sha256(serialized).hexdigest()
    _atomic_write_no_clobber(
        heads_dir / f"{sequence:04d}.json",
        {
            "schema_version": "1.0",
            "record_type": "qualification_campaign_event_head",
            "sequence": sequence,
            "event_sha256": digest,
        },
    )
    return digest


def _partial_event_record(
    spec: _CampaignSpec,
    request: StageRequest,
    *,
    previous_event_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "record_type": "qualification_campaign_event",
        "campaign_manifest_sha256": spec.manifest_sha256,
        "campaign_id_sha256": spec.campaign_id_sha256,
        "sequence": request.sequence,
        "slot_ordinal": request.slot.ordinal,
        "cache_lane": request.slot.cache_lane,
        "pair_index": request.slot.pair_index,
        "stage": request.stage,
        "status": "failed",
        "failure_category": "campaign_partial_stage",
        "runtime_outcome_sha256": None,
        "model_runtime_instance_sha256": None,
        "proxy_reconciliation_sha256": None,
        "previous_event_sha256": previous_event_sha256,
    }


def _terminal_advance(
    spec: _CampaignSpec,
    manifest: Path,
    slots_dir: Path,
    event: dict[str, Any],
    event_sha256: str,
) -> CampaignAdvance:
    sequence = event.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise CampaignFailure("campaign_event_chain_invalid")
    request = _stage_request(spec, manifest, slots_dir, sequence)
    return CampaignAdvance(
        "campaign_failed",
        sequence,
        _public_position(request.slot),
        request.stage,
        event.get("status") if event.get("status") in {"failed", "interrupted"} else "failed",
        event.get("failure_category") if isinstance(event.get("failure_category"), str) else None,
        event_sha256,
        None,
    )


def _complete_campaign(
    spec: _CampaignSpec,
    private_campaign_dir: Path,
    events: list[tuple[dict[str, Any], str]],
    used_instances: set[str],
) -> CampaignAdvance:
    if len(used_instances) != 13:
        raise CampaignFailure("campaign_model_instance_invalid")
    outcome = {
        "schema_version": "1.0",
        "record_type": "qualification_campaign_outcome",
        "status": "passed",
        "campaign_manifest_sha256": spec.manifest_sha256,
        "head_event_sha256": events[-1][1],
        "event_count": 13,
        "slot_count": 6,
        "scored_stage_count": 12,
        "scored_model_instance_count": 12,
        "proxy_reconciliation_sha256s": [
            event["proxy_reconciliation_sha256"]
            for event, _digest in events
            if event["stage"] == "score-proxy"
        ],
    }
    path = private_campaign_dir / "qualification-campaign-outcome.json"
    if path.exists() or path.is_symlink():
        try:
            serialized = _read_regular_file(path, private=True)
            existing = json.loads(serialized, object_pairs_hook=_unique_object)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise CampaignFailure("campaign_outcome_invalid") from None
        if existing != outcome:
            raise CampaignFailure("campaign_outcome_invalid")
    else:
        serialized = _atomic_write_no_clobber(path, outcome)
    digest = hashlib.sha256(serialized).hexdigest()
    return CampaignAdvance("campaign_passed", None, None, None, None, None, events[-1][1], digest)


def _load_campaign_spec(path: Path) -> _CampaignSpec:
    try:
        serialized = _read_regular_file(path, private=False)
        document = json.loads(serialized, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise CampaignFailure("campaign_manifest_invalid") from None
    runtime = document.get("qualification_runtime") if isinstance(document, dict) else None
    campaign = runtime.get("campaign") if isinstance(runtime, dict) else None
    expected_keys = {
        "campaign_id",
        "slots",
        "stage_order",
        "treatment_order",
        "model_instance_policy",
        "failure_policy",
    }
    if not isinstance(campaign, dict) or set(campaign) != expected_keys:
        raise CampaignFailure("campaign_manifest_invalid")
    campaign_id = campaign.get("campaign_id")
    raw_slots = campaign.get("slots")
    if (
        not isinstance(campaign_id, str)
        or _SAFE_ID.fullmatch(campaign_id) is None
        or campaign.get("stage_order") != list(_STAGES)
        or campaign.get("treatment_order") != ["direct", "proxy"]
        or campaign.get("model_instance_policy") != "fresh-per-scored-treatment"
        or campaign.get("failure_policy") != "terminal-no-rerun"
        or not isinstance(raw_slots, list)
        or len(raw_slots) != 6
    ):
        raise CampaignFailure("campaign_manifest_invalid")
    expected_pairs: tuple[tuple[CacheLane, int], ...] = (
        ("cold", 1),
        ("cold", 2),
        ("cold", 3),
        ("warm-prefix", 1),
        ("warm-prefix", 2),
        ("warm-prefix", 3),
    )
    slots: list[CampaignSlot] = []
    run_ids: set[str] = set()
    for ordinal, (raw, expected) in enumerate(zip(raw_slots, expected_pairs, strict=True), start=1):
        if not isinstance(raw, dict) or set(raw) != {"cache_lane", "pair_index", "run_id"}:
            raise CampaignFailure("campaign_manifest_invalid")
        lane, pair = expected
        run_id = raw.get("run_id")
        if (
            raw.get("cache_lane") != lane
            or raw.get("pair_index") != pair
            or not isinstance(run_id, str)
            or _SAFE_ID.fullmatch(run_id) is None
            or run_id in run_ids
        ):
            raise CampaignFailure("campaign_manifest_invalid")
        run_ids.add(run_id)
        slots.append(CampaignSlot(ordinal, lane, pair, run_id))
    return _CampaignSpec(
        manifest_sha256=hashlib.sha256(serialized).hexdigest(),
        campaign_id_sha256=hashlib.sha256(campaign_id.encode()).hexdigest(),
        preflight=CampaignSlot(0, "preflight", 0, f"{campaign_id}-preflight"),
        slots=tuple(slots),
    )


def _validate_private_campaign_dir(path: Path) -> None:
    try:
        status = path.lstat()
    except OSError:
        raise CampaignFailure("campaign_private_dir_invalid") from None
    if path.is_symlink() or not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o700:
        raise CampaignFailure("campaign_private_dir_invalid")


def _private_subdirectory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError:
        raise CampaignFailure("campaign_private_dir_invalid") from None
    try:
        status = path.lstat()
    except OSError:
        raise CampaignFailure("campaign_private_dir_invalid") from None
    if path.is_symlink() or not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o700:
        raise CampaignFailure("campaign_private_dir_invalid")
    return path


def _open_lock(path: Path) -> int:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(descriptor, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CampaignFailure("campaign_lock_invalid")
        return descriptor
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise CampaignFailure("campaign_lock_invalid") from None
    except CampaignFailure:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _inspect_stage(stage_runner: StageRunner, request: StageRequest) -> StageInspection:
    try:
        inspection = stage_runner.inspect(request)
    except Exception:
        raise CampaignFailure("campaign_stage_inspection_failed") from None
    if not isinstance(inspection, StageInspection):
        raise CampaignFailure("campaign_stage_state_invalid")
    return inspection


def _probe_readiness(readiness_probe: ReadinessProbe, request: StageRequest) -> ReadinessResult:
    try:
        readiness = readiness_probe.probe(request)
    except Exception:
        raise CampaignFailure("campaign_readiness_probe_failed") from None
    if not isinstance(readiness, ReadinessResult):
        raise CampaignFailure("campaign_model_instance_invalid")
    return readiness


def _run_stage(stage_runner: StageRunner, request: StageRequest) -> StageResult:
    try:
        result = stage_runner.run(request)
    except Exception:
        raise CampaignFailure("campaign_stage_runner_failed") from None
    if not isinstance(result, StageResult):
        raise CampaignFailure("campaign_stage_outcome_invalid")
    return result


def _validate_stage_result(request: StageRequest, result: StageResult) -> None:
    if (
        result.status not in {"passed", "failed", "interrupted"}
        or (result.status == "passed") != (result.failure_category is None)
        or (
            result.failure_category is not None
            and _FAILURE_CATEGORY.fullmatch(result.failure_category) is None
        )
        or result.outcome_path != request.outcome_path
        or _SHA256.fullmatch(result.outcome_sha256) is None
        or (
            result.model_runtime_instance_sha256 is not None
            and _SHA256.fullmatch(result.model_runtime_instance_sha256) is None
        )
        or (result.status == "passed" and result.model_runtime_instance_sha256 is None)
        or (
            result.proxy_reconciliation_sha256 is not None
            and _SHA256.fullmatch(result.proxy_reconciliation_sha256) is None
        )
        or (
            result.status == "passed"
            and (request.stage == "score-proxy") != (result.proxy_reconciliation_sha256 is not None)
        )
        or (request.stage != "score-proxy" and result.proxy_reconciliation_sha256 is not None)
    ):
        raise CampaignFailure("campaign_stage_outcome_invalid")
    try:
        serialized = _read_regular_file(result.outcome_path, private=True)
    except OSError:
        raise CampaignFailure("campaign_stage_outcome_invalid") from None
    if hashlib.sha256(serialized).hexdigest() != result.outcome_sha256:
        raise CampaignFailure("campaign_stage_outcome_invalid")


def _event_record(
    spec: _CampaignSpec,
    request: StageRequest,
    result: StageResult,
    *,
    previous_event_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "record_type": "qualification_campaign_event",
        "campaign_manifest_sha256": spec.manifest_sha256,
        "campaign_id_sha256": spec.campaign_id_sha256,
        "sequence": request.sequence,
        "slot_ordinal": request.slot.ordinal,
        "cache_lane": request.slot.cache_lane,
        "pair_index": request.slot.pair_index,
        "stage": request.stage,
        "status": result.status,
        "failure_category": result.failure_category,
        "runtime_outcome_sha256": result.outcome_sha256,
        "model_runtime_instance_sha256": result.model_runtime_instance_sha256,
        "proxy_reconciliation_sha256": result.proxy_reconciliation_sha256,
        "previous_event_sha256": previous_event_sha256,
    }


def _atomic_write_no_clobber(path: Path, document: dict[str, Any]) -> bytes:
    serialized = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, serialized)
        os.fsync(descriptor)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError:
        raise CampaignFailure("campaign_evidence_exists") from None
    except OSError:
        raise CampaignFailure("campaign_evidence_write_failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return serialized


def _read_regular_file(path: Path, *, private: bool) -> bytes:
    status = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(status.st_mode) or (private and stat.S_IMODE(status.st_mode) != 0o600):
        raise OSError("invalid file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino)
            or opened.st_size > 1024 * 1024
            or (private and stat.S_IMODE(opened.st_mode) != 0o600)
        ):
            raise OSError("invalid file")
        return os.read(descriptor, opened.st_size + 1)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        offset += os.write(descriptor, data[offset:])


def _slot_directory_name(slot: CampaignSlot) -> str:
    return f"{slot.ordinal:02d}-{slot.cache_lane}-pair{slot.pair_index}"


def _public_position(slot: CampaignSlot) -> CampaignPosition:
    return CampaignPosition(slot.ordinal, slot.cache_lane, slot.pair_index)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result
