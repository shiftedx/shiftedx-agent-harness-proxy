#!/usr/bin/env python3
"""Run one schema-aware Shiftedx agentic trial without modifying the benchmark source."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any, TypeAlias

from shiftedx_bench.agentic import run_agentic_cases, scenario_set
from shiftedx_bench.api import OpenAIClient

from shiftedx_harness_proxy.core import HARNESS_SYSTEM_SUFFIX
from shiftedx_harness_proxy.projection_accounting import (
    LOCAL_PROJECTION_EXTENSION,
    public_projection_summary,
)
from shiftedx_harness_proxy.qualification_contract import (
    ModelBoundaryObserverCursor,
    ModelBoundaryRecord,
    PhasePlanner,
    PreflightFailure,
    PreflightObservation,
    RuntimeAttestation,
    RuntimeAttestationFailure,
    SafeFingerprint,
    load_runtime_attestation,
    model_boundary_fingerprint,
    model_boundary_record,
    qualification_contract_digest,
    request_fingerprints,
    require_candidate_provenance,
    require_scoring_gate,
    terminal_schema_valid,
    validate_run_manifest_sha256,
    write_model_boundary_attempt_ledger,
    write_preflight_ledger,
)
from shiftedx_harness_proxy.qualification_contract import (
    assert_preflight as _assert_preflight,
)
from shiftedx_harness_proxy.qualification_contract import (
    contract_mismatches as _contract_mismatches,
)
from shiftedx_harness_proxy.qualification_reconciliation import (
    RequestAccountingRecord,
    RequestOutcome,
    write_request_accounting_ledger,
)

_SYSTEM_PROMPT = (
    "You are an autonomous coding agent in a deterministic sandbox. Use supplied tools, never invent "
    "results, recover from failures, verify completion, and obey the requested final JSON format."
)
_HTTP_STATUS = re.compile(r"\bHTTP ([1-5][0-9]{2})\b")
_CANONICAL_COUNTER = re.compile(r"^(?:0|[1-9][0-9]{0,19})$")
_MAX_PROXY_RESPONSE_BYTES = 16 * 1024 * 1024
PROXY_RESPONSE_ACCOUNTING = "_shiftedx_qualification_proxy_accounting"
ProxyRequestRecord: TypeAlias = RequestAccountingRecord
SamplerProfile: TypeAlias = str

_SAMPLER_PROFILES: dict[SamplerProfile, dict[str, Any]] = {
    "corrected-parity-v1": {
        "temperature": 0.0,
        "top_p": 0.95,
        "top_k": 20,
        "thinking": {"enabled": True},
        "reasoning_effort": "medium",
        "max_tokens": 1024,
    },
    "historical-aeon-v1": {
        "temperature": 1.0,
        "top_p": 0.95,
        "top_k": 20,
        "thinking": {"enabled": True},
        "reasoning_effort": "medium",
        "max_tokens": 1024,
    },
}


class _RejectAllRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


_NO_PROXY_HANDLER = urllib.request.ProxyHandler({})
_NO_PROXY_OPENER = urllib.request.build_opener(
    _NO_PROXY_HANDLER,
    _RejectAllRedirects(),
)


class ProxyHTTPFailure(RuntimeError):
    """A body-free proxy HTTP status used only for categorical accounting."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"proxy HTTP {status_code}")


class ProjectionAwareOpenAIClient(OpenAIClient):
    """Retain only the validated Local Projection marker dropped by the benchmark normalizer."""

    capture_proxy_accounting = False

    def complete(self, payload: dict[str, Any], *, stream: bool = False) -> dict[str, Any]:
        if not self.capture_proxy_accounting:
            return super().complete(payload, stream=stream)
        if stream:
            raise PreflightFailure("proxy qualification requires non-streaming responses")
        body = dict(payload)
        body["stream"] = False
        request = self._request(body)
        started = time.perf_counter()
        try:
            with _NO_PROXY_OPENER.open(request, timeout=self.timeout_s) as response:  # noqa: S310
                if response.geturl() != request.full_url:
                    raise PreflightFailure("proxy qualification final URL differed")
                value = json.loads(_read_bounded_proxy_response(response).decode("utf-8"))
                if not isinstance(value, dict):
                    raise PreflightFailure("proxy response is malformed")
                accounting = (
                    {key: 0 for key in ("upstream_calls", "corrections", "blocked_duplicates", "blocked_stalls")}
                    if _canonical_local_projection_marker(value) is not None
                    else _proxy_accounting_from_headers(response.headers)
                )
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                raise PreflightFailure("proxy qualification redirect rejected") from None
            raise ProxyHTTPFailure(error.code) from None
        except PreflightFailure:
            raise
        except TimeoutError:
            raise TimeoutError("proxy request deadline exceeded") from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise TimeoutError("proxy request deadline exceeded") from None
            raise ConnectionError("proxy transport failed") from None
        except OSError:
            raise ConnectionError("proxy transport failed") from None
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise PreflightFailure("proxy response is malformed") from None
        wall_s = time.perf_counter() - started
        try:
            normalized = self._normalize(value, wall_s=wall_s, ttft_s=value.pop("_ttft_s", None))
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            raise PreflightFailure("proxy response is malformed") from None
        normalized[PROXY_RESPONSE_ACCOUNTING] = accounting
        return normalized

    @staticmethod
    def _normalize(value: dict[str, Any], *, wall_s: float, ttft_s: float | None) -> dict[str, Any]:
        marker = _canonical_local_projection_marker(value)
        normalized = OpenAIClient._normalize(value, wall_s=wall_s, ttft_s=ttft_s)
        if marker is not None:
            normalized[LOCAL_PROJECTION_EXTENSION] = marker
        return normalized


def _proxy_accounting_from_headers(headers: Any) -> dict[str, int]:
    projected: dict[str, int] = {}
    names = {
        "upstream_calls": "X-Shiftedx-Upstream-Calls",
        "corrections": "X-Shiftedx-Corrections",
        "blocked_duplicates": "X-Shiftedx-Blocked-Duplicates",
        "blocked_stalls": "X-Shiftedx-Blocked-Stalls",
    }
    for key, name in names.items():
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            values = get_all(name) or []
        else:
            value = headers.get(name) if hasattr(headers, "get") else None
            values = [] if value is None else [value]
        if len(values) != 1 or not isinstance(values[0], str) or _CANONICAL_COUNTER.fullmatch(values[0]) is None:
            raise PreflightFailure("proxy response accounting is unavailable")
        projected[key] = int(values[0])
    return projected


def _read_bounded_proxy_response(response: Any) -> bytes:
    payload = response.read(_MAX_PROXY_RESPONSE_BYTES + 1)
    if not isinstance(payload, bytes):
        raise PreflightFailure("proxy response is malformed")
    if len(payload) > _MAX_PROXY_RESPONSE_BYTES:
        raise PreflightFailure("proxy response exceeded size limit")
    return payload


def request_payload(
    scenario: Any,
    *,
    model: str,
    proxy_policy: bool,
    cache_mode: str = "warm-prefix",
    sampler_profile: SamplerProfile = "corrected-parity-v1",
) -> dict[str, Any]:
    """Build the unchanged standard downstream Chat Completions contract."""
    sampler = _sampler_profile(sampler_profile)
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": scenario.prompt},
        ],
        "tools": scenario.tools,
        "tool_choice": "auto",
        **sampler,
        "response_format": response_format(scenario.case_id, scenario.final_keys, scenario.final_types),
    }
    if proxy_policy:
        payload["x-shiftedx-require-receipt"] = scenario.require_receipt
    if cache_mode == "bypass":
        payload["metadata"] = {"cache_mode": "bypass"}
    return payload


def cache_prime_payload(
    scenario: Any, *, model: str, arm: str, sampler_profile: SamplerProfile = "corrected-parity-v1"
) -> dict[str, Any]:
    """Build the exact first scored model-facing payload for warm-cache priming."""
    payload = request_payload(scenario, model=model, proxy_policy=False, sampler_profile=sampler_profile)
    if arm == "proxy":
        system = payload["messages"][0]
        content = system.get("content")
        if not isinstance(content, str) or HARNESS_SYSTEM_SUFFIX in content:
            raise PreflightFailure("cache prime harness system suffix is invalid")
        system["content"] = content + HARNESS_SYSTEM_SUFFIX
    phase = "acquisition" if payload.get("tools") else "terminal"
    return PhasePlanner().plan(payload, phase=phase)


def _sampler_profile(profile: SamplerProfile) -> dict[str, Any]:
    """Copy one immutable named sampler contract; caller values never override it."""

    try:
        return copy.deepcopy(_SAMPLER_PROFILES[profile])
    except KeyError as error:
        raise PreflightFailure("sampler profile is invalid") from error


def contract_fingerprints(
    payload: dict[str, Any], scenario_order: list[str], *, policy_delta: dict[str, bool]
) -> dict[str, Any]:
    """Return only safe downstream/model-facing fingerprints for a request contract."""
    downstream, model_facing = request_fingerprints(payload, scenario_order, policy_delta=policy_delta)
    return {
        "downstream": downstream.to_dict(),
        "model_facing": [fingerprint.to_dict() for fingerprint in model_facing],
    }


def contract_mismatches(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    """Compare serialized safe fingerprints while excluding declared policy deltas."""
    left_downstream = left["downstream"]
    right_downstream = right["downstream"]
    return _contract_mismatches(
        SafeFingerprint(left_downstream["boundary"], left_downstream["digest"], left_downstream["fields"]),
        SafeFingerprint(right_downstream["boundary"], right_downstream["digest"], right_downstream["fields"]),
    )


def assert_preflight(observations: list[PreflightObservation]) -> None:
    """Expose the fail-closed preflight seam used by runner tests."""
    _assert_preflight(observations)


class ProxyRequestAccounting:
    """Accumulate one safe accounting row for each actual downstream proxy call."""

    def __init__(self) -> None:
        self._records: list[ProxyRequestRecord] = []

    @property
    def records(self) -> tuple[ProxyRequestRecord, ...]:
        return tuple(self._records)

    def record_success(
        self,
        response: dict[str, Any],
        observer_records: tuple[ModelBoundaryRecord, ...],
        *,
        local_projection: bool,
    ) -> None:
        accounting = _take_proxy_response_accounting(response)
        phases = [record.fields["compatibility"]["phase"] for record in observer_records]
        retry_count = len(observer_records) - len(set(phases))
        if (
            accounting["upstream_calls"] != len(observer_records)
            or accounting["corrections"] != retry_count
            or local_projection
            and (observer_records or any(accounting.values()))
        ):
            raise PreflightFailure("proxy response accounting differed")
        self._append(
            observer_records,
            outcome="succeeded",
            local_projection=local_projection,
            blocked_duplicates=accounting["blocked_duplicates"],
            blocked_stalls=accounting["blocked_stalls"],
        )

    def record_failure(self, observer_records: tuple[ModelBoundaryRecord, ...], error: BaseException) -> None:
        outcome: RequestOutcome
        if isinstance(error, asyncio.CancelledError):
            outcome = "cancelled"
        elif (
            isinstance(error, ProxyHTTPFailure)
            and error.status_code == 504
            or isinstance(error, TimeoutError)
            or isinstance(error, urllib.error.URLError)
            and isinstance(error.reason, TimeoutError)
        ):
            outcome = "deadline"
        else:
            outcome = "failed"
        self._append(
            observer_records,
            outcome=outcome,
            local_projection=False,
            blocked_duplicates=0,
            blocked_stalls=0,
        )

    def _append(
        self,
        observer_records: tuple[ModelBoundaryRecord, ...],
        *,
        outcome: RequestOutcome,
        local_projection: bool,
        blocked_duplicates: int,
        blocked_stalls: int,
    ) -> None:
        phases = [record.fields["compatibility"]["phase"] for record in observer_records]
        phase_counts = {
            "acquisition": phases.count("acquisition"),
            "finalization": phases.count("finalization"),
        }
        retry_count = len(observer_records) - len(set(phases))
        self._records.append(
            ProxyRequestRecord(
                sequence=len(self._records) + 1,
                outcome=outcome,
                local_projection=local_projection,
                attempt_sequence_start=observer_records[0].sequence if observer_records else None,
                attempt_sequence_end=observer_records[-1].sequence if observer_records else None,
                attempt_count=len(observer_records),
                successful_attempt_count=sum(
                    record.status_code is not None and 200 <= record.status_code < 300 for record in observer_records
                ),
                phase_counts=phase_counts,
                retry_attempt_count=retry_count,
                blocked_duplicate_count=blocked_duplicates,
                blocked_stall_count=blocked_stalls,
            )
        )


def _take_proxy_response_accounting(response: dict[str, Any]) -> dict[str, int]:
    value = response.pop(PROXY_RESPONSE_ACCOUNTING, None)
    keys = {"upstream_calls", "corrections", "blocked_duplicates", "blocked_stalls"}
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in value.values())
    ):
        raise PreflightFailure("proxy response accounting is unavailable")
    return value


class CompatibilityClient:
    """Apply the direct phase plan or consume actual proxy-boundary evidence per turn."""

    def __init__(
        self,
        upstream: Any,
        *,
        arm: str,
        scenario_order: list[str],
        proxy_policy: bool,
        observer: ModelBoundaryObserverCursor | None = None,
        require_cache_evidence: bool = False,
        request_accounting: ProxyRequestAccounting | None = None,
    ) -> None:
        self.upstream = upstream
        self.arm = arm
        self.scenario_order = scenario_order
        self.proxy_policy = proxy_policy
        self.observer = observer
        self.require_cache_evidence = require_cache_evidence
        self.request_accounting = request_accounting
        self.planner = PhasePlanner()
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        self.downstream_payloads: list[dict[str, Any]] = []
        self._direct_model_payloads: list[tuple[str, dict[str, Any]]] = []
        self._proxy_model_turns: list[tuple[SafeFingerprint, ...]] = []
        self._direct_attempt_records: list[ModelBoundaryRecord] = []

    @property
    def attempt_records(self) -> tuple[ModelBoundaryRecord, ...]:
        if self.arm == "direct":
            return tuple(self._direct_attempt_records)
        if self.observer is None:
            return ()
        return tuple(record for turn in self.observer.record_turns for record in turn)

    def complete(self, payload: dict[str, Any], *, stream: bool = False) -> dict[str, Any]:
        del stream  # Qualification is intentionally non-streaming.
        self.downstream_payloads.append(copy.deepcopy(payload))
        phases = self.planner.phases_for(payload)
        if self.arm == "proxy":
            return self._complete_proxy(payload, phases)
        if phases == ("terminal",):
            return self._complete_direct("terminal", payload)
        response = self._complete_direct("acquisition", self.planner.plan(payload, phase="acquisition"))
        if response.get("tool_calls"):
            return response
        return self._complete_direct("finalization", self.planner.plan(payload, phase="finalization"))

    def _complete_direct(self, phase: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._direct_model_payloads.append((phase, copy.deepcopy(payload)))
        sequence = len(self._direct_attempt_records) + 1
        try:
            response = self.upstream.complete(payload, stream=False)
        except Exception:
            self._direct_attempt_records.append(
                model_boundary_record(
                    payload,
                    sequence=sequence,
                    status_code=None,
                    response=None,
                )
            )
            raise
        record = model_boundary_record(
            payload,
            sequence=sequence,
            status_code=200,
            response=response,
        )
        self._direct_attempt_records.append(record)
        if not isinstance(response, dict):
            raise PreflightFailure("preflight_response_malformed")
        if self.require_cache_evidence and record.cache is None:
            raise PreflightFailure("model response cache evidence malformed")
        self.calls.append((phase, payload, response))
        return response

    def _complete_proxy(self, payload: dict[str, Any], phases: tuple[str, ...]) -> dict[str, Any]:
        prior_request_count = len(self.request_accounting.records) if self.request_accounting is not None else 0
        prior_turn_count = len(self.observer.record_turns) if self.observer is not None else 0
        records: tuple[ModelBoundaryRecord, ...] = ()
        call_started = False
        if self.observer is not None:
            self.observer.begin_turn()
        try:
            call_started = True
            response = self.upstream.complete(payload, stream=False)
            if not isinstance(response, dict):
                records = self._consume_proxy_observations(payload, require_records=True)
                raise PreflightFailure("preflight_response_malformed")
            local_projection = _is_local_projection(response)
            records = self._consume_proxy_observations(payload, require_records=not local_projection)
            if self.request_accounting is not None:
                self.request_accounting.record_success(
                    response,
                    records,
                    local_projection=local_projection,
                )
            self.calls.append((phases[-1], payload, response))
            return response
        except BaseException as error:
            if self.observer is not None and len(self.observer.record_turns) > prior_turn_count:
                records = self.observer.record_turns[-1]
            elif call_started:
                try:
                    records = self._consume_proxy_observations(payload, require_records=False)
                except BaseException:
                    if self.observer is not None and len(self.observer.record_turns) > prior_turn_count:
                        records = self.observer.record_turns[-1]
            if (
                call_started
                and self.request_accounting is not None
                and len(self.request_accounting.records) == prior_request_count
            ):
                self.request_accounting.record_failure(records, error)
            raise

    def _consume_proxy_observations(
        self, payload: dict[str, Any], *, require_records: bool
    ) -> tuple[ModelBoundaryRecord, ...]:
        if self.observer is None:
            return ()
        records = self.observer.consume_turn(require_records=require_records)
        self._proxy_model_turns.append(records)
        if self.require_cache_evidence and require_records:
            raw_records = self.observer.record_turns[-1]
            if any(record.status_code is None or record.cache is None for record in raw_records):
                raise PreflightFailure("proxy model-boundary response cache evidence malformed")
        self._validate_proxy_model_turn(payload, records)
        return self.observer.record_turns[-1]

    def _validate_proxy_model_turn(self, payload: dict[str, Any], records: tuple[SafeFingerprint, ...]) -> None:
        expected = tuple(
            (
                phase,
                model_boundary_fingerprint(self.planner.plan(payload, phase=phase), scenario_order=self.scenario_order),
            )
            for phase in self.planner.phases_for(payload)
        )
        matched_phases: list[int] = []
        for record in records:
            matching = [
                index
                for index, (_phase, expected_fingerprint) in enumerate(expected)
                if not _contract_mismatches(expected_fingerprint, record)
            ]
            if not matching:
                raise PreflightFailure("proxy model-boundary observer fields differed")
            matched_phases.append(matching[0])
        if matched_phases != sorted(matched_phases):
            raise PreflightFailure("proxy model-boundary observer order differed")

    def actual_contract_fingerprints(self) -> dict[str, Any]:
        """Return only actual sent/observed hash-only evidence, grouped in turn order."""
        if not self.downstream_payloads:
            return {"downstream": None, "model_facing": [], "model_facing_turns": []}
        policy_delta = {"x-shiftedx-require-receipt": True} if self.proxy_policy else {}
        downstream, _planned_model_facing = request_fingerprints(
            self.downstream_payloads[0], self.scenario_order, policy_delta=policy_delta
        )
        if self.arm == "direct":
            model_turns = tuple(
                (model_boundary_fingerprint(payload, scenario_order=self.scenario_order),)
                for _phase, payload in self._direct_model_payloads
            )
        else:
            model_turns = tuple(self._proxy_model_turns)
        model_facing = tuple(item for turn in model_turns for item in turn)
        return {
            "downstream": downstream.to_dict(),
            "model_facing": [fingerprint.to_dict() for fingerprint in model_facing],
            "model_facing_turns": [
                {
                    "turn_index": index,
                    "fingerprints": [fingerprint.to_dict() for fingerprint in turn],
                }
                for index, turn in enumerate(model_turns)
            ],
        }

    def observation(self, *, tool_required: bool, original_payload: dict[str, Any]) -> PreflightObservation:
        policy_delta = {"x-shiftedx-require-receipt": True} if self.proxy_policy and tool_required else {}
        downstream_payload = self.downstream_payloads[0] if self.downstream_payloads else original_payload
        downstream, planned_model_facing = request_fingerprints(
            downstream_payload, self.scenario_order, policy_delta=policy_delta
        )
        native_calls = sum(
            len(response.get("tool_calls") or [])
            for phase, _payload, response in self.calls
            if self.arm == "proxy" or phase == "acquisition"
        )
        terminal_response = self.calls[-1][2] if self.calls else {}
        model_facing = (
            tuple(
                model_boundary_fingerprint(payload, scenario_order=self.scenario_order)
                for _phase, payload in self._direct_model_payloads
            )
            if self.arm == "direct"
            else tuple(item for turn in self._proxy_model_turns for item in turn)
            if self.observer is not None
            else planned_model_facing
        )
        return PreflightObservation(
            arm=self.arm,  # type: ignore[arg-type]  # validated by the CLI construction
            tool_required=tool_required,
            native_acquisition_tool_calls=native_calls,
            phases=PhasePlanner().phases_for(original_payload),
            terminal_schema_valid=terminal_schema_valid(terminal_response, original_payload.get("response_format")),
            downstream=downstream,
            model_facing=model_facing,
        )


def _canonical_local_projection_marker(value: object) -> dict[str, Any] | None:
    """Return a copied marker only when it satisfies the shared exact accounting contract."""
    if not isinstance(value, dict):
        return None
    marker = value.get(LOCAL_PROJECTION_EXTENSION)
    if not isinstance(marker, dict) or marker.get("origin") != "local_projection":
        return None
    try:
        public_projection_summary([{LOCAL_PROJECTION_EXTENSION: marker}])
    except ValueError:
        return None
    return copy.deepcopy(marker)


def _is_local_projection(response: dict[str, Any]) -> bool:
    return _canonical_local_projection_marker(response) is not None


def _preflight_payload(
    scenario: Any,
    *,
    model: str,
    proxy_policy: bool,
    no_tools: bool,
    cache_mode: str = "warm-prefix",
    sampler_profile: SamplerProfile = "corrected-parity-v1",
) -> dict[str, Any]:
    payload = request_payload(
        scenario,
        model=model,
        proxy_policy=proxy_policy and not no_tools,
        cache_mode=cache_mode,
        sampler_profile=sampler_profile,
    )
    if no_tools:
        payload.pop("tools", None)
        payload.pop("tool_choice", None)
    return payload


def _run_preflight_path(client: CompatibilityClient, payload: dict[str, Any], *, tool_required: bool) -> None:
    response = client.complete(payload)
    calls = response.get("tool_calls") or []
    if tool_required and calls:
        messages = list(payload["messages"])
        messages.append({"role": "assistant", "content": response.get("content") or "", "tool_calls": calls})
        for index, call in enumerate(calls):
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id") or f"preflight-{index}",
                    "content": "synthetic preflight tool completed",
                }
            )
        continued = dict(payload)
        continued["messages"] = messages
        client.complete(continued)


def failure_row(
    *,
    scenario: Any,
    error: Exception,
    run_id: str,
    variant: str,
    agentic_set: str,
    model: str,
    scenario_order: list[str],
    proxy_policy: bool,
    wall_s: float,
    cache_mode: str = "warm-prefix",
    sampler_profile: SamplerProfile = "corrected-parity-v1",
    actual_contract_fingerprints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a prompt-free benchmark row when the client cannot return a response."""
    status_match = _HTTP_STATUS.search(str(error))
    status = int(status_match.group(1)) if status_match is not None else None
    error_label = "client request failed"
    if status is not None:
        error_label += f" with HTTP {status}"
    request_contract = {
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": scenario.prompt},
        ],
        "tools": scenario.tools,
        "agentic_control_profile": "baseline",
        "agentic_set": agentic_set,
    }
    request_hash = hashlib.sha256(
        json.dumps(
            request_contract,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "suite_id": "shiftedx-agentic-v1",
        "case_id": scenario.case_id,
        "lane": "agentic",
        "variant": variant,
        "passed": False,
        "score": 0.0,
        "score_max": 1.0,
        "error": error_label,
        "response": {
            "client_error": {
                "type": type(error).__name__,
                "http_status": status,
            }
        },
        "telemetry": {
            "tool_call_count": 0,
            "tool_calls": [],
            "dispatched_tool_call_count": 0,
            "dispatched_tool_calls": [],
            "blocked_duplicate_count": 0,
            "blocked_stall_count": 0,
            "terminal_correction_count": 0,
            "format_normalization_count": 0,
            "receipt_projection_count": 0,
            "harness_receipts": [],
            "turns": [],
            "wall_s": wall_s,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "ttft_s": None,
        },
        "metadata": {
            "max_turns": scenario.max_turns,
            "max_tool_calls": scenario.max_tool_calls,
            "agentic_control_profile": "baseline",
            "agentic_set": agentic_set,
            "agentic_family": scenario.family,
            "real_repo": scenario.real_repo,
            "forbidden_calls": sorted(scenario.forbidden_calls),
            "runner_failure_stage": "qualification_observer"
            if isinstance(error, PreflightFailure)
            else "benchmark_client",
        },
        "request_hash": request_hash,
        "scored": True,
        "contract_fingerprints": actual_contract_fingerprints
        if actual_contract_fingerprints is not None
        else contract_fingerprints(
            request_payload(
                scenario,
                model=model,
                proxy_policy=proxy_policy,
                cache_mode=cache_mode,
                sampler_profile=sampler_profile,
            ),
            scenario_order,
            policy_delta={"x-shiftedx-require-receipt": True} if proxy_policy else {},
        ),
    }


def append_failure(output: Path, row: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = (
        [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line]
        if output.exists()
        else []
    )
    # The benchmark writer may have emitted a current-case row before the observer rejected it.
    # Replace it with the fail-closed evidence row rather than leaving an unverified scored row.
    rows = [item for item in rows if item.get("case_id") != row.get("case_id")]
    rows.append(row)
    _atomic_replace_jsonl(output, rows)


def annotate_scored_rows(
    output: Path,
    client: CompatibilityClient,
    case_ids: set[str],
) -> None:
    """Attach hash-only evidence from the compatibility client's actual payloads."""
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line]
    for row in rows:
        if row.get("case_id") not in case_ids:
            continue
        row["scored"] = True
        row["contract_fingerprints"] = client.actual_contract_fingerprints()
    _atomic_replace_jsonl(output, rows)


def _atomic_replace_jsonl(output: Path, rows: list[dict[str, Any]]) -> None:
    """Atomically replace a live scored ledger without exposing a truncated prior file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(
                "".join(
                    json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for item in rows
                )
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def response_format(case_id: str, keys: tuple[str, ...] | None, types: dict[str, str]) -> dict[str, Any]:
    properties = {key: {"type": types[key]} for key in keys or ()}
    return {
        "type": "json_schema",
        "json_schema": {
            "name": f"shiftedx_{case_id}",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": properties,
                "required": list(properties),
                "additionalProperties": False,
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument(
        "--api-key-file",
        type=Path,
        default=None,
        help="Read the bearer credential from a private file; never place it in argv.",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--agentic-set", choices=("core", "expanded", "repo"), default="expanded")
    parser.add_argument("--variant", required=True)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--case-id", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--proxy-policy",
        action="store_true",
        help="Send the proxy-only case receipt policy; never use this against a model server directly.",
    )
    parser.add_argument(
        "--preflight-ledger",
        type=Path,
        help="Passed paired-preflight ledger matching the exact source and image candidate.",
    )
    parser.add_argument("--candidate-source-commit")
    parser.add_argument("--candidate-image-digest")
    parser.add_argument(
        "--run-manifest-sha256",
        help="SHA-256 of the immutable approved run manifest carrying the exact model/runtime identity.",
    )
    parser.add_argument(
        "--paired-preflight",
        action="store_true",
        help="Run unscored synthetic tool/no-tool paths through direct and proxy arms, then write a safe ledger.",
    )
    parser.add_argument("--direct-base-url")
    parser.add_argument("--proxy-base-url")
    parser.add_argument("--direct-api-key-file", type=Path)
    parser.add_argument("--proxy-api-key-file", type=Path)
    parser.add_argument(
        "--proxy-metrics-url",
        help="Authenticated proxy /metrics URL used only to verify aggregate phase deltas during preflight.",
    )
    parser.add_argument(
        "--proxy-observer-ledger",
        type=Path,
        help="Fresh hash-only ledger from a transparent proxy-to-model qualification observer.",
    )
    parser.add_argument(
        "--proxy-request-ledger",
        type=Path,
        help="Fresh safe per-downstream-call accounting ledger for proxy reconciliation.",
    )
    parser.add_argument(
        "--runtime-attestation",
        type=Path,
        help="Supervisor-issued allowlisted runtime evidence bound to this exact qualification invocation.",
    )
    parser.add_argument(
        "--preflight-runtime-outcome",
        type=Path,
        help="Passed supervisor outcome bound to the exact preflight attestation and ledger.",
    )
    parser.add_argument(
        "--direct-runtime-outcome",
        type=Path,
        help="Passed direct-treatment outcome required before proxy scoring.",
    )
    parser.add_argument(
        "--cache-mode",
        choices=("bypass", "warm-prefix"),
        default="warm-prefix",
        help="Use deterministic session-cache bypass or the normal primed-prefix lane.",
    )
    parser.add_argument(
        "--sampler-profile",
        choices=tuple(_SAMPLER_PROFILES),
        default="corrected-parity-v1",
        help="Use one immutable named sampler contract; individual sampler overrides are not accepted.",
    )
    parser.add_argument("--direct-model-attempt-ledger", type=Path)
    parser.add_argument("--model-attempt-ledger", type=Path)
    parser.add_argument("--cache-prime-only", action="store_true")
    parser.add_argument("--cache-prime-arm", choices=("direct", "proxy"))
    args = parser.parse_args()

    selected = scenario_set(args.agentic_set)
    if args.case_id is not None:
        selected = [scenario for scenario in selected if scenario.case_id == args.case_id]
        if not selected:
            raise SystemExit(f"unknown case: {args.case_id}")
    if args.limit is not None:
        selected = selected[: args.limit]

    if args.cache_prime_only:
        _run_cache_prime(args, selected)
        return

    if args.paired_preflight:
        if args.direct_model_attempt_ledger is None:
            raise SystemExit("--paired-preflight requires --direct-model-attempt-ledger")
        _require_fresh_attempt_path(args.direct_model_attempt_ledger)
        if args.proxy_request_ledger is None:
            raise SystemExit("--paired-preflight requires --proxy-request-ledger")
        _require_fresh_proxy_request_path(args.proxy_request_ledger)
        _run_paired_preflight(args, selected)
        return
    if args.base_url is None:
        raise SystemExit("--base-url is required for scored mode")
    if (
        args.preflight_ledger is None
        or args.candidate_source_commit is None
        or args.candidate_image_digest is None
        or args.run_manifest_sha256 is None
        or args.runtime_attestation is None
        or args.preflight_runtime_outcome is None
    ):
        raise SystemExit(
            "scored mode requires --preflight-ledger, --candidate-source-commit, --candidate-image-digest, "
            "--run-manifest-sha256, --runtime-attestation, and --preflight-runtime-outcome"
        )
    if args.proxy_policy and args.direct_runtime_outcome is None:
        raise SystemExit("scored proxy mode requires --direct-runtime-outcome")
    if args.proxy_policy and args.proxy_observer_ledger is None:
        raise SystemExit("scored proxy mode requires --proxy-observer-ledger")
    if args.proxy_policy and args.proxy_request_ledger is None:
        raise SystemExit("scored proxy mode requires --proxy-request-ledger")
    if args.proxy_policy:
        _require_fresh_proxy_request_path(args.proxy_request_ledger)
    if not args.proxy_policy and args.direct_model_attempt_ledger is None:
        raise SystemExit("scored direct mode requires --direct-model-attempt-ledger")
    if not args.proxy_policy:
        _require_fresh_attempt_path(args.direct_model_attempt_ledger)
    try:
        validate_run_manifest_sha256(args.run_manifest_sha256)
    except PreflightFailure as error:
        raise SystemExit("--run-manifest-sha256 must be an immutable SHA-256") from error
    require_scoring_gate(
        output=args.output,
        preflight_ledger=args.preflight_ledger,
        candidate_source_commit=args.candidate_source_commit,
        candidate_image_digest=args.candidate_image_digest,
        contract_digest=qualification_contract_digest(
            [
                request_payload(
                    item,
                    model=args.model,
                    proxy_policy=args.proxy_policy,
                    cache_mode=args.cache_mode,
                    sampler_profile=args.sampler_profile,
                )
                for item in selected
            ],
            [item.case_id for item in selected],
            policy_delta={"x-shiftedx-require-receipt": True} if args.proxy_policy else {},
            run_manifest_sha256=args.run_manifest_sha256,
        ),
        arm="proxy" if args.proxy_policy else "direct",
        cache_lane="cold" if args.cache_mode == "bypass" else "warm-prefix",
        model=args.model,
        run_manifest_sha256=args.run_manifest_sha256,
        scenario_order=[item.case_id for item in selected],
        runtime_attestation=args.runtime_attestation,
        preflight_runtime_outcome=args.preflight_runtime_outcome,
        direct_runtime_outcome=args.direct_runtime_outcome,
    )
    api_key = _read_key(args.api_key_file)
    client = ProjectionAwareOpenAIClient(args.base_url, api_key=api_key, timeout_s=600.0)
    client.capture_proxy_accounting = args.proxy_policy
    observer: ModelBoundaryObserverCursor | None = None
    if args.proxy_policy:
        try:
            observer = ModelBoundaryObserverCursor(args.proxy_observer_ledger, [item.case_id for item in selected])
        except PreflightFailure as error:
            raise SystemExit("scored proxy mode requires a fresh proxy model-boundary observer ledger") from error
    run_id = args.run_id or str(uuid.uuid4())
    direct_attempt_records: list[ModelBoundaryRecord] = []
    proxy_request_accounting = ProxyRequestAccounting() if args.proxy_policy else None
    for scenario in selected:
        overrides: dict[str, Any] = {
            **_sampler_profile(args.sampler_profile),
            "response_format": response_format(
                scenario.case_id,
                scenario.final_keys,
                scenario.final_types,
            ),
        }
        if args.proxy_policy:
            overrides["x-shiftedx-require-receipt"] = scenario.require_receipt
        if args.cache_mode == "bypass":
            overrides["metadata"] = {"cache_mode": "bypass"}
        started = time.perf_counter()
        planned_client: CompatibilityClient | None = None
        try:
            planned_client = CompatibilityClient(
                client,
                arm="proxy" if args.proxy_policy else "direct",
                scenario_order=[item.case_id for item in selected],
                proxy_policy=args.proxy_policy,
                observer=observer,
                require_cache_evidence=True,
                request_accounting=proxy_request_accounting,
            )
            rows = run_agentic_cases(
                client=planned_client,
                model=args.model,
                output_path=args.output,
                request_overrides=overrides,
                variant_label=args.variant,
                run_id=run_id,
                control_profile="baseline",
                agentic_set=args.agentic_set,
                case_id=scenario.case_id,
            )
            if observer is not None:
                observer.require_drained()
            annotate_scored_rows(
                args.output,
                planned_client,
                {str(row["case_id"]) for row in rows},
            )
        except asyncio.CancelledError:
            if proxy_request_accounting is not None:
                write_request_accounting_ledger(
                    args.proxy_request_ledger,
                    proxy_request_accounting.records,
                )
            raise
        except Exception as error:  # The failed case is evidence; later cases must still run.
            append_failure(
                args.output,
                failure_row(
                    scenario=scenario,
                    error=error,
                    run_id=run_id,
                    variant=args.variant,
                    agentic_set=args.agentic_set,
                    model=args.model,
                    scenario_order=[item.case_id for item in selected],
                    proxy_policy=args.proxy_policy,
                    wall_s=time.perf_counter() - started,
                    cache_mode=args.cache_mode,
                    sampler_profile=args.sampler_profile,
                    actual_contract_fingerprints=(
                        planned_client.actual_contract_fingerprints() if planned_client is not None else None
                    ),
                ),
            )
        finally:
            if planned_client is not None and not args.proxy_policy:
                direct_attempt_records.extend(planned_client.attempt_records)
    if not args.proxy_policy:
        write_model_boundary_attempt_ledger(
            args.direct_model_attempt_ledger,
            direct_attempt_records,
        )
    elif proxy_request_accounting is not None:
        write_request_accounting_ledger(args.proxy_request_ledger, proxy_request_accounting.records)


def _run_cache_prime(args: argparse.Namespace, selected: list[Any]) -> None:
    if args.cache_mode != "warm-prefix":
        raise SystemExit("--cache-prime-only requires --cache-mode warm-prefix")
    if not args.base_url or args.cache_prime_arm is None or args.model_attempt_ledger is None:
        raise SystemExit("--cache-prime-only requires --base-url, --cache-prime-arm, and --model-attempt-ledger")
    if not selected:
        raise SystemExit("--cache-prime-only requires at least one frozen scenario")
    _require_fresh_attempt_path(args.model_attempt_ledger)
    api_key = _read_key(args.api_key_file)
    client = ProjectionAwareOpenAIClient(args.base_url, api_key=api_key, timeout_s=600.0)
    payload = cache_prime_payload(
        selected[0], model=args.model, arm=args.cache_prime_arm, sampler_profile=args.sampler_profile
    )
    try:
        response = client.complete(payload, stream=False)
    except Exception as error:
        write_model_boundary_attempt_ledger(
            args.model_attempt_ledger,
            [model_boundary_record(payload, sequence=1, status_code=None, response=None)],
        )
        raise SystemExit("cache prime model attempt failed") from error
    record = model_boundary_record(payload, sequence=1, status_code=200, response=response)
    write_model_boundary_attempt_ledger(args.model_attempt_ledger, [record])
    if record.cache is None:
        raise SystemExit("cache prime response cache evidence is malformed")


def _require_fresh_attempt_path(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise SystemExit("refusing to overwrite an existing model-attempt ledger")


def _require_fresh_proxy_request_path(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise SystemExit("refusing to overwrite an existing proxy request ledger")


def _read_key(path: Path | None) -> str | None:
    if path is None:
        return None
    descriptor: int | None = None
    try:
        file_status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(file_status.st_mode) or stat.S_IMODE(file_status.st_mode) != 0o600:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened_status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or stat.S_IMODE(opened_status.st_mode) != 0o600
            or (opened_status.st_dev, opened_status.st_ino) != (file_status.st_dev, file_status.st_ino)
        ):
            raise OSError
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = None
            value = handle.read().strip()
    except (OSError, UnicodeDecodeError) as error:
        raise SystemExit("credential file must be a private mode-0600 regular file") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not value:
        raise SystemExit("credential file must contain a non-empty bearer credential")
    return value


def _run_paired_preflight(args: argparse.Namespace, selected: list[Any]) -> None:
    if (
        not args.direct_base_url
        or not args.proxy_base_url
        or not args.proxy_metrics_url
        or args.proxy_observer_ledger is None
    ):
        raise SystemExit(
            "--paired-preflight requires --direct-base-url, --proxy-base-url, --proxy-metrics-url, and "
            "--proxy-observer-ledger"
        )
    if not args.candidate_source_commit or not args.candidate_image_digest or not args.run_manifest_sha256:
        raise SystemExit(
            "--paired-preflight requires exact --candidate-source-commit, --candidate-image-digest, and "
            "--run-manifest-sha256"
        )
    try:
        validate_run_manifest_sha256(args.run_manifest_sha256)
    except PreflightFailure as error:
        raise SystemExit("--run-manifest-sha256 must be an immutable SHA-256") from error
    require_candidate_provenance(args.candidate_source_commit, args.candidate_image_digest)
    if args.output.exists():
        raise SystemExit("refusing to overwrite an existing preflight ledger; select a new output path")
    tool_scenario = next((item for item in selected if item.tools), None)
    if tool_scenario is None:
        raise SystemExit("selected agentic set has no tool-required scenario for preflight")
    scenario_order = [item.case_id for item in selected]
    sampler_profile = getattr(args, "sampler_profile", "corrected-parity-v1")
    contract_digests = _qualification_contract_digests(
        args.model,
        selected,
        scenario_order,
        args.run_manifest_sha256,
        sampler_profile,
    )
    runtime_attestation: RuntimeAttestation | None = None
    try:
        if args.runtime_attestation is None:
            raise RuntimeAttestationFailure("runtime_attestation_invalid")
        runtime_attestation = load_runtime_attestation(
            args.runtime_attestation,
            expected_stage="preflight",
            source_commit=args.candidate_source_commit,
            image_digest=args.candidate_image_digest,
            run_manifest_sha256=args.run_manifest_sha256,
            model=args.model,
            scenario_order=scenario_order,
        )
    except RuntimeAttestationFailure:
        _record_failed_preflight(
            args,
            [],
            contract_digests,
            runtime_attestation=None,
            reason="runtime_attestation_invalid",
        )
    observations: list[PreflightObservation] = []
    direct_attempt_records: list[ModelBoundaryRecord] = []
    proxy_request_accounting = ProxyRequestAccounting()
    try:
        observer = ModelBoundaryObserverCursor(args.proxy_observer_ledger, scenario_order)
        proxy_metrics_key = _read_key(args.proxy_api_key_file)
        metrics_before = _phase_metrics(args.proxy_metrics_url, proxy_metrics_key)
        for arm, base_url, api_key, proxy_policy in (
            ("direct", args.direct_base_url, _read_key(args.direct_api_key_file), False),
            ("proxy", args.proxy_base_url, proxy_metrics_key, True),
        ):
            tool_upstream = ProjectionAwareOpenAIClient(base_url, api_key=api_key, timeout_s=600.0)
            tool_upstream.capture_proxy_accounting = arm == "proxy"
            tool_client = CompatibilityClient(
                tool_upstream,
                arm=arm,
                scenario_order=scenario_order,
                proxy_policy=proxy_policy,
                observer=observer if arm == "proxy" else None,
                require_cache_evidence=getattr(args, "direct_model_attempt_ledger", None) is not None or arm == "proxy",
                request_accounting=proxy_request_accounting if arm == "proxy" else None,
            )
            tool_payload = _preflight_payload(
                tool_scenario,
                model=args.model,
                proxy_policy=proxy_policy,
                no_tools=False,
                cache_mode=getattr(args, "cache_mode", "warm-prefix"),
                sampler_profile=sampler_profile,
            )
            try:
                _run_preflight_path(tool_client, tool_payload, tool_required=True)
            finally:
                observations.append(tool_client.observation(tool_required=True, original_payload=tool_payload))
                if arm == "direct":
                    direct_attempt_records.extend(tool_client.attempt_records)

            terminal_upstream = ProjectionAwareOpenAIClient(base_url, api_key=api_key, timeout_s=600.0)
            terminal_upstream.capture_proxy_accounting = arm == "proxy"
            terminal_client = CompatibilityClient(
                terminal_upstream,
                arm=arm,
                scenario_order=scenario_order,
                proxy_policy=False,
                observer=observer if arm == "proxy" else None,
                require_cache_evidence=getattr(args, "direct_model_attempt_ledger", None) is not None or arm == "proxy",
                request_accounting=proxy_request_accounting if arm == "proxy" else None,
            )
            terminal_payload = _preflight_payload(
                tool_scenario,
                model=args.model,
                proxy_policy=False,
                no_tools=True,
                cache_mode=getattr(args, "cache_mode", "warm-prefix"),
                sampler_profile=sampler_profile,
            )
            try:
                _run_preflight_path(terminal_client, terminal_payload, tool_required=False)
            finally:
                observations.append(terminal_client.observation(tool_required=False, original_payload=terminal_payload))
                if arm == "direct":
                    direct_attempt_records.extend(terminal_client.attempt_records)
        metrics_after = _phase_metrics(args.proxy_metrics_url, proxy_metrics_key)
        proxy_delta = {key: metrics_after[key] - metrics_before[key] for key in metrics_before}
        observer.require_drained()
        observations = [
            replace(observation, proxy_phase_counts=proxy_delta)
            if observation.arm == "proxy" and observation.tool_required
            else observation
            for observation in observations
        ]
        _assert_preflight(observations)
    except Exception as error:
        _write_direct_attempt_records(args, direct_attempt_records)
        _write_proxy_request_records(args, proxy_request_accounting)
        _record_failed_preflight(
            args,
            observations,
            contract_digests,
            runtime_attestation=runtime_attestation,
            reason=_preflight_failure_reason(error),
        )
    _write_direct_attempt_records(args, direct_attempt_records)
    _write_proxy_request_records(args, proxy_request_accounting)
    try:
        write_preflight_ledger(
            args.output,
            observations,
            source_commit=args.candidate_source_commit,
            image_digest=args.candidate_image_digest,
            contract_digests=contract_digests,
            run_manifest_sha256=args.run_manifest_sha256,
            runtime_attestation=runtime_attestation,
        )
    except PreflightFailure as error:
        raise SystemExit("paired preflight failed before scored output: preflight_evidence_write_failed") from error


def _qualification_contract_digests(
    model: str,
    selected: list[Any],
    scenario_order: list[str],
    run_manifest_sha256: str,
    sampler_profile: SamplerProfile = "corrected-parity-v1",
) -> dict[str, dict[str, str]]:
    return {
        lane: {
            arm: qualification_contract_digest(
                [
                    request_payload(
                        item,
                        model=model,
                        proxy_policy=arm == "proxy",
                        cache_mode="bypass" if lane == "cold" else "warm-prefix",
                        sampler_profile=sampler_profile,
                    )
                    for item in selected
                ],
                scenario_order,
                policy_delta={"x-shiftedx-require-receipt": True} if arm == "proxy" else {},
                run_manifest_sha256=run_manifest_sha256,
            )
            for arm in ("direct", "proxy")
        }
        for lane in ("cold", "warm-prefix")
    }


def _write_direct_attempt_records(args: argparse.Namespace, records: list[ModelBoundaryRecord]) -> None:
    path = getattr(args, "direct_model_attempt_ledger", None)
    if path is not None:
        write_model_boundary_attempt_ledger(path, records)


def _write_proxy_request_records(args: argparse.Namespace, accounting: ProxyRequestAccounting) -> None:
    path = getattr(args, "proxy_request_ledger", None)
    if path is not None:
        write_request_accounting_ledger(path, accounting.records)


def _record_failed_preflight(
    args: argparse.Namespace,
    observations: list[PreflightObservation],
    contract_digests: dict[str, dict[str, str]],
    *,
    runtime_attestation: RuntimeAttestation | None,
    reason: str,
) -> None:
    with suppress(PreflightFailure):
        write_preflight_ledger(
            args.output,
            observations,
            source_commit=args.candidate_source_commit,
            image_digest=args.candidate_image_digest,
            contract_digests=contract_digests,
            run_manifest_sha256=args.run_manifest_sha256,
            runtime_attestation=runtime_attestation,
            failure_reason=reason,
        )
    raise SystemExit(f"paired preflight failed before scored output: {reason}")


def _preflight_failure_reason(error: Exception) -> str:
    if isinstance(error, RuntimeAttestationFailure):
        return "runtime_attestation_invalid"
    if isinstance(error, PreflightFailure):
        known = {
            "proxy_phase_metrics_unavailable",
            "proxy_phase_metrics_malformed",
            "preflight_response_malformed",
        }
        if str(error) in known:
            return str(error)
        if "observer" in str(error):
            return "proxy_model_boundary_observer_failed"
        return "preflight_contract_validation_failed"
    if isinstance(error, TimeoutError):
        return "preflight_timeout"
    if isinstance(error, urllib.error.HTTPError | urllib.error.URLError | ConnectionError | OSError):
        return "preflight_transport_failure"
    if isinstance(error, json.JSONDecodeError | TypeError | ValueError):
        return "preflight_malformed_response"
    return "preflight_client_failure"


def _phase_metrics(url: str, api_key: str | None) -> dict[str, int]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - operator-supplied private endpoint
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - operator-supplied private endpoint
            body = response.read().decode("utf-8", errors="replace")
    except Exception as error:
        raise PreflightFailure("proxy_phase_metrics_unavailable") from error
    values: dict[str, int] = {}
    for name in ("acquisition", "finalization"):
        match = re.search(rf"^shiftedx_proxy_phase_{name}_total ([0-9]+(?:\\.[0-9]+)?)$", body, re.MULTILINE)
        if match is None:
            raise PreflightFailure("proxy_phase_metrics_malformed")
        values[name] = int(float(match.group(1)))
    return values


if __name__ == "__main__":
    main()
