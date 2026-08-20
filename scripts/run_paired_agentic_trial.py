#!/usr/bin/env python3
"""Run one schema-aware Shiftedx agentic trial without modifying the benchmark source."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import urllib.request
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from shiftedx_bench.agentic import run_agentic_cases, scenario_set
from shiftedx_bench.api import OpenAIClient

from shiftedx_harness_proxy.qualification_contract import (
    PhasePlanner,
    PreflightFailure,
    PreflightObservation,
    SafeFingerprint,
    assert_preflight,
    request_fingerprints,
    require_candidate_provenance,
    require_scoring_gate,
    terminal_schema_valid,
    write_preflight_ledger,
)
from shiftedx_harness_proxy.qualification_contract import (
    contract_mismatches as _contract_mismatches,
)

_SYSTEM_PROMPT = (
    "You are an autonomous coding agent in a deterministic sandbox. Use supplied tools, never invent "
    "results, recover from failures, verify completion, and obey the requested final JSON format."
)
_HTTP_STATUS = re.compile(r"\bHTTP ([1-5][0-9]{2})\b")


def request_payload(scenario: Any, *, model: str, proxy_policy: bool) -> dict[str, Any]:
    """Build the unchanged standard downstream Chat Completions contract."""
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": scenario.prompt},
        ],
        "tools": scenario.tools,
        "tool_choice": "auto",
        "temperature": 0.0,
        "top_p": 0.95,
        "top_k": 20,
        "thinking": {"enabled": True},
        "reasoning_effort": "medium",
        "max_tokens": 1024,
        "response_format": response_format(scenario.case_id, scenario.final_keys, scenario.final_types),
    }
    if proxy_policy:
        payload["x-shiftedx-require-receipt"] = scenario.require_receipt
    return payload


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


class CompatibilityClient:
    """Apply the one versioned plan directly, or observe its proxy equivalent.

    The direct arm must split calls itself.  The proxy arm keeps its standard
    combined downstream request and records the same planned model-facing
    phases; the proxy's aggregate phase counters validate that this plan was
    actually carried out during paired preflight.
    """

    def __init__(self, upstream: Any, *, arm: str, scenario_order: list[str], proxy_policy: bool) -> None:
        self.upstream = upstream
        self.arm = arm
        self.scenario_order = scenario_order
        self.proxy_policy = proxy_policy
        self.planner = PhasePlanner()
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    def complete(self, payload: dict[str, Any], *, stream: bool = False) -> dict[str, Any]:
        del stream  # Qualification is intentionally non-streaming.
        phases = self.planner.phases_for(payload)
        if self.arm == "proxy" or phases == ("terminal",):
            response = self.upstream.complete(payload, stream=False)
            self.calls.append((phases[-1], payload, response))
            return response
        acquisition = self.planner.plan(payload, phase="acquisition")
        response = self.upstream.complete(acquisition, stream=False)
        self.calls.append(("acquisition", acquisition, response))
        if response.get("tool_calls"):
            return response
        finalization = self.planner.plan(payload, phase="finalization")
        final_response = self.upstream.complete(finalization, stream=False)
        self.calls.append(("finalization", finalization, final_response))
        return final_response

    def observation(self, *, tool_required: bool, original_payload: dict[str, Any]) -> PreflightObservation:
        policy_delta = {"x-shiftedx-require-receipt": True} if self.proxy_policy and tool_required else {}
        downstream, planned_model_facing = request_fingerprints(
            original_payload, self.scenario_order, policy_delta=policy_delta
        )
        native_calls = sum(
            len(response.get("tool_calls") or [])
            for phase, _payload, response in self.calls
            if phase == "acquisition"
        )
        terminal_response = self.calls[-1][2] if self.calls else {}
        phases = PhasePlanner().phases_for(original_payload)
        return PreflightObservation(
            arm=self.arm,  # type: ignore[arg-type]  # validated by the CLI construction
            tool_required=tool_required,
            native_acquisition_tool_calls=native_calls,
            phases=phases,
            terminal_schema_valid=terminal_schema_valid(terminal_response, original_payload.get("response_format")),
            downstream=downstream,
            model_facing=planned_model_facing,
        )


def _preflight_payload(scenario: Any, *, model: str, proxy_policy: bool, no_tools: bool) -> dict[str, Any]:
    payload = request_payload(scenario, model=model, proxy_policy=proxy_policy and not no_tools)
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
    wall_s: float,
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
            "runner_failure_stage": "benchmark_client",
        },
        "request_hash": request_hash,
        "scored": True,
        "contract_fingerprints": contract_fingerprints(
            request_payload(scenario, model=model, proxy_policy=variant == "proxy"),
            scenario_order,
            policy_delta={"x-shiftedx-require-receipt": True} if variant == "proxy" else {},
        ),
    }


def append_failure(output: Path, row: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        )


def annotate_scored_rows(
    output: Path,
    scenarios: list[Any],
    *,
    model: str,
    proxy_policy: bool,
) -> None:
    """Attach hash-only parity evidence to benchmark-private scored rows."""
    by_case = {scenario.case_id: scenario for scenario in scenarios}
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line]
    for row in rows:
        scenario = by_case.get(row.get("case_id"))
        if scenario is None:
            continue
        row["scored"] = True
        row["contract_fingerprints"] = contract_fingerprints(
            request_payload(scenario, model=model, proxy_policy=proxy_policy),
            [item.case_id for item in scenarios],
            policy_delta={"x-shiftedx-require-receipt": True} if proxy_policy else {},
        )
    output.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


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
    args = parser.parse_args()

    selected = scenario_set(args.agentic_set)
    if args.case_id is not None:
        selected = [scenario for scenario in selected if scenario.case_id == args.case_id]
        if not selected:
            raise SystemExit(f"unknown case: {args.case_id}")
    if args.limit is not None:
        selected = selected[: args.limit]

    if args.paired_preflight:
        _run_paired_preflight(args, selected)
        return
    if args.base_url is None:
        raise SystemExit("--base-url is required for scored mode")
    if (
        args.preflight_ledger is None
        or args.candidate_source_commit is None
        or args.candidate_image_digest is None
    ):
        raise SystemExit(
            "scored mode requires --preflight-ledger, --candidate-source-commit, and --candidate-image-digest"
        )
    require_scoring_gate(
        output=args.output,
        preflight_ledger=args.preflight_ledger,
        candidate_source_commit=args.candidate_source_commit,
        candidate_image_digest=args.candidate_image_digest,
    )
    api_key = args.api_key_file.read_text().strip() if args.api_key_file is not None else None
    if args.api_key_file is not None and not api_key:
        raise SystemExit("--api-key-file must contain a non-empty bearer credential")
    client = OpenAIClient(args.base_url, api_key=api_key, timeout_s=600.0)
    run_id = args.run_id or str(uuid.uuid4())
    for scenario in selected:
        overrides: dict[str, Any] = {
            "temperature": 0.0,
            "top_p": 0.95,
            "top_k": 20,
            "thinking": {"enabled": True},
            "reasoning_effort": "medium",
            "response_format": response_format(
                scenario.case_id,
                scenario.final_keys,
                scenario.final_types,
            ),
        }
        if args.proxy_policy:
            overrides["x-shiftedx-require-receipt"] = scenario.require_receipt
        started = time.perf_counter()
        try:
            planned_client = CompatibilityClient(
                client,
                arm="proxy" if args.proxy_policy else "direct",
                scenario_order=[item.case_id for item in selected],
                proxy_policy=args.proxy_policy,
            )
            run_agentic_cases(
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
            annotate_scored_rows(
                args.output,
                selected,
                model=args.model,
                proxy_policy=args.proxy_policy,
            )
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
                    wall_s=time.perf_counter() - started,
                ),
            )


def _read_key(path: Path | None) -> str | None:
    if path is None:
        return None
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SystemExit(f"{path.name} must contain a non-empty bearer credential")
    return value


def _run_paired_preflight(args: argparse.Namespace, selected: list[Any]) -> None:
    if not args.direct_base_url or not args.proxy_base_url or not args.proxy_metrics_url:
        raise SystemExit(
            "--paired-preflight requires --direct-base-url, --proxy-base-url, and --proxy-metrics-url"
        )
    if not args.candidate_source_commit or not args.candidate_image_digest:
        raise SystemExit("--paired-preflight requires exact --candidate-source-commit and --candidate-image-digest")
    require_candidate_provenance(args.candidate_source_commit, args.candidate_image_digest)
    tool_scenario = next((item for item in selected if item.tools), None)
    if tool_scenario is None:
        raise SystemExit("selected agentic set has no tool-required scenario for preflight")
    scenario_order = [item.case_id for item in selected]
    observations: list[PreflightObservation] = []
    proxy_metrics_key = _read_key(args.proxy_api_key_file)
    metrics_before = _phase_metrics(args.proxy_metrics_url, proxy_metrics_key)
    for arm, base_url, api_key, proxy_policy in (
        ("direct", args.direct_base_url, _read_key(args.direct_api_key_file), False),
        ("proxy", args.proxy_base_url, proxy_metrics_key, True),
    ):
        tool_client = CompatibilityClient(
            OpenAIClient(base_url, api_key=api_key, timeout_s=600.0),
            arm=arm,
            scenario_order=scenario_order,
            proxy_policy=proxy_policy,
        )
        tool_payload = _preflight_payload(tool_scenario, model=args.model, proxy_policy=proxy_policy, no_tools=False)
        _run_preflight_path(tool_client, tool_payload, tool_required=True)
        observations.append(tool_client.observation(tool_required=True, original_payload=tool_payload))

        terminal_client = CompatibilityClient(
            OpenAIClient(base_url, api_key=api_key, timeout_s=600.0),
            arm=arm,
            scenario_order=scenario_order,
            proxy_policy=False,
        )
        terminal_payload = _preflight_payload(tool_scenario, model=args.model, proxy_policy=False, no_tools=True)
        _run_preflight_path(terminal_client, terminal_payload, tool_required=False)
        observations.append(terminal_client.observation(tool_required=False, original_payload=terminal_payload))
    metrics_after = _phase_metrics(args.proxy_metrics_url, proxy_metrics_key)
    proxy_delta = {key: metrics_after[key] - metrics_before[key] for key in metrics_before}
    observations = [
        replace(observation, proxy_phase_counts=proxy_delta)
        if observation.arm == "proxy" and observation.tool_required
        else observation
        for observation in observations
    ]
    try:
        assert_preflight(observations)
        write_preflight_ledger(
            args.output,
            observations,
            source_commit=args.candidate_source_commit,
            image_digest=args.candidate_image_digest,
        )
    except PreflightFailure as error:
        raise SystemExit(f"paired preflight failed before scored output: {error}") from error


def _phase_metrics(url: str, api_key: str | None) -> dict[str, int]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - operator-supplied private endpoint
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - operator-supplied private endpoint
            body = response.read().decode("utf-8", errors="replace")
    except Exception as error:
        raise SystemExit("paired preflight could not read proxy phase counters") from error
    values: dict[str, int] = {}
    for name in ("acquisition", "finalization"):
        match = re.search(rf"^shiftedx_proxy_phase_{name}_total ([0-9]+(?:\\.[0-9]+)?)$", body, re.MULTILINE)
        if match is None:
            raise SystemExit("paired preflight could not parse proxy phase counters")
        values[name] = int(float(match.group(1)))
    return values


if __name__ == "__main__":
    main()
