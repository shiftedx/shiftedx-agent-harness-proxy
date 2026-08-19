#!/usr/bin/env python3
"""Run one schema-aware Shiftedx agentic trial without modifying the benchmark source."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from shiftedx_bench.agentic import run_agentic_cases, scenario_set
from shiftedx_bench.api import OpenAIClient

_SYSTEM_PROMPT = (
    "You are an autonomous coding agent in a deterministic sandbox. Use supplied tools, never invent "
    "results, recover from failures, verify completion, and obey the requested final JSON format."
)
_HTTP_STATUS = re.compile(r"\bHTTP ([1-5][0-9]{2})\b")


def failure_row(
    *,
    scenario: Any,
    error: Exception,
    run_id: str,
    variant: str,
    agentic_set: str,
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
    }


def append_failure(output: Path, row: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
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
    parser.add_argument("--base-url", required=True)
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
    args = parser.parse_args()

    selected = scenario_set(args.agentic_set)
    if args.case_id is not None:
        selected = [scenario for scenario in selected if scenario.case_id == args.case_id]
        if not selected:
            raise SystemExit(f"unknown case: {args.case_id}")
    if args.limit is not None:
        selected = selected[: args.limit]

    api_key = args.api_key_file.read_text().strip() if args.api_key_file is not None else None
    if args.api_key_file is not None and not api_key:
        raise SystemExit("--api-key-file must contain a non-empty bearer credential")
    client = OpenAIClient(args.base_url, api_key=api_key, timeout_s=600.0)
    run_id = args.run_id or str(uuid.uuid4())
    for scenario in selected:
        overrides: dict[str, Any] = {
            "temperature": 1.0,
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
            run_agentic_cases(
                client=client,
                model=args.model,
                output_path=args.output,
                request_overrides=overrides,
                variant_label=args.variant,
                run_id=run_id,
                control_profile="baseline",
                agentic_set=args.agentic_set,
                case_id=scenario.case_id,
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
                    wall_s=time.perf_counter() - started,
                ),
            )


if __name__ == "__main__":
    main()
