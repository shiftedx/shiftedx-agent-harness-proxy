#!/usr/bin/env python3
"""Run one schema-aware Shiftedx agentic trial without modifying the benchmark source."""

from __future__ import annotations

import argparse
import uuid
from pathlib import Path
from typing import Any

from shiftedx_bench.agentic import run_agentic_cases, scenario_set
from shiftedx_bench.api import OpenAIClient


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

    client = OpenAIClient(args.base_url, timeout_s=600.0)
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


if __name__ == "__main__":
    main()
