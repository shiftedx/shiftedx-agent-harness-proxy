#!/usr/bin/env python3
"""Write an allowlist-only public projection summary from private completion records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from shiftedx_harness_proxy.projection_accounting import public_projection_summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--completion-records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records: Any = json.loads(args.completion_records.read_text())
    if not isinstance(records, list):
        raise SystemExit("--completion-records must contain a JSON array")
    args.output.write_text(json.dumps(public_projection_summary(records), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
