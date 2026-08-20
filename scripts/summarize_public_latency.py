#!/usr/bin/env python3
"""Project a private qualification timing ledger into aggregate-only JSON."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from shiftedx_harness_proxy.qualification_timing import TimingFailure, summarize_timing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timing-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = summarize_timing(args.timing_ledger)
        payload = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if not args.output.is_absolute() or args.output.parent.is_symlink():
            raise OSError
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (TimingFailure, OSError):
        raise SystemExit("qualification_timing_summary_failed") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
