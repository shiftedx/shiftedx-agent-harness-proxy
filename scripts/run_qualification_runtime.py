#!/usr/bin/env python3
"""Run the fixed paired qualification child through the private runtime supervisor."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from shiftedx_harness_proxy.qualification_runtime import (
    Outcome,
    RuntimeLease,
    supervise_qualification_runtime,
)


def paired_runner_argv(lease: RuntimeLease) -> tuple[str, ...]:
    """Derive the entire paired-runner child invocation from one supervisor lease."""

    runner = Path(__file__).with_name("run_paired_agentic_trial.py")
    common = [
        sys.executable,
        str(runner),
        "--model",
        lease.model,
        "--agentic-set",
        lease.agentic_set,
        "--output",
        str(lease.output_ledger),
        "--candidate-source-commit",
        lease.source_commit,
        "--candidate-image-digest",
        lease.image_digest,
        "--run-manifest-sha256",
        lease.run_manifest_sha256,
    ]
    if lease.stage == "preflight":
        _require_proxy_lease(lease)
        argv = [
            *common,
            "--paired-preflight",
            "--variant",
            "preflight",
            "--direct-base-url",
            lease.direct_base_url,
            "--proxy-base-url",
            lease.proxy_base_url,
            "--proxy-metrics-url",
            lease.proxy_metrics_url,
            "--proxy-observer-ledger",
            str(lease.observer_ledger),
            "--proxy-api-key-file",
            str(lease.proxy_api_key_file),
            "--runtime-attestation",
            str(lease.attestation_path),
        ]
        if lease.direct_api_key_file is not None:
            argv.extend(("--direct-api-key-file", str(lease.direct_api_key_file)))
        return tuple(argv)
    if lease.stage == "score-direct":
        _require_attestation(lease)
        argv = [
            *common,
            "--base-url",
            lease.direct_base_url,
            "--variant",
            "direct",
            "--preflight-ledger",
            str(lease.preflight_ledger),
            "--runtime-attestation",
            str(lease.attestation_path),
        ]
        if lease.direct_api_key_file is not None:
            argv.extend(("--api-key-file", str(lease.direct_api_key_file)))
        return tuple(argv)
    if lease.stage == "score-proxy":
        _require_proxy_lease(lease)
        argv = [
            *common,
            "--base-url",
            lease.proxy_base_url,
            "--variant",
            "proxy",
            "--proxy-policy",
            "--api-key-file",
            str(lease.proxy_api_key_file),
            "--proxy-observer-ledger",
            str(lease.observer_ledger),
            "--preflight-ledger",
            str(lease.preflight_ledger),
            "--runtime-attestation",
            str(lease.attestation_path),
        ]
        return tuple(argv)
    raise ValueError("unsupported qualification runtime stage")


def invoke_paired_runner(lease: RuntimeLease) -> int:
    """Run the child without injecting secret values into argv or environment."""

    return subprocess.run(list(paired_runner_argv(lease)), check=False).returncode  # noqa: S603


def main(
    argv: Sequence[str] | None = None,
    *,
    supervisor: Callable[..., Outcome] = supervise_qualification_runtime,
) -> int:
    """Accept only manifest/stage/private-directory inputs; runtime behavior has no overrides."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--stage", choices=("preflight", "score-direct", "score-proxy"), required=True)
    parser.add_argument("--private-run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    outcome = supervisor(
        manifest=args.manifest,
        stage=args.stage,
        private_run_dir=args.private_run_dir,
        action=invoke_paired_runner,
    )
    return 0 if outcome.status == "passed" else 1


def _require_proxy_lease(lease: RuntimeLease) -> None:
    if (
        lease.proxy_base_url is None
        or lease.proxy_metrics_url is None
        or lease.proxy_api_key_file is None
        or lease.observer_ledger is None
        or lease.attestation_path is None
    ):
        raise ValueError("proxy lease is incomplete")


def _require_attestation(lease: RuntimeLease) -> None:
    if lease.attestation_path is None:
        raise ValueError("runtime attestation is unavailable")


if __name__ == "__main__":
    raise SystemExit(main())
