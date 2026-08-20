#!/usr/bin/env python3
"""Run the fixed paired qualification child through the private runtime supervisor."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from shiftedx_harness_proxy.qualification_campaign import CampaignAdvance, advance_qualification_campaign
from shiftedx_harness_proxy.qualification_runtime import (
    QualificationCampaignReadinessProbe,
    QualificationCampaignStageRunner,
    RuntimeLease,
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
        "--run-id",
        lease.trial_run_id,
        "--candidate-source-commit",
        lease.source_commit,
        "--candidate-image-digest",
        lease.image_digest,
        "--run-manifest-sha256",
        lease.run_manifest_sha256,
        "--cache-mode",
        _cache_mode(lease),
    ]
    if lease.stage == "preflight":
        proxy_base_url, proxy_metrics_url, proxy_api_key_file, observer_ledger, attestation_path = _require_proxy_lease(
            lease
        )
        proxy_request_ledger = _require_proxy_request_ledger(lease)
        direct_attempt_ledger = _require_direct_attempt_ledger(lease)
        argv = [
            *common,
            "--paired-preflight",
            "--variant",
            _variant(lease, "preflight"),
            "--direct-base-url",
            lease.direct_base_url,
            "--proxy-base-url",
            proxy_base_url,
            "--proxy-metrics-url",
            proxy_metrics_url,
            "--proxy-observer-ledger",
            str(observer_ledger),
            "--proxy-request-ledger",
            str(proxy_request_ledger),
            "--direct-model-attempt-ledger",
            str(direct_attempt_ledger),
            "--proxy-api-key-file",
            str(proxy_api_key_file),
            "--runtime-attestation",
            str(attestation_path),
        ]
        if lease.direct_api_key_file is not None:
            argv.extend(("--direct-api-key-file", str(lease.direct_api_key_file)))
        return tuple(argv)
    if lease.stage == "score-direct":
        _require_attestation(lease)
        direct_attempt_ledger = _require_direct_attempt_ledger(lease)
        argv = [
            *common,
            "--base-url",
            lease.direct_base_url,
            "--variant",
            _variant(lease, "direct"),
            "--preflight-ledger",
            str(lease.preflight_ledger),
            "--runtime-attestation",
            str(lease.attestation_path),
            "--preflight-runtime-outcome",
            str(lease.preflight_ledger.with_name("preflight-runtime-outcome.json")),
            "--direct-model-attempt-ledger",
            str(direct_attempt_ledger),
        ]
        if lease.direct_api_key_file is not None:
            argv.extend(("--api-key-file", str(lease.direct_api_key_file)))
        return tuple(argv)
    if lease.stage == "score-proxy":
        (
            proxy_base_url,
            _proxy_metrics_url,
            proxy_api_key_file,
            observer_ledger,
            attestation_path,
        ) = _require_proxy_lease(lease)
        proxy_request_ledger = _require_proxy_request_ledger(lease)
        argv = [
            *common,
            "--base-url",
            proxy_base_url,
            "--variant",
            _variant(lease, "proxy"),
            "--proxy-policy",
            "--api-key-file",
            str(proxy_api_key_file),
            "--proxy-observer-ledger",
            str(observer_ledger),
            "--proxy-request-ledger",
            str(proxy_request_ledger),
            "--preflight-ledger",
            str(lease.preflight_ledger),
            "--runtime-attestation",
            str(attestation_path),
            "--preflight-runtime-outcome",
            str(lease.preflight_ledger.with_name("preflight-runtime-outcome.json")),
            "--direct-runtime-outcome",
            str(lease.output_ledger.with_name("scored-direct-runtime-outcome.json")),
        ]
        return tuple(argv)
    raise ValueError("unsupported qualification runtime stage")


def invoke_paired_runner(lease: RuntimeLease) -> int:
    """Run the child without injecting secret values into argv or environment."""

    if lease.cache_lane == "warm-prefix" and lease.stage in {"score-direct", "score-proxy"}:
        prime = _run_child(_prime_runner_argv(lease), lease)
        if prime != 0:
            return prime
    return _run_child(paired_runner_argv(lease), lease)


def _run_child(argv: tuple[str, ...], lease: RuntimeLease) -> int:
    return subprocess.run(  # noqa: S603 - argv and environment are derived exclusively from a validated lease
        list(argv),
        check=False,
        env={
            "PYTHONPATH": str(lease.benchmark_source_path),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    ).returncode


def _prime_runner_argv(lease: RuntimeLease) -> tuple[str, ...]:
    """Return the manifest-derived warm-prefix priming child for one scored arm."""

    if lease.stage not in {"score-direct", "score-proxy"}:
        raise ValueError("cache priming is only valid for scored treatments")
    prime_ledger = lease.prime_model_attempt_ledger
    if prime_ledger is None:
        raise ValueError("warm scored lease is missing its prime model-attempt ledger")
    arm = "direct" if lease.stage == "score-direct" else "proxy"
    runner = Path(__file__).with_name("run_paired_agentic_trial.py")
    argv = [
        sys.executable,
        str(runner),
        "--model",
        lease.model,
        "--agentic-set",
        lease.agentic_set,
        "--output",
        str(lease.output_ledger),
        "--run-id",
        lease.trial_run_id,
        "--candidate-source-commit",
        lease.source_commit,
        "--candidate-image-digest",
        lease.image_digest,
        "--run-manifest-sha256",
        lease.run_manifest_sha256,
        "--cache-mode",
        "warm-prefix",
        "--variant",
        _variant(lease, arm),
        "--base-url",
        lease.direct_base_url,
        "--cache-prime-only",
        "--cache-prime-arm",
        arm,
        "--model-attempt-ledger",
        str(prime_ledger),
    ]
    if lease.direct_api_key_file is not None:
        argv.extend(("--api-key-file", str(lease.direct_api_key_file)))
    return tuple(argv)


def _variant(lease: RuntimeLease, treatment: str) -> str:
    return f"{lease.cache_lane}-pair{lease.pair_index}-{treatment}-{lease.agentic_set}"


def _cache_mode(lease: RuntimeLease) -> str:
    if lease.stage == "preflight":
        return "bypass"
    return "bypass" if lease.cache_lane == "cold" else "warm-prefix"


def main(
    argv: Sequence[str] | None = None,
    *,
    campaign_advancer: Callable[..., CampaignAdvance] = advance_qualification_campaign,
) -> int:
    """Advance exactly one manifest-derived campaign stage without operator overrides."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--private-campaign-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.manifest.is_absolute():
        parser.error("--manifest must be an absolute path")
    if not args.private_campaign_dir.is_absolute():
        parser.error("--private-campaign-dir must be an absolute path")
    advance = campaign_advancer(
        args.manifest,
        args.private_campaign_dir,
        stage_runner=QualificationCampaignStageRunner(action=invoke_paired_runner),
        readiness_probe=QualificationCampaignReadinessProbe(),
    )
    if advance.kind in {"stage_completed", "campaign_passed"}:
        return 0
    return 2 if advance.kind == "restart_required" else 1


def _require_proxy_lease(lease: RuntimeLease) -> tuple[str, str, Path, Path, Path]:
    if (
        lease.proxy_base_url is None
        or lease.proxy_metrics_url is None
        or lease.proxy_api_key_file is None
        or lease.observer_ledger is None
        or lease.attestation_path is None
    ):
        raise ValueError("proxy lease is incomplete")
    return (
        lease.proxy_base_url,
        lease.proxy_metrics_url,
        lease.proxy_api_key_file,
        lease.observer_ledger,
        lease.attestation_path,
    )


def _require_attestation(lease: RuntimeLease) -> None:
    if lease.attestation_path is None:
        raise ValueError("runtime attestation is unavailable")


def _require_direct_attempt_ledger(lease: RuntimeLease) -> Path:
    if lease.direct_model_attempt_ledger is None:
        raise ValueError("lease is missing its direct model-attempt ledger")
    return lease.direct_model_attempt_ledger


def _require_proxy_request_ledger(lease: RuntimeLease) -> Path:
    if lease.proxy_request_ledger is None:
        raise ValueError("proxy lease is missing its request-accounting ledger")
    return lease.proxy_request_ledger


if __name__ == "__main__":
    raise SystemExit(main())
