"""Write auditable release-candidate facts without contacting a registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return f"sha256:{hashlib.file_digest(source, 'sha256').hexdigest()}"


def _base_digest(dockerfile: Path) -> str:
    match = re.search(r"^ARG PYTHON_IMAGE=.*@(sha256:[0-9a-f]{64})$", dockerfile.read_text(), re.MULTILINE)
    if match is None:
        raise ValueError("Dockerfile has no pinned PYTHON_IMAGE digest")
    return match.group(1)


def _image_digest(metadata: Path) -> str:
    value = json.loads(metadata.read_text()).get("containerimage.digest")
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("Buildx metadata has no containerimage.digest")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-reference", required=True)
    parser.add_argument("--release-platform", action="append", required=True)
    parser.add_argument("--release-metadata", type=Path, required=True)
    parser.add_argument("--smoke-reference", required=True)
    parser.add_argument("--smoke-architecture", required=True)
    parser.add_argument("--smoke-metadata", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    parser.add_argument("--workflow-url", required=True)
    args = parser.parse_args()

    document = {
        "schema_version": 1,
        "source_commit": args.source_commit,
        "release_candidate": {
            "reference": args.release_reference,
            "digest": _image_digest(args.release_metadata),
            "platforms": args.release_platform,
            "sbom": "embedded Buildx SBOM attestations in the OCI archive",
        },
        "smoke_scan_image": {
            "reference": args.smoke_reference,
            "digest": _image_digest(args.smoke_metadata),
            "architecture": args.smoke_architecture,
            "sbom": "artifacts/shiftedx-proxy-smoke-image.sbom.cdx.json",
        },
        "base_image_digest": _base_digest(args.dockerfile),
        "lock_digest": _sha256(args.lock),
        "workflow_url": args.workflow_url,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
