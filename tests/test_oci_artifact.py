import ast
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]
IMPORT_TO_DISTRIBUTION = {
    "fastapi": "fastapi",
    "httpx": "httpx",
    "pydantic": "pydantic",
    "pydantic_settings": "pydantic-settings",
    "uvicorn": "uvicorn",
    "yaml": "pyyaml",
}


def test_runtime_imports_are_declared_dependencies() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    declared = {dependency.split("==", maxsplit=1)[0].lower() for dependency in project["project"]["dependencies"]}
    imports: set[str] = set()
    for source in (ROOT / "src").rglob("*.py"):
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
                imports.add(node.module.partition(".")[0])
    external = imports - sys.stdlib_module_names - {"shiftedx_harness_proxy"}
    assert {IMPORT_TO_DISTRIBUTION[name] for name in external} <= declared


def test_dockerfile_requires_the_checked_lockfile() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY pyproject.toml uv.lock README.md ./" in dockerfile
    assert "uv lock --check" in dockerfile
    assert "uv export --frozen --no-dev --no-emit-project" in dockerfile
    assert "uv sync --locked --no-dev --no-editable" in dockerfile


def test_release_manifest_distinguishes_release_candidate_from_smoke_image(tmp_path: Path) -> None:
    release_digest = "sha256:" + "a" * 64
    smoke_digest = "sha256:" + "b" * 64
    release_metadata = tmp_path / "multiarch-build-metadata.json"
    release_metadata.write_text(json.dumps({"containerimage.digest": release_digest}))
    smoke_metadata = tmp_path / "smoke-image-metadata.json"
    smoke_metadata.write_text(json.dumps({"containerimage.digest": smoke_digest}))
    output = tmp_path / "release-manifest.json"
    subprocess.run(  # noqa: S603 - fixed local script and test-controlled arguments
        [
            sys.executable,
            "scripts/release-manifest.py",
            "--output",
            str(output),
            "--source-commit",
            "f" * 40,
            "--release-reference",
            "oci-archive:artifacts/shiftedx-proxy.oci.tar",
            "--release-platform",
            "linux/amd64",
            "--release-platform",
            "linux/arm64",
            "--release-metadata",
            str(release_metadata),
            "--smoke-reference",
            "shiftedx-agent-harness-proxy:ci",
            "--smoke-architecture",
            "amd64",
            "--smoke-metadata",
            str(smoke_metadata),
            "--workflow-url",
            "https://github.example/actions/runs/1",
        ],
        check=True,
        cwd=ROOT,
    )
    manifest = json.loads(output.read_text())
    assert manifest["release_candidate"] == {
        "digest": release_digest,
        "platforms": ["linux/amd64", "linux/arm64"],
        "reference": "oci-archive:artifacts/shiftedx-proxy.oci.tar",
        "sbom": "embedded Buildx SBOM attestations in the OCI archive",
    }
    assert manifest["smoke_scan_image"] == {
        "architecture": "amd64",
        "digest": smoke_digest,
        "reference": "shiftedx-agent-harness-proxy:ci",
        "sbom": "artifacts/shiftedx-proxy-smoke-image.sbom.cdx.json",
    }
    assert manifest["lock_digest"].startswith("sha256:")
    assert manifest["base_image_digest"].startswith("sha256:")
