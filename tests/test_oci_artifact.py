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
    "starlette": "starlette",
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


def test_release_compose_overlay_requires_an_exact_image_and_disables_build() -> None:
    overlay = (ROOT / "docker-compose.release.yml").read_text()
    assert 'image: "${PROXY_IMAGE:?Set PROXY_IMAGE to the exact approved image reference}"' in overlay
    assert "build: !reset null" in overlay


def test_compose_can_select_the_tested_phase_split_mode() -> None:
    compose = (ROOT / "docker-compose.yml").read_text()
    assert (
        'UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE: '
        '"${UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE:-passthrough}"'
    ) in compose


def test_ci_validates_the_merged_exact_image_compose_configuration() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "Validate exact-image Compose configuration" in workflow
    assert 'assert "build" not in proxy' in workflow
    assert 'assert proxy["image"] == expected_image' in workflow
    assert 'assert proxy["environment"]["UPSTREAM_TOOL_RESPONSE_CAPABILITY_MODE"] == "phase_split"' in workflow


def test_smoke_uses_the_production_profile_with_a_file_mounted_credential() -> None:
    smoke = (ROOT / "scripts/docker-smoke.sh").read_text()
    assert 'printf \'%s\' \'smoke-proxy-key\' >"$tmpdir/secrets/proxy_api_key"' in smoke
    assert '--mount "type=bind,src=$tmpdir/secrets,dst=/run/secrets,readonly"' in smoke
    assert '--publish "127.0.0.1:$proxy_port:8090"' in smoke
    assert "--env DEPLOYMENT_PROFILE=production" in smoke
    assert '--env "UPSTREAM_BASE_URL=http://host.docker.internal:$upstream_port/v1"' in smoke
    assert "grep --fixed-strings 'smoke-proxy-key'" in smoke


def test_ci_attests_the_oci_archive_but_can_load_the_smoke_image() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    release_build, smoke_build = workflow.split("      - name: Load amd64 image for hardened smoke and scanning\n")
    smoke_build, _ = smoke_build.split("      - name: Smoke loaded hardened image\n")
    assert "--platform linux/amd64,linux/arm64" in release_build
    assert "--provenance mode=max" in release_build
    assert "--sbom=true" in release_build
    assert "--platform linux/amd64" in smoke_build
    assert "--load" in smoke_build
    assert "--metadata-file artifacts/smoke-image-metadata.json" in smoke_build
    assert "--provenance" not in smoke_build
    assert "--sbom" not in smoke_build


def test_container_job_provisions_the_frozen_fake_upstream_runner() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    container_job = workflow.split("  container:\n", maxsplit=1)[1]
    setup, _ = container_job.split("      - uses: docker/setup-qemu-action", maxsplit=1)
    assert "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9" in setup
    assert "uv python install 3.11" in setup
    assert "uv lock --check" in setup
    assert "uv sync --frozen --extra dev --python 3.11" in setup


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
