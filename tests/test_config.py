from pathlib import Path

import pytest
from pydantic import ValidationError

from shiftedx_harness_proxy.config import Settings, configured_roles


def test_upstream_url_is_process_fixed_and_rejects_embedded_credentials() -> None:
    settings = Settings(upstream_base_url="http://model:8000/v1")
    assert settings.upstream_url("chat/completions") == "http://model:8000/v1/chat/completions"
    with pytest.raises(ValidationError):
        Settings(upstream_base_url="http://secret@model:8000/v1")


def test_production_profile_requires_nonempty_well_formed_proxy_credentials() -> None:
    with pytest.raises(ValidationError, match="requires PROXY_API_KEY"):
        Settings(upstream_base_url="http://model:8000/v1", deployment_profile="production")
    with pytest.raises(ValidationError, match="non-empty visible ASCII bearer token"):
        Settings(
            upstream_base_url="http://model:8000/v1",
            deployment_profile="production",
            proxy_api_key="",
        )
    with pytest.raises(ValidationError, match="visible ASCII bearer token"):
        Settings(
            upstream_base_url="http://model:8000/v1",
            deployment_profile="production",
            proxy_api_key="malformed token",
        )
    with pytest.raises(ValidationError, match="upstream_base_url"):
        Settings(deployment_profile="production", proxy_api_key="valid-token")


def test_production_profile_loads_file_mounted_proxy_credentials(tmp_path: Path) -> None:
    (tmp_path / "proxy_api_key").write_text("file-mounted-secret")
    settings = Settings(
        upstream_base_url="http://model:8000/v1",
        deployment_profile="production",
        _secrets_dir=tmp_path,
    )
    assert settings.proxy_api_key is not None
    assert settings.proxy_api_key.get_secret_value() == "file-mounted-secret"


def test_yaml_roles_load_and_environment_style_values_override(tmp_path: Path) -> None:
    config = tmp_path / "harness.yaml"
    config.write_text(
        "roles:\n  mutation: [deploy]\n  verification: [probe]\n  investigation: [inspect]\n"
    )
    roles = configured_roles(
        Settings(
            upstream_base_url="http://model/v1",
            harness_config_file=config,
            verification_tools="healthcheck, smoke",
        )
    )
    assert roles.mutation == {"deploy"}
    assert roles.verification == {"healthcheck", "smoke"}
    assert roles.investigation == {"inspect"}
