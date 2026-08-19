from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

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


def test_policy_extension_capabilities_are_explicit_server_configuration() -> None:
    settings = Settings(
        upstream_base_url="http://model/v1",
        trusted_policy_extension_api_keys=SecretStr("extension-a, extension-b"),
    )
    assert settings.trusted_policy_extension_keys() == {"extension-a", "extension-b"}


def test_cache_capability_profiles_are_process_fixed_and_fail_closed() -> None:
    default = Settings(upstream_base_url="http://model/v1")
    unknown = Settings(
        upstream_base_url="http://model/v1",
        upstream_cache_capability_mode="unknown",
        upstream_cache_namespace_fields="provider_cache_scope",
    )
    assert default.upstream_cache_capability_mode == "disabled"
    assert unknown.upstream_cache_capability_mode == "unknown"
    assert "providercachescope" in unknown.cache_namespace_fields()


@pytest.mark.parametrize(
    "configured_fields",
    ["", "provider_cache_scope,,alternate_scope", "---"],
)
def test_cache_namespace_field_configuration_rejects_malformed_entries_without_echoing_input(
    configured_fields: str,
) -> None:
    with pytest.raises(ValidationError) as raised:
        Settings(
            upstream_base_url="http://model/v1",
            upstream_cache_namespace_fields=configured_fields,
        )
    assert "non-empty cache namespace field names" in str(raised.value)
    if configured_fields:
        assert configured_fields not in str(raised.value)


@pytest.mark.parametrize(
    "configured_capabilities",
    ["", "extension-a,,extension-b", "extension with space", "extension-a,second\nline"],
)
def test_policy_extension_capabilities_fail_closed_without_echoing_secret_values(
    configured_capabilities: str,
) -> None:
    with pytest.raises(ValidationError) as raised:
        Settings(
            upstream_base_url="http://model/v1",
            trusted_policy_extension_api_keys=SecretStr(configured_capabilities),
        )
    assert "HTTP-safe bearer tokens" in str(raised.value)
    if configured_capabilities:
        assert configured_capabilities not in str(raised.value)


def test_trusted_policy_extension_capability_must_be_distinct_from_ordinary_principal() -> None:
    ordinary_key = "ordinary-client-key"
    with pytest.raises(ValidationError) as raised:
        Settings(
            upstream_base_url="http://model/v1",
            deployment_profile="production",
            proxy_api_key=SecretStr(ordinary_key),
            trusted_policy_extension_api_keys=SecretStr(f"trusted-capability,{ordinary_key}"),
        )
    assert "must not include the ordinary PROXY_API_KEY" in str(raised.value)
    assert ordinary_key not in str(raised.value)


def test_production_profile_accepts_a_distinct_trusted_policy_extension_principal() -> None:
    settings = Settings(
        upstream_base_url="http://model/v1",
        deployment_profile="production",
        proxy_api_key=SecretStr("ordinary-client-key"),
        trusted_policy_extension_api_keys=SecretStr("trusted-capability"),
    )
    assert settings.proxy_api_key is not None
    assert settings.trusted_policy_extension_keys() == {"trusted-capability"}


def test_overlapping_server_role_configuration_fails_closed() -> None:
    with pytest.raises(ValueError, match="only one role"):
        configured_roles(
            Settings(
                upstream_base_url="http://model/v1",
                mutation_tools="deploy",
                verification_tools="deploy",
            )
        )
