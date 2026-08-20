"""Process-fixed configuration and secret loading."""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cache_policy import CacheCapabilityMode, cache_namespace_field_names
from .core import HARNESS_PROFILE, ToolRoles
from .provider_capabilities import ToolResponseCapabilityMode

_HTTP_BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+={0,}")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        secrets_dir="/run/secrets" if Path("/run/secrets").is_dir() else None,
        extra="ignore",
        hide_input_in_errors=True,
    )

    deployment_profile: Literal["development", "production"] = "development"
    upstream_base_url: str
    upstream_api_key: SecretStr | None = None
    proxy_api_key: SecretStr | None = None
    listen_host: str = "0.0.0.0"  # noqa: S104 - container listener; Compose controls host exposure
    listen_port: int = Field(default=8090, ge=1, le=65535)
    trusted_policy_extension_api_keys: SecretStr | None = None
    upstream_cache_capability_mode: CacheCapabilityMode = "disabled"
    upstream_tool_response_capability_mode: ToolResponseCapabilityMode = "passthrough"
    upstream_cache_namespace_fields: str | None = None
    harness_profile: str = HARNESS_PROFILE
    harness_config_file: Path | None = None
    mutation_tools: str | None = None
    verification_tools: str | None = None
    investigation_tools: str | None = None
    max_internal_retries: int = Field(default=4, ge=0, le=20)
    max_upstream_calls: int = Field(default=7, ge=1, le=25)
    upstream_timeout_seconds: float = Field(default=120.0, gt=0, le=3600)
    max_request_bytes: int = Field(default=2_000_000, ge=1024, le=100_000_000)
    max_upstream_response_bytes: int = Field(default=10_000_000, ge=1024, le=500_000_000)
    server_connection_limit: int = Field(default=24, ge=1, le=100_000)
    server_backlog: int = Field(default=128, ge=1, le=100_000)
    admission_limit: int = Field(default=16, ge=1, le=10_000)
    admission_wait_seconds: float = Field(default=1.0, gt=0, le=60)
    total_request_deadline_seconds: float = Field(default=180.0, gt=0, le=3600)
    principal_budget_mode: Literal["authenticated", "global"] = "authenticated"
    principal_concurrency_limit: int = Field(default=4, ge=1, le=10_000)
    principal_rate_limit: int = Field(default=60, ge=1, le=100_000)
    principal_rate_window_seconds: float = Field(default=60.0, gt=0, le=3600)
    overload_retry_after_seconds: int = Field(default=1, ge=0, le=3600)
    concurrency_limit: int = Field(default=32, ge=1, le=10_000)
    concurrency_wait_seconds: float = Field(default=1.0, gt=0, le=60)
    telemetry_enabled: bool = False
    metrics_enabled: bool = True
    allow_harness_opt_out: bool = False
    log_level: str = "INFO"
    cors_allow_origins: str | None = None
    require_receipt_when_tools_present: bool = True

    @field_validator("upstream_base_url")
    @classmethod
    def validate_upstream_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("UPSTREAM_BASE_URL must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("UPSTREAM_BASE_URL cannot contain credentials, query, or fragment")
        return value.rstrip("/")

    @field_validator("harness_profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        if value != HARNESS_PROFILE:
            raise ValueError(f"Only HARNESS_PROFILE={HARNESS_PROFILE} is supported")
        return value

    @field_validator("proxy_api_key")
    @classmethod
    def validate_proxy_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        secret = value.get_secret_value()
        if not secret or any(not 33 <= ord(character) <= 126 for character in secret):
            raise ValueError("PROXY_API_KEY must be a non-empty visible ASCII bearer token")
        return value

    @field_validator("trusted_policy_extension_api_keys")
    @classmethod
    def validate_trusted_policy_extension_api_keys(
        cls, value: SecretStr | None
    ) -> SecretStr | None:
        if value is None:
            return None
        entries = [entry.strip() for entry in value.get_secret_value().split(",")]
        if not entries or any(not _HTTP_BEARER_TOKEN.fullmatch(entry) for entry in entries):
            raise ValueError(
                "TRUSTED_POLICY_EXTENSION_API_KEYS must contain non-empty HTTP-safe bearer tokens"
            )
        return value

    @field_validator("upstream_cache_namespace_fields")
    @classmethod
    def validate_upstream_cache_namespace_fields(cls, value: str | None) -> str | None:
        if value is not None:
            cache_namespace_field_names(value)
        return value

    @model_validator(mode="after")
    def validate_production_profile(self) -> Settings:
        if self.deployment_profile == "production" and self.proxy_api_key is None:
            raise ValueError("DEPLOYMENT_PROFILE=production requires PROXY_API_KEY")
        if self.server_connection_limit <= self.admission_limit:
            raise ValueError("SERVER_CONNECTION_LIMIT must exceed ADMISSION_LIMIT for management headroom")
        if self.proxy_api_key is not None and any(
            self.proxy_api_key.get_secret_value() == capability
            for capability in self.trusted_policy_extension_keys()
        ):
            raise ValueError(
                "TRUSTED_POLICY_EXTENSION_API_KEYS must not include the ordinary PROXY_API_KEY"
            )
        return self

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL is invalid")
        return level

    def upstream_url(self, endpoint: str) -> str:
        return f"{self.upstream_base_url}/{endpoint.lstrip('/')}"

    def allowed_origins(self) -> list[str]:
        return _csv(self.cors_allow_origins) if self.cors_allow_origins else []

    def trusted_policy_extension_keys(self) -> frozenset[str]:
        """Return opaque bearer capabilities authorized for policy extensions."""
        if self.trusted_policy_extension_api_keys is None:
            return frozenset()
        return frozenset(_csv(self.trusted_policy_extension_api_keys.get_secret_value()))

    def cache_namespace_fields(self) -> frozenset[str]:
        """Return the process-fixed normalized client namespace denylist."""
        return cache_namespace_field_names(self.upstream_cache_namespace_fields)

    def principal_budget_key(self, credential: str) -> str:
        """Return an opaque, process-derived budget key without retaining the credential."""
        key = (
            self.proxy_api_key.get_secret_value().encode()
            if self.proxy_api_key is not None
            else b"shiftedx-admission-development"
        )
        return hmac.new(key, credential.encode(), hashlib.sha256).hexdigest()


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def configured_roles(settings: Settings) -> ToolRoles:
    roles = ToolRoles()
    if settings.harness_config_file is not None:
        try:
            document = yaml.safe_load(settings.harness_config_file.read_text()) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError("Unable to read HARNESS_CONFIG_FILE") from exc
        if not isinstance(document, dict):
            raise ValueError("HARNESS_CONFIG_FILE must contain a YAML object")
        section = document.get("roles", document)
        if not isinstance(section, dict):
            raise ValueError("Harness YAML roles must be an object")
        roles = ToolRoles(
            mutation=_role_names(section, "mutation", roles.mutation),
            verification=_role_names(section, "verification", roles.verification),
            investigation=_role_names(section, "investigation", roles.investigation),
        )
    configured = ToolRoles(
        mutation=frozenset(_csv(settings.mutation_tools)) if settings.mutation_tools is not None else roles.mutation,
        verification=(
            frozenset(_csv(settings.verification_tools))
            if settings.verification_tools is not None
            else roles.verification
        ),
        investigation=(
            frozenset(_csv(settings.investigation_tools))
            if settings.investigation_tools is not None
            else roles.investigation
        ),
    )
    _validate_distinct_roles(configured)
    return configured


def _role_names(section: dict[str, Any], key: str, default: frozenset[str]) -> frozenset[str]:
    value = section.get(key)
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"Harness YAML roles.{key} must be a list of tool names")
    return frozenset(value)


def _validate_distinct_roles(roles: ToolRoles) -> None:
    assigned: set[str] = set()
    for names in (roles.mutation, roles.verification, roles.investigation):
        overlap = assigned & names
        if overlap:
            raise ValueError("Configured tool roles must assign each tool name to only one role")
        assigned.update(names)
