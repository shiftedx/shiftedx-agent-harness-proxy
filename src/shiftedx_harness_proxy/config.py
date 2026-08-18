"""Process-fixed configuration and secret loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .core import HARNESS_PROFILE, ToolRoles


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        secrets_dir="/run/secrets" if Path("/run/secrets").is_dir() else None,
        extra="ignore",
    )

    upstream_base_url: str
    upstream_api_key: SecretStr | None = None
    proxy_api_key: SecretStr | None = None
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
    return ToolRoles(
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


def _role_names(section: dict[str, Any], key: str, default: frozenset[str]) -> frozenset[str]:
    value = section.get(key)
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"Harness YAML roles.{key} must be a list of tool names")
    return frozenset(value)
