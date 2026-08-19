"""Fail-closed cache-namespace policy for generic v1 upstreams."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

CacheCapabilityMode = Literal["disabled", "unknown"]
DEFAULT_CACHE_NAMESPACE_FIELDS = frozenset(
    {
        "cache_salt",
        "prompt_cache_key",
        "cache_namespace",
        "cache_namespace_key",
        "cache_key_version",
        "cache_principal_id",
        "cache_hmac_namespace",
        "tenant_id",
        "cache_tenant_id",
        "cache_key",
        "prompt_cache_salt",
    }
)


@dataclass(frozen=True)
class ServerCacheNamespace:
    """Reserved #10 authority supplied only by a future authentication adapter.

    ``opaque_hmac_namespace`` and ``key_version`` are deliberately not read from a
    request body or header. Generic v1 modes do not yet use this authority to add
    provider fields; they only reject client-selected namespace controls.
    """

    opaque_hmac_namespace: str = field(repr=False)
    key_version: str


class ClientCacheNamespaceError(ValueError):
    """Raised without retaining a client field name or value for public reporting."""


def normalize_cache_field_name(name: str) -> str:
    """Normalize case and separator variants without inspecting field values."""
    return "".join(character for character in name.casefold() if character.isalnum())


def cache_namespace_field_names(configured_fields: str | None) -> frozenset[str]:
    """Return normalized process-configured denylist entries."""
    configured: tuple[str, ...] = ()
    if configured_fields is not None:
        configured = tuple(normalize_cache_field_name(entry.strip()) for entry in configured_fields.split(","))
        if not configured or any(not entry for entry in configured):
            raise ValueError(
                "UPSTREAM_CACHE_NAMESPACE_FIELDS must contain non-empty cache namespace field names"
            )
    return frozenset(
        normalized
        for field in (*DEFAULT_CACHE_NAMESPACE_FIELDS, *configured)
        if (normalized := normalize_cache_field_name(field))
    )


def reject_client_cache_namespaces(
    payload: dict[str, Any],
    *,
    mode: CacheCapabilityMode,
    denied_fields: frozenset[str],
    server_namespace: ServerCacheNamespace | None = None,
) -> None:
    """Reject top-level client namespace controls for generic upstream profiles.

    The optional server-owned namespace is an internal seam for #10. It cannot
    authorize a request field in either currently supported generic mode.
    """
    del mode, server_namespace
    if any(normalize_cache_field_name(name) in denied_fields for name in payload):
        raise ClientCacheNamespaceError
