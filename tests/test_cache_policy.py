from typing import Any

import pytest

from shiftedx_harness_proxy.cache_policy import (
    ClientCacheNamespaceError,
    ServerCacheNamespace,
    cache_namespace_field_names,
    normalize_cache_field_name,
    reject_client_cache_namespaces,
)


@pytest.mark.parametrize(
    "field_name",
    [
        "cache_salt",
        "CacheSalt",
        "CACHE-SALT",
        "promptCacheKey",
        "PROMPT_CACHE_KEY",
        "cacheNamespace",
        "cache-key-version",
        "CACHE_PRINCIPAL_ID",
        "cacheHmacNamespace",
        "TenantId",
        "cache-tenant-id",
        "CACHEKEY",
        "promptCacheSalt",
    ],
)
@pytest.mark.parametrize("value", [None, False, 0, [], {}, "opaque-test-value"])
def test_cache_namespace_variants_are_rejected_regardless_of_value_type(
    field_name: str, value: Any
) -> None:
    with pytest.raises(ClientCacheNamespaceError):
        reject_client_cache_namespaces(
            {field_name: value},
            mode="disabled",
            denied_fields=cache_namespace_field_names(None),
        )


def test_configured_equivalents_use_the_same_normalization() -> None:
    denied_fields = cache_namespace_field_names("provider_cache_scope")
    assert normalize_cache_field_name("Provider-CacheScope") in denied_fields
    with pytest.raises(ClientCacheNamespaceError):
        reject_client_cache_namespaces(
            {"providerCacheScope": "opaque-test-value"},
            mode="unknown",
            denied_fields=denied_fields,
        )


def test_future_server_namespace_seam_never_authorizes_a_client_selected_field() -> None:
    namespace = ServerCacheNamespace("server-derived-opaque-value", "v1")
    assert "server-derived-opaque-value" not in repr(namespace)
    assert "v1" in repr(namespace)
    reject_client_cache_namespaces(
        {"vendor_extension": {"cache_salt": "nested-value"}},
        mode="disabled",
        denied_fields=cache_namespace_field_names(None),
        server_namespace=namespace,
    )
    with pytest.raises(ClientCacheNamespaceError):
        reject_client_cache_namespaces(
            {"cache_namespace": "client-selected-value"},
            mode="disabled",
            denied_fields=cache_namespace_field_names(None),
            server_namespace=namespace,
        )


def test_duplicate_normalized_top_level_spellings_reject_without_retaining_values() -> None:
    with pytest.raises(ClientCacheNamespaceError) as raised:
        reject_client_cache_namespaces(
            {"cache_salt": "first-opaque-value", "Cache-Salt": "second-opaque-value"},
            mode="disabled",
            denied_fields=cache_namespace_field_names(None),
        )
    assert raised.value.args == ()


def test_standard_openai_user_field_is_not_a_cache_namespace_control() -> None:
    reject_client_cache_namespaces(
        {"user": "compatible-client-value"},
        mode="disabled",
        denied_fields=cache_namespace_field_names(None),
    )
