from shiftedx_harness_proxy.provider_capabilities import (
    COMBINED_CAPABILITY_SCHEMA_VERSION,
    COMBINED_TOOL_TERMINAL_CONTRACT_ID,
    combined_tool_terminal_schema_supported,
    requires_combined_capability,
    requires_phase_split,
)


def test_combined_capability_requires_the_exact_supported_contract_signal() -> None:
    assert combined_tool_terminal_schema_supported(
        {
            "schema_version": COMBINED_CAPABILITY_SCHEMA_VERSION,
            "runtime": {"name": "mtplx", "version": "2.9.0", "source_revision": "a" * 40},
            "features": {
                "combined_tool_terminal_schema": {
                    "supported": True,
                    "contract_id": COMBINED_TOOL_TERMINAL_CONTRACT_ID,
                }
            }
        }
    )


def test_combined_capability_fails_closed_for_missing_false_drifted_or_malformed_signals() -> None:
    documents = [
        {},
        {
            "schema_version": COMBINED_CAPABILITY_SCHEMA_VERSION,
            "runtime": {"name": "mtplx", "version": "2.9.0", "source_revision": "not-a-revision"},
            "features": {
                "combined_tool_terminal_schema": {
                    "supported": True,
                    "contract_id": COMBINED_TOOL_TERMINAL_CONTRACT_ID,
                }
            },
        },
        {"features": {}},
        {
            "features": {
                "combined_tool_terminal_schema": {
                    "supported": False,
                    "contract_id": COMBINED_TOOL_TERMINAL_CONTRACT_ID,
                }
            }
        },
        {
            "features": {
                "combined_tool_terminal_schema": {
                    "supported": True,
                    "contract_id": "native_tool_or_strict_json_schema:v2",
                }
            }
        },
        {"features": {"combined_tool_terminal_schema": "yes"}},
        {"features": []},
    ]

    assert not any(combined_tool_terminal_schema_supported(document) for document in documents)


def test_existing_modes_keep_their_own_translation_decisions() -> None:
    assert requires_phase_split(
        "phase_split",
        has_tools=True,
        has_response_format=True,
        strict_schema_supported=True,
    )
    assert not requires_phase_split(
        "combined_v1",
        has_tools=True,
        has_response_format=True,
        strict_schema_supported=True,
    )
    assert requires_combined_capability(
        "combined_v1", has_tools=True, has_response_format=True, strict_schema_supported=True
    )
    assert not requires_combined_capability(
        "passthrough", has_tools=True, has_response_format=True, strict_schema_supported=True
    )
    assert not requires_combined_capability(
        "combined_v1", has_tools=True, has_response_format=True, strict_schema_supported=False
    )
