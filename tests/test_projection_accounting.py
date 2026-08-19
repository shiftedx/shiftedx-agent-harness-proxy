import json

import pytest

from shiftedx_harness_proxy.projection_accounting import (
    LOCAL_PROJECTION_EXTENSION,
    local_projection_accounting,
    public_projection_summary,
)


def test_public_projection_summary_allowlists_only_approved_aggregates() -> None:
    raw_prompt = "private prompt must not leave the benchmark ledger"
    tenant_identifier = "tenant-42"
    summary = public_projection_summary(
        [
            {
                "id": "chatcmpl-local",
                "messages": [{"role": "user", "content": raw_prompt}],
                "choices": [{"message": {"content": "raw result"}}],
                "tenant_id": tenant_identifier,
                "arbitrary_response_field": {"raw_transcript": "private"},
                LOCAL_PROJECTION_EXTENSION: local_projection_accounting(),
            },
            {
                "id": "chatcmpl-upstream",
                "choices": [{"message": {"content": "ordinary model output"}}],
                "usage": {"prompt_tokens": 7},
            },
        ]
    )
    assert summary == {
        "schema_version": "shiftedx-public-projection-summary-v1",
        "completion_records": 2,
        "local_projections": 1,
        "upstream_calls_avoided": 1,
        "local_projection_upstream_model_usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
        "local_projection_client_input_tokenization": {"available": False, "records": 1},
    }
    published = json.dumps(summary)
    assert raw_prompt not in published
    assert tenant_identifier not in published
    assert "raw_transcript" not in published
    assert "arbitrary_response_field" not in published


def test_public_projection_summary_rejects_invalid_marker_json_types_and_shapes() -> None:
    missing_tokenization = local_projection_accounting()
    del missing_tokenization["client_input_tokenization"]
    invalid_markers = [
        {"origin": "untrusted"},
        {**local_projection_accounting(), "upstream_calls": False},
        {**local_projection_accounting(), "upstream_calls": 0.0},
        {
            **local_projection_accounting(),
            "upstream_model_usage": {
                **local_projection_accounting()["upstream_model_usage"],
                "prompt_tokens": False,
            },
        },
        {**local_projection_accounting(), "unexpected": "field"},
        missing_tokenization,
    ]
    for marker in invalid_markers:
        with pytest.raises(ValueError, match="marker is invalid"):
            public_projection_summary([{LOCAL_PROJECTION_EXTENSION: marker}])
