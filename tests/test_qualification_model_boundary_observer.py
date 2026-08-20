from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_observer(monkeypatch, ledger: Path):
    monkeypatch.setenv("QUALIFICATION_OBSERVER_UPSTREAM", "http://model.invalid/v1")
    monkeypatch.setenv("QUALIFICATION_OBSERVER_LEDGER", str(ledger))
    script = Path(__file__).parents[1] / "scripts" / "qualification_model_boundary_observer.py"
    spec = importlib.util.spec_from_file_location("qualification_model_boundary_observer", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_observer_retains_only_model_boundary_component_hashes(monkeypatch, tmp_path):
    ledger = tmp_path / "observer.jsonl"
    observer = _load_observer(monkeypatch, ledger)
    observer._append_observation(
        {
            "messages": [
                {"role": "system", "content": "private system marker"},
                {"role": "user", "content": "private prompt marker"},
            ],
            "tools": [{"type": "function", "function": {"name": "private_tool"}}],
            "temperature": 0.0,
            "top_p": 0.95,
            "top_k": 20,
            "thinking": {"enabled": True},
            "reasoning_effort": "medium",
            "max_tokens": 1024,
        }
    )

    row = json.loads(ledger.read_text())
    assert set(row) == {"record_type", "sequence", "digest", "fields"}
    assert row["record_type"] == "qualification_model_boundary"
    assert row["sequence"] == 1
    serialized = ledger.read_text()
    assert "private system marker" not in serialized
    assert "private prompt marker" not in serialized
    assert "private_tool" not in serialized
