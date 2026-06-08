"""Tests for the optional AgentDojo adapter.

AgentDojo is not a CI dependency, so the full-run test is skipped when it is not
installed. The mapping/degradation tests run with the standard library only.
"""

from __future__ import annotations

import importlib.util

import pytest

from benchmarks import agentdojo_guardian as adapter


def _agentdojo_available() -> bool:
    return importlib.util.find_spec("agentdojo") is not None


def test_tool_overrides_are_valid_guardian_overrides():
    # Every classified tool must normalize into a usable Guardian tool override
    # so the adapter's mapping never silently drops a tool.
    overrides = adapter._tool_overrides()
    assert len(overrides) == len(adapter.TOOL_CLASSIFICATION)
    egress_values = {o.get("egress") for o in overrides}
    # Sources/neutral reads are marked ignore; sinks use real egress families.
    assert "ignore" in egress_values
    assert "message_send" in egress_values
    assert "tool_write" in egress_values
    for entry in overrides:
        assert entry["egress"] in {"", "ignore"} | {
            "message_send",
            "web_api",
            "tool_write",
            "local_write",
        }


def test_classification_summary_partitions_tools():
    summary = adapter._classification_summary()
    sources = set(summary["source_tools"])
    reads = set(summary["neutral_read_tools"])
    sinks = set(summary["sink_tools"])
    assert sources and sinks
    # Partitions are disjoint and cover the full mapping.
    assert sources.isdisjoint(reads)
    assert sources.isdisjoint(sinks)
    assert reads.isdisjoint(sinks)
    assert sources | reads | sinks == set(adapter.TOOL_CLASSIFICATION)
    # Canonical egress sinks are classified as sinks, not reads.
    for tool in ("send_email", "send_money", "post_webpage", "share_file"):
        assert tool in sinks


def test_missing_agentdojo_degrades_without_fabricating(monkeypatch):
    if _agentdojo_available():
        pytest.skip("agentdojo installed; degradation path not exercised")
    with pytest.raises(RuntimeError) as excinfo:
        adapter.run_agentdojo_adapter()
    message = str(excinfo.value)
    assert "AgentDojo is not installed" in message
    assert "pip install" in message


@pytest.mark.skipif(not _agentdojo_available(), reason="agentdojo not installed")
def test_full_adapter_run_reports_real_metrics():
    result = adapter.run_agentdojo_adapter()
    assert result["benchmark"] == "agentdojo_guardian"
    assert result["privacy_mode"] == "strict"
    assert result["real_llm_judgment"] is False
    assert result["verifier"] == "deterministic"
    counts = result["counts"]
    assert counts["attack_tasks_measurable"] > 0
    assert counts["benign_tasks_measurable"] > 0
    assert 0.0 <= result["prevented_rate"] <= 1.0
    assert 0.0 <= result["false_positive_rate"] <= 1.0
    # The mapping covers AgentDojo's vocabulary; nothing falls through as unknown.
    assert result["unmapped_tools"] == []
    assert set(result["per_suite"]) == {"workspace", "travel", "banking", "slack"}
