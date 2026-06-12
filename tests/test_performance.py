"""Per-check timing capture and the Performance summary aggregation."""

from __future__ import annotations

from support import *  # noqa: F403


def _deny_llm():
    return FakeSecurityLlm({
        "outcome": "deny",
        "risk_level": "high",
        "authorization_level": "unknown",
        "rationale": "needs approval",
    })


def test_pre_tool_call_records_timing_with_llm_flag():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    plugin.state._PLUGIN_LLM = _deny_llm()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    summary = plugin._performance_summary()
    assert summary["overall"]["count"] >= 1
    # The gated egress invoked the LLM verifier, so it lands in the llm bucket.
    assert summary["llm"]["count"] >= 1
    assert "pre_tool_call" in {h["hook"] for h in summary["by_hook"]}


def test_deterministic_check_is_not_flagged_as_llm():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")  # strict blocks without consulting the LLM
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    assert result is not None  # blocked deterministically
    summary = plugin._performance_summary()
    assert summary["deterministic"]["count"] >= 1
    assert summary["llm"]["count"] == 0


def test_summary_exposes_expected_shape_and_samples():
    plugin = load_plugin()

    plugin._on_pre_gateway_dispatch(gateway_event("hello world team standup notes"))

    summary = plugin._performance_summary()
    for key in ("overall", "by_hook", "llm", "deterministic", "samples", "window_size"):
        assert key in summary
    for stat in ("count", "avg_ms", "p50_ms", "p95_ms", "max_ms", "total_ms"):
        assert stat in summary["overall"]
    sample = summary["samples"][0]
    for key in ("ts", "hook", "tool_name", "duration_ms", "llm_invoked", "blocked"):
        assert key in sample
    assert sample["hook"] == "pre_gateway_dispatch"


def test_blocked_checks_are_marked():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    summary = plugin._performance_summary()
    assert any(sample["blocked"] for sample in summary["samples"])


def test_timing_does_not_break_check_result():
    # Timing is best-effort: a recording failure must not change the decision.
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin.activity_store._record_check_timing = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))

    result = plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    assert result is not None
    assert result["action"] == "block"


def test_hook_activity_rows_carry_latency_and_turn_total():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    row = plugin._activity_rows({}, limit=1)[0]
    assert row["latency_us"] > 0
    assert row["latency_hook"] == "pre_tool_call"
    assert row["latency_llm_invoked"] == 0

    turn = plugin._activity_turns_payload({"start": "0", "length": "25"})["turns"][0]
    check = turn["rows"][0]
    assert check["latency_us"] == row["latency_us"]
    assert check["latency_ms"] > 0
    assert check["latency_hook"] == "pre_tool_call"
    assert check["latency_llm_invoked"] is False
    assert turn["total_latency_us"] == row["latency_us"]
    assert turn["total_latency_ms"] == check["latency_ms"]
