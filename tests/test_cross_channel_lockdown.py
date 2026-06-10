"""Cross-channel turn lockdown (channel-shopping defense).

When a private export to an external destination is withheld for approval, the agent
must not be able to re-route the same export through a softer channel within the same
turn and have the verifier auto-allow it. Once a private->external egress is gated, any
later egress carrying the same policy classes to an external destination is gated too —
regardless of tool — until the next user input resets the turn.
"""

from __future__ import annotations

from support import *  # noqa: F403


def _fake_llm(outcome: str, risk_level: str):
    return FakeSecurityLlm(
        {
            "outcome": outcome,
            "risk_level": risk_level,
            "authorization_level": "substantive",
            "rationale": "test verdict",
        }
    )


def test_lockdown_gates_a_rerouted_export_through_another_channel():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    # Attempt 1 (messaging channel): the verifier denies -> gated, arming the lockdown.
    plugin._PLUGIN_LLM = _fake_llm("deny", "high")
    first = plugin._on_pre_tool_call(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1"
    )
    assert first is not None and first["action"] == "block"

    # Attempt 2 (a DIFFERENT channel: browser form-fill into an external page). The
    # verifier WOULD allow it, but the cross-channel lockdown gates the re-route anyway.
    plugin._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s1", "https://docs.google.com/forms/d/e/abc/viewform")
    second = plugin._on_pre_tool_call(
        "browser_type", {"ref": "1", "text": "private calendar event details"}, session_id="s1"
    )
    assert second is not None and second["action"] == "block"
    assert "cross-channel lockdown" in second["message"].lower()


def test_external_export_auto_allows_without_a_prior_denial():
    """Control: the same allowing verifier + the same browser form-fill auto-allows when
    no prior external denial armed the lockdown — proving the gate above is the lockdown,
    not the verifier."""
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin, session_id="s2")
    plugin._taint_session("s2", {"contacts"})
    plugin._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s2", "https://docs.google.com/forms/d/e/abc/viewform")

    result = plugin._on_pre_tool_call(
        "browser_type", {"ref": "1", "text": "alice@example.com"}, session_id="s2"
    )
    assert result is None


def test_lockdown_is_scoped_to_the_denied_policy_classes():
    """A denial of one private class does not lock down an unrelated class. Here the
    first gate carries browser_private only; a later personal_private export is judged
    by the verifier (auto-allowed), not blanket-gated."""
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    # Arm the lockdown for browser_private only (a private browser input gated to external).
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._mark_browser_private_input("s1")
    plugin._PLUGIN_LLM = _fake_llm("deny", "high")
    assert plugin._on_pre_tool_call("browser_press", {"key": "Enter"}, session_id="s1") is not None

    # An unrelated personal_private export on a fresh session is unaffected.
    bind_owner(plugin, session_id="s3")
    plugin._taint_session("s3", {"contacts"})
    plugin._PLUGIN_LLM = _fake_llm("allow", "low")
    assert (
        plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s3")
        is None
    )


def test_new_user_input_clears_the_turn_lockdown(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    plugin._PLUGIN_LLM = _fake_llm("deny", "high")
    assert (
        plugin._on_pre_tool_call("send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1")
        is not None
    )

    # A new owner message starts a fresh turn -> the lockdown resets.
    plugin._on_pre_gateway_dispatch(gateway_event("subscribe me to the newsletter", user_id="owner"))

    # The same export the lockdown would have gated now reaches the (allowing) verifier.
    plugin._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s1", "https://docs.google.com/forms/d/e/abc/viewform")
    assert (
        plugin._on_pre_tool_call("browser_type", {"ref": "1", "text": "alice@example.com"}, session_id="s1")
        is None
    )
