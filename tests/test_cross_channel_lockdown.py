"""Cross-channel turn lockdown (channel-shopping defense).

When a private export to an outward destination is withheld for approval, the agent
must not be able to re-route the same export through a softer channel within the same
turn and have the verifier auto-allow it. High-risk denials apply broadly for the
turn; ordinary ambiguity is route-scoped so unrelated same-turn work can continue.
"""

from __future__ import annotations

import json

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


def test_lockdown_gates_a_rerouted_export_through_another_channel(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})
    plugin._on_pre_gateway_dispatch(gateway_event("send my private update", user_id="owner"))

    # Attempt 1 (messaging channel): the verifier denies -> gated, arming the lockdown.
    plugin.state._PLUGIN_LLM = _fake_llm("deny", "high")
    first = plugin._on_pre_tool_call(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1"
    )
    assert first is not None and first["action"] == "block"

    # Attempt 2 (a DIFFERENT channel: browser form-fill into an external page). The
    # verifier WOULD allow it, but the cross-channel lockdown gates the re-route anyway.
    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s1", "https://docs.google.com/forms/d/e/abc/viewform")
    second = plugin._on_pre_tool_call(
        "browser_type", {"ref": "1", "text": "private calendar event details"}, session_id="s1"
    )
    assert second is not None and second["action"] == "block"
    assert "cross-channel lockdown" in second["message"].lower()
    assert "high-risk private export" in second["message"].lower()


def test_external_export_auto_allows_without_a_prior_denial(monkeypatch):
    """Control: the same allowing verifier + the same browser form-fill auto-allows when
    no prior external denial armed the lockdown — proving the gate above is the lockdown,
    not the verifier."""
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin, session_id="s2")
    plugin._taint_session("s2", {"contacts"})
    # Owner authorization context present (verifier auto-allow of an external private
    # export requires it — doc 02 §3 corroboration gate).
    plugin._on_pre_gateway_dispatch(gateway_event("fill the form with my email", user_id="owner"))
    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s2", "https://docs.google.com/forms/d/e/abc/viewform")

    result = plugin._on_pre_tool_call(
        "browser_type", {"ref": "1", "text": "alice@example.com"}, session_id="s2"
    )
    assert result is None


def test_lockdown_is_scoped_to_the_denied_policy_classes(monkeypatch):
    """A denial of one private class does not lock down an unrelated class. Here the
    first gate carries browser_private only; a later personal_private export is judged
    by the verifier (auto-allowed), not blanket-gated."""
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    # Arm the lockdown for browser_private only (a private browser input gated to external).
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._mark_browser_private_input("s1")
    plugin.state._PLUGIN_LLM = _fake_llm("deny", "high")
    assert plugin._on_pre_tool_call("browser_press", {"key": "Enter"}, session_id="s1") is not None

    # An unrelated personal_private export on a fresh session is unaffected. Owner
    # authorization context is present so the verifier auto-allow is honored.
    bind_owner(plugin, session_id="s3")
    plugin._taint_session("s3", {"contacts"})
    plugin._on_pre_gateway_dispatch(gateway_event("message my friend the update", user_id="owner"))
    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    assert (
        plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s3")
        is None
    )


def test_lockdown_block_does_not_double_log_or_record_allowed_side_effects(monkeypatch):
    """Regression: a lockdown-blocked export must leave exactly ONE activity row (the
    block) and no allowed side effects.

    The verifier's allow-branch used to emit the ``auto_approved`` activity row and record
    side effects (taint / browser-private-input) BEFORE the cross-channel lockdown gate
    ran. When the lockdown then blocked the re-routed export, the call was logged as both
    ``auto_approved`` AND ``blocked`` — inflating auto-approve counts with phantom twins —
    and taint was marked for an action that never executed. The allow emit/side effects
    are now deferred until after the lockdown check passes.
    """
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})
    plugin._on_pre_gateway_dispatch(gateway_event("fill the external form", user_id="owner"))

    # Arm the turn lockdown directly (a prior high-risk private export was already
    # withheld this turn) without emitting its own activity row, so the single gated call
    # below is the only row we expect.
    plugin._record_turn_external_denial(
        {
            "session_id": "s1",
            "tool_name": "send_message",
            "action_family": "message_send",
            "destination": "messaging",
            "data_classes": {"contacts"},
            "destination_trust": "external",
            "purpose": "unknown",
            "recipient_identity": "recipient_deadbeefdeadbeefdeadbe",
            "fingerprint": "fp1",
        },
        {"source": "llm", "risk_level": "high", "authorization_level": "unknown"},
    )

    # The verifier WOULD auto-allow this browser form-fill into an external page...
    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s1", "https://docs.google.com/forms/d/e/abc/viewform")
    result = plugin._on_pre_tool_call(
        "browser_type", {"ref": "1", "text": "private calendar event details"}, session_id="s1"
    )

    # ...but the lockdown gates it for human review.
    assert result is not None and result["action"] == "block"
    assert "cross-channel lockdown" in result["message"].lower()

    # Exactly one activity row, and it is the block — no phantom auto_approved twin.
    rows = plugin._activity_rows({}, limit=10)
    assert len(rows) == 1
    assert rows[0]["decision"] == "blocked"
    assert not any(row["decision"] == "auto_approved" for row in rows)

    # The allow-branch side effect (mark_browser_private_input) was deferred and never
    # applied: the withheld export left no browser-private taint behind.
    assert not plugin._browser_has_private_input("s1")
    assert "browser_private_input" not in plugin._session_taint("s1")


def test_route_lockdown_gates_same_destination_retry_but_not_different_unsubscribe(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications", "contacts"})
    plugin._on_pre_gateway_dispatch(
        gateway_event(
            "Unsubscribe from Costco, Newegg, Ticketmaster, Ember stores, and IHG please",
            user_id="owner",
        )
    )

    # A medium verifier denial on an owner-authorized unsubscribe form-fill arms a
    # route-scoped guard for Costco only.
    plugin.state._PLUGIN_LLM = _fake_llm("deny", "medium")
    plugin._set_browser_host("s1", "https://www.costcobusinessdelivery.com/preferences")
    first = plugin._on_pre_tool_call(
        "browser_type",
        {"ref": "email", "text": "owner@example.com"},
        session_id="s1",
    )
    assert first is not None and first["action"] == "block"

    # Retrying the same destination through a softer read/navigation route is gated.
    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    same_dest = plugin._on_pre_tool_call(
        "browser_navigate",
        {"url": "https://www.costcobusinessdelivery.com/unsubscribe?email=owner@example.com"},
        session_id="s1",
    )
    assert same_dest is not None and same_dest["action"] == "block"
    assert "likely re-route" in same_dest["message"]

    # A different merchant/subscription-management destination in the same bulk request
    # still reaches the verifier and can auto-allow.
    other_dest = plugin._on_pre_tool_call(
        "browser_navigate",
        {"url": "https://hs-49503193.s.hubspotemail.net/unsubscribe?email=owner@example.com"},
        session_id="s1",
    )
    assert other_dest is None


def test_safe_remote_read_bypasses_even_global_lockdown():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})
    plugin._record_turn_external_denial(
        {
            "session_id": "s1",
            "tool_name": "send_message",
            "action_family": "message_send",
            "destination": "messaging",
            "data_classes": {"contacts"},
            "destination_trust": "external",
            "purpose": "unknown",
            "recipient_identity": "recipient_deadbeefdeadbeefdeadbe",
            "fingerprint": "fp1",
        },
        {"source": "llm", "risk_level": "high", "authorization_level": "unknown"},
    )
    plugin.state._PLUGIN_LLM = _fake_llm("deny", "high")

    result = plugin._on_pre_tool_call(
        "terminal",
        {"command": "curl https://api.weather.gov/points/47.61,-122.33"},
        session_id="s1",
    )

    assert result is None


def test_lockdown_records_are_metadata_only_and_do_not_refresh_on_lockdown_block():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    plugin.state._PLUGIN_LLM = _fake_llm("deny", "medium")
    plugin._set_browser_host("s1", "https://www.costcobusinessdelivery.com/preferences")
    first = plugin._on_pre_tool_call(
        "browser_type",
        {"ref": "email", "text": "owner@example.com"},
        session_id="s1",
    )
    assert first is not None and first["action"] == "block"
    records = list(plugin._TURN_DENIED_EXTERNAL["s1"])
    assert len(records) == 1
    encoded = json.dumps(records, sort_keys=True)
    assert "owner@example.com" not in encoded
    assert "ref" not in encoded
    assert "text" not in encoded

    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    blocked = plugin._on_pre_tool_call(
        "browser_navigate",
        {"url": "https://www.costcobusinessdelivery.com/unsubscribe?email=owner@example.com"},
        session_id="s1",
    )
    assert blocked is not None and blocked["action"] == "block"
    assert len(plugin._TURN_DENIED_EXTERNAL["s1"]) == 1


def test_new_user_input_clears_the_turn_lockdown(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    plugin.state._PLUGIN_LLM = _fake_llm("deny", "high")
    assert (
        plugin._on_pre_tool_call("send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1")
        is not None
    )

    # A new owner message starts a fresh turn -> the lockdown resets.
    plugin._on_pre_gateway_dispatch(gateway_event("subscribe me to the newsletter", user_id="owner"))

    # The same export the lockdown would have gated now reaches the (allowing) verifier.
    plugin.state._PLUGIN_LLM = _fake_llm("allow", "low")
    plugin._set_browser_host("s1", "https://docs.google.com/forms/d/e/abc/viewform")
    assert (
        plugin._on_pre_tool_call("browser_type", {"ref": "1", "text": "alice@example.com"}, session_id="s1")
        is None
    )
