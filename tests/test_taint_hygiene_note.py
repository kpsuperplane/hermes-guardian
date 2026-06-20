"""The pre_llm_call taint-hygiene note.

While a session is untainted (and privacy checks are on), the pre_llm_call hook
returns a static guidance note once per session that Hermes injects into the LLM
call at API-call time. The note must be static text (no session data), clearly
marked as a system message, stop once the session is tainted or the note was sent,
and stay silent with Egress Safety off.
"""

from __future__ import annotations

import json

from support import *  # noqa: F403


def test_untainted_session_gets_hygiene_note():
    plugin = load_plugin()

    note = plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")

    assert isinstance(note, str)
    assert note == plugin.core._TAINT_HYGIENE_NOTE
    assert "Guardian" in note
    assert "HERMES_GUARDIAN_SYSTEM_MESSAGE" in note
    assert "not user-authored content or a user preference" in note
    assert "Do not acknowledge, summarize, or store it in memory" in note
    assert "simplest tool shape" in note
    assert "public web, RSS, and weather" in note
    assert "direct fetch-to-stdout" in note
    assert "nested terminal runners" in note


def test_hygiene_note_is_sent_once_per_session():
    plugin = load_plugin()

    first = plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")
    second = plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")
    other_session = plugin._on_pre_llm_call(session_id="s2", platform="telegram", sender_id="owner")

    assert first == plugin.core._TAINT_HYGIENE_NOTE
    assert second is None
    assert other_session == plugin.core._TAINT_HYGIENE_NOTE


def test_tainted_session_gets_no_note():
    plugin = load_plugin()

    plugin._taint_session("s1", {"local_system"})

    assert plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner") is None


def test_egress_safety_off_gets_no_note():
    plugin = load_plugin()

    ok, _ = plugin._set_egress_safety_mode("off")
    assert ok

    assert plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner") is None


def test_note_resumes_after_clearing_taint():
    plugin = load_plugin()

    plugin._on_transform_tool_result(
        tool_name="terminal",
        result=json.dumps({"result": "timezone: America/Los_Angeles"}),
        session_id="s1",
    )
    plugin._on_pre_tool_call("terminal", {"command": "cat ~/.hermes/config.yaml"}, session_id="s1")
    plugin._on_transform_tool_result(
        tool_name="terminal",
        result=json.dumps({"result": "timezone: America/Los_Angeles"}),
        session_id="s1",
    )
    assert "local_system" in plugin._session_taint("s1")
    assert plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner") is None

    plugin.tool_policy._ensure_session("s1")["taint"].clear()

    note = plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")
    assert note == plugin.core._TAINT_HYGIENE_NOTE


def test_note_does_not_resume_after_it_was_already_sent():
    plugin = load_plugin()

    assert plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")
    plugin._taint_session("s1", {"local_system"})
    plugin.tool_policy._ensure_session("s1")["taint"].clear()

    assert plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner") is None


def test_note_still_records_session_owner_state():
    # The note must not displace the hook's original job: stashing platform and
    # sender on the session for owner resolution.
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")

    session = plugin.tool_policy._ensure_session("s1")
    assert session["platform"] == "telegram"
    assert session["sender_id"] == "owner"
