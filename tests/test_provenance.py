from __future__ import annotations

import json

from support import *  # noqa: F403


COPIED_EMAIL_PHRASE = "Quarterly roadmap notes mention the private launch window"
COPIED_CONTACT_PHRASE = "Alice Stone prefers Tuesday morning planning calls"
PARAPHRASED_EMAIL_PHRASE = "The launch window was discussed in roadmap notes"
SENSITIVE_PHRASE = "Your verification code is 123456"


def _observe_email_phrase(plugin, *, session_id: str = "s1", phrase: str = COPIED_EMAIL_PHRASE) -> None:
    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"messages": [{"snippet": phrase}]}),
        session_id=session_id,
    )


def _observe_contact_phrase(plugin, *, session_id: str = "s1", phrase: str = COPIED_CONTACT_PHRASE) -> None:
    plugin._on_transform_tool_result(
        tool_name="mcp_dex_search",
        result=json.dumps({"people": [{"note": phrase}]}),
        session_id=session_id,
    )


def test_exact_copied_phrase_narrows_egress_classes():
    plugin = load_plugin()
    bind_owner(plugin)
    _observe_email_phrase(plugin)
    _observe_contact_phrase(plugin)

    classes = plugin._data_classes_for_egress("s1", {"text": COPIED_EMAIL_PHRASE})

    assert classes == {"communications"}


def test_unrelated_session_class_is_excluded_when_provenance_matches():
    plugin = load_plugin()
    bind_owner(plugin)
    _observe_email_phrase(plugin)
    plugin._taint_session("s1", {"calendar"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": COPIED_EMAIL_PHRASE},
        session_id="s1",
    )

    assert result is not None
    assert "Data classes: communications" in result["message"]
    assert "calendar" not in result["message"]


def test_no_match_and_paraphrase_fall_back_to_session_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    _observe_email_phrase(plugin)
    _observe_contact_phrase(plugin)

    classes = plugin._data_classes_for_egress("s1", {"text": PARAPHRASED_EMAIL_PHRASE})

    assert classes == {"communications", "contacts"}


def test_final_response_exact_copied_phrase_narrows_classes():
    plugin = load_plugin()
    bind_owner(plugin)
    _observe_email_phrase(plugin)
    _observe_contact_phrase(plugin)

    response = plugin._privacy_transform_llm_output(
        response_text=COPIED_EMAIL_PHRASE,
        session_id="s1",
        platform="telegram",
        chat_type="group",
    )

    assert response is not None
    row = plugin._activity_rows({"decision": "blocked"}, limit=1)[0]
    assert row["action_family"] == "final_response"
    assert row["data_classes"] == "communications"


def test_untainted_final_response_with_email_shaped_text_is_not_privacy_suppressed():
    plugin = load_plugin()

    response = plugin._privacy_transform_llm_output(
        response_text="The public contact address is support@example.com.",
        session_id="s1",
        platform="telegram",
        chat_type="group",
    )

    assert response is None


def test_short_strings_do_not_match_provenance():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"messages": [{"snippet": "short private"}]}),
        session_id="s1",
    )
    plugin._taint_session("s1", {"contacts"})

    classes = plugin._data_classes_for_egress("s1", {"text": "short private"})

    assert classes == {"communications", "contacts"}


def test_security_sensitive_strings_are_not_indexed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"messages": [{"snippet": SENSITIVE_PHRASE}]}),
        session_id="s1",
    )
    plugin._taint_session("s1", {"contacts"})

    classes = plugin._data_classes_for_egress("s1", {"text": SENSITIVE_PHRASE})

    assert classes == {"communications", "contacts"}
    state = plugin._SESSIONS["s1"]
    assert "provenance" not in state or not state["provenance"]


def test_unavailable_hmac_key_suppresses_result_fail_closed(tmp_path):
    plugin = load_plugin()
    bad_key_path = tmp_path / "hmac-key-is-directory"
    bad_key_path.mkdir()
    plugin._GUARDIAN_HMAC_KEY_PATH = bad_key_path

    result = plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"messages": [{"snippet": COPIED_EMAIL_PHRASE}]}),
        session_id="s1",
    )
    parsed = json.loads(result)

    assert parsed["hermes_guardian"]["suppressed"] is True
    assert "fail-closed" in parsed["hermes_guardian"]["reason"]


def test_raw_content_stays_out_of_storage_but_reaches_llm_verifier():
    # In llm mode the verifier (the same provider the agent already uses) reads the
    # real payload so it can judge content/intent. Persistent state stays
    # metadata-only: raw content must never enter session state, activity rows, or
    # approval records.
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = FakeSecurityLlm({
        "outcome": "deny",
        "risk_level": "high",
        "authorization_level": "unknown",
        "rationale": "private data may leave",
    })
    plugin._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    _observe_email_phrase(plugin)

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "unknown", "text": COPIED_EMAIL_PHRASE},
        session_id="s1",
    )

    assert result is not None
    storage = "\n".join(
        [
            repr(plugin._SESSIONS),
            json.dumps(plugin._activity_rows({}, limit=20), sort_keys=True),
            json.dumps(plugin._PENDING_APPROVALS, sort_keys=True),
        ]
    )
    assert COPIED_EMAIL_PHRASE not in storage
    assert "provenance-v1" not in storage
    # The verifier input, by contrast, deliberately carries the real payload.
    llm_input = json.dumps(fake_llm.calls, sort_keys=True, default=str)
    assert COPIED_EMAIL_PHRASE in llm_input


def test_reset_clears_provenance_but_session_end_does_not():
    plugin = load_plugin()
    bind_owner(plugin)
    _observe_email_phrase(plugin)
    assert plugin._provenance_match_classes("s1", {"text": COPIED_EMAIL_PHRASE}) == {"communications"}

    plugin._on_session_end(session_id="s1")

    assert plugin._provenance_match_classes("s1", {"text": COPIED_EMAIL_PHRASE}) == {"communications"}

    plugin._on_session_reset(session_id="s1")

    assert plugin._provenance_match_classes("s1", {"text": COPIED_EMAIL_PHRASE}) == set()
