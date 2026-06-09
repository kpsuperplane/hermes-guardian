from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import re
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from support import *  # noqa: F403


def test_sensitive_reason_detects_core_security_flows():
    plugin = load_plugin()

    cases = [
        ("Reset your password using this link", "password reset"),
        ("We received an account recovery request", "account recovery"),
        ("Your verification code is 123456", "auth code"),
        ("Use this one-time code: 123456", "one-time code"),
        ("Open your magic link to sign in", "magic link"),
        ("Security alert: new sign-in detected", "security alert"),
        ("A new SSH key was added to your account", "security key change"),
        ("GitHub token [redacted]", "redacted security content"),
        ("Subject: [redacted sensitive subject]", "redacted sensitive email"),
        ("https://example.com/reset-password?token=abc", "sensitive link"),
        ("[sensitive email subject redacted]", "redacted sensitive email"),
    ]

    for text, expected in cases:
        assert plugin._sensitive_reason(text) == expected


def test_sensitive_reason_ignores_normal_content():
    plugin = load_plugin()

    assert plugin._sensitive_reason("Lunch at noon tomorrow") is None
    assert plugin._sensitive_reason({"url": "https://example.com/docs"}) is None
    assert plugin._sensitive_reason({"items": [{"title": "normal status update"}]}) is None
    assert plugin._sensitive_reason("Use skill_view to inspect code examples and snippets.") is None
    assert plugin._sensitive_reason("The Notion resource explains verification code flows.") is None


def test_doc_read_tools_do_not_suppress_code_documentation():
    plugin = load_plugin()

    skill_result = plugin._on_transform_tool_result(
        tool_name="skill_view",
        result="This skill explains code execution and how to format code snippets.",
    )
    notion_result = plugin._on_transform_tool_result(
        tool_name="mcp_notion_read_resource",
        result=json.dumps({
            "content": "A runbook about verification code flows and code examples.",
        }),
    )

    assert skill_result is None
    assert notion_result is None


def test_inbound_result_allows_api_token_assignments():
    plugin = load_plugin()

    # An MCP/skill result that surfaces a service token the agent legitimately needs is read
    # into context rather than suppressed at read-time. (Egress remains guarded; see below.)
    skill_doc = (
        "# Setup\n"
        "Add to your .env file:\n"
        "  SLACK_API_TOKEN=xoxb-9f3a8e2188b-example-token-value\n"
        "Then run the skill.\n"
    )
    assert plugin._on_transform_tool_result(tool_name="skill_view", result=skill_doc) is None
    assert plugin._on_transform_tool_result(
        tool_name="mcp_acme_config",
        result=json.dumps({"result": "key: sk-" + "a" * 40}),
    ) is None


def test_inbound_result_still_suppresses_hard_secrets():
    plugin = load_plugin()

    for result in (
        "config:\n  DB_PRIVATE_KEY=abcdefgh12345678\n",
        "config:\n  DB_PASSWORD=hunter2hunter2\n",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc...\n",
    ):
        transformed = plugin._on_transform_tool_result(tool_name="skill_view", result=result)
        assert transformed is not None
        assert parse_json(transformed)["hermes_guardian"]["suppressed"] is True


def test_inbound_result_still_suppresses_account_security_content():
    plugin = load_plugin()

    for result in (
        "Your verification code is 123456",
        "Reset your password using this link",
    ):
        transformed = plugin._on_transform_tool_result(tool_name="mcp_gmail_read", result=result)
        assert transformed is not None
        assert parse_json(transformed)["result"] == "[suppressed by hermes-guardian]"


def test_egress_still_blocks_api_tokens_read_inbound():
    plugin = load_plugin()
    token_line = "SLACK_API_TOKEN=xoxb-9f3a8e2188b-example-token-value"

    # Final response carrying the token is suppressed on the way out.
    assert plugin._on_transform_llm_output(response_text=f"Token:\n  {token_line}") is not None

    # The token going out as a tool argument is hard-blocked.
    blocked = plugin._on_pre_tool_call(tool_name="message_send", args={"text": token_line})
    assert blocked is not None and blocked["action"] == "block"


def test_sensitive_finding_includes_match_and_context():
    plugin = load_plugin()

    finding = plugin._sensitive_finding(
        "Please open https://example.com/reset-password?token=abc to continue"
    )

    assert finding == {
        "reason": "sensitive link",
        "match": "https://example.com/reset-password?token=abc",
        "context": "Please open https://example.com/reset-password?token=abc to continue",
    }


def test_unsafe_diagnostic_logging_is_opt_in(monkeypatch, caplog):
    plugin = load_plugin()
    text = "Your verification code is 123456"
    monkeypatch.setattr(plugin, "_UNSAFE_DIAGNOSTICS_FLAG", Path("/tmp/missing-unsafe-diagnostic-flag"))
    monkeypatch.delenv("HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS", raising=False)
    monkeypatch.delenv("SECURITY_SENSITIVE_FILTER_UNSAFE_DIAGNOSTICS", raising=False)

    with caplog.at_level(logging.WARNING):
        plugin._log_unsafe_diagnostic("test", text)
    assert "UNSAFE diagnostic" not in caplog.text

    caplog.clear()
    monkeypatch.setenv("HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS", "1")
    with caplog.at_level(logging.WARNING):
        plugin._log_unsafe_diagnostic("test", text)

    assert "UNSAFE diagnostic" in caplog.text
    assert "reason=auth code" in caplog.text
    assert "Your verification code is 123456" in caplog.text


def test_pre_tool_call_blocks_security_sensitive_browser_url_before_execution():
    plugin = load_plugin()

    result = plugin._on_pre_tool_call(
        tool_name="browser_navigate",
        args={"url": "https://example.com/reset-password?token=abc"},
    )

    assert result == {
        "action": "block",
        "message": "Blocked by hermes-guardian: sensitive link detected in tool arguments.",
    }


def test_security_sensitive_args_are_blocked_even_with_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._SESSION_APPROVALS["s1"] = [{
        "owner_hash": plugin._SESSIONS["s1"]["owner_hash"],
        "action_family": "browser_type",
        "destination": "example.com",
        "data_classes": ["communications"],
        "fingerprint": "anything",
    }]

    result = plugin._on_pre_tool_call(
        tool_name="browser_type",
        args={"text": "Your password reset code is 123456"},
        session_id="s1",
    )

    assert result is not None
    assert result["action"] == "block"
    assert "auth code" in result["message"] or "password reset" in result["message"]


def test_transform_tool_result_replaces_sensitive_plain_text_result():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="terminal",
        result="Your password reset code is 123456",
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == "[suppressed by hermes-guardian]"
    assert parsed["hermes_guardian"]["suppressed"] is True
    assert parsed["security_sensitive_filter"]["reason"] == "password reset"


def test_transform_tool_result_removes_sensitive_plain_text_records():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="gmail",
        result=(
            "From: GitHub\n"
            "Subject: A new public key was added\n\n"
            "From: Alex Rivera\n"
            "Subject: Hello\n"
            "Body: How are you?\n\n"
            "From: Alex Rivera\n"
            "Subject: One time [redacted]\n"
        ),
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == "From: Alex Rivera\nSubject: Hello\nBody: How are you?"
    assert parsed["hermes_guardian"]["suppressed_count"] == 2
    assert parsed["hermes_guardian"]["reason"] == "security key change"


def test_transform_tool_result_does_not_leak_when_all_plain_text_records_are_sensitive():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="gmail",
        result=(
            "From: GitHub\n"
            "Subject: A new public key was added\n\n"
            "From: Example\n"
            "Subject: Your verification code is 123456\n"
        ),
    )

    parsed = parse_json(transformed)
    encoded = json.dumps(parsed)
    assert parsed["result"] == "[suppressed by hermes-guardian]"
    assert parsed["hermes_guardian"]["suppressed"] is True
    assert "public key was added" not in encoded
    assert "123456" not in encoded


def test_transform_tool_result_removes_sensitive_list_items_entirely():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="mcp_search",
        result=json.dumps({
            "result": [
                {"id": "1", "subject": "[sensitive email subject redacted]"},
                {"id": "2", "subject": "Lunch"},
            ]
        }),
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == [{"id": "2", "subject": "Lunch"}]
    assert parsed["hermes_guardian"]["suppressed_count"] == 1


def test_transform_tool_result_marks_communications_taint_even_for_normal_email():
    plugin = load_plugin()
    bind_owner(plugin)

    assert plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"result": [{"subject": "Hello", "body": "How are you?"}]}),
        session_id="s1",
    ) is None

    assert plugin._session_taint("s1") == {"communications"}


def test_transform_tool_result_logs_specific_source_taint_reason():
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"result": [{"subject": "Hello", "body": "How are you?"}]}),
        session_id="s1",
    )

    rows = plugin._activity_rows({"decision": "tainted"}, limit=10)
    assert rows
    assert rows[0]["reason"] == "tainted by email tool result (communications)"


def test_transform_tool_result_logs_specific_content_pattern_taint_reason():
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_transform_tool_result(
        tool_name="mcp_acme_lookup",
        result=json.dumps({"result": "Contact me at person@example.com"}),
        session_id="s1",
    )

    rows = plugin._activity_rows({"decision": "tainted"}, limit=10)
    assert rows
    assert rows[0]["reason"] == "tainted by content pattern in mcp_acme_lookup result (contacts)"


def test_transform_tool_result_source_based_taint_classes():
    plugin = load_plugin()
    bind_owner(plugin)

    cases = [
        ("mcp_dex_search_contacts", "contacts"),
        ("mnemosyne_search", "memory"),
        ("mcp_notion_read_page", "documents"),
        ("search_files", "documents"),
        ("calendar_list_events", "calendar"),
        ("computer_use", "local_system"),
    ]

    for tool_name, expected in cases:
        plugin._on_transform_tool_result(
            tool_name=tool_name,
            result=json.dumps({"result": "normal private-source data"}),
            session_id="s1",
        )
        assert expected in plugin._session_taint("s1")


def test_low_risk_terminal_result_does_not_taint_local_system():
    plugin = load_plugin()
    bind_owner(plugin)

    assert plugin._on_pre_tool_call("terminal", {"command": "pwd"}, session_id="s1") is None
    plugin._on_transform_tool_result(
        tool_name="terminal",
        result=json.dumps({"result": "/root"}),
        session_id="s1",
    )

    assert "local_system" not in plugin._session_taint("s1")
    rows = plugin._activity_rows({"decision": "tainted"}, limit=10)
    assert rows == []


def test_content_bearing_terminal_result_taints_local_system():
    plugin = load_plugin()
    bind_owner(plugin)

    assert plugin._on_pre_tool_call("terminal", {"command": "cat ~/.hermes/config.yaml"}, session_id="s1") is None
    plugin._on_transform_tool_result(
        tool_name="terminal",
        result=json.dumps({"result": "timezone: America/Los_Angeles"}),
        session_id="s1",
    )

    assert "local_system" in plugin._session_taint("s1")


def test_terminal_result_without_call_policy_uses_content_detection_only():
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_transform_tool_result(
        tool_name="terminal",
        result=json.dumps({"result": "plain startup output"}),
        session_id="s1",
    )

    assert plugin._session_taint("s1") == set()


def test_public_remote_read_result_does_not_suppress_auth_code_like_text():
    plugin = load_plugin()
    bind_owner(plugin)

    command = (
        "python3 - <<'PY'\n"
        "import urllib.request, pathlib\n"
        "data=urllib.request.urlopen('https://pastebin.com/raw/t4SF0XfV').read()\n"
        "pathlib.Path('/tmp/paste_t4SF0XfV').write_bytes(data)\n"
        "PY"
    )
    assert plugin._on_pre_tool_call("terminal", {"command": command}, session_id="s1") is None

    result = plugin._on_transform_tool_result(
        tool_name="terminal",
        result=json.dumps({"result": "Example page says: your verification code is 123456"}),
        session_id="s1",
    )

    assert result is None
    assert plugin._session_taint("s1") == set()
    rows = plugin._activity_rows({"decision": "security_suppressed"}, limit=10)
    assert rows == []
