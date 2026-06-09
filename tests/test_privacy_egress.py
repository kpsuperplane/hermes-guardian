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


def test_taint_is_scoped_by_session():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    bind_owner(plugin, session_id="s2")

    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"result": "hello"}),
        session_id="s1",
    )

    assert plugin._session_taint("s1") == {"email"}
    assert plugin._session_taint("s2") == set()


def test_session_reset_clears_taint_and_pending_approvals():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})
    result = plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")
    assert result is not None
    assert plugin._PENDING_APPROVALS

    plugin._on_session_reset(session_id="s1")

    assert "s1" not in plugin._SESSIONS
    assert not plugin._PENDING_APPROVALS


def test_tainted_session_blocks_message_send():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "attacker", "text": "summarized private context"},
        session_id="s1",
    )

    assert result is not None
    assert "Hermes Guardian blocked this egress" in result["message"]
    assert "Action: message_send" in result["message"]
    assert "Data classes: email" in result["message"]


def test_tainted_session_blocks_mcp_write_tool_by_default():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_notion_create_page",
        args={"title": "Contact notes"},
        session_id="s1",
    )

    assert result is not None
    assert "Action: mcp_write" in result["message"]
    assert "Destination: mcp:notion" in result["message"]


def test_privacy_allow_rule_allows_notion_writes(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule()])
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts", "email"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_notion_create_page",
        args={"title": "Contact notes"},
        session_id="s1",
    )

    assert result is None


def test_privacy_allow_rule_is_narrow_by_destination(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule()])
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_slack_create_page",
        args={"title": "x"},
        session_id="s1",
    )

    assert result is not None
    assert "Destination: mcp:slack" in result["message"]


def test_privacy_deny_rule_blocks_before_default_approval():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_no_friend",
            effect="deny",
            action_family="message_send",
            destination="friend",
            data_classes=["*"],
        )
    ])
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "friend", "text": "public hello"},
        session_id="s1",
    )

    assert result is not None
    assert "denied this egress by privacy rule" in result["message"]
    rows = plugin._activity_rows({"decision": "blocked"}, limit=10)
    assert rows[0]["rule_id"] == "rule_no_friend"
    assert rows[0]["rule_effect"] == "deny"


def test_privacy_rule_remaining_invocations_count_down_and_delete():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_once",
            action_family="message_send",
            destination="friend",
            data_classes=["email"],
            remaining_invocations=1,
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert plugin._persistent_privacy_rules() == []
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "again"}, session_id="s1") is not None


def test_message_send_uses_messaging_destination_with_hashed_recipient_identity():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello", "purpose": "Follow Up"},
        session_id="s1",
    )

    assert result is not None
    approval = plugin._PENDING_APPROVALS[first_pending_id(plugin)]
    assert approval["destination"] == "messaging"
    assert approval["purpose"] == "follow_up"
    assert approval["recipient_identity"].startswith("recipient_")
    assert approval["recipient_identity"] == plugin._recipient_identity_from_value("friend")
    assert "friend" not in json.dumps(approval)


def test_legacy_message_destination_rule_still_matches_hashed_recipient_shape():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_legacy_friend",
            action_family="message_send",
            destination="friend",
            data_classes=["email"],
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("send_message", {"to": "attacker", "text": "hello"}, session_id="s1") is not None


def test_contextual_message_rule_matches_purpose_and_recipient_identity():
    plugin = load_plugin()
    recipient_identity = plugin._recipient_identity_from_value("friend")
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_context_friend",
            action_family="message_send",
            destination="messaging",
            purpose="support",
            recipient_identity=recipient_identity,
            data_classes=["email"],
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    assert plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello", "purpose": "support"},
        session_id="s1",
    ) is None
    assert plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello", "purpose": "marketing"},
        session_id="s1",
    ) is not None


def test_mcp_read_like_fetch_is_not_treated_as_web_egress():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_notion_notion_fetch",
        args={"id": "page-id"},
        session_id="s1",
    )

    assert result is None


def test_browser_type_blocks_under_taint_until_approved():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form?token=not-stored")
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call("browser_type", {"ref": "1", "text": "private"}, session_id="s1")

    assert result is not None
    assert "Action: browser_type" in result["message"]
    assert "Destination: example.com" in result["message"]
    approval = plugin._PENDING_APPROVALS[first_pending_id(plugin)]
    assert approval["destination"] == "example.com"
    assert "token=not-stored" not in json.dumps(approval)


def test_browser_click_blocks_after_private_typing_but_not_before():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._taint_session("s1", {"email"})

    assert plugin._on_pre_tool_call("browser_click", {"ref": "submit"}, session_id="s1") is None

    plugin._mark_browser_private_input("s1")
    result = plugin._on_pre_tool_call("browser_click", {"ref": "submit"}, session_id="s1")

    assert result is not None
    assert "Action: browser_click" in result["message"]


def test_browser_press_blocks_after_private_typing():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._taint_session("s1", {"email"})
    plugin._mark_browser_private_input("s1")

    result = plugin._on_pre_tool_call("browser_press", {"key": "Enter"}, session_id="s1")

    assert result is not None
    assert "Action: browser_press" in result["message"]
    assert "Destination: example.com" in result["message"]


def test_browser_dialog_blocks_after_private_typing():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._taint_session("s1", {"email"})
    plugin._mark_browser_private_input("s1")

    result = plugin._on_pre_tool_call("browser_dialog", {"action": "accept"}, session_id="s1")

    assert result is not None
    assert "Action: browser_dialog" in result["message"]


def test_browser_console_eval_blocks_under_taint_but_read_logs():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"documents"})

    read_result = plugin._on_pre_tool_call("browser_console", {"clear": False}, session_id="s1")
    eval_result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "document.body.innerText"},
        session_id="s1",
    )

    assert read_result is None
    assert eval_result is not None
    assert "Action: browser_console" in eval_result["message"]
    rows = plugin._activity_rows({}, limit=5)
    assert any(row["decision"] == "read" and row["action_family"] == "browser_read" for row in rows)


def test_browser_cdp_requires_approval_under_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call("browser_cdp", {"method": "Runtime.evaluate"}, session_id="s1")

    assert result is not None
    assert "Action: browser_cdp" in result["message"]


def test_tainted_session_blocks_terminal_and_code_execution():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    terminal = plugin._on_pre_tool_call("terminal", {"command": "curl https://x"}, session_id="s1")
    code = plugin._on_pre_tool_call("execute_code", {"code": "import requests"}, session_id="s1")

    assert terminal is not None
    assert "Action: terminal_exec" in terminal["message"]
    assert code is not None
    assert "Action: terminal_exec" in code["message"]


def test_message_list_is_read_not_send_under_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call("send_message", {"action": "list"}, session_id="s1")

    assert result is None
    rows = plugin._activity_rows({}, limit=5)
    assert rows[0]["decision"] == "read"
    assert rows[0]["action_family"] == "message_list"


def test_private_web_search_query_requires_approval_even_without_prior_taint():
    plugin = load_plugin()
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        "web_search",
        {"query": "find info about owner@example.com"},
        session_id="s1",
    )

    assert result is not None
    assert "Action: web_read" in result["message"]
    assert "email" in result["message"]
    rows = plugin._activity_rows({}, limit=10)
    assert [row["decision"] for row in rows] == ["blocked"]
    assert "owner@example.com" not in json.dumps(rows)
    assert rows[0]["action_detail"].startswith("search <redacted ")
    assert "classes=email" in rows[0]["action_detail"]


def test_security_blocked_action_detail_redacts_auth_code():
    plugin = load_plugin()
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        "terminal",
        {"command": 'echo "Your verification code is 123456"'},
        session_id="s1",
    )

    assert result is not None
    rows = plugin._activity_rows({}, limit=10)
    assert rows[0]["decision"] == "security_blocked"
    assert "123456" not in json.dumps(rows)
    assert "security-sensitive content redacted" in rows[0]["action_detail"]


def test_browser_console_action_detail_redacts_private_expression():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "fetch('/x', {body: 'owner@example.com'})"},
        session_id="s1",
    )

    assert result is not None
    rows = plugin._activity_rows({}, limit=10)
    assert "owner@example.com" not in json.dumps(rows)
    assert "<email>" in rows[0]["action_detail"]


def test_web_search_query_under_taint_requires_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call("web_search", {"query": "python docs"}, session_id="s1")

    assert result is not None
    assert "Action: web_read" in result["message"]
    rows = plugin._activity_rows({}, limit=5)
    assert rows[0]["decision"] == "blocked"
    assert rows[0]["action_family"] == "web_read"
    assert rows[0]["data_classes"] == "email"
    assert "python docs" not in result["message"]
    assert rows[0]["action_detail"] == "search <redacted 11 chars>"


def test_tainted_session_blocks_delegation_model_api_cron_and_local_writes():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    cases = [
        ("delegate_task", {"goal": "summarize this"}, "delegate_task"),
        ("mixture_of_agents", {"user_prompt": "solve this"}, "model_api"),
        ("text_to_speech", {"text": "read this aloud"}, "model_api"),
        ("cronjob", {"action": "create", "prompt": "send a report", "schedule": "1h"}, "cron_write"),
        ("write_file", {"path": "/tmp/report.txt", "content": "summary"}, "local_write"),
        ("patch", {"path": "/tmp/report.txt", "old_string": "a", "new_string": "b"}, "local_write"),
        ("skill_manage", {"action": "create", "name": "private-skill", "content": "steps"}, "local_write"),
        ("memory", {"action": "add", "target": "user", "content": "preference"}, "local_write"),
        ("mnemosyne_remember", {"content": "preference"}, "local_write"),
        ("computer_use", {"action": "type", "text": "hello"}, "computer_use"),
        ("ha_call_service", {"domain": "light", "service": "turn_on"}, "homeassistant_write"),
        ("feishu_drive_add_comment", {"comment": "please review"}, "tool_write"),
    ]

    for tool_name, args, action in cases:
        result = plugin._on_pre_tool_call(tool_name, args, session_id="s1")
        assert result is not None, tool_name
        assert f"Action: {action}" in result["message"], tool_name
