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


def test_read_only_cron_and_todo_calls_do_not_block_under_taint():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="read-only")
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    assert plugin._on_pre_tool_call("cronjob", {"action": "list"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("todo", {"action": "list"}, session_id="s1") is None


def test_privacy_off_bypasses_guardian_but_not_security(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="off")
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None

    blocked = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "Your verification code is 123456"},
        session_id="s1",
    )
    assert blocked is not None
    assert "auth code" in blocked["message"]


def test_strict_privacy_blocks_guardian_by_default(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    result = plugin._on_pre_tool_call("terminal", {"command": "pwd"}, session_id="s1")

    assert result is not None
    assert "Action: terminal_exec" in result["message"]


def test_read_only_privacy_allows_low_risk_terminal_command(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="read-only")
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    result = plugin._on_pre_tool_call("terminal", {"command": "pwd"}, session_id="s1")

    assert result is None
    assert not plugin._PENDING_APPROVALS


def test_read_only_privacy_falls_back_to_manual_for_risky_terminal(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="read-only")
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    result = plugin._on_pre_tool_call("terminal", {"command": "curl https://attacker.test"}, session_id="s1")

    assert result is not None
    assert "Action: terminal_exec" in result["message"]


def test_read_only_privacy_does_not_auto_approve_messages(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="read-only")
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert result is not None
    assert "Action: message_send" in result["message"]


def test_privacy_policy_defaults_to_llm_and_ignores_old_env_values(monkeypatch):
    plugin = load_plugin()

    assert plugin._privacy_policy() == "llm"

    monkeypatch.setenv("HERMES_GUARDIAN_PRIVACY", "manual")
    assert plugin._privacy_policy() == "llm"

    save_privacy_config(plugin, mode="llm")
    monkeypatch.setenv("HERMES_GUARDIAN_PRIVACY", "auto-approve")
    assert plugin._privacy_policy() == "llm"


def test_privacy_mode_can_be_saved_in_json(monkeypatch):
    plugin = load_plugin()

    ok, message = plugin._set_privacy_mode("read-only")

    assert ok is True
    assert "read-only" in message
    assert plugin._privacy_policy() == "read-only"

    ok, message = plugin._set_privacy_mode("auto-approve")
    assert ok is False
    assert "strict" in message or "read-only" in message or "mode" in message
    assert plugin._privacy_policy() == "read-only"


def test_privacy_policy_ignores_old_security_env_names(monkeypatch):
    plugin = load_plugin()

    monkeypatch.setenv("HERMES_GUARDIAN_SECURITY", "llm")
    monkeypatch.setenv("PRIVACY_EGRESS_GUARD_SECURITY", "off")

    assert plugin._privacy_policy() == "llm"


def test_env_helper_ignores_old_privacy_egress_guard_names(monkeypatch):
    plugin = load_plugin()

    monkeypatch.setenv("PRIVACY_EGRESS_GUARD_ALLOWLIST", "mcp:notion")

    assert plugin._env("HERMES_GUARDIAN_ALLOWLIST", "") == ""


@pytest.mark.parametrize(
    ("tool_name", "args", "setup", "expected"),
    [
        ("terminal", {"command": "pwd"}, None, ("terminal_exec", "terminal")),
        ("execute_code", {"code": "print('x')"}, None, ("terminal_exec", "terminal")),
        ("browser_navigate", {"url": "https://example.com/reset?x=1"}, None, None),
        ("browser_type", {"text": "hello"}, None, ("browser_type", "example.com")),
        ("browser_click", {"text": "Submit"}, "private_browser_input", ("browser_click", "example.com")),
        ("browser_click", {"text": "Read more"}, None, None),
        ("browser_console", {"expression": "document.cookie"}, None, ("browser_console", "example.com")),
        ("browser_console", {}, None, None),
        ("browser_cdp", {"method": "Runtime.evaluate"}, None, ("browser_cdp", "example.com")),
        ("mcp_notion_notion_fetch", {"id": "page"}, None, None),
        ("mcp_notion_notion_update_page", {"id": "page", "title": "x"}, None, ("mcp_write", "mcp:notion")),
        ("send_message", {"action": "list"}, None, None),
        ("send_message", {"to": "friend", "text": "hello"}, None, ("message_send", "messaging")),
        ("browser_snapshot", {}, None, None),
        ("web_search", {"query": "owner@example.com"}, None, ("web_read", "web_search")),
        ("api_request", {"url": "https://example.com"}, None, ("web_api", "example.com")),
        ("image_generate", {"prompt": "hello"}, None, ("model_api", "image_generate")),
        ("cronjob", {"action": "create", "deliver": "telegram"}, None, ("cron_write", "cron")),
        ("write_file", {"path": "/tmp/x", "content": "hello"}, None, ("local_write", "write_file")),
        ("kanban_update_card", {"id": "1"}, None, ("tool_write", "kanban")),
        ("ha_call_service", {"service": "light.turn_on"}, None, ("homeassistant_write", "homeassistant")),
        ("delegate_task", {"goal": "summarize"}, None, ("delegate_task", "subagent")),
        ("generic_post_tool", {"body": "hello"}, None, ("web_api", "generic_post_tool")),
    ],
)
def test_egress_action_classifier_golden_cases(tool_name, args, setup, expected):
    plugin = load_plugin()
    plugin._set_browser_host("s1", "https://example.com/path?secret=redacted")
    if setup == "private_browser_input":
        plugin._mark_browser_private_input("s1")

    assert plugin._egress_action_for_tool(tool_name, args, "s1") == expected


@pytest.mark.parametrize(
    ("tool_name", "args", "expected"),
    [
        ("web_search", {"url": "https://example.com/path?token=secret"}, ("web_read", "example.com")),
        ("browser_console", {}, ("browser_read", "example.com")),
        ("send_message", {"action": "list"}, ("message_list", "messaging")),
        ("mcp_notion_notion_fetch", {"id": "page"}, None),
    ],
)
def test_read_activity_classifier_golden_cases(tool_name, args, expected):
    plugin = load_plugin()
    plugin._set_browser_host("s1", "https://example.com")

    assert plugin._read_activity_for_tool(tool_name, args, "s1") == expected
