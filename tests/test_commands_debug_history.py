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


def test_dashboard_debugger_uses_safe_metadata(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule(rule_id="rule_debug", data_classes=["communications"])])

    allowed = plugin._debug_decision({
        "action_family": "mcp_write",
        "destination": "mcp:notion",
        "data_classes": "communications",
    })

    assert allowed["decision"] == "allowed"
    assert allowed["source"] == {"source": "persistent", "rule_id": "rule_debug", "effect": "allow"}
    assert allowed["action_family"] == "mcp_write"
    assert allowed["destination"] == "mcp:notion"
    assert allowed["data_classes"] == ["communications"]


def test_guardian_debug_command_reports_gateway_safe_decision(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule(rule_id="rule_debug", data_classes=["communications"])])

    response = plugin._handle_guardian_command(
        "debug action=mcp_write destination=mcp:notion classes=communications tool=mcp_notion_update_page"
    )

    assert "Guardian debug decision" in response
    assert "Decision: allowed" in response
    assert "Action: mcp_write" in response
    assert "Destination: mcp:notion" in response
    assert "Data classes: communications" in response
    assert "Source: persistent rule_debug" in response


def test_guardian_debug_command_accepts_contextual_fields():
    plugin = load_plugin()
    recipient_identity = plugin._recipient_identity_from_value("friend")
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_context_debug",
            action_family="message_send",
            destination="messaging",
            purpose="support",
            recipient_identity=recipient_identity,
            data_classes=["communications"],
        )
    ])

    response = plugin._handle_guardian_command(
        "debug action=message_send destination=messaging classes=communications "
        f"purpose=support recipient={recipient_identity}"
    )

    assert "Decision: allowed" in response
    assert "Purpose: support" in response
    assert f"Recipient identity: {recipient_identity}" in response


def test_guardian_debug_command_does_not_consume_once_approval():
    plugin = load_plugin()
    plugin._ONCE_APPROVALS[plugin._GLOBAL_SESSION_ID] = [{
        "owner_hash": plugin._CLI_OWNER_HASH,
        "action_family": "browser_type",
        "destination": "example.com",
        "data_classes": ["communications"],
        "fingerprint": "debug",
    }]

    first = plugin._handle_guardian_command(
        "debug action=browser_type destination=example.com classes=communications"
    )
    second = plugin._handle_guardian_command(
        "debug action=browser_type destination=example.com classes=communications"
    )

    assert "Decision: allowed" in first
    assert "Decision: allowed" in second
    assert len(plugin._ONCE_APPROVALS[plugin._GLOBAL_SESSION_ID]) == 1


def test_guardian_debug_command_reports_privacy_off(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="off")

    response = plugin._handle_guardian_command(
        "debug action=message_send destination=friend classes=communications"
    )

    assert "Decision: allowed" in response
    assert "Privacy policy: off" in response
    assert "privacy policy is off" in response


def test_guardian_history_command_lists_recent_sanitized_activity():
    plugin = load_plugin()

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"communications"},
        reason="requires approval",
        approval_id="peg_test",
    )
    plugin._emit_activity(
        "allowed",
        session_id="s1",
        tool_name="mcp_notion_update_page",
        action_family="mcp_write",
        destination="mcp:notion",
        data_classes={"documents"},
        reason="matched allow rule",
        rule_source="env",
    )

    response = plugin._handle_guardian_command("history")

    assert "🛡️ **Guardian history** · newest first · 2 shown" in response
    assert "✅ **`mcp_notion_update_page`**" in response
    assert "🏷️ `documents`" in response
    assert "Allowed: matched allow rule (`env`)" in response
    assert "❌ **`send_message`**" in response
    assert "🏷️ `communications`" in response
    assert "Blocked: requires approval (`peg_test`)" in response
    assert "**Action:**" not in response
    assert "**Status:**" not in response
    assert "**Classes:**" not in response
    assert "**Reason:**" not in response
    assert "1. ALLOWED" not in response
    assert "2. BLOCKED" not in response
    assert "-> `n/a`" not in response
    assert response.index("✅ **`mcp_notion_update_page`**") < response.index("Allowed: matched allow rule")


def test_guardian_history_shows_terminal_action_detail():
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_pre_tool_call("terminal", {"command": "pwd | grep root"}, session_id="s1")

    response = plugin._handle_guardian_command("history")

    assert "✅ **`terminal`**" in response
    assert "Action: `pwd | grep root`" in response
    assert "Allowed: no private data in scope" in response


def test_guardian_history_command_groups_quick_same_tool_calls(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_HISTORY_TIMEZONE", "America/Los_Angeles")
    now = {"value": 1780775040}
    monkeypatch.setattr(plugin, "_now", lambda: now["value"])

    for index, offset in enumerate((0, 12, 24), start=1):
        now["value"] = 1780775040 + offset
        plugin._emit_activity(
            "blocked",
            session_id="s1",
            tool_name="browser_type",
            action_family="browser_type",
            destination="example.com",
            data_classes={"communications"},
            reason="requires approval",
            approval_id=f"peg_{index}",
        )

    response = plugin._handle_guardian_command("history")

    assert "🛡️ **Guardian history** · newest first · 1 shown" in response
    assert "❌ **`browser_type`** x3" in response
    assert "Jun 6, 2026 12:44 PM PDT" in response
    assert " - Jun 6, 2026 12:44 PM PDT" not in response
    assert "🏷️ `communications`" in response
    assert "Blocked: requires approval (`peg_3`)" in response
    assert response.count("❌ **`browser_type`**") == 1


def test_guardian_history_command_empty_and_limit_handling():
    plugin = load_plugin()

    assert plugin._handle_guardian_command("history") == "No guardian activity history yet."
    assert plugin._handle_guardian_command("history nope") == "Usage: /guardian history [limit]"

    for index in range(30):
        plugin._emit_activity(
            "blocked",
            session_id=f"s{index}",
            action_family="message_send",
            destination=f"dest-{index}",
            data_classes={"communications"},
            reason="test",
        )

    response = plugin._handle_guardian_command("history 100")

    assert "🛡️ **Guardian history** · newest first · 25 shown" in response
    assert response.count("\n❌ **`message_send`**") == 25
    assert response.count("\nBlocked: test") == 25


def test_guardian_dashboard_is_not_a_chat_command():
    plugin = load_plugin()

    help_text = plugin._handle_guardian_command("help")
    assert "dashboard" not in help_text
    assert help_text.startswith("Usage: /guardian <command>\n")
    assert "\n/guardian status\n" in help_text
    assert "\n/guardian approve <id> once|session|always\n" in help_text
    assert "\n/guardian dismiss <id> (alias: deny)\n" in help_text
    assert "\n/guardian rule enable|disable <rule_id>\n" in help_text
    assert "\n/guardian rule move <rule_id> before|after <other_rule_id>\n" in help_text
    assert "\n/guardian failures [limit]\n" in help_text
    assert plugin._handle_guardian_command("dashboard status") == "Invalid /guardian command. Try /guardian help."


def test_guardian_cli_dashboard_command_reports_integrated_dashboard(capsys):
    plugin = load_plugin()
    parser = argparse.ArgumentParser(prog="hermes guardian")

    plugin._guardian_cli_setup(parser)
    args = parser.parse_args(["dashboard", "status"])
    args.func(args)

    assert capsys.readouterr().out.strip() == "Hermes Guardian is integrated into the Hermes dashboard at /guardian."
