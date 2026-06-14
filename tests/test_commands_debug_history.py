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

    response = plugin._guardian_debug_command(
        ["debug", "action=mcp_write", "destination=mcp:notion", "classes=communications", "tool=mcp_notion_update_page"]
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

    response = plugin._guardian_debug_command(
        [
            "debug",
            "action=message_send",
            "destination=messaging",
            "classes=communications",
            "purpose=support",
            f"recipient={recipient_identity}",
        ]
    )

    assert "Decision: allowed" in response
    assert "Purpose: support" in response
    assert f"Recipient identity: {recipient_identity}" in response


def test_guardian_debug_command_does_not_consume_expiring_rule():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            action_family="browser_type",
            destination="example.com",
            data_classes=["communications"],
            owner_hash=plugin._CLI_OWNER_HASH,
            expires_at=int(plugin.state._now() + 300),
        )
    ])

    first = plugin._guardian_debug_command(
        ["debug", "action=browser_type", "destination=example.com", "classes=communications"]
    )
    second = plugin._guardian_debug_command(
        ["debug", "action=browser_type", "destination=example.com", "classes=communications"]
    )

    assert "Decision: allowed" in first
    assert "Decision: allowed" in second
    assert len(plugin._persistent_privacy_rules()) == 1


def test_guardian_debug_command_reports_privacy_off(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="off")

    response = plugin._guardian_debug_command(
        ["debug", "action=message_send", "destination=friend", "classes=communications"]
    )

    assert "Decision: allowed" in response
    assert "Egress Safety: off" in response
    assert "Egress Safety is off" in response


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

    response = plugin._handle_guardian_command("activity")

    # Both checks share one session -> one turn with two nested checks, newest first.
    assert "🛡️ **Guardian activity** — newest first — 1 turn" in response
    assert "2 checks" in response
    assert "- ✅ `mcp_notion_update_page` · `documents`" in response
    assert "allowed · matched allow rule (env)" in response
    assert "- ❌ `send_message` · `communications`" in response
    assert "blocked · requires approval (peg_test)" in response
    assert response.index("mcp_notion_update_page") < response.index("send_message")


def test_guardian_history_shows_terminal_action_detail():
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_pre_tool_call("terminal", {"command": "pwd | grep root"}, session_id="s1")

    response = plugin._handle_guardian_command("activity")

    assert "- ✅ `terminal`" in response
    assert "Action:" not in response
    assert "allowed · no private data in scope" in response


def test_guardian_activity_lists_each_check_within_a_turn(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_HISTORY_TIMEZONE", "America/Los_Angeles")
    now = {"value": 1780775040}
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])

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

    response = plugin._handle_guardian_command("activity")

    # One session -> one turn; each check is listed individually (no metadata collapsing).
    assert "🛡️ **Guardian activity** — newest first — 1 turn" in response
    assert "3 checks" in response
    assert response.count("- ❌ `browser_type` · `communications`") == 3
    assert "Jun 6, 2026 12:44 PM PDT" not in response
    assert "blocked · requires approval (peg_3)" in response


def test_guardian_history_command_empty_and_limit_handling():
    plugin = load_plugin()

    assert plugin._handle_guardian_command("activity") == "No guardian activity history yet."
    assert plugin._handle_guardian_command("activity nope") == "Usage: /guardian activity [limit]"

    for index in range(30):
        plugin._emit_activity(
            "blocked",
            session_id=f"s{index}",
            action_family="message_send",
            destination=f"dest-{index}",
            data_classes={"communications"},
            reason="test",
        )

    response = plugin._handle_guardian_command("activity 100")

    # 30 distinct sessions -> 30 single-check turns; the limit clamps to 25 turns.
    assert "🛡️ **Guardian activity** — newest first — 25 turns" in response
    assert response.count("- ❌ `message_send` · `communications`") == 25
    assert response.count("\n    - blocked · test") == 25


def test_guardian_activity_default_limit_is_five_turns():
    plugin = load_plugin()

    for index in range(6):
        plugin._emit_activity(
            "blocked",
            session_id=f"s{index}",
            action_family="message_send",
            destination=f"dest-{index}",
            data_classes={"communications"},
            reason=f"test-{index}",
        )

    response = plugin._handle_guardian_command("activity")

    assert "🛡️ **Guardian activity** — newest first — 5 turns" in response
    assert response.count("- ❌ `message_send` · `communications`") == 5
    assert "test-5" in response
    assert "test-0" not in response


def test_guardian_dashboard_is_not_a_chat_command():
    plugin = load_plugin()

    help_text = plugin._handle_guardian_command("help")
    assert "dashboard" not in help_text
    assert help_text.startswith("/guardian — privacy firewall for your agent")
    # The five concepts appear in `decide` order, with status/why on top.
    assert help_text.index("status") < help_text.index("ACTIVITY")
    for heading in ("ACTIVITY", "WHAT'S YOURS", "SHARING", "REVIEW", "PROTECTION"):
        assert heading in help_text
    assert (
        help_text.index("ACTIVITY")
        < help_text.index("WHAT'S YOURS")
        < help_text.index("SHARING")
        < help_text.index("REVIEW")
        < help_text.index("PROTECTION")
    )
    assert plugin._handle_guardian_command("dashboard status") == "Invalid /guardian command. Try /guardian help."


def test_guardian_cli_dashboard_command_reports_integrated_dashboard(capsys):
    plugin = load_plugin()
    parser = argparse.ArgumentParser(prog="hermes guardian")

    plugin._guardian_cli_setup(parser)
    args = parser.parse_args(["dashboard", "status"])
    args.func(args)

    assert capsys.readouterr().out.strip() == "Hermes Guardian is integrated into the Hermes dashboard at /guardian."
