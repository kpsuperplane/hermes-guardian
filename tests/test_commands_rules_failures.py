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


def test_guardian_rule_delete_slash_alias_removes_persistent_rule(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_delete_me",
            action_family="message_send",
            destination="friend",
            data_classes=["email"],
            owner_hash="cli",
        ),
        privacy_rule(
            rule_id="rule_keep",
            action_family="browser_type",
            destination="www.google.com",
            data_classes=["email"],
            owner_hash="cli",
        ),
    ])

    response = plugin._handle_guardian_command("rule delete rule_delete_me")

    assert response == "Deleted privacy rule rule_delete_me."
    data = json.loads((tmp_path / "rules.json").read_text())
    assert [rule["id"] for rule in data["privacy"]["rules"]] == ["rule_keep"]


def test_non_owner_slash_cannot_change_global_privacy_mode():
    plugin = load_plugin()

    plugin._on_pre_gateway_dispatch(gateway_event("/guardian privacy mode off", user_id="attacker"))
    response = plugin._handle_guardian_command("privacy mode off")

    assert "Permission denied" in response
    assert plugin._privacy_policy() == "strict"


def test_guardian_rule_add_defaults_platform_slash_to_caller_scope(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    command = "rule add allow action=message_send destination=friend classes=email"

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian {command}", user_id="kevin"))
    response = plugin._handle_guardian_command(command)

    assert "Added privacy allow rule" in response
    data = json.loads((tmp_path / "rules.json").read_text())
    rule = data["privacy"]["rules"][0]
    assert rule["scope"]["owner_hash"] == plugin._hash_identity("telegram", "kevin")
    assert rule["match"]["data_classes"] == ["email"]


def test_guardian_rule_add_rejects_invalid_classes_and_malformed_args(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None

    response = plugin._handle_guardian_command(
        "rule add allow action=message_send destination=friend classes=emial"
    )
    malformed = plugin._handle_guardian_command(
        "rule add allow action=message_send destination=friend classes=email stray"
    )

    assert "Unknown data class(es): emial" in response
    assert "Expected key=value argument: stray" in malformed
    assert plugin._persistent_privacy_rules() == []


def test_non_owner_slash_cannot_create_global_or_cron_rule(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    global_command = "rule add allow action=message_send destination=friend classes=email owner=*"
    cron_command = "rule add allow action=message_send destination=friend classes=email cron=41c2974734f8"

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian {global_command}", user_id="attacker"))
    global_response = plugin._handle_guardian_command(global_command)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian {cron_command}", user_id="attacker"))
    cron_response = plugin._handle_guardian_command(cron_command)

    assert "Permission denied" in global_response
    assert "Permission denied" in cron_response
    assert plugin._persistent_privacy_rules() == []


def test_guardian_rule_move_requires_target_rule_permission(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    kevin_owner = plugin._hash_identity("telegram", "kevin")
    other_owner = plugin._hash_identity("telegram", "other")
    save_privacy_config(plugin, rules=[
        privacy_rule(rule_id="rule_kevin", destination="friend", data_classes=["email"], owner_hash=kevin_owner),
        privacy_rule(rule_id="rule_other", destination="other", data_classes=["email"], owner_hash=other_owner),
    ])

    command = "rule move rule_kevin after rule_other"
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian {command}", user_id="kevin"))
    response = plugin._handle_guardian_command(command)

    data = json.loads((tmp_path / "rules.json").read_text())
    assert response == "No matching privacy rule found for move."
    assert [rule["id"] for rule in data["privacy"]["rules"]] == ["rule_kevin", "rule_other"]


def test_guardian_rules_command_uses_readable_card_format(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_everywhere",
            effect="allow",
            action_family="mcp_write",
            destination="mcp:notion",
            data_classes=["*"],
        ),
        privacy_rule(
            rule_id="rule_limited",
            effect="deny",
            action_family="browser_type",
            destination="example.com",
            data_classes=["email", "contacts"],
            owner_hash="cli",
            remaining_invocations=3,
            enabled=False,
        ),
    ])

    response = plugin._handle_guardian_command("rules")

    assert "🛡️ **Guardian privacy rules** · mode `strict` · 2 shown" in response
    assert "✅ **ALLOW** `mcp_write -> mcp:notion`" in response
    assert "`rule_everywhere`" in response
    assert "Scope: Runs everywhere" in response
    assert "🏷️ `all data classes`" in response
    assert "⏸️ **DENY (disabled)** `browser_type -> example.com`" in response
    assert "`rule_limited` · 3 invocations left" in response
    assert "Scope: Owner scoped" in response
    assert "🏷️ `contacts,email`" in response
    assert "scope=" not in response
    assert "remaining=" not in response


def test_guardian_failures_command_lists_only_failed_command_activity():
    plugin = load_plugin()

    plugin._emit_activity(
        "allowed",
        session_id="s1",
        tool_name="terminal",
        action_family="terminal_exec",
        destination="terminal",
        reason="no private data in scope",
    )
    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"email"},
        reason="requires approval",
        approval_id="peg_test",
    )
    plugin._emit_activity(
        "security_suppressed",
        session_id="s1",
        tool_name="gmail",
        reason="security-sensitive content",
    )
    plugin._emit_activity(
        "denied",
        session_id="s1",
        tool_name="browser_type",
        action_family="browser_type",
        destination="example.com",
        data_classes={"contacts"},
        reason="requires approval",
    )
    plugin._emit_activity(
        "security_blocked",
        session_id="s1",
        tool_name="terminal",
        action_family="terminal_exec",
        destination="terminal",
        reason="auth code",
    )

    response = plugin._handle_guardian_command("failures")

    assert "🛡️ **Guardian failures** · newest first · 3 shown" in response
    assert "❌ **`terminal`**" in response
    assert "Blocked: auth code" in response
    assert "❌ **`browser_type`**" in response
    assert "Dismissed: requires approval" in response
    assert "❌ **`send_message`**" in response
    assert "Blocked: requires approval (`peg_test`)" in response
    assert "✅ **`terminal`**" not in response
    assert "gmail" not in response


def test_guardian_failures_command_alias_empty_and_limit_handling():
    plugin = load_plugin()

    assert plugin._handle_guardian_command("failures") == "No guardian failure history yet."
    assert plugin._handle_guardian_command("failed nope") == "Usage: /guardian failed [limit]"

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"email"},
        reason="requires approval",
    )
    plugin._emit_activity(
        "blocked",
        session_id="s2",
        tool_name="browser_type",
        action_family="browser_type",
        destination="example.com",
        data_classes={"contacts"},
        reason="requires approval",
    )

    response = plugin._handle_guardian_command("failed 1")

    assert "🛡️ **Guardian failures** · newest first · 1 shown" in response
    assert response.count("\n❌ **`") == 1


def test_guardian_history_command_clarifies_legacy_private_source_reason():
    plugin = load_plugin()

    plugin._emit_activity(
        "tainted",
        session_id="s1",
        tool_name="mcp_gmail_search",
        data_classes={"email"},
        reason="private source result",
    )

    response = plugin._handle_guardian_command("history")

    assert "📥 **`mcp_gmail_search`**" in response
    assert "`mcp_gmail_search` -> `n/a`" not in response
    assert "🏷️ `email`" in response
    assert "Read/result allowed" not in response
    assert "future outbound approval checks" not in response
    assert "private source result" not in response
    assert "🏷️ **TAINTED**" not in response


def test_guardian_history_labels_terminal_taint_as_result():
    plugin = load_plugin()

    plugin._emit_activity(
        "tainted",
        session_id="s1",
        tool_name="terminal",
        data_classes={"local_system"},
        reason="tainted by local system tool result (local_system)",
    )

    response = plugin._handle_guardian_command("history")

    assert "📥 **`terminal result`**" in response
    assert "📥 **`terminal`**" not in response


def test_guardian_history_command_uses_configured_timezone(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_HISTORY_TIMEZONE", "America/Los_Angeles")
    monkeypatch.setattr(plugin, "_now", lambda: 1780775049)

    plugin._emit_activity(
        "allowed",
        session_id="s1",
        tool_name="mcp_notion_update_page",
        data_classes=set(),
        reason="matched allow rule",
    )

    response = plugin._handle_guardian_command("history")

    assert "Jun 6, 2026 12:44 PM PDT" in response
    assert "🏷️ No taints" in response
