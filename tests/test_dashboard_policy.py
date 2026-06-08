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


def test_policy_snapshot_compacts_all_class_privacy_rule(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule(rule_id="rule_all", data_classes=["*"])])

    policy = plugin._policy_snapshot()

    assert policy["rules"][0]["rule_id"] == "rule_all"
    assert policy["rules"][0]["data_classes"] == ["*"]


def test_policy_snapshot_includes_cron_rule_scope(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    plugin._CORE._cron_job_name = lambda job_id: "Ritz-Carlton AX 2026 availability check" if job_id == "41c2974734f8" else ""
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_test",
            action_family="browser_type",
            destination="www.google.com",
            data_classes=["email"],
            cron_job_id="41c2974734f8",
            cron_job_name="Ritz-Carlton AX 2026 availability check",
        )
    ])

    policy = plugin._policy_snapshot()
    rule = policy["rules"][0]

    assert rule["action_family"] == "browser_type"
    assert rule["destination"] == "www.google.com"
    assert rule["cron_job_id"] == "41c2974734f8"
    assert rule["cron_job_name"] == "Ritz-Carlton AX 2026 availability check"
    assert rule["scope"] == "cron job Ritz-Carlton AX 2026 availability check (41c2974734f8)"


def test_policy_snapshot_includes_persistent_rule_metadata(tmp_path):
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
        )
    ])

    policy = plugin._policy_snapshot()
    rule = policy["rules"][0]

    assert rule["rule_id"] == "rule_delete_me"
    assert rule["action_family"] == "message_send"
    assert rule["destination"] == "friend"
    assert rule["data_classes"] == ["email"]
    assert rule["owner_hash"] == "cli"


def test_policy_snapshot_includes_rule_form_suggestions(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    rule = privacy_rule(
        rule_id="rule_suggest",
        action_family="mcp_write",
        destination="mcp:notion",
        data_classes=["documents"],
    )
    rule["match"]["tool_name"] = "mcp_notion_update_page"
    save_privacy_config(plugin, rules=[rule])
    plugin._emit_activity(
        "blocked",
        tool_name="browser_type",
        action_family="browser_type",
        destination="example.com",
        data_classes=["email"],
    )

    policy = plugin._policy_snapshot()

    assert "mcp:notion" in policy["destination_suggestions"]
    assert "example.com" in policy["destination_suggestions"]
    assert "mcp_notion_update_page" in policy["tool_name_suggestions"]
    assert "browser_type" in policy["tool_name_suggestions"]
    assert "*" not in policy["destination_suggestions"]
    assert policy["suggestions"]["destinations"] == policy["destination_suggestions"]
    assert policy["suggestions"]["tool_names"] == policy["tool_name_suggestions"]


def test_dashboard_rule_delete_action_removes_persistent_rule(tmp_path):
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

    payload, status = plugin._dashboard_rule_delete_action("rule_delete_me")

    assert status == 200
    assert payload["ok"] is True
    assert "Deleted privacy rule rule_delete_me" in payload["message"]
    data = json.loads((tmp_path / "rules.json").read_text())
    assert [rule["id"] for rule in data["privacy"]["rules"]] == ["rule_keep"]
    assert [rule["rule_id"] for rule in payload["policy"]["rules"]] == ["rule_keep"]


def test_policy_snapshot_includes_five_recent_unresolved_blocks(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin, "_now", lambda: now["value"])
    approval_ids = []

    for index in range(6):
        session_id = f"s{index}"
        bind_owner(plugin, session_id=session_id)
        plugin._taint_session(session_id, {"email"})
        before = set(plugin._PENDING_APPROVALS)
        now["value"] = 1000 + index
        plugin._on_pre_tool_call("send_message", {"to": f"friend-{index}", "text": "hello"}, session_id=session_id)
        new_ids = set(plugin._PENDING_APPROVALS) - before
        assert len(new_ids) == 1
        approval_ids.append(new_ids.pop())

    policy = plugin._policy_snapshot()

    assert len(policy["recent_blocks"]) == 5
    assert [block["id"] for block in policy["recent_blocks"]] == list(reversed(approval_ids[1:]))
    assert policy["recent_blocks"][0]["reason"].startswith("requires approval")
    assert policy["recent_blocks"][0]["action_family"] == "message_send"
    assert policy["recent_blocks"][0]["pending"] is True


def test_policy_snapshot_marks_pending_block_covered_by_new_allow_rule(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_cover_friend",
            action_family="message_send",
            destination="friend",
            data_classes=["email"],
            remaining_invocations=1,
        )
    ])

    policy = plugin._policy_snapshot()
    block = policy["recent_blocks"][0]
    rules = plugin._persistent_privacy_rules()

    assert block["id"] == approval_id
    assert block["pending"] is True
    assert block["covered_by_rule"] is True
    assert block["covered_rule_id"] == "rule_cover_friend"
    assert block["covered_rule_source"] == "persistent"
    assert rules[0]["remaining_invocations"] == 1


def test_policy_snapshot_does_not_mark_pending_block_covered_by_new_deny_rule(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_deny_friend",
            effect="deny",
            action_family="message_send",
            destination="friend",
            data_classes=["email"],
        )
    ])

    policy = plugin._policy_snapshot()
    block = policy["recent_blocks"][0]

    assert block["id"] == approval_id
    assert block["pending"] is True
    assert block["covered_by_rule"] is False
    assert block["covered_rule_id"] == ""


def test_policy_snapshot_recent_blocks_includes_hard_blocks_without_pending_approval():
    plugin = load_plugin()

    plugin._emit_activity(
        "security_blocked",
        session_id="cron_f530ee708b98_20260607_231047",
        tool_name="terminal",
        action_family="terminal_exec",
        destination="terminal",
        data_classes={"local_system"},
        reason="explicit malicious or credential-exfiltration pattern",
        module="privacy",
    )

    policy = plugin._policy_snapshot()
    block = policy["recent_blocks"][0]

    assert block["decision"] == "security_blocked"
    assert block["pending"] is False
    assert block["approval_id"] == ""
    assert block["tool_name"] == "terminal"
    assert block["action_family"] == "terminal_exec"
    assert block["destination"] == "terminal"


def test_dashboard_approval_actions_remove_pending_blocks():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    payload, status = plugin._dashboard_approval_action(approval_id, "approve", "once")

    assert status == 200
    assert payload["ok"] is True
    assert approval_id not in plugin._PENDING_APPROVALS
    assert payload["policy"]["recent_blocks"][0]["pending"] is False
    assert payload["policy"]["recent_blocks"][0]["approval_id"] == ""
    assert len(payload["policy"]["rules"]) == 1
    rule = payload["policy"]["rules"][0]
    assert rule["action_family"] == "message_send"
    assert rule["destination"] == "friend"
    assert rule["remaining_invocations"] == 1

    bind_owner(plugin, session_id="s2")
    plugin._taint_session("s2", {"email"})
    plugin._on_pre_tool_call("send_message", {"to": "other-friend", "text": "hello"}, session_id="s2")
    approval_id = first_pending_id(plugin)

    payload, status = plugin._dashboard_approval_action(approval_id, "dismiss")

    assert status == 200
    assert payload["ok"] is True
    assert approval_id not in plugin._PENDING_APPROVALS
    assert payload["policy"]["recent_blocks"][0]["pending"] is False
    assert payload["policy"]["recent_blocks"][0]["approval_id"] == ""
    assert payload["policy"]["recent_blocks"][0]["decision"] == "denied"


def test_datatables_payload_labels_terminal_taint_as_result():
    plugin = load_plugin()

    plugin._emit_activity(
        "tainted",
        session_id="s1",
        tool_name="terminal",
        data_classes={"local_system"},
        reason="tainted by local system tool result (local_system)",
    )
    payload = plugin._activity_datatables_payload({"draw": "1", "start": "0", "length": "25"})

    assert payload["data"][0]["tool"] == "terminal result"


def test_datatables_payload_shows_terminal_action_detail():
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_pre_tool_call("terminal", {"command": "pwd | grep root"}, session_id="s1")
    payload = plugin._activity_datatables_payload({"draw": "1", "start": "0", "length": "25"})

    assert payload["data"][0]["action_detail"] == "pwd | grep root"


def test_activity_reason_preserves_long_llm_rationale():
    plugin = load_plugin()
    long_reason = "llm low: " + "safe public read. " * 30

    plugin._emit_activity(
        "auto_approved",
        session_id="s1",
        tool_name="terminal",
        action_family="terminal_exec",
        destination="terminal",
        data_classes={"local_system"},
        reason=long_reason,
        rule_source="llm",
    )

    row = plugin._activity_rows({}, limit=1)[0]
    assert row["reason"] == long_reason
    assert len(row["reason"]) > 200


def test_datatables_payload_exposes_full_long_reason():
    plugin = load_plugin()
    long_reason = "llm low: " + "safe public read. " * 30

    plugin._emit_activity(
        "auto_approved",
        session_id="s1",
        tool_name="terminal",
        action_family="terminal_exec",
        destination="terminal",
        data_classes={"local_system"},
        reason=long_reason,
        rule_source="llm",
    )
    payload = plugin._activity_datatables_payload({"draw": "1", "start": "0", "length": "25"})

    assert payload["data"][0]["reason"] == long_reason.strip()
    assert payload["data"][0]["reason_short"].startswith("Allowed: llm low")
    assert len(payload["data"][0]["reason_short"]) < len(long_reason)


def test_activity_presentation_helpers_keep_datatables_and_history_consistent(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_HISTORY_TIMEZONE", "America/Los_Angeles")
    monkeypatch.setattr(plugin, "_now", lambda: 1780775049)

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="browser_type",
        action_family="browser_type",
        destination="example.com",
        data_classes={"email", "contacts"},
        reason="requires approval",
        approval_id="amber-bridge-1234",
        action_detail="type into example.com: <redacted 42 chars; classes=email>",
    )

    row = plugin._grouped_activity_rows({}, limit=1)[0]
    datatables_row = plugin._activity_datatables_payload({"draw": "1", "start": "0", "length": "25"})["data"][0]
    history = plugin._handle_guardian_command("history")

    assert plugin._activity_status_icon(row["decision"]) == "❌"
    assert plugin._activity_time_text(row) == "Jun 6, 2026 12:44 PM PDT"
    assert plugin._activity_taints_text(row, code=True) == "🏷️ `contacts,email`"
    assert plugin._activity_reason_line_text(row) == "Blocked: requires approval (`amber-bridge-1234`)"
    assert datatables_row["icon"] == "❌"
    assert datatables_row["time"] == "Jun 6, 2026 12:44 PM PDT"
    assert datatables_row["data_classes"] == "contacts,email"
    assert datatables_row["reason_short"] == "Blocked: requires approval"
    assert "Jun 6, 2026 12:44 PM PDT" in history
    assert "🏷️ `contacts,email`" in history
    assert "Blocked: requires approval (`amber-bridge-1234`)" in history


def test_activity_action_detail_keeps_safe_raw_command_but_redacts_security_sensitive_text():
    plugin = load_plugin()

    safe_detail = plugin._activity_action_detail("terminal", {"command": "pwd | grep root"}, "terminal_exec", "terminal")
    sensitive_detail = plugin._activity_action_detail(
        "terminal",
        {"command": "echo 'Your verification code is 123456'"},
        "terminal_exec",
        "terminal",
    )

    assert safe_detail == "pwd | grep root"
    assert sensitive_detail == "<security-sensitive content redacted: auth code>"
    assert "123456" not in sensitive_detail


def test_activity_prune_limits_max_rows(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_MAX_ROWS", "3")
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS", "0")

    for index in range(6):
        plugin._emit_activity(
            "blocked",
            session_id=f"s{index}",
            tool_name="send_message",
            action_family="message_send",
            destination=f"dest-{index}",
            data_classes={"email"},
            reason="test",
        )

    result = plugin._prune_activity_db(force=True)
    rows = plugin._activity_rows({}, limit=10)

    assert result["remaining"] == 3
    assert len(rows) == 3


def test_activity_prune_limits_retention_days(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_MAX_ROWS", "0")
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS", "1")

    plugin._emit_activity("blocked", session_id="old", reason="old")
    plugin._emit_activity("blocked", session_id="new", reason="new")
    with plugin._activity_connect() as conn:
        conn.execute("UPDATE activity SET ts = ? WHERE reason = ?", (1, "old"))

    result = plugin._prune_activity_db(force=True)
    rows = plugin._activity_rows({}, limit=10)

    assert result["remaining"] == 1
    assert rows[0]["reason"] == "new"
