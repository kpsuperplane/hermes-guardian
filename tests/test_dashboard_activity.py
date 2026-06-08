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


def test_dashboard_payload_filters_activity_by_decision():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    plugin._on_pre_tool_call("browser_navigate", {"url": "https://example.com"}, session_id="s1")

    payload = plugin._dashboard_payload({"decision": "blocked"}, limit=10)

    assert payload["policy"]["privacy_policy"] == "llm"
    assert payload["activity"]
    assert all(row["decision"] == "blocked" for row in payload["activity"])


def test_activity_rows_and_datatables_include_contextual_metadata():
    plugin = load_plugin()
    recipient_identity = plugin._recipient_identity_from_value("friend")

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="send_message",
        action_family="message_send",
        destination="messaging",
        purpose="support",
        recipient_identity=recipient_identity,
        data_classes={"email"},
        reason="requires approval",
    )

    row = plugin._activity_rows({}, limit=1)[0]
    payload = plugin._activity_datatables_payload({
        "draw": "1",
        "start": "0",
        "length": "25",
        "purpose": "support",
        "recipient_identity": recipient_identity,
    })

    assert row["purpose"] == "support"
    assert row["recipient_identity"] == recipient_identity
    assert payload["recordsFiltered"] == 1
    assert payload["data"][0]["purpose"] == "support"
    assert payload["data"][0]["recipient_identity"] == recipient_identity


def test_datatables_payload_paginates_and_counts(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin, "_now", lambda: now["value"])

    for index in range(30):
        now["value"] = 1000 + index
        plugin._emit_activity(
            "blocked",
            session_id=f"s{index}",
            tool_name=f"tool_{index:02d}",
            action_family="message_send",
            destination="friend",
            data_classes={"email"},
            reason=f"requires approval {index}",
        )

    first = plugin._activity_datatables_payload({"draw": "7", "start": "0", "length": "25"})
    second = plugin._activity_datatables_payload({"draw": "8", "start": "25", "length": "25"})

    assert first["draw"] == 7
    assert first["recordsTotal"] == 30
    assert first["recordsFiltered"] == 30
    assert len(first["data"]) == 25
    assert first["data"][0]["tool"] == "tool_29"
    assert len(second["data"]) == 5
    assert second["data"][-1]["tool"] == "tool_00"


def test_datatables_payload_search_and_filters_sanitized_metadata():
    plugin = load_plugin()

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="terminal",
        action_family="terminal_exec",
        destination="terminal",
        data_classes={"local_system"},
        reason="requires approval",
        action_detail="pwd | grep root",
    )
    plugin._emit_activity(
        "allowed",
        session_id="s2",
        tool_name="mcp_notion_update_page",
        action_family="mcp_write",
        destination="mcp:notion",
        data_classes={"documents"},
        reason="matched allow rule",
    )

    searched = plugin._activity_datatables_payload({
        "draw": "1",
        "start": "0",
        "length": "25",
        "search[value]": "grep root",
    })
    filtered = plugin._activity_datatables_payload({
        "draw": "2",
        "start": "0",
        "length": "25",
        "decision": "allowed",
        "data_class": "documents",
    })

    assert searched["recordsTotal"] == 2
    assert searched["recordsFiltered"] == 1
    assert searched["data"][0]["tool"] == "terminal"
    assert searched["data"][0]["action_detail"] == "pwd | grep root"
    assert filtered["recordsFiltered"] == 1
    assert filtered["data"][0]["tool"] == "mcp_notion_update_page"


def test_datatables_payload_sort_whitelist_and_invalid_sort_fallback(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin, "_now", lambda: now["value"])

    for index, tool in enumerate(["zeta", "alpha"]):
        now["value"] = 1000 + index
        plugin._emit_activity("blocked", session_id=f"s{index}", tool_name=tool, reason=tool)

    sorted_payload = plugin._activity_datatables_payload({
        "draw": "1",
        "start": "0",
        "length": "25",
        "order[0][column]": "3",
        "order[0][dir]": "asc",
        "columns[3][data]": "tool",
    })
    fallback_payload = plugin._activity_datatables_payload({
        "draw": "2",
        "start": "0",
        "length": "25",
        "order[0][column]": "99",
        "order[0][dir]": "asc",
        "columns[99][data]": "not_a_real_column",
    })

    assert [row["tool"] for row in sorted_payload["data"]] == ["alpha", "zeta"]
    assert [row["tool"] for row in fallback_payload["data"]] == ["alpha", "zeta"]


def test_activity_grouping_collapses_quick_same_tool_calls():
    plugin = load_plugin()
    rows = [
        {
            "id": 3,
            "ts": 130,
            "decision": "allowed",
            "mode": "strict",
            "session_hash": "s1",
            "tool_name": "mcp_notion_update_page",
            "action_family": "mcp_write",
            "destination": "mcp:notion",
            "data_classes": "documents",
            "reason": "matched allow rule",
            "approval_id": "",
            "rule_id": "env_1",
            "rule_source": "env",
        },
        {
            "id": 2,
            "ts": 120,
            "decision": "allowed",
            "mode": "strict",
            "session_hash": "s1",
            "tool_name": "mcp_notion_update_page",
            "action_family": "mcp_write",
            "destination": "mcp:notion",
            "data_classes": "documents",
            "reason": "matched allow rule",
            "approval_id": "",
            "rule_id": "env_1",
            "rule_source": "env",
        },
        {
            "id": 1,
            "ts": 90,
            "decision": "allowed",
            "mode": "strict",
            "session_hash": "s1",
            "tool_name": "mcp_notion_update_page",
            "action_family": "mcp_write",
            "destination": "mcp:notion",
            "data_classes": "documents",
            "reason": "matched allow rule",
            "approval_id": "",
            "rule_id": "env_1",
            "rule_source": "env",
        },
    ]

    grouped = plugin._group_activity_rows(rows, window_seconds=60)

    assert len(grouped) == 1
    assert grouped[0]["count"] == 3
    assert grouped[0]["ts"] == 130
    assert grouped[0]["first_ts"] == 90
    assert grouped[0]["grouped"] is True


def test_activity_grouping_keeps_distinct_or_old_calls_separate():
    plugin = load_plugin()
    base = {
        "decision": "blocked",
        "mode": "strict",
        "session_hash": "s1",
        "tool_name": "browser_type",
        "action_family": "browser_type",
        "destination": "example.com",
        "data_classes": "email",
        "reason": "requires approval",
        "approval_id": "peg_latest",
        "rule_id": "",
        "rule_source": "",
    }
    rows = [
        dict(base, id=3, ts=200),
        dict(base, id=2, ts=170, destination="other.example"),
        dict(base, id=1, ts=100),
    ]

    grouped = plugin._group_activity_rows(rows, window_seconds=60)

    assert len(grouped) == 3
    assert [row["count"] for row in grouped] == [1, 1, 1]


def test_dashboard_payload_groups_quick_activity(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin, "_now", lambda: now["value"])

    for offset in (0, 5, 10):
        now["value"] = 1000 + offset
        plugin._emit_activity(
            "tainted",
            session_id="s1",
            tool_name="mcp_notion_notion_fetch",
            data_classes={"documents"},
            reason="private source result",
        )

    payload = plugin._dashboard_payload(limit=10)

    assert len(payload["activity"]) == 1
    assert payload["activity"][0]["tool_name"] == "mcp_notion_notion_fetch"
    assert payload["activity"][0]["count"] == 3
    assert payload["policy"]["activity_group_seconds"] == 60
