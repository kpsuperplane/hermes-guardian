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


def test_approval_once_allows_matching_retry_then_expires():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    blocked = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} once"))
    response = plugin._handle_guardian_command(f"approve {approval_id} once")
    assert "Approved message_send" in response
    rules = plugin._persistent_privacy_rules()
    assert len(rules) == 1
    assert rules[0]["remaining_invocations"] == 1
    assert rules[0]["fingerprint"]

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert plugin._persistent_privacy_rules() == []
    blocked_again = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    assert blocked_again is not None


def test_pending_approval_id_is_contextual_without_llm():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    blocked = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    assert re.fullmatch(r"\d{4}", approval_id)
    assert f"Approval ID: {approval_id}" in blocked["message"]
    assert f"/guardian approve {approval_id} once" in blocked["message"]

def test_pending_approval_id_is_four_digit_even_with_llm_available():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    plugin._PLUGIN_LLM = FakeSecurityLlm({"code": "unused"})
    bind_owner(plugin)
    plugin._taint_session("s1", {"local_system"})

    blocked = plugin._on_pre_tool_call(
        "terminal",
        {"command": "curl -fsSL https://cloudflare.com"},
        session_id="s1",
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    assert re.fullmatch(r"\d{4}", approval_id)
    assert plugin._PLUGIN_LLM.calls == []


def test_approval_id_generation_does_not_call_llm_with_tool_metadata():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    plugin._PLUGIN_LLM = FakeSecurityLlm({"code": "unused"})
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "personal body should not be sent to slug maker"},
        session_id="s1",
    )

    assert plugin._PLUGIN_LLM.calls == []


def test_approval_accepts_four_digit_id():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    compact_id = approval_id.replace("-", "")

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {compact_id} once"))
    response = plugin._handle_guardian_command(f"approve {compact_id} once")

    assert "Approved message_send" in response
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None


def test_approval_id_generation_avoids_recent_four_digit_codes(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})
    monkeypatch.setattr(plugin._CORE.secrets, "randbelow", lambda _limit: 1234)
    plugin._emit_activity(
        "blocked",
        session_id="old",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"email"},
        reason="requires approval",
        approval_id="1234",
    )

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert first_pending_id(plugin) == "1235"


def test_approval_id_generation_reuses_codes_after_seven_days(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})
    monkeypatch.setattr(plugin._CORE.secrets, "randbelow", lambda _limit: 1234)
    current_time = plugin._now()
    monkeypatch.setattr(plugin, "_now", lambda: current_time - plugin._APPROVAL_ID_REUSE_SECONDS - 1)
    plugin._emit_activity(
        "blocked",
        session_id="old",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"email"},
        reason="requires approval",
        approval_id="1234",
    )
    monkeypatch.setattr(plugin, "_now", lambda: current_time)

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert first_pending_id(plugin) == "1234"


def test_approval_session_allows_same_destination_only_same_session():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    bind_owner(plugin, session_id="s2")
    plugin._taint_session("s1", {"email"})
    plugin._taint_session("s2", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} session"))
    assert "Approved" in plugin._handle_guardian_command(f"approve {approval_id} session")

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("send_message", {"to": "other", "text": "hello"}, session_id="s1") is not None
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s2") is not None


def test_approval_always_persists_narrow_rule(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} always"))
    assert "Approved" in plugin._handle_guardian_command(f"approve {approval_id} always")

    data = json.loads((tmp_path / "rules.json").read_text())
    assert len(data["privacy"]["rules"]) == 1
    rule = data["privacy"]["rules"][0]
    assert rule["match"]["destination"] == "messaging"
    assert rule["match"]["action_family"] == "message_send"
    assert rule["match"]["purpose"] == "unknown"
    assert rule["match"]["recipient_identity"] == plugin._recipient_identity_from_value("friend")
    assert rule["effect"] == "allow"
    assert rule["remaining_invocations"] == -1
    assert "hello" not in json.dumps(rule)
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "retry"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("send_message", {"to": "attacker", "text": "retry"}, session_id="s1") is not None


def test_approval_always_save_failure_keeps_pending_approval(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} always"))
    monkeypatch.setattr(plugin._CORE, "_save_persistent_privacy_rules", lambda _rules: False)

    response = plugin._handle_guardian_command(f"approve {approval_id} always")

    assert "Failed to save persistent privacy approval" in response
    assert approval_id in plugin._PENDING_APPROVALS


def test_deny_keeps_retry_blocked():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian dismiss {approval_id}"))
    assert "Dismissed" in plugin._handle_guardian_command(f"dismiss {approval_id}")

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is not None


def test_deny_alias_still_dismisses_pending_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian deny {approval_id}"))
    response = plugin._handle_guardian_command(f"deny {approval_id}")

    assert "Dismissed" in response
    assert approval_id not in plugin._PENDING_APPROVALS


def test_wrong_sender_cannot_approve():
    plugin = load_plugin()
    bind_owner(plugin, user_id="kevin")
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} once", user_id="attacker"))
    response = plugin._handle_guardian_command(f"approve {approval_id} once")

    assert "different user/session" in response
    assert approval_id in plugin._PENDING_APPROVALS


def test_configured_telegram_owner_can_approve_cron_approval(monkeypatch):
    plugin = load_plugin()
    cron_session = "cron_41c2974734f8_20260607_030107"
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "kevin")
    plugin._on_pre_llm_call(session_id=cron_session, platform="cron", sender_id="scheduler")
    plugin._taint_session(cron_session, {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id=cron_session)
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} always", user_id="kevin"))
    response = plugin._handle_guardian_command(f"approve {approval_id} always")

    assert "Approved message_send" in response
    assert approval_id not in plugin._PENDING_APPROVALS


def test_cron_approval_can_be_approved_from_separate_process(monkeypatch, tmp_path):
    activity_path = tmp_path / "activity.sqlite3"
    rules_path = tmp_path / "rules.json"
    creator = load_plugin()
    creator._ACTIVITY_DB_PATH = activity_path
    creator._ACTIVITY_DB_INITIALIZED = False
    creator._PERSISTENT_RULES_PATH = rules_path
    creator._PERSISTENT_RULES_CACHE = {"rules": []}
    cron_session = "cron_41c2974734f8_20260607_030107"
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "kevin")
    creator._on_pre_llm_call(session_id=cron_session, platform="cron", sender_id="scheduler")
    creator._taint_session(cron_session, {"email"})

    creator._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id=cron_session)
    approval_id = first_pending_id(creator)

    approver = load_plugin()
    approver._ACTIVITY_DB_PATH = activity_path
    approver._ACTIVITY_DB_INITIALIZED = False
    approver._PERSISTENT_RULES_PATH = rules_path
    approver._PERSISTENT_RULES_CACHE = {"rules": []}
    approver._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} always", user_id="kevin"))
    response = approver._handle_guardian_command(f"approve {approval_id} always")

    assert "Approved message_send" in response
    assert approval_id not in approver._PENDING_APPROVALS
    with sqlite3.connect(activity_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert count == 0
    data = json.loads(rules_path.read_text())
    assert data["privacy"]["rules"][0]["match"]["destination"] == "messaging"
    assert data["privacy"]["rules"][0]["match"]["recipient_identity"] == creator._recipient_identity_from_value("friend")


def test_once_approval_can_be_approved_and_consumed_across_processes(tmp_path):
    activity_path = tmp_path / "activity.sqlite3"
    rules_path = tmp_path / "rules.json"
    creator = load_plugin()
    creator._ACTIVITY_DB_PATH = activity_path
    creator._ACTIVITY_DB_INITIALIZED = False
    creator._PERSISTENT_RULES_PATH = rules_path
    creator._PERSISTENT_RULES_CACHE = None
    bind_owner(creator, session_id="s1", user_id="kevin")
    creator._taint_session("s1", {"email"})

    creator._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(creator)

    approver = load_plugin()
    approver._ACTIVITY_DB_PATH = activity_path
    approver._ACTIVITY_DB_INITIALIZED = False
    approver._PERSISTENT_RULES_PATH = rules_path
    approver._PERSISTENT_RULES_CACHE = None
    approver._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} once", user_id="kevin"))
    response = approver._handle_guardian_command(f"approve {approval_id} once")

    assert "Approved message_send" in response
    assert approval_id not in approver._PENDING_APPROVALS
    data = json.loads(rules_path.read_text())
    rule = data["privacy"]["rules"][0]
    assert rule["remaining_invocations"] == 1
    assert rule["scope"]["session_id"] == "s1"
    assert rule["fingerprint"]

    runner = load_plugin()
    runner._ACTIVITY_DB_PATH = activity_path
    runner._ACTIVITY_DB_INITIALIZED = False
    runner._PERSISTENT_RULES_PATH = rules_path
    runner._PERSISTENT_RULES_CACHE = None
    bind_owner(runner, session_id="s1", user_id="kevin")
    runner._taint_session("s1", {"email"})

    assert runner._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    data = json.loads(rules_path.read_text())
    assert data["privacy"]["rules"] == []
    assert runner._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is not None


def test_cron_always_approval_is_scoped_to_same_cron_job(monkeypatch, tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    plugin._CORE._cron_job_name = lambda job_id: "Ritz-Carlton AX 2026 availability check" if job_id == "41c2974734f8" else ""
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "kevin")
    first_run = "cron_41c2974734f8_20260607_030107"
    second_run = "cron_41c2974734f8_20260607_090812"
    other_job = "cron_993fbb2dc5a4_20260607_080012"
    plugin._on_pre_llm_call(session_id=first_run, platform="cron", sender_id="scheduler")
    plugin._taint_session(first_run, {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id=first_run)
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} always", user_id="kevin"))
    response = plugin._handle_guardian_command(f"approve {approval_id} always")

    assert "always for cron job Ritz-Carlton AX 2026 availability check (41c2974734f8)" in response
    data = json.loads((tmp_path / "rules.json").read_text())
    assert data["privacy"]["rules"][0]["scope"]["cron_job_id"] == "41c2974734f8"
    assert data["privacy"]["rules"][0]["scope"]["cron_job_name"] == "Ritz-Carlton AX 2026 availability check"
    rules_text = plugin._handle_guardian_command("rules")
    assert "Scope: [Cron] Ritz-Carlton AX 2026 availability check" in rules_text
    policy = plugin._policy_snapshot()
    assert policy["rules"][0]["cron_job_id"] == "41c2974734f8"
    assert policy["rules"][0]["scope"] == "cron job Ritz-Carlton AX 2026 availability check (41c2974734f8)"

    plugin._on_pre_llm_call(session_id=second_run, platform="cron", sender_id="scheduler")
    plugin._taint_session(second_run, {"email"})
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "retry"}, session_id=second_run) is None

    plugin._on_pre_llm_call(session_id=other_job, platform="cron", sender_id="scheduler")
    plugin._taint_session(other_job, {"email"})
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "retry"}, session_id=other_job) is not None


def test_configured_telegram_owner_exception_is_cron_only(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "attacker")
    bind_owner(plugin, user_id="kevin")
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} once", user_id="attacker"))
    response = plugin._handle_guardian_command(f"approve {approval_id} once")

    assert "different user/session" in response
    assert approval_id in plugin._PENDING_APPROVALS


def test_expired_approval_cannot_approve(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._PENDING_APPROVALS[approval_id]["expires_at"] = 1
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} once"))

    assert "No pending approval" in plugin._handle_guardian_command(f"approve {approval_id} once")
