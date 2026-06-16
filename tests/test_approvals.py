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


def test_approval_5m_allows_matching_retry_until_expiry(monkeypatch):
    now = {"value": 1_000}
    plugin = load_plugin()
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    blocked = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} 5m"))
    response = plugin._handle_guardian_command(f"approve {approval_id} 5m")
    assert "Approved message_send" in response
    rules = plugin._persistent_privacy_rules()
    assert len(rules) == 1
    assert rules[0]["expires_at"] == 1_300
    assert not rules[0].get("fingerprint")
    assert "session_id" not in rules[0]["scope"]

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert len(plugin._persistent_privacy_rules()) == 1
    now["value"] = 1_301
    blocked_again = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    assert blocked_again is not None


def test_pending_approval_id_is_contextual_without_llm():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    blocked = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    assert re.fullmatch(r"\d{4}", approval_id)
    assert f"Approval ID: {approval_id}" in blocked["message"]
    assert f"/guardian approve {approval_id} 5m" in blocked["message"]
    assert f"/guardian approve {approval_id} forever" in blocked["message"]


def test_block_message_carries_metadata_plus_anti_circumvention_directive():
    """The agent relays the block to the user, so the message keeps the reason and the
    approval commands. It must ALSO carry an explicit anti-circumvention directive so a
    blocked egress is not re-routed through a different tool/channel."""
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    blocked = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s1")
    assert blocked is not None
    message = blocked["message"]
    approval_id = first_pending_id(plugin)

    # Metadata retained for the agent to surface to the user.
    assert f"/guardian approve {approval_id} 5m" in message
    assert "Trusted Destination Options:" in message
    assert "Ownership options:" in message
    assert "Reason:" in message
    assert "Data classes:" in message
    # Explicit anti-circumvention directive present.
    lowered = message.lower()
    assert "do not" in lowered
    assert "circumvention" in lowered


def test_block_message_includes_metadata_only_why_now():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    canary = "RAW-CANARY-BODY-5f4e"

    blocked = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": canary}, session_id="s1")
    assert blocked is not None
    message = blocked["message"]
    why_now = message.split("Why now:", 1)[1].split("DO NOT", 1)[0]

    assert "Why now: Guardian needs approval before private data leaves your boundary." in message
    assert "- Boundary: Outward" in why_now
    assert "- Data classes in scope: communications" in why_now
    assert "- Action family: message_send" in why_now
    assert "- Destination trust: external" in why_now
    assert canary not in why_now
    assert "friend" not in why_now


def test_pending_approval_id_is_four_digit_even_with_llm_available():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    plugin.state._PLUGIN_LLM = FakeSecurityLlm({"code": "unused"})
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
    assert plugin.state._PLUGIN_LLM.calls == []


def test_approval_id_generation_does_not_call_llm_with_tool_metadata():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    plugin.state._PLUGIN_LLM = FakeSecurityLlm({"code": "unused"})
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "personal body should not be sent to slug maker"},
        session_id="s1",
    )

    assert plugin.state._PLUGIN_LLM.calls == []


def test_approval_resolves_id_with_punctuation_via_compact_match():
    """A user retyping the 4-digit code with stray punctuation (e.g. "12-34") still resolves:
    _resolve_pending_approval_id falls back to a compact match that strips non-alphanumerics."""
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    # A dashed variant that does NOT exact-match any pending id, exercising the compact path.
    dashed_id = f"{approval_id[:2]}-{approval_id[2:]}"
    assert dashed_id not in plugin._PENDING_APPROVALS

    response = plugin._handle_guardian_command(f"approve {dashed_id} 5m")

    assert "Approved message_send" in response
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None


def test_approval_id_generation_avoids_recent_four_digit_codes(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    monkeypatch.setattr(plugin.approvals.secrets, "randbelow", lambda _limit: 1234)
    plugin._emit_activity(
        "blocked",
        session_id="old",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"communications"},
        reason="requires approval",
        approval_id="1234",
    )

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert first_pending_id(plugin) == "1235"


def test_approval_id_generation_reuses_codes_after_seven_days(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    monkeypatch.setattr(plugin.approvals.secrets, "randbelow", lambda _limit: 1234)
    current_time = plugin.state._now()
    monkeypatch.setattr(plugin.state, "_now", lambda: current_time - plugin._APPROVAL_ID_REUSE_SECONDS - 1)
    plugin._emit_activity(
        "blocked",
        session_id="old",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"communications"},
        reason="requires approval",
        approval_id="1234",
    )
    monkeypatch.setattr(plugin.state, "_now", lambda: current_time)

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert first_pending_id(plugin) == "1234"


def test_approval_forever_applies_across_sessions_for_same_owner():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1", user_id="owner")
    bind_owner(plugin, session_id="s2", user_id="owner")
    plugin._taint_session("s1", {"communications"})
    plugin._taint_session("s2", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} forever"))
    assert "Approved" in plugin._handle_guardian_command(f"approve {approval_id} forever")

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("send_message", {"to": "other", "text": "hello"}, session_id="s1") is not None
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s2") is None


def test_approval_forever_persists_narrow_rule(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} forever"))
    assert "Approved" in plugin._handle_guardian_command(f"approve {approval_id} forever")

    data = json.loads((tmp_path / "rules.json").read_text())
    assert len(data["sharing"]["rules"]) == 1
    rule = data["sharing"]["rules"][0]
    assert rule["match"]["destination"] == "messaging"
    assert rule["match"]["action_family"] == "message_send"
    assert rule["match"]["purpose"] == "unknown"
    assert rule["match"]["recipient_identity"] == plugin._recipient_identity_from_value("friend")
    assert rule["effect"] == "allow"
    assert rule["expires_at"] == 0
    assert "remaining_invocations" not in rule
    assert "session_id" not in rule["scope"]
    assert "hello" not in json.dumps(rule)
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "retry"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("send_message", {"to": "attacker", "text": "retry"}, session_id="s1") is not None


def test_approval_forever_save_failure_keeps_pending_approval(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} forever"))
    monkeypatch.setattr(plugin.rules, "_save_persistent_privacy_rules", lambda _rules: False)

    response = plugin._handle_guardian_command(f"approve {approval_id} forever")

    assert "Failed to save privacy approval" in response
    assert approval_id in plugin._PENDING_APPROVALS


def test_deny_keeps_retry_blocked():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian dismiss {approval_id}"))
    assert "Dismissed" in plugin._handle_guardian_command(f"dismiss {approval_id}")

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is not None


def test_deny_alias_still_dismisses_pending_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian deny {approval_id}"))
    response = plugin._handle_guardian_command(f"deny {approval_id}")

    assert "Dismissed" in response
    assert approval_id not in plugin._PENDING_APPROVALS


def test_unrecorded_command_fails_closed_without_trusted_local_context():
    # Production reaches `_handle_guardian_command` only via the gateway, which records
    # the real owner first. A command that arrives with no recorded owner and no trusted
    # local context (agent-emitted slash text, a lost/stale gateway record) must NOT
    # inherit CLI-owner admin and self-approve — it fails closed.
    plugin = load_plugin()
    plugin.state._TRUSTED_LOCAL_COMMAND_CONTEXT = False  # simulate production
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    # No gateway dispatch recorded this command's owner.
    response = plugin._handle_guardian_command(f"approve {approval_id} forever")
    assert "denied" in response.lower()
    assert approval_id in plugin._PENDING_APPROVALS  # not approved
    assert not plugin._persistent_privacy_rules()  # no broad grant created


def test_wrong_sender_cannot_approve():
    plugin = load_plugin()
    bind_owner(plugin, user_id="owner")
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} 5m", user_id="attacker"))
    response = plugin._handle_guardian_command(f"approve {approval_id} 5m")

    assert "different user/session" in response
    assert approval_id in plugin._PENDING_APPROVALS


def test_configured_telegram_owner_can_approve_cron_approval(monkeypatch):
    plugin = load_plugin()
    cron_session = "cron_aaaaaaaaaaaa_20260607_030107"
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin._on_pre_llm_call(session_id=cron_session, platform="cron", sender_id="scheduler")
    plugin._taint_session(cron_session, {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id=cron_session)
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} forever", user_id="owner"))
    response = plugin._handle_guardian_command(f"approve {approval_id} forever")

    assert "Approved message_send" in response
    assert approval_id not in plugin._PENDING_APPROVALS


def test_cron_approval_can_be_approved_from_separate_process(monkeypatch, tmp_path):
    activity_path = tmp_path / "activity.sqlite3"
    rules_path = tmp_path / "rules.json"
    creator = load_plugin()
    creator.state._ACTIVITY_DB_PATH = activity_path
    creator.state._ACTIVITY_DB_INITIALIZED = False
    creator.state._PERSISTENT_RULES_PATH = rules_path
    creator.state._PERSISTENT_RULES_CACHE = {"rules": []}
    cron_session = "cron_aaaaaaaaaaaa_20260607_030107"
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    creator._on_pre_llm_call(session_id=cron_session, platform="cron", sender_id="scheduler")
    creator._taint_session(cron_session, {"communications"})

    creator._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id=cron_session)
    approval_id = first_pending_id(creator)

    approver = load_plugin()
    approver.state._ACTIVITY_DB_PATH = activity_path
    approver.state._ACTIVITY_DB_INITIALIZED = False
    approver.state._PERSISTENT_RULES_PATH = rules_path
    approver.state._PERSISTENT_RULES_CACHE = {"rules": []}
    approver._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} forever", user_id="owner"))
    response = approver._handle_guardian_command(f"approve {approval_id} forever")

    assert "Approved message_send" in response
    assert approval_id not in approver._PENDING_APPROVALS
    with sqlite3.connect(activity_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert count == 0
    data = json.loads(rules_path.read_text())
    assert data["sharing"]["rules"][0]["match"]["destination"] == "messaging"
    assert data["sharing"]["rules"][0]["match"]["recipient_identity"] == creator._recipient_identity_from_value("friend")


def test_5m_approval_can_be_approved_and_expire_across_processes(monkeypatch, tmp_path):
    now = {"value": 2_000}
    activity_path = tmp_path / "activity.sqlite3"
    rules_path = tmp_path / "rules.json"
    creator = load_plugin()
    monkeypatch.setattr(creator.state, "_now", lambda: now["value"])
    creator.state._ACTIVITY_DB_PATH = activity_path
    creator.state._ACTIVITY_DB_INITIALIZED = False
    creator.state._PERSISTENT_RULES_PATH = rules_path
    creator.state._PERSISTENT_RULES_CACHE = None
    bind_owner(creator, session_id="s1", user_id="owner")
    creator._taint_session("s1", {"communications"})

    creator._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(creator)

    approver = load_plugin()
    monkeypatch.setattr(approver.state, "_now", lambda: now["value"])
    approver.state._ACTIVITY_DB_PATH = activity_path
    approver.state._ACTIVITY_DB_INITIALIZED = False
    approver.state._PERSISTENT_RULES_PATH = rules_path
    approver.state._PERSISTENT_RULES_CACHE = None
    approver._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} 5m", user_id="owner"))
    response = approver._handle_guardian_command(f"approve {approval_id} 5m")

    assert "Approved message_send" in response
    assert approval_id not in approver._PENDING_APPROVALS
    data = json.loads(rules_path.read_text())
    rule = data["sharing"]["rules"][0]
    assert rule["expires_at"] == 2_300
    assert "session_id" not in rule["scope"]
    assert not rule.get("fingerprint")

    runner = load_plugin()
    monkeypatch.setattr(runner.state, "_now", lambda: now["value"])
    runner.state._ACTIVITY_DB_PATH = activity_path
    runner.state._ACTIVITY_DB_INITIALIZED = False
    runner.state._PERSISTENT_RULES_PATH = rules_path
    runner.state._PERSISTENT_RULES_CACHE = None
    bind_owner(runner, session_id="s1", user_id="owner")
    runner._taint_session("s1", {"communications"})

    assert runner._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    now["value"] = 2_301
    data = json.loads(rules_path.read_text())
    assert runner._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is not None


def test_cron_always_approval_is_scoped_to_same_cron_job(monkeypatch, tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.cron_notifications._cron_job_name = lambda job_id: "Example Availability Check" if job_id == "aaaaaaaaaaaa" else ""
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    first_run = "cron_aaaaaaaaaaaa_20260607_030107"
    second_run = "cron_aaaaaaaaaaaa_20260607_090812"
    other_job = "cron_bbbbbbbbbbbb_20260607_080012"
    plugin._on_pre_llm_call(session_id=first_run, platform="cron", sender_id="scheduler")
    plugin._taint_session(first_run, {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id=first_run)
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} forever", user_id="owner"))
    response = plugin._handle_guardian_command(f"approve {approval_id} forever")

    assert "forever for cron job Example Availability Check (aaaaaaaaaaaa)" in response
    data = json.loads((tmp_path / "rules.json").read_text())
    assert data["sharing"]["rules"][0]["scope"]["cron_job_id"] == "aaaaaaaaaaaa"
    assert data["sharing"]["rules"][0]["scope"]["cron_job_name"] == "Example Availability Check"
    rules_text = plugin._handle_guardian_command("sharing")
    assert "Scope: [Cron] Example Availability Check" in rules_text
    policy = plugin._policy_snapshot()
    assert policy["rules"][0]["cron_job_id"] == "aaaaaaaaaaaa"
    assert policy["rules"][0]["scope"] == "cron job Example Availability Check (aaaaaaaaaaaa)"

    plugin._on_pre_llm_call(session_id=second_run, platform="cron", sender_id="scheduler")
    plugin._taint_session(second_run, {"communications"})
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "retry"}, session_id=second_run) is None

    plugin._on_pre_llm_call(session_id=other_job, platform="cron", sender_id="scheduler")
    plugin._taint_session(other_job, {"communications"})
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "retry"}, session_id=other_job) is not None


def test_configured_telegram_owner_exception_is_cron_only(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "attacker")
    bind_owner(plugin, user_id="owner")
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} 5m", user_id="attacker"))
    response = plugin._handle_guardian_command(f"approve {approval_id} 5m")

    assert "different user/session" in response
    assert approval_id in plugin._PENDING_APPROVALS


def test_expired_approval_cannot_approve(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    plugin._PENDING_APPROVALS[approval_id]["expires_at"] = 1
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} 5m"))

    assert "No pending approval" in plugin._handle_guardian_command(f"approve {approval_id} 5m")
