from __future__ import annotations

import argparse
import asyncio
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


def _load_plugin_api():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "hermes_guardian_dashboard_plugin_api", root / "dashboard" / "plugin_api.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _request(headers: dict | None = None):
    return SimpleNamespace(headers=headers or {})


def test_reading_and_sharing_routes_replace_old_tool_and_taint_routes():
    source = (Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py").read_text()

    for path in {
        "/sharing/egress-safety",
        "/sharing/owner-context",
        "/sharing/cron-context",
        "/sharing/verifier-model",
        "/reading/taint-classification",
        "/reading/tools",
        "/reading/tools/{override_id}",
        "/sharing/tools",
        "/sharing/tools/{override_id}",
        "/reading/source-suggestions",
        "/reading/source-classification",
    }:
        assert path in source
    for path in {
        "/privacy/taint-classification",
        "/tools",
        "/tools/{override_id}",
        "/tools/source-suggestions",
        "/tools/source",
        "/privacy/egress-safety",
        "/privacy/user-context",
        "/privacy/cron-context",
        "/privacy/verifier-model",
    }:
        assert f'"{path}"' not in source


def test_policy_snapshot_compacts_all_class_privacy_rule(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule(rule_id="rule_all", data_classes=["*"])])

    policy = plugin._policy_snapshot()

    assert policy["rules"][0]["rule_id"] == "rule_all"
    assert policy["rules"][0]["data_classes"] == ["*"]


def test_dashboard_policy_snapshot_includes_risk_banners():
    plugin = load_plugin()
    assert plugin._set_security_rule("intrinsic_exfiltration", False)[0]

    policy = plugin._policy_snapshot()
    banner_ids = {banner["id"] for banner in policy["risk_banners"]}

    assert banner_ids == {"intrinsic_exfiltration_disabled"}


def test_dashboard_static_renders_risk_banners():
    static_js = (Path(__file__).resolve().parents[1] / "dashboard" / "dist" / "index.js").read_text()

    # The bundle is built from src/ (see dashboard/README.md); assert on the
    # data binding and the rendered class names rather than an internal symbol,
    # which minification renames.
    assert "risk_banners" in static_js
    assert "hermes-guardian-risk-banner" in static_js


def test_policy_snapshot_includes_cron_rule_scope(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.cron_notifications._cron_job_name = lambda job_id: "Example Availability Check" if job_id == "aaaaaaaaaaaa" else ""
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_test",
            action_family="browser_type",
            destination="www.google.com",
            data_classes=["communications"],
            cron_job_id="aaaaaaaaaaaa",
            cron_job_name="Example Availability Check",
        )
    ])

    policy = plugin._policy_snapshot()
    rule = policy["rules"][0]

    assert rule["action_family"] == "browser_type"
    assert rule["destination"] == "www.google.com"
    assert rule["cron_job_id"] == "aaaaaaaaaaaa"
    assert rule["cron_job_name"] == "Example Availability Check"
    assert rule["scope"] == "cron job Example Availability Check (aaaaaaaaaaaa)"


def test_policy_snapshot_includes_persistent_rule_metadata(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_delete_me",
            action_family="message_send",
            destination="friend",
            data_classes=["communications"],
            owner_hash="cli",
        )
    ])

    policy = plugin._policy_snapshot()
    rule = policy["rules"][0]

    assert rule["rule_id"] == "rule_delete_me"
    assert rule["action_family"] == "message_send"
    assert rule["destination"] == "friend"
    assert rule["purpose"] == "*"
    assert rule["recipient_identity"] == "*"
    assert rule["data_classes"] == ["communications"]
    assert rule["owner_hash"] == "cli"


def test_policy_snapshot_includes_rule_form_suggestions(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
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
        data_classes=["communications"],
    )

    policy = plugin._policy_snapshot()

    assert "mcp:notion" in policy["destination_suggestions"]
    assert "example.com" in policy["destination_suggestions"]
    assert "mcp_notion_update_page" in policy["tool_name_suggestions"]
    assert "browser_type" in policy["tool_name_suggestions"]
    assert "*" not in policy["destination_suggestions"]
    assert policy["suggestions"]["destinations"] == policy["destination_suggestions"]
    assert policy["suggestions"]["tool_names"] == policy["tool_name_suggestions"]


def test_dashboard_policy_exposes_contextual_rule_and_pending_fields():
    plugin = load_plugin()
    recipient_identity = plugin._recipient_identity_from_value("friend")
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_context",
            action_family="message_send",
            destination="messaging",
            purpose="support",
            recipient_identity=recipient_identity,
            data_classes=["communications"],
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        "send_message",
        {"to": "other", "text": "hello", "purpose": "marketing"},
        session_id="s1",
    )

    policy = plugin._policy_snapshot()

    assert policy["rules"][0]["purpose"] == "support"
    assert policy["rules"][0]["recipient_identity"] == recipient_identity
    assert policy["pending"][0]["purpose"] == "marketing"
    assert policy["pending"][0]["recipient_identity"] == plugin._recipient_identity_from_value("other")
    assert "support" in policy["purpose_suggestions"]
    assert recipient_identity in policy["recipient_identity_suggestions"]


def test_dashboard_rule_delete_action_removes_persistent_rule(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_delete_me",
            action_family="message_send",
            destination="friend",
            data_classes=["communications"],
            owner_hash="cli",
        ),
        privacy_rule(
            rule_id="rule_keep",
            action_family="browser_type",
            destination="www.google.com",
            data_classes=["communications"],
            owner_hash="cli",
        ),
    ])

    payload, status = plugin._dashboard_rule_delete_action("rule_delete_me")

    assert status == 200
    assert payload["ok"] is True
    assert "Deleted privacy rule rule_delete_me" in payload["message"]
    data = json.loads((tmp_path / "rules.json").read_text())
    assert [rule["id"] for rule in data["sharing"]["rules"]] == ["rule_keep"]
    assert [rule["rule_id"] for rule in payload["policy"]["rules"]] == ["rule_keep"]


def test_policy_snapshot_includes_five_recent_unresolved_blocks(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    approval_ids = []

    for index in range(6):
        session_id = f"s{index}"
        bind_owner(plugin, session_id=session_id)
        plugin._taint_session(session_id, {"communications"})
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


def test_policy_snapshot_pending_and_recent_blocks_include_why_now_and_flow_boundary():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    canary = "RAW-CANARY-POLICY-9d7a"

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": canary}, session_id="s1")

    policy = plugin._policy_snapshot()
    pending = policy["pending"][0]
    recent = policy["recent_blocks"][0]
    for item in (pending, recent):
        assert item["flow_boundary"] == "outward"
        assert item["flow_boundary_label"] == "Outward"
        assert item["flow_boundary_detail"] == "The action would move data outside your boundary."
        assert item["why_now"]["summary"] == "Guardian needs approval before private data leaves your boundary."
        assert "Boundary: Outward" in item["why_now"]["bullets"]
        assert "Data classes in scope: communications" in item["why_now"]["bullets"]
        assert "Action family: message_send" in item["why_now"]["bullets"]
        derived = json.dumps(
            {
                "why_now": item["why_now"],
                "flow_boundary": item["flow_boundary"],
                "flow_boundary_label": item["flow_boundary_label"],
                "flow_boundary_detail": item["flow_boundary_detail"],
            }
        )
        assert canary not in derived
        assert "friend" not in derived


def test_policy_snapshot_omits_final_response_pending_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts", "documents"})

    out = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="even-ai",
    )

    policy = plugin._policy_snapshot()

    assert out is None
    assert policy["pending"] == []
    assert policy["recent_blocks"] == []


def test_policy_snapshot_marks_pending_block_covered_by_new_allow_rule(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    recipient_identity = plugin._PENDING_APPROVALS[approval_id]["recipient_identity"]
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_cover_friend",
            action_family="message_send",
            destination="messaging",
            recipient_identity=recipient_identity,
            data_classes=["communications"],
            expires_at=int(plugin.state._now() + 300),
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
    assert rules[0]["expires_at"] > int(plugin.state._now())


def test_policy_snapshot_does_not_mark_pending_block_covered_by_new_deny_rule(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_deny_friend",
            effect="deny",
            action_family="message_send",
            destination="friend",
            data_classes=["communications"],
        )
    ])

    policy = plugin._policy_snapshot()
    block = policy["recent_blocks"][0]

    assert block["id"] == approval_id
    assert block["pending"] is True
    assert block["covered_by_rule"] is False
    assert block["covered_rule_id"] == ""


def test_policy_snapshot_marks_stored_expired_approval_as_dismissible(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    expires_at = int(plugin._PENDING_APPROVALS[approval_id]["expires_at"])
    plugin._PENDING_APPROVALS.clear()
    now["value"] = expires_at + 1

    policy = plugin._policy_snapshot()
    block = policy["recent_blocks"][0]

    assert block["id"].startswith("activity-")
    assert block["pending"] is False
    assert block["approval_id"] == ""
    assert block["historical_approval_id"] == approval_id
    assert block["approval_status"] == "expired"
    assert block["dismiss_id"] == approval_id
    assert block["expires_at"] == expires_at


def test_policy_snapshot_omits_orphaned_historical_approval_blocks():
    plugin = load_plugin()

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="send_message",
        action_family="message_send",
        destination="friend",
        data_classes={"communications"},
        reason="requires approval",
        approval_id="1234",
    )

    policy = plugin._policy_snapshot()

    assert policy["recent_blocks"] == []


def test_dashboard_dismiss_action_handles_stored_expired_approval(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)
    expires_at = int(plugin._PENDING_APPROVALS[approval_id]["expires_at"])
    plugin._PENDING_APPROVALS.clear()
    now["value"] = expires_at + 1

    payload, status = plugin._dashboard_approval_action(approval_id, "dismiss")

    assert status == 200
    assert payload["ok"] is True
    assert payload["message"] == f"Dismissed expired guardian approval {approval_id}."
    assert payload["policy"]["recent_blocks"] == []
    with plugin._activity_connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert count == 0


def test_attention_dismissals_are_sanitized_active_and_expire(monkeypatch):
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])

    payload, status = plugin._dashboard_attention_dismiss_action({
        "kind": "source",
        "item_id": "source:<crm private>",
        "dismiss_key": "source:<crm private>|last=1|hits=2",
    })

    assert status == 200
    assert payload["ok"] is True
    dismissal = payload["policy"]["attention_dismissals"][0]
    assert dismissal["kind"] == "source"
    assert dismissal["dismiss_key"] == "source:_crm_private_|last=1|hits=2"
    assert dismissal["item_id"] == "source:_crm_private"
    assert dismissal["created_at"] == 1000
    assert dismissal["expires_at"] == 1000 + 30 * 24 * 60 * 60

    now["value"] = dismissal["expires_at"] + 1
    assert plugin._policy_snapshot()["attention_dismissals"] == []


def test_attention_dismissal_rejects_approval_kind():
    plugin = load_plugin()

    payload, status = plugin._dashboard_attention_dismiss_action({
        "kind": "approval",
        "item_id": "approval:1234",
        "dismiss_key": "approval:1234",
    })

    assert status == 400
    assert payload["ok"] is False
    assert payload["policy"]["attention_dismissals"] == []


def test_attention_restore_one_or_all():
    plugin = load_plugin()
    plugin._dashboard_attention_dismiss_action({
        "kind": "risk",
        "item_id": "risk:relaxed",
        "dismiss_key": "risk:relaxed",
    })
    plugin._dashboard_attention_dismiss_action({
        "kind": "info",
        "item_id": "info:self",
        "dismiss_key": "info:self",
    })

    payload, status = plugin._dashboard_attention_restore_action({"dismiss_key": "risk:relaxed"})

    assert status == 200
    assert payload["ok"] is True
    assert [item["dismiss_key"] for item in payload["policy"]["attention_dismissals"]] == ["info:self"]

    payload, status = plugin._dashboard_attention_restore_action({})

    assert status == 200
    assert payload["ok"] is True
    assert payload["policy"]["attention_dismissals"] == []


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
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    payload, status = plugin._dashboard_approval_action(approval_id, "approve", "5m")

    assert status == 200
    assert payload["ok"] is True
    assert approval_id not in plugin._PENDING_APPROVALS
    assert payload["policy"]["recent_blocks"] == []
    assert len(payload["policy"]["rules"]) == 1
    rule = payload["policy"]["rules"][0]
    assert rule["action_family"] == "message_send"
    assert rule["destination"] == "messaging"
    assert rule["recipient_identity"] == plugin._recipient_identity_from_value("friend")
    assert rule["expires_at"] > int(plugin.state._now())

    bind_owner(plugin, session_id="s2")
    plugin._taint_session("s2", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "other-friend", "text": "hello"}, session_id="s2")
    approval_id = first_pending_id(plugin)

    payload, status = plugin._dashboard_approval_action(approval_id, "dismiss")

    assert status == 200
    assert payload["ok"] is True
    assert approval_id not in plugin._PENDING_APPROVALS
    assert payload["policy"]["recent_blocks"] == []


# --- doc 06 §8-9: permit options on the snapshot + method-based approve --------
def test_pending_snapshot_carries_context_permit_options():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "me@example.com", "text": "hi"}, session_id="s1")

    pending = plugin._dashboard_pending_approvals()
    assert len(pending) == 1
    methods = {opt["method"] for opt in pending[0]["permit_options"]}
    # Rule rows always, plus the messaging structural dimensions.
    assert {"rule_5m", "rule_forever", "self_identity", "trusted_identity"} <= methods
    groups = {opt["group"] for opt in pending[0]["permit_options"]}
    assert {"Approval options", "Trusted Destination Options", "Ownership options"} <= groups
    self_identity = next(o for o in pending[0]["permit_options"] if o["method"] == "self_identity")
    assert self_identity["value"] == "me@example.com" and self_identity["structural"] is True


def test_dashboard_approve_by_structural_method_mutates_config():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "me@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    payload, status = plugin._dashboard_approval_action(approval_id, "approve", "self_identity")
    assert status == 200 and payload["ok"] is True
    assert "me@example.com" in plugin._self_config_snapshot()["identities"]
    assert approval_id not in plugin._PENDING_APPROVALS


def test_dashboard_structural_method_detection_and_unknown_rejected():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "me@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    # The HTTP layer uses this to decide whether to require the destination-trust confirm.
    assert plugin._dashboard_permit_method_is_structural("self_identity") is True
    assert plugin._dashboard_permit_method_is_structural("trusted_identity") is True
    assert plugin._dashboard_permit_method_is_structural("5m") is False
    assert plugin._dashboard_permit_method_is_structural("rule_forever") is False

    payload, status = plugin._dashboard_approval_action(approval_id, "approve", "bogus_method")
    assert status == 400 and payload["ok"] is False
    assert approval_id in plugin._PENDING_APPROVALS


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

    assert payload["data"][0]["action_detail"] == "command: pwd | grep root"


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
    monkeypatch.setattr(plugin.state, "_now", lambda: 1780775049)

    plugin._emit_activity(
        "blocked",
        session_id="s1",
        tool_name="browser_type",
        action_family="browser_type",
        destination="example.com",
        data_classes={"communications", "contacts"},
        reason="requires approval",
        approval_id="amber-bridge-1234",
        action_detail="type into example.com: <redacted 42 chars; classes=communications>",
    )

    row = plugin._grouped_activity_rows({}, limit=1)[0]
    datatables_row = plugin._activity_datatables_payload({"draw": "1", "start": "0", "length": "25"})["data"][0]
    history = plugin._handle_guardian_command("activity")

    assert plugin._activity_status_icon(row["decision"]) == "❌"
    assert plugin._activity_time_text(row) == "Jun 6, 2026 12:44 PM PDT"
    assert plugin._activity_taints_text(row, code=True) == "🏷️ `communications,contacts`"
    assert plugin._activity_reason_line_text(row) == "Blocked: requires approval (`amber-bridge-1234`)"
    assert datatables_row["icon"] == "❌"
    assert datatables_row["time"] == "Jun 6, 2026 12:44 PM PDT"
    assert datatables_row["data_classes"] == "communications,contacts"
    assert datatables_row["reason_short"] == "Blocked: requires approval"
    assert "Jun 6, 2026 12:44 PM PDT" not in history
    assert "- ❌ `browser_type` · `communications, contacts`" in history
    assert "blocked · requires approval (amber-bridge-1234)" in history


def test_activity_action_detail_keeps_safe_raw_command_but_redacts_security_sensitive_text():
    plugin = load_plugin()

    safe_detail = plugin._activity_action_detail("terminal", {"command": "pwd | grep root"}, "terminal_exec", "terminal")
    sensitive_detail = plugin._activity_action_detail(
        "terminal",
        {"command": "echo 'Your verification code is 123456'"},
        "terminal_exec",
        "terminal",
    )

    assert safe_detail == "command: pwd | grep root"
    assert sensitive_detail == "command: <security-sensitive content redacted: auth code>"
    assert "123456" not in sensitive_detail


def test_terminal_action_detail_preserves_sanitized_command_preview():
    plugin = load_plugin()
    token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
    command = (
        "python3 - <<'PY'\n"
        "import urllib.request\n"
        "url='https://api.weather.gov/gridpoints/LOX/154,44/forecast?email=reader@example.com'\n"
        f"value='{token}'\n"
        "print(url, value)\n"
        "PY"
    )

    detail = plugin._activity_action_detail("terminal", {"command": command}, "terminal_exec", "terminal")

    assert detail.startswith("command: python3 - <<'PY'")
    assert "import urllib.request" in detail
    assert "api.weather.gov" in detail
    assert "<path:redacted>" in detail
    assert "<token-like>" in detail
    assert "reader@example.com" not in detail
    assert "gridpoints/LOX" not in detail
    assert token not in detail


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
            data_classes={"communications"},
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


# --- Security: unauthenticated read routes must not leak the 4-digit approval id -----
def _drive_route_with_live_plugin(api, plugin, coro_factory):
    """Run an async route coroutine with the route facade bound to the live test plugin
    so it observes the same in-memory pending approvals the test created."""
    sys.modules["_hermes_guardian_dashboard_facade"] = plugin
    try:
        return asyncio.run(coro_factory())
    finally:
        sys.modules.pop("_hermes_guardian_dashboard_facade", None)


def test_unauthenticated_policy_route_redacts_live_approval_id():
    api = _load_plugin_api()
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1"
    )
    real_id = first_pending_id(plugin)
    assert re.fullmatch(r"[0-9]{4}", real_id), "precondition: a live 4-digit approval id exists"

    policy = _drive_route_with_live_plugin(api, plugin, api.policy)

    # The pending row is still rendered, with its metadata — but the approve credential is gone.
    assert policy["pending"], "pending row should still be present for the UI"
    assert policy["pending"][0]["id"] == ""
    assert policy["pending"][0]["action_family"] == "message_send"
    assert policy["pending"][0]["destination"] == "messaging"
    assert policy["pending"][0]["destination_trust"] == "external"
    # The id leaks nowhere in the serialized read payload (also covers recent_blocks).
    assert real_id not in json.dumps(policy)


def test_approvals_route_returns_live_approval_id_for_dashboard_actions():
    api = _load_plugin_api()
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1"
    )
    real_id = first_pending_id(plugin)

    result = _drive_route_with_live_plugin(api, plugin, api.approvals)

    assert result["approvals"], "approvals list should still be present for the UI"
    assert result["approvals"][0]["id"] == real_id
    # Permit options / trust pill survive so the UI can drive approve/dismiss through
    # the admin-gated mutation route.
    assert result["approvals"][0]["destination_trust"] == "external"


def test_recent_blocks_in_policy_route_redact_approval_id(monkeypatch):
    api = _load_plugin_api()
    plugin = load_plugin()
    now = {"value": 1000}
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")
    real_id = first_pending_id(plugin)

    policy = _drive_route_with_live_plugin(api, plugin, api.policy)

    blocks = policy["recent_blocks"]
    assert blocks, "a pending block should surface in recent_blocks"
    # The id-bearing fields (id / approval_id / dismiss_id / historical_approval_id) are blanked.
    for field in ("id", "approval_id", "dismiss_id", "historical_approval_id"):
        assert blocks[0].get(field, "") == ""
    assert real_id not in json.dumps(policy)


def _activity_leak_setup(api, plugin):
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1"
    )
    real_id = first_pending_id(plugin)
    assert re.fullmatch(r"[0-9]{4}", real_id), "precondition: a live 4-digit approval id exists"
    return real_id


def test_unauthenticated_activity_route_redacts_live_approval_id():
    api = _load_plugin_api()
    plugin = load_plugin()
    _activity_leak_setup(api, plugin)

    result = _drive_route_with_live_plugin(api, plugin, api.activity)

    rows = [r for r in result["activity"] if r.get("action_family") == "message_send"]
    assert rows, "the pending block should still surface in activity history"
    assert rows[0]["approval_id"] == ""


def test_unauthenticated_activity_datatables_route_redacts_live_approval_id():
    api = _load_plugin_api()
    plugin = load_plugin()
    _activity_leak_setup(api, plugin)

    request = SimpleNamespace(headers={}, query_params={"draw": "1", "start": "0", "length": "25"})
    result = _drive_route_with_live_plugin(api, plugin, lambda: api.activity_datatables(request))

    rows = [r for r in result["data"] if r.get("action_family") == "message_send"]
    assert rows, "the pending block should still surface in the datatables payload"
    assert rows[0]["approval_id"] == ""


def test_unauthenticated_activity_turns_route_redacts_live_approval_id():
    api = _load_plugin_api()
    plugin = load_plugin()
    _activity_leak_setup(api, plugin)

    request = SimpleNamespace(headers={}, query_params={"draw": "1", "start": "0", "length": "25"})
    result = _drive_route_with_live_plugin(api, plugin, lambda: api.activity_turns(request))

    assert result["turns"], "the pending block should still surface as a turn"
    for turn in result["turns"]:
        for row in turn["rows"]:
            assert row.get("approval_id", "") == ""


# --- Security: the approve route fails closed without admin auth (no token configured) -
def test_approve_route_without_token_passes_host_auth_gate(monkeypatch):
    """DEFAULT config (no token): the host dashboard's own authentication is the gate, so
    the approve route is reachable (no 403) and consumes the pending approval. The
    Activity tab reads the live approval id from /approvals and posts it back here."""
    api = _load_plugin_api()
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    sys.modules["_hermes_guardian_dashboard_facade"] = plugin
    try:
        approvals_payload = asyncio.run(api.approvals())
        dashboard_approval_id = approvals_payload["approvals"][0]["id"]
        response = asyncio.run(api.approve(_request(), dashboard_approval_id, {"method": "rule_5m"}))
    finally:
        sys.modules.pop("_hermes_guardian_dashboard_facade", None)

    assert dashboard_approval_id == approval_id
    assert response.status_code != 403
    assert approval_id not in plugin._PENDING_APPROVALS


def test_approve_route_allows_with_token(monkeypatch):
    """With a token configured and the correct header, the approve route passes the gate
    and runs the underlying approval action."""
    api = _load_plugin_api()
    monkeypatch.setenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", "s3cret")
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    sys.modules["_hermes_guardian_dashboard_facade"] = plugin
    try:
        response = asyncio.run(
            api.approve(
                _request({"x-hermes-guardian-token": "s3cret"}),
                approval_id,
                {"method": "rule_5m"},
            )
        )
    finally:
        sys.modules.pop("_hermes_guardian_dashboard_facade", None)

    assert response.status_code == 200
    assert response.content["ok"] is True
    assert approval_id not in plugin._PENDING_APPROVALS


# --- Security: every mutation route enforces the admin gate (guard-wiring tripwire) ---
# A token IS configured but the request carries the wrong/no header, so each route must
# 403 at _require_dashboard_admin before doing any work. If a route ever loses that call,
# exactly one parameter here flips to a non-403 and fails. Routes are invoked with
# placeholder args (the admin check runs first, before args are used).
def _mutation_route_invokers(api):
    req = _request({})  # no x-hermes-guardian-token header -> wrong credential
    return {
        "set_egress_safety": lambda: api.set_egress_safety(req, {"mode": "strict"}),
        "update_security_rule": lambda: api.update_security_rule(req, "sensitive_links", {"enabled": False}),
        "update_language_pack": lambda: api.update_language_pack(req, "es", {"enabled": True}),
        "create_rule": lambda: api.create_rule(req, {}),
        "update_rule": lambda: api.update_rule(req, "rule_x", {}),
        "delete_rule": lambda: api.delete_rule(req, "rule_x"),
        "approve": lambda: api.approve(req, "1234", {"method": "rule_5m"}),
        "dismiss": lambda: api.dismiss(req, "1234"),
        "clear_taint": lambda: api.clear_taint(req),
        "dismiss_attention": lambda: api.dismiss_attention(req, {"kind": "risk", "dismiss_key": "risk:x"}),
        "restore_attention": lambda: api.restore_attention(req, {}),
        "set_taint_classification": lambda: api.set_taint_classification(req, {"mode": "strict"}),
        "set_llm_source_classification": lambda: api.set_llm_source_classification(req, {"enabled": False}),
        "set_source_model": lambda: api.set_source_model(req, {"model": ""}),
        "set_user_context": lambda: api.set_user_context(req, {"enabled": True}),
        "set_cron_context": lambda: api.set_cron_context(req, {"enabled": False}),
        "set_verifier_model": lambda: api.set_verifier_model(req, {"model": ""}),
        "set_persist_prompts": lambda: api.set_persist_prompts(req, {"enabled": False}),
        "create_reading_tool": lambda: api.create_reading_tool(req, {"match": "acme_*"}),
        "update_reading_tool": lambda: api.update_reading_tool(req, "source_tool_x", {}),
        "delete_reading_tool": lambda: api.delete_reading_tool(req, "source_tool_x"),
        "create_sharing_tool": lambda: api.create_sharing_tool(req, {"match": "acme_*"}),
        "update_sharing_tool": lambda: api.update_sharing_tool(req, "sharing_tool_x", {}),
        "delete_sharing_tool": lambda: api.delete_sharing_tool(req, "sharing_tool_x"),
        "classify_source": lambda: api.classify_source(req, {"tool_name": "acme_read", "source": "private"}),
        "add_self_destination": lambda: api.add_self_destination(req, {"kind": "identity", "value": "x@example.com"}),
        "remove_self_destination": lambda: api.remove_self_destination(req, {"kind": "identity", "value": "x@example.com"}),
        "add_trusted_recipient": lambda: api.add_trusted_recipient(req, {"identity": "x@example.com"}),
        "remove_trusted_recipient": lambda: api.remove_trusted_recipient(req, {"identity": "x@example.com"}),
        "add_sharing_subtype": lambda: api.add_sharing_subtype(req, {"subtype": "share"}),
        "remove_sharing_subtype": lambda: api.remove_sharing_subtype(req, {"subtype": "share"}),
    }


@pytest.mark.parametrize("route_name", list(_mutation_route_invokers(_load_plugin_api()).keys()))
def test_every_mutation_route_requires_admin(monkeypatch, route_name):
    api = _load_plugin_api()
    monkeypatch.setenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", "s3cret")
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)
    invoke = _mutation_route_invokers(api)[route_name]
    with pytest.raises(api.HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == 403


# --- Security: confirmation-gated weakening actions reject without the token (no admin
# token configured, so the admin gate passes and the confirmation gate is what 400s). ---
def _confirmation_gate_invokers(api):
    req = _request({})
    return {
        "egress-safety-off": lambda: api.set_egress_safety(req, {"mode": "off"}),
        "wildcard-allow": lambda: api.create_rule(
            req,
            {
                "effect": "allow",
                "match": {
                    "tool_name": "*",
                    "action_family": "*",
                    "destination": "*",
                    "purpose": "*",
                    "recipient_identity": "*",
                    "data_classes": ["*"],
                },
            },
        ),
        "taint-classification-relaxed": lambda: api.set_taint_classification(req, {"mode": "relaxed"}),
        "tool-ignore": lambda: api.create_sharing_tool(req, {"match": "acme_*", "egress": "ignore"}),
        "source-reference": lambda: api.classify_source(req, {"tool_name": "acme_read", "source": "reference"}),
        "source-public": lambda: api.create_reading_tool(req, {"match": "clock_*", "source": "public"}),
    }


@pytest.mark.parametrize("action", list(_confirmation_gate_invokers(_load_plugin_api()).keys()))
def test_weakening_action_requires_confirmation(monkeypatch, action):
    api = _load_plugin_api()
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)
    invoke = _confirmation_gate_invokers(api)[action]
    with pytest.raises(api.HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == 400


def test_dashboard_can_create_public_reading_tool_with_confirmation(monkeypatch):
    api = _load_plugin_api()
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)

    response = asyncio.run(
        api.create_reading_tool(
            _request({}),
            {"match": "clock_*", "source": "public", "confirm": "source-public"},
        )
    )

    assert response.status_code == 200
    tools = response.content["policy"]["reading_tools"]
    assert any(tool["match"] == "clock_*" and tool["source"] == "public" for tool in tools)
