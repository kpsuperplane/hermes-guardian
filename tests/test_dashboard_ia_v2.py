"""Dashboard IA v2 — five-tab reshape (doc 02).

Covers the dashboard reshape's new read-only endpoints and the three pure-function
widgets, the clear-taint dashboard mutator, and the static-bundle wiring of the five
tabs + deep links. No engine changes — every widget routes through the existing pure
decide / resolve_destination_trust with hypothetical inputs.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only
synthetic placeholders.
"""

from __future__ import annotations

import importlib.util
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


# --- GET /approvals: pending-approvals read list (doc 02 §Tab1) ----------------------
def test_dashboard_pending_approvals_reads_snapshot_pending():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    # Gate an external send so a pending approval exists.
    plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "stranger@example.com", "text": "hi"},
        session_id="s1",
    )
    approvals = plugin._dashboard_pending_approvals()
    assert approvals, "expected a pending approval in the read list"
    item = approvals[0]
    # The read list carries the trust pill + deep-linkable decision step.
    assert item["destination_trust"] == "external"
    assert item["decision_step"] == "step6_approve_external"
    # It mirrors the snapshot's pending slice exactly (no new logic).
    assert approvals == plugin._policy_snapshot()["pending"]


# --- Clear-taint dashboard mutator (doc 02 §Tab1) ------------------------------------
def test_dashboard_clear_taint_action_clears_session_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    # Sanity: the session is tainted and surfaced in the snapshot.
    assert any(s["taint"] for s in plugin._policy_snapshot()["sessions"])
    result, status = plugin._dashboard_clear_taint_action()
    assert status == 200 and result["ok"]
    assert not any(s["taint"] for s in result["policy"]["sessions"])


# --- "Check a destination" widget (What's Yours, doc 02 §Tab2) -----------------------
def test_check_destination_resolves_self_after_grant():
    plugin = load_plugin()
    # A host not declared yours resolves non-self...
    before = plugin._dashboard_resolve_destination("host:myvps.example.com")
    assert before["trust"] != "self"
    # ...declaring it yours flips it to self (the resolver is read live).
    ok, _ = plugin._add_self_destination("host", "myvps.example.com")
    assert ok
    after = plugin._dashboard_resolve_destination("host:myvps.example.com")
    assert after["kind"] == "host"
    assert after["id"] == "myvps.example.com"
    assert after["trust"] == "self"


def test_check_destination_templated_recipient_is_unknown():
    plugin = load_plugin()
    # An empty/templated recipient is never guessed self — it is unknown.
    result = plugin._dashboard_resolve_destination("messaging:")
    assert result["trust"] == "unknown"


def test_check_destination_external_recipient():
    plugin = load_plugin()
    result = plugin._dashboard_resolve_destination("stranger@example.com")
    assert result["kind"] == "messaging"
    assert result["trust"] == "external"


# --- "Preview a send" widget (Sharing, doc 02 §Tab3) ---------------------------------
def test_preview_send_external_gates_at_step6():
    plugin = load_plugin()
    result = plugin._dashboard_preview_send("message_send", "stranger@example.com", ["email"])
    assert result["destination_trust"] == "external"
    assert result["decision"] == "approve"
    assert result["decision_step"] == "step6_approve_external"


def test_preview_send_self_host_is_allowed():
    plugin = load_plugin()
    plugin._add_self_destination("host", "myvps.example.com")
    result = plugin._dashboard_preview_send("web_api", "host:myvps.example.com", ["email"])
    assert result["destination_trust"] == "self"
    assert result["decision"] == "allow"
    assert result["decision_step"] == "step3_intra_boundary_self"


def test_preview_send_no_taint_is_allowed():
    plugin = load_plugin()
    # External destination but no private classes -> nothing confidential to leak.
    result = plugin._dashboard_preview_send("message_send", "stranger@example.com", [])
    assert result["decision"] == "allow"
    assert result["decision_step"] == "step4_no_private_taint"


# --- "Impact preview" widget (Sharing, doc 02 §Tab3) ---------------------------------
def test_impact_preview_lists_matching_historical_rows():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    # Record a gated external send so there is a historical row to replay.
    plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "stranger@example.com", "text": "hi"},
        session_id="s1",
    )
    # A wildcard allow candidate covers the gated send.
    candidate = {
        "effect": "allow",
        "match": {"action_family": "*", "destination": "*", "purpose": "*", "data_classes": ["*"]},
    }
    impact = plugin._dashboard_sharing_impact(candidate)
    assert impact["effect"] == "allow"
    assert impact["verb"] == "auto-allowed"
    assert impact["matched_count"] >= 1
    assert any(row["action_family"] == "message_send" for row in impact["matched"])


def test_impact_preview_narrow_candidate_excludes_unrelated_rows():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "stranger@example.com", "text": "hi"},
        session_id="s1",
    )
    # A candidate scoped to a different action family matches nothing.
    candidate = {
        "effect": "allow",
        "match": {
            "action_family": "mcp_write",
            "destination": "*",
            "purpose": "*",
            "data_classes": ["*"],
        },
    }
    impact = plugin._dashboard_sharing_impact(candidate)
    assert impact["matched_count"] == 0


# --- The new read endpoints need no admin guard (they only compute) ------------------
# --- Static bundle: five tabs + deep links wired (doc 02 §nav, §Deep links) ----------
def test_static_bundle_renders_five_tabs_and_deeplinks():
    static_js = (
        Path(__file__).resolve().parents[1] / "dashboard" / "dist" / "index.js"
    ).read_text()
    # The five tab labels are present in the bundle, the old junk-drawer labels are gone.
    for label in ("Activity", "What's Yours", "Sharing", "Review", "Protection"):
        assert label in static_js, f"missing tab label {label!r}"
    assert "Destinations & Trust" not in static_js
    assert "Connectors" not in static_js
    # Deep-link affordance + the new widgets are bundled.
    assert "hermes-guardian-deeplink" in static_js
    assert "Check a destination" in static_js
    assert "Preview a send" in static_js
    assert "Preview impact" in static_js
