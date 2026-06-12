"""Dashboard Destinations & Trust panel (doc 03 §3.1, §3.3, §7 tests 8-9).

Covers: the dashboard self/trusted/sharing actions persist and mirror the slash commands,
the admin-token + confirmation guards gate destination-trust edits (like the cron-context
toggle), and the informational banner appears when an identity/host grant is present.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only synthetic
placeholders.
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


# --- 8. Dashboard self-edit is admin + confirmation gated and persists. ---------------
def test_dashboard_self_action_persists():
    plugin = load_plugin()
    result, status = plugin._dashboard_self_add_action({"kind": "destination", "value": "store:crm"})
    assert status == 200 and result["ok"]
    assert "store:crm" in plugin._self_config_snapshot()["destinations"]
    # The mutation is reflected in the policy snapshot the dashboard reads.
    summary = result["policy"]["destination_trust"]
    assert "store:crm" in summary["self"]["destinations"]
    # Remove path persists too.
    result, status = plugin._dashboard_self_remove_action({"kind": "destination", "value": "store:crm"})
    assert status == 200 and result["ok"]
    assert "store:crm" not in plugin._self_config_snapshot()["destinations"]


def test_dashboard_trusted_and_sharing_actions_persist():
    plugin = load_plugin()
    plugin._dashboard_trusted_add_action({"identity": "partner@example.com", "classes": ["communications"]})
    assert any(e["identity"] == "partner@example.com" for e in plugin._trusted_recipients_snapshot())
    plugin._dashboard_sharing_add_action({"subtype": "crosspost"})
    assert "crosspost" in plugin._outward_sharing_snapshot()["extra"]
    # A builtin sharing subtype cannot be removed through the dashboard either.
    result, status = plugin._dashboard_sharing_remove_action({"subtype": "share"})
    assert not result["ok"]
    assert "share" in plugin._outward_sharing_snapshot()["builtin"]


def test_destination_trust_edits_require_confirmation():
    api = _load_plugin_api()
    # Without the confirmation token, the guard rejects the edit.
    with pytest.raises(api.HTTPException) as exc:
        api._require_dashboard_confirmation(
            "destination_trust", {"kind": "destination", "value": "store:crm"}
        )
    assert exc.value.status_code == 400
    # With the token, it passes.
    api._require_dashboard_confirmation(
        "destination_trust",
        {"kind": "destination", "value": "store:crm", "confirm": "destination-trust"},
    )


def test_destination_trust_edits_require_admin_token(monkeypatch):
    api = _load_plugin_api()
    monkeypatch.setenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", "s3cret")
    # Wrong / missing token -> rejected.
    with pytest.raises(api.HTTPException) as exc:
        api._require_dashboard_admin(_request({"x-hermes-guardian-token": "wrong"}))
    assert exc.value.status_code == 403
    # Correct token -> allowed.
    api._require_dashboard_admin(_request({"x-hermes-guardian-token": "s3cret"}))


def test_dashboard_mutations_disabled_blocks_admin(monkeypatch):
    api = _load_plugin_api()
    monkeypatch.setenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", "0")
    with pytest.raises(api.HTTPException) as exc:
        api._require_dashboard_admin(_request())
    assert exc.value.status_code == 403


def test_admin_gate_allows_when_no_token_configured(monkeypatch):
    """No admin token configured (the default): the host dashboard's own authentication
    is the gate, so the admin check passes without a Guardian token. The token is opt-in
    hardening for direct-port exposure; the read routes never leak live approval IDs, so
    the unauthenticated read-then-approve chain stays closed even here."""
    api = _load_plugin_api()
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)
    # No exception -> allowed (host auth is the gate).
    api._require_dashboard_admin(_request())


# --- 9. Identity/host grant raises the informational banner. --------------------------
def test_identity_grant_raises_informational_banner():
    plugin = load_plugin()
    # No grant -> no self-trust banner.
    assert not any(b["id"] == "self_trust_grants" for b in plugin._runtime_risk_banners())
    plugin._add_self_destination("identity", "me@example.com")
    banners = plugin._runtime_risk_banners()
    self_banner = next((b for b in banners if b["id"] == "self_trust_grants"), None)
    assert self_banner is not None
    assert self_banner["severity"] == "info"
    assert "send-to-self" in self_banner["message"]


def test_host_grant_raises_informational_banner():
    plugin = load_plugin()
    plugin._add_self_destination("host", "box.example.com")
    self_banner = next(
        (b for b in plugin._runtime_risk_banners() if b["id"] == "self_trust_grants"), None
    )
    assert self_banner is not None
    assert "own-infra" in self_banner["message"]


def test_verifier_model_divergence_banner_still_present(monkeypatch):
    # The existing verifier-model-divergence banner is kept alongside the new one.
    plugin = load_plugin()
    # The risk-banner set is additive; the new banner does not displace existing ones.
    plugin._set_security_rule("intrinsic_exfiltration", False)
    plugin._add_self_destination("identity", "me@example.com")
    ids = {b["id"] for b in plugin._runtime_risk_banners()}
    assert "intrinsic_exfiltration_disabled" in ids
    assert "self_trust_grants" in ids


def test_policy_snapshot_exposes_destination_trust_summary():
    plugin = load_plugin()
    snapshot = plugin._policy_snapshot()
    assert "destination_trust" in snapshot
    summary = snapshot["destination_trust"]
    for key in ("tally", "self", "trusted_recipients", "outward_sharing", "self_grants_present"):
        assert key in summary


# --- Commit 1: a pending block carries the trust pill + decision step (doc 03 §3.2). ---
def test_pending_block_snapshot_carries_trust_and_decision_step():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "stranger@example.com", "text": "hi"},
        session_id="s1",
    )
    assert result is not None and result.get("action") == "block"

    pending = plugin._policy_snapshot()["pending"]
    assert pending, "expected a pending approval for the gated external send"
    block = pending[0]
    # External boundary crossing → step6, trust=external (the warning pill in the UI).
    assert block["destination_trust"] == "external"
    assert block["decision_step"] == "step6_approve_external"


# --- Commit 2: the "Seen recently" list + one-click add-to-self suggestion. -----------
def test_suggest_self_grant_maps_destinations_to_valid_grants():
    plugin = load_plugin()
    # Hostnames -> own-infra host grant.
    assert plugin._suggest_self_grant("docs.google.com") == {"kind": "host", "value": "docs.google.com"}
    # MCP connectors stay MCP grants; store destinations stay store grants.
    assert plugin._suggest_self_grant("mcp:notion") == {"kind": "destination", "value": "mcp:notion"}
    assert plugin._suggest_self_grant("store:crm") == {"kind": "destination", "value": "store:crm"}
    # Pseudo-destinations, IPs, and empties are NOT one-click addable.
    for non_addable in ("", "web_search", "cron", "telegram", "127.0.0.1", "messaging"):
        assert plugin._suggest_self_grant(non_addable) is None


def test_destination_trust_summary_includes_seen_with_suggestion():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    # Gate an external send so an external destination is recorded.
    plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "stranger@example.com", "text": "hi"},
        session_id="s1",
    )
    summary = plugin._destination_trust_summary()
    assert "seen" in summary and isinstance(summary["seen"], list)
    # Every seen entry is metadata-only and carries trust + count + recipient.
    for entry in summary["seen"]:
        assert set(entry) >= {"destination", "trust", "count", "suggest", "recipient_identity"}


def test_seen_groups_messaging_by_pseudonymized_recipient():
    """Messaging egress to distinct recipients yields distinct seen entries keyed by the
    pseudonymized recipient_identity (never a raw address), so the dashboard can show a
    recipients bucket. Metadata-only: the recipient is the recipient_<hash> token."""
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    for who in ("alice@example.com", "bob@example.com"):
        plugin._on_pre_tool_call(
            tool_name="send_message",
            args={"to": who, "text": "hi"},
            session_id="s1",
        )
    seen = plugin._destination_trust_summary()["seen"]
    recipients = {
        str(e.get("recipient_identity"))
        for e in seen
        if str(e.get("recipient_identity") or "none") != "none"
    }
    # Two distinct recipients -> two distinct pseudonymized tokens, never the raw address.
    assert len(recipients) >= 2
    assert all(r.startswith("recipient_") for r in recipients)
    assert not any("@" in r for r in recipients)


def test_add_to_self_suggestion_flips_resolution_external_to_self():
    """The centerpiece interaction: claiming a seen destination moves it into the
    self-allowlist so the same destination resolves self instead of external/unknown."""
    plugin = load_plugin()
    SELF = plugin._DestinationTrust.SELF
    before = plugin._resolve_destination_trust("network", "myvps.example.com", "post", "", plugin._load_privacy_config())
    assert before != SELF
    ok, _ = plugin._add_self_destination("host", "myvps.example.com")
    assert ok
    after = plugin._resolve_destination_trust("network", "myvps.example.com", "post", "", plugin._load_privacy_config())
    assert after == SELF

    mcp_suggest = plugin._suggest_self_grant("mcp:google")
    assert mcp_suggest == {"kind": "destination", "value": "mcp:google"}
    before_mcp = plugin._resolve_destination_trust("mcp", "google", "write", "", plugin._load_privacy_config())
    assert before_mcp != SELF
    ok, _ = plugin._add_self_destination(mcp_suggest["kind"], mcp_suggest["value"])
    assert ok
    after_mcp = plugin._resolve_destination_trust("mcp", "google", "write", "", plugin._load_privacy_config())
    assert after_mcp == SELF


def test_pending_block_trust_survives_store_reload():
    """A gateway restart reloads pending approvals from SQLite; the trust pill + step must
    survive (Commit 1 persists them as columns, not in-memory only)."""
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "stranger@example.com", "text": "hi"},
        session_id="s1",
    )
    # Drop the in-memory cache and reload purely from the store, as a restart would.
    plugin._PENDING_APPROVALS.clear()
    plugin._load_pending_approvals_from_store_unlocked()
    reloaded = list(plugin._PENDING_APPROVALS.values())
    assert reloaded, "pending approval should reload from the store"
    assert reloaded[0]["destination_trust"] == "external"
    assert reloaded[0]["decision_step"] == "step6_approve_external"
