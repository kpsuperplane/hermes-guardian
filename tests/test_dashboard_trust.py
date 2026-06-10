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
