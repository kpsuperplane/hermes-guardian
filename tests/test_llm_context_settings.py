"""Config, slash-command, and dashboard surface for the LLM context settings.

Two privacy-level booleans gate the authorization-evidence channels:
`llm_user_context` (default on) and `llm_cron_context` (default on). These tests
cover defaults, JSON normalization/preservation, the `/guardian privacy
user-context|cron-context` command handlers with owner checks, the dashboard adapters and
policy snapshot, and the cron-context confirmation guard.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from support import *  # noqa: F403


# --- config + normalization ----------------------------------------------

def test_defaults_user_on_cron_on():
    plugin = load_plugin()
    assert plugin._llm_user_context_enabled() is True
    assert plugin._llm_cron_context_enabled() is True


def test_settings_persist_and_preserve_other_privacy_config(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None

    assert plugin._set_llm_user_context(False)[0]
    assert plugin._set_llm_cron_context(True)[0]
    # A later, unrelated mutation must not clobber the context flags.
    assert plugin._set_taint_classification_mode("relaxed")[0]
    assert plugin._set_egress_safety_mode("strict")[0]

    data = json.loads((tmp_path / "rules.json").read_text())
    # v4 on-disk: the sharing block carries Egress Safety + context flags; source/sink
    # fallback lives in the reading block.
    sharing = data["sharing"]
    assert sharing["owner_context"] is False
    assert sharing["cron_context"] is True
    assert data["reading"]["taint_classification"] == "relaxed"
    assert sharing["egress_safety"] == "strict"
    assert plugin._llm_user_context_enabled() is False
    assert plugin._llm_cron_context_enabled() is True


def test_normalization_coerces_loose_values(tmp_path):
    plugin = load_plugin()
    path = tmp_path / "rules.json"
    # v4 sharing block; loose string booleans normalize via _config_bool.
    path.write_text(json.dumps({
        "version": 4,
        "sharing": {"egress_safety": "llm", "owner_context": "off", "cron_context": "yes"},
    }))
    plugin.state._PERSISTENT_RULES_PATH = path
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None

    assert plugin._llm_user_context_enabled() is False
    assert plugin._llm_cron_context_enabled() is True


def test_invalid_context_value_is_rejected_to_fail_closed(tmp_path):
    plugin = load_plugin()
    path = tmp_path / "rules.json"
    # A hard-typed sharing.cron_context (an object) is rejected at validation so the
    # whole document fails closed to strict rather than silently coercing.
    path.write_text(json.dumps({
        "version": 4,
        "sharing": {"egress_safety": "llm", "cron_context": {"unexpected": "object"}},
    }))
    plugin.state._PERSISTENT_RULES_PATH = path
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None

    # Invalid config falls back to strict; context defaults still apply.
    assert plugin._egress_safety_policy() == "strict"
    assert plugin._llm_cron_context_enabled() is True


def test_policy_snapshot_exposes_both_flags():
    plugin = load_plugin()
    plugin._set_llm_cron_context(True)
    snap = plugin._policy_snapshot()
    assert snap["llm_user_context"] is True
    assert snap["llm_cron_context"] is True
    assert not any(b["id"] == "llm_cron_context" for b in snap["risk_banners"])


# --- slash command --------------------------------------------------------

def test_slash_toggles_contexts_as_owner():
    plugin = load_plugin()

    assert "off" in plugin._handle_guardian_command("sharing owner-context off")
    assert plugin._llm_user_context_enabled() is False
    assert "on" in plugin._handle_guardian_command("sharing cron-context on")
    assert plugin._llm_cron_context_enabled() is True


def test_slash_status_surfaces_context_flags():
    plugin = load_plugin()
    plugin._set_llm_cron_context(True)
    status = plugin._handle_guardian_command("status")
    assert "user-prompt on" in status
    assert "cron on" in status


def test_slash_invalid_value_returns_usage():
    plugin = load_plugin()
    response = plugin._handle_guardian_command("sharing cron-context maybe")
    assert "Usage: /guardian sharing cron-context on|off" in response
    assert plugin._llm_cron_context_enabled() is True


def test_non_owner_cannot_toggle_contexts():
    plugin = load_plugin()

    plugin._on_pre_gateway_dispatch(gateway_event("/guardian sharing cron-context off", user_id="attacker"))
    response = plugin._handle_guardian_command("sharing cron-context off")

    assert "Permission denied" in response
    assert plugin._llm_cron_context_enabled() is True


# --- dashboard adapters + confirmation guard ------------------------------

def test_dashboard_adapters_update_and_return_snapshot():
    plugin = load_plugin()

    payload, status = plugin._dashboard_llm_user_context_action(False)
    assert status == 200 and payload["ok"] is True
    assert payload["policy"]["llm_user_context"] is False

    payload, status = plugin._dashboard_llm_cron_context_action(True)
    assert status == 200 and payload["ok"] is True
    assert payload["policy"]["llm_cron_context"] is True


def _load_plugin_api():
    server_path = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("hermes_guardian_dashboard_api_ctx", server_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_enabling_cron_context_requires_confirmation():
    api = _load_plugin_api()

    with pytest.raises(api.HTTPException):
        api._require_dashboard_confirmation("llm_cron_context", {"enabled": True})

    # With the confirmation token, the guard passes.
    api._require_dashboard_confirmation("llm_cron_context", {"enabled": True, "confirm": "cron-context-on"})
    # Disabling never needs confirmation.
    api._require_dashboard_confirmation("llm_cron_context", {"enabled": False})
