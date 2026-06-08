from __future__ import annotations

import json

from support import *  # noqa: F403
from language_packs.runtime import _ALL_PACK_IDS


def test_language_packs_default_enabled_in_policy_snapshot():
    plugin = load_plugin()

    packs = {pack["id"]: pack for pack in plugin._policy_snapshot()["language_packs"]}

    assert packs["en"]["enabled"] is True
    assert packs["en"]["required"] is True
    assert packs["es"]["enabled"] is True


def test_disabling_spanish_language_pack_updates_scanner_and_json(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None

    assert plugin._sensitive_reason("Restablecer tu contraseña ahora") == "password reset"

    ok, message = plugin._set_language_pack("es", False)

    assert ok is True
    assert "Disabled language pack es" in message
    assert plugin._sensitive_reason("Restablecer tu contraseña ahora") is None
    assert plugin._sensitive_reason("Reset your password now") == "password reset"
    data = json.loads((tmp_path / "rules.json").read_text())
    assert data["language_packs"]["enabled"] == [pack_id for pack_id in _ALL_PACK_IDS if pack_id != "es"]


def test_language_pack_can_be_disabled_by_direct_json_edit(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None
    plugin._PERSISTENT_RULES_MTIME = None
    (tmp_path / "rules.json").write_text(json.dumps({
        "version": 1,
        "privacy": {
            "mode": "strict",
            "rules": [],
        },
        "language_packs": {
            "enabled": ["en"],
        },
    }))

    packs = {pack["id"]: pack for pack in plugin._policy_snapshot()["language_packs"]}

    assert packs["en"]["enabled"] is True
    assert packs["es"]["enabled"] is False
    assert plugin._sensitive_reason("Restablecer tu contraseña ahora") is None


def test_privacy_and_security_saves_preserve_language_pack_config(tmp_path):
    plugin = load_plugin()
    plugin._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin._PERSISTENT_RULES_CACHE = None

    assert plugin._set_language_pack("es", False)[0]
    assert plugin._set_privacy_mode("read-only")[0]
    assert plugin._set_security_rule("sensitive_links", False)[0]

    data = json.loads((tmp_path / "rules.json").read_text())

    assert data["privacy"]["mode"] == "read-only"
    assert data["language_packs"]["enabled"] == [pack_id for pack_id in _ALL_PACK_IDS if pack_id != "es"]


def test_english_language_pack_cannot_be_disabled():
    plugin = load_plugin()

    ok, message = plugin._set_language_pack("en", False)

    assert ok is False
    assert "English language pack is required" in message
    assert plugin._language_pack_ids() == list(_ALL_PACK_IDS)


def test_language_pack_slash_command_lists_and_toggles_packs():
    plugin = load_plugin()

    listing = plugin._handle_guardian_command("language-packs")
    disabled = plugin._handle_guardian_command("language-packs disable es")
    enabled = plugin._handle_guardian_command("languages enable es")

    assert "Hermes Guardian language packs" in listing
    assert "en: enabled required" in listing
    assert "es: enabled" in listing
    assert "Disabled language pack es" in disabled
    assert "Enabled language pack es" in enabled


def test_non_owner_cannot_toggle_language_pack():
    plugin = load_plugin()
    plugin._on_pre_gateway_dispatch(gateway_event("/guardian language-packs disable es", user_id="not-owner"))

    response = plugin._handle_guardian_command("language-packs disable es")

    assert "Permission denied" in response


def test_dashboard_language_pack_action_updates_policy():
    plugin = load_plugin()

    payload, status = plugin._dashboard_language_pack_action("es", "false")

    assert status == 200
    assert payload["ok"] is True
    packs = {pack["id"]: pack for pack in payload["policy"]["language_packs"]}
    assert packs["es"]["enabled"] is False
