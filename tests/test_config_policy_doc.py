"""One-policy-document config tests (doc 03 §1 + doc 04 carryover fix).

Covers: a partial v4 file filling the rest from safe defaults, fail-closed parse of
malformed v4 blocks, the non-narrowable outward-sharing builtin, the env-override
surfacing, and the carryover bug fix (an operator-customized self block must survive
an unrelated mode/rule save). All config is authored in the v4 five-block schema —
there is no back-compat with the old key paths.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only
synthetic placeholders.
"""

from __future__ import annotations

import json

from support import *  # noqa: F403


def _write_config(plugin, data: dict) -> None:
    plugin.state._PERSISTENT_RULES_PATH.write_text(json.dumps(data))
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None


# --- 1. v4 partial load: a file with only some blocks fills the rest from defaults. ---
def test_v4_partial_config_fills_defaults():
    plugin = load_plugin()
    _write_config(
        plugin,
        {
            "version": 4,
            "review": {
                "mode": "strict",
            },
            "sharing": {
                "rules": [privacy_rule(rule_id="rule_allow", effect="allow")],
            },
        },
    )
    config = plugin._load_privacy_config()
    # Authored rule honored unchanged (sharing.rules -> internal privacy.rules).
    assert [r["id"] for r in config["privacy"]["rules"]] == ["rule_allow"]
    # whats_yours absent -> self defaults seeded; identities/hosts default EMPTY.
    assert config["self"]["destinations"]  # non-empty default store list
    assert config["self"]["identities"] == []
    assert config["self"]["hosts"] == []
    assert "trusted_recipients" in config and config["trusted_recipients"]["entries"] == []
    assert set(config["outward_sharing"]["builtin"]) == set(plugin._OUTWARD_SHARING_BUILTIN_SUBTYPES)
    # version is the current document version on normalize.
    assert config["version"] == plugin._PRIVACY_RULE_FILE_VERSION == 4
    # protection block absent -> retention / dashboard injected with defaults.
    assert config["retention"]["max_rows"] == plugin._DEFAULT_RETENTION_MAX_ROWS
    assert config["dashboard"]["mutations"] == plugin._DEFAULT_DASHBOARD_MUTATIONS


# --- 2. Fail-closed parse: malformed self/outward_sharing -> safe subset. -------------
def test_malformed_self_block_drops_to_safe_subset():
    plugin = load_plugin()
    _write_config(
        plugin,
        {
            "version": 4,
            "review": {"mode": "strict"},
            "whats_yours": "not-a-dict",  # wholly malformed block
            "sharing": {"outward": 12345},  # malformed outward block
        },
    )
    config = plugin._load_privacy_config()
    # Safe default subset: default destinations, EMPTY identities/hosts.
    assert config["self"]["destinations"] == list(plugin._DEFAULT_SELF_DESTINATIONS)
    assert config["self"]["identities"] == []
    assert config["self"]["hosts"] == []
    # outward_sharing falls back to the full builtin set.
    assert set(config["outward_sharing"]["builtin"]) == set(plugin._OUTWARD_SHARING_BUILTIN_SUBTYPES)


def test_wholly_corrupt_document_falls_back_to_strict():
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH.write_text("{ this is not valid json")
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None
    config = plugin._load_privacy_config()
    assert config["privacy"]["mode"] == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True


# --- 3. Non-narrowable sharing: removing a builtin subtype has no effect. -------------
def test_outward_sharing_builtin_is_not_narrowable():
    plugin = load_plugin()
    _write_config(
        plugin,
        {
            "version": 4,
            "review": {"mode": "strict"},
            # operator tries to drop "share" and keep only "invite"; add an extra.
            "sharing": {"outward": {"builtin": ["invite"], "extra": ["crosspost"]}},
        },
    )
    config = plugin._load_privacy_config()
    # All builtin subtypes survive regardless of the narrowed list.
    assert set(config["outward_sharing"]["builtin"]) == set(plugin._OUTWARD_SHARING_BUILTIN_SUBTYPES)
    # extra additions are kept.
    assert "crosspost" in config["outward_sharing"]["extra"]
    # The remove helper also refuses a builtin.
    ok, _msg = plugin._remove_outward_sharing_subtype("share")
    assert ok is False
    assert "share" in plugin._outward_sharing_snapshot()["builtin"]


# --- Carryover fix: a customized self block survives an unrelated mode/rule save. -----
def test_self_customization_survives_unrelated_mode_change():
    plugin = load_plugin()
    # Operator adds an owned store.
    ok, _msg = plugin._add_self_destination("destination", "store:crm")
    assert ok
    assert "store:crm" in plugin._self_config_snapshot()["destinations"]
    # An UNRELATED mode change must not re-default the self block (Phase 1 carryover bug).
    plugin._set_privacy_mode("strict")
    assert "store:crm" in plugin._self_config_snapshot()["destinations"]
    # Same for an unrelated security-rule toggle and a rule save.
    plugin._set_security_rule("intrinsic_exfiltration", False)
    plugin._save_persistent_privacy_rules([privacy_rule(rule_id="r1")])
    assert "store:crm" in plugin._self_config_snapshot()["destinations"]


def test_self_add_destination_flips_resolution_external_to_self():
    plugin = load_plugin()
    # A custom store is external before the grant.
    before = plugin._resolve_destination_trust("store", "crm", "write", "")
    assert plugin._trust_label_for_debug(before) != "self"
    plugin._add_self_destination("destination", "store:crm")
    after = plugin._resolve_destination_trust("store", "crm", "write", "")
    assert plugin._trust_label_for_debug(after) == "self"


def test_tool_override_direction_and_destination_round_trip():
    plugin = load_plugin()
    ok, _msg = plugin._set_tool_override("crm_*", direction="read", destination="store:crm")
    assert ok
    override = plugin._tool_override_for("crm_lookup")
    assert override is not None
    assert override["direction"] == "read"
    assert override["destination"] == "store:crm"
    # An invalid direction is rejected.
    ok, msg = plugin._set_tool_override("crm_*", direction="sideways")
    assert ok is False
    assert "direction" in msg


def test_env_overrides_surface_in_status(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_MAX_ROWS", "5")
    overrides = plugin._active_env_overrides()
    assert any("HERMES_GUARDIAN_ACTIVITY_MAX_ROWS" in line for line in overrides)
    status = plugin._handle_guardian_command("status")
    assert "Env overrides shadowing the policy document" in status
    assert "HERMES_GUARDIAN_ACTIVITY_MAX_ROWS" in status
    # The env value actually drives the effective retention setting.
    assert plugin._activity_max_rows() == 5
