"""Slash-command IA regroup (doc 03 §6): rename map, grouped help, new commands.

Step 2 of the IA refactor regroups `/guardian` subcommands into the five group
verbs (`activity`, `mine`, `reading`, `sharing`, `review`, `protection`) plus top-level
`status`/`why`. The old top-level names (`self`, `rules`, the bare outward
`sharing`, `security`, `tools`, `language-packs`, `privacy`) are removed, not
aliased; each capability survives via the SAME underlying handler function.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only
synthetic placeholders (example.com addresses, made-up store ids).
"""

from __future__ import annotations

import re

from support import *  # noqa: F403


# --- §6.1 Renamed commands work via the reused handler; old names are gone. ----
# One assertion per row of doc 03 §3.


def test_mine_replaces_self_and_reuses_self_handler():
    plugin = load_plugin()
    # Old name removed.
    assert plugin._handle_guardian_command("self") == "Invalid /guardian command. Try /guardian help."
    # New name does the old thing via the same handler.
    out = plugin._handle_guardian_command("mine add destination store:crm")
    assert "store:crm" in out
    assert "store:crm" in plugin._self_config_snapshot()["destinations"]
    plugin._handle_guardian_command("mine remove destination store:crm")
    assert "store:crm" not in plugin._self_config_snapshot()["destinations"]


def test_sharing_rule_replaces_rules_and_reuses_rule_handler():
    plugin = load_plugin()
    # The bare old `rules` listing name is gone as a mutating verb; `rule add`
    # is now `sharing rule add`, reusing the same rule handler.
    assert plugin._handle_guardian_command("rules") == "Invalid /guardian command. Try /guardian help."
    out = plugin._handle_guardian_command(
        "sharing rule add allow action=message_send destination=friend classes=communications"
    )
    assert "Added privacy allow rule" in out
    assert len(plugin._persistent_privacy_rules()) == 1


def test_sharing_outward_replaces_bare_sharing_outward_behavior():
    plugin = load_plugin()
    out = plugin._handle_guardian_command("sharing outward add crosspost")
    assert "crosspost" in plugin._outward_sharing_snapshot()["extra"]
    plugin._handle_guardian_command("sharing outward remove crosspost")
    assert "crosspost" not in plugin._outward_sharing_snapshot()["extra"]


def test_sharing_trusted_reuses_trusted_handler():
    plugin = load_plugin()
    assert plugin._handle_guardian_command("trusted add partner@example.com") == (
        "Invalid /guardian command. Try /guardian help."
    )
    plugin._handle_guardian_command(
        "sharing trusted add partner@example.com classes=communications"
    )
    assert any(
        e["identity"] == "partner@example.com" for e in plugin._trusted_recipients_snapshot()
    )
    plugin._handle_guardian_command("sharing trusted remove partner@example.com")
    assert not plugin._trusted_recipients_snapshot()


def test_protection_security_replaces_security_and_reuses_handler():
    plugin = load_plugin()
    assert plugin._handle_guardian_command("security") == "Invalid /guardian command. Try /guardian help."
    listing = plugin._handle_guardian_command("protection security")
    assert "Hermes Guardian security rules" in listing
    disabled = plugin._handle_guardian_command("protection security disable sensitive_links")
    assert "Disabled security rule sensitive_links" in disabled


def test_reading_tool_replaces_tools_and_old_protection_location_is_gone():
    plugin = load_plugin()
    assert plugin._handle_guardian_command("tools") == "Invalid /guardian command. Try /guardian help."
    assert "Usage" in plugin._handle_guardian_command("protection tool set mcp_acme_* egress=ignore")
    plugin._remember_command_owner(
        "reading tool set mcp_acme_* source=reference", plugin._CLI_OWNER_HASH
    )
    out = plugin._handle_guardian_command("reading tool set mcp_acme_* source=reference")
    assert "Saved Reading tool classification" in out
    listing = plugin._handle_guardian_command("reading tools")
    assert "mcp_acme_*" in listing
    assert "Invalid Reading tool arguments" in plugin._handle_guardian_command(
        "reading tool set other_* egress=ignore"
    )
    plugin._remember_command_owner(
        "sharing tool set mcp_acme_* egress=ignore", plugin._CLI_OWNER_HASH
    )
    sharing_out = plugin._handle_guardian_command("sharing tool set mcp_acme_* egress=ignore")
    assert "Saved Sharing tool classification" in sharing_out
    sharing_listing = plugin._handle_guardian_command("sharing tools")
    assert "mcp_acme_*" in sharing_listing
    assert "Invalid Sharing tool arguments" in plugin._handle_guardian_command(
        "sharing tool set other_* taints=contacts"
    )
    assert "Usage" in plugin._handle_guardian_command("protection source suggest")


def test_reading_source_command_replaces_protection_source():
    plugin = load_plugin()
    assert "No undeclared MCP doc-read sources" in plugin._handle_guardian_command("reading source suggest")
    plugin._remember_command_owner("reading source set crm reference", plugin._CLI_OWNER_HASH)
    out = plugin._handle_guardian_command("reading source set crm reference")
    assert "crm" in out
    assert plugin._reading_tool_for("crm_read_resource").get("source") == "reference"
    plugin._remember_command_owner("reading source set time public", plugin._CLI_OWNER_HASH)
    out = plugin._handle_guardian_command("reading source set time public")
    assert "time" in out
    assert plugin._reading_tool_for("time_read_resource").get("source") == "public"


def test_protection_language_packs_replaces_language_packs_and_reuses_handler():
    plugin = load_plugin()
    assert plugin._handle_guardian_command("language-packs") == (
        "Invalid /guardian command. Try /guardian help."
    )
    listing = plugin._handle_guardian_command("protection language-packs")
    assert "Hermes Guardian language packs" in listing
    disabled = plugin._handle_guardian_command("protection language-packs disable es")
    assert "Disabled language pack es" in disabled


def test_review_maps_privacy_setters_and_old_privacy_name_is_gone():
    plugin = load_plugin()
    # The old `privacy` group name is removed.
    assert plugin._handle_guardian_command("privacy mode off") == (
        "Invalid /guardian command. Try /guardian help."
    )
    # Each review verb reuses the review/egress setter.
    plugin._remember_command_owner("review egress-safety read-only", plugin._CLI_OWNER_HASH)
    assert "read-only" in plugin._handle_guardian_command("review egress-safety read-only")
    assert plugin._egress_safety_policy() == "read-only"
    assert "Usage" in plugin._handle_guardian_command("review mode strict")
    assert plugin._egress_safety_policy() == "read-only"
    plugin._remember_command_owner("review owner-context off", plugin._CLI_OWNER_HASH)
    plugin._handle_guardian_command("review owner-context off")
    assert plugin._llm_user_context_enabled() is False
    plugin._remember_command_owner("review cron-context on", plugin._CLI_OWNER_HASH)
    plugin._handle_guardian_command("review cron-context on")
    assert plugin._llm_cron_context_enabled() is True
    assert "Usage" in plugin._handle_guardian_command("protection taint-classification relaxed")
    plugin._remember_command_owner("reading taint-classification relaxed", plugin._CLI_OWNER_HASH)
    plugin._handle_guardian_command("reading taint-classification relaxed")
    assert plugin._taint_classification_mode() == "relaxed"
    plugin._remember_command_owner("reading llm-source-classification off", plugin._CLI_OWNER_HASH)
    plugin._handle_guardian_command("reading llm-source-classification off")
    assert plugin._llm_source_classification_enabled() is False
    plugin._remember_command_owner("reading tool set crm_* source=unknown", plugin._CLI_OWNER_HASH)
    assert "Saved Reading tool" in plugin._handle_guardian_command("reading tool set crm_* source=unknown")
    assert plugin._reading_tools()[0]["source"] == "unknown"
    plugin._remember_command_owner("reading tool set clock_* source=public", plugin._CLI_OWNER_HASH)
    assert "Saved Reading tool" in plugin._handle_guardian_command("reading tool set clock_* source=public")
    assert plugin._reading_tool_for("clock_now")["source"] == "public"
    review_out = plugin._handle_guardian_command("review unknown-tools gate")
    assert plugin._taint_classification_mode() == "relaxed"
    assert "unknown-tools" not in review_out


def test_status_and_why_remain_top_level():
    plugin = load_plugin()
    assert "Hermes Guardian status" in plugin._handle_guardian_command("status")
    # why is unchanged and still top-level.
    assert "No Guardian activity found" in plugin._handle_guardian_command("why 9999")


def test_clear_taint_stays_under_activity():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s_taint", user_id="owner")
    plugin._taint_session("s_taint", {"communications"})
    out = plugin._handle_guardian_command("clear-taint")
    assert "Cleared Guardian taint" in out


# --- §6.2 Grouped help lists the five concepts in order with status/why on top.-
def test_grouped_help_lists_five_concepts_in_decide_order():
    plugin = load_plugin()
    help_text = plugin._handle_guardian_command("help")
    assert help_text.startswith("/guardian — privacy firewall for your agent")
    # status/why are the everyday commands, above the groups.
    assert help_text.index("status") < help_text.index("ACTIVITY")
    assert help_text.index("why <id>") < help_text.index("ACTIVITY")
    # The five concepts appear in `decide` order.
    order = ["ACTIVITY", "WHAT'S YOURS", "SHARING", "REVIEW", "PROTECTION"]
    positions = [help_text.index(name) for name in order]
    assert positions == sorted(positions)
    # No removed top-level names are advertised.
    for removed in ("/guardian self", "/guardian rules", "/guardian security",
                    "/guardian tools", "/guardian language-packs", "/guardian privacy"):
        assert removed not in help_text


# --- §6.3 New commands: check, sharing preview, approvals/approve/deny. --------
def test_sharing_preview_returns_the_firing_step():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    out = plugin._handle_guardian_command(
        "sharing preview message_send stranger@example.com communications"
    )
    assert "Guardian send preview" in out
    assert "Decide step:" in out
    assert "Outcome:" in out
    # An external tainted send in strict mode gates/blocks.
    assert "external" in out


def test_approvals_approve_round_trip_against_seeded_pending_item():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "friend", "text": "hello"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    listing = plugin._handle_guardian_command("approvals")
    assert approval_id in listing
    assert "message_send" in listing

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id} 5m"))
    approved = plugin._handle_guardian_command(f"approve {approval_id} 5m")
    assert "Approved message_send" in approved
    assert approval_id not in plugin._PENDING_APPROVALS


def test_deny_round_trip_against_seeded_pending_item():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian deny {approval_id}"))
    denied = plugin._handle_guardian_command(f"deny {approval_id}")
    assert "Dismissed guardian approval" in denied
    assert approval_id not in plugin._PENDING_APPROVALS


def test_bare_approve_shows_the_permit_menu_without_granting():  # doc 06 §7.1
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian approve {approval_id}"))
    out = plugin._handle_guardian_command(f"approve {approval_id}")
    # Bare `approve <id>` lists the ways to permit.
    assert "Ways to permit" in out
    assert f"/guardian approve {approval_id} 5m" in out
    assert f"/guardian approve {approval_id} forever" in out
    assert f"/guardian approve {approval_id} mine" in out  # this recipient is me
    assert "Approved" not in out
    assert plugin._persistent_privacy_rules() == []
    assert approval_id in plugin._PENDING_APPROVALS


# --- §6.4 Delegation, not duplication: group verb == original handler. ---------
def test_check_delegates_to_resolve_widget_identically():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    # The command's trust label must match the underlying read-only widget exactly.
    direct = plugin._dashboard_resolve_destination("stranger@example.com")
    out = plugin._handle_guardian_command("check stranger@example.com")
    assert f"-> {direct['trust']}" in out


def test_sharing_preview_delegates_to_preview_widget_identically():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    direct = plugin._dashboard_preview_send(
        "message_send", "stranger@example.com", ["communications"]
    )
    out = plugin._handle_guardian_command(
        "sharing preview message_send stranger@example.com communications"
    )
    assert direct["decision_step"] in out
    assert f"Outcome: {direct['decision']}" in out


def test_mine_delegates_to_self_handler_identically():
    plugin = load_plugin()
    plugin._add_self_destination("destination", "store:crm")
    # The `mine` group verb and the original `self` handler produce byte-identical
    # output for the same input — proving delegation, not a reimplementation.
    via_group = plugin._handle_guardian_command("mine")
    via_handler = plugin._guardian_self_command(plugin._CLI_OWNER_HASH, ["mine"])
    assert via_group == via_handler
    assert "store:crm" in via_group


def test_review_egress_safety_delegates_to_setter_identically():
    plugin_a = load_plugin()
    plugin_b = load_plugin()
    plugin_a._remember_command_owner("review egress-safety strict", plugin_a._CLI_OWNER_HASH)
    via_group = plugin_a._handle_guardian_command("review egress-safety strict")
    via_handler = plugin_b._guardian_privacy_command(
        plugin_b._CLI_OWNER_HASH, ["privacy", "egress-safety", "strict"]
    )
    assert via_group == via_handler
    assert plugin_a._egress_safety_policy() == plugin_b._egress_safety_policy() == "strict"
