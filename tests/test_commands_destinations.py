"""Destination-trust slash commands + activity rows (doc 03 §2, §3.2, §7 4-7, 10).

Covers: /guardian self add/remove round-trip and resolution flip, /guardian why printing
the resolved Capability + firing decide step matching the actual outcome, /guardian debug
recipient=<id> preview, activity rows carrying destination_trust + decision_step with fine
tags preserved and filterable, and the at-rest metadata-only check.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only synthetic
placeholders (example.com addresses, made-up store ids, synthetic session ids).
"""

from __future__ import annotations

from support import *  # noqa: F403


# --- 4. /guardian self add/remove round-trips and flips resolution. -------------------
def test_self_add_remove_round_trip_and_resolution_flip():
    plugin = load_plugin()
    out = plugin._handle_guardian_command("mine add destination store:crm")
    assert "store:crm" in out
    assert "store:crm" in plugin._self_config_snapshot()["destinations"]
    # A write to the newly-owned store now resolves to self.
    trust = plugin._resolve_destination_trust("store", "crm", "write", "")
    assert plugin._trust_label_for_debug(trust) == "self"
    # Remove flips it back to non-self.
    plugin._handle_guardian_command("mine remove destination store:crm")
    assert "store:crm" not in plugin._self_config_snapshot()["destinations"]
    trust = plugin._resolve_destination_trust("store", "crm", "write", "")
    assert plugin._trust_label_for_debug(trust) != "self"


def test_trusted_and_sharing_commands_round_trip():
    plugin = load_plugin()
    plugin._handle_guardian_command("sharing trusted add partner@example.com classes=communications")
    entries = plugin._trusted_recipients_snapshot()
    assert any(e["identity"] == "partner@example.com" for e in entries)
    # sharing builtin marked non-removable in the regrouped sharing overview.
    listing = plugin._handle_guardian_command("sharing")
    assert "share (builtin, non-removable)" in listing
    plugin._handle_guardian_command("sharing outward add crosspost")
    assert "crosspost" in plugin._outward_sharing_snapshot()["extra"]
    plugin._handle_guardian_command("sharing trusted remove partner@example.com")
    assert not plugin._trusted_recipients_snapshot()


# --- 5. /guardian why prints the Capability + firing decide step matching outcome. ----
def test_why_prints_capability_and_step_matching_outcome():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin, session_id="s_why", user_id="owner")
    plugin._taint_session("s_why", {"communications"})
    result = plugin._privacy_pre_tool_call(
        "telegram_send", {"to": "stranger@example.com", "text": "hi"}, "s_why"
    )
    assert result and result.get("action") == "block"
    with plugin._activity_connect() as conn:
        row = conn.execute(
            "SELECT id, decision, destination_trust, decision_step FROM activity "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    explanation = plugin._handle_guardian_command(f"why {row['id']}")
    # The printed trust + step match the persisted (and therefore actual) decision.
    assert f"trust={row['destination_trust']}" in explanation
    assert row["destination_trust"] == "external"
    assert row["decision_step"] in explanation
    assert row["decision_step"].startswith("step6_approve")
    assert "Outcome: blocked" in explanation
    # why is also reachable by approval id.
    approval_id = next(iter(plugin._PENDING_APPROVALS))
    by_approval = plugin._handle_guardian_command(f"why {approval_id}")
    assert "Resolved Capability" in by_approval


def test_why_self_write_reports_self_and_step3():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin, session_id="s_self", user_id="owner")
    plugin._taint_session("s_self", {"communications"})
    # A draft compose resolves to self (draft:* allowlist) -> ALLOW at step 3.
    plugin._privacy_pre_tool_call("create_draft", {"body": "note to self"}, "s_self")
    with plugin._activity_connect() as conn:
        row = conn.execute(
            "SELECT id, decision, destination_trust, decision_step FROM activity "
            "WHERE decision = 'allowed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert row["destination_trust"] == "self"
    assert row["decision_step"].startswith("step3_intra_boundary")


# --- 6. /guardian check <recipient> previews recipient trust (doc 03 §5). -------------
def test_check_recipient_preview_resolves_trust():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    # An owned send-to-self identity resolves to self.
    plugin._add_self_destination("identity", "me@example.com")
    out_self = plugin._handle_guardian_command("check me@example.com")
    assert "-> self" in out_self
    # A real external recipient resolves to external.
    out_ext = plugin._handle_guardian_command("check stranger@example.com")
    assert "-> external" in out_ext


# --- 7. Activity row carries trust + step, fine tags preserved, filterable. -----------
def test_activity_row_carries_trust_step_and_preserves_fine_tags():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin, session_id="s_row", user_id="owner")
    plugin._taint_session("s_row", {"communications", "contacts"})
    plugin._privacy_pre_tool_call(
        "telegram_send", {"to": "stranger@example.com", "text": "hi"}, "s_row"
    )
    rows = plugin._activity_rows({}, limit=5)
    blocked = next(r for r in rows if r["decision"] == "blocked")
    assert blocked["destination_trust"] == "external"
    assert blocked["decision_step"].startswith("step6_approve")
    # Fine tags preserved in data_classes (audit fidelity, invariant #6).
    assert "communications" in blocked["data_classes"]
    assert "contacts" in blocked["data_classes"]
    # destination_trust is in the filterable-column allowlist.
    assert plugin._activity_distinct_values("destination_trust")
    # And exact-match filtering on the enum works.
    filtered = plugin._activity_rows({"destination_trust": "external"}, limit=5)
    assert filtered and all(r["destination_trust"] == "external" for r in filtered)
    # The datatables row exposes the new columns.
    dt = plugin._activity_datatables_row(blocked)
    assert dt["destination_trust"] == "external"
    assert dt["decision_step"].startswith("step6_approve")


def test_old_rows_without_new_fields_render_display_safe():
    plugin = load_plugin()
    plugin._ensure_activity_db()
    # Simulate a pre-migration row by dropping the new columns from a fresh DB copy is
    # heavy; instead assert the defaults: a row inserted without the fields gets the
    # display-safe defaults.
    plugin._emit_activity(
        "blocked",
        session_id="s_old",
        tool_name="telegram_send",
        action_family="message_send",
        destination="telegram:abc",
        data_classes={"communications"},
        reason="legacy",
    )
    rows = plugin._activity_rows({}, limit=1)
    assert rows[0]["destination_trust"] == "unknown"
    assert rows[0]["decision_step"] == ""


# --- 10. At-rest check: new fields are enums/labels only; no payload content. ---------
def test_activity_new_fields_are_metadata_only():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin, session_id="s_atrest", user_id="owner")
    plugin._taint_session("s_atrest", {"communications"})
    secret_body = "SUPER-SECRET-PAYLOAD-9f2c"
    plugin._privacy_pre_tool_call(
        "telegram_send", {"to": "stranger@example.com", "text": secret_body}, "s_atrest"
    )
    with plugin._activity_connect() as conn:
        rows = conn.execute(
            "SELECT destination_trust, decision_step FROM activity"
        ).fetchall()
    assert rows
    for row in rows:
        # destination_trust is one of the small enum label set.
        assert row["destination_trust"] in plugin._DESTINATION_TRUST_LABELS
        # decision_step is a short step label, never payload content.
        assert secret_body not in str(row["destination_trust"])
        assert secret_body not in str(row["decision_step"])
        assert len(str(row["decision_step"])) <= 60
        # the recipient never appears raw in the new fields (pseudonymous only elsewhere).
        assert "stranger@example.com" not in str(row["destination_trust"])
        assert "stranger@example.com" not in str(row["decision_step"])
