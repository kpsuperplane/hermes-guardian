from __future__ import annotations

import json

from support import *  # noqa: F403


def _row(rows, *, row_type: str, match: str):
    return next(
        row
        for row in rows
        if row.get("row_type") == row_type and row.get("match") == match
    )


def test_tool_inventory_records_sanitized_call_and_result_metadata():
    plugin = load_plugin()
    bind_owner(plugin, session_id="inventory")

    plugin._on_pre_tool_call(
        "crm_read_resource",
        {"query": "raw private search", "url": "https://example.com/private/path?q=secret"},
        session_id="inventory",
    )
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource",
        result='{"private": "raw result content"}',
        session_id="inventory",
    )

    rows = plugin._tool_inventory_rows()
    assert len(rows) == 1
    row = rows[0]
    assert row["tool_name"] == "crm_read_resource"
    assert row["call_count"] == 1
    assert row["result_count"] == 1
    assert row["observed_read_families"] == ["mcp_read"]
    assert row["mcp_server_prefix"] == "crm"

    encoded = json.dumps(row)
    assert "raw private search" not in encoded
    assert "raw result content" not in encoded
    assert "secret" not in encoded


def test_tool_inventory_survives_activity_pruning(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_MAX_ROWS", "1")
    monkeypatch.setenv("HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS", "0")

    plugin._record_tool_inventory("seen_tool", call=True, egress_family="tool_unknown")
    for index in range(5):
        plugin._emit_activity("blocked", session_id=f"s{index}", tool_name=f"tool_{index}")

    plugin._prune_activity_db(force=True)

    assert [row["tool_name"] for row in plugin._tool_inventory_rows()] == ["seen_tool"]
    assert len(plugin._activity_rows({}, limit=10)) == 1


def test_tool_inventory_counts_empty_and_non_string_results_without_taint():
    plugin = load_plugin()

    plugin._on_transform_tool_result("empty_result_tool", "", session_id="inventory")
    plugin._on_transform_tool_result("structured_result_tool", {"ok": True}, session_id="inventory")

    rows = {row["tool_name"]: row for row in plugin._tool_inventory_rows()}
    assert rows["empty_result_tool"]["result_count"] == 1
    assert rows["structured_result_tool"]["result_count"] == 1
    assert rows["empty_result_tool"]["observed_read_families"] == []
    assert rows["structured_result_tool"]["observed_read_families"] == []
    assert not plugin._session_taint("inventory")


def test_policy_snapshot_inventory_resolves_prefix_and_exact_policies():
    plugin = load_plugin()
    bind_owner(plugin, session_id="inventory")

    plugin._on_pre_tool_call("crm_read_resource", {}, session_id="inventory")
    plugin._on_transform_tool_result("crm_read_resource", "plain text", session_id="inventory")
    assert plugin._set_reading_tool("crm_*", source="private", taints=["documents"])[0]
    assert plugin._set_sharing_tool("crm_read_resource", egress="ignore")[0]

    snapshot = plugin._policy_snapshot()
    reading_rows = snapshot["reading_tool_inventory"]
    sharing_rows = snapshot["sharing_tool_inventory"]

    reading_child = _row(reading_rows, row_type="tool", match="crm_read_resource")
    assert reading_child["policy_state"] == "inherited"
    assert reading_child["policy"]["match"] == "crm_*"
    assert reading_child["policy"]["source"] == "private"

    sharing_child = _row(sharing_rows, row_type="tool", match="crm_read_resource")
    assert sharing_child["policy_state"] == "exact"
    assert sharing_child["policy"]["match"] == "crm_read_resource"
    assert sharing_child["policy"]["egress"] == "ignore"


def test_same_seen_tool_has_independent_reading_and_sharing_policy_views():
    plugin = load_plugin()
    plugin._record_tool_inventory("acme_lookup", call=True, result=True)
    assert plugin._set_reading_tool("acme_*", source="reference")[0]
    assert plugin._set_sharing_tool("acme_*", egress="gate")[0]

    snapshot = plugin._policy_snapshot()
    reading_child = _row(snapshot["reading_tool_inventory"], row_type="tool", match="acme_lookup")
    sharing_child = _row(snapshot["sharing_tool_inventory"], row_type="tool", match="acme_lookup")

    assert reading_child["policy"]["source"] == "reference"
    assert "egress" not in reading_child["policy"]
    assert sharing_child["policy"]["egress"] == "gate"
    assert "source" not in sharing_child["policy"]


def test_inventory_includes_policy_only_rows_for_unseen_matchers():
    plugin = load_plugin()
    assert plugin._set_reading_tool("unseen_tool", source="unknown")[0]
    assert plugin._set_sharing_tool("unseen_*", egress="ignore")[0]

    snapshot = plugin._policy_snapshot()
    reading_policy = _row(snapshot["reading_tool_inventory"], row_type="policy", match="unseen_tool")
    sharing_group = _row(snapshot["sharing_tool_inventory"], row_type="group", match="unseen_*")

    assert reading_policy["policy_state"] == "policy_only"
    assert reading_policy["policy"]["source"] == "unknown"
    assert sharing_group["policy_state"] == "policy_only"
    assert sharing_group["policy"]["egress"] == "ignore"
