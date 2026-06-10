"""Turn grouping + opt-in prompt persistence.

History rows carry a turn_id (one user prompt + the actions it drove) so the dashboard
can group them. A default-off `protection.runtime.persist_prompts` setting additionally
writes the ALREADY-sanitized user/cron prompt onto rows for debugging. Per project
memory, only synthetic identifiers are used (no real cron job ids).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from support import *  # noqa: F403


def _owner_hash(plugin):
    return plugin._owner_hash_from_event(gateway_event("x", user_id="owner"))


def _latest(plugin):
    return plugin._activity_rows({}, limit=1)[0]


# --- Schema ------------------------------------------------------------------
def test_activity_table_has_turn_columns():
    plugin = load_plugin()
    plugin._ensure_activity_db()
    with plugin._activity_connect() as conn:
        cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(activity)").fetchall()}
    assert "turn_id" in cols and "user_prompt" in cols


# --- Turn id -----------------------------------------------------------------
def test_turn_id_is_stamped_and_rotates_per_user_message(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)  # session s1 owned by "owner"
    owner = _owner_hash(plugin)

    plugin._on_pre_gateway_dispatch(gateway_event("first request", user_id="owner"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="a", reason="r")
    t1 = _latest(plugin)["turn_id"]

    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="a2", reason="r")
    t1b = _latest(plugin)["turn_id"]
    assert t1 and t1 == t1b  # same turn for actions under one prompt

    plugin._on_pre_gateway_dispatch(gateway_event("second request", user_id="owner"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="b", reason="r")
    t2 = _latest(plugin)["turn_id"]
    assert t2 and t2 != t1  # a new user message starts a new turn


def test_turn_id_lazily_assigned_for_sessions_without_a_gateway_turn():
    plugin = load_plugin()
    # A session that never hit the gateway turn boundary (e.g. cron / unauthenticated)
    # still gets a stable turn_id.
    plugin._emit_activity("blocked", session_id="cron_aabbccddeeff_20260101_120000", tool_name="a", reason="r")
    first = _latest(plugin)["turn_id"]
    plugin._emit_activity("blocked", session_id="cron_aabbccddeeff_20260101_120000", tool_name="b", reason="r")
    second = _latest(plugin)["turn_id"]
    assert first and first == second


# --- Prompt persistence ------------------------------------------------------
def test_persist_off_by_default_stores_no_prompt(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)
    owner = _owner_hash(plugin)
    assert plugin._persist_prompts_enabled() is False

    plugin._on_pre_gateway_dispatch(gateway_event("subscribe me please", user_id="owner"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="a", reason="r")
    assert _latest(plugin)["user_prompt"] == ""


def test_persist_on_stores_redacted_user_prompt(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)
    owner = _owner_hash(plugin)
    plugin._set_persist_prompts(True)

    plugin._on_pre_gateway_dispatch(
        gateway_event("email the notes to alice@example.com now", user_id="owner")
    )
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="send_message", reason="r")
    prompt = _latest(plugin)["user_prompt"]

    assert prompt  # the prompt is recorded
    assert "subscribe" not in prompt  # it's this turn's request
    assert "alice@example.com" not in prompt and "<email>" in prompt  # redacted, not raw
    assert len(prompt) <= 500


def test_persist_on_unauthenticated_sender_stores_no_prompt(monkeypatch):
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    plugin = load_plugin()
    bind_owner(plugin, user_id="stranger")
    owner = plugin._owner_hash_from_event(gateway_event("x", user_id="stranger"))
    plugin._set_persist_prompts(True)

    plugin._on_pre_gateway_dispatch(gateway_event("do something", user_id="stranger"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="a", reason="r")
    assert _latest(plugin)["user_prompt"] == ""


def test_persist_on_cron_stores_redacted_job_instruction(monkeypatch, tmp_path):
    plugin = load_plugin()  # config/state already redirected to /tmp by support
    plugin._set_persist_prompts(True)
    # Synthetic cron job + session id (no real identifiers). Point HOME at a tmp dir
    # holding the jobs.json the cron-instruction lookup reads.
    monkeypatch.setenv("HOME", str(tmp_path))
    job_id = "0123456789ab"
    cron_dir = tmp_path / ".hermes" / "cron"
    cron_dir.mkdir(parents=True, exist_ok=True)
    (cron_dir / "jobs.json").write_text(
        json.dumps({"jobs": [{"id": job_id, "prompt": "post the digest to ops@example.com"}]}),
        encoding="utf-8",
    )
    session_id = f"cron_{job_id}_20260101_090000"
    plugin._emit_activity("blocked", session_id=session_id, tool_name="send_message", reason="r")
    prompt = _latest(plugin)["user_prompt"]
    assert prompt and "ops@example.com" not in prompt and "<email>" in prompt


# --- Config round-trip -------------------------------------------------------
def test_persist_prompts_round_trips_v4():
    plugin = load_plugin()
    ok, _ = plugin._set_persist_prompts(True)
    assert ok and plugin._persist_prompts_enabled() is True
    # It serializes under protection.runtime in the on-disk v4 file...
    on_disk = json.loads(plugin._PERSISTENT_RULES_PATH.read_text())
    assert on_disk["protection"]["runtime"]["persist_prompts"] is True
    # ...and survives a cold reload.
    plugin._PERSISTENT_RULES_CACHE = None
    plugin._PERSISTENT_RULES_MTIME = None
    assert plugin._persist_prompts_enabled() is True


# --- Slash command -----------------------------------------------------------
def test_slash_persist_prompts_toggles_and_gates(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    assert "on" in plugin._handle_guardian_command("protection persist-prompts on").lower()
    assert plugin._persist_prompts_enabled() is True
    assert "off" in plugin._handle_guardian_command("protection persist-prompts off").lower()
    assert plugin._persist_prompts_enabled() is False
    assert "Usage" in plugin._handle_guardian_command("protection persist-prompts")


# --- Dashboard ---------------------------------------------------------------
def test_dashboard_snapshot_reflects_persist_prompts():
    plugin = load_plugin()
    assert plugin._policy_snapshot()["persist_prompts"] is False
    payload, status = plugin._dashboard_persist_prompts_action(True)
    assert status == 200 and payload["ok"] is True
    assert payload["policy"]["persist_prompts"] is True
    # No risk banner for prompt persistence (it is a debugging toggle, not a weakening).
    banners = plugin._policy_snapshot().get("risk_banners") or plugin._runtime_risk_banners()
    assert not any(b.get("id") == "persist_prompts" for b in banners)


def test_dashboard_persist_prompts_route_requires_confirmation():
    api = _load_plugin_api()
    with pytest.raises(api.HTTPException) as exc:
        api._require_dashboard_confirmation("persist_prompts", {"enabled": True})
    assert exc.value.status_code == 400
    # With the token it passes; disabling never needs confirmation.
    api._require_dashboard_confirmation("persist_prompts", {"enabled": True, "confirm": "persist-prompts-on"})
    api._require_dashboard_confirmation("persist_prompts", {"enabled": False})


# --- Read path: fields exposed but not searchable/sortable -------------------
def test_turn_fields_exposed_but_not_in_sort_or_search_allowlists():
    plugin = load_plugin()
    plugin._emit_activity("blocked", session_id="s1", tool_name="a", reason="r")
    row = plugin._activity_datatables_payload({"draw": "1", "start": "0", "length": "25"})["data"][0]
    assert "turn_id" in row and "user_prompt" in row
    assert "turn_id" not in plugin._DATATABLES_SORT_COLUMNS
    assert "user_prompt" not in plugin._DATATABLES_SORT_COLUMNS
    assert "user_prompt" not in plugin._DATATABLES_SEARCH_COLUMNS


# --- Turn-paginated payload (dashboard cards) --------------------------------
def test_turns_payload_groups_and_orders_by_recency(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)
    owner = _owner_hash(plugin)

    plugin._on_pre_gateway_dispatch(gateway_event("first", user_id="owner"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="a", reason="r")
    plugin._emit_activity("allowed", session_id="s1", owner_hash=owner, tool_name="b", reason="r")
    plugin._on_pre_gateway_dispatch(gateway_event("second", user_id="owner"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="c", reason="r")

    payload = plugin._activity_turns_payload({"draw": "1", "start": "0", "length": "25"})
    assert payload["recordsTotal"] == 2
    turns = payload["turns"]
    assert len(turns) == 2
    # Newest turn first; each turn carries all of its checks together.
    assert [r["tool_name"] for r in turns[0]["rows"]] == ["c"]
    assert sorted(r["tool_name"] for r in turns[1]["rows"]) == ["a", "b"]
    assert turns[0]["ts"] >= turns[1]["ts"]


def test_turns_payload_offset_paginates_by_turn(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)
    owner = _owner_hash(plugin)
    for i in range(3):
        plugin._on_pre_gateway_dispatch(gateway_event(f"turn {i}", user_id="owner"))
        plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name=f"t{i}", reason="r")

    page = plugin._activity_turns_payload({"start": "1", "length": "25"})
    assert page["recordsTotal"] == 3
    assert len(page["turns"]) == 2  # newest turn skipped by the offset
    tools = [r["tool_name"] for t in page["turns"] for r in t["rows"]]
    assert "t2" not in tools


def test_turns_payload_legacy_rows_are_singletons():
    plugin = load_plugin()
    plugin._ensure_activity_db()
    cols = (
        "ts, decision, mode, session_label, session_hash, owner_hash, tool_name, "
        "action_family, destination, data_classes, reason, approval_id, rule_id, rule_source"
    )
    with plugin._activity_connect() as conn:
        for ts, tool in ((1000, "legacy1"), (1001, "legacy2")):
            conn.execute(
                f"INSERT INTO activity ({cols}) VALUES (?, 'blocked','strict','s','h','o',?,'x','d','','r','','','')",
                (ts, tool),
            )
    payload = plugin._activity_turns_payload({"start": "0", "length": "25"})
    singletons = [t for t in payload["turns"] if t["turn_id"] == ""]
    assert len(singletons) == 2
    assert all(len(t["rows"]) == 1 for t in singletons)


# --- Slash /guardian activity grouped by turn --------------------------------
def test_slash_activity_groups_by_turn_with_nested_checks(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)
    owner = _owner_hash(plugin)
    plugin._set_persist_prompts(True)

    plugin._on_pre_gateway_dispatch(gateway_event("subscribe me to the newsletter", user_id="owner"))
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="browser_type",
                          action_family="browser_type", reason="requires approval")
    plugin._emit_activity("allowed", session_id="s1", owner_hash=owner, tool_name="web_read",
                          action_family="web_read", reason="public read")

    out = plugin._handle_guardian_command("activity 5")
    assert "**Turn**" in out
    assert "2 checks" in out
    assert "subscribe me to the newsletter" in out  # prompt shown when persisted
    assert "browser_type" in out and "web_read" in out  # both checks nested under the turn


def test_slash_activity_robot_prefix_marks_llm_involved_checks(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    bind_owner(plugin)
    owner = _owner_hash(plugin)
    plugin._on_pre_gateway_dispatch(gateway_event("go", user_id="owner"))
    plugin._emit_activity("auto_approved", session_id="s1", owner_hash=owner, tool_name="browser_type", reason="llm low: fine")
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="send_message", reason="requires approval (llm high: mismatch)")
    plugin._emit_activity("blocked", session_id="s1", owner_hash=owner, tool_name="terminal", reason="requires approval")

    out = plugin._handle_guardian_command("activity 3")
    # Decisions render as emojis; the LLM-involved ones carry a 🤖 suffix, the
    # deterministic block does not.
    assert "✅🤖 `browser_type`" in out
    assert "❌🤖 `send_message`" in out
    assert "❌ `terminal`" in out and "❌🤖 `terminal`" not in out


def _load_plugin_api():
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "hermes_guardian_dashboard_plugin_api_tgp", root / "dashboard" / "plugin_api.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module
