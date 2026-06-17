"""SQLite activity persistence and retention management."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from .. import core
from .. import state
from ..privacy import approvals
from ..privacy import rules
from ..privacy import tool_policy


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        result = super().__exit__(exc_type, exc_value, traceback)
        self.close()
        return result


def _activity_connect() -> sqlite3.Connection:
    state._ACTIVITY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(state._ACTIVITY_DB_PATH), timeout=2.0, factory=_ClosingConnection)
    conn.row_factory = sqlite3.Row
    # WAL lets dashboard reads (e.g. the history page) proceed against a
    # consistent snapshot while activity writes are in flight, instead of
    # blocking on the writer's lock up to the busy timeout. synchronous=NORMAL
    # is the safe/standard pairing for WAL. Both are best-effort; an old SQLite
    # or a read-only volume simply keeps the previous (rollback-journal) mode.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error:
        pass
    return conn


def _activity_max_rows() -> int:
    # Document `retention.max_rows` is the source of truth; the env var still overrides
    # for ops (doc 03 §1.2). _retention_setting handles the precedence + surfacing.
    value, _overridden = rules._retention_setting(
        "max_rows", core._ACTIVITY_MAX_ROWS_ENV, core._DEFAULT_ACTIVITY_MAX_ROWS
    )
    return value


def _activity_retention_days() -> int:
    value, _overridden = rules._retention_setting(
        "max_age_days", core._ACTIVITY_RETENTION_DAYS_ENV, core._DEFAULT_ACTIVITY_RETENTION_DAYS
    )
    return value


def _activity_group_seconds() -> int:
    raw = state._env(core._ACTIVITY_GROUP_SECONDS_ENV, str(core._DEFAULT_ACTIVITY_GROUP_SECONDS)).strip()
    try:
        value = int(raw)
    except ValueError:
        return core._DEFAULT_ACTIVITY_GROUP_SECONDS
    return max(0, min(value, 3600))


def _ensure_activity_db() -> None:
    if state._ACTIVITY_DB_INITIALIZED:
        return
    with state._LOCK:
        if state._ACTIVITY_DB_INITIALIZED:
            return
        try:
            with _activity_connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS activity (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        decision TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        session_label TEXT NOT NULL,
                        session_hash TEXT NOT NULL,
                        owner_hash TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        action_family TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        data_classes TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        approval_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        rule_source TEXT NOT NULL,
                        action_detail TEXT NOT NULL DEFAULT '',
                        module TEXT NOT NULL DEFAULT '',
                        rule_effect TEXT NOT NULL DEFAULT '',
                        rule_scope TEXT NOT NULL DEFAULT '',
                        purpose TEXT NOT NULL DEFAULT '',
                        recipient_identity TEXT NOT NULL DEFAULT '',
                        destination_trust TEXT NOT NULL DEFAULT 'unknown',
                        decision_step TEXT NOT NULL DEFAULT '',
                        turn_id TEXT NOT NULL DEFAULT '',
                        user_prompt TEXT NOT NULL DEFAULT '',
                        latency_us INTEGER NOT NULL DEFAULT 0,
                        latency_hook TEXT NOT NULL DEFAULT '',
                        latency_llm_invoked INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                columns = {
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(activity)").fetchall()
                }
                if "action_detail" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN action_detail TEXT NOT NULL DEFAULT ''")
                if "module" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN module TEXT NOT NULL DEFAULT ''")
                if "rule_effect" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN rule_effect TEXT NOT NULL DEFAULT ''")
                if "rule_scope" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN rule_scope TEXT NOT NULL DEFAULT ''")
                if "purpose" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN purpose TEXT NOT NULL DEFAULT ''")
                if "recipient_identity" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN recipient_identity TEXT NOT NULL DEFAULT ''")
                # Doc 03 §3.2: additive, nullable-with-default metadata columns. Existing
                # rows backfill to destination_trust='unknown' / decision_step='' (display
                # -safe; no historical migration, retention unchanged).
                if "destination_trust" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN destination_trust TEXT NOT NULL DEFAULT 'unknown'")
                if "decision_step" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN decision_step TEXT NOT NULL DEFAULT ''")
                # Turn grouping + opt-in prompt persistence: turn_id groups a user prompt's
                # actions; user_prompt holds the already-sanitized prompt only when the
                # protection.runtime.persist_prompts flag is on. Additive, display-safe
                # backfill ('') with the same retention as every other row.
                if "turn_id" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN turn_id TEXT NOT NULL DEFAULT ''")
                if "user_prompt" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN user_prompt TEXT NOT NULL DEFAULT ''")
                if "latency_us" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN latency_us INTEGER NOT NULL DEFAULT 0")
                if "latency_hook" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN latency_hook TEXT NOT NULL DEFAULT ''")
                if "latency_llm_invoked" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN latency_llm_invoked INTEGER NOT NULL DEFAULT 0")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_ts_idx ON activity(ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_decision_idx ON activity(decision)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_action_idx ON activity(action_family)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_destination_idx ON activity(destination)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_approval_idx ON activity(approval_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_turn_idx ON activity(turn_id)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pending_approvals (
                        id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        owner_hash TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        action_family TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        data_classes TEXT NOT NULL,
                        action_detail TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        cron_job_id TEXT NOT NULL DEFAULT '',
                        cron_job_name TEXT NOT NULL DEFAULT '',
                        reason TEXT NOT NULL DEFAULT '',
                        purpose TEXT NOT NULL DEFAULT 'unknown',
                        recipient_identity TEXT NOT NULL DEFAULT 'none',
                        legacy_destination TEXT NOT NULL DEFAULT '',
                        destination_trust TEXT NOT NULL DEFAULT 'unknown',
                        decision_step TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                pending_columns = {
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(pending_approvals)").fetchall()
                }
                if "cron_job_id" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN cron_job_id TEXT NOT NULL DEFAULT ''")
                if "cron_job_name" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN cron_job_name TEXT NOT NULL DEFAULT ''")
                if "reason" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN reason TEXT NOT NULL DEFAULT ''")
                if "purpose" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN purpose TEXT NOT NULL DEFAULT 'unknown'")
                if "recipient_identity" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN recipient_identity TEXT NOT NULL DEFAULT 'none'")
                if "legacy_destination" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN legacy_destination TEXT NOT NULL DEFAULT ''")
                # destination_trust/decision_step (doc 03 §3.2) so a pending block keeps its
                # trust pill + decision step across a gateway restart, not just in memory.
                if "destination_trust" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN destination_trust TEXT NOT NULL DEFAULT 'unknown'")
                if "decision_step" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN decision_step TEXT NOT NULL DEFAULT ''")
                # Raw permit candidates (doc 06 §4.1): the concrete recipient/host/command a
                # structural permit would add to self.* / trusted_recipients. Kept verbatim
                # ONLY in this short-lived row (deleted on approve/dismiss/expiry).
                if "permit_recipient" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN permit_recipient TEXT NOT NULL DEFAULT ''")
                if "permit_host" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN permit_host TEXT NOT NULL DEFAULT ''")
                if "permit_command" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN permit_command TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_session_idx ON pending_approvals(session_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_expires_idx ON pending_approvals(expires_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_cron_job_idx ON pending_approvals(cron_job_id)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS check_timings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        hook TEXT NOT NULL,
                        tool_name TEXT NOT NULL DEFAULT '',
                        duration_us INTEGER NOT NULL,
                        llm_invoked INTEGER NOT NULL DEFAULT 0,
                        blocked INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS check_timings_ts_idx ON check_timings(ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS check_timings_hook_idx ON check_timings(hook)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tool_inventory (
                        tool_name TEXT PRIMARY KEY,
                        first_seen INTEGER NOT NULL,
                        last_seen INTEGER NOT NULL,
                        call_count INTEGER NOT NULL DEFAULT 0,
                        result_count INTEGER NOT NULL DEFAULT 0,
                        observed_read_families TEXT NOT NULL DEFAULT '[]',
                        observed_egress_families TEXT NOT NULL DEFAULT '[]',
                        observed_destinations TEXT NOT NULL DEFAULT '[]',
                        mcp_server_prefix TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                inventory_columns = {
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(tool_inventory)").fetchall()
                }
                if "first_seen" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0")
                if "last_seen" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0")
                if "call_count" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN call_count INTEGER NOT NULL DEFAULT 0")
                if "result_count" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN result_count INTEGER NOT NULL DEFAULT 0")
                if "observed_read_families" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN observed_read_families TEXT NOT NULL DEFAULT '[]'")
                if "observed_egress_families" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN observed_egress_families TEXT NOT NULL DEFAULT '[]'")
                if "observed_destinations" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN observed_destinations TEXT NOT NULL DEFAULT '[]'")
                if "mcp_server_prefix" not in inventory_columns:
                    conn.execute("ALTER TABLE tool_inventory ADD COLUMN mcp_server_prefix TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS tool_inventory_last_seen_idx ON tool_inventory(last_seen)")
                # Classification-picker candidates, by kind (doc: source provenance §3):
                #   kind="command" → safe terminal command prefixes that gated (Trusted-
                #     destinations picker; program + script/subcommand only, never flag values).
                #   kind="source"  → MCP server prefixes whose doc-reads hit the conservative
                #     source-default (Reading "Sources seen" picker; server prefix only,
                #     never content).
                # Shared across the gateway/dashboard processes via this DB.
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS suggestions (
                        kind TEXT NOT NULL,
                        prefix TEXT NOT NULL,
                        last_ts INTEGER NOT NULL,
                        hits INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (kind, prefix)
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS suggestions_ts_idx ON suggestions(last_ts)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS attention_dismissals (
                        dismiss_key TEXT PRIMARY KEY,
                        kind TEXT NOT NULL,
                        item_id TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS attention_dismissals_expires_idx ON attention_dismissals(expires_at)")
                conn.execute("DROP TABLE IF EXISTS command_suggestions")
            state._ACTIVITY_DB_INITIALIZED = True
        except Exception as exc:
            core.logger.debug("%s: failed to initialize activity db: %s", core._PLUGIN_NAME, exc)


# Allowed destination-trust labels persisted on a row (doc 03 §3.2). A garbage / empty
# label fails closed to "unknown" so the column is always a clean enum, never payload.
_DESTINATION_TRUST_LABELS = {
    "self",
    "trusted_recipient",
    "trusted",
    "local_system",
    "model_provider",
    "external",
    "public",
    "unknown",
}

_PSEUDO_TOOL_NAMES = {"", "*", "llm_output", "gateway_message"}
_FLOW_BOUNDARIES = frozenset({"read", "inside_boundary", "outward", "outward_trusted", "unknown"})
_FLOW_BOUNDARY_LABELS = {
    "read": "Read (no egress)",
    "inside_boundary": "Stays with you",
    "outward": "Outward",
    "outward_trusted": "Outward to trusted",
    "unknown": "Boundary unknown",
}
_FLOW_READ_ACTION_FAMILIES = frozenset({"browser_read", "mcp_read_query", "message_list", "web_read"})
_FLOW_INSIDE_TRUSTS = frozenset({"self", "local_system", "model_provider"})
_FLOW_TRUSTED_TRUSTS = frozenset({"trusted", "trusted_recipient"})
_FLOW_OUTWARD_TRUSTS = frozenset({"external", "public"})
_FLOW_READ_HOOKS = frozenset({"transform_tool_result", "pre_gateway_dispatch"})
_FLOW_WRITE_HOOKS = frozenset({"pre_tool_call", "transform_llm_output"})
_WHY_TEXT_RE = re.compile(r"[^A-Za-z0-9_.,:;()/?@%+= \-]+")
_ATTENTION_DISMISS_KINDS = frozenset({"risk", "info", "source", "egress-tool", "read-tool"})
_ATTENTION_DISMISS_TTL_SECONDS = {
    "risk": 7 * 24 * 60 * 60,
    "info": 30 * 24 * 60 * 60,
    "source": 30 * 24 * 60 * 60,
    "egress-tool": 30 * 24 * 60 * 60,
    "read-tool": 30 * 24 * 60 * 60,
}
_ATTENTION_DISMISS_KEY_RE = re.compile(r"[^A-Za-z0-9_.,:@|=-]+")


def _safe_metadata_text(value: Any, *, limit: int = 120, fallback: str = "") -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip() or fallback
    text = _WHY_TEXT_RE.sub("", text)
    text = " ".join(text.split())
    return text[: max(0, int(limit))]


def _safe_attention_dismiss_key(value: Any) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    text = _ATTENTION_DISMISS_KEY_RE.sub("_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text[:180]


def _safe_attention_kind(value: Any) -> str:
    kind = str(value or "").strip().lower()
    return kind if kind in _ATTENTION_DISMISS_KINDS else ""


def _flow_boundary_label(boundary: Any) -> str:
    value = str(boundary or "").strip().lower()
    return _FLOW_BOUNDARY_LABELS.get(value, _FLOW_BOUNDARY_LABELS["unknown"])


def _flow_boundary_from_metadata(item: dict[str, Any]) -> str:
    decision = str(item.get("decision") or "").strip().lower()
    action_family = str(item.get("action_family") or "").strip().lower()
    hook = str(item.get("latency_hook") or "").strip().lower()
    tool_name = str(item.get("tool_name") or "").strip().lower()
    if decision in {"read", "tainted"}:
        return "read"
    if action_family in _FLOW_READ_ACTION_FAMILIES:
        return "read"
    if hook in _FLOW_READ_HOOKS:
        return "read"
    if decision == "security_suppressed" and tool_name and tool_name != "llm_output":
        return "read"
    if decision == "security_blocked" and tool_name == "gateway_message":
        return "read"

    trust = _normalize_destination_trust_label(item.get("destination_trust"))
    if trust in _FLOW_INSIDE_TRUSTS:
        return "inside_boundary"
    if trust in _FLOW_TRUSTED_TRUSTS:
        return "outward_trusted"
    if trust in _FLOW_OUTWARD_TRUSTS:
        return "outward"
    if hook in _FLOW_WRITE_HOOKS or action_family:
        return "unknown"
    return "unknown"


def _flow_boundary_detail(item: dict[str, Any], boundary: str) -> str:
    action_family = _safe_metadata_text(item.get("action_family"), limit=64)
    trust = _normalize_destination_trust_label(item.get("destination_trust"))
    if boundary == "read":
        if action_family:
            return f"{action_family} is classified as read/no-egress metadata."
        return "This check observed data without an outward egress."
    if boundary == "inside_boundary":
        if trust == "self":
            return "The destination resolved to something configured as yours."
        if trust == "local_system":
            return "The destination resolved to the local system boundary."
        if trust == "model_provider":
            return "The destination stays inside the configured model-provider boundary."
        return "The destination resolved inside your boundary."
    if boundary == "outward_trusted":
        return "The destination resolved to a trusted recipient or trusted command."
    if boundary == "outward":
        if trust == "public":
            return "The action targets a public/outward destination."
        return "The action would move data outside your boundary."
    return "Guardian could not prove where this egress stays."


def _flow_boundary_fields(item: dict[str, Any]) -> dict[str, str]:
    boundary = _flow_boundary_from_metadata(item if isinstance(item, dict) else {})
    return {
        "flow_boundary": boundary if boundary in _FLOW_BOUNDARIES else "unknown",
        "flow_boundary_label": _flow_boundary_label(boundary),
        "flow_boundary_detail": _safe_metadata_text(
            _flow_boundary_detail(item if isinstance(item, dict) else {}, boundary),
            limit=180,
        ),
    }


def _metadata_data_classes(value: Any) -> list[str]:
    raw = value if isinstance(value, (list, tuple, set)) else str(value or "").split(",")
    return sorted(
        cls
        for cls in (str(item).strip() for item in raw)
        if cls in core._ALL_PRIVACY_CLASSES
    )


def _why_now(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item if isinstance(item, dict) else {}
    flow = _flow_boundary_fields(metadata)
    classes = _metadata_data_classes(metadata.get("data_classes"))
    reason = _safe_metadata_text(metadata.get("reason"), limit=140)
    mode = _safe_metadata_text(metadata.get("mode") or metadata.get("egress_safety"), limit=40)
    step = _normalize_decision_step_label(metadata.get("decision_step"))
    action_family = _safe_metadata_text(metadata.get("action_family"), limit=64)
    trust = _normalize_destination_trust_label(metadata.get("destination_trust"))

    if flow["flow_boundary"] == "read":
        summary = "Guardian classified this as a read, so no outward approval was needed."
    elif flow["flow_boundary"] == "inside_boundary":
        summary = "Guardian found the action stayed inside your boundary."
    elif flow["flow_boundary"] == "outward_trusted":
        summary = "Guardian recognized an outward flow to a trusted destination."
    elif flow["flow_boundary"] == "outward":
        summary = "Guardian needs approval before private data leaves your boundary."
    else:
        summary = "Guardian needs approval because the destination boundary is unclear."

    bullets = [f"Boundary: {flow['flow_boundary_label']}"]
    if classes:
        bullets.append("Data classes in scope: " + ", ".join(classes))
    if action_family:
        bullets.append(f"Action family: {action_family}")
    if trust != "unknown":
        bullets.append(f"Destination trust: {trust}")
    if step:
        bullets.append(f"Decision step: {step}")
    if mode:
        bullets.append(f"Mode: {mode}")
    if reason:
        bullets.append(f"Reason: {reason}")
    return {
        "summary": _safe_metadata_text(summary, limit=160),
        "bullets": [_safe_metadata_text(bullet, limit=180) for bullet in bullets[:6] if _safe_metadata_text(bullet, limit=180)],
    }


def _safe_tool_inventory_name(value: Any) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value or "").strip().lower())
    text = text.strip("_")[:120]
    return "" if text in _PSEUDO_TOOL_NAMES else text


def _safe_inventory_token(value: Any, *, limit: int = 80) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:@-]+", "_", str(value or "").strip().lower())
    return text.strip("_")[:limit]


def _inventory_json_array(value: Any) -> list[str]:
    try:
        parsed = json.loads(str(value or "[]"))
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    return [
        token
        for token in (_safe_inventory_token(item) for item in parsed)
        if token
    ][:20]


def _inventory_array_with(values: Any, additions: list[str]) -> str:
    current = _inventory_json_array(values)
    for item in additions:
        token = _safe_inventory_token(item)
        if token and token not in current:
            current.append(token)
    return json.dumps(current[:20], separators=(",", ":"))


def _tool_inventory_mcp_prefix(tool_name: str) -> str:
    lower = _safe_tool_inventory_name(tool_name)
    if not lower:
        return ""
    try:
        server = tool_policy._mcp_server_prefix(lower)
    except Exception:
        server = ""
    if server:
        return server[:80]
    if lower.startswith("mcp_"):
        parts = lower.split("_")
        if len(parts) >= 2 and parts[1]:
            return f"mcp_{parts[1]}"[:80]
    return ""


def _record_tool_inventory(
    tool_name: str,
    *,
    call: bool = False,
    result: bool = False,
    read_family: str = "",
    egress_family: str = "",
    destination: str = "",
) -> None:
    safe_name = _safe_tool_inventory_name(tool_name)
    if not safe_name:
        return
    read_values = [_safe_inventory_token(read_family)]
    egress_values = [_safe_inventory_token(egress_family)]
    destination_values = [_safe_inventory_token(destination, limit=120)]
    now = int(state._now())
    mcp_prefix = _tool_inventory_mcp_prefix(safe_name)
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            row = conn.execute(
                "SELECT * FROM tool_inventory WHERE tool_name=?",
                (safe_name,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO tool_inventory (
                        tool_name, first_seen, last_seen, call_count, result_count,
                        observed_read_families, observed_egress_families,
                        observed_destinations, mcp_server_prefix
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        safe_name,
                        now,
                        now,
                        1 if call else 0,
                        1 if result else 0,
                        _inventory_array_with("[]", read_values),
                        _inventory_array_with("[]", egress_values),
                        _inventory_array_with("[]", destination_values),
                        mcp_prefix,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE tool_inventory
                    SET last_seen=?,
                        call_count=call_count+?,
                        result_count=result_count+?,
                        observed_read_families=?,
                        observed_egress_families=?,
                        observed_destinations=?,
                        mcp_server_prefix=CASE
                            WHEN mcp_server_prefix='' THEN ?
                            ELSE mcp_server_prefix
                        END
                    WHERE tool_name=?
                    """,
                    (
                        now,
                        1 if call else 0,
                        1 if result else 0,
                        _inventory_array_with(row["observed_read_families"], read_values),
                        _inventory_array_with(row["observed_egress_families"], egress_values),
                        _inventory_array_with(row["observed_destinations"], destination_values),
                        mcp_prefix,
                        safe_name,
                    ),
                )
    except Exception as exc:
        core.logger.debug("%s: failed to record tool inventory: %s", core._PLUGIN_NAME, exc)


def _tool_inventory_rows(limit: int = 1000) -> list[dict[str, Any]]:
    _ensure_activity_db()
    try:
        with _activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT tool_name, first_seen, last_seen, call_count, result_count,
                       observed_read_families, observed_egress_families,
                       observed_destinations, mcp_server_prefix
                FROM tool_inventory
                ORDER BY last_seen DESC, tool_name ASC
                LIMIT ?
                """,
                (max(1, min(int(limit or 1000), 5000)),),
            ).fetchall()
    except Exception as exc:
        core.logger.debug("%s: failed to read tool inventory: %s", core._PLUGIN_NAME, exc)
        return []
    return [
        {
            "tool_name": str(row["tool_name"] or ""),
            "first_seen": int(row["first_seen"] or 0),
            "last_seen": int(row["last_seen"] or 0),
            "call_count": int(row["call_count"] or 0),
            "result_count": int(row["result_count"] or 0),
            "observed_read_families": _inventory_json_array(row["observed_read_families"]),
            "observed_egress_families": _inventory_json_array(row["observed_egress_families"]),
            "observed_destinations": _inventory_json_array(row["observed_destinations"]),
            "mcp_server_prefix": str(row["mcp_server_prefix"] or "")[:80],
        }
        for row in rows
    ]


def _normalize_destination_trust_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text == "trusted_recipient":
        text = "trusted"
    return text if text in _DESTINATION_TRUST_LABELS else "unknown"


def _normalize_decision_step_label(value: Any) -> str:
    # A short, charset-bounded step label (e.g. "step3_intra_boundary"); never payload.
    text = re.sub(r"[^a-z0-9_:.\- ]+", "", str(value or "").strip().lower())
    return text[:60]


def _record_suggestion(kind: str, prefix: str) -> None:
    """Remember a classification-picker candidate of ``kind`` (command | source). The
    prefix is a structural token (a command prefix or an MCP server prefix), never content."""
    text = str(prefix or "").strip()
    kind_text = str(kind or "").strip()
    if not text or not kind_text:
        return
    _ensure_activity_db()
    try:
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO suggestions (kind, prefix, last_ts, hits) VALUES (?, ?, ?, 1)
                ON CONFLICT(kind, prefix) DO UPDATE SET last_ts=excluded.last_ts, hits=hits+1
                """,
                (kind_text[:32], text[:400], int(state._now())),
            )
    except Exception as exc:
        core.logger.debug("%s: failed to record %s suggestion: %s", core._PLUGIN_NAME, kind_text, exc)


def _recent_suggestions(kind: str, limit: int = 20) -> list[dict[str, Any]]:
    """Recently recorded picker candidates of ``kind``, newest first."""
    _ensure_activity_db()
    try:
        with _activity_connect() as conn:
            rows = conn.execute(
                "SELECT prefix, last_ts, hits FROM suggestions WHERE kind=? ORDER BY last_ts DESC LIMIT ?",
                (str(kind or "").strip(), max(1, min(int(limit or 20), 100))),
            ).fetchall()
        return [
            {"prefix": str(row["prefix"]), "last_ts": int(row["last_ts"]), "hits": int(row["hits"])}
            for row in rows
        ]
    except Exception as exc:
        core.logger.debug("%s: failed to read %s suggestions: %s", core._PLUGIN_NAME, kind, exc)
        return []


def _prune_attention_dismissals() -> int:
    _ensure_activity_db()
    try:
        with _activity_connect() as conn:
            return int(conn.execute(
                "DELETE FROM attention_dismissals WHERE expires_at <= ?",
                (int(state._now()),),
            ).rowcount)
    except Exception as exc:
        core.logger.debug("%s: failed to prune attention dismissals: %s", core._PLUGIN_NAME, exc)
        return 0


def _attention_dismissals(limit: int = 200) -> list[dict[str, Any]]:
    """Active dashboard Attention snoozes, stored as sanitized metadata only."""
    _prune_attention_dismissals()
    try:
        with _activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT dismiss_key, kind, item_id, created_at, expires_at
                FROM attention_dismissals
                WHERE expires_at > ?
                ORDER BY created_at DESC, dismiss_key ASC
                LIMIT ?
                """,
                (int(state._now()), max(1, min(int(limit or 200), 1000))),
            ).fetchall()
    except Exception as exc:
        core.logger.debug("%s: failed to read attention dismissals: %s", core._PLUGIN_NAME, exc)
        return []
    return [
        {
            "dismiss_key": str(row["dismiss_key"] or ""),
            "kind": _safe_attention_kind(row["kind"]),
            "item_id": _safe_attention_dismiss_key(row["item_id"]),
            "created_at": int(row["created_at"] or 0),
            "expires_at": int(row["expires_at"] or 0),
        }
        for row in rows
        if str(row["dismiss_key"] or "") and _safe_attention_kind(row["kind"])
    ]


def _dismiss_attention_item(kind: Any, dismiss_key: Any, item_id: Any = "") -> tuple[bool, str]:
    safe_kind = _safe_attention_kind(kind)
    if not safe_kind:
        return False, "Unsupported Attention item kind."
    safe_key = _safe_attention_dismiss_key(dismiss_key)
    if not safe_key:
        return False, "Attention dismissal key is required."
    safe_item_id = _safe_attention_dismiss_key(item_id) or safe_key
    now = int(state._now())
    expires_at = now + _ATTENTION_DISMISS_TTL_SECONDS[safe_kind]
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO attention_dismissals (dismiss_key, kind, item_id, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(dismiss_key) DO UPDATE SET
                    kind=excluded.kind,
                    item_id=excluded.item_id,
                    created_at=excluded.created_at,
                    expires_at=excluded.expires_at
                """,
                (safe_key, safe_kind, safe_item_id, now, expires_at),
            )
    except Exception as exc:
        core.logger.debug("%s: failed to dismiss attention item: %s", core._PLUGIN_NAME, exc)
        return False, "Failed to dismiss Attention item."
    days = max(1, int(round(_ATTENTION_DISMISS_TTL_SECONDS[safe_kind] / 86400)))
    return True, f"Snoozed Attention item for {days} day{'s' if days != 1 else ''}."


def _restore_attention_dismissal(dismiss_key: Any = "") -> tuple[bool, str]:
    safe_key = _safe_attention_dismiss_key(dismiss_key)
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            if safe_key:
                deleted = int(conn.execute(
                    "DELETE FROM attention_dismissals WHERE dismiss_key = ?",
                    (safe_key,),
                ).rowcount)
            else:
                deleted = int(conn.execute("DELETE FROM attention_dismissals").rowcount)
    except Exception as exc:
        core.logger.debug("%s: failed to restore attention dismissal: %s", core._PLUGIN_NAME, exc)
        return False, "Failed to restore Attention item."
    if safe_key and not deleted:
        return False, "No matching Attention snooze found."
    if safe_key:
        return True, "Restored Attention item."
    return True, "Restored snoozed Attention items."


def _emit_activity(
    decision: str,
    *,
    session_id: str | None = "",
    owner_hash: str = "",
    tool_name: str = "",
    action_family: str = "",
    destination: str = "",
    data_classes: list[str] | set[str] | tuple[str, ...] | None = None,
    reason: str = "",
    approval_id: str = "",
    rule_id: str = "",
    rule_source: str = "",
    action_detail: str = "",
    module: str = "",
    rule_effect: str = "",
    rule_scope: str = "",
    purpose: str = "",
    recipient_identity: str = "",
    destination_trust: str = "",
    decision_step: str = "",
) -> None:
    """Persist sanitized activity metadata for dashboard/debugging.

    ``destination_trust`` (an enum label: self/trusted/external/public/unknown) and
    ``decision_step`` (a decide() step label) are METADATA ONLY — no payload content
    (doc 03 §5 / invariant #5). They default to display-safe values for callers/old rows.
    """
    if decision not in core._ACTIVITY_DECISIONS:
        decision = "allowed"
    if not module:
        if decision in {"security_blocked", "security_suppressed"}:
            module = "security"
        elif decision in {"allowed", "auto_approved", "blocked", "denied", "manual_approved", "privacy_off_allowed", "tainted"}:
            module = "privacy"
    safe_classes = sorted(str(cls) for cls in (data_classes or []) if str(cls) in core._ALL_PRIVACY_CLASSES)
    sid = tool_policy._normalize_session_id(session_id)
    # Turn grouping is always on (cheap random label). The prompt is persisted ONLY when
    # the operator opts in; both sources (owner request / cron instruction) are already
    # sanitized by _redact_command_for_llm, and we re-clamp defensively. Unauthenticated
    # senders / non-cron sessions yield "" from both, so nothing is persisted for them.
    turn_id = tool_policy._current_turn_id(sid)
    user_prompt = ""
    if rules._persist_prompts_enabled():
        user_prompt = (approvals._latest_owner_request_for_owner(owner_hash) or approvals._cron_instruction_for_session(sid))[:500]
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO activity (
                    ts, decision, mode, session_label, session_hash, owner_hash,
                    tool_name, action_family, destination, data_classes, reason,
                    approval_id, rule_id, rule_source, action_detail,
                    module, rule_effect, rule_scope, purpose, recipient_identity,
                    destination_trust, decision_step, turn_id, user_prompt
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(state._now()),
                    decision,
                    core._egress_safety_policy(),
                    core._safe_session_label(sid),
                    core._short_hash(sid),
                    core._short_hash(owner_hash),
                    str(tool_name or "")[:120],
                    str(action_family or "")[:80],
                    str(destination or "")[:160],
                    ",".join(safe_classes),
                    str(reason or "")[:1000],
                    str(approval_id or "")[:80],
                    str(rule_id or "")[:80],
                    str(rule_source or "")[:80],
                    str(action_detail or "")[:500],
                    str(module or "")[:40],
                    str(rule_effect or "")[:40],
                    str(rule_scope or "")[:160],
                    tool_policy._normalize_rule_purpose(purpose or "unknown", allow_star=False),
                    tool_policy._normalize_rule_recipient_identity(recipient_identity or "none", allow_star=False),
                    _normalize_destination_trust_label(destination_trust),
                    _normalize_decision_step_label(decision_step),
                    str(turn_id or "")[:60],
                    str(user_prompt or "")[:500],
                ),
            )
            activity_ids = getattr(state._CHECK_TIMING_STATE, "activity_ids", None)
            if isinstance(activity_ids, list):
                activity_ids.append(int(cursor.lastrowid))
        _prune_activity_db()
    except Exception as exc:
        core.logger.debug("%s: failed to write activity event: %s", core._PLUGIN_NAME, exc)


def _perf_begin_check() -> None:
    """Reset per-thread timing scratch state at the start of a hook check."""
    state._CHECK_TIMING_STATE.llm_invoked = False
    state._CHECK_TIMING_STATE.activity_ids = []


def _perf_mark_llm_invoked() -> None:
    """Flag that the current hook check invoked the LLM verifier (its main cost)."""
    state._CHECK_TIMING_STATE.llm_invoked = True


def _perf_llm_invoked() -> bool:
    return bool(getattr(state._CHECK_TIMING_STATE, "llm_invoked", False))


def _record_check_timing(
    hook: str,
    *,
    duration_us: int,
    tool_name: str = "",
    llm_invoked: bool = False,
    blocked: bool = False,
) -> None:
    """Persist sanitized per-check timing for the Performance dashboard."""
    try:
        safe_duration_us = max(0, int(duration_us))
        safe_hook = str(hook or "")[:60]
        safe_llm_invoked = 1 if llm_invoked else 0
        activity_ids = [
            int(value)
            for value in getattr(state._CHECK_TIMING_STATE, "activity_ids", [])
            if isinstance(value, int) or str(value).isdigit()
        ]
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO check_timings (ts, hook, tool_name, duration_us, llm_invoked, blocked)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(state._now()),
                    safe_hook,
                    str(tool_name or "")[:120],
                    safe_duration_us,
                    safe_llm_invoked,
                    1 if blocked else 0,
                ),
            )
            if activity_ids:
                conn.executemany(
                    """
                    UPDATE activity
                    SET latency_us = ?, latency_hook = ?, latency_llm_invoked = ?
                    WHERE id = ?
                    """,
                    [(safe_duration_us, safe_hook, safe_llm_invoked, activity_id) for activity_id in activity_ids],
                )
    except Exception as exc:
        core.logger.debug("%s: failed to write check timing: %s", core._PLUGIN_NAME, exc)


def _prune_activity_db(*, force: bool = False) -> dict[str, int]:
    """Bound activity DB size by age and row count.

    A value of 0 disables the corresponding limit.
    """
    now = state._now()
    if not force and now - state._LAST_ACTIVITY_PRUNE < core._ACTIVITY_PRUNE_INTERVAL_SECONDS:
        return {"deleted": 0, "remaining": -1}
    state._LAST_ACTIVITY_PRUNE = now

    max_rows = _activity_max_rows()
    retention_days = _activity_retention_days()
    deleted = 0
    remaining = 0
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            if retention_days > 0:
                cutoff = int(now - retention_days * 86400)
                deleted += conn.execute("DELETE FROM activity WHERE ts < ?", (cutoff,)).rowcount
                conn.execute("DELETE FROM check_timings WHERE ts < ?", (cutoff,))
            if max_rows > 0:
                deleted += conn.execute(
                    """
                    DELETE FROM activity
                    WHERE id NOT IN (
                        SELECT id FROM activity ORDER BY ts DESC, id DESC LIMIT ?
                    )
                    """,
                    (max_rows,),
                ).rowcount
                conn.execute(
                    """
                    DELETE FROM check_timings
                    WHERE id NOT IN (
                        SELECT id FROM check_timings ORDER BY ts DESC, id DESC LIMIT ?
                    )
                    """,
                    (max_rows,),
                )
            remaining = int(conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0])
        if deleted:
            # The table is bounded by row count / retention, so its file size
            # self-limits at steady state -- a full VACUUM after every prune is
            # unnecessary churn and (before WAL) was the main source of the
            # multi-second exclusive lock that stalled dashboard reads. Just
            # truncate the WAL so it doesn't grow unbounded; this does not block
            # concurrent readers the way VACUUM does.
            with _activity_connect() as conn:
                conn.isolation_level = None
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
    except Exception as exc:
        core.logger.debug("%s: failed to prune activity db: %s", core._PLUGIN_NAME, exc)
    return {"deleted": int(deleted or 0), "remaining": remaining}
