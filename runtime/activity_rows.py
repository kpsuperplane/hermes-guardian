"""Activity query, filtering, grouping, and DataTables row shaping."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from . import activity_store
from .. import core
from .. import state
from ..privacy import approvals
from ..privacy import destinations as destinations_mod
from ..privacy import llm
from ..privacy import rules as rules_mod
from ..privacy import tool_policy
from ..ui import dashboard


def _activity_rows(filters: dict[str, str], *, limit: int = 200) -> list[dict[str, Any]]:
    activity_store._ensure_activity_db()
    clauses, params = _activity_filter_clauses(filters)
    sql = "SELECT * FROM activity"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))
    try:
        with activity_store._activity_connect() as conn:
            rows = conn.execute(sql, params).fetchall()
    except Exception:
        return []
    return [_activity_row_from_sql(row) for row in rows]


def _dashboard_suggestion_value(value: Any, *, limit: int = 160) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    if not cleaned or cleaned == "*":
        return ""
    if re.search(r"(?:access_?token|auth_?token|api_?key|secret|password)=", cleaned, re.I):
        return ""
    return cleaned[:limit]


def _activity_distinct_values(column: str, *, limit: int = 40) -> list[str]:
    if column not in {"destination", "tool_name", "purpose", "recipient_identity", "destination_trust"}:
        return []
    activity_store._ensure_activity_db()
    sql = (
        f"SELECT {column} AS value, MAX(ts) AS latest FROM activity "
        f"WHERE {column} NOT IN ('', '*') "
        f"GROUP BY {column} ORDER BY latest DESC LIMIT ?"
    )
    try:
        with activity_store._activity_connect() as conn:
            values = [row["value"] for row in conn.execute(sql, (max(1, min(int(limit), 100)),)).fetchall()]
    except Exception:
        return []
    return [
        cleaned
        for cleaned in (_dashboard_suggestion_value(value) for value in values)
        if cleaned
    ]


def _dashboard_rule_form_suggestions(
    rules: list[dict[str, Any]],
    pending: list[dict[str, Any]],
) -> dict[str, list[str]]:
    destinations: list[str] = []
    tool_names: list[str] = []
    purposes: list[str] = []
    recipient_identities: list[str] = []

    def add(target: list[str], value: Any, *, limit: int = 160) -> None:
        cleaned = _dashboard_suggestion_value(value, limit=limit)
        if cleaned and cleaned not in target:
            target.append(cleaned)

    for rule in rules:
        match = rule.get("match") or {}
        add(destinations, match.get("destination"))
        add(tool_names, match.get("tool_name"), limit=120)
        add(purposes, match.get("purpose"), limit=80)
        add(recipient_identities, match.get("recipient_identity"), limit=120)
    for approval in pending:
        add(destinations, approval.get("destination"))
        add(tool_names, approval.get("tool_name"), limit=120)
        add(purposes, approval.get("purpose"), limit=80)
        add(recipient_identities, approval.get("recipient_identity"), limit=120)
    for value in _activity_distinct_values("destination"):
        add(destinations, value)
    for value in _activity_distinct_values("tool_name", limit=60):
        add(tool_names, value, limit=120)
    for value in _activity_distinct_values("purpose", limit=60):
        add(purposes, value, limit=80)
    for value in _activity_distinct_values("recipient_identity", limit=60):
        add(recipient_identities, value, limit=120)

    return {
        "destinations": destinations[:80],
        "tool_names": tool_names[:80],
        "purposes": purposes[:80],
        "recipient_identities": recipient_identities[:80],
    }


_OUTWARD_HISTORY_ACTION_FAMILIES = {
    "mcp_write",
    "mcp_unknown",
    "tool_write",
    "tool_unknown",
    "kanban_write",
    "web_api",
    "model_api",
    "homeassistant_write",
}
_OUTWARD_HISTORY_BUILTIN_VERB_RE = re.compile(
    r"(?:^|[^a-z0-9])(share|invite|publish|add_collaborator|make_public|set_permissions|"
    r"add_permission|grant)(?:[^a-z0-9]|$)",
    re.I,
)
_OUTWARD_HISTORY_HINTS = frozenset({
    "access",
    "collaborator",
    "collaborators",
    "crosspost",
    "external",
    "grant",
    "invite",
    "permission",
    "permissions",
    "public",
    "publish",
    "share",
    "sharing",
})
_OUTWARD_HISTORY_DETECTED_PARTS = frozenset({
    "add",
    "collaborator",
    "grant",
    "invite",
    "make",
    "permission",
    "permissions",
    "public",
    "publish",
    "set",
    "share",
})
_OUTWARD_HISTORY_GENERIC_PARTS = frozenset({
    "add",
    "append",
    "archive",
    "batch",
    "call",
    "complete",
    "create",
    "delete",
    "deliver",
    "edit",
    "fetch",
    "find",
    "get",
    "insert",
    "list",
    "lookup",
    "merge",
    "modify",
    "move",
    "mcp",
    "open",
    "patch",
    "post",
    "query",
    "read",
    "rename",
    "reply",
    "retrieve",
    "run",
    "search",
    "send",
    "set",
    "submit",
    "sync",
    "tool",
    "update",
    "upload",
    "upsert",
    "write",
})


def _outward_history_candidate_tokens(tool_name: Any, action_family: Any) -> list[str]:
    family = str(action_family or "").strip().lower()
    if family not in _OUTWARD_HISTORY_ACTION_FAMILIES:
        return []
    normalized = re.sub(r"[^a-z0-9_]+", "_", str(tool_name or "").strip().lower())
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    if not normalized:
        return []

    out: list[str] = []
    match = _OUTWARD_HISTORY_BUILTIN_VERB_RE.search(normalized)
    if match:
        out.append(match.group(1).lower())

    parts = [part for part in normalized.split("_") if part]
    if len(parts) >= 3 and parts[0] == "mcp":
        parts = parts[2:]
    for index in range(len(parts)):
        phrase_parts = parts[index:index + 3]
        if not phrase_parts:
            continue
        if phrase_parts[0] in _OUTWARD_HISTORY_GENERIC_PARTS:
            continue
        if not any(part in _OUTWARD_HISTORY_HINTS for part in phrase_parts):
            continue
        if any(part in _OUTWARD_HISTORY_DETECTED_PARTS for part in phrase_parts):
            continue
        token = "_".join(phrase_parts)
        if token and token not in out:
            out.append(token)
    return [
        token
        for token in out
        if 3 <= len(token) <= 48 and token not in _OUTWARD_HISTORY_GENERIC_PARTS
    ]


def _outward_sharing_history_suggestions(outward_snapshot: dict[str, Any], *, limit: int = 40) -> list[str]:
    excluded = {
        str(item or "").strip().lower()
        for item in list(outward_snapshot.get("builtin") or []) + list(outward_snapshot.get("extra") or [])
    }
    activity_store._ensure_activity_db()
    try:
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT tool_name, action_family, MAX(ts) AS latest
                FROM activity
                WHERE tool_name NOT IN ('', '*')
                GROUP BY tool_name, action_family
                ORDER BY latest DESC
                LIMIT ?
                """,
                (max(1, min(int(limit or 40) * 5, 200)),),
            ).fetchall()
    except Exception:
        return []

    out: list[str] = []
    for row in rows:
        for token in _outward_history_candidate_tokens(row["tool_name"], row["action_family"]):
            if token in excluded or token in out:
                continue
            out.append(token)
            if len(out) >= limit:
                return out
    return out


_RECENT_BLOCK_DECISIONS = ("blocked", "security_blocked")
_RESOLVED_APPROVAL_DECISIONS = ("denied", "manual_approved")


def _activity_data_classes_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw = value
    else:
        raw = str(value or "").split(",")
    return sorted(
        cls
        for cls in (str(item).strip() for item in raw)
        if cls in core._ALL_PRIVACY_CLASSES
    )


def _pending_approval_rule_coverage(approval: dict[str, Any]) -> dict[str, Any]:
    shape = {
        "session_id": tool_policy._normalize_session_id(approval.get("session_id")),
        "owner_hash": str(approval.get("owner_hash") or ""),
        "tool_name": str(approval.get("tool_name") or ""),
        "action_family": str(approval.get("action_family") or ""),
        "destination": str(approval.get("destination") or ""),
        "purpose": str(approval.get("purpose") or "unknown"),
        "recipient_identity": str(approval.get("recipient_identity") or "none"),
        "legacy_destination": str(approval.get("legacy_destination") or ""),
        "data_classes": _activity_data_classes_list(approval.get("data_classes")),
        "fingerprint": str(approval.get("fingerprint") or ""),
    }
    source = rules_mod._approval_source(shape)
    if source and source.get("effect") == "allow":
        return {
            "covered_by_rule": True,
            "covered_rule_id": str(source.get("rule_id") or ""),
            "covered_rule_source": str(source.get("source") or ""),
        }
    return {
        "covered_by_rule": False,
        "covered_rule_id": "",
        "covered_rule_source": "",
    }


def _stored_pending_approval_expirations(approval_ids: set[str]) -> dict[str, int]:
    ids = sorted(
        approval_id
        for approval_id in (str(item or "").strip() for item in approval_ids)
        if re.fullmatch(r"[0-9]{4}", approval_id)
    )
    if not ids:
        return {}
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT id, expires_at
                FROM pending_approvals
                WHERE id IN (
                """ + ",".join("?" for _ in ids) + ")",
                ids,
            ).fetchall()
    except Exception as exc:
        core.logger.debug("%s: failed to load stored approval expirations: %s", core._PLUGIN_NAME, exc)
        return {}
    return {
        str(row["id"]): int(float(row["expires_at"] or 0))
        for row in rows
        if str(row["id"] or "")
    }


def _resolved_approval_times(approval_ids: set[str]) -> dict[str, int]:
    ids = sorted(
        approval_id
        for approval_id in (str(item or "").strip() for item in approval_ids)
        if re.fullmatch(r"[0-9]{4}", approval_id)
    )
    if not ids:
        return {}
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT approval_id, MAX(ts) AS ts
                FROM activity
                WHERE approval_id IN (
                """ + ",".join("?" for _ in ids) + """
                )
                AND decision IN (
                """ + ",".join("?" for _ in _RESOLVED_APPROVAL_DECISIONS) + """
                )
                GROUP BY approval_id
                """,
                ids + list(_RESOLVED_APPROVAL_DECISIONS),
            ).fetchall()
    except Exception as exc:
        core.logger.debug("%s: failed to load resolved approval times: %s", core._PLUGIN_NAME, exc)
        return {}
    return {
        str(row["approval_id"]): int(float(row["ts"] or 0))
        for row in rows
        if str(row["approval_id"] or "")
    }


def _dashboard_recent_blocks(pending: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    pending_by_id = {
        str(item.get("id") or ""): item
        for item in pending
        if str(item.get("id") or "")
    }
    rows = _activity_rows({"decisions": ",".join(_RECENT_BLOCK_DECISIONS)}, limit=max(limit * 4, limit))
    row_approval_ids = {
        str(row.get("approval_id") or "")
        for row in rows
        if str(row.get("approval_id") or "")
    }
    stored_expirations = _stored_pending_approval_expirations(row_approval_ids)
    resolved_approval_times = _resolved_approval_times(row_approval_ids)
    blocks: list[dict[str, Any]] = []
    seen: set[str] = set()

    for row in rows:
        approval_id = str(row.get("approval_id") or "")
        pending_approval = pending_by_id.get(approval_id)
        row_ts = int(row.get("ts") or 0)
        if approval_id and not pending_approval and resolved_approval_times.get(approval_id, 0) >= row_ts:
            continue
        historical_approval_id = approval_id if approval_id and not pending_approval else ""
        expires_at = int((pending_approval or {}).get("expires_at") or stored_expirations.get(approval_id, 0) or 0)
        if historical_approval_id and not expires_at:
            continue
        if pending_approval:
            approval_status = "pending"
        elif str(row.get("decision") or "") == "denied":
            approval_status = "dismissed"
        elif historical_approval_id and expires_at and expires_at <= int(state._now()):
            approval_status = "expired"
        elif historical_approval_id:
            approval_status = "not_pending"
        else:
            approval_status = ""
        block_id = approval_id if pending_approval else f"activity-{int(row.get('id') or 0)}"
        if block_id in seen:
            continue
        seen.add(block_id)
        data_classes = (
            list(pending_approval.get("data_classes") or [])
            if pending_approval
            else _activity_data_classes_list(row.get("data_classes"))
        )
        blocks.append({
            "id": block_id,
            "activity_id": int(row.get("id") or 0),
            "approval_id": approval_id if pending_approval else "",
            "historical_approval_id": historical_approval_id,
            "dismiss_id": historical_approval_id if approval_status == "expired" else "",
            "approval_status": approval_status,
            "pending": bool(pending_approval),
            "decision": str(row.get("decision") or ""),
            "module": str(row.get("module") or ""),
            "session_label": str(row.get("session_label") or ""),
            "session_hash": str(row.get("session_hash") or ""),
            "tool_name": str(row.get("tool_name") or (pending_approval or {}).get("tool_name") or ""),
            "action_family": str(row.get("action_family") or (pending_approval or {}).get("action_family") or ""),
            "destination": str(row.get("destination") or (pending_approval or {}).get("destination") or ""),
            "purpose": str(row.get("purpose") or (pending_approval or {}).get("purpose") or "unknown"),
            "recipient_identity": str(row.get("recipient_identity") or (pending_approval or {}).get("recipient_identity") or "none"),
            "data_classes": sorted(data_classes),
            "action_detail": str(row.get("action_detail") or (pending_approval or {}).get("action_detail") or ""),
            "reason": str(row.get("reason") or (pending_approval or {}).get("reason") or ""),
            "created_at": int(row.get("ts") or (pending_approval or {}).get("created_at") or 0),
            "expires_at": expires_at,
            "cron_job_id": str((pending_approval or {}).get("cron_job_id") or ""),
            "cron_job_name": str((pending_approval or {}).get("cron_job_name") or ""),
            "scope": str((pending_approval or {}).get("scope") or ""),
            "covered_by_rule": bool((pending_approval or {}).get("covered_by_rule")),
            "covered_rule_id": str((pending_approval or {}).get("covered_rule_id") or ""),
            "covered_rule_source": str((pending_approval or {}).get("covered_rule_source") or ""),
        })

    for approval in pending:
        approval_id = str(approval.get("id") or "")
        if not approval_id or approval_id in seen:
            continue
        seen.add(approval_id)
        blocks.append(dict(approval, approval_id=approval_id, pending=True, decision="blocked", module="privacy"))

    return sorted(blocks, key=lambda item: int(item.get("created_at") or 0), reverse=True)[:limit]


_DATATABLES_SORT_COLUMNS = {
    "ts": "ts",
    "time": "ts",
    "decision": "decision",
    "icon": "decision",
    "tool": "tool_name",
    "tool_name": "tool_name",
    "action_family": "action_family",
    "destination": "destination",
    "data_classes": "data_classes",
    "mode": "mode",
    "reason": "reason",
    "reason_short": "reason",
    "purpose": "purpose",
    "recipient_identity": "recipient_identity",
    "destination_trust": "destination_trust",
    "decision_step": "decision_step",
}
_DATATABLES_SEARCH_COLUMNS = (
    "decision",
    "mode",
    "tool_name",
    "action_family",
    "destination",
    "purpose",
    "recipient_identity",
    "destination_trust",
    "decision_step",
    "data_classes",
    "reason",
    "approval_id",
    "rule_id",
    "rule_source",
    "action_detail",
    "module",
    "rule_effect",
    "rule_scope",
)


def _activity_filter_clauses(filters: dict[str, str]) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for key in ("decision", "action_family", "destination", "tool_name", "mode", "session_hash", "purpose", "recipient_identity", "destination_trust"):
        value = str(filters.get(key) or "").strip()
        if not value:
            continue
        if key in {"destination", "tool_name", "purpose", "recipient_identity"}:
            clauses.append(f"{key} LIKE ?")
            params.append(f"%{value}%")
        else:
            clauses.append(f"{key} = ?")
            params.append(value)
    decisions = [
        decision.strip()
        for decision in str(filters.get("decisions") or "").split(",")
        if decision.strip() in core._ACTIVITY_DECISIONS
    ]
    if decisions:
        clauses.append("decision IN (" + ",".join("?" for _ in decisions) + ")")
        params.extend(decisions)
    data_class = str(filters.get("data_class") or "").strip()
    if data_class:
        clauses.append("data_classes LIKE ?")
        params.append(f"%{data_class}%")
    search = str(filters.get("search") or filters.get("search[value]") or filters.get("q") or "").strip()
    if search:
        like = f"%{search}%"
        clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in _DATATABLES_SEARCH_COLUMNS) + ")")
        params.extend([like] * len(_DATATABLES_SEARCH_COLUMNS))
    return clauses, params


def _activity_count(clauses: list[str] | None = None, params: list[Any] | None = None) -> int:
    activity_store._ensure_activity_db()
    sql = "SELECT COUNT(*) FROM activity"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    try:
        with activity_store._activity_connect() as conn:
            return int(conn.execute(sql, params or []).fetchone()[0])
    except Exception:
        return 0


def _activity_row_from_sql(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "ts": row["ts"],
        "decision": row["decision"],
        "mode": row["mode"],
        "egress_safety": row["mode"],
        "session_label": row["session_label"],
        "session_hash": row["session_hash"],
        "owner_hash": row["owner_hash"],
        "tool_name": row["tool_name"],
        "action_family": row["action_family"],
        "destination": row["destination"],
        "purpose": row["purpose"],
        "recipient_identity": row["recipient_identity"],
        "data_classes": row["data_classes"],
        "reason": row["reason"],
        "approval_id": row["approval_id"],
        "rule_id": row["rule_id"],
        "rule_source": row["rule_source"],
        "action_detail": row["action_detail"],
        "module": row["module"],
        "rule_effect": row["rule_effect"],
        "rule_scope": row["rule_scope"],
        # Additive metadata columns (doc 03 §3.2). Guard with key presence so a row read
        # from a pre-migration snapshot renders display-safe (unknown / empty step).
        "destination_trust": _row_value(row, "destination_trust", "unknown"),
        "decision_step": _row_value(row, "decision_step", ""),
        "turn_id": _row_value(row, "turn_id", ""),
        "user_prompt": _row_value(row, "user_prompt", ""),
        "latency_us": _row_value(row, "latency_us", 0),
        "latency_hook": _row_value(row, "latency_hook", ""),
        "latency_llm_invoked": _row_value(row, "latency_llm_invoked", 0),
    }


def _row_value(row: sqlite3.Row, column: str, default: Any) -> Any:
    try:
        keys = row.keys()
    except Exception:
        return default
    if column in keys:
        value = row[column]
        return value if value is not None else default
    return default


def _activity_plain_reason_line(row: dict[str, Any], *, limit: int = 120) -> str:
    decision = str(row.get("decision") or "").strip()
    if decision == "tainted":
        return ""
    reason = dashboard._clip_text(dashboard._activity_display_reason(row), limit, ellipsis="...", fallback="")
    if not reason:
        return ""
    prefix = dashboard._activity_reason_prefix(decision)
    return f"{prefix}: {reason}" if prefix else reason


def _activity_datatables_row(row: dict[str, Any]) -> dict[str, Any]:
    direction = _activity_display_direction(row)
    return {
        "id": int(row.get("id") or 0),
        "DT_RowId": f"activity-{int(row.get('id') or 0)}",
        "ts": int(row.get("ts") or 0),
        "time": dashboard._activity_time_text(row),
        "time_short": dashboard._activity_clock_text(row),
        "icon": dashboard._activity_status_icon(str(row.get("decision") or "")),
        "decision": str(row.get("decision") or ""),
        "direction": direction,
        "tool": dashboard._activity_display_tool(row),
        "tool_name": str(row.get("tool_name") or ""),
        "action_family": str(row.get("action_family") or ""),
        "destination": str(row.get("destination") or ""),
        "destination_trust": str(row.get("destination_trust") or "unknown"),
        "decision_step": str(row.get("decision_step") or ""),
        "purpose": str(row.get("purpose") or ""),
        "recipient_identity": str(row.get("recipient_identity") or ""),
        "data_classes": str(row.get("data_classes") or ""),
        "reason_short": _activity_plain_reason_line(row),
        "reason": dashboard._activity_display_reason(row),
        "action_detail": str(row.get("action_detail") or ""),
        "mode": str(row.get("mode") or row.get("egress_safety") or ""),
        "session_hash": str(row.get("session_hash") or ""),
        "owner_hash": str(row.get("owner_hash") or ""),
        "approval_id": str(row.get("approval_id") or ""),
        "rule_id": str(row.get("rule_id") or ""),
        "rule_source": str(row.get("rule_source") or ""),
        "module": str(row.get("module") or ""),
        "rule_effect": str(row.get("rule_effect") or ""),
        "rule_scope": str(row.get("rule_scope") or ""),
        # Turn grouping + opt-in persisted prompt (read-shaping only; deliberately NOT in
        # the sort/search allowlists). user_prompt is the already-sanitized excerpt.
        "turn_id": str(row.get("turn_id") or ""),
        "user_prompt": str(row.get("user_prompt") or ""),
        "latency_us": max(0, int(row.get("latency_us") or 0)),
        "latency_ms": round(max(0, int(row.get("latency_us") or 0)) / 1000.0, 3),
        "latency_hook": str(row.get("latency_hook") or ""),
        "latency_llm_invoked": bool(row.get("latency_llm_invoked")),
    }


_READ_ACTION_FAMILIES = frozenset({"browser_read", "mcp_read_query", "message_list", "web_read"})


def _activity_display_direction(row: dict[str, Any]) -> str:
    decision = str(row.get("decision") or "")
    action_family = str(row.get("action_family") or "")
    hook = str(row.get("latency_hook") or "")
    tool_name = str(row.get("tool_name") or "")
    if decision in {"read", "tainted"}:
        return "read"
    if action_family in _READ_ACTION_FAMILIES:
        return "read"
    if hook in {"transform_tool_result", "pre_gateway_dispatch"}:
        return "read"
    if hook in {"pre_tool_call", "transform_llm_output"}:
        return "write"
    if decision == "security_suppressed" and tool_name and tool_name != "llm_output":
        return "read"
    if decision == "security_blocked" and tool_name == "gateway_message":
        return "read"
    return "write"


def _datatables_column_name(params: dict[str, str], index: int) -> str:
    return str(
        params.get(f"columns[{index}][name]")
        or params.get(f"columns[{index}][data]")
        or ""
    ).strip()


def _activity_datatables_payload(params: dict[str, str]) -> dict[str, Any]:
    def parse_int(name: str, default: int) -> int:
        try:
            return int(str(params.get(name, default)).strip())
        except (TypeError, ValueError):
            return default

    draw = max(0, parse_int("draw", 0))
    start = max(0, parse_int("start", 0))
    length = parse_int("length", 25)
    if length not in {25, 50, 100}:
        length = 25

    filters = {
        "decision": params.get("decision", ""),
        "data_class": params.get("data_class", ""),
        "tool_name": params.get("tool_name", ""),
        "action_family": params.get("action_family", ""),
        "destination": params.get("destination", ""),
        "destination_trust": params.get("destination_trust", ""),
        "purpose": params.get("purpose", ""),
        "recipient_identity": params.get("recipient_identity", ""),
        "search": params.get("search[value]", ""),
    }
    clauses, query_params = _activity_filter_clauses(filters)
    records_total = _activity_count()
    records_filtered = _activity_count(clauses, query_params)

    order_index = parse_int("order[0][column]", 0)
    requested_sort = _datatables_column_name(params, order_index)
    sort_column = _DATATABLES_SORT_COLUMNS.get(requested_sort)
    if sort_column is None:
        sort_column = "ts"
        sort_dir = "DESC"
    else:
        sort_dir = "ASC" if str(params.get("order[0][dir]", "")).lower() == "asc" else "DESC"
    sql = "SELECT * FROM activity"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += f" ORDER BY {sort_column} {sort_dir}, id DESC LIMIT ? OFFSET ?"
    page_params = [*query_params, length, start]
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            rows = [_activity_row_from_sql(row) for row in conn.execute(sql, page_params).fetchall()]
    except Exception:
        rows = []

    return {
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": [_activity_datatables_row(row) for row in rows],
    }


def _activity_turns_payload(params: dict[str, str]) -> dict[str, Any]:
    """History grouped by TURN for the dashboard, paginated by turn (not by row), newest
    first. Each returned turn carries all of its checks so a turn's actions never straddle
    a page. Legacy rows (turn_id='') are each their own single-check turn. Read-only,
    metadata-only — reuses the same row shaping as the datatables payload.
    """
    def parse_int(name: str, default: int) -> int:
        try:
            return int(str(params.get(name, default)).strip())
        except (TypeError, ValueError):
            return default

    draw = max(0, parse_int("draw", 0))
    start = max(0, parse_int("start", 0))
    length = parse_int("length", 25)
    if length not in {25, 50, 100}:
        length = 25

    # Group key: a real turn_id, or a per-row sentinel for legacy/ungrouped rows so each
    # is its own singleton turn (turn_ids are "turn_<hex>", never "row_<id>").
    gkey_expr = "COALESCE(NULLIF(turn_id, ''), 'row_' || id)"
    gkeys: list[str] = []
    rows_by_gkey: dict[str, list[dict[str, Any]]] = {}
    total_turns = 0
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            total_turns = int(
                conn.execute(
                    f"SELECT COUNT(*) AS n FROM (SELECT 1 FROM activity GROUP BY {gkey_expr})"
                ).fetchone()["n"]
            )
            page = conn.execute(
                f"SELECT {gkey_expr} AS gkey, MAX(ts) AS mts, MAX(id) AS mid "
                "FROM activity GROUP BY gkey ORDER BY mts DESC, mid DESC LIMIT ? OFFSET ?",
                (length, start),
            ).fetchall()
            gkeys = [str(r["gkey"]) for r in page]
            rows_by_gkey = {k: [] for k in gkeys}
            turn_ids = [k for k in gkeys if not k.startswith("row_")]
            legacy_ids = [int(k[4:]) for k in gkeys if k.startswith("row_") and k[4:].isdigit()]
            where: list[str] = []
            args: list[Any] = []
            if turn_ids:
                where.append("turn_id IN (" + ",".join("?" * len(turn_ids)) + ")")
                args.extend(turn_ids)
            if legacy_ids:
                where.append("id IN (" + ",".join("?" * len(legacy_ids)) + ")")
                args.extend(legacy_ids)
            if where:
                fetched = conn.execute(
                    "SELECT * FROM activity WHERE " + " OR ".join(where) + " ORDER BY ts DESC, id DESC",
                    args,
                ).fetchall()
                for raw in fetched:
                    row = _activity_row_from_sql(raw)
                    tid = str(row.get("turn_id") or "")
                    gkey = tid if tid else ("row_" + str(raw["id"]))
                    if gkey in rows_by_gkey:
                        rows_by_gkey[gkey].append(row)
    except Exception:
        return {"draw": draw, "recordsTotal": 0, "recordsFiltered": 0, "turns": []}

    turns: list[dict[str, Any]] = []
    for gkey in gkeys:
        rows = rows_by_gkey.get(gkey) or []
        if not rows:
            continue
        prompt = ""
        for row in rows:
            if str(row.get("user_prompt") or "").strip():
                prompt = str(row["user_prompt"]).strip()
                break
        turns.append(
            {
                "turn_id": "" if gkey.startswith("row_") else gkey,
                "user_prompt": prompt,
                "ts": max(int(row.get("ts") or 0) for row in rows),
                "total_latency_us": sum(max(0, int(row.get("latency_us") or 0)) for row in rows),
                "total_latency_ms": round(
                    sum(max(0, int(row.get("latency_us") or 0)) for row in rows) / 1000.0,
                    3,
                ),
                # A cron run's session id (and its truncated label) starts with "cron_".
                "is_cron": any(str(row.get("session_label") or "").startswith("cron_") for row in rows),
                "rows": [_activity_datatables_row(row) for row in rows],
            }
        )

    return {
        "draw": draw,
        "recordsTotal": total_turns,
        "recordsFiltered": total_turns,
        "turns": turns,
    }


def _activity_group_key(row: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(row.get("decision") or ""),
        str(row.get("mode") or ""),
        str(row.get("session_hash") or ""),
        str(row.get("tool_name") or ""),
        str(row.get("action_family") or ""),
        str(row.get("destination") or ""),
        str(row.get("purpose") or ""),
        str(row.get("recipient_identity") or ""),
        str(row.get("data_classes") or ""),
        str(row.get("reason") or ""),
        str(row.get("rule_source") or ""),
        str(row.get("action_detail") or ""),
    )


def _activity_marker(row: dict[str, Any]) -> str:
    return str(row.get("rule_source") or row.get("rule_id") or row.get("approval_id") or "")


def _group_activity_rows(
    rows: list[dict[str, Any]],
    *,
    limit: int | None = None,
    window_seconds: int | None = None,
) -> list[dict[str, Any]]:
    window = activity_store._activity_group_seconds() if window_seconds is None else max(0, int(window_seconds))
    if window <= 0:
        grouped = [dict(row, count=1, first_ts=row.get("ts"), grouped=False) for row in rows]
        return grouped[:limit] if limit is not None else grouped

    groups: list[dict[str, Any]] = []
    keys: list[tuple[str, ...]] = []
    for row in rows:
        try:
            row_ts = int(row.get("ts") or 0)
        except (TypeError, ValueError):
            row_ts = 0
        key = _activity_group_key(row)
        match: dict[str, Any] | None = None
        for index, group in enumerate(groups):
            if keys[index] != key:
                continue
            try:
                oldest_ts = int(group.get("first_ts") or group.get("ts") or 0)
            except (TypeError, ValueError):
                oldest_ts = 0
            if oldest_ts - row_ts <= window:
                match = group
                break
        if match is None:
            new_group = dict(row)
            new_group["count"] = 1
            new_group["first_ts"] = row_ts
            new_group["grouped"] = False
            groups.append(new_group)
            keys.append(key)
            continue
        match["count"] = int(match.get("count") or 1) + 1
        match["first_ts"] = min(int(match.get("first_ts") or row_ts), row_ts)
        match["grouped"] = True
        if not _activity_marker(match) and _activity_marker(row):
            match["approval_id"] = row.get("approval_id") or ""
            match["rule_id"] = row.get("rule_id") or ""
            match["rule_source"] = row.get("rule_source") or ""

    return groups[:limit] if limit is not None else groups


def _grouped_activity_rows(filters: dict[str, str], *, limit: int = 200) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    raw_limit = safe_limit if activity_store._activity_group_seconds() <= 0 else min(1000, max(safe_limit * 5, safe_limit))
    return _group_activity_rows(_activity_rows(filters, limit=raw_limit), limit=safe_limit)


def _cron_job_choices_for_dashboard() -> list[dict[str, Any]]:
    path = Path.home() / ".hermes" / "cron" / "jobs.json"
    try:
        parsed = json.loads(path.read_text()) if path.exists() else []
    except Exception as exc:
        core.logger.warning("%s: failed to load cron job choices for dashboard: %s", core._PLUGIN_NAME, exc)
        return []
    if isinstance(parsed, dict):
        raw_jobs: Any = parsed.get("jobs", parsed.get("items", []))
    else:
        raw_jobs = parsed
    if isinstance(raw_jobs, dict):
        iterable = []
        for key, value in raw_jobs.items():
            if isinstance(value, dict):
                merged = dict(value)
                merged.setdefault("id", key)
                iterable.append(merged)
    elif isinstance(raw_jobs, list):
        iterable = raw_jobs
    else:
        iterable = []
    choices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for job in iterable:
        if not isinstance(job, dict):
            continue
        job_id = str(job.get("id") or job.get("job_id") or "").strip()
        name = str(job.get("name") or job.get("title") or job_id).strip()
        if not job_id or not name or job_id in seen:
            continue
        raw_active = job.get("enabled", job.get("active", None))
        if raw_active is None:
            active = not bool(job.get("paused", False))
        elif isinstance(raw_active, str):
            active = raw_active.strip().lower() not in {"0", "false", "no", "off", "paused"}
        else:
            active = bool(raw_active)
        choices.append({
            "id": job_id[:80],
            "name": " ".join(name.split())[:160],
            "active": active,
        })
        seen.add(job_id)
    return choices


def _runtime_risk_banners() -> list[dict[str, str]]:
    banners = []
    if not core._security_rule_enabled("intrinsic_exfiltration"):
        banners.append(
            {
                "id": "intrinsic_exfiltration_disabled",
                "severity": "high",
                "message": "Security rule intrinsic_exfiltration is disabled; same-call source-and-sink hard blocks are not active.",
            }
        )
    if rules_mod._taint_classification_mode() == "relaxed":
        banners.append(
            {
                "id": "taint_classification_relaxed",
                "severity": "high",
                "message": "Taint Classification is relaxed; unrecognized tools are not gated under taint.",
            }
        )
    if rules_mod._self_grants_present():
        # Doc 03 §3.3: a non-empty self.identities / self.hosts is a real send-to-self /
        # own-infra trust grant. Informational, so the grant is never invisible.
        snapshot = rules_mod._self_config_snapshot()
        granted = []
        if snapshot.get("identities"):
            granted.append(f"{len(snapshot['identities'])} send-to-self identity(ies)")
        if snapshot.get("hosts"):
            granted.append(f"{len(snapshot['hosts'])} own-infra host(s)")
        banners.append(
            {
                "id": "self_trust_grants",
                "severity": "info",
                "message": (
                    "Self-destination trust granted: "
                    + ", ".join(granted)
                    + ". Sends/flows to these resolve to self and skip gating."
                ),
            }
        )
    return banners


def _perf_stats(durations_us: list[int]) -> dict[str, Any]:
    n = len(durations_us)
    if n == 0:
        return {"count": 0, "avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0, "total_ms": 0.0}
    ordered = sorted(durations_us)

    def pct(p: float) -> int:
        if n == 1:
            return ordered[0]
        idx = int(round((p / 100.0) * (n - 1)))
        return ordered[min(max(idx, 0), n - 1)]

    total = sum(ordered)
    return {
        "count": n,
        "avg_ms": round(total / n / 1000.0, 3),
        "p50_ms": round(pct(50) / 1000.0, 3),
        "p95_ms": round(pct(95) / 1000.0, 3),
        "max_ms": round(ordered[-1] / 1000.0, 3),
        "total_ms": round(total / 1000.0, 3),
    }


_PERF_HOOK_LABELS = {
    "pre_tool_call": "Tool call check",
    "transform_tool_result": "Tool result scrub",
    "transform_llm_output": "Final response check",
    "pre_gateway_dispatch": "Inbound message scan",
}


def _performance_summary(*, sample_limit: int = 50) -> dict[str, Any]:
    """Aggregate recent per-check timings for the Performance dashboard tab."""
    activity_store._ensure_activity_db()
    try:
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, hook, tool_name, duration_us, llm_invoked, blocked
                FROM check_timings ORDER BY ts DESC, id DESC LIMIT 5000
                """
            ).fetchall()
    except Exception:
        rows = []

    by_hook: dict[str, list[int]] = {}
    llm_us: list[int] = []
    deterministic_us: list[int] = []
    all_us: list[int] = []
    for row in rows:
        dur = int(row["duration_us"])
        all_us.append(dur)
        by_hook.setdefault(str(row["hook"]), []).append(dur)
        (llm_us if row["llm_invoked"] else deterministic_us).append(dur)

    hooks = [
        {"hook": hook, "label": _PERF_HOOK_LABELS.get(hook, hook), **_perf_stats(values)}
        for hook, values in sorted(by_hook.items(), key=lambda item: -sum(item[1]))
    ]
    samples = [
        {
            "ts": int(row["ts"]),
            "hook": str(row["hook"]),
            "tool_name": str(row["tool_name"] or ""),
            "duration_ms": round(int(row["duration_us"]) / 1000.0, 3),
            "llm_invoked": bool(row["llm_invoked"]),
            "blocked": bool(row["blocked"]),
        }
        for row in rows[:max(1, min(int(sample_limit), 500))]
    ]
    return {
        "overall": _perf_stats(all_us),
        "by_hook": hooks,
        "llm": _perf_stats(llm_us),
        "deterministic": _perf_stats(deterministic_us),
        "samples": samples,
        "window_size": len(rows),
    }


def _destination_trust_tally(*, limit: int = 500) -> dict[str, int]:
    """Count recent activity rows bucketed by ``destination_trust`` (doc 03 §3.1).

    Powers the dashboard "live tally of destinations-by-trust this session" and the
    `/guardian status` destination-trust summary, so an operator can spot an
    external/unknown they expected to be self. Metadata-only (reads the enum column).
    """
    activity_store._ensure_activity_db()
    tally: dict[str, int] = {}
    try:
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                "SELECT destination_trust AS trust, COUNT(*) AS n FROM activity "
                "WHERE decision NOT IN ('read', 'tainted') "
                "GROUP BY destination_trust"
            ).fetchall()
    except Exception:
        return {}
    for row in rows:
        label = activity_store._normalize_destination_trust_label(row["trust"])
        tally[label] = tally.get(label, 0) + int(row["n"] or 0)
    return tally


# Pseudo-destinations that are not ownable infra/stores, so they get no one-click
# "add to self" suggestion (the operator can still add anything via the explicit form).
_NON_ADDABLE_DESTINATIONS = frozenset(
    {"", "messaging", "web_search", "cron", "telegram", "model", "subagent", "browser", "shell", "network", "store"}
)
# A bare DNS hostname (browser/network destination) — own-infra host grant candidate.
_SEEN_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def _suggest_self_grant(destination: str) -> dict[str, str] | None:
    """Map an observed destination to a sensible self-grant {kind, value}, or None.

    Presentation-only: turns a display destination into the (kind, value) the existing
    `_add_self_destination` route accepts, so the dashboard can offer a one-click
    "this is mine". IPs/localhost and pseudo-destinations get no suggestion on purpose.
    """
    dest = str(destination or "").strip()
    low = dest.lower()
    if not dest or low in _NON_ADDABLE_DESTINATIONS:
        return None
    if low.startswith("mcp:") or low.startswith("store:") or low.startswith("draft:"):
        return {"kind": "destination", "value": low}
    if _SEEN_HOSTNAME_RE.match(low):
        return {"kind": "host", "value": dest}
    return None


def _seen_destination_resolver_shape(destination: str) -> tuple[str, str, str, str] | None:
    """Return resolver inputs for a claimable seen destination, or None."""
    suggest = _suggest_self_grant(destination)
    if not suggest:
        return None
    kind = str(suggest.get("kind") or "").strip().lower()
    value = str(suggest.get("value") or "").strip()
    if kind == "host":
        return ("host", value, "write", "")
    if kind != "destination":
        return None
    if ":" not in value:
        return ("store", value, "write", "")
    dest_kind, _, dest_id = value.partition(":")
    dest_kind = dest_kind.strip().lower()
    if dest_kind in {"mcp", "store", "draft"} and dest_id.strip():
        return (dest_kind, dest_id.strip(), "write", "")
    return None


def _current_seen_destination_trust(
    destination: str,
    stored_trust: str,
    config: dict[str, Any],
) -> str:
    """Resolve current trust for claimable seen destinations.

    Activity rows intentionally keep their historical trust label. The dashboard's
    "Seen recently" affordance is a live policy summary, though, so a destination the
    operator just claimed should stop looking unknown and stop offering "I own this".
    """
    trust = activity_store._normalize_destination_trust_label(stored_trust)
    shape = _seen_destination_resolver_shape(destination)
    if not shape:
        return trust
    try:
        resolved = destinations_mod._resolve_destination_trust(*shape, config)
    except Exception:
        return trust
    return activity_store._normalize_destination_trust_label(getattr(resolved, "value", resolved))


def _destination_trust_seen(*, limit: int = 300, max_entries: int = 40) -> list[dict[str, Any]]:
    """Distinct recent egress destinations with their trust + a suggested self-grant.

    Powers the dashboard "Seen recently" list and the one-click "this is mine -> add to
    self" (doc 03 §3.1). Metadata-only: reads the destination + historical
    destination_trust + recipient_identity columns, never payload. Claimable
    destinations are re-resolved against the current config for display, so a newly
    owned store/host no longer appears as unknown. The recipient identity is the same
    pseudonymized ``recipient_<hash>`` token stored on the row (never a raw address),
    and is surfaced so messaging egress can be grouped by recipient on the dashboard.
    Ordered most-recent-first, deduped by (destination, current trust, recipient_identity).
    """
    activity_store._ensure_activity_db()
    counts: dict[tuple[str, str, str], int] = {}
    order: list[tuple[str, str, str]] = []
    config = core._load_privacy_config()
    try:
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                "SELECT destination, destination_trust AS trust, recipient_identity FROM activity "
                "WHERE decision NOT IN ('read', 'tainted') "
                "ORDER BY ts DESC, id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
    except Exception:
        return []
    for row in rows:
        dest = str(row["destination"] or "")
        trust = _current_seen_destination_trust(dest, str(row["trust"] or ""), config)
        recipient = str(row["recipient_identity"] or "none")
        key = (dest, trust, recipient)
        if key not in counts:
            counts[key] = 0
            order.append(key)
        counts[key] += 1
    seen: list[dict[str, Any]] = []
    for dest, trust, recipient in order[:max_entries]:
        suggest = _suggest_self_grant(dest) if trust in ("external", "unknown", "public") else None
        seen.append(
            {
                "destination": dest,
                "trust": trust,
                "recipient_identity": recipient,
                "count": counts[(dest, trust, recipient)],
                "suggest": suggest,
            }
        )
    return seen


def _destination_trust_summary() -> dict[str, Any]:
    """The destination-trust summary block for status + dashboard (doc 03 §2, §3.1)."""
    self_snapshot = rules_mod._self_config_snapshot()
    outward_sharing = rules_mod._outward_sharing_snapshot()
    outward_sharing["suggestions"] = _outward_sharing_history_suggestions(outward_sharing)
    return {
        "tally": _destination_trust_tally(),
        "seen": _destination_trust_seen(),
        "self": self_snapshot,
        "trusted_recipients": rules_mod._trusted_recipients_snapshot(),
        "outward_sharing": outward_sharing,
        "self_grants_present": rules_mod._self_grants_present(),
        "env_overrides": rules_mod._active_env_overrides(),
    }


def _tool_group_for_name(tool_name: str, mcp_server_prefix: str = "") -> str:
    name = re.sub(r"[^a-z0-9_.:-]+", "_", str(tool_name or "").strip().lower()).strip("_")
    prefix = re.sub(r"[^a-z0-9_.:-]+", "_", str(mcp_server_prefix or "").strip().lower()).strip("_")
    if prefix:
        return f"{prefix}_*"
    if name.startswith("mcp_"):
        parts = name.split("_")
        if len(parts) >= 2 and parts[1]:
            return f"mcp_{parts[1]}_*"
    if "_" in name:
        return f"{name.split('_', 1)[0]}_*"
    return name or "other"


def _tool_group_for_match(match: str) -> str:
    text = re.sub(r"[^a-z0-9_.:-]+", "_", str(match or "").strip().lower()).strip("_")
    if not text:
        return "other"
    if text.endswith("*"):
        return text
    return _tool_group_for_name(text)


def _policy_snapshot_for_inventory(policy: dict[str, Any] | None, kind: str) -> dict[str, Any] | None:
    if not policy:
        return None
    base = {
        "id": str(policy.get("id") or ""),
        "match": str(policy.get("match") or ""),
        "enabled": bool(policy.get("enabled", True)),
        "note": str(policy.get("note") or ""),
    }
    if kind == "reading":
        base["source"] = str(policy.get("source") or "")
        base["taints"] = list(policy.get("taints") or [])
    else:
        base["egress"] = str(policy.get("egress") or "")
        base["destination"] = str(policy.get("destination") or "")
    return base


def _policy_for_tool_inventory(tool_name: str, policies: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    name = str(tool_name or "").strip().lower()
    exact = next((policy for policy in policies if policy.get("match") == name), None)
    if exact:
        return exact, "exact"
    prefix_matches = [
        policy
        for policy in policies
        if str(policy.get("match") or "").endswith("*")
        and name.startswith(str(policy.get("match") or "")[:-1])
    ]
    if prefix_matches:
        prefix_matches.sort(key=lambda policy: len(str(policy.get("match") or "")), reverse=True)
        return prefix_matches[0], "inherited"
    return None, "none"


def _merge_inventory_tokens(rows: list[dict[str, Any]], key: str) -> list[str]:
    out: list[str] = []
    for row in rows:
        for value in row.get(key) or []:
            text = str(value or "")
            if text and text not in out:
                out.append(text)
    return out[:20]


def _tool_inventory_tree(kind: str) -> list[dict[str, Any]]:
    policies = (
        rules_mod._reading_tools_snapshot()
        if kind == "reading"
        else rules_mod._sharing_tools_snapshot()
    )
    inventory = activity_store._tool_inventory_rows()
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in inventory:
        group = _tool_group_for_name(row.get("tool_name", ""), row.get("mcp_server_prefix", ""))
        groups.setdefault(group, []).append(row)
    for policy in policies:
        match = str(policy.get("match") or "")
        if match.endswith("*"):
            groups.setdefault(match, [])
        else:
            groups.setdefault(_tool_group_for_match(match), [])

    rows: list[dict[str, Any]] = []
    used_policy_ids: set[str] = set()
    group_order = sorted(
        groups,
        key=lambda group: (
            -max((int(row.get("last_seen") or 0) for row in groups[group]), default=0),
            group,
        ),
    )
    for group in group_order:
        children = sorted(
            groups[group],
            key=lambda row: (-int(row.get("last_seen") or 0), str(row.get("tool_name") or "")),
        )
        group_policy = next((policy for policy in policies if policy.get("match") == group), None)
        if group_policy:
            used_policy_ids.add(str(group_policy.get("id") or ""))
        group_policy_state = "exact" if group_policy and children else "policy_only" if group_policy else "none"
        group_call_count = sum(int(row.get("call_count") or 0) for row in children)
        group_result_count = sum(int(row.get("result_count") or 0) for row in children)
        rows.append({
            "key": f"group:{kind}:{group}",
            "row_type": "group",
            "depth": 0,
            "tool_name": "",
            "match": group,
            "group": group,
            "child_count": len(children),
            "call_count": group_call_count,
            "result_count": group_result_count,
            "seen_count": group_call_count + group_result_count,
            "first_seen": min((int(row.get("first_seen") or 0) for row in children), default=0),
            "last_seen": max((int(row.get("last_seen") or 0) for row in children), default=0),
            "observed_read_families": _merge_inventory_tokens(children, "observed_read_families"),
            "observed_egress_families": _merge_inventory_tokens(children, "observed_egress_families"),
            "observed_destinations": _merge_inventory_tokens(children, "observed_destinations"),
            "mcp_server_prefix": group[:-2] if group.endswith("_*") else "",
            "policy": _policy_snapshot_for_inventory(group_policy, kind),
            "policy_state": group_policy_state,
            "policy_match": str((group_policy or {}).get("match") or ""),
        })
        child_names = {str(row.get("tool_name") or "") for row in children}
        exact_policies = [
            policy
            for policy in policies
            if str(policy.get("match") or "")
            and not str(policy.get("match") or "").endswith("*")
            and _tool_group_for_match(str(policy.get("match") or "")) == group
            and str(policy.get("match") or "") not in child_names
        ]
        for row in children:
            tool_name = str(row.get("tool_name") or "")
            policy, policy_state = _policy_for_tool_inventory(tool_name, policies)
            if policy:
                used_policy_ids.add(str(policy.get("id") or ""))
            rows.append({
                "key": f"tool:{kind}:{tool_name}",
                "row_type": "tool",
                "depth": 1,
                "tool_name": tool_name,
                "match": tool_name,
                "group": group,
                "child_count": 0,
                "call_count": int(row.get("call_count") or 0),
                "result_count": int(row.get("result_count") or 0),
                "seen_count": int(row.get("call_count") or 0) + int(row.get("result_count") or 0),
                "first_seen": int(row.get("first_seen") or 0),
                "last_seen": int(row.get("last_seen") or 0),
                "observed_read_families": list(row.get("observed_read_families") or []),
                "observed_egress_families": list(row.get("observed_egress_families") or []),
                "observed_destinations": list(row.get("observed_destinations") or []),
                "mcp_server_prefix": str(row.get("mcp_server_prefix") or ""),
                "policy": _policy_snapshot_for_inventory(policy, kind),
                "policy_state": policy_state,
                "policy_match": str((policy or {}).get("match") or ""),
            })
        for policy in exact_policies:
            used_policy_ids.add(str(policy.get("id") or ""))
            match = str(policy.get("match") or "")
            rows.append({
                "key": f"policy:{kind}:{match}",
                "row_type": "policy",
                "depth": 1,
                "tool_name": "",
                "match": match,
                "group": group,
                "child_count": 0,
                "call_count": 0,
                "result_count": 0,
                "seen_count": 0,
                "first_seen": 0,
                "last_seen": 0,
                "observed_read_families": [],
                "observed_egress_families": [],
                "observed_destinations": [],
                "mcp_server_prefix": "",
                "policy": _policy_snapshot_for_inventory(policy, kind),
                "policy_state": "policy_only",
                "policy_match": match,
            })
    # Defensive: if any policy escaped grouping due to a malformed match, show it.
    for policy in policies:
        policy_id = str(policy.get("id") or "")
        if policy_id in used_policy_ids:
            continue
        match = str(policy.get("match") or "")
        rows.append({
            "key": f"policy:{kind}:{match or policy_id}",
            "row_type": "policy",
            "depth": 0,
            "tool_name": "",
            "match": match,
            "group": _tool_group_for_match(match),
            "child_count": 0,
            "call_count": 0,
            "result_count": 0,
            "seen_count": 0,
            "first_seen": 0,
            "last_seen": 0,
            "observed_read_families": [],
            "observed_egress_families": [],
            "observed_destinations": [],
            "mcp_server_prefix": "",
            "policy": _policy_snapshot_for_inventory(policy, kind),
            "policy_state": "policy_only",
            "policy_match": match,
        })
    return rows[:1200]


def _policy_snapshot() -> dict[str, Any]:
    with state._LOCK:
        llm._prune_expired()
        sessions = [
            {
                "session_label": core._safe_session_label(sid),
                "session_hash": core._short_hash(sid),
                "taint": sorted(session.get("taint") or []),
                "browser_host": session.get("browser_host") or "",
                "private_browser_hosts": sorted(session.get("browser_private_hosts") or []),
            }
            for sid, session in state._SESSIONS.items()
        ]
        pending = sorted(
            [
                {
                    "id": approval.get("id"),
                    "session_label": core._safe_session_label(approval.get("session_id")),
                    "session_hash": core._short_hash(approval.get("session_id")),
                    "tool_name": approval.get("tool_name"),
                    "action_family": approval.get("action_family"),
                    "destination": approval.get("destination"),
                    "destination_trust": activity_store._normalize_destination_trust_label(approval.get("destination_trust")),
                    "decision_step": activity_store._normalize_decision_step_label(approval.get("decision_step")),
                    "purpose": approval.get("purpose", "unknown"),
                    "recipient_identity": approval.get("recipient_identity", "none"),
                    "data_classes": sorted(approval.get("data_classes") or []),
                    "action_detail": approval.get("action_detail", ""),
                    "reason": approval.get("reason", ""),
                    "created_at": int(float(approval.get("created_at") or 0)),
                    "expires_at": int(float(approval.get("expires_at") or 0)),
                    "cron_job_id": str(approval.get("cron_job_id") or ""),
                    "cron_job_name": str(approval.get("cron_job_name") or ""),
                    "scope": approvals._rule_scope_label(
                        {
                            "scope": {
                                "cron_job_id": str(approval.get("cron_job_id") or ""),
                                "cron_job_name": str(approval.get("cron_job_name") or ""),
                            }
                        }
                    )
                    if str(approval.get("cron_job_id") or "")
                    else "",
                    # The context-filtered ways to permit this block (doc 06): expiry-based
                    # approval options plus any structural option (this recipient is me, trust this host, …).
                    "permit_options": approvals._approval_permit_options(approval),
                    **_pending_approval_rule_coverage(approval),
                }
                for approval in list(state._PENDING_APPROVALS.values())
            ],
            key=lambda item: int(item.get("created_at") or 0),
            reverse=True,
        )
        rules = rules_mod._persistent_privacy_rules()
    suggestions = _dashboard_rule_form_suggestions(rules, pending)
    recent_blocks = _dashboard_recent_blocks(pending)
    risk_banners = _runtime_risk_banners()
    return {
        "egress_safety": core._egress_safety_policy(),
        "taint_classification": rules_mod._taint_classification_mode(),
        "llm_source_classification": rules_mod._llm_source_classification_enabled(),
        "llm_source_classifier_model": rules_mod._llm_source_classifier_model(),
        "llm_source_classifier_model_options": rules_mod._source_classifier_model_options(),
        "llm_user_context": rules_mod._llm_user_context_enabled(),
        "llm_cron_context": rules_mod._llm_cron_context_enabled(),
        "persist_prompts": rules_mod._persist_prompts_enabled(),
        "llm_verifier_model": rules_mod._llm_verifier_model(),
        "llm_verifier_model_options": rules_mod._verifier_model_options(),
        "reading_tools": rules_mod._reading_tools_snapshot(),
        "sharing_tools": rules_mod._sharing_tools_snapshot(),
        "reading_tool_inventory": _tool_inventory_tree("reading"),
        "sharing_tool_inventory": _tool_inventory_tree("sharing"),
        "sharing_tool_egress_options": sorted(rules_mod._SHARING_TOOL_EGRESS_VALUES),
        "all_privacy_classes": sorted(core._ALL_PRIVACY_CLASSES),
        "destination_trust": _destination_trust_summary(),
        "risk_banners": risk_banners,
        "security_rules": rules_mod._security_rules_snapshot(),
        "language_packs": rules_mod._language_packs_snapshot(),
        "activity_db": str(state._ACTIVITY_DB_PATH),
        "activity_max_rows": activity_store._activity_max_rows(),
        "activity_retention_days": activity_store._activity_retention_days(),
        "activity_group_seconds": activity_store._activity_group_seconds(),
        "sessions": sessions,
        "pending": pending,
        "recent_blocks": recent_blocks,
        "cron_jobs": _cron_job_choices_for_dashboard(),
        "suggestions": suggestions,
        "destination_suggestions": suggestions["destinations"],
        "tool_name_suggestions": suggestions["tool_names"],
        "purpose_suggestions": suggestions["purposes"],
        "recipient_identity_suggestions": suggestions["recipient_identities"],
        "rules": [
            {
                "rule_id": rule.get("id", ""),
                "id": rule.get("id", ""),
                "source": "persistent",
                "effect": rule.get("effect", ""),
                "enabled": bool(rule.get("enabled", True)),
                "action_family": (rule.get("match") or {}).get("action_family", ""),
                "destination": (rule.get("match") or {}).get("destination", ""),
                "purpose": (rule.get("match") or {}).get("purpose", ""),
                "recipient_identity": (rule.get("match") or {}).get("recipient_identity", ""),
                "tool_name": (rule.get("match") or {}).get("tool_name", ""),
                "data_classes": sorted((rule.get("match") or {}).get("data_classes") or []),
                "scope": approvals._rule_scope_label(rule),
                "expires_at": int(float(rule.get("expires_at") or 0)),
                "owner_hash": str((rule.get("scope") or {}).get("owner_hash") or "*"),
                "cron_job_id": str((rule.get("scope") or {}).get("cron_job_id") or ""),
                "cron_job_name": str((rule.get("scope") or {}).get("cron_job_name") or ""),
            }
            for rule in rules
        ],
    }
