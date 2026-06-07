"""Modularized guardian runtime module."""

from __future__ import annotations

def _activity_rows(filters: dict[str, str], *, limit: int = 200) -> list[dict[str, Any]]:
    _ensure_activity_db()
    clauses: list[str] = []
    params: list[Any] = []
    for key in ("decision", "action_family", "destination", "tool_name", "mode", "session_hash"):
        value = str(filters.get(key) or "").strip()
        if not value:
            continue
        if key in {"destination", "tool_name"}:
            clauses.append(f"{key} LIKE ?")
            params.append(f"%{value}%")
        else:
            clauses.append(f"{key} = ?")
            params.append(value)
    data_class = str(filters.get("data_class") or "").strip()
    if data_class:
        clauses.append("data_classes LIKE ?")
        params.append(f"%{data_class}%")
    sql = "SELECT * FROM activity"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))
    try:
        with _activity_connect() as conn:
            rows = conn.execute(sql, params).fetchall()
    except Exception:
        return []
    return [
        {
            "id": row["id"],
            "ts": row["ts"],
            "decision": row["decision"],
            "mode": row["mode"],
            "privacy_policy": row["mode"],
            "session_label": row["session_label"],
            "session_hash": row["session_hash"],
            "owner_hash": row["owner_hash"],
            "tool_name": row["tool_name"],
            "action_family": row["action_family"],
            "destination": row["destination"],
            "data_classes": row["data_classes"],
            "reason": row["reason"],
            "approval_id": row["approval_id"],
            "rule_id": row["rule_id"],
            "rule_source": row["rule_source"],
            "action_detail": row["action_detail"],
        }
        for row in rows
    ]


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
}
_DATATABLES_SEARCH_COLUMNS = (
    "decision",
    "mode",
    "tool_name",
    "action_family",
    "destination",
    "data_classes",
    "reason",
    "approval_id",
    "rule_id",
    "rule_source",
    "action_detail",
)


def _activity_filter_clauses(filters: dict[str, str]) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for key in ("decision", "action_family", "destination", "tool_name", "mode", "session_hash"):
        value = str(filters.get(key) or "").strip()
        if not value:
            continue
        if key in {"destination", "tool_name"}:
            clauses.append(f"{key} LIKE ?")
            params.append(f"%{value}%")
        else:
            clauses.append(f"{key} = ?")
            params.append(value)
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
    _ensure_activity_db()
    sql = "SELECT COUNT(*) FROM activity"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    try:
        with _activity_connect() as conn:
            return int(conn.execute(sql, params or []).fetchone()[0])
    except Exception:
        return 0


def _activity_row_from_sql(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "ts": row["ts"],
        "decision": row["decision"],
        "mode": row["mode"],
        "privacy_policy": row["mode"],
        "session_label": row["session_label"],
        "session_hash": row["session_hash"],
        "owner_hash": row["owner_hash"],
        "tool_name": row["tool_name"],
        "action_family": row["action_family"],
        "destination": row["destination"],
        "data_classes": row["data_classes"],
        "reason": row["reason"],
        "approval_id": row["approval_id"],
        "rule_id": row["rule_id"],
        "rule_source": row["rule_source"],
        "action_detail": row["action_detail"],
    }


def _activity_plain_reason_line(row: dict[str, Any], *, limit: int = 120) -> str:
    decision = str(row.get("decision") or "").strip()
    if decision == "tainted":
        return ""
    reason = _clip_text(_activity_display_reason(row), limit, ellipsis="...", fallback="")
    if not reason:
        return ""
    prefix = _activity_reason_prefix(decision)
    return f"{prefix}: {reason}" if prefix else reason


def _activity_datatables_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row.get("id") or 0),
        "DT_RowId": f"activity-{int(row.get('id') or 0)}",
        "ts": int(row.get("ts") or 0),
        "time": _activity_time_text(row),
        "icon": _activity_status_icon(str(row.get("decision") or "")),
        "decision": str(row.get("decision") or ""),
        "tool": _activity_display_tool(row),
        "tool_name": str(row.get("tool_name") or ""),
        "action_family": str(row.get("action_family") or ""),
        "destination": str(row.get("destination") or ""),
        "data_classes": str(row.get("data_classes") or ""),
        "reason_short": _activity_plain_reason_line(row),
        "reason": _activity_display_reason(row),
        "action_detail": str(row.get("action_detail") or ""),
        "mode": str(row.get("mode") or row.get("privacy_policy") or ""),
        "session_hash": str(row.get("session_hash") or ""),
        "owner_hash": str(row.get("owner_hash") or ""),
        "approval_id": str(row.get("approval_id") or ""),
        "rule_id": str(row.get("rule_id") or ""),
        "rule_source": str(row.get("rule_source") or ""),
    }


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
        _ensure_activity_db()
        with _activity_connect() as conn:
            rows = [_activity_row_from_sql(row) for row in conn.execute(sql, page_params).fetchall()]
    except Exception:
        rows = []

    return {
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": [_activity_datatables_row(row) for row in rows],
    }


def _activity_group_key(row: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(row.get("decision") or ""),
        str(row.get("mode") or ""),
        str(row.get("session_hash") or ""),
        str(row.get("tool_name") or ""),
        str(row.get("action_family") or ""),
        str(row.get("destination") or ""),
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
    window = _activity_group_seconds() if window_seconds is None else max(0, int(window_seconds))
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
    raw_limit = safe_limit if _activity_group_seconds() <= 0 else min(1000, max(safe_limit * 5, safe_limit))
    return _group_activity_rows(_activity_rows(filters, limit=raw_limit), limit=safe_limit)


def _policy_snapshot() -> dict[str, Any]:
    with _LOCK:
        _prune_expired()
        sessions = [
            {
                "session_label": _safe_session_label(sid),
                "session_hash": _short_hash(sid),
                "taint": sorted(state.get("taint") or []),
                "browser_host": state.get("browser_host") or "",
                "private_browser_hosts": sorted(state.get("browser_private_hosts") or []),
            }
            for sid, state in _SESSIONS.items()
        ]
        pending = [
            {
                "id": approval.get("id"),
                "session_label": _safe_session_label(approval.get("session_id")),
                "action_family": approval.get("action_family"),
                "destination": approval.get("destination"),
                "data_classes": sorted(approval.get("data_classes") or []),
                "expires_at": approval.get("expires_at"),
            }
            for approval in _PENDING_APPROVALS.values()
        ]
        rules = _configured_allow_rules() + _load_persistent_rules().get("rules", [])
    return {
        "privacy_policy": _privacy_policy(),
        "allowlist_env_set": bool(_env(_ALLOWLIST_ENV, "").strip()),
        "activity_db": str(_ACTIVITY_DB_PATH),
        "activity_max_rows": _activity_max_rows(),
        "activity_retention_days": _activity_retention_days(),
        "activity_group_seconds": _activity_group_seconds(),
        "sessions": sessions,
        "pending": pending,
        "rules": [
            {
                "rule_id": rule.get("rule_id", ""),
                "source": rule.get("source", "persistent"),
                "action_family": rule.get("action_family", ""),
                "destination": rule.get("destination", ""),
                "data_classes": sorted(rule.get("data_classes") or []),
            }
            for rule in rules
        ],
    }
