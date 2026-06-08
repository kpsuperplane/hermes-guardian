"""Activity query, filtering, grouping, and DataTables row shaping."""

from __future__ import annotations

def _activity_rows(filters: dict[str, str], *, limit: int = 200) -> list[dict[str, Any]]:
    _ensure_activity_db()
    clauses, params = _activity_filter_clauses(filters)
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
    return [_activity_row_from_sql(row) for row in rows]


def _dashboard_suggestion_value(value: Any, *, limit: int = 160) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    if not cleaned or cleaned == "*":
        return ""
    if re.search(r"(?:access_?token|auth_?token|api_?key|secret|password)=", cleaned, re.I):
        return ""
    return cleaned[:limit]


def _activity_distinct_values(column: str, *, limit: int = 40) -> list[str]:
    if column not in {"destination", "tool_name"}:
        return []
    _ensure_activity_db()
    sql = (
        f"SELECT {column} AS value, MAX(ts) AS latest FROM activity "
        f"WHERE {column} NOT IN ('', '*') "
        f"GROUP BY {column} ORDER BY latest DESC LIMIT ?"
    )
    try:
        with _activity_connect() as conn:
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

    def add(target: list[str], value: Any, *, limit: int = 160) -> None:
        cleaned = _dashboard_suggestion_value(value, limit=limit)
        if cleaned and cleaned not in target:
            target.append(cleaned)

    for rule in rules:
        match = rule.get("match") or {}
        add(destinations, match.get("destination"))
        add(tool_names, match.get("tool_name"), limit=120)
    for approval in pending:
        add(destinations, approval.get("destination"))
        add(tool_names, approval.get("tool_name"), limit=120)
    for value in _activity_distinct_values("destination"):
        add(destinations, value)
    for value in _activity_distinct_values("tool_name", limit=60):
        add(tool_names, value, limit=120)

    return {
        "destinations": destinations[:80],
        "tool_names": tool_names[:80],
    }


_RECENT_BLOCK_DECISIONS = ("blocked", "denied", "security_blocked")


def _activity_data_classes_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw = value
    else:
        raw = str(value or "").split(",")
    return sorted(
        cls
        for cls in (str(item).strip() for item in raw)
        if cls in _ALL_PRIVACY_CLASSES
    )


def _pending_approval_rule_coverage(approval: dict[str, Any]) -> dict[str, Any]:
    shape = {
        "session_id": _normalize_session_id(approval.get("session_id")),
        "owner_hash": str(approval.get("owner_hash") or ""),
        "tool_name": str(approval.get("tool_name") or ""),
        "action_family": str(approval.get("action_family") or ""),
        "destination": str(approval.get("destination") or ""),
        "data_classes": _activity_data_classes_list(approval.get("data_classes")),
        "fingerprint": str(approval.get("fingerprint") or ""),
    }
    source = _approval_source(shape, consume_once=False)
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
        _ensure_activity_db()
        with _activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT id, expires_at
                FROM pending_approvals
                WHERE id IN (
                """ + ",".join("?" for _ in ids) + ")",
                ids,
            ).fetchall()
    except Exception as exc:
        logger.debug("%s: failed to load stored approval expirations: %s", _PLUGIN_NAME, exc)
        return {}
    return {
        str(row["id"]): int(float(row["expires_at"] or 0))
        for row in rows
        if str(row["id"] or "")
    }


def _dashboard_recent_blocks(pending: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    pending_by_id = {
        str(item.get("id") or ""): item
        for item in pending
        if str(item.get("id") or "")
    }
    rows = _activity_rows({"decisions": ",".join(_RECENT_BLOCK_DECISIONS)}, limit=max(limit * 4, limit))
    stored_expirations = _stored_pending_approval_expirations({
        str(row.get("approval_id") or "")
        for row in rows
        if str(row.get("approval_id") or "")
    })
    blocks: list[dict[str, Any]] = []
    seen: set[str] = set()

    for row in rows:
        approval_id = str(row.get("approval_id") or "")
        pending_approval = pending_by_id.get(approval_id)
        historical_approval_id = approval_id if approval_id and not pending_approval else ""
        expires_at = int((pending_approval or {}).get("expires_at") or stored_expirations.get(approval_id, 0) or 0)
        if pending_approval:
            approval_status = "pending"
        elif str(row.get("decision") or "") == "denied":
            approval_status = "dismissed"
        elif historical_approval_id and expires_at and expires_at <= int(_now()):
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
    "module",
    "rule_effect",
    "rule_scope",
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
    decisions = [
        decision.strip()
        for decision in str(filters.get("decisions") or "").split(",")
        if decision.strip() in _ACTIVITY_DECISIONS
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
        "module": row["module"],
        "rule_effect": row["rule_effect"],
        "rule_scope": row["rule_scope"],
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
        "module": str(row.get("module") or ""),
        "rule_effect": str(row.get("rule_effect") or ""),
        "rule_scope": str(row.get("rule_scope") or ""),
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


def _cron_job_choices_for_dashboard() -> list[dict[str, Any]]:
    path = Path.home() / ".hermes" / "cron" / "jobs.json"
    try:
        parsed = json.loads(path.read_text()) if path.exists() else []
    except Exception as exc:
        logger.warning("%s: failed to load cron job choices for dashboard: %s", _PLUGIN_NAME, exc)
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
        pending = sorted(
            [
                {
                    "id": approval.get("id"),
                    "session_label": _safe_session_label(approval.get("session_id")),
                    "session_hash": _short_hash(approval.get("session_id")),
                    "tool_name": approval.get("tool_name"),
                    "action_family": approval.get("action_family"),
                    "destination": approval.get("destination"),
                    "data_classes": sorted(approval.get("data_classes") or []),
                    "action_detail": approval.get("action_detail", ""),
                    "reason": approval.get("reason", ""),
                    "created_at": int(float(approval.get("created_at") or 0)),
                    "expires_at": int(float(approval.get("expires_at") or 0)),
                    "cron_job_id": str(approval.get("cron_job_id") or ""),
                    "cron_job_name": str(approval.get("cron_job_name") or ""),
                    "scope": _rule_scope_label(
                        {
                            "scope": {
                                "cron_job_id": str(approval.get("cron_job_id") or ""),
                                "cron_job_name": str(approval.get("cron_job_name") or ""),
                            }
                        }
                    )
                    if str(approval.get("cron_job_id") or "")
                    else "",
                    **_pending_approval_rule_coverage(approval),
                }
                for approval in list(_PENDING_APPROVALS.values())
            ],
            key=lambda item: int(item.get("created_at") or 0),
            reverse=True,
        )
        rules = _persistent_privacy_rules()
    suggestions = _dashboard_rule_form_suggestions(rules, pending)
    recent_blocks = _dashboard_recent_blocks(pending)
    return {
        "privacy_policy": _privacy_policy(),
        "privacy_mode": _privacy_policy(),
        "security_rules": _security_rules_snapshot(),
        "language_packs": _language_packs_snapshot(),
        "activity_db": str(_ACTIVITY_DB_PATH),
        "activity_max_rows": _activity_max_rows(),
        "activity_retention_days": _activity_retention_days(),
        "activity_group_seconds": _activity_group_seconds(),
        "sessions": sessions,
        "pending": pending,
        "recent_blocks": recent_blocks,
        "cron_jobs": _cron_job_choices_for_dashboard(),
        "suggestions": suggestions,
        "destination_suggestions": suggestions["destinations"],
        "tool_name_suggestions": suggestions["tool_names"],
        "rules": [
            {
                "rule_id": rule.get("id", ""),
                "id": rule.get("id", ""),
                "source": "persistent",
                "effect": rule.get("effect", ""),
                "enabled": bool(rule.get("enabled", True)),
                "action_family": (rule.get("match") or {}).get("action_family", ""),
                "destination": (rule.get("match") or {}).get("destination", ""),
                "tool_name": (rule.get("match") or {}).get("tool_name", ""),
                "data_classes": sorted((rule.get("match") or {}).get("data_classes") or []),
                "scope": _rule_scope_label(rule),
                "remaining_invocations": int(rule.get("remaining_invocations", -1)),
                "owner_hash": str((rule.get("scope") or {}).get("owner_hash") or "*"),
                "session_id": str((rule.get("scope") or {}).get("session_id") or ""),
                "cron_job_id": str((rule.get("scope") or {}).get("cron_job_id") or ""),
                "cron_job_name": str((rule.get("scope") or {}).get("cron_job_name") or ""),
            }
            for rule in rules
        ],
    }
