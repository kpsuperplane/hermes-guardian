"""Dashboard data and action adapters for the Hermes dashboard plugin."""

from __future__ import annotations


def _dashboard_payload(filters: dict[str, str] | None = None, *, limit: int = 200) -> dict[str, Any]:
    return {
        "policy": _policy_snapshot(),
        "activity": _grouped_activity_rows(filters or {}, limit=limit),
    }


def _configured_history_timezone() -> str:
    raw = _env(_HISTORY_TIMEZONE_ENV, "").strip()
    if raw:
        return raw
    try:
        config_path = Path.home() / ".hermes" / "config.yaml"
        if config_path.exists():
            match = re.search(r"(?m)^\s*timezone:\s*['\"]?([^'\"\n#]*)", config_path.read_text())
            if match:
                return match.group(1).strip()
    except Exception:
        return ""
    return ""


def _history_timezone() -> ZoneInfo | None:
    configured = _configured_history_timezone()
    if configured:
        try:
            return ZoneInfo(configured)
        except ZoneInfoNotFoundError:
            logger.warning("%s: invalid history timezone %r; using local time", _PLUGIN_NAME, configured)
    return None


def _activity_display_tool(row: dict[str, Any]) -> str:
    return _presentation.activity_display_tool(row)


def _clip_text(value: Any, limit: int = 120, *, ellipsis: str = "...", fallback: str = "") -> str:
    return _presentation.clip_text(value, limit, ellipsis=ellipsis, fallback=fallback)


def _friendly_activity_timestamp(ts: Any) -> str:
    return _presentation.friendly_activity_timestamp(ts, _history_timezone())


def _activity_time_text(row: dict[str, Any]) -> str:
    return _presentation.activity_time_text(row, _history_timezone())


def _activity_display_reason(row: dict[str, Any]) -> str:
    return _presentation.activity_display_reason(
        row,
        all_privacy_classes=_ALL_PRIVACY_CLASSES,
        taint_reason_for_tool_result=_taint_reason_for_tool_result,
    )


def _activity_status_icon(decision: str) -> str:
    return _presentation.activity_status_icon(decision)


def _activity_reason_prefix(decision: str) -> str:
    return _presentation.activity_reason_prefix(decision)


def _activity_reason_line_text(row: dict[str, Any], *, limit: int = 72, marker_limit: int = 72) -> str:
    return _presentation.activity_reason_line_text(
        row,
        marker=_activity_marker(row),
        display_reason=_activity_display_reason(row),
        limit=limit,
        marker_limit=marker_limit,
    )


def _activity_taints_text(row: dict[str, Any], *, code: bool = False, html_code: bool = False) -> str:
    return _presentation.activity_taints_text(row, code=code, html_code=html_code)


def _dashboard_approval_action(approval_id: str, action: str, scope: str = "") -> tuple[dict[str, Any], int]:
    approval_id = str(approval_id or "").strip()
    action = str(action or "").strip().lower()
    scope = str(scope or "").strip().lower()
    if not re.fullmatch(r"[0-9]{4}", approval_id):
        return {"ok": False, "message": "Invalid approval id.", "policy": _policy_snapshot()}, 400
    if action == "approve":
        if scope not in {"once", "always"}:
            return {"ok": False, "message": "Approval scope must be once or always.", "policy": _policy_snapshot()}, 400
        message = _guardian_approve(_CLI_OWNER_HASH, approval_id, scope)
        ok = message.startswith("Approved ")
    elif action == "dismiss":
        message = _guardian_deny(_CLI_OWNER_HASH, approval_id)
        ok = message.startswith("Dismissed ")
    else:
        return {"ok": False, "message": "Unsupported approval action.", "policy": _policy_snapshot()}, 400
    status = 200 if ok else (404 if message.startswith("No pending approval") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


def _dashboard_rule_delete_action(rule_id: str) -> tuple[dict[str, Any], int]:
    ok, message, _removed = _delete_persistent_rule(_CLI_OWNER_HASH, rule_id)
    status = 200 if ok else (404 if message.startswith("No matching privacy rule") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


def _dashboard_privacy_mode_action(mode: str) -> tuple[dict[str, Any], int]:
    ok, message = _set_privacy_mode(mode)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_rule_create_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    rule = _normalize_privacy_rule(payload)
    if rule is None:
        return {"ok": False, "message": "Invalid privacy rule.", "policy": _policy_snapshot()}, 400
    rules = _persistent_privacy_rules()
    rules.append(rule)
    if not _save_persistent_privacy_rules(rules):
        return {"ok": False, "message": "Failed to save privacy rule.", "policy": _policy_snapshot()}, 500
    return {"ok": True, "message": f"Added privacy rule {rule['id']}.", "policy": _policy_snapshot()}, 200


def _dashboard_rule_update_action(rule_id: str, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    rules = _persistent_privacy_rules()
    index = next((idx for idx, rule in enumerate(rules) if rule.get("id") == rule_id), -1)
    if index < 0:
        return {"ok": False, "message": f"No matching privacy rule found for {rule_id}.", "policy": _policy_snapshot()}, 404
    move = payload.get("move") if isinstance(payload.get("move"), dict) else {}
    if move:
        target_id = str(move.get("target_id") or "").strip()
        where = str(move.get("where") or "").strip().lower()
        moving = rules.pop(index)
        target_index = next((idx for idx, rule in enumerate(rules) if rule.get("id") == target_id), -1)
        if target_index < 0 or where not in {"before", "after"}:
            rules.insert(index, moving)
            return {"ok": False, "message": "Invalid rule move.", "policy": _policy_snapshot()}, 400
        rules.insert(target_index if where == "before" else target_index + 1, moving)
    else:
        merged = dict(rules[index])
        for key in ("effect", "enabled", "match", "scope", "remaining_invocations"):
            if key in payload:
                merged[key] = payload[key]
        normalized = _normalize_privacy_rule(merged)
        if normalized is None:
            return {"ok": False, "message": "Invalid privacy rule update.", "policy": _policy_snapshot()}, 400
        rules[index] = normalized
    if not _save_persistent_privacy_rules(rules):
        return {"ok": False, "message": "Failed to save privacy rules.", "policy": _policy_snapshot()}, 500
    return {"ok": True, "message": f"Updated privacy rule {rule_id}.", "policy": _policy_snapshot()}, 200
