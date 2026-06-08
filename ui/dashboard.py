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
        if not ok and message.startswith("No pending approval"):
            ok, message = _dashboard_dismiss_expired_approval(approval_id)
    else:
        return {"ok": False, "message": "Unsupported approval action.", "policy": _policy_snapshot()}, 400
    status = 200 if ok else (404 if message.startswith("No pending approval") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


def _dashboard_dismiss_expired_approval(approval_id: str) -> tuple[bool, str]:
    with _LOCK:
        approval = _pending_approval_from_store_unlocked(approval_id)
        if not approval:
            return False, f"No pending approval found for {approval_id}."
        if int(float(approval.get("expires_at") or 0)) > int(_now()):
            return False, f"No pending approval found for {approval_id}."
        if not _approval_owner_allowed(_CLI_OWNER_HASH, approval):
            return False, "Approval denied: this request belongs to a different user/session."
        _delete_pending_approvals_from_store_unlocked([approval_id])

    _emit_activity(
        "denied",
        session_id=approval.get("session_id", ""),
        owner_hash=approval.get("owner_hash", ""),
        tool_name=approval.get("tool_name", ""),
        action_family=approval.get("action_family", ""),
        destination=approval.get("destination", ""),
        purpose=approval.get("purpose", "unknown"),
        recipient_identity=approval.get("recipient_identity", "none"),
        data_classes=approval.get("data_classes") or [],
        reason=approval.get("reason") or "expired approval dismissed",
        approval_id=approval_id,
        action_detail=approval.get("action_detail", ""),
    )
    return True, f"Dismissed expired guardian approval {approval_id}."


def _dashboard_rule_delete_action(rule_id: str) -> tuple[dict[str, Any], int]:
    ok, message, _removed = _delete_persistent_rule(_CLI_OWNER_HASH, rule_id)
    status = 200 if ok else (404 if message.startswith("No matching privacy rule") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


def _dashboard_privacy_mode_action(mode: str) -> tuple[dict[str, Any], int]:
    ok, message = _set_privacy_mode(mode)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_security_rule_action(rule_id: str, enabled: Any) -> tuple[dict[str, Any], int]:
    ok, message = _set_security_rule(rule_id, _config_bool(enabled, default=True))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_language_pack_action(pack_id: str, enabled: Any) -> tuple[dict[str, Any], int]:
    ok, message = _set_language_pack(pack_id, _config_bool(enabled, default=True))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_unknown_tools_mode_action(mode: str) -> tuple[dict[str, Any], int]:
    ok, message = _set_unknown_tools_mode(mode)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_tool_override_create_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    match = payload.get("match") or payload.get("tool") or payload.get("tool_name") or ""
    ok, message = _set_tool_override(
        match,
        taints=payload.get("taints"),
        egress=payload.get("egress"),
        destination=payload.get("destination"),
        note=payload.get("note"),
        enabled=payload.get("enabled"),
    )
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_tool_override_update_action(override_id: str, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    target = str(override_id or "").strip()
    existing = next((o for o in _tool_overrides() if o.get("id") == target), None)
    if existing is None:
        return {
            "ok": False,
            "message": f"No matching tool override found for {override_id}.",
            "policy": _policy_snapshot(),
        }, 404
    if set(payload.keys()) <= {"enabled"} and "enabled" in payload:
        ok, message = _set_tool_override_enabled(target, _config_bool(payload.get("enabled"), default=True))
    else:
        ok, message = _set_tool_override(
            existing.get("match"),
            taints=payload.get("taints"),
            egress=payload.get("egress"),
            destination=payload.get("destination"),
            note=payload.get("note"),
            enabled=payload.get("enabled"),
        )
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_tool_override_delete_action(match_or_id: str) -> tuple[dict[str, Any], int]:
    ok, message = _delete_tool_override(match_or_id)
    status = 200 if ok else (404 if message.startswith("No matching tool override") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


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
