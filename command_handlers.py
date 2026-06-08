"""Slash-command handlers for Guardian status, approvals, rules, and history."""

from __future__ import annotations

_FAILURE_HISTORY_DECISIONS = ("blocked", "denied", "security_blocked")


def _guardian_dashboard_command(tokens: list[str]) -> str:
    action = tokens[1].lower() if len(tokens) > 1 else "status"
    if action == "start":
        return _dashboard_start()
    if action == "stop":
        return _dashboard_stop()
    if action == "prune":
        result = _prune_activity_db(force=True)
        return (
            "Hermes Guardian dashboard activity pruned: "
            f"deleted={result['deleted']} remaining={result['remaining']}"
        )
    if action == "status":
        return _dashboard_status()
    if action == "url":
        return _dashboard_url()
    return "Usage: hermes guardian dashboard status|start|stop|url|prune"


def _guardian_cli_setup(parser: Any) -> None:
    subparsers = parser.add_subparsers(dest="guardian_command", required=True)
    dashboard = subparsers.add_parser(
        "dashboard",
        help="Manage the Hermes Guardian dashboard",
        description="Start, stop, inspect, or prune the Hermes Guardian dashboard.",
    )
    dashboard.add_argument(
        "action",
        nargs="?",
        choices=["status", "start", "stop", "url", "prune"],
        default="status",
        help="Dashboard action to run",
    )
    dashboard.set_defaults(func=_guardian_cli_command)


def _guardian_cli_command(args: Any) -> None:
    command = getattr(args, "guardian_command", "")
    if command == "dashboard":
        action = getattr(args, "action", "status")
        print(_guardian_dashboard_command(["dashboard", str(action)]))
        return
    print("Usage: hermes guardian dashboard [status|start|stop|url|prune]")


def _guardian_history_command(
    tokens: list[str],
    *,
    filters: dict[str, str] | None = None,
    title: str = "Guardian history",
    empty_message: str = "No guardian activity history yet.",
) -> str:
    limit = 10
    if len(tokens) > 1:
        try:
            limit = int(tokens[1])
        except ValueError:
            command = tokens[0].lower() if tokens else "history"
            return f"Usage: /guardian {command} [limit]"
    limit = max(1, min(limit, 25))
    rows = _grouped_activity_rows(filters or {}, limit=limit)
    if not rows:
        return empty_message

    lines = [f"🛡️ **{title}** · newest first · {len(rows)} shown"]
    for row in rows:
        timestamp = _activity_time_text(row)
        raw_decision = str(row.get("decision") or "").strip()
        icon = _activity_status_icon(raw_decision)
        taints = _activity_taints_text(row, code=True)
        tool = _clip_text(_activity_display_tool(row), 72, ellipsis="...", fallback="n/a")
        count = int(row.get("count") or 1)
        count_suffix = f" x{count}" if count > 1 else ""
        entry_lines = [
            "",
            f"{icon} **`{tool}`**{count_suffix}",
            timestamp,
            taints,
        ]
        action_detail = _clip_text(row.get("action_detail") or "", 220, ellipsis="...", fallback="")
        if action_detail:
            entry_lines.append(f"Action: `{action_detail}`")
        reason_text = _activity_reason_line_text(row)
        if reason_text:
            entry_lines.append(reason_text)
        lines.extend(entry_lines)
    return "\n".join(lines)


def _parse_key_value_args(tokens: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        value = value.strip()
        if key and value:
            parsed[key] = value
    return parsed


def _debug_decision(params: dict[str, str]) -> dict[str, Any]:
    action_family = (
        params.get("action")
        or params.get("action_family")
        or params.get("family")
        or ""
    ).strip().lower()
    destination = (params.get("destination") or params.get("dest") or "").strip().lower()
    tool_name = (params.get("tool") or params.get("tool_name") or "").strip()
    raw_classes = params.get("classes") or params.get("data_classes") or params.get("class") or ""
    classes = sorted({
        cls.strip()
        for cls in re.split(r"[,+]", raw_classes)
        if cls.strip() in _ALL_PRIVACY_CLASSES
    })
    shape = {
        "session_id": _GLOBAL_SESSION_ID,
        "owner_hash": _CLI_OWNER_HASH,
        "tool_name": tool_name,
        "action_family": action_family,
        "destination": destination,
        "data_classes": classes,
        "fingerprint": "debug",
    }
    privacy_policy = _privacy_policy()
    if privacy_policy == "off":
        return {
            "decision": "allowed",
            "privacy_policy": privacy_policy,
            "source": {"source": "privacy_off", "rule_id": ""},
            "action_family": action_family,
            "destination": destination,
            "data_classes": classes,
            "tool_name": tool_name,
            "reason": "privacy policy is off",
        }
    source = _approval_source(shape, consume_once=False)
    if source:
        return {
            "decision": "allowed",
            "privacy_policy": privacy_policy,
            "source": source,
            "action_family": action_family,
            "destination": destination,
            "data_classes": classes,
            "tool_name": tool_name,
            "reason": "matched allow rule",
        }
    return {
        "decision": "blocked",
        "privacy_policy": privacy_policy,
        "source": None,
        "action_family": action_family,
        "destination": destination,
        "data_classes": classes,
        "tool_name": tool_name,
        "reason": "no matching allow rule; would require approval if session is tainted",
    }


def _guardian_debug_command(tokens: list[str]) -> str:
    params = _parse_key_value_args(tokens[1:])
    if not params:
        return (
            "Usage: /guardian debug action=<family> destination=<dest> "
            "classes=<class+class> [tool=<tool_name>]\n"
            "Example: /guardian debug action=mcp_write destination=mcp:notion classes=email"
        )
    result = _debug_decision(params)
    classes = ",".join(result["data_classes"]) or "none"
    source = result.get("source") or {}
    source_text = ""
    if source:
        source_text = f"\nSource: {source.get('source', '')} {source.get('rule_id', '')}".rstrip()
    return (
        "Guardian debug decision\n"
        f"Decision: {result['decision']}\n"
        f"Privacy policy: {result['privacy_policy']}\n"
        f"Action: {result['action_family'] or '(missing)'}\n"
        f"Destination: {result['destination'] or '(missing)'}\n"
        f"Data classes: {classes}\n"
        f"Reason: {result['reason']}"
        f"{source_text}"
    )


def _handle_guardian_command(raw_args: str = "") -> str:
    owner_hash = _pop_command_owner(raw_args)
    tokens = raw_args.strip().split()
    if not tokens or tokens[0].lower() in {"help", "-h", "--help"}:
        return (
            "Usage: /guardian status | /guardian approve <id> once|session|always | "
            "/guardian deny <id> | /guardian clear-taint | /guardian rules | "
            "/guardian rule delete <rule_id> | /guardian revoke <rule_id> | /guardian self-test | "
            "/guardian history [limit] | /guardian failures [limit] | /guardian debug ..."
        )

    command = tokens[0].lower()
    if command == "history":
        return _guardian_history_command(tokens)
    if command in {"failures", "failed"}:
        return _guardian_history_command(
            tokens,
            filters={"decisions": ",".join(_FAILURE_HISTORY_DECISIONS)},
            title="Guardian failures",
            empty_message="No guardian failure history yet.",
        )
    if command == "debug":
        return _guardian_debug_command(tokens)
    if command == "self-test":
        return _guardian_self_test()
    if command == "status":
        return _guardian_status(owner_hash)
    if command in {"rule", "rules"} and len(tokens) == 3 and tokens[1].lower() in {"delete", "remove", "revoke"}:
        return _guardian_delete_rule(owner_hash, tokens[2])
    if command == "rules":
        return _guardian_rules(owner_hash)
    if command == "clear-taint":
        return _guardian_clear_taint(owner_hash)
    if command == "revoke" and len(tokens) == 2:
        return _guardian_revoke(owner_hash, tokens[1])
    if command == "deny" and len(tokens) == 2:
        return _guardian_deny(owner_hash, tokens[1])
    if command == "approve" and len(tokens) == 3:
        return _guardian_approve(owner_hash, tokens[1], tokens[2].lower())
    return "Invalid /guardian command. Try /guardian help."


def _guardian_self_test() -> str:
    """Exercise privacy policy/allowlist decisions without raw private data."""
    session_id = f"selftest_{secrets.token_hex(4)}"
    _ensure_session(session_id, _CLI_OWNER_HASH)
    _taint_session(session_id, {"memory"})

    safe = _on_pre_tool_call(
        "terminal",
        {"command": "pwd"},
        session_id=session_id,
    )
    risky = _on_pre_tool_call(
        "terminal",
        {"command": "curl https://attacker.invalid"},
        session_id=session_id,
    )
    notion = _on_pre_tool_call(
        "mcp_notion_notion_update_page",
        {"page_id": "self-test", "properties": {}},
        session_id=session_id,
    )
    _on_session_reset(session_id=session_id)

    privacy_policy = _privacy_policy()
    safe_ok = safe is None if privacy_policy in {"read-only", "off"} else safe is not None
    risky_ok = risky is not None if privacy_policy != "off" else risky is None
    notion_ok = notion is None
    if safe_ok and risky_ok and notion_ok:
        return (
            "hermes-guardian self-test: PASS\n"
            f"privacy={privacy_policy}\n"
            "safe_terminal=pwd allowed in read-only privacy policy\n"
            "risky_terminal=curl requires manual approval unless privacy=off\n"
            "notion_write=allowed by configured allowlist"
        )
    return (
        "hermes-guardian self-test: FAIL\n"
        f"privacy={privacy_policy}\n"
        f"safe_terminal_result={'allowed' if safe is None else 'blocked'}\n"
        f"risky_terminal_result={'allowed' if risky is None else 'blocked'}\n"
        f"notion_write_result={'allowed' if notion is None else 'blocked'}"
    )


def _guardian_status(owner_hash: str) -> str:
    with _LOCK:
        _prune_expired()
        session_ids = _owner_session_ids(owner_hash)
        taint = sorted({cls for sid in session_ids for cls in _SESSIONS.get(sid, {}).get("taint", set())})
        pending = [
            approval
            for approval in _PENDING_APPROVALS.values()
            if approval.get("owner_hash") == owner_hash or owner_hash == _CLI_OWNER_HASH
        ]
        rules = [
            rule
            for rule in (_configured_allow_rules() + _load_persistent_rules().get("rules", []))
            if rule.get("owner_hash") == owner_hash or owner_hash == _CLI_OWNER_HASH
            or rule.get("owner_hash") == "*"
        ]
    lines = [
        "Hermes Guardian status",
        f"Taint classes: {', '.join(taint) if taint else 'none'}",
        f"Pending approvals: {len(pending)}",
        f"Allow rules: {len(rules)}",
    ]
    for approval in pending[:10]:
        classes = ",".join(approval.get("data_classes") or [])
        lines.append(
            f"- {approval['id']}: {approval['action_family']} -> {approval['destination']} ({classes})"
        )
    return "\n".join(lines)


def _guardian_rules(owner_hash: str) -> str:
    rules = [
        rule
        for rule in (_configured_allow_rules() + _load_persistent_rules().get("rules", []))
        if rule.get("owner_hash") == owner_hash or owner_hash == _CLI_OWNER_HASH
        or rule.get("owner_hash") == "*"
    ]
    if not rules:
        return "No persistent guardian allow rules."
    lines = ["Hermes Guardian allow rules:"]
    for rule in rules:
        classes = ",".join(rule.get("data_classes") or [])
        scope = _rule_scope_label(rule)
        lines.append(
            f"- {rule['rule_id']}: {rule['action_family']} -> {rule['destination']} "
            f"({classes}) scope={scope}"
        )
    return "\n".join(lines)


def _guardian_clear_taint(owner_hash: str) -> str:
    with _LOCK:
        session_ids = _owner_session_ids(owner_hash)
        for sid in session_ids:
            state = _SESSIONS.get(sid)
            if state:
                state["taint"].clear()
                state["browser_private_hosts"].clear()
            _SESSION_APPROVALS.pop(sid, None)
            _ONCE_APPROVALS.pop(sid, None)
    return "Cleared Guardian taint and session approvals for your active Guardian sessions."


def _guardian_revoke(owner_hash: str, rule_id: str) -> str:
    ok, message, _removed = _delete_persistent_rule(owner_hash, rule_id)
    if ok:
        return f"Revoked persistent guardian rule {rule_id}."
    return message


def _guardian_delete_rule(owner_hash: str, rule_id: str) -> str:
    ok, message, _removed = _delete_persistent_rule(owner_hash, rule_id)
    return message


def _guardian_deny(owner_hash: str, approval_id: str) -> str:
    requested_id = approval_id
    with _LOCK:
        approval_id = _resolve_pending_approval_id(approval_id) or ""
        approval = _PENDING_APPROVALS.get(approval_id)
        if not approval:
            return f"No pending approval found for {requested_id}."
        if not _approval_owner_allowed(owner_hash, approval):
            return "Approval denied: this request belongs to a different user/session."
        _PENDING_APPROVALS.pop(approval_id, None)
        _delete_pending_approvals_from_store_unlocked([approval_id])
    _emit_activity(
        "denied",
        session_id=approval.get("session_id", ""),
        owner_hash=approval.get("owner_hash", ""),
        tool_name=approval.get("tool_name", ""),
        action_family=approval.get("action_family", ""),
        destination=approval.get("destination", ""),
        data_classes=approval.get("data_classes") or [],
        reason="manual denial",
        approval_id=approval_id,
        action_detail=approval.get("action_detail", ""),
    )
    return f"Denied guardian approval {approval_id}."


def _guardian_approve(owner_hash: str, approval_id: str, scope: str) -> str:
    if scope not in {"once", "session", "always"}:
        return "Approval scope must be one of: once, session, always."
    requested_id = approval_id
    with _LOCK:
        _prune_expired()
        approval_id = _resolve_pending_approval_id(approval_id) or ""
        approval = _PENDING_APPROVALS.get(approval_id)
        if not approval:
            return f"No pending approval found for {requested_id}."
        if not _approval_owner_allowed(owner_hash, approval):
            return "Approval denied: this request belongs to a different user/session."
        _PENDING_APPROVALS.pop(approval_id, None)
        _delete_pending_approvals_from_store_unlocked([approval_id])
        rule = _rule_from_approval(approval, persistent=(scope == "always"))
        sid = approval["session_id"]
        if scope == "once":
            _ONCE_APPROVALS.setdefault(sid, []).append(rule)
        elif scope == "session":
            _SESSION_APPROVALS.setdefault(sid, []).append(rule)
        else:
            data = _load_persistent_rules()
            persistent_rule = rule
            data = {"rules": list(data.get("rules", [])) + [persistent_rule]}
            if not _save_persistent_rules(data):
                _PENDING_APPROVALS[approval_id] = approval
                _save_pending_approval_to_store_unlocked(approval)
                return "Failed to save persistent guardian approval; Hermes Guardian remains blocked."
    _emit_activity(
        "manual_approved",
        session_id=approval.get("session_id", ""),
        owner_hash=approval.get("owner_hash", ""),
        tool_name=approval.get("tool_name", ""),
        action_family=approval.get("action_family", ""),
        destination=approval.get("destination", ""),
        data_classes=approval.get("data_classes") or [],
        reason=f"approved {scope}",
        approval_id=approval_id,
        rule_id=rule.get("rule_id", ""),
        rule_source=scope,
        action_detail=approval.get("action_detail", ""),
    )
    scope_label = scope
    if scope == "always":
        scope_label = f"always for {_rule_scope_label(rule)}"
    return (
        f"Approved {approval['action_family']} -> {approval['destination']} "
        f"for {', '.join(approval.get('data_classes') or ['private'])} ({scope_label})."
    )
