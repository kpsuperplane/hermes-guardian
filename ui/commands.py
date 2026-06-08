"""Slash-command handlers for Guardian status, approvals, rules, and history."""

from __future__ import annotations

import shlex
import secrets

_FAILURE_HISTORY_DECISIONS = ("blocked", "denied", "security_blocked")

_GUARDIAN_HELP_LINES = [
    "/guardian status",
    "/guardian approve <id> once|session|always",
    "/guardian dismiss <id> (alias: deny)",
    "/guardian clear-taint",
    "/guardian rules",
    "/guardian rule add allow|deny action=<family|*> destination=<dest|*> classes=<class+class|*> [tool=<tool_name|*>]",
    "/guardian rule delete <rule_id>",
    "/guardian rule enable|disable <rule_id>",
    "/guardian rule move <rule_id> before|after <other_rule_id>",
    "/guardian privacy mode strict|read-only|llm|off",
    "/guardian history [limit]",
    "/guardian failures [limit]",
    "/guardian failed [limit] (alias)",
    "/guardian debug action=<family> destination=<dest> classes=<class+class> [tool=<tool_name>]",
]

_RULE_ADD_KEYS = {
    "id",
    "action",
    "action_family",
    "family",
    "destination",
    "dest",
    "tool",
    "tool_name",
    "classes",
    "data_classes",
    "owner",
    "owner_hash",
    "session",
    "session_id",
    "cron",
    "cron_job_id",
    "cron_name",
    "cron_job_name",
    "remaining",
    "remaining_invocations",
}

_DEBUG_KEYS = {
    "action",
    "action_family",
    "family",
    "destination",
    "dest",
    "tool",
    "tool_name",
    "classes",
    "data_classes",
    "class",
}


def _guardian_help_text() -> str:
    return "Usage: /guardian <command>\n" + "\n".join(_GUARDIAN_HELP_LINES)


def _slash_admin_allowed(owner_hash: str) -> bool:
    return owner_hash == _CLI_OWNER_HASH or owner_hash in _configured_owner_hashes()


def _global_mutation_denied_message() -> str:
    return "Permission denied: only the CLI or configured Guardian owners can change global Guardian configuration."


def _guardian_dashboard_command(tokens: list[str]) -> str:
    action = tokens[1].lower() if len(tokens) > 1 else "status"
    if action == "prune":
        result = _prune_activity_db(force=True)
        return (
            "Hermes Guardian activity pruned: "
            f"deleted={result['deleted']} remaining={result['remaining']}"
        )
    if action in {"status", "url"}:
        return "Hermes Guardian is integrated into the Hermes dashboard at /guardian."
    return "Usage: hermes guardian dashboard status|url|prune"


def _guardian_cli_setup(parser: Any) -> None:
    subparsers = parser.add_subparsers(dest="guardian_command", required=True)
    dashboard = subparsers.add_parser(
        "dashboard",
        help="Inspect the Hermes Guardian dashboard integration",
        description="Show the Hermes dashboard integration status or prune Guardian activity.",
    )
    dashboard.add_argument(
        "action",
        nargs="?",
        choices=["status", "url", "prune"],
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
    print("Usage: hermes guardian dashboard [status|url|prune]")


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


def _parse_key_value_args(tokens: list[str], *, allowed_keys: set[str] | None = None) -> tuple[dict[str, str], list[str]]:
    parsed: dict[str, str] = {}
    errors: list[str] = []
    for token in tokens:
        if "=" not in token:
            errors.append(f"Expected key=value argument: {token}")
            continue
        key, value = token.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        value = value.strip()
        if not key:
            errors.append(f"Invalid empty argument key in {token}")
            continue
        if allowed_keys is not None and key not in allowed_keys:
            errors.append(f"Unknown argument: {key}")
            continue
        if not value:
            errors.append(f"Missing value for argument: {key}")
            continue
        parsed[key] = value
    return parsed, errors


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
        denied = source.get("effect") == "deny"
        return {
            "decision": "blocked" if denied else "allowed",
            "privacy_policy": privacy_policy,
            "source": source,
            "action_family": action_family,
            "destination": destination,
            "data_classes": classes,
            "tool_name": tool_name,
            "reason": "matched deny rule" if denied else "matched allow rule",
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
    params, errors = _parse_key_value_args(tokens[1:], allowed_keys=_DEBUG_KEYS)
    if errors:
        return "Invalid debug arguments: " + "; ".join(errors)
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
    try:
        tokens = shlex.split(raw_args.strip())
    except ValueError as exc:
        return f"Invalid /guardian command syntax: {exc}"
    if not tokens or tokens[0].lower() in {"help", "-h", "--help"}:
        return _guardian_help_text()

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
    if command == "status":
        return _guardian_status(owner_hash)
    if command == "privacy":
        return _guardian_privacy_command(owner_hash, tokens)
    if command == "rule":
        return _guardian_rule_command(owner_hash, tokens)
    if command in {"rule", "rules"} and len(tokens) == 3 and tokens[1].lower() in {"delete", "remove", "revoke"}:
        return _guardian_delete_rule(owner_hash, tokens[2])
    if command == "rules":
        return _guardian_rules(owner_hash)
    if command == "clear-taint":
        return _guardian_clear_taint(owner_hash)
    if command == "revoke" and len(tokens) == 2:
        return _guardian_revoke(owner_hash, tokens[1])
    if command in {"dismiss", "deny"} and len(tokens) == 2:
        return _guardian_dismiss(owner_hash, tokens[1])
    if command == "approve" and len(tokens) == 3:
        return _guardian_approve(owner_hash, tokens[1], tokens[2].lower())
    return "Invalid /guardian command. Try /guardian help."


def _guardian_privacy_command(owner_hash: str, tokens: list[str]) -> str:
    if len(tokens) == 1:
        return f"Privacy mode: {_privacy_policy()}"
    if len(tokens) == 3 and tokens[1].lower() == "mode":
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        ok, message = _set_privacy_mode(tokens[2])
        return message
    return "Usage: /guardian privacy mode strict|read-only|llm|off"


def _rule_add_usage() -> str:
    return "Usage: /guardian rule add allow|deny action=<family|*> destination=<dest|*> classes=<class+class|*> [tool=<tool_name|*>]"


def _rule_add_error(message: str) -> tuple[dict[str, Any] | None, str]:
    return None, f"Invalid privacy rule. {message}\n{_rule_add_usage()}"


def _new_privacy_rule_from_params(
    owner_hash: str,
    effect: str,
    params: dict[str, str],
) -> tuple[dict[str, Any] | None, str]:
    raw_action = params.get("action") or params.get("action_family") or params.get("family")
    raw_destination = params.get("destination") or params.get("dest")
    raw_classes = params.get("classes") or params.get("data_classes")
    if raw_action is None:
        return _rule_add_error("Missing required action=<family|*>.")
    if raw_destination is None:
        return _rule_add_error("Missing required destination=<dest|*>.")
    if raw_classes is None:
        return _rule_add_error("Missing required classes=<class+class|*>.")

    action_family = raw_action
    destination = raw_destination
    tool_name = params.get("tool") or params.get("tool_name") or "*"
    if raw_classes.strip() == "*":
        classes = ["*"]
    else:
        requested_classes = [cls.strip() for cls in re.split(r"[,+]", raw_classes) if cls.strip()]
        invalid_classes = [cls for cls in requested_classes if cls not in _ALL_PRIVACY_CLASSES]
        if invalid_classes:
            return _rule_add_error("Unknown data class(es): " + ", ".join(invalid_classes) + ".")
        if not requested_classes:
            return _rule_add_error("Data classes must be a valid class list or explicit *.")
        classes = requested_classes
    try:
        remaining = int(params.get("remaining") or params.get("remaining_invocations") or "-1")
    except ValueError:
        return _rule_add_error("remaining must be an integer.")

    requested_owner = params.get("owner") or params.get("owner_hash")
    cron_job_id = params.get("cron") or params.get("cron_job_id") or ""
    if requested_owner is None:
        rule_owner = "*" if owner_hash == _CLI_OWNER_HASH or (cron_job_id and _slash_admin_allowed(owner_hash)) else owner_hash
    else:
        rule_owner = requested_owner
        if rule_owner == "*" and not _slash_admin_allowed(owner_hash):
            return None, _global_mutation_denied_message()
        if rule_owner != "*" and owner_hash != _CLI_OWNER_HASH and rule_owner != owner_hash:
            return None, "Permission denied: you can only create privacy rules for your own owner scope."
    if cron_job_id and not _slash_admin_allowed(owner_hash):
        return None, _global_mutation_denied_message()

    rule = {
        "id": params.get("id") or f"rule_{secrets.token_hex(4)}",
        "effect": effect,
        "enabled": True,
        "match": {
            "tool_name": tool_name,
            "action_family": action_family,
            "destination": destination,
            "data_classes": classes or ["*"],
        },
        "scope": {
            "owner_hash": rule_owner,
            "session_id": params.get("session") or params.get("session_id") or "",
            "cron_job_id": cron_job_id,
            "cron_job_name": params.get("cron_name") or params.get("cron_job_name") or "",
        },
        "remaining_invocations": remaining,
        "created_at": int(_now()),
    }
    return _normalize_privacy_rule(rule), ""


def _guardian_rule_command(owner_hash: str, tokens: list[str]) -> str:
    if len(tokens) >= 3 and tokens[1].lower() == "add" and tokens[2].lower() in {"allow", "deny"}:
        params, errors = _parse_key_value_args(tokens[3:], allowed_keys=_RULE_ADD_KEYS)
        if errors:
            return "Invalid privacy rule arguments: " + "; ".join(errors) + f"\n{_rule_add_usage()}"
        rule, error = _new_privacy_rule_from_params(owner_hash, tokens[2].lower(), params)
        if not rule:
            return error
        rules = _persistent_privacy_rules()
        rules.append(rule)
        if not _save_persistent_privacy_rules(rules):
            return "Failed to save privacy rule."
        match = rule.get("match") or {}
        return (
            f"Added privacy {rule['effect']} rule {rule['id']}.\n"
            f"Match: {match.get('action_family', '*')} -> {match.get('destination', '*')}\n"
            f"Scope: {_rule_scope_text(rule)}\n"
            f"{_rule_classes_line(match.get('data_classes') or [])}"
        )
    if len(tokens) == 3 and tokens[1].lower() in {"delete", "remove", "revoke"}:
        return _guardian_delete_rule(owner_hash, tokens[2])
    if len(tokens) == 3 and tokens[1].lower() in {"enable", "disable"}:
        desired = tokens[1].lower() == "enable"
        rules = _persistent_privacy_rules()
        for rule in rules:
            if rule.get("id") == tokens[2] and _rule_delete_owner_allowed(owner_hash, rule):
                rule["enabled"] = desired
                if not _save_persistent_privacy_rules(rules):
                    return "Failed to save privacy rule."
                return f"{'Enabled' if desired else 'Disabled'} privacy rule {tokens[2]}."
        return f"No matching privacy rule found for {tokens[2]}."
    if len(tokens) == 5 and tokens[1].lower() == "move" and tokens[3].lower() in {"before", "after"}:
        rules = _persistent_privacy_rules()
        moving = next((rule for rule in rules if rule.get("id") == tokens[2] and _rule_delete_owner_allowed(owner_hash, rule)), None)
        target = next((rule for rule in rules if rule.get("id") == tokens[4] and _rule_delete_owner_allowed(owner_hash, rule)), None)
        if moving is None or target is None:
            return "No matching privacy rule found for move."
        rules = [rule for rule in rules if rule.get("id") != tokens[2]]
        target_index = next((idx for idx, rule in enumerate(rules) if rule.get("id") == tokens[4]), len(rules))
        insert_at = target_index if tokens[3].lower() == "before" else target_index + 1
        rules.insert(insert_at, moving)
        if not _save_persistent_privacy_rules(rules):
            return "Failed to save privacy rule order."
        return f"Moved privacy rule {tokens[2]} {tokens[3].lower()} {tokens[4]}."
    return (
        f"{_rule_add_usage()} | "
        "/guardian rule delete <rule_id> | /guardian rule enable|disable <rule_id> | "
        "/guardian rule move <rule_id> before|after <other_rule_id>"
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
        rules = _privacy_rules_for_owner(owner_hash)
    lines = [
        "Hermes Guardian status",
        f"Privacy mode: {_privacy_policy()}",
        f"Taint classes: {', '.join(taint) if taint else 'none'}",
        f"Pending approvals: {len(pending)}",
        f"Privacy rules: {len(rules)}",
    ]
    for approval in pending[:10]:
        classes = ",".join(approval.get("data_classes") or [])
        lines.append(
            f"- {approval['id']}: {approval['action_family']} -> {approval['destination']} ({classes})"
        )
    return "\n".join(lines)


def _guardian_rules(owner_hash: str) -> str:
    rules = _privacy_rules_for_owner(owner_hash)
    if not rules:
        return "No persistent Guardian privacy rules."
    lines = [f"🛡️ **Guardian privacy rules** · mode `{_privacy_policy()}` · {len(rules)} shown"]
    for rule in rules:
        match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
        effect = str(rule.get("effect") or "allow").strip().lower()
        action = _rule_match_text(match.get("action_family"), "Any action")
        destination = _rule_match_text(match.get("destination"), "Any destination")
        tool = _rule_match_text(match.get("tool_name"), "")
        disabled = not bool(rule.get("enabled", True))
        icon = "⏸️" if disabled else ("⛔" if effect == "deny" else "✅")
        label = effect.upper() if effect else "RULE"
        if disabled:
            label = f"{label} (disabled)"
        metadata = f"`{rule.get('id', '')}`"
        remaining = _rule_remaining_text(rule)
        if remaining:
            metadata += f" · {remaining}"
        lines.extend([
            "",
            f"{icon} **{label}** `{action} -> {destination}`",
            metadata,
            f"Scope: {_rule_scope_text(rule)}",
        ])
        if tool:
            lines.append(f"Tool: `{tool}`")
        lines.append(_rule_classes_line(match.get("data_classes") or []))
    return "\n".join(lines)


def _rule_match_text(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    if not text or text == "*":
        return fallback
    return _clip_text(text, 96, ellipsis="...", fallback=fallback)


def _rule_scope_text(rule: dict[str, Any]) -> str:
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    cron_job_id = str(scope.get("cron_job_id") or rule.get("cron_job_id") or "").strip()
    if cron_job_id:
        cron_job_name = str(scope.get("cron_job_name") or rule.get("cron_job_name") or "").strip()
        try:
            cron_job_name = cron_job_name or _cron_job_name(cron_job_id)
        except Exception:
            pass
        return f"[Cron] {cron_job_name or cron_job_id}"
    if str(scope.get("session_id") or rule.get("session_id") or "").strip():
        return "Session scoped"
    owner_hash = str(scope.get("owner_hash") or rule.get("owner_hash") or "*").strip()
    label = _rule_scope_label(rule).lower()
    if owner_hash == "*" or label in {"all owners", "global"}:
        return "Runs everywhere"
    if label == "session":
        return "Session scoped"
    return "Owner scoped"


def _rule_remaining_text(rule: dict[str, Any]) -> str:
    try:
        remaining = int(rule.get("remaining_invocations", -1))
    except (TypeError, ValueError):
        return ""
    if remaining < 0:
        return ""
    return "1 invocation left" if remaining == 1 else f"{remaining} invocations left"


def _rule_classes_line(classes: list[Any]) -> str:
    safe_classes = sorted(str(cls).strip() for cls in classes if str(cls).strip())
    if not safe_classes:
        return "🏷️ No data classes"
    if "*" in safe_classes:
        return "🏷️ `all data classes`"
    return f"🏷️ `{','.join(safe_classes)}`"


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
        return f"Revoked privacy rule {rule_id}."
    return message


def _guardian_delete_rule(owner_hash: str, rule_id: str) -> str:
    ok, message, _removed = _delete_persistent_rule(owner_hash, rule_id)
    return message


def _guardian_dismiss(owner_hash: str, approval_id: str) -> str:
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
        reason=approval.get("reason") or "requires approval",
        approval_id=approval_id,
        action_detail=approval.get("action_detail", ""),
    )
    return f"Dismissed guardian approval {approval_id}."


def _guardian_deny(owner_hash: str, approval_id: str) -> str:
    return _guardian_dismiss(owner_hash, approval_id)


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
            rule["remaining_invocations"] = 1
            rule["id"] = f"rule_{secrets.token_hex(4)}"
            rules = _persistent_privacy_rules()
            rules.append(rule)
            if not _save_persistent_privacy_rules(rules):
                _PENDING_APPROVALS[approval_id] = approval
                _save_pending_approval_to_store_unlocked(approval)
                return "Failed to save one-time privacy approval; Hermes Guardian remains blocked."
        elif scope == "session":
            _SESSION_APPROVALS.setdefault(sid, []).append(rule)
        else:
            persistent_rule = rule
            rules = _persistent_privacy_rules()
            rules.append(persistent_rule)
            if not _save_persistent_privacy_rules(rules):
                _PENDING_APPROVALS[approval_id] = approval
                _save_pending_approval_to_store_unlocked(approval)
                return "Failed to save persistent privacy approval; Hermes Guardian remains blocked."
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
        rule_id=rule.get("id", ""),
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
