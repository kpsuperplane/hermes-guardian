"""Slash-command handlers for Guardian status, approvals, rules, and history."""

from __future__ import annotations

import re
from typing import Any


import shlex
import secrets

from . import dashboard as dashboard_mod
from .. import core
from .. import state
from ..integrations import cron_notifications
from ..privacy import approvals
from ..privacy import destinations
from ..privacy import llm
from ..privacy import rules as rules_mod
from ..privacy import tool_policy
from ..runtime import activity_rows
from ..runtime import activity_store

_FAILURE_HISTORY_DECISIONS = ("blocked", "denied", "security_blocked")

# Grouped help (doc 03 §4): the five concepts in `decide` order, with the
# everyday `status`/`why` on top. Reading this help IS the mental model — it
# mirrors the dashboard tab bar and the config file shape.
_GUARDIAN_HELP_LINES = [
    "/guardian — privacy firewall for your agent",
    "",
    "- `/guardian status` — what's happening right now",
    "- `/guardian why <id>` — explain a specific decision",
    "",
    "ACTIVITY — what happened, and what needs you",
    "- `/guardian activity [limit]` — recent decided actions",
    "- `/guardian approvals` — list pending approvals",
    "- `/guardian approve <id>` — show the ways to permit a pending item",
    "- `/guardian approve <id> 5m|forever` — allow this action shape briefly / permanently",
    "- `/guardian approve <id> mine|trust` — it's yours / you trust it (admin; if the action supports it)",
    "- `/guardian deny <id>` — deny a pending item (alias: dismiss)",
    "- `/guardian clear-taint` — clear session taint",
    "",
    "WHAT'S YOURS — where you end and the world begins",
    "- `/guardian mine` — show self stores/identities/hosts",
    "- `/guardian mine add|remove destination|identity|host <value>`",
    "- `/guardian check <destination|recipient>` — resolve trust preview",
    "",
    "SHARING — what you've authorized to leave you",
    "- `/guardian sharing` — show trusted destinations + rules + outward-sharing",
    "- `/guardian sharing destination add|remove <identity> [classes=<class+class>]`",
    "- `/guardian sharing destination suggest | trust <n>` — pick a trusted command",
    "- `/guardian sharing rule add|delete|enable|disable|move ...`",
    "- `/guardian sharing outward add|remove <subtype>`",
    "- `/guardian sharing preview <action> <destination> <class>` — which step fires",
    "",
    "REVIEW — who judges everything else",
    "- `/guardian review` — show mode, contexts, verifier model",
    "- `/guardian review mode strict|read-only|llm|off`",
    "- `/guardian review owner-context on|off`",
    "- `/guardian review cron-context on|off`",
    "- `/guardian review verifier-model <model_id|default>`",
    "",
    "PROTECTION — the floor that always holds",
    "- `/guardian protection` — show security, tool overrides, language packs",
    "- `/guardian protection security enable|disable <rule_id>`",
    "- `/guardian protection tool set|delete|enable|disable ...`",
    "- `/guardian protection source suggest|set <server> reference|private`",
    "- `/guardian protection unknown-tools gate|allow`",
    "- `/guardian protection persist-prompts on|off`",
    "- `/guardian protection language-packs enable|disable <pack_id>`",
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
    "purpose",
    "recipient",
    "recipient_identity",
    "owner",
    "owner_hash",
    "cron",
    "cron_job_id",
    "cron_name",
    "cron_job_name",
    "expires",
    "expires_at",
    "duration",
    "ttl",
}

_TOOL_SET_KEYS = {
    "taints",
    "taint",
    "egress",
    "direction",
    "source",
    "destination",
    "dest",
    "note",
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
    "purpose",
    "recipient",
    "recipient_identity",
}


def _guardian_help_text() -> str:
    return "\n".join(_GUARDIAN_HELP_LINES)


def _slash_admin_allowed(owner_hash: str) -> bool:
    return owner_hash == core._CLI_OWNER_HASH or owner_hash in approvals._configured_owner_hashes()


def _global_mutation_denied_message() -> str:
    return "Permission denied: only the CLI or configured Guardian owners can change global Guardian configuration."


def _guardian_dashboard_command(tokens: list[str]) -> str:
    action = tokens[1].lower() if len(tokens) > 1 else "status"
    if action == "prune":
        result = activity_store._prune_activity_db(force=True)
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
    limit = 5
    if len(tokens) > 1:
        try:
            limit = int(tokens[1])
        except ValueError:
            command = tokens[0].lower() if tokens else "history"
            return f"Usage: /guardian {command} [limit]"
    limit = max(1, min(limit, 25))  # number of TURNS to show
    rows = activity_rows._activity_rows(filters or {}, limit=1000)
    if not rows:
        return empty_message

    # Group rows into turns (one user prompt + its checks). Legacy rows (turn_id='')
    # are each their own single-check turn. Order follows recency (rows are ts DESC).
    order: list[str] = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        turn_id = str(row.get("turn_id") or "")
        key = turn_id if turn_id else f"row_{row.get('id')}"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(row)
    turn_keys = order[:limit]

    _MAX_CHECKS_PER_TURN = 20
    lines = [f"🛡️ **{title}** — newest first — {len(turn_keys)} turn{'s' if len(turn_keys) != 1 else ''}"]
    for key in turn_keys:
        turn_rows = groups[key]
        n = len(turn_rows)
        prompt = ""
        for candidate in turn_rows:
            text_value = _compact_prompt_text(candidate.get("user_prompt"))
            if text_value:
                prompt = text_value
                break
        is_cron = any(str(r.get("session_label") or "").startswith("cron_") for r in turn_rows)
        label = "⏲️" if is_cron else "👤"
        header_parts = [label]
        if prompt:
            header_parts.append(dashboard_mod._clip_text(prompt, 120, ellipsis="...", fallback=""))
        if n > 1:
            header_parts.append(f"{n} checks")
        header = " · ".join(part for part in header_parts if part) if (is_cron or prompt or n > 1) else label
        lines.append(f"- **{header}**")
        for check in turn_rows[:_MAX_CHECKS_PER_TURN]:
            decision = str(check.get("decision") or "").strip()
            icon = dashboard_mod._activity_status_icon(decision)
            # 🤖 suffix when the LLM verifier was involved (auto-approval, or a verdict
            # whose reason names the verifier).
            if decision == "auto_approved" or "llm" in str(check.get("reason") or "").lower():
                icon = icon + "🤖"
            tool = dashboard_mod._clip_text(dashboard_mod._activity_display_tool(check), 48, ellipsis="...", fallback="n/a")
            classes = _compact_activity_classes(check)
            latency_label = _latency_label(check.get("latency_ms"))
            check_parts = [f"  - {icon} {_history_code(tool, fallback='n/a')}"]
            if classes:
                check_parts.append(_history_code(classes))
            if latency_label:
                check_parts.append(latency_label)
            lines.append(" · ".join(check_parts))
            reason_text = _compact_activity_reason_line(check)
            if reason_text:
                lines.append(f"    - {reason_text}")
        if n > _MAX_CHECKS_PER_TURN:
            lines.append(f"  - +{n - _MAX_CHECKS_PER_TURN} more checks")
    return "\n".join(lines)


def _latency_label(milliseconds: Any) -> str:
    try:
        value = float(milliseconds or 0)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    if value < 1:
        return "<1 ms"
    if value < 1000:
        return f"{round(value)} ms"
    if value < 10000:
        return f"{value / 1000:.1f} s"
    return f"{round(value / 1000)} s"


def _compact_prompt_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _compact_activity_classes(row: dict[str, Any]) -> str:
    classes = [
        cls.strip()
        for cls in str(row.get("data_classes") or "").split(",")
        if cls.strip() and cls.strip().lower() not in {"none", "n/a"}
    ]
    if not classes:
        return ""
    return dashboard_mod._clip_text(", ".join(classes), 80, ellipsis="...", fallback="")


def _compact_activity_status(decision: str) -> str:
    text = str(decision or "").strip().lower().replace("_", " ")
    if text in {"security blocked", "security suppressed"}:
        return "security"
    if text in {"mode off allowed", "privacy off allowed"}:
        return "allowed"
    if text in {"auto approved", "manual approved"}:
        return "approved"
    if text == "denied":
        return "dismissed"
    return text


def _compact_activity_reason_line(row: dict[str, Any]) -> str:
    decision = str(row.get("decision") or "").strip()
    if decision == "tainted":
        return ""
    reason = dashboard_mod._clip_text(dashboard_mod._activity_display_reason(row), 90, ellipsis="...", fallback="")
    if not reason:
        return ""
    marker = dashboard_mod._clip_text(activity_rows._activity_marker(row), 40, ellipsis="...", fallback="")
    suffix = f" ({marker})" if marker else ""
    status = _compact_activity_status(decision)
    return f"{status} · {reason}{suffix}" if status else f"{reason}{suffix}"


def _history_code(value: Any, *, fallback: str = "") -> str:
    text = str(value or "").strip() or fallback
    return "`" + text.replace("`", "'") + "`"


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
    purpose = tool_policy._normalize_rule_purpose(params.get("purpose", "unknown"), allow_star=False)
    recipient_identity = tool_policy._normalize_rule_recipient_identity(
        params.get("recipient_identity", params.get("recipient", "none")),
        allow_star=False,
    )
    tool_name = (params.get("tool") or params.get("tool_name") or "").strip()
    raw_classes = params.get("classes") or params.get("data_classes") or params.get("class") or ""
    classes = sorted({
        cls.strip()
        for cls in re.split(r"[,+]", raw_classes)
        if cls.strip() in core._ALL_PRIVACY_CLASSES
    })
    # Preview how a recipient/destination resolves to a trust level (doc 03 §2.2). For a
    # messaging destination the recipient drives trust; otherwise the destination token.
    raw_recipient = (params.get("recipient") or params.get("recipient_identity") or "").strip()
    # A templated/placeholder recipient (e.g. "{{recipient}}", "<to>", "${addr}") is
    # unresolvable — never guess it is self (doc 01 §3.2). Treat it as empty so the
    # resolver returns unknown.
    if re.search(r"\{\{.*\}\}|\$\{.*\}|<[^>]+>", raw_recipient):
        raw_recipient = ""
    is_messaging = action_family in {"message_send", "message_list"} or any(
        verb in action_family for verb in ("message", "send")
    )
    if is_messaging:
        trust = destinations.resolve_destination_trust("messaging", "messaging", "send", raw_recipient)
    else:
        dest_token = destination.split(":", 1)[1] if destination.startswith("mcp:") else destination
        dest_kind = destination.split(":", 1)[0] if ":" in destination else (destination or "store")
        trust = destinations.resolve_destination_trust(dest_kind, dest_token, "write", raw_recipient)
    destination_trust = _trust_label_for_debug(trust)
    shape = {
        "session_id": core._GLOBAL_SESSION_ID,
        "owner_hash": core._CLI_OWNER_HASH,
        "tool_name": tool_name,
        "action_family": action_family,
        "destination": destination,
        "purpose": purpose,
        "recipient_identity": recipient_identity,
        "data_classes": classes,
        "fingerprint": "debug",
    }
    privacy_policy = core._privacy_policy()
    if privacy_policy == "off":
        return {
            "decision": "allowed",
            "privacy_policy": privacy_policy,
            "source": {"source": "privacy_off", "rule_id": ""},
            "action_family": action_family,
            "destination": destination,
            "destination_trust": destination_trust,
            "purpose": purpose,
            "recipient_identity": recipient_identity,
            "data_classes": classes,
            "tool_name": tool_name,
            "reason": "privacy policy is off",
        }
    source = rules_mod._approval_source(shape)
    if source:
        denied = source.get("effect") == "deny"
        return {
            "decision": "blocked" if denied else "allowed",
            "privacy_policy": privacy_policy,
            "source": source,
            "action_family": action_family,
            "destination": destination,
            "destination_trust": destination_trust,
            "purpose": purpose,
            "recipient_identity": recipient_identity,
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
        "destination_trust": destination_trust,
        "purpose": purpose,
        "recipient_identity": recipient_identity,
        "data_classes": classes,
        "tool_name": tool_name,
        "reason": "no matching allow rule; would require approval if session is tainted",
    }


def _trust_label_for_debug(trust: Any) -> str:
    value = getattr(trust, "value", None)
    return str(value if value is not None else (trust or "unknown"))


def _guardian_debug_command(tokens: list[str]) -> str:
    params, errors = _parse_key_value_args(tokens[1:], allowed_keys=_DEBUG_KEYS)
    if errors:
        return "Invalid debug arguments: " + "; ".join(errors)
    if not params:
        return (
            "Usage: `/guardian debug action=<family> destination=<dest> "
            "classes=<class+class> [tool=<tool_name>] [recipient=<id>]`\n"
            "Example: `/guardian debug action=mcp_write destination=mcp:notion classes=communications`"
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
        f"Destination trust: {result.get('destination_trust') or 'unknown'}\n"
        f"Purpose: {result.get('purpose') or 'unknown'}\n"
        f"Recipient identity: {result.get('recipient_identity') or 'none'}\n"
        f"Data classes: {classes}\n"
        f"Reason: {result['reason']}"
        f"{source_text}"
    )


def _telegram_rich_slash_supported() -> bool:
    try:
        from gateway.platforms.telegram import TelegramAdapter
    except Exception:
        return False
    required = (
        "_try_send_rich",
        "_rich_message_payload",
        "_should_attempt_rich",
        "_bot_supports_rich",
    )
    return all(callable(getattr(TelegramAdapter, name, None)) for name in required)


def _telegram_command_enabled(command_context: dict[str, str]) -> bool:
    return (
        str(command_context.get("platform") or "").strip().lower() == "telegram"
        and _telegram_rich_slash_supported()
    )


def _md_inline(value: Any, *, fallback: str = "") -> str:
    text = str(value or "").strip() or fallback
    return text.replace("\n", " ").replace("|", "\\|")


def _md_code(value: Any, *, fallback: str = "") -> str:
    text = _md_inline(value, fallback=fallback).replace("`", "'")
    return f"`{text}`"


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return ""
    safe_headers = [_md_inline(header) for header in headers]
    lines = [
        "| " + " | ".join(safe_headers) + " |",
        "| " + " | ".join("---" for _ in safe_headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_md_inline(cell, fallback="n/a") for cell in row) + " |")
    return "\n".join(lines)


def _md_details(summary: str, body_lines: list[str]) -> str:
    body = "\n".join(line for line in body_lines if str(line).strip())
    if not body:
        return ""
    return f"<details>\n<summary>{_md_inline(summary)}</summary>\n\n{body}\n</details>"


def _pending_for_owner(owner_hash: str) -> list[dict[str, Any]]:
    with state._LOCK:
        approvals._load_pending_approvals_from_store_unlocked()
        return [
            dict(approval)
            for approval in state._PENDING_APPROVALS.values()
            if approval.get("owner_hash") == owner_hash or owner_hash == core._CLI_OWNER_HASH
        ]


def _status_snapshot(owner_hash: str) -> dict[str, Any]:
    with state._LOCK:
        llm._prune_expired()
        session_ids = approvals._owner_session_ids(owner_hash)
        taint = sorted({cls for sid in session_ids for cls in state._SESSIONS.get(sid, {}).get("taint", set())})
        pending = [
            approval
            for approval in state._PENDING_APPROVALS.values()
            if approval.get("owner_hash") == owner_hash or owner_hash == core._CLI_OWNER_HASH
        ]
        rules = rules_mod._privacy_rules_for_owner(owner_hash)
        disabled_security = [
            rule
            for rule in rules_mod._security_rules_snapshot()
            if not bool(rule.get("enabled"))
        ]
        enabled_language_packs = [
            pack
            for pack in rules_mod._language_packs_snapshot()
            if bool(pack.get("enabled"))
        ]
    return {
        "taint": taint,
        "pending": pending,
        "rules": rules,
        "disabled_security": disabled_security,
        "enabled_language_packs": enabled_language_packs,
        "risk_banners": activity_rows._runtime_risk_banners(),
        "trust_summary": activity_rows._destination_trust_summary(),
    }


def _guardian_status_telegram(owner_hash: str) -> str:
    snapshot = _status_snapshot(owner_hash)
    trust_summary = snapshot["trust_summary"]
    self_block = trust_summary.get("self") or {}
    tally = trust_summary.get("tally") or {}
    tally_text = ", ".join(f"{label}={count}" for label, count in sorted(tally.items())) if tally else "none observed yet"
    enabled_packs = ", ".join(pack.get("id", "") for pack in snapshot["enabled_language_packs"]) or "none"
    rows = [
        ["Privacy mode", core._privacy_policy()],
        ["Unknown tools", f"{rules_mod._unknown_tools_mode()} ({len(rules_mod._tool_overrides())} override(s))"],
        ["LLM context", f"user-prompt {'on' if rules_mod._llm_user_context_enabled() else 'off'}, cron {'on' if rules_mod._llm_cron_context_enabled() else 'off'}"],
        ["Security rules", f"{len(rules_mod._SECURITY_RULE_IDS) - len(snapshot['disabled_security'])} enabled, {len(snapshot['disabled_security'])} disabled"],
        ["Language packs", enabled_packs],
        ["Taint classes", ", ".join(snapshot["taint"]) if snapshot["taint"] else "none"],
        ["Pending approvals", str(len(snapshot["pending"]))],
        ["Privacy rules", str(len(snapshot["rules"]))],
    ]
    lines = [
        "## Hermes Guardian Status",
        "",
        _md_table(["Signal", "Value"], rows),
        "",
        "### Destination Trust",
        _md_table(
            ["Bucket", "Count"],
            [
                ["Self destinations", len(self_block.get("destinations") or [])],
                ["Self identities", len(self_block.get("identities") or [])],
                ["Self hosts", len(self_block.get("hosts") or [])],
                ["Trusted recipients", len(trust_summary.get("trusted_recipients") or [])],
                ["Outward-sharing", f"{len((trust_summary.get('outward_sharing') or {}).get('builtin') or [])} builtin + {len((trust_summary.get('outward_sharing') or {}).get('extra') or [])} extra"],
                ["Seen by trust", tally_text],
            ],
        ),
    ]
    pending = snapshot["pending"][:10]
    if pending:
        lines.extend([
            "",
            "### Pending Approvals",
            _md_table(
                ["ID", "Action", "Destination", "Classes"],
                [
                    [
                        approval.get("id", ""),
                        approval.get("action_family", ""),
                        approval.get("destination", ""),
                        ",".join(approval.get("data_classes") or []) or "none",
                    ]
                    for approval in pending
                ],
            ),
        ])
    risk_lines = [str(banner.get("message", "")).strip() for banner in snapshot["risk_banners"] if banner.get("message")]
    if risk_lines:
        lines.extend(["", _md_details("Risk banners", [f"- {line}" for line in risk_lines])])
    return "\n".join(line for line in lines if line != "")


def _guardian_approvals_command_telegram(owner_hash: str) -> str:
    pending = _pending_for_owner(owner_hash)
    if not pending:
        return "No pending Guardian approvals."
    return "\n\n".join([
        f"## Pending Guardian Approvals\n{len(pending)} shown",
        _md_table(
            ["ID", "Action", "Destination", "Trust", "Classes"],
            [
                [
                    approval.get("id", ""),
                    approval.get("action_family", ""),
                    approval.get("destination", ""),
                    approval.get("destination_trust", "unknown"),
                    ",".join(approval.get("data_classes") or []) or "none",
                ]
                for approval in pending
            ],
        ),
        "Run `/guardian approve <id>` to see permit options, or `/guardian deny <id>`.",
    ])


def _guardian_permit_menu_telegram(owner_hash: str, approval_id: str) -> str:
    resolved_id, approval, error = _resolve_owned_approval(owner_hash, approval_id)
    if error:
        return error
    sections: list[str] = [
        f"## Permit Approval {resolved_id}",
        _md_table(
            ["Field", "Value"],
            [
                ["Action", approval.get("action_family", "")],
                ["Destination", approval.get("destination", "")],
                ["Trust", approval.get("destination_trust", "unknown")],
                ["Classes", ", ".join(approval.get("data_classes") or []) or "none"],
            ],
        ),
    ]
    groups: dict[str, list[list[str]]] = {}
    for option in approvals._approval_permit_options(approval):
        command = approvals._permit_command_line(resolved_id, option["method"])
        groups.setdefault(str(option.get("group") or "Approval options"), []).append([
            _md_code(command),
            option.get("label", ""),
            "yes" if option.get("structural") else "no",
        ])
    for group, rows in groups.items():
        sections.extend(["", f"### {group}", _md_table(["Command", "Scope", "Admin"], rows)])
    details = [
        f"- Dismiss: `/guardian dismiss {resolved_id}`",
        "- Temporary permits are shape-scoped.",
        "- Trust-boundary changes are admin-only and update Guardian policy.",
    ]
    sections.extend(["", _md_details("What this allows", details)])
    return "\n".join(section for section in sections if section != "")


def _guardian_activity_command_telegram(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if sub == "approvals":
        return _guardian_approvals_command_telegram(owner_hash)
    if sub == "approve" and len(tokens) >= 3 and len(tokens) == 3:
        return _guardian_permit_menu_telegram(owner_hash, tokens[2])
    if sub in {"failures", "failed"}:
        return _guardian_history_command_telegram(
            ["activity failures", *tokens[2:]],
            filters={"decisions": ",".join(_FAILURE_HISTORY_DECISIONS)},
            title="Guardian Failures",
            empty_message="No guardian failure history yet.",
        )
    if sub in {"deny", "dismiss", "clear-taint"} or (sub == "approve" and len(tokens) >= 4):
        return _guardian_activity_command(owner_hash, tokens)
    return _guardian_history_command_telegram(
        ["activity", *tokens[1:]],
        title="Guardian Activity",
        empty_message="No guardian activity history yet.",
    )


def _guardian_history_command_telegram(
    tokens: list[str],
    *,
    filters: dict[str, str] | None = None,
    title: str = "Guardian Activity",
    empty_message: str = "No guardian activity history yet.",
) -> str:
    limit = 5
    if len(tokens) > 1:
        try:
            limit = int(tokens[1])
        except ValueError:
            command = tokens[0].lower() if tokens else "history"
            return f"Usage: /guardian {command} [limit]"
    limit = max(1, min(limit, 25))
    rows = activity_rows._activity_rows(filters or {}, limit=1000)
    if not rows:
        return empty_message

    order: list[str] = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        turn_id = str(row.get("turn_id") or "")
        key = turn_id if turn_id else f"row_{row.get('id')}"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(row)
    turn_keys = order[:limit]

    lines = [f"## {title}", f"Newest first · {len(turn_keys)} turn{'s' if len(turn_keys) != 1 else ''}"]
    max_checks = 20
    for key in turn_keys:
        turn_rows = groups[key]
        prompt = ""
        for candidate in turn_rows:
            text_value = _compact_prompt_text(candidate.get("user_prompt"))
            if text_value:
                prompt = dashboard_mod._clip_text(text_value, 120, ellipsis="...", fallback="")
                break
        is_cron = any(str(r.get("session_label") or "").startswith("cron_") for r in turn_rows)
        heading = "Cron turn" if is_cron else "User turn"
        if prompt:
            heading += f": {prompt}"
        if len(turn_rows) > 1:
            heading += f" · {len(turn_rows)} checks"
        lines.extend(["", f"### {heading}"])
        check_rows: list[list[str]] = []
        reason_lines: list[str] = []
        for check in turn_rows[:max_checks]:
            decision = str(check.get("decision") or "").strip()
            tool = dashboard_mod._clip_text(dashboard_mod._activity_display_tool(check), 48, ellipsis="...", fallback="n/a")
            classes = _compact_activity_classes(check) or "none"
            latency_label = _latency_label(check.get("latency_ms"))
            reason_text = _compact_activity_reason_line(check)
            llm_mark = "yes" if decision == "auto_approved" or "llm" in str(check.get("reason") or "").lower() else "no"
            check_rows.append([
                tool,
                decision or "unknown",
                classes,
                llm_mark,
                latency_label or "n/a",
            ])
            if reason_text:
                reason_lines.append(f"- **{_md_inline(tool)}**: {_md_inline(reason_text)}")
        lines.append(_md_table(["Tool", "Decision", "Classes", "LLM", "Time"], check_rows))
        if reason_lines:
            lines.append("")
            lines.append(_md_details("Decision reasons", reason_lines))
        if len(turn_rows) > max_checks:
            lines.append(f"- +{len(turn_rows) - max_checks} more checks")
    return "\n".join(lines)


def _guardian_why_command_telegram(tokens: list[str]) -> str:
    if len(tokens) != 2:
        return "Usage: /guardian why <activity_id|approval_id>"
    return _guardian_why_telegram(tokens[1])


def _guardian_why_telegram(identifier: str) -> str:
    row = _activity_row_for_why(identifier)
    if row is None:
        return f"No Guardian activity found for {identifier}."
    decision = str(row.get("decision") or "")
    direction = "read" if decision in {"read", "tainted"} else "write"
    classes = activity_rows._activity_data_classes_list(row.get("data_classes"))
    reason = str(row.get("reason") or "").strip()
    lines = [
        f"## Guardian Decision {identifier}",
        _md_table(
            ["Field", "Value"],
            [
                ["Outcome", decision or "unknown"],
                ["Direction", direction],
                ["Destination", f"{row.get('destination') or '(none)'} (trust={row.get('destination_trust') or 'unknown'})"],
                ["Classes", ", ".join(classes) if classes else "none"],
                ["Action family", row.get("action_family") or "(none)"],
                ["Purpose", row.get("purpose") or "unknown"],
                ["Recipient identity", row.get("recipient_identity") or "none"],
                ["Decide step", row.get("decision_step") or "(pre-migration row; step not recorded)"],
            ],
        ),
    ]
    if reason:
        lines.extend(["", _md_details("Reason", [reason])])
    return "\n".join(lines)


def _guardian_mine_telegram(owner_hash: str) -> str:
    snapshot = rules_mod._self_config_snapshot()
    trusted = rules_mod._trusted_recipients_snapshot()
    lines = [
        "## What's Yours",
        _md_table(
            ["Boundary", "Values"],
            [
                ["Destinations", ", ".join(snapshot["destinations"]) or "none"],
                ["Identities", ", ".join(snapshot["identities"]) or "none"],
                ["Hosts", ", ".join(snapshot["hosts"]) or "none"],
                ["Trusted recipients", str(len(trusted))],
            ],
        ),
        "",
        "`/guardian mine add|remove destination|identity|host <value>`",
    ]
    return "\n".join(lines)


def _guardian_review_telegram(owner_hash: str) -> str:
    return "\n\n".join([
        "## Review",
        _md_table(
            ["Setting", "Value"],
            [
                ["Privacy mode", core._privacy_policy()],
                ["Unknown-tools mode", rules_mod._unknown_tools_mode()],
                ["LLM user-prompt context", "on" if rules_mod._llm_user_context_enabled() else "off"],
                ["LLM cron context", "on" if rules_mod._llm_cron_context_enabled() else "off"],
                ["LLM verifier model", rules_mod._llm_verifier_model() or "default"],
            ],
        ),
        "`/guardian review mode strict|read-only|llm|off`\n`/guardian review owner-context on|off`\n`/guardian review cron-context on|off`\n`/guardian review verifier-model <model_id|default>`",
    ])


def _guardian_sharing_group_command_telegram(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if sub:
        return ""
    trusted = rules_mod._trusted_recipients_snapshot()
    rules = rules_mod._privacy_rules_for_owner(owner_hash)
    outward = rules_mod._outward_sharing_snapshot()
    trusted_rows = [
        [
            entry.get("kind", "identity"),
            entry.get("value") or entry.get("identity") or "",
            ",".join(entry.get("classes") or []) or "none",
            entry.get("note", ""),
        ]
        for entry in trusted
    ]
    rule_rows = []
    for rule in rules[:15]:
        match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
        rule_rows.append([
            rule.get("id", ""),
            rule.get("effect", "allow"),
            match.get("action_family", "*"),
            match.get("destination", "*"),
            ",".join(match.get("data_classes") or []) or "*",
        ])
    lines = ["## Sharing"]
    lines.extend(["", "### Trusted Destinations", _md_table(["Kind", "Value", "Classes", "Note"], trusted_rows) if trusted_rows else "No trusted destinations configured."])
    lines.extend(["", "### Privacy Rules", _md_table(["ID", "Effect", "Action", "Destination", "Classes"], rule_rows) if rule_rows else "No persistent Guardian privacy rules."])
    lines.extend([
        "",
        "### Outward Sharing",
        _md_table(
            ["Type", "Count"],
            [["Builtin subtypes", len(outward["builtin"])], ["Extra subtypes", len(outward["extra"])]],
        ),
    ])
    return "\n".join(lines)


def _guardian_protection_command_telegram(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if sub:
        return ""
    security_rows = [
        [rule["id"], "enabled" if rule.get("enabled") else "disabled", rule.get("label", "")]
        for rule in rules_mod._security_rules_snapshot()
    ]
    overrides = rules_mod._tool_overrides_snapshot()
    override_rows = [
        [
            override.get("id", ""),
            override.get("match", ""),
            "enabled" if override.get("enabled") else "disabled",
            override.get("egress") or override.get("direction") or "",
            ",".join(override.get("taints") or []) or "none",
        ]
        for override in overrides
    ]
    pack_rows = [
        [pack["id"], "enabled" if pack.get("enabled") else "disabled", "yes" if pack.get("required") else "no", pack.get("name", "")]
        for pack in rules_mod._language_packs_snapshot()
    ]
    persist = "on" if rules_mod._persist_prompts_enabled() else "off"
    return "\n\n".join([
        "## Protection",
        "### Security Rules\n" + _md_table(["ID", "State", "Label"], security_rows),
        "### Tool Overrides\n" + (_md_table(["ID", "Match", "State", "Egress/Direction", "Taints"], override_rows) if override_rows else "No tool overrides configured."),
        f"### Runtime\nPrompt persistence: `{persist}`",
        "### Language Packs\n" + _md_table(["ID", "State", "Required", "Name"], pack_rows),
    ])


def _handle_guardian_command(raw_args: str = "") -> str:
    command_context = approvals._pop_command_context(raw_args)
    owner_hash = command_context.get("owner_hash") or approvals._UNAUTHENTICATED_OWNER_HASH
    try:
        tokens = shlex.split(raw_args.strip())
    except ValueError as exc:
        return f"Invalid /guardian command syntax: {exc}"
    if not tokens or tokens[0].lower() in {"help", "-h", "--help"}:
        return _guardian_help_text()

    command = tokens[0].lower()

    # --- Everyday commands (always on top of help). -----------------------------
    if command == "status":
        if _telegram_command_enabled(command_context):
            return _guardian_status_telegram(owner_hash)
        return _guardian_status(owner_hash)
    if command == "why":
        if _telegram_command_enabled(command_context):
            return _guardian_why_command_telegram(tokens)
        return _guardian_why_command(tokens)

    # --- The five group verbs (doc 03 §2), in `decide` order. -------------------
    if command == "activity":
        if _telegram_command_enabled(command_context):
            return _guardian_activity_command_telegram(owner_hash, tokens)
        return _guardian_activity_command(owner_hash, tokens)
    if command == "mine":
        if _telegram_command_enabled(command_context) and len(tokens) == 1:
            return _guardian_mine_telegram(owner_hash)
        return _guardian_mine_command(owner_hash, tokens)
    if command == "sharing":
        if _telegram_command_enabled(command_context):
            rich = _guardian_sharing_group_command_telegram(owner_hash, tokens)
            if rich:
                return rich
        return _guardian_sharing_group_command(owner_hash, tokens)
    if command == "review":
        if _telegram_command_enabled(command_context) and len(tokens) == 1:
            return _guardian_review_telegram(owner_hash)
        return _guardian_review_command(owner_hash, tokens)
    if command == "protection":
        if _telegram_command_enabled(command_context):
            rich = _guardian_protection_command_telegram(owner_hash, tokens)
            if rich:
                return rich
        return _guardian_protection_command(owner_hash, tokens)

    # --- Activity verbs that read best as their own top-level words. ------------
    if command == "check":
        return _guardian_check_command(tokens)
    if command == "approvals":
        if _telegram_command_enabled(command_context):
            return _guardian_approvals_command_telegram(owner_hash)
        return _guardian_approvals_command(owner_hash)
    if command == "clear-taint":
        return _guardian_clear_taint(owner_hash)
    if command == "approve" and len(tokens) >= 2:
        keyword = tokens[2].lower() if len(tokens) >= 3 else ""
        if _telegram_command_enabled(command_context) and not keyword:
            return _guardian_permit_menu_telegram(owner_hash, tokens[1])
        return _guardian_approve(owner_hash, tokens[1], keyword)
    if command in {"deny", "dismiss"} and len(tokens) == 2:
        return _guardian_dismiss(owner_hash, tokens[1])
    return "Invalid /guardian command. Try /guardian help."


# --- Group dispatchers (doc 03 §2/§3): rename + regroup only. ------------------
# Each group verb parses its second token and delegates to the SAME underlying
# handler functions the old top-level commands used. No handler logic is
# duplicated here — this is purely renaming and grouping.


def _guardian_activity_command(owner_hash: str, tokens: list[str]) -> str:
    """ACTIVITY group: recent decided actions + approvals + clear-taint.

    `/guardian activity [limit]` wraps the existing activity listing
    (`_guardian_history_command`); the verb form `/guardian activity <verb>`
    delegates to the same approval/clear-taint handlers the top-level words use.
    """
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if sub == "approvals":
        return _guardian_approvals_command(owner_hash)
    if sub == "approve" and len(tokens) >= 3:
        keyword = tokens[3].lower() if len(tokens) >= 4 else ""
        return _guardian_approve(owner_hash, tokens[2], keyword)
    if sub in {"deny", "dismiss"} and len(tokens) == 3:
        return _guardian_dismiss(owner_hash, tokens[2])
    if sub == "clear-taint":
        return _guardian_clear_taint(owner_hash)
    if sub in {"failures", "failed"}:
        return _guardian_history_command(
            ["activity failures", *tokens[2:]],
            filters={"decisions": ",".join(_FAILURE_HISTORY_DECISIONS)},
            title="Guardian failures",
            empty_message="No guardian failure history yet.",
        )
    # `/guardian activity [limit]` -> the recent decided-actions listing.
    return _guardian_history_command(
        ["activity", *tokens[1:]],
        title="Guardian activity",
        empty_message="No guardian activity history yet.",
    )


def _guardian_mine_command(owner_hash: str, tokens: list[str]) -> str:
    """WHAT'S YOURS group: delegates to the current `self` handler."""
    return _guardian_self_command(owner_hash, ["mine", *tokens[1:]])


def _guardian_sharing_group_command(owner_hash: str, tokens: list[str]) -> str:
    """SHARING group: trusted recipients + rules + outward-sharing + preview.

    Delegates to the existing trusted/rule/outward handlers; no logic is copied.
    """
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if sub in {"trusted", "destination", "destinations"}:
        return _guardian_trusted_command(owner_hash, ["trusted", *tokens[2:]])
    if sub in {"rule", "rules"}:
        return _guardian_rule_command(owner_hash, ["rule", *tokens[2:]])
    if sub == "outward":
        return _guardian_sharing_command(owner_hash, ["sharing", *tokens[2:]])
    if sub == "preview":
        return _guardian_sharing_preview_command(tokens[2:])
    if not sub:
        return _guardian_sharing_overview(owner_hash)
    return (
        "Usage: `/guardian sharing` | "
        "`/guardian sharing trusted add|remove <identity> [classes=<class+class>]` | "
        "`/guardian sharing rule add|delete|enable|disable|move ...` | "
        "`/guardian sharing outward add|remove <subtype>` | "
        "`/guardian sharing preview <action> <destination> <class>`"
    )


def _guardian_sharing_overview(owner_hash: str) -> str:
    """The SHARING parent screen: trusted recipients + rules + outward-sharing."""
    return "\n\n".join(
        [
            _guardian_trusted_command(owner_hash, ["trusted"]),
            _guardian_rules(owner_hash),
            _guardian_sharing_command(owner_hash, ["sharing"]),
        ]
    )


def _guardian_review_command(owner_hash: str, tokens: list[str]) -> str:
    """REVIEW group: mode, contexts, verifier model, unknown-tools.

    Maps the new review verbs onto the existing `privacy` handler's subcommands;
    the underlying setters/guards are unchanged.
    """
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if not sub:
        return _guardian_privacy_command(owner_hash, ["privacy"])
    # Rename review verbs to the privacy handler's expected tokens.
    rename = {
        "mode": "mode",
        "owner-context": "user-context",
        "owner_context": "user-context",
        "cron-context": "cron-context",
        "cron_context": "cron-context",
        "verifier-model": "verifier-model",
        "verifier_model": "verifier-model",
    }
    if sub not in rename:
        return (
            "Usage: `/guardian review` | "
            "`/guardian review mode strict|read-only|llm|off` | "
            "`/guardian review owner-context on|off` | "
            "`/guardian review cron-context on|off` | "
            "`/guardian review verifier-model <model_id|default>`"
        )
    return _guardian_privacy_command(owner_hash, ["privacy", rename[sub], *tokens[2:]])


def _guardian_protection_command(owner_hash: str, tokens: list[str]) -> str:
    """PROTECTION group: security rules, tool overrides, language packs.

    Delegates to the existing security/tools/language-packs handlers.
    """
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    if sub == "security":
        return _guardian_security_command(owner_hash, ["security", *tokens[2:]])
    if sub == "tool":
        return _guardian_tool_command(owner_hash, ["tool", *tokens[2:]])
    if sub == "tools":
        return _guardian_tools_command()
    if sub == "source":
        return _guardian_source_command(owner_hash, tokens)
    if sub in {"unknown-tools", "unknown_tools"}:
        return _guardian_privacy_command(owner_hash, ["privacy", "unknown-tools", *tokens[2:]])
    if sub in {"persist-prompts", "persist_prompts"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        enabled = _parse_on_off(tokens[2]) if len(tokens) >= 3 else None
        if enabled is None:
            return "Usage: /guardian protection persist-prompts on|off"
        ok, message = rules_mod._set_persist_prompts(enabled)
        return message
    if sub in {"language-packs", "language-pack", "languages"}:
        return _guardian_language_packs_command(owner_hash, ["language-packs", *tokens[2:]])
    if not sub:
        return _guardian_protection_overview()
    return (
        "Usage: `/guardian protection` | "
        "`/guardian protection security enable|disable <rule_id>` | "
        "`/guardian protection tool set|delete|enable|disable ...` | "
        "`/guardian protection unknown-tools gate|allow` | "
        "`/guardian protection source suggest|set <server> reference|private` | "
        "`/guardian protection persist-prompts on|off` | "
        "`/guardian protection language-packs enable|disable <pack_id>`"
    )


def _guardian_source_command(owner_hash: str, tokens: list[str]) -> str:
    """SOURCE group: classify the doc-read provenance of an MCP server seen by Guardian.

    `suggest` lists servers whose undeclared doc-reads were tainted conservatively; `set`
    declares one as reference material or personal data (a prefix-scoped tool override).
    """
    sub = tokens[2].lower() if len(tokens) > 2 else ""
    usage = (
        "Usage: `/guardian protection source suggest` | "
        "`/guardian protection source set <server> reference|private`"
    )
    if sub == "suggest":
        suggestions = rules_mod._source_classification_suggestions()
        if not suggestions:
            return "No undeclared MCP doc-read sources seen yet."
        lines = ["🛡️ **Sources seen** · `/guardian protection source set <server> reference|private`"]
        for item in suggestions:
            lines.append(f"- `{item['server']}` ({item['hits']}×)")
        return "\n".join(lines)
    if sub == "set" and len(tokens) >= 5:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        server = tokens[3]
        mode = tokens[4].lower()
        ok, message = rules_mod._set_source_classification(server, mode)
        return message
    return usage


def _guardian_protection_overview() -> str:
    """The PROTECTION parent screen: security rules + tool overrides + packs."""
    persist = "on" if rules_mod._persist_prompts_enabled() else "off"
    return "\n\n".join(
        [
            _guardian_security_command("", ["security"]),
            _guardian_tools_command(),
            f"Prompt persistence: {persist} (sanitized user/cron prompt stored on activity rows for debugging)",
            _guardian_language_packs_command("", ["language-packs"]),
        ]
    )


# --- New read commands (doc 03 §5): non-mutating, no confirmation. -------------
# They delegate to the existing read-only dashboard widgets, which call the pure
# engine functions (`resolve_destination_trust`, `decide_with_step`) — no new
# decision logic and no side effects.


def _guardian_check_command(tokens: list[str]) -> str:
    """`/guardian check <destination|recipient>` — resolve a trust preview.

    Calls the engine resolver read-only (via the dashboard's `_dashboard_resolve_destination`)
    and prints `value -> <trust>` with a one-line reason, mirroring `why`'s style.
    """
    if len(tokens) < 2:
        return "Usage: `/guardian check <destination|recipient>`"
    value = " ".join(tokens[1:]).strip()
    result = dashboard_mod._dashboard_resolve_destination(value)
    trust = result.get("trust") or "unknown"
    reasons = {
        "self": "in your self-allowlist -> self",
        "trusted": "a configured trusted recipient -> trusted",
        "external": "not in your self-allowlist -> external",
        "unknown": "could not be resolved -> unknown",
    }
    reason = reasons.get(trust, f"resolved to {trust}")
    return f"{value} -> {trust}\nReason: {reason}"


def _guardian_sharing_preview_command(args: list[str]) -> str:
    """`/guardian sharing preview <action> <destination> <class>` — preview a send.

    Calls `decide` read-only (via the dashboard's `_dashboard_preview_send`) and
    prints the firing decide() step and the outcome.
    """
    if len(args) < 3:
        return (
            "Usage: `/guardian sharing preview <action> <destination> <class>`\n"
            "Example: `/guardian sharing preview message_send telegram:abc communications`"
        )
    action_family = args[0].strip()
    destination = args[1].strip()
    classes = [cls.strip() for cls in re.split(r"[,+]", " ".join(args[2:])) if cls.strip()]
    result = dashboard_mod._dashboard_preview_send(action_family, destination, classes)
    return (
        "Guardian send preview\n"
        f"Action: {result.get('action_family') or '(missing)'}\n"
        f"Destination: {result.get('destination') or '(missing)'} "
        f"(trust={result.get('destination_trust') or 'unknown'})\n"
        f"Data classes: {', '.join(result.get('data_classes') or []) or 'none'}\n"
        f"Decide step: {result.get('decision_step') or '(none)'}\n"
        f"Outcome: {result.get('decision') or 'unknown'}"
    )


def _guardian_approvals_command(owner_hash: str) -> str:
    """`/guardian approvals` — list pending approvals (read-only).

    Reads the same pending-approval store the dashboard uses
    (`_dashboard_pending_approvals`), scoped to the caller's owner like status.
    """
    pending = [
        approval
        for approval in dashboard_mod._dashboard_pending_approvals()
        if approval.get("owner_hash") == owner_hash or owner_hash == core._CLI_OWNER_HASH
    ]
    if not pending:
        return "No pending Guardian approvals."
    lines = [f"Hermes Guardian pending approvals · {len(pending)} shown"]
    for approval in pending:
        classes = ",".join(approval.get("data_classes") or []) or "none"
        lines.append(
            f"- {approval.get('id', '')}: {approval.get('action_family', '')} -> "
            f"{approval.get('destination', '')} ({classes})"
        )
    lines.append("Run `/guardian approve <id>` to see the ways to permit it, or `/guardian deny <id>`.")
    return "\n".join(lines)


def _parse_on_off(token: str) -> bool | None:
    text = str(token or "").strip().lower()
    if text in {"on", "true", "yes", "enable", "enabled", "1"}:
        return True
    if text in {"off", "false", "no", "disable", "disabled", "0"}:
        return False
    return None


def _guardian_privacy_command(owner_hash: str, tokens: list[str]) -> str:
    if len(tokens) == 1:
        return (
            f"Privacy mode: {core._privacy_policy()}\n"
            f"Unknown-tools mode: {rules_mod._unknown_tools_mode()}\n"
            f"LLM user-prompt context: {'on' if rules_mod._llm_user_context_enabled() else 'off'}\n"
            f"LLM cron context: {'on' if rules_mod._llm_cron_context_enabled() else 'off'}\n"
            f"LLM verifier model: {rules_mod._llm_verifier_model() or 'default'}"
        )
    if len(tokens) == 3 and tokens[1].lower() == "mode":
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        ok, message = rules_mod._set_privacy_mode(tokens[2])
        return message
    if len(tokens) == 3 and tokens[1].lower() in {"unknown-tools", "unknown_tools"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        ok, message = rules_mod._set_unknown_tools_mode(tokens[2])
        return message
    if len(tokens) == 3 and tokens[1].lower() in {"user-context", "user_context"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        enabled = _parse_on_off(tokens[2])
        if enabled is None:
            return "Usage: /guardian review owner-context on|off"
        ok, message = rules_mod._set_llm_user_context(enabled)
        return message
    if len(tokens) == 3 and tokens[1].lower() in {"cron-context", "cron_context"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        enabled = _parse_on_off(tokens[2])
        if enabled is None:
            return "Usage: /guardian review cron-context on|off"
        ok, message = rules_mod._set_llm_cron_context(enabled)
        return message
    if len(tokens) >= 3 and tokens[1].lower() in {"verifier-model", "verifier_model"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        ok, message = rules_mod._set_llm_verifier_model(" ".join(tokens[2:]))
        return message
    return (
        "Usage: /guardian review mode strict|read-only|llm|off | "
        "/guardian review owner-context on|off | "
        "/guardian review cron-context on|off | "
        "`/guardian review verifier-model <model_id|default>` | "
        "/guardian protection unknown-tools gate|allow"
    )


def _guardian_tools_command() -> str:
    overrides = rules_mod._tool_overrides_snapshot()
    lines = [
        "Hermes Guardian tool overrides",
        f"Unknown-tools mode: {rules_mod._unknown_tools_mode()}",
    ]
    if not overrides:
        lines.append("No tool overrides configured.")
    for override in overrides:
        state = "enabled" if override.get("enabled") else "disabled"
        bits = [f"match={override.get('match', '')}", state]
        if override.get("egress"):
            bits.append(f"egress={override['egress']}")
        if override.get("direction"):
            bits.append(f"direction={override['direction']}")
        if override.get("destination"):
            bits.append(f"destination={override['destination']}")
        if override.get("taints"):
            bits.append(f"taints={','.join(override['taints'])}")
        note = override.get("note") or ""
        suffix = f" - {note}" if note else ""
        lines.append(f"- {override.get('id', '')}: " + " ".join(bits) + suffix)
    lines.append(
        "Use /guardian protection tool set|delete|enable|disable and "
        "/guardian protection unknown-tools gate|allow."
    )
    return "\n".join(lines)


def _guardian_tool_command(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    usage = (
        "Usage: `/guardian protection tool set <match> [taints=a+b] [egress=ignore|gate|<family>] "
        "[direction=read|write] [source=reference|private] [destination=<dest>] [note=<text>]` | "
        "`/guardian protection tool delete <match_or_id>` | "
        "`/guardian protection tool enable|disable <id_or_match>`"
    )
    if sub == "set" and len(tokens) >= 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        match = tokens[2]
        params, errors = _parse_key_value_args(tokens[3:], allowed_keys=_TOOL_SET_KEYS)
        if errors:
            return "Invalid tool override arguments: " + "; ".join(errors) + f"\n{usage}"
        kwargs: dict[str, Any] = {}
        raw_taints = params.get("taints") or params.get("taint")
        if raw_taints is not None:
            kwargs["taints"] = [cls.strip() for cls in re.split(r"[,+]", raw_taints) if cls.strip()]
        if "egress" in params:
            kwargs["egress"] = params["egress"]
        if "direction" in params:
            kwargs["direction"] = params["direction"]
        if "source" in params:
            kwargs["source"] = params["source"]
        raw_destination = params.get("destination") or params.get("dest")
        if raw_destination is not None:
            kwargs["destination"] = raw_destination
        if "note" in params:
            kwargs["note"] = params["note"]
        if not kwargs:
            return "Provide at least one of: taints=, egress=, direction=, source=, destination=, note=.\n" + usage
        ok, message = rules_mod._set_tool_override(match, **kwargs)
        return message
    if sub in {"delete", "remove"} and len(tokens) == 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        ok, message = rules_mod._delete_tool_override(tokens[2])
        return message
    if sub in {"enable", "disable"} and len(tokens) == 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        ok, message = rules_mod._set_tool_override_enabled(tokens[2], sub == "enable")
        return message
    return usage


def _guardian_self_command(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    usage = (
        "Usage: `/guardian mine` | "
        "`/guardian mine add destination|identity|host <value>` | "
        "`/guardian mine remove destination|identity|host <value>`"
    )
    if not sub:
        snapshot = rules_mod._self_config_snapshot()
        trusted = rules_mod._trusted_recipients_snapshot()
        lines = ["Hermes Guardian self-destinations (intra-boundary, never gated)"]
        lines.append(f"Destinations ({len(snapshot['destinations'])}): " + (", ".join(snapshot["destinations"]) or "none"))
        lines.append(f"Identities ({len(snapshot['identities'])}): " + (", ".join(snapshot["identities"]) or "none (send-to-self not proven)"))
        lines.append(f"Hosts ({len(snapshot['hosts'])}): " + (", ".join(snapshot["hosts"]) or "none (own-infra not proven)"))
        if trusted:
            lines.append("Trusted recipients: " + ", ".join(
                f"{entry['identity']} ({','.join(entry['classes'])})" for entry in trusted
            ))
        else:
            lines.append("Trusted recipients: none")
        lines.append(usage)
        return "\n".join(lines)
    if sub == "add" and len(tokens) >= 4:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        _ok, message = rules_mod._add_self_destination(tokens[2], " ".join(tokens[3:]))
        return message
    if sub in {"remove", "delete"} and len(tokens) >= 4:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        _ok, message = rules_mod._remove_self_destination(tokens[2], " ".join(tokens[3:]))
        return message
    return usage


def _guardian_trusted_command(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    usage = (
        "Usage: `/guardian sharing destination add <identity> [classes=<class+class>] [note=<text>]` | "
        "`/guardian sharing destination suggest` | "
        "`/guardian sharing destination trust <n> [classes=<class+class>]` | "
        "`/guardian sharing destination remove <identity>` | "
        "`/guardian sharing destination remove command <n>`"
    )
    if not sub:
        trusted = rules_mod._trusted_recipients_snapshot()
        if not trusted:
            return "No trusted destinations configured.\n" + usage
        lines = ["🛡️ **Guardian trusted destinations**"]
        commands = [e for e in trusted if e.get("kind") == "command"]
        identities = [e for e in trusted if e.get("kind") != "command"]
        for entry in identities:
            note = f" — {entry['note']}" if entry.get("note") else ""
            lines.append(f"↳ 👤 `{entry['value']}` · classes={','.join(entry['classes'])}{note}")
        for idx, entry in enumerate(commands):
            note = f" — {entry['note']}" if entry.get("note") else ""
            lines.append(f"↳ 🖥️ [{idx}] `{entry['value']}` · classes={','.join(entry['classes'])}{note}")
        lines.append(usage)
        return "\n".join(lines)
    if sub == "suggest":
        suggestions = rules_mod._trusted_destination_suggestions()
        if not suggestions:
            return "No command suggestions available yet (none gated recently; no skill scripts found)."
        lines = ["🛡️ **Trusted-destination suggestions** · `/guardian sharing destination trust <n>`"]
        for idx, item in enumerate(suggestions):
            tag = "📁" if item.get("wildcard") else "🖥️"
            src = " (recent)" if item.get("source") == "recent" else ""
            lines.append(f"[{idx}] {tag} `{item['value']}`{src}")
        return "\n".join(lines)
    if sub == "trust" and len(tokens) >= 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        try:
            index = int(tokens[2])
        except ValueError:
            return "Usage: `/guardian sharing destination trust <n> [classes=<class+class>]`"
        suggestions = rules_mod._trusted_destination_suggestions()
        if index < 0 or index >= len(suggestions):
            return f"No suggestion #{index}. Run /guardian sharing destination suggest for the list."
        params, errors = _parse_key_value_args(tokens[3:], allowed_keys={"classes", "class", "data_classes", "note"})
        if errors:
            return "Invalid arguments: " + "; ".join(errors)
        classes = params.get("classes") or params.get("class") or params.get("data_classes")
        class_list = [cls.strip() for cls in re.split(r"[,+]", classes)] if classes else None
        _ok, message = rules_mod._add_trusted_command(suggestions[index]["value"], classes=class_list, note=params.get("note", ""))
        return message
    if sub == "add" and len(tokens) >= 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        identity = tokens[2]
        params, errors = _parse_key_value_args(tokens[3:], allowed_keys={"classes", "class", "data_classes", "note"})
        if errors:
            return "Invalid trusted destination arguments: " + "; ".join(errors) + f"\n{usage}"
        classes = params.get("classes") or params.get("class") or params.get("data_classes")
        class_list = [cls.strip() for cls in re.split(r"[,+]", classes)] if classes else None
        _ok, message = rules_mod._add_trusted_recipient(identity, classes=class_list, note=params.get("note", ""))
        return message
    if sub in {"remove", "delete"} and len(tokens) >= 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        if tokens[2].lower() == "command" and len(tokens) == 4:
            commands = [e for e in rules_mod._trusted_recipients_snapshot() if e.get("kind") == "command"]
            try:
                index = int(tokens[3])
            except ValueError:
                return "Usage: `/guardian sharing destination remove command <n>`"
            if index < 0 or index >= len(commands):
                return f"No trusted command #{index}."
            _ok, message = rules_mod._remove_trusted_command(commands[index]["value"])
            return message
        _ok, message = rules_mod._remove_trusted_recipient(tokens[2])
        return message
    return usage


def _guardian_sharing_command(owner_hash: str, tokens: list[str]) -> str:
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    usage = "Usage: `/guardian sharing outward add <subtype>` | `/guardian sharing outward remove <subtype>`"
    if not sub:
        snapshot = rules_mod._outward_sharing_snapshot()
        lines = ["Hermes Guardian outward-sharing subtypes (always external, even on a self store)"]
        for subtype in snapshot["builtin"]:
            lines.append(f"- {subtype} (builtin, non-removable)")
        for subtype in snapshot["extra"]:
            lines.append(f"- {subtype} (extra)")
        lines.append(usage)
        return "\n".join(lines)
    if sub == "add" and len(tokens) == 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        _ok, message = rules_mod._add_outward_sharing_subtype(tokens[2])
        return message
    if sub in {"remove", "delete"} and len(tokens) == 3:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        _ok, message = rules_mod._remove_outward_sharing_subtype(tokens[2])
        return message
    return usage


def _guardian_why_command(tokens: list[str]) -> str:
    if len(tokens) != 2:
        return "Usage: `/guardian why <activity_id|approval_id>`"
    return _guardian_why(tokens[1])


def _activity_row_for_why(identifier: str) -> dict[str, Any] | None:
    """Find the activity row a `why` query refers to (doc 03 §2).

    Accepts a bare activity row id (e.g. ``42`` or ``activity-42``) or a 4-digit
    approval id; returns the most recent matching row or None.
    """
    raw = str(identifier or "").strip()
    activity_match = re.fullmatch(r"(?:activity-)?(\d+)", raw)
    activity_store._ensure_activity_db()
    try:
        with activity_store._activity_connect() as conn:
            if re.fullmatch(r"[0-9]{4}", raw):
                # 4 digits could be an approval id OR a small row id; prefer approval id.
                row = conn.execute(
                    "SELECT * FROM activity WHERE approval_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
                    (raw,),
                ).fetchone()
                if row is not None:
                    return activity_rows._activity_row_from_sql(row)
            if activity_match:
                row = conn.execute(
                    "SELECT * FROM activity WHERE id = ? LIMIT 1",
                    (int(activity_match.group(1)),),
                ).fetchone()
                if row is not None:
                    return activity_rows._activity_row_from_sql(row)
    except Exception:
        return None
    return None


def _guardian_why(identifier: str) -> str:
    """Explain a recorded decision: resolved Capability + the firing decide() step.

    Reads the persisted activity row (the trust + step were stamped at decision time by
    the authoritative path, doc 03 §3.2), so the printed Capability and step match the
    actual outcome — this is the reason-about-ability payoff (doc 03 §2.1).
    """
    row = _activity_row_for_why(identifier)
    if row is None:
        return f"No Guardian activity found for {identifier}."
    decision = str(row.get("decision") or "")
    action_family = str(row.get("action_family") or "")
    destination = str(row.get("destination") or "")
    trust = str(row.get("destination_trust") or "unknown")
    step = str(row.get("decision_step") or "")
    classes = activity_rows._activity_data_classes_list(row.get("data_classes"))
    direction = "read" if decision in {"read", "tainted"} else "write"
    lines = [
        f"Guardian decision for {identifier}",
        f"Outcome: {decision or 'unknown'}",
        "Resolved Capability:",
        f"  direction: {direction}",
        f"  destination: {destination or '(none)'} (trust={trust})",
        f"  policy classes / fine tags: {', '.join(classes) if classes else 'none'}",
        f"  action family: {action_family or '(none)'}",
        f"  purpose: {row.get('purpose') or 'unknown'}",
        f"  recipient identity: {row.get('recipient_identity') or 'none'}",
        f"Decide step: {step or '(pre-migration row; step not recorded)'}",
    ]
    reason = str(row.get("reason") or "").strip()
    if reason:
        lines.append(f"Reason: {reason}")
    return "\n".join(lines)


def _guardian_security_command(owner_hash: str, tokens: list[str]) -> str:
    if len(tokens) == 1:
        lines = ["Hermes Guardian security rules"]
        for rule in rules_mod._security_rules_snapshot():
            state = "enabled" if rule.get("enabled") else "disabled"
            lines.append(
                f"- {rule['id']}: {state} - {rule.get('label', '')}"
            )
        lines.append("Use `/guardian protection security enable|disable <rule_id>`.")
        return "\n".join(lines)
    if len(tokens) == 3 and tokens[1].lower() in {"enable", "disable"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        enabled = tokens[1].lower() == "enable"
        ok, message = rules_mod._set_security_rule(tokens[2], enabled)
        return message
    return "Usage: `/guardian protection security` | `/guardian protection security enable|disable <rule_id>`"


def _guardian_language_packs_command(owner_hash: str, tokens: list[str]) -> str:
    if len(tokens) == 1:
        lines = ["Hermes Guardian language packs"]
        for pack in rules_mod._language_packs_snapshot():
            state = "enabled" if pack.get("enabled") else "disabled"
            required = " required" if pack.get("required") else ""
            lines.append(
                f"- {pack['id']}: {state}{required} - {pack.get('name', '')}"
            )
        lines.append("Use `/guardian protection language-packs enable|disable <pack_id>`.")
        return "\n".join(lines)
    if len(tokens) == 3 and tokens[1].lower() in {"enable", "disable"}:
        if not _slash_admin_allowed(owner_hash):
            return _global_mutation_denied_message()
        enabled = tokens[1].lower() == "enable"
        ok, message = rules_mod._set_language_pack(tokens[2], enabled)
        return message
    return (
        "Usage: `/guardian protection language-packs` | "
        "`/guardian protection language-packs enable|disable <pack_id>`"
    )


def _rule_add_usage() -> str:
    return "Usage: `/guardian sharing rule add allow|deny action=<family|*> destination=<dest|*> classes=<class+class|*> [tool=<tool_name|*>] [purpose=<token|*>] [recipient=<id|raw|*>] [expires=<5m|1h|unix|forever>]`"


def _rule_add_error(message: str) -> tuple[dict[str, Any] | None, str]:
    return None, f"Invalid privacy rule. {message}\n{_rule_add_usage()}"


def _parse_rule_expiry(params: dict[str, str]) -> tuple[int | None, str]:
    raw = (
        params.get("expires_at")
        or params.get("expires")
        or params.get("duration")
        or params.get("ttl")
        or ""
    )
    text = str(raw or "").strip().lower()
    if not text or text in {"0", "never", "forever", "none"}:
        return 0, ""
    if re.fullmatch(r"\d+", text):
        value = int(text)
        if value > 10_000_000_000:
            return value, ""
        return int(state._now()) + value, ""
    match = re.fullmatch(r"(\d+)([smhd])", text)
    if not match:
        return None, "expires must be a unix timestamp, seconds, or duration like 5m/1h."
    amount = int(match.group(1))
    unit = match.group(2)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return int(state._now()) + amount * multiplier, ""


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
    purpose = tool_policy._normalize_rule_purpose(params.get("purpose", "*"))
    recipient_identity = tool_policy._normalize_rule_recipient_identity(
        params.get("recipient_identity", params.get("recipient", "*"))
    )
    tool_name = params.get("tool") or params.get("tool_name") or "*"
    if raw_classes.strip() == "*":
        classes = ["*"]
    else:
        requested_classes = [cls.strip() for cls in re.split(r"[,+]", raw_classes) if cls.strip()]
        invalid_classes = [cls for cls in requested_classes if cls not in core._ALL_PRIVACY_CLASSES]
        if invalid_classes:
            return _rule_add_error("Unknown data class(es): " + ", ".join(invalid_classes) + ".")
        if not requested_classes:
            return _rule_add_error("Data classes must be a valid class list or explicit *.")
        classes = requested_classes
    expires_at, expiry_error = _parse_rule_expiry(params)
    if expiry_error:
        return _rule_add_error(expiry_error)

    requested_owner = params.get("owner") or params.get("owner_hash")
    cron_job_id = params.get("cron") or params.get("cron_job_id") or ""
    if requested_owner is None:
        rule_owner = "*" if owner_hash == core._CLI_OWNER_HASH or (cron_job_id and _slash_admin_allowed(owner_hash)) else owner_hash
    else:
        rule_owner = requested_owner
        if rule_owner == "*" and not _slash_admin_allowed(owner_hash):
            return None, _global_mutation_denied_message()
        if rule_owner != "*" and owner_hash != core._CLI_OWNER_HASH and rule_owner != owner_hash:
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
            "purpose": purpose,
            "recipient_identity": recipient_identity,
            "data_classes": classes or ["*"],
        },
        "scope": {
            "owner_hash": rule_owner,
            "cron_job_id": cron_job_id,
            "cron_job_name": params.get("cron_name") or params.get("cron_job_name") or "",
        },
        "expires_at": expires_at or 0,
        "created_at": int(state._now()),
    }
    return rules_mod._normalize_privacy_rule(rule), ""


def _guardian_rule_command(owner_hash: str, tokens: list[str]) -> str:
    if len(tokens) >= 3 and tokens[1].lower() == "add" and tokens[2].lower() in {"allow", "deny"}:
        params, errors = _parse_key_value_args(tokens[3:], allowed_keys=_RULE_ADD_KEYS)
        if errors:
            return "Invalid privacy rule arguments: " + "; ".join(errors) + f"\n{_rule_add_usage()}"
        rule, error = _new_privacy_rule_from_params(owner_hash, tokens[2].lower(), params)
        if not rule:
            return error
        rules = rules_mod._persistent_privacy_rules()
        rules.append(rule)
        if not rules_mod._save_persistent_privacy_rules(rules):
            return "Failed to save privacy rule."
        match = rule.get("match") or {}
        return (
            f"Added privacy {rule['effect']} rule {rule['id']}.\n"
            f"Match: {match.get('action_family', '*')} -> {match.get('destination', '*')}\n"
            f"Context: purpose={match.get('purpose', '*')} recipient={match.get('recipient_identity', '*')}\n"
            f"Scope: {_rule_scope_text(rule)}\n"
            f"{_rule_classes_line(match.get('data_classes') or [])}"
        )
    if len(tokens) == 3 and tokens[1].lower() in {"delete", "remove", "revoke"}:
        return _guardian_delete_rule(owner_hash, tokens[2])
    if len(tokens) == 3 and tokens[1].lower() in {"enable", "disable"}:
        desired = tokens[1].lower() == "enable"
        rules = rules_mod._persistent_privacy_rules()
        for rule in rules:
            if rule.get("id") == tokens[2] and approvals._rule_delete_owner_allowed(owner_hash, rule):
                rule["enabled"] = desired
                if not rules_mod._save_persistent_privacy_rules(rules):
                    return "Failed to save privacy rule."
                return f"{'Enabled' if desired else 'Disabled'} privacy rule {tokens[2]}."
        return f"No matching privacy rule found for {tokens[2]}."
    if len(tokens) == 5 and tokens[1].lower() == "move" and tokens[3].lower() in {"before", "after"}:
        rules = rules_mod._persistent_privacy_rules()
        moving = next((rule for rule in rules if rule.get("id") == tokens[2] and approvals._rule_delete_owner_allowed(owner_hash, rule)), None)
        target = next((rule for rule in rules if rule.get("id") == tokens[4] and approvals._rule_delete_owner_allowed(owner_hash, rule)), None)
        if moving is None or target is None:
            return "No matching privacy rule found for move."
        rules = [rule for rule in rules if rule.get("id") != tokens[2]]
        target_index = next((idx for idx, rule in enumerate(rules) if rule.get("id") == tokens[4]), len(rules))
        insert_at = target_index if tokens[3].lower() == "before" else target_index + 1
        rules.insert(insert_at, moving)
        if not rules_mod._save_persistent_privacy_rules(rules):
            return "Failed to save privacy rule order."
        return f"Moved privacy rule {tokens[2]} {tokens[3].lower()} {tokens[4]}."
    return (
        f"{_rule_add_usage()} | "
        "`/guardian sharing rule delete <rule_id>` | `/guardian sharing rule enable|disable <rule_id>` | "
        "`/guardian sharing rule move <rule_id> before|after <other_rule_id>`"
    )


def _guardian_status(owner_hash: str) -> str:
    with state._LOCK:
        llm._prune_expired()
        session_ids = approvals._owner_session_ids(owner_hash)
        taint = sorted({cls for sid in session_ids for cls in state._SESSIONS.get(sid, {}).get("taint", set())})
        pending = [
            approval
            for approval in state._PENDING_APPROVALS.values()
            if approval.get("owner_hash") == owner_hash or owner_hash == core._CLI_OWNER_HASH
        ]
        rules = rules_mod._privacy_rules_for_owner(owner_hash)
        disabled_security = [
            rule
            for rule in rules_mod._security_rules_snapshot()
            if not bool(rule.get("enabled"))
        ]
        enabled_language_packs = [
            pack
            for pack in rules_mod._language_packs_snapshot()
            if bool(pack.get("enabled"))
        ]
    risk_banners = activity_rows._runtime_risk_banners()
    trust_summary = activity_rows._destination_trust_summary()
    self_block = trust_summary.get("self") or {}
    tally = trust_summary.get("tally") or {}
    tally_text = (
        ", ".join(f"{label}={count}" for label, count in sorted(tally.items()))
        if tally
        else "none observed yet"
    )
    lines = [
        "Hermes Guardian status",
        f"Privacy mode (preset): {core._privacy_policy()}",
        f"Unknown tools: {rules_mod._unknown_tools_mode()} ({len(rules_mod._tool_overrides())} override(s))",
        f"LLM context: user-prompt {'on' if rules_mod._llm_user_context_enabled() else 'off'}, "
        f"cron {'on' if rules_mod._llm_cron_context_enabled() else 'off'}",
        f"Security rules: {len(rules_mod._SECURITY_RULE_IDS) - len(disabled_security)} enabled, {len(disabled_security)} disabled",
        f"Language packs: {', '.join(pack.get('id', '') for pack in enabled_language_packs) or 'none'}",
        f"Taint classes: {', '.join(taint) if taint else 'none'}",
        f"Pending approvals: {len(pending)}",
        f"Privacy rules: {len(rules)}",
        "Destination trust:",
        f"  self destinations: {len(self_block.get('destinations') or [])}, "
        f"identities: {len(self_block.get('identities') or [])}, "
        f"hosts: {len(self_block.get('hosts') or [])}",
        f"  trusted recipients: {len(trust_summary.get('trusted_recipients') or [])}",
        f"  outward-sharing subtypes: {len((trust_summary.get('outward_sharing') or {}).get('builtin') or [])} builtin + "
        f"{len((trust_summary.get('outward_sharing') or {}).get('extra') or [])} extra",
        f"  destinations seen by trust: {tally_text}",
    ]
    env_overrides = trust_summary.get("env_overrides") or []
    if env_overrides:
        lines.append("Env overrides shadowing the policy document:")
        for override in env_overrides:
            lines.append(f"  {override}")
    for banner in risk_banners:
        lines.append(f"Risk: {banner.get('message', '')}")
    for approval in pending[:10]:
        classes = ",".join(approval.get("data_classes") or [])
        lines.append(
            f"- {approval['id']}: {approval['action_family']} -> {approval['destination']} ({classes})"
        )
    return "\n".join(lines)


def _guardian_rules(owner_hash: str) -> str:
    rules = rules_mod._privacy_rules_for_owner(owner_hash)
    if not rules:
        return "No persistent Guardian privacy rules."
    lines = [f"🛡️ **Guardian privacy rules** · mode `{core._privacy_policy()}` · {len(rules)} shown"]
    for rule in rules:
        match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
        effect = str(rule.get("effect") or "allow").strip().lower()
        action = _rule_match_text(match.get("action_family"), "Any action")
        destination = _rule_match_text(match.get("destination"), "Any destination")
        purpose = _rule_match_text(match.get("purpose"), "Any purpose")
        recipient_identity = _rule_match_text(match.get("recipient_identity"), "Any recipient")
        tool = _rule_match_text(match.get("tool_name"), "")
        disabled = not bool(rule.get("enabled", True))
        icon = "⏸️" if disabled else ("⛔" if effect == "deny" else "✅")
        label = effect.upper() if effect else "RULE"
        if disabled:
            label = f"{label} (disabled)"
        metadata = f"`{rule.get('id', '')}`"
        expiry = _rule_expiry_text(rule)
        if expiry:
            metadata += f" · {expiry}"
        lines.extend([
            "",
            f"{icon} **{label}** `{action} -> {destination}`",
            metadata,
            f"Scope: {_rule_scope_text(rule)}",
        ])
        if tool:
            lines.append(f"Tool: `{tool}`")
        lines.append(f"Context: purpose=`{purpose}` recipient=`{recipient_identity}`")
        lines.append(_rule_classes_line(match.get("data_classes") or []))
    return "\n".join(lines)


def _rule_match_text(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    if not text or text == "*":
        return fallback
    return dashboard_mod._clip_text(text, 96, ellipsis="...", fallback=fallback)


def _rule_scope_text(rule: dict[str, Any]) -> str:
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    cron_job_id = str(scope.get("cron_job_id") or rule.get("cron_job_id") or "").strip()
    if cron_job_id:
        cron_job_name = str(scope.get("cron_job_name") or rule.get("cron_job_name") or "").strip()
        try:
            cron_job_name = cron_job_name or cron_notifications._cron_job_name(cron_job_id)
        except Exception:
            pass
        return f"[Cron] {cron_job_name or cron_job_id}"
    owner_hash = str(scope.get("owner_hash") or rule.get("owner_hash") or "*").strip()
    label = approvals._rule_scope_label(rule).lower()
    if owner_hash == "*" or label in {"all owners", "global"}:
        return "Runs everywhere"
    return "Owner scoped"


def _rule_expiry_text(rule: dict[str, Any]) -> str:
    try:
        expires_at = int(float(rule.get("expires_at") or 0))
    except (TypeError, ValueError):
        return ""
    if expires_at <= 0:
        return ""
    if expires_at <= int(state._now()):
        return "expired"
    return f"expires {dashboard_mod._friendly_activity_timestamp(expires_at)}"


def _rule_classes_line(classes: list[Any]) -> str:
    safe_classes = sorted(str(cls).strip() for cls in classes if str(cls).strip())
    if not safe_classes:
        return "🏷️ No data classes"
    if "*" in safe_classes:
        return "🏷️ `all data classes`"
    return f"🏷️ `{','.join(safe_classes)}`"


def _guardian_clear_taint(owner_hash: str) -> str:
    with state._LOCK:
        session_ids = approvals._owner_session_ids(owner_hash)
        for sid in session_ids:
            session = state._SESSIONS.get(sid)
            if session:
                session["taint"].clear()
                session["browser_private_hosts"].clear()
    return "Cleared Guardian taint for your active Guardian sessions."


def _guardian_revoke(owner_hash: str, rule_id: str) -> str:
    ok, message, _removed = approvals._delete_persistent_rule(owner_hash, rule_id)
    if ok:
        return f"Revoked privacy rule {rule_id}."
    return message


def _guardian_delete_rule(owner_hash: str, rule_id: str) -> str:
    ok, message, _removed = approvals._delete_persistent_rule(owner_hash, rule_id)
    return message


def _guardian_dismiss(owner_hash: str, approval_id: str) -> str:
    requested_id = approval_id
    with state._LOCK:
        approval_id = approvals._resolve_pending_approval_id(approval_id) or ""
        approval = state._PENDING_APPROVALS.get(approval_id)
        if not approval:
            return f"No pending approval found for {requested_id}."
        if not approvals._approval_owner_allowed(owner_hash, approval):
            return "Approval denied: this request belongs to a different user/session."
        state._PENDING_APPROVALS.pop(approval_id, None)
        approvals._delete_pending_approvals_from_store_unlocked([approval_id])
    activity_store._emit_activity(
        "denied",
        session_id=approval.get("session_id", ""),
        owner_hash=approval.get("owner_hash", ""),
        tool_name=approval.get("tool_name", ""),
        action_family=approval.get("action_family", ""),
        destination=approval.get("destination", ""),
        purpose=approval.get("purpose", "unknown"),
        recipient_identity=approval.get("recipient_identity", "none"),
        data_classes=approval.get("data_classes") or [],
        reason=approval.get("reason") or "requires approval",
        approval_id=approval_id,
        action_detail=approval.get("action_detail", ""),
    )
    return f"Dismissed guardian approval {approval_id}."


def _guardian_deny(owner_hash: str, approval_id: str) -> str:
    return _guardian_dismiss(owner_hash, approval_id)


# Slash keyword -> permit method (doc 06 §7). The expiry keywords map directly; the
# context keywords `mine`/`trust` resolve to the single self_*/trusted_* option the
# approval offers (each context yields at most one of each, so no qualifier is needed).
_SCOPE_KEYWORD_TO_METHOD = {
    "5m": "rule_5m",
    "forever": "rule_forever",
}


def _resolve_owned_approval(owner_hash: str, approval_id: str):
    """Resolve a pending approval the caller is allowed to act on. Returns
    ``(resolved_id, approval, error_message)`` — ``error_message`` is "" on success."""
    requested_id = approval_id
    with state._LOCK:
        llm._prune_expired()
        resolved_id = approvals._resolve_pending_approval_id(approval_id) or ""
        approval = state._PENDING_APPROVALS.get(resolved_id)
        if not approval:
            return "", None, f"No pending approval found for {requested_id}."
        if not approvals._approval_owner_allowed(owner_hash, approval):
            return "", None, "Approval denied: this request belongs to a different user/session."
    return resolved_id, approval, ""


def _guardian_permit_menu(owner_hash: str, approval_id: str) -> str:
    """The context-filtered list of ways to permit a pending approval (doc 06 §7.1)."""
    resolved_id, approval, error = _resolve_owned_approval(owner_hash, approval_id)
    if error:
        return error
    lines = [
        f"Ways to permit approval {resolved_id} "
        f"({approval.get('action_family', '')} -> {approval.get('destination', '')}):"
    ]
    last_group = ""
    for option in approvals._approval_permit_options(approval):
        group = str(option.get("group") or "Approval options")
        if group != last_group:
            lines.append(f"{group}:")
            last_group = group
        command = approvals._permit_command_line(resolved_id, option["method"])
        admin = " [admin]" if option.get("structural") else ""
        detail = f" — {option['detail']}" if option.get("detail") else ""
        lines.append(f"  {command}{admin}: {option['label']}{detail}")
    lines.append(f"or dismiss with: /guardian dismiss {resolved_id}")
    return "\n".join(lines)


def _context_permit_method(owner_hash: str, approval_id: str, keyword: str):
    """Resolve `mine`/`trust` to the single self_*/trusted_* method the approval offers.
    Returns ``(method, error_message)`` — exactly one is set."""
    resolved_id, approval, error = _resolve_owned_approval(owner_hash, approval_id)
    if error:
        return None, error
    prefix = "self_" if keyword == "mine" else "trusted_"
    methods = [
        option["method"]
        for option in approvals._approval_permit_options(approval)
        if option["method"].startswith(prefix)
    ]
    if not methods:
        return None, (
            f"No '{keyword}' option for approval {resolved_id} given this action.\n"
            + _guardian_permit_menu(owner_hash, approval_id)
        )
    return methods[0], None


def _guardian_approve(owner_hash: str, approval_id: str, keyword: str = "") -> str:
    keyword = str(keyword or "").strip().lower()
    if not keyword:
        return _guardian_permit_menu(owner_hash, approval_id)
    method = _SCOPE_KEYWORD_TO_METHOD.get(keyword)
    if method is None:
        if keyword in {"mine", "trust"}:
            method, error = _context_permit_method(owner_hash, approval_id, keyword)
            if error:
                return error
        else:
            return (
                f"Unknown approve option '{keyword}'.\n"
                + _guardian_permit_menu(owner_hash, approval_id)
            )
    _ok, message = approvals._apply_permit_option(owner_hash, approval_id, method)
    return message
