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


def _activity_clock_text(row: dict[str, Any]) -> str:
    return _presentation.friendly_activity_clock(row.get("ts"), _history_timezone())


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


def _dashboard_llm_user_context_action(enabled: Any) -> tuple[dict[str, Any], int]:
    ok, message = _set_llm_user_context(_config_bool(enabled, default=_DEFAULT_LLM_USER_CONTEXT))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_llm_cron_context_action(enabled: Any) -> tuple[dict[str, Any], int]:
    ok, message = _set_llm_cron_context(_config_bool(enabled, default=_DEFAULT_LLM_CRON_CONTEXT))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_persist_prompts_action(enabled: Any) -> tuple[dict[str, Any], int]:
    ok, message = _set_persist_prompts(_config_bool(enabled, default=_DEFAULT_PERSIST_PROMPTS))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_llm_verifier_model_action(model: Any) -> tuple[dict[str, Any], int]:
    ok, message = _set_llm_verifier_model(str(model or ""))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_tool_override_create_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    match = payload.get("match") or payload.get("tool") or payload.get("tool_name") or ""
    ok, message = _set_tool_override(
        match,
        taints=payload.get("taints"),
        egress=payload.get("egress"),
        direction=payload.get("direction"),
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
            direction=payload.get("direction"),
            destination=payload.get("destination"),
            note=payload.get("note"),
            enabled=payload.get("enabled"),
        )
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_tool_override_delete_action(match_or_id: str) -> tuple[dict[str, Any], int]:
    ok, message = _delete_tool_override(match_or_id)
    status = 200 if ok else (404 if message.startswith("No matching tool override") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


# --- Destinations & Trust panel actions (doc 03 §3.1) ------------------------
# Mirror the slash commands; mutations go through the same admin-token + confirmation
# guards in dashboard/plugin_api.py (destination-trust edits require confirmation like
# the cron-context toggle).
def _dashboard_self_add_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    kind = str(payload.get("kind") or "").strip().lower()
    value = str(payload.get("value") or "").strip()
    ok, message = _add_self_destination(kind, value)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_self_remove_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    kind = str(payload.get("kind") or "").strip().lower()
    value = str(payload.get("value") or "").strip()
    ok, message = _remove_self_destination(kind, value)
    status = 200 if ok else (404 if message.startswith("No ") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


def _dashboard_trusted_add_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ok, message = _add_trusted_recipient(
        str(payload.get("identity") or ""),
        classes=payload.get("classes"),
        note=str(payload.get("note") or ""),
    )
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_trusted_remove_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ok, message = _remove_trusted_recipient(str(payload.get("identity") or ""))
    status = 200 if ok else (404 if message.startswith("No ") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


def _dashboard_sharing_add_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ok, message = _add_outward_sharing_subtype(str(payload.get("subtype") or ""))
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, 200 if ok else 400


def _dashboard_sharing_remove_action(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ok, message = _remove_outward_sharing_subtype(str(payload.get("subtype") or ""))
    status = 200 if ok else (404 if message.startswith("No ") else 400)
    return {"ok": ok, "message": message, "policy": _policy_snapshot()}, status


# --- Activity tab: clear session taint (doc 02 §Tab1) ------------------------
# Thin dashboard wrapper over the same _guardian_clear_taint handler the slash
# command (/guardian clear-taint) uses; it stays admin-token guarded in
# dashboard/plugin_api.py like every other mutator.
def _dashboard_clear_taint_action() -> tuple[dict[str, Any], int]:
    message = _guardian_clear_taint(_CLI_OWNER_HASH)
    return {"ok": True, "message": message, "policy": _policy_snapshot()}, 200


# --- Activity tab: pending-approvals read list (doc 02 §Tab1) ----------------
# The activity store already surfaces pending approvals inside _policy_snapshot()
# (the "pending" list, with trust pill + decision step). The dashboard's GET
# /approvals reads exactly that slice — no new decision logic, no mutation.
def _dashboard_pending_approvals() -> list[dict[str, Any]]:
    return list(_policy_snapshot().get("pending") or [])


# --- Pure-function widgets (charter §5; doc 02 §Tab2/§Tab3) ------------------
# All three widgets call the existing pure engine functions with hypothetical
# inputs. They compute and return; they never mutate state and add no decision
# logic (charter §4 invariant #1).
def _parse_destination_value(value: str) -> tuple[str, str]:
    """Split a "kind:id" destination string into (kind, id).

    A bare token with no colon is treated as an id with an inferred kind: an
    address-like token (contains "@") is a messaging recipient; anything with a
    dot is a host; otherwise it is a store id. This only shapes the resolver's
    inputs — the resolver itself is unchanged and conservative.
    """
    raw = str(value or "").strip()
    if ":" in raw:
        kind, _, dest_id = raw.partition(":")
        return kind.strip().lower(), dest_id.strip()
    if "@" in raw:
        return "messaging", raw
    if "." in raw:
        return "host", raw
    return "store", raw


def _dashboard_resolve_destination(value: str) -> dict[str, Any]:
    """"Check a destination" widget (What's Yours). Read-only.

    Resolves a hypothetical destination/recipient to its trust level via the
    engine's pure resolve_destination_trust. For messaging kinds the id doubles
    as the recipient identity.
    """
    raw = str(value or "").strip()
    kind, dest_id = _parse_destination_value(raw)
    recipient = dest_id if kind in {"messaging", "message", "send"} else ""
    subtype = "send" if kind in {"messaging", "message", "send"} else "write"
    trust = _resolve_destination_trust(kind, dest_id, subtype, recipient, _load_privacy_config())
    return {
        "value": raw,
        "kind": kind,
        "id": dest_id,
        "trust": _normalize_destination_trust_label(getattr(trust, "value", trust)),
    }


def _build_preview_capability(action_family: str, destination: str, classes: list[str]) -> Any:
    """Construct a hypothetical Capability for the preview/impact widgets.

    Mirrors classify()'s mapping from an egress action_family to the resolver's
    destination kind/subtype, then resolves trust with the live config. The
    data_classes are the caller's hypothetical taint (collapsed to policy classes
    by decide downstream). No tool call is made; nothing is stored.
    """
    family = str(action_family or "").strip()
    kind, dest_id = _parse_destination_value(destination)
    # Messaging families resolve the recipient from the destination id.
    is_messaging = family in {"message_send", "message_list", "final_response"} or kind in {
        "messaging",
        "message",
        "send",
    }
    if is_messaging:
        kind = "messaging"
        recipient = dest_id
        subtype = "send"
    else:
        recipient = ""
        subtype = "write"
    trust = _resolve_destination_trust(kind, dest_id, subtype, recipient, _load_privacy_config())
    dest = _Destination(kind=kind, id=dest_id, trust=trust)
    return _Capability(
        direction="write",
        destination=dest,
        data_classes=frozenset(str(c) for c in (classes or []) if str(c).strip()),
        data_tags=frozenset(),
        action_subtype=subtype,
    )


def _dashboard_preview_send(action_family: str, destination: str, classes: list[str]) -> dict[str, Any]:
    """"Preview a send" widget (Sharing). Read-only.

    Builds a hypothetical Capability and runs the pure decide_with_step to report
    which decide() step fires and the outcome.
    """
    cap = _build_preview_capability(action_family, destination, classes)
    outcome, step = _decide_with_step(
        cap, classes or [], "unknown", _privacy_policy()
    )
    dest = getattr(cap, "destination", None)
    return {
        "action_family": str(action_family or ""),
        "destination": str(destination or ""),
        "data_classes": sorted(str(c) for c in (classes or []) if str(c).strip()),
        "destination_trust": _normalize_destination_trust_label(
            getattr(getattr(dest, "trust", None), "value", getattr(dest, "trust", None))
        ),
        "decision": str(outcome),
        "decision_step": _normalize_decision_step_label(step),
    }


def _candidate_rule_matches(candidate: dict[str, Any], row: dict[str, Any]) -> bool:
    """Does a hypothetical allow/deny rule cover a historical activity row?

    Uses the SAME first-match semantics as match_declassification_rule (purpose /
    destination token / data-class with "*" wildcard), applied to the candidate
    rule only. Read-only: it inspects stored, already-sanitized metadata rows and
    mutates nothing.
    """
    match = candidate.get("match") if isinstance(candidate.get("match"), dict) else {}
    rule_purpose = str(match.get("purpose", "*") or "*").strip().lower()
    row_purpose = str(row.get("purpose") or "unknown").strip().lower() or "unknown"
    if rule_purpose not in {"*", row_purpose}:
        return False

    rule_dest = str(match.get("destination", "*") or "*").strip().lower()
    dest_id = str(row.get("destination") or "")
    if rule_dest != "*" and rule_dest != dest_id.strip().lower():
        return False

    rule_classes = {str(c).strip().lower() for c in (match.get("data_classes") or ["*"])}
    if "*" not in rule_classes:
        row_classes = row.get("data_classes")
        if isinstance(row_classes, str):
            row_classes = [tok for tok in re.split(r"[\s,]+", row_classes) if tok]
        row_class_set = {str(c).strip().lower() for c in (row_classes or [])}
        if not (rule_classes & row_class_set):
            return False

    rule_action = str(match.get("action_family", "*") or "*").strip().lower()
    if rule_action != "*" and rule_action != str(row.get("action_family") or "").strip().lower():
        return False
    return True


def _dashboard_sharing_impact(candidate: dict[str, Any], *, limit: int = 200) -> dict[str, Any]:
    """"Impact preview" (Sharing). Read-only over-permissiveness guardrail.

    Replays recent gated activity against a candidate allow/deny rule and lists the
    rows whose outcome the rule would have changed. Computes only — no mutation,
    no decision-engine change. This is the prioritized guardrail from doc 02 §Tab3.
    """
    effect = str(candidate.get("effect") or "allow").strip().lower()
    rows = _grouped_activity_rows({"decisions": "approve,blocked,denied,gated"}, limit=limit)
    matched: list[dict[str, Any]] = []
    for row in rows:
        decision = str(row.get("decision") or "").strip().lower()
        # Only rows that were gated/blocked are candidates for an allow flip; only
        # currently-allowed-by-gate rows are candidates for a deny flip. We report
        # the rows the candidate rule would newly cover.
        if not _candidate_rule_matches(candidate, row):
            continue
        matched.append(
            {
                "id": str(row.get("id") or row.get("activity_id") or ""),
                "decision": decision,
                "action_family": str(row.get("action_family") or ""),
                "destination": str(row.get("destination") or ""),
                "destination_trust": _normalize_destination_trust_label(row.get("destination_trust")),
                "data_classes": row.get("data_classes"),
                "purpose": str(row.get("purpose") or "unknown"),
                "recipient_identity": str(row.get("recipient_identity") or "none"),
                "created_at": int(float(row.get("ts") or row.get("created_at") or 0)),
            }
        )
    verb = "auto-allowed" if effect == "allow" else "blocked"
    return {
        "effect": effect,
        "verb": verb,
        "matched_count": len(matched),
        "considered": len(rows),
        "matched": matched,
    }


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
