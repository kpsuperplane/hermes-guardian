"""Privacy egress orchestration for Hermes Guardian."""

from __future__ import annotations


def _emit_read_activity_if_applicable(tool_name: str, args: Any, session_id: str | None) -> bool:
    read_activity = _read_activity_for_tool(tool_name, args, session_id)
    if not read_activity:
        return False
    action_family, destination = read_activity
    _emit_activity(
        "read",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=set(),
        reason="public read",
        action_detail=_activity_action_detail(tool_name, args, action_family, destination),
    )
    return True


def _record_allowed_tool_side_effects(
    session_id: str | None,
    tool_name: str,
    args: Any,
    *,
    action_family: str = "",
    mark_browser_private_input: bool = False,
) -> None:
    if mark_browser_private_input and action_family == "browser_type":
        _mark_browser_private_input(session_id)
    _record_local_system_result_policy(session_id, tool_name, args)


def _emit_egress_activity(
    decision: str,
    *,
    session_id: str | None,
    tool_name: str,
    action_family: str,
    destination: str,
    data_classes: set[str],
    reason: str,
    owner_hash: str = "",
    approval_id: str = "",
    rule_id: str = "",
    rule_source: str = "",
    rule_effect: str = "",
    rule_scope: str = "",
    action_detail: str = "",
) -> None:
    _emit_activity(
        decision,
        session_id=session_id,
        owner_hash=owner_hash,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=data_classes,
        reason=reason,
        approval_id=approval_id,
        rule_id=rule_id,
        rule_source=rule_source,
        rule_effect=rule_effect,
        rule_scope=rule_scope,
        action_detail=action_detail,
        module="privacy",
    )


def _allow_privacy_off_tool_call(tool_name: str, args: Any, session_id: str | None, action: tuple[str, str] | None) -> None:
    if action:
        action_family, destination = action
        data_classes = _data_classes_for_egress(session_id, args)
        if data_classes:
            _emit_egress_activity(
                "privacy_off_allowed",
                session_id=session_id,
                tool_name=tool_name,
                action_family=action_family,
                destination=destination,
                data_classes=data_classes,
                reason="privacy policy off",
                action_detail=_activity_action_detail(tool_name, args, action_family, destination),
            )
    else:
        _emit_read_activity_if_applicable(tool_name, args, session_id)
    _record_allowed_tool_side_effects(session_id, tool_name, args)


def _allow_untainted_tool_call(
    tool_name: str,
    args: Any,
    session_id: str | None,
    *,
    action_family: str,
    destination: str,
) -> None:
    _emit_egress_activity(
        "allowed",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=set(),
        reason="no private data in scope",
        action_detail=_activity_action_detail(tool_name, args, action_family, destination),
    )
    _record_allowed_tool_side_effects(session_id, tool_name, args)


def _allow_approved_tool_call(shape: dict[str, Any], source: dict[str, Any], tool_name: str, args: Any) -> None:
    _emit_egress_activity(
        "allowed",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason="matched allow rule",
        rule_id=source.get("rule_id", ""),
        rule_source=source.get("source", ""),
        rule_effect=source.get("effect", "allow"),
        action_detail=shape.get("action_detail", ""),
    )
    _record_allowed_tool_side_effects(
        shape.get("session_id", ""),
        tool_name,
        args,
        action_family=shape.get("action_family", ""),
        mark_browser_private_input=True,
    )


def _block_for_privacy_rule(shape: dict[str, Any], tool_name: str, source: dict[str, Any]) -> dict[str, str]:
    reason = "matched deny rule"
    _emit_egress_activity(
        "blocked",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=reason,
        rule_id=source.get("rule_id", ""),
        rule_source=source.get("source", "persistent"),
        rule_effect=source.get("effect", "deny"),
        action_detail=shape.get("action_detail", ""),
    )
    _notify_cron_failure_if_needed(
        session_id=shape.get("session_id", ""),
        tool_name=tool_name,
        decision="blocked",
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=reason,
    )
    return {
        "action": "block",
        "message": (
            "Hermes Guardian denied this egress by privacy rule.\n\n"
            f"Rule ID: {source.get('rule_id', '')}\n"
            f"Action: {shape.get('action_family', '')}\n"
            f"Destination: {shape.get('destination', '')}\n"
            f"Data classes: {', '.join(shape.get('data_classes') or ['none'])}"
        ),
    }


def _allow_read_only_tool_call(shape: dict[str, Any], tool_name: str, args: Any) -> None:
    logger.info(
        "%s: read-only policy approved low-risk Hermes Guardian %s to %s for session %s",
        _PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        _normalize_session_id(shape.get("session_id", "")),
    )
    _emit_egress_activity(
        "auto_approved",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason="read-only low-risk",
        rule_source="read-only",
        action_detail=shape.get("action_detail", ""),
    )
    _record_allowed_tool_side_effects(shape.get("session_id", ""), tool_name, args)


def _llm_policy_tool_call_result(shape: dict[str, Any], tool_name: str, args: Any) -> tuple[dict[str, str] | None, str | None]:
    hard_reason = _llm_hard_deny_reason(shape, args)
    if hard_reason:
        logger.info(
            "%s: hard-blocked Hermes Guardian %s to %s for session %s (%s)",
            _PLUGIN_NAME,
            shape.get("action_family", ""),
            shape.get("destination", ""),
            _normalize_session_id(shape.get("session_id", "")),
            hard_reason,
        )
        _emit_egress_activity(
            "security_blocked",
            session_id=shape.get("session_id", ""),
            owner_hash=shape.get("owner_hash", ""),
            tool_name=tool_name,
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=hard_reason,
            action_detail=shape.get("action_detail", ""),
        )
        _notify_cron_failure_if_needed(
            session_id=shape.get("session_id", ""),
            tool_name=tool_name,
            decision="security_blocked",
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=hard_reason,
        )
        return {"action": "block", "message": _block_message(hard_reason)}, None

    verdict = _llm_security_verdict(shape, args)
    if verdict.get("outcome") == "allow":
        reason = (
            f"llm {verdict.get('risk_level', 'unknown')}: "
            f"{verdict.get('rationale', 'approved')}"
        )
        logger.info(
            "%s: LLM-approved Hermes Guardian %s to %s for session %s",
            _PLUGIN_NAME,
            shape.get("action_family", ""),
            shape.get("destination", ""),
            _normalize_session_id(shape.get("session_id", "")),
        )
        _emit_egress_activity(
            "auto_approved",
            session_id=shape.get("session_id", ""),
            owner_hash=shape.get("owner_hash", ""),
            tool_name=tool_name,
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=reason,
            rule_source="llm",
            action_detail=shape.get("action_detail", ""),
        )
        _record_allowed_tool_side_effects(
            shape.get("session_id", ""),
            tool_name,
            args,
            action_family=shape.get("action_family", ""),
            mark_browser_private_input=True,
        )
        return None, None

    blocked_reason = (
        f"requires approval (llm {verdict.get('risk_level', 'unknown')}: "
        f"{verdict.get('rationale', 'denied')})"
    )
    return None, blocked_reason


def _block_for_pending_approval(shape: dict[str, Any], tool_name: str, blocked_reason: str) -> dict[str, str]:
    approval = _create_pending_approval(shape)
    approval["reason"] = blocked_reason
    _save_pending_approval_to_store_unlocked(approval)
    logger.info(
        "%s: blocked Hermes Guardian %s to %s for session %s",
        _PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        _normalize_session_id(shape.get("session_id", "")),
    )
    _emit_egress_activity(
        "blocked",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=blocked_reason,
        approval_id=approval.get("id", ""),
        action_detail=shape.get("action_detail", ""),
    )
    _notify_cron_failure_if_needed(
        session_id=shape.get("session_id", ""),
        tool_name=tool_name,
        decision="blocked",
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=blocked_reason,
        approval_id=approval.get("id", ""),
    )
    return {"action": "block", "message": _guardian_block_message(approval)}


def _privacy_pre_tool_call(tool_name: str = "", args: Any = None, session_id: str = "") -> dict[str, str] | None:
    if str(tool_name or "").lower() == "browser_navigate":
        _set_browser_host(session_id, _extract_url(args))

    privacy_policy = _privacy_policy()
    action = _egress_action_for_tool(tool_name, args, session_id)

    if privacy_policy == "off":
        _allow_privacy_off_tool_call(tool_name, args, session_id, action)
        return None

    if not action:
        _emit_read_activity_if_applicable(tool_name, args, session_id)
        return None

    action_family, destination = action
    data_classes = _data_classes_for_egress(session_id, args)
    shape = _approval_shape(
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=data_classes,
        args=args,
    )
    source = _approval_source(shape)
    if source:
        if source.get("effect") == "deny":
            return _block_for_privacy_rule(shape, tool_name, source)
        _allow_approved_tool_call(shape, source, tool_name, args)
        return None

    if not data_classes:
        _allow_untainted_tool_call(
            tool_name,
            args,
            session_id,
            action_family=action_family,
            destination=destination,
        )
        return None

    if privacy_policy == "read-only" and _read_only_auto_approves(shape, args):
        _allow_read_only_tool_call(shape, tool_name, args)
        return None

    blocked_reason = "requires approval"
    if privacy_policy == "llm":
        llm_result, llm_blocked_reason = _llm_policy_tool_call_result(shape, tool_name, args)
        if llm_result is not None:
            return llm_result
        if llm_blocked_reason is None:
            return None
        blocked_reason = llm_blocked_reason

    return _block_for_pending_approval(shape, tool_name, blocked_reason)


def _privacy_observe_tool_result(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
) -> dict[str, Any] | None:
    if not isinstance(result, str) or not result:
        return None

    parsed: Any
    parsed_ok = True
    try:
        parsed = json.loads(result)
    except (TypeError, ValueError):
        parsed_ok = False
        parsed = result

    local_system_policy = (
        _consume_local_system_result_policy(session_id, tool_name)
        if _is_local_system_tool(tool_name)
        else {}
    )
    public_remote_read = bool(local_system_policy.get("remote_read"))
    taint_classes = _taint_classes_for_tool_result(
        tool_name,
        parsed,
        status=status,
        session_id=session_id,
        local_system_policy=local_system_policy,
    )
    if taint_classes:
        _taint_session(session_id, taint_classes)
        _emit_activity(
            "tainted",
            session_id=session_id,
            tool_name=tool_name,
            data_classes=taint_classes,
            reason=_taint_reason_for_tool_result(tool_name, taint_classes),
        )

    return {
        "parsed": parsed,
        "parsed_ok": parsed_ok,
        "taint_classes": taint_classes,
        "public_remote_read": public_remote_read,
    }
