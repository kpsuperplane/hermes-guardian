"""Hermes hook implementations for security filtering and egress policy."""

from __future__ import annotations

def _on_pre_llm_call(
    session_id: str = "",
    platform: str = "",
    sender_id: str = "",
    **_: Any,
) -> None:
    owner_hash = _hash_identity(platform or "cli", sender_id or "")
    _ensure_session(session_id, owner_hash)
    return None


def _security_block_for_tool_call(tool_name: str, args: Any, session_id: str | None) -> dict[str, str] | None:
    reason = _sensitive_reason(args)
    if not reason:
        return None
    _log_unsafe_diagnostic(f"pre_tool_call:{tool_name}", args)
    logger.info("%s: blocked sensitive tool call to %s (%s)", _PLUGIN_NAME, tool_name, reason)
    _emit_activity(
        "security_blocked",
        session_id=session_id,
        tool_name=tool_name,
        reason=reason,
        action_detail=_activity_action_detail(tool_name, args),
    )
    _notify_cron_failure_if_needed(
        session_id=session_id,
        tool_name=tool_name,
        decision="security_blocked",
        reason=reason,
    )
    return {"action": "block", "message": _block_message(reason)}


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
        action_detail=action_detail,
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
        action_detail=shape.get("action_detail", ""),
    )
    _record_allowed_tool_side_effects(
        shape.get("session_id", ""),
        tool_name,
        args,
        action_family=shape.get("action_family", ""),
        mark_browser_private_input=True,
    )


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


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    session_id: str = "",
    **_: Any,
) -> dict[str, str] | None:
    """Block security-sensitive args and approval-gate Hermes Guardian."""
    security_block = _security_block_for_tool_call(tool_name, args, session_id)
    if security_block:
        return security_block

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
    if not data_classes:
        _allow_untainted_tool_call(
            tool_name,
            args,
            session_id,
            action_family=action_family,
            destination=destination,
        )
        return None

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
        _allow_approved_tool_call(shape, source, tool_name, args)
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


def _on_transform_tool_result(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
    **_: Any,
) -> str | None:
    """Rewrite sensitive tool results and taint sessions on private reads."""
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

    if not parsed_ok:
        reason = None if public_remote_read else _sensitive_reason(result)
        if not reason:
            return None
        _log_unsafe_diagnostic(f"transform_tool_result:{tool_name}", result)
        scrubbed_text, suppressed, text_reason = _scrub_text_records(result)
        if suppressed and scrubbed_text.strip():
            _emit_activity(
                "security_suppressed",
                session_id=session_id,
                tool_name=tool_name,
                data_classes=taint_classes,
                reason=text_reason or reason,
            )
            return json.dumps({
                "result": scrubbed_text,
                "hermes_guardian": {
                    "suppressed": True,
                    "suppressed_count": suppressed,
                    "reason": text_reason or reason,
                    "former_plugin": _FORMER_PLUGIN_NAME,
                },
                "security_sensitive_filter": {
                    "suppressed": True,
                    "suppressed_count": suppressed,
                    "reason": text_reason or reason,
                },
            }, ensure_ascii=False)
        _emit_activity(
            "security_suppressed",
            session_id=session_id,
            tool_name=tool_name,
            data_classes=taint_classes,
            reason=reason,
        )
        return json.dumps(_safe_stub(reason=reason), ensure_ascii=False)

    if public_remote_read:
        return None

    scrubbed, suppressed, reason = _scrub(deepcopy(parsed))
    if not suppressed:
        return None

    _log_unsafe_diagnostic(f"transform_tool_result:{tool_name}", parsed)
    if scrubbed is None:
        scrubbed = _safe_stub(suppressed, reason or "security-sensitive content")
    logger.info("%s: suppressed %d sensitive record(s) from %s", _PLUGIN_NAME, suppressed, tool_name)
    _emit_activity(
        "security_suppressed",
        session_id=session_id,
        tool_name=tool_name,
        data_classes=taint_classes,
        reason=reason or "security-sensitive content",
    )
    return json.dumps(scrubbed, ensure_ascii=False)


def _on_pre_gateway_dispatch(event: Any = None, **_: Any) -> dict[str, Any] | None:
    """Drop sensitive inbound messages and remember /guardian command owners."""
    text = getattr(event, "text", "")
    if not isinstance(text, str) or not text:
        return None

    if text.strip().lower().startswith("/guardian"):
        raw_args = text.strip()[len("/guardian"):].strip()
        _remember_command_owner(raw_args, _owner_hash_from_event(event))
        return None

    reason = _sensitive_reason(text)
    if not reason:
        return None
    _log_unsafe_diagnostic("pre_gateway_dispatch", text)
    logger.info("%s: skipped sensitive inbound message before dispatch (%s)", _PLUGIN_NAME, reason)
    _emit_activity("security_blocked", reason=reason, tool_name="gateway_message")
    return {"action": "skip", "reason": "security-sensitive content suppressed before model dispatch"}


def _on_transform_llm_output(response_text: str = "", **_: Any) -> str | None:
    """Remove sensitive email rows from final responses if upstream already summarized them."""
    if not isinstance(response_text, str) or not response_text or not _email_shaped_text(response_text):
        return None

    hide_subjectless = bool(re.search(r"(?i)security-sensitive filter|Hermes Guardian|security filter|triggered", response_text))
    scrubbed_text, suppressed, reason = _scrub_text_records(
        response_text,
        hide_subjectless_email_records=hide_subjectless,
    )
    if not suppressed or scrubbed_text == response_text:
        return None

    _log_unsafe_diagnostic("transform_llm_output", response_text)
    logger.info("%s: suppressed %d sensitive final response record(s)", _PLUGIN_NAME, suppressed)
    _emit_activity("security_suppressed", tool_name="llm_output", reason=reason or "security-sensitive response")
    if not scrubbed_text.strip():
        return (
            "[hermes-guardian omitted "
            + str(suppressed)
            + " security-sensitive email record(s).]"
        )
    return (
        scrubbed_text.rstrip()
        + "\n\n[hermes-guardian omitted "
        + str(suppressed)
        + " security-sensitive email record(s).]"
    )
