"""Core-facing wrappers around reusable security scanning helpers."""

from __future__ import annotations

def _context(text: str, start: int, end: int, *, radius: int = 120) -> str:
    return _security._context(text, start, end, radius=radius)


def _stringify_for_scan(value: Any, *, depth: int = 0) -> str:
    return _security._stringify_for_scan(value, depth=depth)


def _sensitive_finding(value: Any) -> dict[str, str] | None:
    return _security._sensitive_finding(value)


def _sensitive_reason(value: Any) -> str | None:
    return _security._sensitive_reason(value)


def _log_unsafe_diagnostic(surface: str, value: Any) -> None:
    if not _unsafe_diagnostics_enabled():
        return
    finding = _sensitive_finding(value)
    if not finding:
        return
    logger.warning(
        "%s UNSAFE diagnostic: surface=%s reason=%s match=%r context=%r",
        _PLUGIN_NAME,
        surface,
        finding["reason"],
        finding["match"],
        finding["context"],
    )


def _safe_stub(suppressed_count: int = 1, reason: str = "security-sensitive content") -> dict[str, Any]:
    return _security._safe_stub(suppressed_count=suppressed_count, reason=reason)


def _block_message(reason: str) -> str:
    return _security._block_message(reason)


def _email_shaped_text(value: str) -> bool:
    return _security._email_shaped_text(value)


def _looks_like_message_record(value: Any) -> bool:
    return _security._looks_like_message_record(value)


def _scrub_text_records(
    text: str,
    *,
    hide_subjectless_email_records: bool = False,
) -> tuple[str, int, str | None]:
    return _security._scrub_text_records(
        text,
        hide_subjectless_email_records=hide_subjectless_email_records,
    )


def _scrub(value: Any) -> tuple[Any, int, str | None]:
    return _security._scrub(value)


def _security_pre_tool_call(tool_name: str, args: Any, session_id: str | None) -> dict[str, str] | None:
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


def _security_transform_tool_result(
    *,
    tool_name: str,
    result: str,
    parsed: Any,
    parsed_ok: bool,
    session_id: str | None,
    taint_classes: set[str],
    public_remote_read: bool,
) -> str | None:
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


def _security_pre_gateway_dispatch(event: Any = None) -> dict[str, Any] | None:
    text = getattr(event, "text", "")
    if not isinstance(text, str) or not text:
        return None
    reason = _sensitive_reason(text)
    if not reason:
        return None
    _log_unsafe_diagnostic("pre_gateway_dispatch", text)
    logger.info("%s: skipped sensitive inbound message before dispatch (%s)", _PLUGIN_NAME, reason)
    _emit_activity("security_blocked", reason=reason, tool_name="gateway_message")
    return {"action": "skip", "reason": "security-sensitive content suppressed before model dispatch"}


def _security_transform_llm_output(response_text: str = "") -> str | None:
    if not isinstance(response_text, str) or not response_text:
        return None

    reason = _sensitive_reason(response_text)
    if _email_shaped_text(response_text):
        hide_subjectless = bool(re.search(r"(?i)security-sensitive filter|Hermes Guardian|security filter|triggered", response_text))
        scrubbed_text, suppressed, record_reason = _scrub_text_records(
            response_text,
            hide_subjectless_email_records=hide_subjectless,
        )
        if suppressed and scrubbed_text != response_text:
            _log_unsafe_diagnostic("transform_llm_output", response_text)
            logger.info("%s: suppressed %d sensitive final response record(s)", _PLUGIN_NAME, suppressed)
            _emit_activity("security_suppressed", tool_name="llm_output", reason=record_reason or reason or "security-sensitive response")
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

    if not reason:
        return None
    _log_unsafe_diagnostic("transform_llm_output", response_text)
    logger.info("%s: suppressed sensitive final response (%s)", _PLUGIN_NAME, reason)
    _emit_activity("security_suppressed", tool_name="llm_output", reason=reason)
    return "[hermes-guardian omitted security-sensitive final response.]"
