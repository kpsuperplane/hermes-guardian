"""Core-facing wrappers around reusable security scanning helpers."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from .. import core
from ..integrations import cron_notifications
from ..privacy import action_details
from ..runtime import activity_store


def _context(text: str, start: int, end: int, *, radius: int = 120) -> str:
    return core._security._context(text, start, end, radius=radius)


def _stringify_for_scan(value: Any, *, depth: int = 0) -> str:
    return core._security._stringify_for_scan(value, depth=depth)


def _sensitive_finding(
    value: Any, *, skip_reasons: frozenset[str] = frozenset()
) -> dict[str, str] | None:
    return core._security._sensitive_finding(value, skip_reasons=skip_reasons)


def _sensitive_reason(
    value: Any, *, skip_reasons: frozenset[str] = frozenset()
) -> str | None:
    return core._security._sensitive_reason(value, skip_reasons=skip_reasons)


def _log_unsafe_diagnostic(surface: str, value: Any) -> None:
    if not core._unsafe_diagnostics_enabled():
        return
    finding = _sensitive_finding(value)
    if not finding:
        return
    core.logger.warning(
        "%s UNSAFE diagnostic: surface=%s reason=%s match=%r context=%r",
        core._PLUGIN_NAME,
        surface,
        finding["reason"],
        finding["match"],
        finding["context"],
    )


def _safe_stub(suppressed_count: int = 1, reason: str = "security-sensitive content") -> dict[str, Any]:
    return core._security._safe_stub(suppressed_count=suppressed_count, reason=reason)


def _block_message(reason: str) -> str:
    return core._security._block_message(reason)


def _email_shaped_text(value: str) -> bool:
    return core._security._email_shaped_text(value)


def _looks_like_message_record(value: Any) -> bool:
    return core._security._looks_like_message_record(value)


def _scrub_text_records(
    text: str,
    *,
    hide_subjectless_email_records: bool = False,
    skip_reasons: frozenset[str] = frozenset(),
) -> tuple[str, int, str | None]:
    return core._security._scrub_text_records(
        text,
        hide_subjectless_email_records=hide_subjectless_email_records,
        skip_reasons=skip_reasons,
    )


def _scrub(
    value: Any, *, skip_reasons: frozenset[str] = frozenset()
) -> tuple[Any, int, str | None]:
    return core._security._scrub(value, skip_reasons=skip_reasons)


def _security_pre_tool_call(tool_name: str, args: Any, session_id: str | None) -> dict[str, str] | None:
    reason = _sensitive_reason(args)
    if not reason:
        return None
    _log_unsafe_diagnostic(f"pre_tool_call:{tool_name}", args)
    core.logger.info("%s: blocked sensitive tool call to %s (%s)", core._PLUGIN_NAME, tool_name, reason)
    activity_store._emit_activity(
        "security_blocked",
        session_id=session_id,
        tool_name=tool_name,
        reason=reason,
        action_detail=action_details._activity_action_detail(tool_name, args),
    )
    cron_notifications._notify_cron_failure_if_needed(
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
    is_reference_read: bool = False,
) -> str | None:
    # Inbound reads may carry API/service tokens the agent legitimately needs (e.g. an MCP
    # server's own auth token). Suppressing them at read-time breaks the integration without
    # preventing a leak — every egress surface still scans at full strictness. Hard secrets
    # and account-security content stay suppressed here; see _INBOUND_ALLOWED_CREDENTIAL_REASONS.
    inbound_allowed = core._security._INBOUND_ALLOWED_CREDENTIAL_REASONS
    if is_reference_read:
        # Provably-reference reads (skill docs, skills-tree files) carry benign URLs whose
        # paths match security terms; suppressing the whole doc is a false positive. Skip
        # "sensitive link" here only — egress surfaces still scan it. A generic MCP doc-read of
        # unknown provenance does NOT get this skip (conservative until declared; see
        # tool_policy._is_reference_read). See _DOC_READ_INBOUND_ALLOWED_REASONS.
        inbound_allowed = inbound_allowed | core._security._DOC_READ_INBOUND_ALLOWED_REASONS
    if not parsed_ok:
        reason = None if public_remote_read else _sensitive_reason(result, skip_reasons=inbound_allowed)
        if not reason:
            return None
        _log_unsafe_diagnostic(f"transform_tool_result:{tool_name}", result)
        scrubbed_text, suppressed, text_reason = _scrub_text_records(result, skip_reasons=inbound_allowed)
        if suppressed and scrubbed_text.strip():
            activity_store._emit_activity(
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
                    "former_plugin": core._FORMER_PLUGIN_NAME,
                },
                "security_sensitive_filter": {
                    "suppressed": True,
                    "suppressed_count": suppressed,
                    "reason": text_reason or reason,
                },
            }, ensure_ascii=False)
        activity_store._emit_activity(
            "security_suppressed",
            session_id=session_id,
            tool_name=tool_name,
            data_classes=taint_classes,
            reason=reason,
        )
        return json.dumps(_safe_stub(reason=reason), ensure_ascii=False)

    if public_remote_read:
        return None

    scrubbed, suppressed, reason = _scrub(deepcopy(parsed), skip_reasons=inbound_allowed)
    if not suppressed:
        return None

    _log_unsafe_diagnostic(f"transform_tool_result:{tool_name}", parsed)
    if scrubbed is None:
        scrubbed = _safe_stub(suppressed, reason or "security-sensitive content")
    core.logger.info("%s: suppressed %d sensitive record(s) from %s", core._PLUGIN_NAME, suppressed, tool_name)
    activity_store._emit_activity(
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
    core.logger.info("%s: skipped sensitive inbound message before dispatch (%s)", core._PLUGIN_NAME, reason)
    activity_store._emit_activity("security_blocked", reason=reason, tool_name="gateway_message")
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
            core.logger.info("%s: suppressed %d sensitive final response record(s)", core._PLUGIN_NAME, suppressed)
            activity_store._emit_activity("security_suppressed", tool_name="llm_output", reason=record_reason or reason or "security-sensitive response")
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
    core.logger.info("%s: suppressed sensitive final response (%s)", core._PLUGIN_NAME, reason)
    activity_store._emit_activity("security_suppressed", tool_name="llm_output", reason=reason)
    return "[hermes-guardian omitted security-sensitive final response.]"
