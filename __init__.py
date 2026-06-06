"""Suppress security-sensitive content before it reaches the model.

This plugin is intentionally local to ~/.hermes/plugins so Hermes updates do
not overwrite it. It filters:

* All tool calls through pre_tool_call.
* All tool results through transform_tool_result.
* All gateway inbound messages through pre_gateway_dispatch.

The policy is deterministic and intentionally conservative: every value in a
tool result or gateway message is scanned. If a single unstructured result
looks like a password reset, OTP, magic link, or account security email, the
whole result is replaced with a safe stub. For structured lists, matching
items are removed entirely.
"""

from __future__ import annotations

import json
import logging
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PLUGIN_NAME = "security-sensitive-filter"
_UNSAFE_DIAGNOSTICS_FLAG = Path(__file__).with_name(".unsafe-diagnostics")

_MESSAGE_KEYS = {
    "body",
    "from",
    "html",
    "message_id",
    "sender",
    "snippet",
    "subject",
    "thread_id",
}

_SENSITIVE_PATTERNS = [
    (re.compile(r"\[\s*sensitive\s+email\s+subject\s+redacted\s*\]", re.I), "redacted sensitive email"),
    (re.compile(r"\[\s*sensitive\s+email\s+(?:content|body|message)\s+redacted\s*\]", re.I), "redacted sensitive email"),
    (re.compile(r"\[\s*redacted\s+sensitive\s+(?:email\s+)?subject\s*\]", re.I), "redacted sensitive email"),
    (re.compile(r"\bpassword\s+(reset|change|recovery)\b", re.I), "password reset"),
    (re.compile(r"\breset\s+(your|the|my)?\s*password\b", re.I), "password reset"),
    (re.compile(r"\bforgot\s+(your|my)?\s*password\b", re.I), "password recovery"),
    (re.compile(r"\baccount\s+recovery\b", re.I), "account recovery"),
    (re.compile(r"\b(recovery|security|verification|authentication|login|sign[- ]?in)\s+code\b", re.I), "auth code"),
    (re.compile(r"\b(one[- ]?time|temporary)\s+(password|passcode|code)\b", re.I), "one-time code"),
    (re.compile(r"\bone[- ]?time\b.{0,80}\[?\s*redacted\s*\]?", re.I | re.S), "one-time code"),
    (re.compile(r"\bOTP\b", re.I), "otp"),
    (re.compile(r"\b(2FA|two[- ]?factor|multi[- ]?factor)\b", re.I), "multi-factor auth"),
    (re.compile(r"\bmagic\s+link\b", re.I), "magic link"),
    (re.compile(r"\b(public|ssh|gpg|deploy)\s+key\b.{0,120}\b(added|created|removed|deleted|changed)\b", re.I | re.S), "security key change"),
    (re.compile(r"\b(added|created|removed|deleted|changed)\b.{0,120}\b(public|ssh|gpg|deploy)\s+key\b", re.I | re.S), "security key change"),
    (re.compile(r"\bverify\s+(your\s+)?(email|account|identity)\b", re.I), "account verification"),
    (re.compile(r"\bconfirm\s+(your\s+)?(email|account|identity)\b", re.I), "account confirmation"),
    (re.compile(r"\bsecurity\s+alert\b", re.I), "security alert"),
    (re.compile(r"\bnew\s+(sign[- ]?in|login)\b", re.I), "new login alert"),
    (re.compile(r"\bsuspicious\s+(sign[- ]?in|login|activity)\b", re.I), "suspicious activity"),
    (re.compile(r"\bunauthori[sz]ed\s+(sign[- ]?in|login|activity)\b", re.I), "unauthorized activity"),
    (re.compile(r"\b(password|reset|recover|verify|verification|auth|authentication|login|sign[- ]?in|one[- ]?time|otp|2fa|token|passcode|code|security|magic|key)\b.{0,120}\[?\s*redacted\s*\]?", re.I | re.S), "redacted security content"),
    (re.compile(r"\[?\s*redacted\s*\]?.{0,120}\b(password|reset|recover|verify|verification|auth|authentication|login|sign[- ]?in|one[- ]?time|otp|2fa|token|passcode|code|security|magic|key)\b", re.I | re.S), "redacted security content"),
    (re.compile(r"https?://[^\s\"'<>]*(reset|recover|verify|confirm|magic|otp|2fa)[^\s\"'<>]*", re.I), "sensitive link"),
]

_CODE_CONTEXT_RE = re.compile(
    r"\b(code|otp|passcode|pin)\b.{0,80}\b[A-Z0-9][A-Z0-9 -]{4,15}\b",
    re.I | re.S,
)
_NUMBERED_RECORD_START_RE = re.compile(r"(?m)(?=^\s*\d+[\.)]\s+)")
_HEADER_RECORD_START_RE = re.compile(r"(?m)(?=^\s*(?:\d+[\.)]\s*)?(?:From|Sender):\s)")
_EMAIL_SHAPED_TEXT_RE = re.compile(
    r"(?im)^\s*(?:\d+[\.)]\s*)?(?:From|Sender|Subject|Unread|Labels|ID):\s"
)


def _unsafe_diagnostics_enabled() -> bool:
    return _UNSAFE_DIAGNOSTICS_FLAG.exists() or os.getenv(
        "SECURITY_SENSITIVE_FILTER_UNSAFE_DIAGNOSTICS", ""
    ).lower() in {"1", "true", "yes", "on"}


def _context(text: str, start: int, end: int, *, radius: int = 120) -> str:
    prefix = max(0, start - radius)
    suffix = min(len(text), end + radius)
    return text[prefix:suffix].replace("\n", "\\n")


def _sensitive_finding(value: Any) -> dict[str, str] | None:
    text = _stringify_for_scan(value)
    if not text:
        return None
    for pattern, reason in _SENSITIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            return {
                "reason": reason,
                "match": match.group(0),
                "context": _context(text, match.start(), match.end()),
            }
    match = _CODE_CONTEXT_RE.search(text)
    if match:
        return {
            "reason": "auth code",
            "match": match.group(0),
            "context": _context(text, match.start(), match.end()),
        }
    return None


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
    return {
        "result": "[suppressed by security-sensitive-filter]",
        "security_sensitive_filter": {
            "suppressed": True,
            "suppressed_count": max(1, suppressed_count),
            "reason": reason,
        },
    }


def _block_message(reason: str) -> str:
    return f"Blocked by security-sensitive-filter: {reason} detected in tool arguments."


def _stringify_for_scan(value: Any, *, depth: int = 0) -> str:
    if value is None or depth > 6:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "\n".join(_stringify_for_scan(v, depth=depth + 1) for v in value[:50])
    if isinstance(value, dict):
        parts = [_stringify_for_scan(val, depth=depth + 1) for val in value.values()]
        return "\n".join(p for p in parts if p)
    return str(value)


def _sensitive_reason(value: Any) -> str | None:
    finding = _sensitive_finding(value)
    return finding["reason"] if finding else None


def _scrub_text_records(
    text: str,
    *,
    hide_subjectless_email_records: bool = False,
) -> tuple[str, int, str | None]:
    """Remove sensitive records from plaintext batches when records are obvious."""
    starts = [match.start() for match in _NUMBERED_RECORD_START_RE.finditer(text)]
    numbered_records = len(starts) >= 2
    if not numbered_records:
        starts = [match.start() for match in _HEADER_RECORD_START_RE.finditer(text)]
    if len(starts) < 2:
        return text, 0, None

    prefix = text[:starts[0]]
    records = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        records.append(text[start:end])

    cleaned = []
    suppressed = 0
    first_reason = None
    for record in records:
        reason = _sensitive_reason(record)
        if not reason and hide_subjectless_email_records and _email_shaped_text(record):
            if not re.search(r"(?im)^\s*Subject:\s*\S", record):
                reason = "redacted sensitive email metadata"
        if reason:
            suppressed += 1
            if first_reason is None:
                first_reason = reason
            continue
        cleaned.append(record)

    if not suppressed or not cleaned:
        return text, suppressed, first_reason
    if numbered_records:
        item_index = 0
        renumbered = []
        for record in cleaned:
            if re.match(r"^\s*\d+[\.)]\s+", record):
                item_index += 1
                record = re.sub(r"^(\s*)\d+([\.)]\s+)", rf"\g<1>{item_index}\2", record, count=1)
            renumbered.append(record)
        cleaned = [
            record for record in renumbered
        ]
    return prefix + "".join(cleaned).strip(), suppressed, first_reason


def _email_shaped_text(value: str) -> bool:
    return bool(_EMAIL_SHAPED_TEXT_RE.search(value))


def _looks_like_message_record(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    keys = {str(k).lower() for k in value.keys()}
    return len(keys & _MESSAGE_KEYS) >= 2 or (
        ("subject" in keys or "snippet" in keys) and ("id" in keys or "messageid" in keys or "threadid" in keys)
    )


def _scrub(value: Any) -> tuple[Any, int, str | None]:
    reason = _sensitive_reason(value)
    if _looks_like_message_record(value) and reason:
        return None, 1, reason

    if isinstance(value, dict) and reason and isinstance(value.get("result"), str):
        scrubbed_text, suppressed, text_reason = _scrub_text_records(value["result"])
        if suppressed and scrubbed_text.strip():
            cleaned = dict(value)
            cleaned["result"] = scrubbed_text
            meta = cleaned.get("security_sensitive_filter")
            if not isinstance(meta, dict):
                meta = {}
            meta.update({
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": text_reason or reason,
            })
            cleaned["security_sensitive_filter"] = meta
            return cleaned, suppressed, text_reason or reason
        return _safe_stub(reason=reason), 1, reason

    if isinstance(value, list):
        cleaned = []
        suppressed = 0
        first_reason = None
        for item in value:
            item_reason_pre = _sensitive_reason(item)
            if item_reason_pre:
                suppressed += 1
                if first_reason is None:
                    first_reason = item_reason_pre
                continue
            scrubbed, count, item_reason = _scrub(item)
            suppressed += count
            if first_reason is None and item_reason:
                first_reason = item_reason
            if count and scrubbed is None:
                continue
            cleaned.append(scrubbed)
        return cleaned, suppressed, first_reason

    if isinstance(value, dict):
        cleaned = {}
        suppressed = 0
        first_reason = None
        for key, item in value.items():
            scrubbed, count, item_reason = _scrub(item)
            suppressed += count
            if first_reason is None and item_reason:
                first_reason = item_reason
            if count and scrubbed is None:
                continue
            cleaned[key] = scrubbed
        if suppressed:
            meta = cleaned.get("security_sensitive_filter")
            if not isinstance(meta, dict):
                meta = {}
            meta.update({
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": first_reason or "security-sensitive content",
            })
            cleaned["security_sensitive_filter"] = meta
        return cleaned, suppressed, first_reason

    if reason:
        return _safe_stub(reason=reason), 1, reason
    return value, 0, None


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    **_: Any,
) -> dict[str, str] | None:
    """Block sensitive tool calls before browser/web/MCP tools can execute."""
    reason = _sensitive_reason(args)
    if not reason:
        return None
    _log_unsafe_diagnostic(f"pre_tool_call:{tool_name}", args)
    logger.info("%s: blocked sensitive tool call to %s (%s)", _PLUGIN_NAME, tool_name, reason)
    return {"action": "block", "message": _block_message(reason)}


def _on_transform_tool_result(
    tool_name: str = "",
    result: Any = None,
    **_: Any,
) -> str | None:
    """Rewrite sensitive tool results before they enter model history."""
    if not isinstance(result, str) or not result:
        return None

    try:
        parsed = json.loads(result)
    except (TypeError, ValueError):
        reason = _sensitive_reason(result)
        if not reason:
            return None
        _log_unsafe_diagnostic(f"transform_tool_result:{tool_name}", result)
        scrubbed_text, suppressed, text_reason = _scrub_text_records(result)
        if suppressed and scrubbed_text.strip():
            return json.dumps({
                "result": scrubbed_text,
                "security_sensitive_filter": {
                    "suppressed": True,
                    "suppressed_count": suppressed,
                    "reason": text_reason or reason,
                },
            }, ensure_ascii=False)
        return json.dumps(_safe_stub(reason=reason), ensure_ascii=False)

    scrubbed, suppressed, reason = _scrub(deepcopy(parsed))
    if not suppressed:
        return None

    _log_unsafe_diagnostic(f"transform_tool_result:{tool_name}", parsed)
    if scrubbed is None:
        scrubbed = _safe_stub(suppressed, reason or "security-sensitive content")
    logger.info("%s: suppressed %d sensitive record(s) from %s", _PLUGIN_NAME, suppressed, tool_name)
    return json.dumps(scrubbed, ensure_ascii=False)


def _on_pre_gateway_dispatch(event: Any = None, **_: Any) -> dict[str, Any] | None:
    """Drop inbound gateway messages that look security-sensitive."""
    text = getattr(event, "text", "")
    if not isinstance(text, str) or not text:
        return None

    reason = _sensitive_reason(text)
    if not reason:
        return None
    _log_unsafe_diagnostic("pre_gateway_dispatch", text)
    logger.info("%s: skipped sensitive inbound message before dispatch (%s)", _PLUGIN_NAME, reason)
    return {"action": "skip", "reason": "security-sensitive content suppressed before model dispatch"}


def _on_transform_llm_output(response_text: str = "", **_: Any) -> str | None:
    """Remove sensitive email rows from final responses if upstream already summarized them."""
    if not isinstance(response_text, str) or not response_text or not _email_shaped_text(response_text):
        return None

    hide_subjectless = bool(re.search(r"(?i)security-sensitive filter|security filter|triggered", response_text))
    scrubbed_text, suppressed, reason = _scrub_text_records(
        response_text,
        hide_subjectless_email_records=hide_subjectless,
    )
    if not suppressed or not scrubbed_text.strip() or scrubbed_text == response_text:
        return None

    _log_unsafe_diagnostic("transform_llm_output", response_text)
    logger.info("%s: suppressed %d sensitive final response record(s)", _PLUGIN_NAME, suppressed)
    return (
        scrubbed_text.rstrip()
        + "\n\n[security-sensitive-filter omitted "
        + str(suppressed)
        + " security-sensitive email record(s).]"
    )


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
    ctx.register_hook("transform_llm_output", _on_transform_llm_output)
