"""Suppress security-sensitive content before it reaches the model.

This plugin is intentionally local to ~/.hermes/plugins so Hermes updates do
not overwrite it. It filters:

* All tool results through transform_tool_result.
* All gateway inbound messages through pre_gateway_dispatch.

The policy is deterministic and intentionally conservative: if a single
unstructured result looks like a password reset, OTP, magic link, or account
security email, the whole result is replaced with a safe stub. For structured
lists of message-like dicts, only matching message records are removed.
"""

from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from typing import Any

logger = logging.getLogger(__name__)

_PLUGIN_NAME = "email-sensitive-filter"

_TEXT_KEYS = {
    "body",
    "content",
    "date",
    "from",
    "html",
    "message",
    "result",
    "sender",
    "snippet",
    "subject",
    "text",
    "to",
}

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
    (re.compile(r"\bpassword\s+(reset|change|recovery)\b", re.I), "password reset"),
    (re.compile(r"\breset\s+(your|the|my)?\s*password\b", re.I), "password reset"),
    (re.compile(r"\bforgot\s+(your|my)?\s*password\b", re.I), "password recovery"),
    (re.compile(r"\baccount\s+recovery\b", re.I), "account recovery"),
    (re.compile(r"\b(recovery|security|verification|authentication|login|sign[- ]?in)\s+code\b", re.I), "auth code"),
    (re.compile(r"\b(one[- ]?time|temporary)\s+(password|passcode|code)\b", re.I), "one-time code"),
    (re.compile(r"\bOTP\b", re.I), "otp"),
    (re.compile(r"\b(2FA|two[- ]?factor|multi[- ]?factor)\b", re.I), "multi-factor auth"),
    (re.compile(r"\bmagic\s+link\b", re.I), "magic link"),
    (re.compile(r"\bverify\s+(your\s+)?(email|account|identity)\b", re.I), "account verification"),
    (re.compile(r"\bconfirm\s+(your\s+)?(email|account|identity)\b", re.I), "account confirmation"),
    (re.compile(r"\bsecurity\s+alert\b", re.I), "security alert"),
    (re.compile(r"\bnew\s+(sign[- ]?in|login)\b", re.I), "new login alert"),
    (re.compile(r"\bsuspicious\s+(sign[- ]?in|login|activity)\b", re.I), "suspicious activity"),
    (re.compile(r"\bunauthori[sz]ed\s+(sign[- ]?in|login|activity)\b", re.I), "unauthorized activity"),
    (re.compile(r"https?://[^\s\"'<>]*(reset|recover|verify|confirm|magic|otp|2fa)[^\s\"'<>]*", re.I), "sensitive link"),
]

_CODE_CONTEXT_RE = re.compile(
    r"\b(code|otp|passcode|pin)\b.{0,80}\b[A-Z0-9][A-Z0-9 -]{4,15}\b",
    re.I | re.S,
)


def _safe_stub(suppressed_count: int = 1, reason: str = "security-sensitive content") -> dict[str, Any]:
    return {
        "result": "[suppressed by email-sensitive-filter]",
        "email_sensitive_filter": {
            "suppressed": True,
            "suppressed_count": max(1, suppressed_count),
            "reason": reason,
        },
    }


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
        parts = []
        for key, val in value.items():
            key_s = str(key).lower()
            if key_s in _TEXT_KEYS or any(token in key_s for token in ("body", "content", "sender", "snippet", "subject")):
                parts.append(_stringify_for_scan(val, depth=depth + 1))
        return "\n".join(p for p in parts if p)
    return str(value)


def _sensitive_reason(value: Any) -> str | None:
    text = _stringify_for_scan(value)
    if not text:
        return None
    for pattern, reason in _SENSITIVE_PATTERNS:
        if pattern.search(text):
            return reason
    if _CODE_CONTEXT_RE.search(text):
        return "auth code"
    return None


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
        return _safe_stub(reason=reason), 1, reason

    if isinstance(value, list):
        cleaned = []
        suppressed = 0
        first_reason = None
        for item in value:
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
            meta = cleaned.get("email_sensitive_filter")
            if not isinstance(meta, dict):
                meta = {}
            meta.update({
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": first_reason or "security-sensitive email",
            })
            cleaned["email_sensitive_filter"] = meta
        return cleaned, suppressed, first_reason

    if reason:
        return _safe_stub(reason=reason), 1, reason
    return value, 0, None


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
        return json.dumps(_safe_stub(reason=reason), ensure_ascii=False)

    scrubbed, suppressed, reason = _scrub(deepcopy(parsed))
    if not suppressed:
        return None

    if scrubbed is None:
        scrubbed = _safe_stub(suppressed, reason or "security-sensitive email")
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
    logger.info("%s: skipped sensitive inbound email before dispatch (%s)", _PLUGIN_NAME, reason)
    return {"action": "skip", "reason": "security-sensitive content suppressed before model dispatch"}


def register(ctx) -> None:
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
