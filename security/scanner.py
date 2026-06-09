"""Security-sensitive content scanning and scrubbing for Hermes Guardian."""

from __future__ import annotations

import re
from typing import Any

from language_packs.runtime import _COMPILED_LANGUAGE_PACKS, _compile_language_packs

_PLUGIN_NAME = "hermes-guardian"
_FORMER_PLUGIN_NAME = "privacy-egress-guard"
_SECURITY_RULE_ENABLED_CALLBACK: Any | None = None

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

_SECURITY_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = []
_REDACTION_MARKER_PATTERNS: list[tuple[re.Pattern[str], str]] = []

_CREDENTIAL_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws access key id"),
    (re.compile(r"(?im)^\s*AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]{32,}\s*$"), "aws secret access key"),
    (re.compile(r"\bghp_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "github token"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b"), "api key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "slack token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
    (re.compile(r"\b(?:Bearer|Refresh)\s+[A-Za-z0-9._~+/=-]{24,}\b", re.I), "bearer token"),
    (re.compile(r"(?im)^\s*(?:cookie|session(?:id)?|csrf(?:_token)?)\s*[:=]\s*[^\s#;]{12,}"), "session cookie"),
    # Password and private-key assignments are hard secrets: kept suppressed even on the
    # inbound tool-result path. Matched before the token pattern below so a name containing
    # PASSWORD/PRIVATE_KEY always classifies as a hard secret, never as a service token.
    (re.compile(r"(?im)^\s*[A-Z0-9_]*(?:PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*[^\s#]{8,}"), "password assignment"),
    # API/service token assignments (e.g. ``FOO_API_KEY=...``, ``CLIENT_SECRET=...``). These are
    # token-style credentials the agent may legitimately need to read — for instance an MCP
    # server's own auth token — so they are allowed inbound but still blocked at every egress.
    (re.compile(r"(?im)^\s*[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY)[A-Z0-9_]*\s*=\s*[^\s#]{8,}"), "secret assignment"),
]

# Credential reasons representing API/service authentication tokens. On the inbound
# tool-result path (and only there) these are read into context rather than suppressed:
# legitimate MCP/service integrations routinely surface their own tokens, and suppressing
# them at read-time breaks the integration without preventing any leak — egress remains
# guarded. Every egress surface (tool args, gateway dispatch, final response) still scans
# without this allowance. Hard secrets (private keys, AWS keys, password assignments) and
# all account-security content (OTPs, reset/recovery, magic links, ...) are intentionally
# absent here and stay suppressed even on inbound reads.
_INBOUND_ALLOWED_CREDENTIAL_REASONS = frozenset({
    "api key",
    "github token",
    "slack token",
    "bearer token",
    "jwt",
    "session cookie",
    "secret assignment",
})


def _set_security_rule_enabled_callback(callback: Any) -> None:
    global _SECURITY_RULE_ENABLED_CALLBACK
    _SECURITY_RULE_ENABLED_CALLBACK = callback


def _scanner_security_rule_enabled(rule_id: str) -> bool:
    if _SECURITY_RULE_ENABLED_CALLBACK is None:
        return True
    try:
        return bool(_SECURITY_RULE_ENABLED_CALLBACK(rule_id))
    except Exception:
        return True


def _code_context_pattern() -> re.Pattern[str]:
    return re.compile(
        _COMPILED_LANGUAGE_PACKS.auth_code_label_pattern.pattern
        + r"(?:\s*(?:is|es|=|:|-|#)\s*|\s.{0,40}?\s)"
        + r"\b(?:\d[\d -]{4,15}|[A-Z0-9]*\d[A-Z0-9 -]{4,15})\b",
        re.I | re.S,
    )


def _apply_compiled_language_packs(compiled: Any) -> None:
    global _COMPILED_LANGUAGE_PACKS, _SECURITY_SENSITIVE_PATTERNS, _REDACTION_MARKER_PATTERNS
    global _CODE_CONTEXT_RE, _PRIVATE_FIELD_RE
    _COMPILED_LANGUAGE_PACKS = compiled
    _SECURITY_SENSITIVE_PATTERNS = list(compiled.security_sensitive_patterns)
    _REDACTION_MARKER_PATTERNS = list(compiled.redaction_marker_patterns)
    _CODE_CONTEXT_RE = _code_context_pattern()
    _PRIVATE_FIELD_RE = compiled.private_field_pattern


def _set_enabled_language_packs(raw_ids: str | None = None) -> tuple[str, ...]:
    compiled = _compile_language_packs(raw_ids)
    _apply_compiled_language_packs(compiled)
    return compiled.ids


_CODE_CONTEXT_RE = _code_context_pattern()
_NUMBERED_RECORD_START_RE = re.compile(r"(?m)(?=^[^\S\r\n]*\d+[\.)][^\S\r\n]+)")
_HEADER_RECORD_START_RE = re.compile(r"(?m)(?=^[^\S\r\n]*(?:\d+[\.)][^\S\r\n]*)?(?:From|Sender):[^\S\r\n])")
_EMAIL_SHAPED_TEXT_RE = re.compile(
    r"(?im)^\s*(?:\d+[\.)]\s*)?(?:From|Sender|Subject|Unread|Labels|ID|Message ID):\s"
)

_EMAIL_ADDRESS_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PRIVATE_FIELD_RE = _COMPILED_LANGUAGE_PACKS.private_field_pattern
_apply_compiled_language_packs(_COMPILED_LANGUAGE_PACKS)

def _context(text: str, start: int, end: int, *, radius: int = 120) -> str:
    prefix = max(0, start - radius)
    suffix = min(len(text), end + radius)
    return text[prefix:suffix].replace("\n", "\\n")


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


def _sensitive_finding(
    value: Any, *, skip_reasons: frozenset[str] = frozenset()
) -> dict[str, str] | None:
    text = _stringify_for_scan(value)
    if not text:
        return None
    account_security_enabled = _scanner_security_rule_enabled("account_security_content")
    sensitive_links_enabled = _scanner_security_rule_enabled("sensitive_links")
    if _scanner_security_rule_enabled("credential_content"):
        for pattern, reason in _CREDENTIAL_PATTERNS:
            if reason in skip_reasons:
                continue
            match = pattern.search(text)
            if match:
                return {
                    "reason": reason,
                    "match": match.group(0),
                    "context": _context(text, match.start(), match.end()),
                }
    if account_security_enabled:
        for pattern, reason in _REDACTION_MARKER_PATTERNS:
            match = pattern.search(text)
            if match:
                return {
                    "reason": reason,
                    "match": match.group(0),
                    "context": _context(text, match.start(), match.end()),
                }
    redacted_match = re.search(r"\[?\s*redacted\s*\]?", text, re.I)
    if (
        redacted_match
        and account_security_enabled
        and _COMPILED_LANGUAGE_PACKS.redacted_security_context_pattern.search(text)
    ):
        return {
            "reason": "redacted security content",
            "match": redacted_match.group(0),
            "context": _context(text, redacted_match.start(), redacted_match.end()),
        }
    if account_security_enabled:
        for pattern, reason in _SECURITY_SENSITIVE_PATTERNS:
            match = pattern.search(text)
            if match:
                return {
                    "reason": reason,
                    "match": match.group(0),
                    "context": _context(text, match.start(), match.end()),
                }
    if account_security_enabled:
        match = _CODE_CONTEXT_RE.search(text)
        if match:
            return {
                "reason": "auth code",
                "match": match.group(0),
                "context": _context(text, match.start(), match.end()),
            }
    for match in re.finditer(r"https?://[^\s\"'<>]+", text, re.I):
        if (
            sensitive_links_enabled
            and _COMPILED_LANGUAGE_PACKS.security_link_term_pattern.search(match.group(0))
        ):
            return {
                "reason": "sensitive link",
                "match": match.group(0),
                "context": _context(text, match.start(), match.end()),
            }
    return None


def _sensitive_reason(
    value: Any, *, skip_reasons: frozenset[str] = frozenset()
) -> str | None:
    finding = _sensitive_finding(value, skip_reasons=skip_reasons)
    return finding["reason"] if finding else None


def _safe_stub(suppressed_count: int = 1, reason: str = "security-sensitive content") -> dict[str, Any]:
    return {
        "result": "[suppressed by hermes-guardian]",
        "hermes_guardian": {
            "suppressed": True,
            "suppressed_count": max(1, suppressed_count),
            "reason": reason,
            "former_plugin": _FORMER_PLUGIN_NAME,
        },
        "security_sensitive_filter": {
            "suppressed": True,
            "suppressed_count": max(1, suppressed_count),
            "reason": reason,
        },
    }


def _block_message(reason: str) -> str:
    return f"Blocked by {_PLUGIN_NAME}: {reason} detected in tool arguments."


def _email_shaped_text(value: str) -> bool:
    return bool(_EMAIL_SHAPED_TEXT_RE.search(value))


def _looks_like_message_record(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    keys = {str(k).lower() for k in value.keys()}
    return len(keys & _MESSAGE_KEYS) >= 2 or (
        ("subject" in keys or "snippet" in keys)
        and ("id" in keys or "messageid" in keys or "threadid" in keys)
    )


def _scrub_text_records(
    text: str,
    *,
    hide_subjectless_email_records: bool = False,
    skip_reasons: frozenset[str] = frozenset(),
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
        reason = _sensitive_reason(record, skip_reasons=skip_reasons)
        if not reason and hide_subjectless_email_records and _email_shaped_text(record):
            if not re.search(r"(?im)^\s*Subject:\s*\S", record):
                reason = "redacted sensitive email metadata"
        if reason:
            suppressed += 1
            if first_reason is None:
                first_reason = reason
            continue
        cleaned.append(record)

    if not suppressed:
        return text, suppressed, first_reason
    if not cleaned:
        return "", suppressed, first_reason
    if numbered_records:
        item_index = 0
        renumbered = []
        for record in cleaned:
            if re.match(r"^\s*\d+[\.)]\s+", record):
                item_index += 1
                record = re.sub(r"^(\s*)\d+([\.)]\s+)", rf"\g<1>{item_index}\2", record, count=1)
            renumbered.append(record)
        cleaned = renumbered
    return prefix + "".join(cleaned).strip(), suppressed, first_reason


def _scrub(
    value: Any, *, skip_reasons: frozenset[str] = frozenset()
) -> tuple[Any, int, str | None]:
    reason = _sensitive_reason(value, skip_reasons=skip_reasons)
    if _looks_like_message_record(value) and reason:
        return None, 1, reason

    if isinstance(value, dict) and reason and isinstance(value.get("result"), str):
        scrubbed_text, suppressed, text_reason = _scrub_text_records(
            value["result"], skip_reasons=skip_reasons
        )
        if suppressed and scrubbed_text.strip():
            cleaned = dict(value)
            cleaned["result"] = scrubbed_text
            meta = cleaned.get("hermes_guardian")
            if not isinstance(meta, dict):
                meta = {}
            meta.update({
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": text_reason or reason,
                "former_plugin": _FORMER_PLUGIN_NAME,
            })
            cleaned["hermes_guardian"] = meta
            cleaned["security_sensitive_filter"] = {
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": text_reason or reason,
            }
            return cleaned, suppressed, text_reason or reason
        return _safe_stub(reason=reason), 1, reason

    if isinstance(value, list):
        cleaned = []
        suppressed = 0
        first_reason = None
        for item in value:
            item_reason_pre = _sensitive_reason(item, skip_reasons=skip_reasons)
            if item_reason_pre:
                suppressed += 1
                if first_reason is None:
                    first_reason = item_reason_pre
                continue
            scrubbed, count, item_reason = _scrub(item, skip_reasons=skip_reasons)
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
            scrubbed, count, item_reason = _scrub(item, skip_reasons=skip_reasons)
            suppressed += count
            if first_reason is None and item_reason:
                first_reason = item_reason
            if count and scrubbed is None:
                continue
            cleaned[key] = scrubbed
        if suppressed:
            meta = cleaned.get("hermes_guardian")
            if not isinstance(meta, dict):
                meta = {}
            meta.update({
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": first_reason or "security-sensitive content",
                "former_plugin": _FORMER_PLUGIN_NAME,
            })
            cleaned["hermes_guardian"] = meta
            cleaned["security_sensitive_filter"] = {
                "suppressed": True,
                "suppressed_count": suppressed,
                "reason": first_reason or "security-sensitive content",
            }
        return cleaned, suppressed, first_reason

    if reason:
        return _safe_stub(reason=reason), 1, reason
    return value, 0, None
