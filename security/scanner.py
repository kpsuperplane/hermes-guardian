"""Security-sensitive content scanning and scrubbing for Hermes Guardian."""

from __future__ import annotations

import re
import unicodedata
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

# The distinct reasons (category names) produced by _SECURITY_SENSITIVE_PATTERNS — the
# account-security phrase categories (password reset, account recovery, OTP, magic link,
# MFA, account verification, ...). Recomputed whenever language packs are (re)compiled.
# Passed as skip_reasons by callers that want to suppress phrase matching while keeping
# sensitive-link and hard-credential detection (see _security_transform_tool_result's
# web_extract path).
_SECURITY_SENSITIVE_REASONS: frozenset[str] = frozenset()

# Whether a ``NAME = value`` assignment is a hardcoded secret is decided by the VALUE
# SHAPE, not by the variable name. The name suffix (``_path``/``_url``/...) is not trusted
# to exempt an assignment on its own: ``api_token_url = abcdef1234567890...`` (a bare
# opaque token) and ``DB_PASSWORD = ('hunter2hunter2')`` (a parenthesized literal) are real
# secrets a ``_url`` name or wrapping parens must not launder past us.
#
# ``_VALUE_NOT_A_SECRET`` is a negative lookahead placed right after ``=\s*`` (at the start
# of the value). It FAILS the assignment match — i.e. exempts the line — only when the
# value is one of three non-credential shapes:
#   (a) a URL / scheme  (``https://``, ``s3://``, ``file://``, ...),
#   (b) a filesystem path  (starts with ``/``, ``~``, ``./``, ``../`` — after any wrapping
#       quote/paren — or the unquoted value contains a ``/`` path separator), or
#   (c) a call/subscript EXPRESSION that *derives* a secret rather than being one
#       (``os.environ['KEY']``, ``json.loads(...)``, ``resp.json()['token']``, ...).
# A *literal* value — bare (``hunter2hunter2``) or wrapped in quotes/parens/brackets
# (``('abcdef1234567890')``, ``["x"]``) — is NOT exempt: the leading openers/quotes are
# stripped before the shape is judged, so a wrapped opaque literal still matches. This
# replaces "any bracket anywhere disqualifies", which let ``API_TOKEN = ('...')`` through.
_VALUE_WRAP_OPENERS = r"""[('"\[\s]*"""
_VALUE_URL_SHAPE = r"[A-Za-z][A-Za-z0-9+.-]*://"
_VALUE_PATH_START = r"(?:~|\.{1,2}/|/)"
_VALUE_CALL_EXPR = r"\w[\w.]*\s*[([]"
_VALUE_NOT_A_SECRET = (
    r"(?!"
    + _VALUE_WRAP_OPENERS
    + r"(?:" + _VALUE_URL_SHAPE + r"|" + _VALUE_PATH_START + r"|" + _VALUE_CALL_EXPR + r"))"
    # Also exempt an unquoted value that carries a ``/`` path separator (a bare path); a
    # quoted opaque literal has its closing run start with a quote, so this stops short.
    + r"(?![^\s#'\"]*/)"
)

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
    # PASSWORD/PRIVATE_KEY always classifies as a hard secret, never as a service token. The
    # value-shape exemption still applies (``reset_password_url = "https://..."`` is a URL,
    # not a secret), but a bare opaque value is never laundered by a ``_url``/handle name.
    (re.compile(r"(?im)^\s*[A-Z0-9_]*(?:PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*" + _VALUE_NOT_A_SECRET + r"[^\s#]{8,}"), "password assignment"),
    # API/service token assignments (e.g. ``FOO_API_KEY=...``, ``CLIENT_SECRET=...``). These are
    # token-style credentials the agent may legitimately need to read — for instance an MCP
    # server's own auth token — so they are allowed inbound but still blocked at every egress.
    (re.compile(r"(?im)^\s*[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY)[A-Z0-9_]*\s*=\s*" + _VALUE_NOT_A_SECRET + r"[^\s#]{8,}"), "secret assignment"),
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

# Provably-reference reads (skill docs, skills-tree files) are reference material by nature
# and routinely embed benign URLs whose paths contain security terms (``/verify``,
# ``/confirm``, OAuth 2FA settings pages, ...). A URL in such a doc is not a leak — and the
# ``sensitive_links`` rule suppressing the whole doc breaks the agent's ability to use the
# skill. So on the inbound read path ONLY, reference reads skip the "sensitive link" reason
# (see _DOC_READ_INBOUND_ALLOWED_REASONS) plus account-security phrase categories added by the
# caller. The reference verdict is *provenance*-based and is computed by
# privacy/tool_policy._is_reference_read (the only place with the call's args) and passed into
# _security_transform_tool_result — a generic MCP doc-read of unknown provenance does NOT
# qualify. Concrete auth-code shapes, redaction markers, and hard secrets stay suppressed even
# in docs; every egress surface still scans at full strictness.
_DOC_READ_INBOUND_ALLOWED_REASONS = frozenset({"sensitive link"})


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
    global _CODE_CONTEXT_RE, _PRIVATE_FIELD_RE, _SECURITY_SENSITIVE_REASONS
    _COMPILED_LANGUAGE_PACKS = compiled
    _SECURITY_SENSITIVE_PATTERNS = list(compiled.security_sensitive_patterns)
    _SECURITY_SENSITIVE_REASONS = frozenset(reason for _, reason in _SECURITY_SENSITIVE_PATTERNS)
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

# Magic/login-link detector: a ``?code=`` / ``&code=`` query param or a ``/code/`` path
# segment carrying a HIGH-ENTROPY token (12+ token chars) is a one-time login link, even
# with no trigger keyword and no digit. The length floor is what distinguishes it from an
# OAuth authorization grant (``response_type=code``, short ``?code=4/0Ae...`` callbacks),
# which carries a short or word-shaped value and must stay un-flagged. Applied per-URL.
_MAGIC_CODE_LINK_RE = re.compile(r"(?:[?&]code=|/code/)[A-Za-z0-9_-]{12,}", re.I)

_EMAIL_ADDRESS_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PRIVATE_FIELD_RE = _COMPILED_LANGUAGE_PACKS.private_field_pattern
_apply_compiled_language_packs(_COMPILED_LANGUAGE_PACKS)

_GUARDIAN_CONTROL_PLANE_RE = re.compile(
    r"\b(?:hermes[- ]guardian|guardian|security module|security filter)\b",
    re.I,
)
_GUARDIAN_REDACTED_SECURITY_NOTICE_RE = re.compile(
    r"\bredacted\s+security\s+content(?:\s+(?:was\s+)?detected)?\b"
    r"|\bsecurity-sensitive\s+content\s+(?:detected|suppressed|blocked|omitted)\b",
    re.I,
)

# Maximum scanned-text size, in characters. A multi-MB tool result would otherwise run
# every pattern over the whole payload on every egress (seconds-long stalls; potential
# catastrophic backtracking). Inputs over this are scanned on the capped prefix only and,
# on egress surfaces, treated as a positive finding (fail closed) — see _stringify_for_scan
# and _OVER_CAP_REASON. ~1 MB of text; generous for any legitimate tool result.
_SCAN_TEXT_CAP = 1_000_000
_OVER_CAP_REASON = "unscannable oversize payload"

# Zero-width and bidi/format characters an attacker can interleave between OTP digits or
# inside a label word to evade matching. Stripped before scanning so ``1<ZWSP>2<ZWSP>3``
# collapses to ``123``. Covers ZWSP/ZWNJ/ZWJ (U+200B-200D), LRM/RLM (U+200E/200F), word
# joiner (U+2060), ZWNBSP/BOM (U+FEFF) and soft hyphen (U+00AD).
_ZERO_WIDTH_RE = re.compile("[­​-‏⁠﻿]")

# Cyrillic/Greek letters that are visual homoglyphs of ASCII letters used in account-security
# label words (``code``, ``password``, ``verify``, ...). NFKC does not fold these (they are
# not compatibility-equivalent), so ``cоde`` with a Cyrillic ``о`` slips the ASCII matchers
# unless folded explicitly. Mapped to their ASCII look-alike before scanning.
_HOMOGLYPH_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p",
    "х": "x", "у": "y", "к": "k", "м": "m", "н": "h",
    "т": "t", "в": "b", "і": "i", "ѕ": "s", "ј": "j",
    "А": "A", "С": "C", "Е": "E", "О": "O", "Р": "P",
    "Х": "X", "У": "Y", "К": "K", "М": "M", "Н": "H",
    "Т": "T", "В": "B",
    "ο": "o", "ρ": "p", "α": "a", "ε": "e", "ν": "v",
    "Ο": "O", "Α": "A", "Ε": "E", "Ρ": "P", "Τ": "T",
    "Κ": "K", "Μ": "M", "Χ": "X", "Ι": "I",
}
_HOMOGLYPH_RE = re.compile("[" + re.escape("".join(_HOMOGLYPH_MAP)) + "]")


def _normalize_for_scan(text: str) -> str:
    """Fold non-homoglyph obfuscation so OTP/label evasions don't slip the matchers.

    NFKC normalizes full-width digits, NBSP/unicode spaces (to ASCII space, which the
    auth-code matcher already treats as an intra-digit separator) and other compatibility
    forms; zero-width/format chars are stripped. ASCII-only text is returned unchanged
    (cheap fast-path). Homoglyph folding is deliberately NOT done here — it is destructive
    to legitimate non-Latin text (e.g. a Russian "сбросить пароль" reset phrase), so it runs
    only as a separate fallback pass via _homoglyph_fold / _scan_text.
    """
    if text.isascii():
        return text
    normalized = unicodedata.normalize("NFKC", text)
    if _ZERO_WIDTH_RE.search(normalized):
        normalized = _ZERO_WIDTH_RE.sub("", normalized)
    return normalized


def _homoglyph_fold(text: str) -> str | None:
    """Map Cyrillic/Greek ASCII-look-alike letters to ASCII, or None if there are none.

    Used only as a second scan pass after the primary scan finds nothing, so legitimate
    non-Latin matching (which the first pass handles) is never disturbed; this pass catches
    a Latin label word with a single homoglyph swapped in (``cоde`` with Cyrillic ``о``).
    """
    if not _HOMOGLYPH_RE.search(text):
        return None
    return _HOMOGLYPH_RE.sub(lambda m: _HOMOGLYPH_MAP[m.group(0)], text)


def _context(text: str, start: int, end: int, *, radius: int = 120) -> str:
    prefix = max(0, start - radius)
    suffix = min(len(text), end + radius)
    return text[prefix:suffix].replace("\n", "\\n")


def _stringify_for_scan(value: Any, *, depth: int = 0) -> str:
    if value is None or depth > 6:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (int, float, bool)):
        text = str(value)
    elif isinstance(value, list):
        text = "\n".join(_stringify_for_scan(v, depth=depth + 1) for v in value[:50])
    elif isinstance(value, dict):
        parts = [_stringify_for_scan(val, depth=depth + 1) for val in value.values()]
        text = "\n".join(p for p in parts if p)
    else:
        text = str(value)
    # Cap at the top-level call only so a multi-MB payload can't drive every pattern over
    # the whole text. The over-cap signal (used to fail closed on egress) is recovered by
    # _sensitive_finding via length, so callers that only need the (capped) text are unaffected.
    if depth == 0 and len(text) > _SCAN_TEXT_CAP:
        return text[:_SCAN_TEXT_CAP]
    return text


def _sensitive_finding(
    value: Any, *, skip_reasons: frozenset[str] = frozenset(), egress: bool = True
) -> dict[str, str] | None:
    text = _stringify_for_scan(value)
    if not text:
        return None
    # Fail closed on an unscannably-large egress payload: an attacker could hide a secret
    # past the cap, so an over-cap egress input is itself a positive finding — block/suppress
    # outright without running every pattern over the 1 MB prefix (the result would be
    # suppression either way, and scanning it is the very stall the cap exists to prevent).
    # Inbound reads are not an egress leak, so they scan the prefix without forcing
    # suppression (egress=False); see _security_transform_tool_result.
    if egress and len(text) >= _SCAN_TEXT_CAP:
        return {
            "reason": _OVER_CAP_REASON,
            "match": "[oversize payload]",
            "context": "[oversize payload truncated by hermes-guardian for scanning]",
        }
    return _scan_text(text, skip_reasons=skip_reasons)


def _scan_text(
    text: str, *, skip_reasons: frozenset[str] = frozenset()
) -> dict[str, str] | None:
    normalized = _normalize_for_scan(text)
    if not normalized:
        return None
    finding = _scan_normalized_text(normalized, skip_reasons=skip_reasons)
    if finding:
        return finding
    # Second pass: fold Cyrillic/Greek homoglyphs of ASCII label letters and re-scan, so a
    # Latin label word with a swapped-in look-alike (``cоde``) is caught. Runs only when the
    # first pass found nothing, so legitimate non-Latin matching is never disturbed.
    folded = _homoglyph_fold(normalized)
    if folded is not None and folded != normalized:
        return _scan_normalized_text(folded, skip_reasons=skip_reasons)
    return None


def _scan_normalized_text(
    text: str, *, skip_reasons: frozenset[str] = frozenset()
) -> dict[str, str] | None:
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
        if not (
            _GUARDIAN_CONTROL_PLANE_RE.search(text)
            and _GUARDIAN_REDACTED_SECURITY_NOTICE_RE.search(text)
        ):
            return {
                "reason": "redacted security content",
                "match": redacted_match.group(0),
                "context": _context(text, redacted_match.start(), redacted_match.end()),
            }
    if account_security_enabled:
        for pattern, reason in _SECURITY_SENSITIVE_PATTERNS:
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
        match = _CODE_CONTEXT_RE.search(text)
        if match:
            return {
                "reason": "auth code",
                "match": match.group(0),
                "context": _context(text, match.start(), match.end()),
            }
    if sensitive_links_enabled and "sensitive link" not in skip_reasons:
        for match in re.finditer(r"https?://[^\s\"'<>]+", text, re.I):
            url = match.group(0)
            if _COMPILED_LANGUAGE_PACKS.security_link_term_pattern.search(
                url
            ) or _MAGIC_CODE_LINK_RE.search(url):
                return {
                    "reason": "sensitive link",
                    "match": url,
                    "context": _context(text, match.start(), match.end()),
                }
    return None


def _sensitive_reason(
    value: Any, *, skip_reasons: frozenset[str] = frozenset(), egress: bool = True
) -> str | None:
    finding = _sensitive_finding(value, skip_reasons=skip_reasons, egress=egress)
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
    egress: bool = True,
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
        reason = _sensitive_reason(record, skip_reasons=skip_reasons, egress=egress)
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
    value: Any, *, skip_reasons: frozenset[str] = frozenset(), egress: bool = True
) -> tuple[Any, int, str | None]:
    reason = _sensitive_reason(value, skip_reasons=skip_reasons, egress=egress)
    if _looks_like_message_record(value) and reason:
        return None, 1, reason

    if isinstance(value, dict) and reason and isinstance(value.get("result"), str):
        scrubbed_text, suppressed, text_reason = _scrub_text_records(
            value["result"], skip_reasons=skip_reasons, egress=egress
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
            item_reason_pre = _sensitive_reason(item, skip_reasons=skip_reasons, egress=egress)
            if item_reason_pre:
                suppressed += 1
                if first_reason is None:
                    first_reason = item_reason_pre
                continue
            scrubbed, count, item_reason = _scrub(item, skip_reasons=skip_reasons, egress=egress)
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
            scrubbed, count, item_reason = _scrub(item, skip_reasons=skip_reasons, egress=egress)
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
