"""Modularized guardian runtime module."""

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
