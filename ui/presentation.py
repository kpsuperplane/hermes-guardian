"""Activity presentation helpers for Hermes Guardian."""

from __future__ import annotations

import html
import time
from datetime import datetime
from typing import Any, Callable
from zoneinfo import ZoneInfo


def activity_display_tool(row: dict[str, Any]) -> str:
    tool = str(row.get("tool_name") or row.get("action_family") or "").strip()
    if row.get("decision") == "tainted" and tool.lower() in {"terminal", "execute_code", "code_execution", "shell"}:
        return f"{tool} result"
    return tool


def clip_text(value: Any, limit: int = 120, *, ellipsis: str = "...", fallback: str = "") -> str:
    text = str(value or "").strip() or fallback
    if len(text) <= limit:
        return text
    suffix = ellipsis or ""
    return text[: max(0, limit - len(suffix))].rstrip() + suffix


def friendly_activity_timestamp(ts: Any, tz: ZoneInfo | None) -> str:
    try:
        dt = datetime.fromtimestamp(int(ts or 0), tz=tz)
    except Exception:
        dt = datetime.fromtimestamp(0, tz=tz)
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    hour = dt.hour % 12 or 12
    am_pm = "AM" if dt.hour < 12 else "PM"
    zone = dt.tzname() or time.tzname[0] or "local"
    return f"{months[dt.month - 1]} {dt.day}, {dt.year} {hour}:{dt.minute:02d} {am_pm} {zone}"


def friendly_activity_clock(ts: Any, tz: ZoneInfo | None) -> str:
    """Time-only ('11:43 AM') for a row whose date is implied by its turn header."""
    try:
        dt = datetime.fromtimestamp(int(ts or 0), tz=tz)
    except Exception:
        dt = datetime.fromtimestamp(0, tz=tz)
    hour = dt.hour % 12 or 12
    am_pm = "AM" if dt.hour < 12 else "PM"
    return f"{hour}:{dt.minute:02d} {am_pm}"


def activity_time_text(row: dict[str, Any], tz: ZoneInfo | None) -> str:
    count = int(row.get("count") or 1)
    if count <= 1:
        return friendly_activity_timestamp(row.get("ts"), tz)
    first_ts = int(row.get("first_ts") or row.get("ts") or 0)
    latest_ts = int(row.get("ts") or 0)
    if first_ts == latest_ts:
        return friendly_activity_timestamp(latest_ts, tz)
    first_text = friendly_activity_timestamp(first_ts, tz)
    latest_text = friendly_activity_timestamp(latest_ts, tz)
    if first_text == latest_text:
        return latest_text
    return f"{first_text} - {latest_text}"


def activity_display_reason(
    row: dict[str, Any],
    *,
    all_privacy_classes: set[str],
    taint_reason_for_tool_result: Callable[[str, set[str]], str],
) -> str:
    reason = str(row.get("reason") or "").strip()
    if reason == "private source result" and row.get("decision") == "tainted":
        classes = {
            cls.strip()
            for cls in str(row.get("data_classes") or "").split(",")
            if cls.strip() in all_privacy_classes
        }
        return taint_reason_for_tool_result(str(row.get("tool_name") or ""), classes)
    return reason


def activity_status_icon(decision: str) -> str:
    status_icons = {
        "allowed": "✅",
        "auto_approved": "✅",
        "blocked": "❌",
        "denied": "❌",
        "manual_approved": "✅",
        "mode_off_allowed": "✅",
        "privacy_off_allowed": "✅",
        "read": "🌐",
        "security_blocked": "❌",
        "security_suppressed": "❌",
        "tainted": "📥",
    }
    return status_icons.get(str(decision or "").strip(), "•")


def activity_reason_prefix(decision: str) -> str:
    if decision == "read":
        return "Read"
    if decision in {"allowed", "auto_approved", "manual_approved", "mode_off_allowed", "privacy_off_allowed"}:
        return "Allowed"
    if decision == "denied":
        return "Dismissed"
    if decision in {"blocked", "security_blocked", "security_suppressed"}:
        return "Blocked"
    return ""


def activity_reason_line_text(
    row: dict[str, Any],
    *,
    marker: str,
    display_reason: str,
    limit: int = 72,
    marker_limit: int = 72,
) -> str:
    decision = str(row.get("decision") or "").strip()
    if decision == "tainted":
        return ""
    reason = clip_text(display_reason, limit, ellipsis="...", fallback="")
    if not reason:
        return ""
    suffix = f" (`{clip_text(marker, marker_limit, ellipsis='...', fallback='')}`)" if marker else ""
    prefix = activity_reason_prefix(decision)
    return f"{prefix}: {reason}{suffix}" if prefix else f"{reason}{suffix}"


def activity_taints_text(row: dict[str, Any], *, code: bool = False, html_code: bool = False) -> str:
    raw_classes = str(row.get("data_classes") or "").strip()
    classes = clip_text(raw_classes, 120, fallback="") if raw_classes else ""
    if not classes or classes in {"none", "n/a"}:
        return "🏷️ No taints"
    if html_code:
        return f"🏷️ <code>{html.escape(classes, quote=True)}</code>"
    if code:
        return f"🏷️ `{classes}`"
    return f"🏷️ {classes}"
