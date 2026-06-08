"""Sanitized cross-hook context shared by security and privacy modules."""

from __future__ import annotations

_SHARED_CONTEXT_TTL_SECONDS = 120
_SHARED_CONTEXT: dict[tuple[str, str], list[dict[str, Any]]] = {}


def _shared_context_key(session_id: str | None, tool_name: str) -> tuple[str, str]:
    return (_normalize_session_id(session_id), str(tool_name or "").lower())


def _prune_shared_context_unlocked(now: float | None = None) -> None:
    cutoff = (now if now is not None else _now()) - _SHARED_CONTEXT_TTL_SECONDS
    for key, entries in list(_SHARED_CONTEXT.items()):
        fresh = [entry for entry in entries if float(entry.get("ts") or 0) >= cutoff]
        if fresh:
            _SHARED_CONTEXT[key] = fresh[-10:]
        else:
            _SHARED_CONTEXT.pop(key, None)


def _record_shared_context(
    session_id: str | None,
    tool_name: str,
    **facts: Any,
) -> None:
    safe_facts = {
        key: value
        for key, value in facts.items()
        if key in {"public_remote_read", "local_system_taint", "action_family", "destination"}
    }
    safe_facts["ts"] = _now()
    with _LOCK:
        _prune_shared_context_unlocked()
        entries = _SHARED_CONTEXT.setdefault(_shared_context_key(session_id, tool_name), [])
        entries.append(safe_facts)
        del entries[:-10]


def _consume_shared_context(session_id: str | None, tool_name: str) -> dict[str, Any]:
    with _LOCK:
        _prune_shared_context_unlocked()
        entries = _SHARED_CONTEXT.get(_shared_context_key(session_id, tool_name)) or []
        if not entries:
            return {}
        return dict(entries.pop(0))


def _peek_shared_context(session_id: str | None, tool_name: str) -> dict[str, Any]:
    with _LOCK:
        _prune_shared_context_unlocked()
        entries = _SHARED_CONTEXT.get(_shared_context_key(session_id, tool_name)) or []
        return dict(entries[0]) if entries else {}
