"""Session lifecycle hooks for Hermes Guardian."""

from __future__ import annotations

from typing import Any


def _on_session_reset(session_id: str = "", old_session_id: str = "", **_: Any) -> None:
    with _LOCK:
        _load_pending_approvals_from_store_unlocked()
        deleted_approval_ids: list[str] = []
        for sid in {_normalize_session_id(session_id), _normalize_session_id(old_session_id)}:
            _SESSIONS.pop(sid, None)
            _ONCE_APPROVALS.pop(sid, None)
            _SESSION_APPROVALS.pop(sid, None)
            _TURN_DENIED_EXTERNAL.pop(sid, None)
            _CRON_NOTIFICATIONS_SENT.discard(sid)
        for owner, session_ids in list(_OWNER_SESSIONS.items()):
            session_ids.difference_update({_normalize_session_id(session_id), _normalize_session_id(old_session_id)})
            if not session_ids:
                _OWNER_SESSIONS.pop(owner, None)
        for approval_id, approval in list(_PENDING_APPROVALS.items()):
            if approval.get("session_id") in {_normalize_session_id(session_id), _normalize_session_id(old_session_id)}:
                _PENDING_APPROVALS.pop(approval_id, None)
                deleted_approval_ids.append(approval_id)
        _delete_pending_approvals_from_store_unlocked(deleted_approval_ids)


def _on_session_end(session_id: str = "", **_: Any) -> None:
    # Hermes currently fires this at run-conversation boundaries, so do not
    # clear taint here. Prune volatile state only.
    _prune_expired()
