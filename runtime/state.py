"""Session lifecycle hooks for Hermes Guardian."""

from __future__ import annotations

from typing import Any

from .. import state
from ..privacy import approvals
from ..privacy import llm
from ..privacy import tool_policy


def _on_session_reset(session_id: str = "", old_session_id: str = "", **_: Any) -> None:
    with state._LOCK:
        approvals._load_pending_approvals_from_store_unlocked()
        deleted_approval_ids: list[str] = []
        for sid in {tool_policy._normalize_session_id(session_id), tool_policy._normalize_session_id(old_session_id)}:
            state._SESSIONS.pop(sid, None)
            state._ONCE_APPROVALS.pop(sid, None)
            state._SESSION_APPROVALS.pop(sid, None)
            state._TURN_DENIED_EXTERNAL.pop(sid, None)
            state._CRON_NOTIFICATIONS_SENT.discard(sid)
        for owner, session_ids in list(state._OWNER_SESSIONS.items()):
            session_ids.difference_update({tool_policy._normalize_session_id(session_id), tool_policy._normalize_session_id(old_session_id)})
            if not session_ids:
                state._OWNER_SESSIONS.pop(owner, None)
        for approval_id, approval in list(state._PENDING_APPROVALS.items()):
            if approval.get("session_id") in {tool_policy._normalize_session_id(session_id), tool_policy._normalize_session_id(old_session_id)}:
                state._PENDING_APPROVALS.pop(approval_id, None)
                deleted_approval_ids.append(approval_id)
        approvals._delete_pending_approvals_from_store_unlocked(deleted_approval_ids)


def _on_session_end(session_id: str = "", **_: Any) -> None:
    # Hermes currently fires this at run-conversation boundaries, so do not
    # clear taint here. Prune volatile state only.
    llm._prune_expired()
