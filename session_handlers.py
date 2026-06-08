"""Session lifecycle hooks and plugin registration."""

from __future__ import annotations

def _on_session_reset(session_id: str = "", old_session_id: str = "", **_: Any) -> None:
    with _LOCK:
        _load_pending_approvals_from_store_unlocked()
        deleted_approval_ids: list[str] = []
        for sid in {_normalize_session_id(session_id), _normalize_session_id(old_session_id)}:
            _SESSIONS.pop(sid, None)
            _ONCE_APPROVALS.pop(sid, None)
            _SESSION_APPROVALS.pop(sid, None)
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


def register(ctx) -> None:
    global _PLUGIN_LLM
    try:
        _PLUGIN_LLM = getattr(ctx, "llm", None)
    except Exception as exc:
        logger.warning("%s: failed to capture plugin LLM facade: %s", _PLUGIN_NAME, exc)
        _PLUGIN_LLM = None
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
    ctx.register_hook("transform_llm_output", _on_transform_llm_output)
    ctx.register_hook("pre_llm_call", _on_pre_llm_call)
    ctx.register_hook("on_session_reset", _on_session_reset)
    ctx.register_hook("on_session_end", _on_session_end)
    if hasattr(ctx, "register_command"):
        ctx.register_command(
            _COMMAND_NAME,
            _handle_guardian_command,
            description="Manage Hermes Guardian approvals",
            args_hint="status|approve|deny|rules|revoke|clear-taint|history|failures|debug",
        )
    if hasattr(ctx, "register_cli_command"):
        ctx.register_cli_command(
            "guardian",
            "Manage Hermes Guardian",
            _guardian_cli_setup,
            description="Manage Hermes Guardian dashboard and local maintenance commands.",
        )
