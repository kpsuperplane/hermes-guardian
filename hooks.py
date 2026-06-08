"""Hermes hook orchestration for Security and Privacy modules."""

from __future__ import annotations


def _on_pre_llm_call(
    session_id: str = "",
    platform: str = "",
    sender_id: str = "",
    **_: Any,
) -> None:
    owner_hash = _hash_identity(platform or "cli", sender_id or "")
    _ensure_session(session_id, owner_hash)
    return None


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    session_id: str = "",
    **_: Any,
) -> dict[str, str] | None:
    security_block = _security_pre_tool_call(tool_name, args, session_id)
    if security_block:
        return security_block
    return _privacy_pre_tool_call(tool_name, args, session_id)


def _on_transform_tool_result(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
    **_: Any,
) -> str | None:
    privacy_context = _privacy_observe_tool_result(
        tool_name=tool_name,
        result=result,
        session_id=session_id,
        status=status,
    )
    if privacy_context is None:
        return None
    return _security_transform_tool_result(
        tool_name=tool_name,
        result=result,
        parsed=privacy_context["parsed"],
        parsed_ok=bool(privacy_context["parsed_ok"]),
        session_id=session_id,
        taint_classes=set(privacy_context.get("taint_classes") or []),
        public_remote_read=bool(privacy_context.get("public_remote_read")),
    )


def _on_pre_gateway_dispatch(event: Any = None, **_: Any) -> dict[str, Any] | None:
    text = getattr(event, "text", "")
    if isinstance(text, str) and text.strip().lower().startswith("/guardian"):
        raw_args = text.strip()[len("/guardian"):].strip()
        _remember_command_owner(raw_args, _owner_hash_from_event(event))
        return None
    return _security_pre_gateway_dispatch(event)


def _on_transform_llm_output(response_text: str = "", **_: Any) -> str | None:
    return _security_transform_llm_output(response_text)
