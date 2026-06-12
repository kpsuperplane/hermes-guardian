"""Hermes hook orchestration for Security and Privacy modules."""

from __future__ import annotations

import json
import time
from typing import Any

from . import core
from .privacy import action_details
from .privacy import approvals
from .privacy import module as privacy_module
from .privacy import rules
from .privacy import tool_policy
from .runtime import activity_store
from .security import module as security_module



def _emit_fail_closed_activity(
    decision: str,
    *,
    session_id: str | None = "",
    tool_name: str = "",
    reason: str = "",
    args: Any = None,
) -> None:
    try:
        activity_store._emit_activity(
            decision,
            session_id=session_id,
            tool_name=tool_name,
            reason=reason,
            action_detail=action_details._activity_action_detail(tool_name, args),
        )
    except Exception:
        pass


def _fail_closed_tool_result(reason: str) -> str:
    return json.dumps(security_module._safe_stub(reason=reason), ensure_ascii=False)


def _timed_hook_check(hook: str, tool_name: str, fn: Any) -> Any:
    """Run a hook check, recording its wall-clock cost and whether it hit the LLM.

    Timing is best-effort and never affects the check's result: a failure to
    record is swallowed, and the check's own exceptions propagate unchanged after
    the duration is logged.
    """
    activity_store._perf_begin_check()
    start = time.perf_counter()
    blocked = False
    try:
        result = fn()
        blocked = result is not None
        return result
    finally:
        try:
            activity_store._record_check_timing(
                hook,
                duration_us=int((time.perf_counter() - start) * 1_000_000),
                tool_name=tool_name,
                llm_invoked=activity_store._perf_llm_invoked(),
                blocked=blocked,
            )
        except Exception:
            pass


def _on_pre_llm_call_impl(
    session_id: str = "",
    platform: str = "",
    sender_id: str = "",
    **_: Any,
) -> str | None:
    owner_hash = tool_policy._hash_identity(platform or "cli", sender_id or "")
    state = tool_policy._ensure_session(session_id, owner_hash)
    state["platform"] = str(platform or "")
    state["sender_id"] = str(sender_id or "")
    # While the session is still clean, hand the agent an ephemeral hygiene note
    # (Hermes appends it to the current turn's user message at API-call time only).
    # Once tainted — or with privacy checks off — the note has nothing to protect.
    if rules._privacy_mode() == "off":
        return None
    if tool_policy._session_taint(session_id):
        return None
    return core._TAINT_HYGIENE_NOTE


def _on_pre_llm_call(
    session_id: str = "",
    platform: str = "",
    sender_id: str = "",
    **kwargs: Any,
) -> str | None:
    try:
        return _on_pre_llm_call_impl(
            session_id=session_id,
            platform=platform,
            sender_id=sender_id,
            **kwargs,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        core.logger.exception("%s: pre_llm_call error", core._PLUGIN_NAME)
        return None


def _on_pre_tool_call_impl(
    tool_name: str = "",
    args: Any = None,
    session_id: str = "",
    **_: Any,
) -> dict[str, str] | None:
    # Stash the call's args so the post-result hook (not handed args) can resolve taint
    # against them — e.g. a doc read's target path. Single-slot per session; harmless if
    # the call is later blocked (the result hook only fires for calls that ran).
    tool_policy._stash_pending_tool_args(session_id, tool_name, args)
    security_block = security_module._security_pre_tool_call(tool_name, args, session_id)
    if security_block:
        return security_block
    return privacy_module._privacy_pre_tool_call(tool_name, args, session_id)


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    session_id: str = "",
    **kwargs: Any,
) -> dict[str, str] | None:
    try:
        return _timed_hook_check(
            "pre_tool_call",
            tool_name,
            lambda: _on_pre_tool_call_impl(
                tool_name=tool_name,
                args=args,
                session_id=session_id,
                **kwargs,
            ),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        core.logger.exception("%s: fail-closed pre_tool_call error", core._PLUGIN_NAME)
        reason = "guardian internal error; blocked fail-closed"
        _emit_fail_closed_activity(
            "security_blocked",
            session_id=session_id,
            tool_name=tool_name,
            reason=reason,
            args=args,
        )
        return {
            "action": "block",
            "message": "Hermes Guardian had an internal policy error, so this tool call was blocked fail-closed.",
        }


def _on_transform_tool_result_impl(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
    **_: Any,
) -> str | None:
    privacy_context = privacy_module._privacy_observe_tool_result(
        tool_name=tool_name,
        result=result,
        session_id=session_id,
        status=status,
    )
    if privacy_context is None:
        return None
    return security_module._security_transform_tool_result(
        tool_name=tool_name,
        result=result,
        parsed=privacy_context["parsed"],
        parsed_ok=bool(privacy_context["parsed_ok"]),
        session_id=session_id,
        taint_classes=set(privacy_context.get("taint_classes") or []),
        public_remote_read=bool(privacy_context.get("public_remote_read")),
        is_reference_read=bool(privacy_context.get("is_reference_read")),
    )


def _on_transform_tool_result(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
    **kwargs: Any,
) -> str | None:
    try:
        return _timed_hook_check(
            "transform_tool_result",
            tool_name,
            lambda: _on_transform_tool_result_impl(
                tool_name=tool_name,
                result=result,
                session_id=session_id,
                status=status,
                **kwargs,
            ),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        core.logger.exception("%s: fail-closed transform_tool_result error", core._PLUGIN_NAME)
        _emit_fail_closed_activity(
            "security_suppressed",
            session_id=session_id,
            tool_name=tool_name,
            reason="guardian internal error; suppressed fail-closed",
        )
        return _fail_closed_tool_result("guardian internal error; suppressed fail-closed")


def _on_pre_gateway_dispatch_impl(event: Any = None, **_: Any) -> dict[str, Any] | None:
    text = getattr(event, "text", "")
    if isinstance(text, str) and text.strip().lower().startswith("/guardian"):
        raw_args = text.strip()[len("/guardian"):].strip()
        approvals._remember_command_owner(raw_args, tool_policy._owner_hash_from_event(event))
        return None
    security_result = security_module._security_pre_gateway_dispatch(event)
    if security_result is None:
        # Only cache the request after the Security Module clears the message,
        # so sensitive content (reset codes, credentials) is never stored.
        approvals._remember_user_request(event)
    return security_result


def _on_pre_gateway_dispatch(event: Any = None, **kwargs: Any) -> dict[str, Any] | None:
    try:
        return _timed_hook_check(
            "pre_gateway_dispatch",
            "gateway_message",
            lambda: _on_pre_gateway_dispatch_impl(event=event, **kwargs),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        core.logger.exception("%s: pre_gateway_dispatch error", core._PLUGIN_NAME)
        text = getattr(event, "text", "")
        reason = security_module._sensitive_reason(text) if isinstance(text, str) else None
        if reason:
            _emit_fail_closed_activity(
                "security_blocked",
                tool_name="gateway_message",
                reason=f"{reason}; guardian internal error",
            )
            return {"action": "skip", "reason": "security-sensitive content suppressed before model dispatch"}
        return None


def _on_transform_llm_output_impl(response_text: str = "", **kwargs: Any) -> str | None:
    security_output = security_module._security_transform_llm_output(response_text)
    if security_output is not None:
        return security_output
    return privacy_module._privacy_transform_llm_output(response_text=response_text, **kwargs)


def _on_transform_llm_output(response_text: str = "", **kwargs: Any) -> str | None:
    try:
        return _timed_hook_check(
            "transform_llm_output",
            "llm_output",
            lambda: _on_transform_llm_output_impl(response_text=response_text, **kwargs),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        core.logger.exception("%s: fail-closed transform_llm_output error", core._PLUGIN_NAME)
        session_id = str(kwargs.get("session_id") or "")
        reason = "guardian internal error; final response suppressed fail-closed"
        if tool_policy._session_taint(session_id) or security_module._sensitive_reason(response_text):
            _emit_fail_closed_activity(
                "security_suppressed",
                session_id=session_id,
                tool_name="llm_output",
                reason=reason,
            )
            return "[hermes-guardian suppressed a final response after an internal policy error.]"
        return None
