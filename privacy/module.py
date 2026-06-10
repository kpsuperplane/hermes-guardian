"""Privacy egress orchestration for Hermes Guardian."""

from __future__ import annotations


def _emit_read_activity_if_applicable(tool_name: str, args: Any, session_id: str | None) -> bool:
    read_activity = _read_activity_for_tool(tool_name, args, session_id)
    if not read_activity:
        return False
    action_family, destination = read_activity
    _emit_activity(
        "read",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=set(),
        reason="public read",
        action_detail=_activity_action_detail(tool_name, args, action_family, destination),
    )
    return True


def _record_allowed_tool_side_effects(
    session_id: str | None,
    tool_name: str,
    args: Any,
    *,
    action_family: str = "",
    mark_browser_private_input: bool = False,
) -> None:
    if str(tool_name or "").lower() == "browser_navigate":
        _set_browser_host(session_id, _extract_url(args))
    if mark_browser_private_input and action_family == "browser_type":
        _mark_browser_private_input(session_id)
    _record_local_system_result_policy(session_id, tool_name, args)


def _emit_egress_activity(
    decision: str,
    *,
    session_id: str | None,
    tool_name: str,
    action_family: str,
    destination: str,
    data_classes: set[str],
    reason: str,
    owner_hash: str = "",
    approval_id: str = "",
    rule_id: str = "",
    rule_source: str = "",
    rule_effect: str = "",
    rule_scope: str = "",
    action_detail: str = "",
    purpose: str = "",
    recipient_identity: str = "",
) -> None:
    _emit_activity(
        decision,
        session_id=session_id,
        owner_hash=owner_hash,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=data_classes,
        reason=reason,
        approval_id=approval_id,
        rule_id=rule_id,
        rule_source=rule_source,
        rule_effect=rule_effect,
        rule_scope=rule_scope,
        action_detail=action_detail,
        purpose=purpose,
        recipient_identity=recipient_identity,
        module="privacy",
    )


def _allow_privacy_off_tool_call(tool_name: str, args: Any, session_id: str | None, action: ToolAction | None) -> None:
    if action:
        action_family, destination = action.as_tuple()
        data_classes = _data_classes_for_egress(session_id, args)
        if data_classes:
            _emit_egress_activity(
                "privacy_off_allowed",
                session_id=session_id,
                tool_name=tool_name,
                action_family=action_family,
                destination=destination,
                data_classes=data_classes,
                reason="privacy policy off",
                action_detail=_activity_action_detail(tool_name, args, action_family, destination),
                purpose=action.purpose,
                recipient_identity=action.recipient_identity,
            )
    else:
        _emit_read_activity_if_applicable(tool_name, args, session_id)
    _record_allowed_tool_side_effects(session_id, tool_name, args)


def _allow_untainted_tool_call(
    tool_name: str,
    args: Any,
    session_id: str | None,
    *,
    action_family: str,
    destination: str,
    purpose: str = "unknown",
    recipient_identity: str = "none",
) -> None:
    _emit_egress_activity(
        "allowed",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=set(),
        reason="no private data in scope",
        action_detail=_activity_action_detail(tool_name, args, action_family, destination),
        purpose=purpose,
        recipient_identity=recipient_identity,
    )
    _record_allowed_tool_side_effects(session_id, tool_name, args)


def _allow_approved_tool_call(shape: dict[str, Any], source: dict[str, Any], tool_name: str, args: Any) -> None:
    _emit_egress_activity(
        "allowed",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason="matched allow rule",
        rule_id=source.get("rule_id", ""),
        rule_source=source.get("source", ""),
        rule_effect=source.get("effect", "allow"),
        action_detail=shape.get("action_detail", ""),
        purpose=shape.get("purpose", "unknown"),
        recipient_identity=shape.get("recipient_identity", "none"),
    )
    _record_allowed_tool_side_effects(
        shape.get("session_id", ""),
        tool_name,
        args,
        action_family=shape.get("action_family", ""),
        mark_browser_private_input=True,
    )


def _block_for_privacy_rule(shape: dict[str, Any], tool_name: str, source: dict[str, Any]) -> dict[str, str]:
    reason = "matched deny rule"
    _emit_egress_activity(
        "blocked",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=reason,
        rule_id=source.get("rule_id", ""),
        rule_source=source.get("source", "persistent"),
        rule_effect=source.get("effect", "deny"),
        action_detail=shape.get("action_detail", ""),
        purpose=shape.get("purpose", "unknown"),
        recipient_identity=shape.get("recipient_identity", "none"),
    )
    _notify_cron_failure_if_needed(
        session_id=shape.get("session_id", ""),
        tool_name=tool_name,
        decision="blocked",
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=reason,
    )
    return {
        "action": "block",
        "message": (
            "Hermes Guardian denied this egress by privacy rule.\n\n"
            f"Rule ID: {source.get('rule_id', '')}\n"
            f"Action: {shape.get('action_family', '')}\n"
            f"Destination: {shape.get('destination', '')}\n"
            f"Data classes: {', '.join(shape.get('data_classes') or ['none'])}"
        ),
    }


def _allow_read_only_tool_call(shape: dict[str, Any], tool_name: str, args: Any) -> None:
    logger.info(
        "%s: read-only policy approved low-risk Hermes Guardian %s to %s for session %s",
        _PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        _normalize_session_id(shape.get("session_id", "")),
    )
    _emit_egress_activity(
        "auto_approved",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason="read-only low-risk",
        rule_source="read-only",
        action_detail=shape.get("action_detail", ""),
        purpose=shape.get("purpose", "unknown"),
        recipient_identity=shape.get("recipient_identity", "none"),
    )
    _record_allowed_tool_side_effects(shape.get("session_id", ""), tool_name, args)


def _llm_policy_tool_call_result(shape: dict[str, Any], tool_name: str, args: Any) -> tuple[dict[str, str] | None, str | None]:
    hard_reason = _llm_hard_deny_reason(shape, args)
    if hard_reason:
        logger.info(
            "%s: hard-blocked Hermes Guardian %s to %s for session %s (%s)",
            _PLUGIN_NAME,
            shape.get("action_family", ""),
            shape.get("destination", ""),
            _normalize_session_id(shape.get("session_id", "")),
            hard_reason,
        )
        _emit_egress_activity(
            "security_blocked",
            session_id=shape.get("session_id", ""),
            owner_hash=shape.get("owner_hash", ""),
            tool_name=tool_name,
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=hard_reason,
            action_detail=shape.get("action_detail", ""),
            purpose=shape.get("purpose", "unknown"),
            recipient_identity=shape.get("recipient_identity", "none"),
        )
        _notify_cron_failure_if_needed(
            session_id=shape.get("session_id", ""),
            tool_name=tool_name,
            decision="security_blocked",
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=hard_reason,
        )
        return {"action": "block", "message": _block_message(hard_reason)}, None

    cached = _cached_deny_verdict(shape)
    verdict = cached if cached is not None else _llm_security_verdict(shape, args)
    if (
        verdict.get("outcome") == "allow"
        and verdict.get("risk_level") == "high"
        and _is_cron_session_id(shape.get("session_id"))
    ):
        # Cron runs unattended with no human to catch a bad auto-approval, so a
        # cron job can never self-authorize high-risk egress even when cron
        # context is enabled. Downgrade to manual approval.
        verdict = {
            **verdict,
            "outcome": "deny",
            "rationale": f"cron high-risk egress requires human approval ({verdict.get('rationale', '')})",
        }
    if cached is None:
        # Cache only freshly-computed denials so retried/looping blocked actions
        # don't re-pay the verifier latency.
        _store_deny_verdict(shape, verdict)
    if verdict.get("outcome") == "allow":
        reason = (
            f"llm {verdict.get('risk_level', 'unknown')}: "
            f"{verdict.get('rationale', 'approved')}"
        )
        logger.info(
            "%s: LLM-approved Hermes Guardian %s to %s for session %s",
            _PLUGIN_NAME,
            shape.get("action_family", ""),
            shape.get("destination", ""),
            _normalize_session_id(shape.get("session_id", "")),
        )
        _emit_egress_activity(
            "auto_approved",
            session_id=shape.get("session_id", ""),
            owner_hash=shape.get("owner_hash", ""),
            tool_name=tool_name,
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=reason,
            rule_source="llm",
            action_detail=shape.get("action_detail", ""),
            purpose=shape.get("purpose", "unknown"),
            recipient_identity=shape.get("recipient_identity", "none"),
        )
        _record_allowed_tool_side_effects(
            shape.get("session_id", ""),
            tool_name,
            args,
            action_family=shape.get("action_family", ""),
            mark_browser_private_input=True,
        )
        return None, None

    blocked_reason = (
        f"requires approval (llm {verdict.get('risk_level', 'unknown')}: "
        f"{verdict.get('rationale', 'denied')})"
    )
    return None, blocked_reason


def _block_for_pending_approval(shape: dict[str, Any], tool_name: str, blocked_reason: str) -> dict[str, str]:
    approval = _create_pending_approval(shape)
    approval["reason"] = blocked_reason
    _save_pending_approval_to_store_unlocked(approval)
    logger.info(
        "%s: blocked Hermes Guardian %s to %s for session %s",
        _PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        _normalize_session_id(shape.get("session_id", "")),
    )
    _emit_egress_activity(
        "blocked",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=blocked_reason,
        approval_id=approval.get("id", ""),
        action_detail=shape.get("action_detail", ""),
        purpose=shape.get("purpose", "unknown"),
        recipient_identity=shape.get("recipient_identity", "none"),
    )
    _notify_cron_failure_if_needed(
        session_id=shape.get("session_id", ""),
        tool_name=tool_name,
        decision="blocked",
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=blocked_reason,
        approval_id=approval.get("id", ""),
    )
    return {"action": "block", "message": _guardian_block_message(approval)}


# --- Phase 2 shadow mode (doc 04 §4) -----------------------------------------
# The new classify+decide engine runs ALONGSIDE the authoritative old path, never
# changing what the hook returns. Divergences are counted + logged so the corpus replay
# and live bake can prove "only intra-boundary gate->allow flips" before Phase 3 flips
# the switch. A shadow exception must NEVER affect the real decision.
_SHADOW_DECISION_COUNTS: dict[str, int] = {
    "evaluations": 0,
    "shadow_mismatch": 0,
    "shadow_error": 0,
}


def _shadow_decision_counts() -> dict[str, int]:
    """Reader for the shadow counters (tests + diagnostics). Returns a copy."""
    return dict(_SHADOW_DECISION_COUNTS)


def _reset_shadow_decision_counts() -> None:
    for key in _SHADOW_DECISION_COUNTS:
        _SHADOW_DECISION_COUNTS[key] = 0


def _shadow_decision_for(tool_name: str, args: Any, session_id: str | None):
    """Pure shadow computation: build ``(Capability, Decision)`` for a tool call.

    Returns ``(capability, decision)`` where ``decision`` is one of the policy outcomes
    (ALLOW/APPROVE/BLOCK from ``privacy/policy``). Used by the corpus-replay test to call
    the new engine directly without going through the hook. ``decide`` reasons over the
    AMBIENT session taint (provenance retired, doc 02 §4) and the current purpose/mode.
    """
    cap = classify(tool_name, args, session_id)
    # Ambient "what is potentially leaving" = session taint UNION the classes detected in
    # this call's content (doc 02 §4 conservative ambient default; charter invariant #4).
    # This is exactly the set the old authoritative path reasoned over
    # (``_data_classes_for_egress``), so the floor is preserved: a previously-correct
    # content-detected block (e.g. an external send carrying a contact) is NOT narrowed
    # away. ``decide`` never infers "absence means safe".
    taint = _data_classes_for_egress(session_id, args)
    purpose = _purpose_from_args(args)
    mode = _privacy_policy()
    decision = decide(cap, taint, purpose, mode)
    return cap, decision


def _shadow_compare(tool_name: str, args: Any, session_id: str | None, old_outcome: str) -> None:
    """Run the shadow engine and record divergence vs the OLD authoritative outcome.

    Exception-safe: any failure increments ``shadow_error`` and is swallowed — the real
    decision is already returned by the caller and is never affected (doc 04 §4).

    ``old_outcome`` is the authoritative outcome bucketed into the same vocabulary as
    ``decide`` for comparison: "allow" (the call proceeded), "approve" (gated to manual
    approval), or "block" (a deny rule / hard block).
    """
    try:
        _SHADOW_DECISION_COUNTS["evaluations"] += 1
        _cap, new_decision = _shadow_decision_for(tool_name, args, session_id)
        if new_decision != old_outcome:
            _SHADOW_DECISION_COUNTS["shadow_mismatch"] += 1
            logger.info(
                "%s: shadow decision divergence tool=%s old=%s new=%s trust=%s",
                _PLUGIN_NAME,
                re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(tool_name or ""))[:64],
                old_outcome,
                new_decision,
                getattr(getattr(_cap, "destination", None), "trust", "unknown"),
            )
    except Exception as exc:  # noqa: BLE001 — shadow must never affect the real decision
        _SHADOW_DECISION_COUNTS["shadow_error"] += 1
        logger.debug("%s: shadow decision error: %s", _PLUGIN_NAME, exc)


def _privacy_pre_tool_call(tool_name: str = "", args: Any = None, session_id: str = "") -> dict[str, str] | None:
    """Authoritative privacy pre-tool-call decision (UNCHANGED behavior) + Phase 2 shadow.

    The old path stays authoritative and decides what is returned. A holder collects the
    old outcome bucketed into decide's vocabulary (allow/approve/block), and after the
    authoritative decision we run the new classify+decide engine in shadow and record any
    divergence. The shadow computation can never change the return value.
    """
    outcome_sink: list[str] = []
    result = _privacy_pre_tool_call_authoritative(tool_name, args, session_id, outcome_sink)
    old_outcome = outcome_sink[0] if outcome_sink else "allow"
    _shadow_compare(tool_name, args, session_id, old_outcome)
    return result


def _privacy_pre_tool_call_authoritative(
    tool_name: str = "",
    args: Any = None,
    session_id: str = "",
    outcome_sink: list[str] | None = None,
) -> dict[str, str] | None:
    def _record_outcome(value: str) -> None:
        if outcome_sink is not None:
            outcome_sink.append(value)

    intrinsic_risk = _intrinsic_risk_for_tool(tool_name, args)
    if intrinsic_risk:
        reason = str(intrinsic_risk.get("reason") or "intrinsic source-and-sink risk")
        action_family = str(intrinsic_risk.get("action_family") or "")
        destination = str(intrinsic_risk.get("destination") or "")
        data_classes = set(intrinsic_risk.get("data_classes") or [])
        action_detail = (
            f"action_family={action_family or 'unknown'} "
            f"destination={destination or 'network'} "
            f"data_classes={','.join(sorted(data_classes)) or 'unknown'} "
            f"reason={reason}"
        )
        _emit_egress_activity(
            "security_blocked",
            session_id=session_id,
            tool_name=tool_name,
            action_family=action_family,
            destination=destination,
            data_classes=data_classes,
            reason=reason,
            action_detail=action_detail,
        )
        _notify_cron_failure_if_needed(
            session_id=session_id,
            tool_name=tool_name,
            decision="security_blocked",
            action_family=action_family,
            destination=destination,
            data_classes=data_classes,
            reason=reason,
        )
        _record_outcome("block")
        return {"action": "block", "message": f"Blocked by {_PLUGIN_NAME}: {reason}."}

    privacy_policy = _privacy_policy()
    action = _egress_action_context_for_tool(tool_name, args, session_id)

    if privacy_policy == "off":
        _allow_privacy_off_tool_call(tool_name, args, session_id, action)
        _record_outcome("allow")
        return None

    if not action:
        _emit_read_activity_if_applicable(tool_name, args, session_id)
        _record_allowed_tool_side_effects(session_id, tool_name, args)
        _record_outcome("allow")
        return None

    action_family, destination = action.as_tuple()
    data_classes = _data_classes_for_egress(session_id, args)
    shape = _approval_shape(
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        purpose=action.purpose,
        recipient_identity=action.recipient_identity,
        legacy_destination=action.legacy_destination,
        data_classes=data_classes,
        args=args,
    )
    source = _approval_source(shape)
    if source:
        if source.get("effect") == "deny":
            _record_outcome("block")
            return _block_for_privacy_rule(shape, tool_name, source)
        _allow_approved_tool_call(shape, source, tool_name, args)
        _record_outcome("allow")
        return None

    if not data_classes:
        _allow_untainted_tool_call(
            tool_name,
            args,
            session_id,
            action_family=action_family,
            destination=destination,
            purpose=action.purpose,
            recipient_identity=action.recipient_identity,
        )
        _record_outcome("allow")
        return None

    if privacy_policy == "read-only" and _read_only_auto_approves(shape, args):
        _allow_read_only_tool_call(shape, tool_name, args)
        _record_outcome("allow")
        return None

    blocked_reason = "requires approval"
    if privacy_policy == "llm":
        llm_result, llm_blocked_reason = _llm_policy_tool_call_result(shape, tool_name, args)
        if llm_result is not None:
            # llm verifier resolved this call: a block dict is a gate (approve), a None-
            # carrying allow is an allow. _llm_policy_tool_call_result returns the hook
            # result; a returned dict here is the verifier holding the call for approval.
            _record_outcome("approve")
            return llm_result
        if llm_blocked_reason is None:
            _record_outcome("allow")
            return None
        blocked_reason = llm_blocked_reason

    # Pending manual approval is a GATE, not a block (doc 02 §3 step 6 APPROVE).
    _record_outcome("approve")
    return _block_for_pending_approval(shape, tool_name, blocked_reason)


def _privacy_observe_tool_result(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
) -> dict[str, Any] | None:
    if not isinstance(result, str) or not result:
        return None

    parsed: Any
    parsed_ok = True
    try:
        parsed = json.loads(result)
    except (TypeError, ValueError):
        parsed_ok = False
        parsed = result

    local_system_policy = (
        _consume_local_system_result_policy(session_id, tool_name)
        if _is_local_system_tool(tool_name)
        else {}
    )
    public_remote_read = bool(local_system_policy.get("remote_read"))
    taint_classes = _taint_classes_for_tool_result(
        tool_name,
        parsed,
        status=status,
        session_id=session_id,
        local_system_policy=local_system_policy,
    )
    if taint_classes:
        _taint_session(session_id, taint_classes)
        _record_provenance_from_tool_result(session_id, tool_name, parsed, taint_classes)
        _emit_activity(
            "tainted",
            session_id=session_id,
            tool_name=tool_name,
            data_classes=taint_classes,
            reason=_taint_reason_for_tool_result(tool_name, taint_classes),
        )

    if str(tool_name or "").lower().startswith("browser_"):
        url = _extract_url(parsed)
        if url:
            _set_browser_host(session_id, url)
        if _browser_result_has_private_context(parsed):
            _mark_browser_private_input(session_id)
            _emit_activity(
                "tainted",
                session_id=session_id,
                tool_name=tool_name,
                data_classes={"browser_private_input"},
                reason="tainted by browser private context",
            )

    return {
        "parsed": parsed,
        "parsed_ok": parsed_ok,
        "taint_classes": taint_classes,
        "public_remote_read": public_remote_read,
    }


def _final_response_destination(
    *,
    session_id: str | None = "",
    platform: str = "",
    recipient: str = "",
    chat_type: str = "",
) -> str:
    state = _ensure_session(session_id)
    platform = str(platform or state.get("platform") or "unknown").strip().lower() or "unknown"
    recipient = str(recipient or "").strip()
    chat_type = str(chat_type or "").strip().lower()
    parts = [platform]
    if chat_type:
        parts.append(chat_type)
    if recipient:
        parts.append(_short_hash(recipient))
    return ":".join(parts)


def _final_destination_is_owner_private(
    *,
    session_id: str | None = "",
    platform: str = "",
    sender_id: str = "",
    chat_type: str = "",
) -> bool:
    state = _ensure_session(session_id)
    platform = str(platform or state.get("platform") or "unknown").strip().lower()
    sender_id = str(sender_id or state.get("sender_id") or "").strip()
    chat_type = str(chat_type or "").strip().lower()
    if platform == "cli":
        return True
    if chat_type in {"group", "supergroup", "channel", "guild", "server", "room"}:
        return False
    owner_hash = str(state.get("owner_hash") or "")
    if sender_id:
        return _hash_identity(platform or "unknown", sender_id) == owner_hash
    return bool(owner_hash and platform and platform != "unknown")


def _privacy_transform_llm_output(response_text: str = "", **kwargs: Any) -> str | None:
    session_id = str(kwargs.get("session_id") or "")
    if not _session_taint(session_id):
        return None
    classes = _data_classes_for_egress(session_id, response_text)
    if not classes:
        return None
    platform = str(kwargs.get("platform") or "")
    sender_id = str(kwargs.get("sender_id") or kwargs.get("user_id") or "")
    chat_type = str(kwargs.get("chat_type") or kwargs.get("channel_type") or kwargs.get("conversation_type") or "")
    recipient = str(kwargs.get("recipient") or kwargs.get("to") or kwargs.get("chat_id") or kwargs.get("channel") or "")
    recipient_identity = _recipient_identity_from_value(recipient)
    destination = _final_response_destination(
        session_id=session_id,
        platform=platform,
        recipient=recipient,
        chat_type=chat_type,
    )
    if _final_destination_is_owner_private(
        session_id=session_id,
        platform=platform,
        sender_id=sender_id,
        chat_type=chat_type,
    ):
        _emit_egress_activity(
            "allowed",
            session_id=session_id,
            tool_name="llm_output",
            action_family="final_response",
            destination=destination,
            data_classes=classes,
            reason="owner-visible final response",
            purpose="unknown",
            recipient_identity=recipient_identity,
        )
        return None
    _emit_egress_activity(
        "blocked",
        session_id=session_id,
        tool_name="llm_output",
        action_family="final_response",
        destination=destination,
        data_classes=classes,
        reason="tainted final response to non-owner destination",
        purpose="unknown",
        recipient_identity=recipient_identity,
    )
    return "[hermes-guardian suppressed a tainted final response to this destination.]"
