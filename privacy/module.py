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
    destination_trust: str = "unknown",
    decision_step: str = "",
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
        destination_trust=destination_trust,
        decision_step=decision_step,
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
    destination_trust: str = "unknown",
    decision_step: str = "",
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
        destination_trust=destination_trust,
        decision_step=decision_step,
    )
    _record_allowed_tool_side_effects(session_id, tool_name, args)


def _allow_intra_boundary_tool_call(
    tool_name: str,
    args: Any,
    session_id: str | None,
    *,
    action_family: str,
    destination: str,
    data_classes: set[str],
    trust: Any,
    purpose: str = "unknown",
    recipient_identity: str = "none",
    decision_step: str = "",
) -> None:
    """Allow a tainted write whose ``decide`` outcome is ALLOW (doc 02 §3).

    This fires for the two non-untainted ALLOW paths: an intra-boundary destination
    (self / local_system / model_provider / draft) reaching no new party (step 3 — the G1
    false-positive win), or an outward destination covered by an explicit allow
    declassification rule (step 5). The reason distinguishes the two so "why was this
    allowed" stays answerable. The data classes are preserved on the activity record for
    audit fidelity (charter invariant #6); ``_record_allowed_tool_side_effects`` runs
    exactly as for any other allowed egress (e.g. a self draft still records its effects).
    """
    if _is_intra_boundary_trust(trust):
        reason = f"intra-boundary destination ({_trust_label(trust)})"
    else:
        reason = "matched allow rule"
    _emit_egress_activity(
        "allowed",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=data_classes,
        reason=reason,
        action_detail=_activity_action_detail(tool_name, args, action_family, destination),
        purpose=purpose,
        recipient_identity=recipient_identity,
        destination_trust=_trust_label(trust),
        decision_step=decision_step,
    )
    _record_allowed_tool_side_effects(
        session_id,
        tool_name,
        args,
        action_family=action_family,
        mark_browser_private_input=True,
    )


def _trust_label(trust: Any) -> str:
    """String label for a ``DestinationTrust`` (or anything coerced to it) for activity
    reasons. Total: garbage resolves to ``unknown``."""
    value = getattr(trust, "value", None)
    return str(value if value is not None else (trust or "unknown"))


def _is_intra_boundary_trust(trust: Any) -> bool:
    """True iff ``trust`` is an intra-boundary destination trust (self / local_system /
    model_provider) — the trusts ``decide`` step 3 allows without gating."""
    return _trust_label(trust) in {"self", "local_system", "model_provider"}


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
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
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
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
    )
    _notify_cron_failure_if_needed(
        session_id=shape.get("session_id", ""),
        tool_name=tool_name,
        decision="blocked",
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason=reason,
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
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
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
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
            destination_trust=shape.get("destination_trust", "unknown"),
            decision_step=shape.get("decision_step", ""),
        )
        _notify_cron_failure_if_needed(
            session_id=shape.get("session_id", ""),
            tool_name=tool_name,
            decision="security_blocked",
            action_family=shape.get("action_family", ""),
            destination=shape.get("destination", ""),
            data_classes=set(shape.get("data_classes") or []),
            reason=hard_reason,
            destination_trust=shape.get("destination_trust", "unknown"),
            decision_step=shape.get("decision_step", ""),
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
            destination_trust=shape.get("destination_trust", "unknown"),
            decision_step=shape.get("decision_step", ""),
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


# --- Cross-channel turn lockdown (channel-shopping defense) ------------------
_LOCKDOWN_BLOCKED_REASON = (
    "requires approval (cross-channel lockdown: an export of this private data to an "
    "external destination was already withheld this turn; re-routing the same export "
    "through another tool or channel is gated for your review)"
)

# Once a private export to an EXTERNAL destination is withheld this turn, the
# verifier / read-only may not auto-allow another export of the same policy classes
# to external in the same turn — regardless of which tool or channel is used. This
# closes the terminal->browser channel-shop: the deterministic engine already gated
# the first attempt; this denies the re-route a soft channel. Turn-scoped (cleared
# on the next user input and on session reset); never persisted.
def _egress_gating_policy_classes(data_classes: Any) -> set[str]:
    try:
        fine = set(data_classes or ())
    except TypeError:
        return set()
    return set(_taint_policy_classes(fine)) & set(_EGRESS_GATING_POLICY_CLASSES)


def _record_turn_external_denial(session_id: Any, data_classes: Any) -> None:
    classes = _egress_gating_policy_classes(data_classes)
    if not classes:
        return
    with _LOCK:
        _TURN_DENIED_EXTERNAL.setdefault(_normalize_session_id(session_id), set()).update(classes)


def _turn_external_denial_hit(session_id: Any, data_classes: Any) -> bool:
    classes = _egress_gating_policy_classes(data_classes)
    if not classes:
        return False
    with _LOCK:
        remembered = _TURN_DENIED_EXTERNAL.get(_normalize_session_id(session_id))
        return bool(remembered and (classes & remembered))


def _clear_turn_external_denials_for_owner(owner_hash: str) -> None:
    if not owner_hash:
        return
    with _LOCK:
        for sid in set(_OWNER_SESSIONS.get(owner_hash, set())):
            _TURN_DENIED_EXTERNAL.pop(sid, None)


def _block_for_pending_approval(shape: dict[str, Any], tool_name: str, blocked_reason: str) -> dict[str, str]:
    # Withholding a private->external egress arms the turn lockdown so a re-route
    # through another channel this turn cannot be auto-allowed (channel-shop defense).
    _record_turn_external_denial(shape.get("session_id"), shape.get("data_classes"))
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
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
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
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
    )
    return {"action": "block", "message": _guardian_block_message(approval)}


# --- decide() is authoritative (Phase 3, doc 04 §5) --------------------------
# The classify+decide engine now drives the privacy egress decision. The old scattered
# family/destination gating and the taint->gate branching it owned are DELETED; their
# behavior lives in ``decide`` (doc 02 §3). What remains here is the SURROUNDING
# mechanics that decide does not own: the security-first short-circuit (runs before
# decide, unchanged), the read-side classifier helpers, the approval-shape construction,
# the runtime/persistent approval-source matching + consumption (``_approval_source`` —
# which covers once/session user approvals decide cannot see, doc 04 §5 "Persistent
# privacy.rules semantics"), the verifier upgrade in llm mode, the read-only low-risk
# auto-approve preset, activity emission, cron failure notification, and HMAC approval
# binding.
#
# Mapping (doc 02 §3 -> this function):
#   decide ALLOW   -> allow the call (intra-boundary self/draft write, or no private
#                     taint leaving, or an allow declassification rule).
#   decide BLOCK   -> the privacy-rule deny path (_block_for_privacy_rule).
#   decide APPROVE -> gate: llm mode routes through the verifier upgrade
#                     (_llm_policy_tool_call_result, incl. cron high-risk downgrade and
#                     _validated_llm_security_verdict — UNCHANGED); strict/read-only have
#                     no verifier, so read-only's metadata-verified low-risk preset may
#                     auto-approve, else _block_for_pending_approval.


def _shadow_decision_for(tool_name: str, args: Any, session_id: str | None):
    """Build ``(Capability, Decision)`` for a tool call via the authoritative engine.

    Returns ``(capability, decision)`` where ``decision`` is one of the policy outcomes
    (ALLOW/APPROVE/BLOCK from ``privacy/policy``). Used by the corpus-replay parity test
    (``tests/test_policy_engine.py`` test 10) to call the engine directly without going
    through the hook. ``decide`` reasons over the AMBIENT session taint (provenance
    retired, doc 02 §4) and the current purpose/mode — exactly the set the live path below
    feeds it, so the test exercises the real decision.
    """
    cap = classify(tool_name, args, session_id)
    taint = _data_classes_for_egress(session_id, args)
    purpose = _purpose_from_args(args)
    mode = _privacy_policy()
    decision = decide(cap, taint, purpose, mode)
    return cap, decision


def _trusted_destination_classes_cover(entry_classes: Any, leaving: Any) -> bool:
    cls = {str(c).strip().lower() for c in (entry_classes or [])}
    if "*" in cls:
        return True
    return {str(c).strip().lower() for c in (leaving or set())} <= cls


def _trusted_destination_match(action_family: str, args: Any, data_classes: set[str]) -> dict[str, Any] | None:
    """The user-trusted destination entry covering this egress, or None.

    Trusted destinations (Trusted-destinations list) deterministically allow an egress
    when the matched entry's ``classes`` cover everything leaving — a consented
    declassification. ``command`` entries match the terminal command; ``identity`` entries
    match the resolved recipient. Class coverage is mandatory, so an entry trusted for one
    class can never wave through another.
    """
    leaving = set(data_classes or set())
    entries = _trusted_recipients_snapshot()
    if action_family == "terminal_exec":
        command = _terminal_command_for_args(args)
        if command:
            for entry in entries:
                if (
                    entry.get("kind") == "command"
                    and _trusted_command_matches(entry.get("value"), command)
                    and _trusted_destination_classes_cover(entry.get("classes"), leaving)
                ):
                    return entry
    recipient = _normalize_identity(_recipient_raw_from_args(args))
    if recipient:
        for entry in entries:
            if (
                entry.get("kind") == "identity"
                and _normalize_identity(entry.get("value")) == recipient
                and _trusted_destination_classes_cover(entry.get("classes"), leaving)
            ):
                return entry
    return None


def _allow_trusted_destination_call(
    tool_name: str,
    args: Any,
    session_id: str | None,
    *,
    action_family: str,
    destination: str,
    data_classes: set[str],
    entry: dict[str, Any],
    purpose: str = "unknown",
    recipient_identity: str = "none",
    decision_step: str = "",
) -> None:
    kind = str(entry.get("kind") or "identity")
    _emit_egress_activity(
        "allowed",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=data_classes,
        reason=f"matched trusted destination ({kind})",
        action_detail=_activity_action_detail(tool_name, args, action_family, destination),
        purpose=purpose,
        recipient_identity=recipient_identity,
        destination_trust="trusted_recipient",
        decision_step=decision_step,
    )
    _record_allowed_tool_side_effects(session_id, tool_name, args, action_family=action_family)


def _privacy_pre_tool_call(tool_name: str = "", args: Any = None, session_id: str = "") -> dict[str, str] | None:
    """Authoritative privacy pre-tool-call decision, driven by ``decide`` (doc 02 §3).

    Order (charter §5 invariant #1, security before privacy):
      1. Security/intrinsic hard-block short-circuit — UNCHANGED, runs before decide.
      2. ``privacy.mode == off`` disables ONLY private-egress checks (security still ran).
      3. Non-sink calls are reads (taint, never egress; charter invariant #3).
      4. A sink: build the Capability, resolve the runtime/persistent approval source, then
         call ``decide`` and map ALLOW/BLOCK/APPROVE onto the existing mechanics.
    """
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
        return {"action": "block", "message": f"Blocked by {_PLUGIN_NAME}: {reason}."}

    privacy_policy = _privacy_policy()
    action = _egress_action_context_for_tool(tool_name, args, session_id)

    if privacy_policy == "off":
        # off disables ONLY private-egress checks; security already ran (charter §5).
        _allow_privacy_off_tool_call(tool_name, args, session_id, action)
        return None

    if not action:
        # Non-sink: a read. Reads taint; they are never a blockable egress.
        _emit_read_activity_if_applicable(tool_name, args, session_id)
        _record_allowed_tool_side_effects(session_id, tool_name, args)
        return None

    action_family, destination = action.as_tuple()
    data_classes = _data_classes_for_egress(session_id, args)
    # Resolve the Capability + decide() step ONCE up front so every emit path (approval
    # source match, block, approve, verifier) stamps the activity row with the SAME
    # destination trust + decide step (doc 03 §3.2). decide_with_step is pure; the outcome
    # it returns equals what the authoritative decide() below returns (asserted by test).
    cap = classify(tool_name, args, session_id)
    decision, decision_step = decide_with_step(cap, data_classes, action.purpose, privacy_policy)
    destination_trust = _trust_label(getattr(cap.destination, "trust", None))
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
        destination_trust=destination_trust,
        decision_step=decision_step,
    )

    # Runtime + persistent approval matching (once/session/persistent privacy.rules) with
    # consumption + HMAC-bound rule mutation. decide step 5 (match_declassification_rule)
    # only reads persistent rules and cannot see/consume once/session user approvals, so
    # this stays the authoritative source for an explicit user-granted allow/deny (doc 04
    # §5 "Persistent privacy.rules semantics"). When a source matches it wins, exactly as
    # before.
    source = _approval_source(shape)
    if source:
        if source.get("effect") == "deny":
            return _block_for_privacy_rule(shape, tool_name, source)
        _allow_approved_tool_call(shape, source, tool_name, args)
        return None

    # No explicit approval source: the engine decision computed up front (doc 02 §3).
    if decision == _DECISION_ALLOW:
        if not data_classes:
            # No private content leaving — the old "no private data in scope" allow.
            _allow_untainted_tool_call(
                tool_name,
                args,
                session_id,
                action_family=action_family,
                destination=destination,
                purpose=action.purpose,
                recipient_identity=action.recipient_identity,
                destination_trust=destination_trust,
                decision_step=decision_step,
            )
        else:
            # Tainted session, but decide allowed it: an intra-boundary destination
            # (self/draft/local_system/model_provider) reaching no new party. This is the
            # G1 false-positive win — a self-write/draft that used to gate now allows.
            _allow_intra_boundary_tool_call(
                tool_name,
                args,
                session_id,
                action_family=action_family,
                destination=destination,
                data_classes=data_classes,
                trust=cap.destination.trust,
                purpose=action.purpose,
                recipient_identity=action.recipient_identity,
                decision_step=decision_step,
            )
        return None

    if decision == _DECISION_BLOCK:
        # A deny declassification rule that match_declassification_rule caught but the
        # richer _approval_source matcher did not (e.g. a rule keyed purely on
        # purpose/classes/destination without a fingerprint). Preserve the deny block path.
        return _block_for_privacy_rule(
            shape,
            tool_name,
            {"source": "persistent", "effect": "deny", "rule_id": ""},
        )

    # A user-trusted destination (recipient or terminal command) whose class scope covers
    # everything leaving is a consented declassification — allow deterministically before
    # the gate. decide() stays pure; deny rules above still win; the security layer already
    # ran. Class-scoped, so an entry trusted only for local_system can't launder other
    # classes out.
    trusted_destination = _trusted_destination_match(action_family, args, data_classes)
    if trusted_destination is not None:
        _allow_trusted_destination_call(
            tool_name,
            args,
            session_id,
            action_family=action_family,
            destination=destination,
            data_classes=data_classes,
            entry=trusted_destination,
            purpose=action.purpose,
            recipient_identity=action.recipient_identity,
            decision_step=decision_step,
        )
        return None

    if action_family == "terminal_exec":
        # Remember a safe prefix of this gated command so the Trusted-destinations picker
        # can offer "trust this" (recent-blocks source). Flags/values are stripped.
        suggestion = _command_prefix_for_suggestion(_terminal_command_for_args(args))
        if suggestion:
            _record_command_suggestion(suggestion)

    # decision == APPROVE: gate for human approval (doc 02 §3 step 6).
    # Cross-channel turn lockdown (channel-shopping defense): if a private export of
    # these classes to an external destination was already withheld this turn, an
    # AUTO-ALLOW (read-only preset OR llm verifier) is downgraded to a manual gate. The
    # verifier still runs and may DENY; it just may not auto-allow a re-routed export
    # this turn. Channel-agnostic; turn-scoped (cleared on the next user input).
    lockdown = _turn_external_denial_hit(session_id, data_classes)

    if privacy_policy == "read-only" and not lockdown and _read_only_auto_approves(shape, args):
        # read-only's metadata-verified low-risk auto-approve preset (doc 02 §6): a
        # read-only auto-approval that happens today must still happen.
        _allow_read_only_tool_call(shape, tool_name, args)
        return None

    blocked_reason = _LOCKDOWN_BLOCKED_REASON if lockdown else "requires approval"
    if privacy_policy == "llm":
        # llm mode: the verifier may UPGRADE the APPROVE to allow/hold/deny, including the
        # cron high-risk downgrade and _validated_llm_security_verdict — UNCHANGED.
        llm_result, llm_blocked_reason = _llm_policy_tool_call_result(shape, tool_name, args)
        if llm_result is not None:
            return llm_result
        if llm_blocked_reason is None:
            # Verifier cleared it. Honor that unless the turn lockdown is armed, in which
            # case a re-routed external export is gated for the human regardless.
            if not lockdown:
                return None
        elif not lockdown:
            blocked_reason = llm_blocked_reason

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
        # Provenance retired (doc 02 §4): the read taints the session ambiently; there is
        # no read-time fingerprint index. ``decide`` reasons over this ambient taint.
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
