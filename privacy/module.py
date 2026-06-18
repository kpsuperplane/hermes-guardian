"""Privacy egress orchestration for Hermes Guardian."""

from __future__ import annotations

import json
from typing import Any, Callable

from . import action_details
from . import approvals
from . import capability
from . import destinations
from . import llm
from . import policy
from . import rules
from . import tool_policy
from .. import core
from .. import state
from ..integrations import cron_notifications
from ..runtime import activity_store
from ..security import module as security_module



def _emit_read_activity_if_applicable(tool_name: str, args: Any, session_id: str | None) -> bool:
    read_activity = tool_policy._read_activity_for_tool(tool_name, args, session_id)
    if not read_activity:
        return False
    action_family, destination = read_activity
    activity_store._emit_activity(
        "read",
        session_id=session_id,
        tool_name=tool_name,
        action_family=action_family,
        destination=destination,
        data_classes=set(),
        reason="public read",
        action_detail=action_details._activity_action_detail(tool_name, args, action_family, destination),
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
        tool_policy._set_browser_host(session_id, tool_policy._extract_url(args))
    if mark_browser_private_input and action_family == "browser_type":
        tool_policy._mark_browser_private_input(session_id)
    tool_policy._record_local_system_result_policy(session_id, tool_name, args)


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
    activity_store._emit_activity(
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


def _allow_privacy_off_tool_call(tool_name: str, args: Any, session_id: str | None, action: tool_policy.ToolAction | None) -> None:
    if action:
        action_family, destination = action.as_tuple()
        data_classes = tool_policy._data_classes_for_egress(session_id, args)
        if data_classes:
            _emit_egress_activity(
                "privacy_off_allowed",
                session_id=session_id,
                tool_name=tool_name,
                action_family=action_family,
                destination=destination,
                data_classes=data_classes,
                reason="privacy policy off",
                action_detail=action_details._activity_action_detail(tool_name, args, action_family, destination),
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
        action_detail=action_details._activity_action_detail(tool_name, args, action_family, destination),
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
        action_detail=action_details._activity_action_detail(tool_name, args, action_family, destination),
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
    cron_notifications._notify_cron_failure_if_needed(
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
    core.logger.info(
        "%s: read-only policy approved low-risk Hermes Guardian %s to %s for session %s",
        core._PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        tool_policy._normalize_session_id(shape.get("session_id", "")),
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


def _allow_safe_remote_read_tool_call(shape: dict[str, Any], tool_name: str, args: Any) -> None:
    core.logger.info(
        "%s: safe remote read approved Hermes Guardian %s to %s for session %s",
        core._PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        tool_policy._normalize_session_id(shape.get("session_id", "")),
    )
    _emit_egress_activity(
        "auto_approved",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason="safe public remote read",
        rule_source="safe_remote_read",
        action_detail=shape.get("action_detail", ""),
        purpose=shape.get("purpose", "unknown"),
        recipient_identity=shape.get("recipient_identity", "none"),
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
    )
    _record_allowed_tool_side_effects(shape.get("session_id", ""), tool_name, args)


def _allow_safe_local_metadata_tool_call(shape: dict[str, Any], tool_name: str, args: Any) -> None:
    core.logger.info(
        "%s: safe local metadata approved Hermes Guardian %s for session %s",
        core._PLUGIN_NAME,
        shape.get("action_family", ""),
        tool_policy._normalize_session_id(shape.get("session_id", "")),
    )
    _emit_egress_activity(
        "auto_approved",
        session_id=shape.get("session_id", ""),
        owner_hash=shape.get("owner_hash", ""),
        tool_name=tool_name,
        action_family=shape.get("action_family", ""),
        destination=shape.get("destination", ""),
        data_classes=set(shape.get("data_classes") or []),
        reason="safe local metadata computation",
        rule_source="safe_local_metadata",
        action_detail=shape.get("action_detail", ""),
        purpose=shape.get("purpose", "unknown"),
        recipient_identity=shape.get("recipient_identity", "none"),
        destination_trust=shape.get("destination_trust", "unknown"),
        decision_step=shape.get("decision_step", ""),
    )
    _record_allowed_tool_side_effects(shape.get("session_id", ""), tool_name, args)


def _llm_policy_tool_call_result(
    shape: dict[str, Any], tool_name: str, args: Any
) -> tuple[dict[str, str] | None, str | None, Callable[[], None] | None, dict[str, Any]]:
    # Returns ``(block_result, blocked_reason, apply_allow)``. At most one is set:
    #   - block_result: a hard-deny/security block to return verbatim (lockdown-independent).
    #   - blocked_reason: the verifier wants manual approval; caller gates it.
    #   - apply_allow: the verifier auto-approved. The caller invokes this ONLY after the
    #     cross-channel lockdown check passes; it emits the ``auto_approved`` activity row and
    #     records allowed side effects. Deferring it here means a lockdown block never leaves a
    #     phantom ``auto_approved`` twin in the audit trail, and taint/browser-private-input
    #     state is never recorded for an export the lockdown then withholds.
    hard_reason = llm._llm_hard_deny_reason(shape, args)
    if hard_reason:
        _record_turn_external_denial(shape, {"source": "hard_deny", "reason": hard_reason})
        core.logger.info(
            "%s: hard-blocked Hermes Guardian %s to %s for session %s (%s)",
            core._PLUGIN_NAME,
            shape.get("action_family", ""),
            shape.get("destination", ""),
            tool_policy._normalize_session_id(shape.get("session_id", "")),
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
        cron_notifications._notify_cron_failure_if_needed(
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
        return {"action": "block", "message": security_module._block_message(hard_reason)}, None, None, {}

    cached = llm._cached_deny_verdict(shape)
    verdict = cached if cached is not None else llm._llm_security_verdict(shape, args)
    if (
        verdict.get("outcome") == "allow"
        and verdict.get("risk_level") == "high"
        and approvals._is_cron_session_id(shape.get("session_id"))
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
        # don't re-pay the verifier latency. Done BEFORE the corroboration downgrade
        # below so a downgraded allow is NOT poisoned into the deny cache: an allow the
        # model emitted (skipped by _store_deny_verdict) must stay un-cached, so a later
        # call that DOES arrive with owner-authorization context gets a fresh verifier
        # consult instead of a stale gate.
        llm._store_deny_verdict(shape, verdict)
    safe_remote_read = tool_policy._tool_call_is_safe_remote_read(tool_name, args)
    owner_context_present = llm._owner_context_present(shape)
    corroboration_reason = llm._llm_corroboration_downgrade_reason(
        shape,
        verdict,
        owner_context_present,
        safe_remote_read=safe_remote_read,
    )
    if verdict.get("outcome") == "allow" and corroboration_reason:
        # Deterministic corroboration gate (charter §2.1-§2.2). An ``allow`` of a private
        # export to an external/unknown destination is the softest model-trust point: the
        # prompt waves through low/medium risk, and both risk_level and authorization_level
        # are model-emitted. Honor such an allow only when the model rated authorization
        # explicit/substantive AND Guardian ACTUALLY held owner/cron authorization context
        # for this owner context. Otherwise downgrade to a manual gate — never
        # auto-allow. Additive: this only turns an allow into a deny, and only for genuinely
        # outward private exports (intra-boundary allows and reads are untouched). Runs
        # AFTER the cron high-risk downgrade so that cap still holds, and after the deny
        # cache so the downgrade is per-call (never cached as a deny).
        verdict = {
            **verdict,
            "outcome": "deny",
            "rationale": (
                f"{corroboration_reason} "
                f"({verdict.get('rationale', '')})"
            ),
        }
    if verdict.get("outcome") == "allow":
        reason = (
            f"llm {verdict.get('risk_level', 'unknown')}: "
            f"{verdict.get('rationale', 'approved')}"
        )

        def _apply_allow() -> None:
            core.logger.info(
                "%s: LLM-approved Hermes Guardian %s to %s for session %s",
                core._PLUGIN_NAME,
                shape.get("action_family", ""),
                shape.get("destination", ""),
                tool_policy._normalize_session_id(shape.get("session_id", "")),
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

        return None, None, _apply_allow, {
            "source": "llm",
            "outcome": "allow",
            "risk_level": verdict.get("risk_level", "unknown"),
            "authorization_level": verdict.get("authorization_level", "unknown"),
            "owner_context_present": owner_context_present,
            "corroboration_reason": corroboration_reason,
        }

    blocked_reason = (
        f"requires approval (llm {verdict.get('risk_level', 'unknown')}: "
        f"{verdict.get('rationale', 'denied')})"
    )
    return None, blocked_reason, None, {
        "source": "llm",
        "outcome": "deny",
        "risk_level": verdict.get("risk_level", "unknown"),
        "authorization_level": verdict.get("authorization_level", "unknown"),
        "owner_context_present": owner_context_present,
        "corroboration_reason": corroboration_reason,
    }


# --- Cross-channel turn lockdown (channel-shopping defense) ------------------
_LOCKDOWN_ROUTE_BLOCKED_REASON = (
    "requires approval (cross-channel lockdown: likely re-route of a withheld "
    "private export; this retry is gated for your review)"
)
_LOCKDOWN_GLOBAL_BLOCKED_REASON = (
    "requires approval (cross-channel lockdown: a high-risk private export was "
    "already withheld this turn; further outward exports of the same private data "
    "classes are gated for your review)"
)

_LOCKDOWN_ACTION_GROUPS = {
    "browser_type": "browser_write",
    "browser_click": "browser_write",
    "browser_press": "browser_write",
    "browser_dialog": "browser_write",
    "browser_console": "browser_write",
    "browser_cdp": "browser_write",
    "message_send": "message",
    "web_api": "network_write",
    "terminal_exec": "network_write",
    "model_api": "network_write",
    "mcp_write": "service_write",
    "mcp_unknown": "service_write",
    "tool_write": "service_write",
    "tool_unknown": "service_write",
    "local_write": "local_write",
    "cron_write": "local_write",
    "kanban_write": "local_write",
    "homeassistant_write": "local_write",
    "computer_use": "computer_use",
    "browser_read": "read",
    "web_read": "read",
    "mcp_read_query": "read",
    "message_list": "read",
}

# Once a private outward export is withheld this turn, the verifier / read-only
# preset may not auto-allow a likely reroute. High-risk records still apply
# broadly across channels; ordinary ambiguity is route-scoped so one benign bulk
# workflow item does not freeze unrelated same-turn destinations. Records are
# metadata-only, turn-scoped, and never persisted.
def _egress_gating_policy_classes(data_classes: Any) -> set[str]:
    try:
        fine = set(data_classes or ())
    except TypeError:
        return set()
    return set(policy._taint_policy_classes(fine)) & set(policy._EGRESS_GATING_POLICY_CLASSES)


def _lockdown_action_group(action_family: Any) -> str:
    family = str(action_family or "").strip().lower()
    if family in _LOCKDOWN_ACTION_GROUPS:
        return _LOCKDOWN_ACTION_GROUPS[family]
    if family.endswith("_read"):
        return "read"
    if family.endswith("_write"):
        return "service_write"
    return family or "unknown"


def _lockdown_destination_key(destination: Any) -> str:
    return str(destination or "").strip().lower()[:160]


def _lockdown_purpose_key(purpose: Any) -> str:
    return tool_policy._normalize_rule_purpose(purpose or "unknown", allow_star=False)


def _lockdown_recipient_key(recipient_identity: Any) -> str:
    return tool_policy._normalize_rule_recipient_identity(recipient_identity or "none", allow_star=False)


def _lockdown_is_outward_shape(shape: dict[str, Any]) -> bool:
    trust = _trust_label(shape.get("destination_trust", "unknown"))
    if trust in {"self", "local_system", "model_provider", "trusted_recipient"}:
        return False
    return bool(_egress_gating_policy_classes(shape.get("data_classes")))


def _lockdown_scope_for_basis(shape: dict[str, Any], basis: dict[str, Any] | None) -> str:
    basis = basis or {}
    if basis.get("source") in {"hard_deny", "security_blocked"}:
        return "global"
    risk = str(basis.get("risk_level") or "").strip().lower()
    if risk in {"high", "critical"}:
        return "global"
    corroboration = str(basis.get("corroboration_reason") or "").lower()
    if "owner/cron authorization context was absent" in corroboration:
        return "global"
    authorization = str(basis.get("authorization_level") or "").strip().lower()
    if authorization == "unknown" and not bool(basis.get("owner_context_present")):
        return "global"
    return "route"


def _lockdown_record_for_shape(shape: dict[str, Any], basis: dict[str, Any] | None) -> dict[str, Any]:
    classes = _egress_gating_policy_classes(shape.get("data_classes"))
    return {
        "scope": _lockdown_scope_for_basis(shape, basis),
        "classes": sorted(classes),
        "destination": _lockdown_destination_key(shape.get("destination")),
        "action_group": _lockdown_action_group(shape.get("action_family")),
        "action_family": str(shape.get("action_family") or ""),
        "purpose": _lockdown_purpose_key(shape.get("purpose")),
        "recipient_identity": _lockdown_recipient_key(shape.get("recipient_identity")),
        "fingerprint": str(shape.get("fingerprint") or ""),
        "source": str((basis or {}).get("source") or "manual_gate"),
        "risk_level": str((basis or {}).get("risk_level") or "unknown"),
        "authorization_level": str((basis or {}).get("authorization_level") or "unknown"),
        "ts": state._now(),
    }


def _record_turn_external_denial(shape: dict[str, Any] | Any, basis: dict[str, Any] | None = None) -> None:
    if not isinstance(shape, dict):
        shape = {
            "session_id": shape,
            "data_classes": basis if not isinstance(basis, dict) else (),
            "destination_trust": "external",
        }
        basis = {"source": "manual_gate"}
    if not _lockdown_is_outward_shape(shape):
        return
    record = _lockdown_record_for_shape(shape, basis)
    classes = set(record.get("classes") or [])
    if not classes:
        return
    with state._LOCK:
        sid = tool_policy._normalize_session_id(shape.get("session_id"))
        records = [
            entry
            for entry in state._TURN_DENIED_EXTERNAL.get(sid, [])
            if isinstance(entry, dict)
        ]
        records.append(record)
        state._TURN_DENIED_EXTERNAL[sid] = records[-12:]


def _lockdown_record_matches(record: dict[str, Any], shape: dict[str, Any]) -> bool:
    classes = _egress_gating_policy_classes(shape.get("data_classes"))
    if not classes:
        return False
    remembered = set(record.get("classes") or [])
    if not remembered or not (classes & remembered):
        return False
    if str(record.get("scope") or "") == "global":
        return True

    fingerprint = str(shape.get("fingerprint") or "")
    if fingerprint and fingerprint == str(record.get("fingerprint") or ""):
        return True

    recipient = _lockdown_recipient_key(shape.get("recipient_identity"))
    if recipient != "none" and recipient == str(record.get("recipient_identity") or ""):
        return True

    destination = _lockdown_destination_key(shape.get("destination"))
    if not destination or destination != str(record.get("destination") or ""):
        return False
    group = _lockdown_action_group(shape.get("action_family"))
    if group == "read" or str(record.get("action_group") or "") == "read":
        return True
    if group == str(record.get("action_group") or ""):
        return True
    purpose = _lockdown_purpose_key(shape.get("purpose"))
    return purpose != "unknown" and purpose == str(record.get("purpose") or "")


def _turn_external_denial_hit(shape: dict[str, Any], args: Any = None) -> dict[str, Any] | None:
    if tool_policy._tool_call_is_safe_remote_read(shape.get("tool_name", ""), args):
        return None
    if not _lockdown_is_outward_shape(shape):
        return None
    with state._LOCK:
        records = [
            dict(entry)
            for entry in state._TURN_DENIED_EXTERNAL.get(tool_policy._normalize_session_id(shape.get("session_id")), [])
            if isinstance(entry, dict)
        ]
    for record in reversed(records):
        if _lockdown_record_matches(record, shape):
            return record
    return None


def _lockdown_blocked_reason(record: dict[str, Any] | None) -> str:
    if record and str(record.get("scope") or "") == "global":
        return _LOCKDOWN_GLOBAL_BLOCKED_REASON
    return _LOCKDOWN_ROUTE_BLOCKED_REASON


def _clear_turn_external_denials_for_owner(owner_hash: str) -> None:
    if not owner_hash:
        return
    with state._LOCK:
        for sid in set(state._OWNER_SESSIONS.get(owner_hash, set())):
            state._TURN_DENIED_EXTERNAL.pop(sid, None)


def _block_for_pending_approval(
    shape: dict[str, Any],
    tool_name: str,
    blocked_reason: str,
    lockdown_basis: dict[str, Any] | None = None,
    *,
    arm_lockdown: bool = True,
) -> dict[str, str]:
    if arm_lockdown:
        _record_turn_external_denial(shape, lockdown_basis or {"source": "manual_gate"})
    approvals._queue_owner_context_expansion_for_shape(shape)
    approval = approvals._create_pending_approval(shape)
    approval["reason"] = blocked_reason
    approvals._save_pending_approval_to_store_unlocked(approval)
    core.logger.info(
        "%s: blocked Hermes Guardian %s to %s for session %s",
        core._PLUGIN_NAME,
        shape.get("action_family", ""),
        shape.get("destination", ""),
        tool_policy._normalize_session_id(shape.get("session_id", "")),
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
    cron_notifications._notify_cron_failure_if_needed(
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
    return {"action": "block", "message": approvals._guardian_block_message(approval)}


# --- Authoritative privacy egress decision (doc 04 §5) ------------------------
# The classify+decide engine drives the privacy egress decision. This module owns the
# surrounding mechanics that ``decide`` intentionally leaves outside the pure policy
# function: the security-first short-circuit, read-side classifier helpers,
# approval-shape construction, persistent approval-source matching
# (``_approval_source`` — doc 04 §5 "Persistent privacy.rules semantics"), verifier
# upgrade in llm mode, read-only low-risk auto-approve preset, activity emission, cron
# failure notification, and approval binding.
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
    cap = capability.classify(tool_name, args, session_id)
    taint = tool_policy._data_classes_for_egress(session_id, args)
    purpose = tool_policy._purpose_from_args(args)
    mode = core._egress_safety_policy()
    decision = policy.decide(cap, taint, purpose, mode)
    return cap, decision


def _trusted_destination_classes_cover(entry_classes: Any, leaving: Any) -> bool:
    cls = {str(c).strip().lower() for c in (entry_classes or [])}
    if "*" in cls:
        return True
    return {str(c).strip().lower() for c in (leaving or set())} <= cls


def _trusted_destination_match(
    action_family: str, args: Any, data_classes: set[str], destination: Any = None
) -> dict[str, Any] | None:
    """The user-trusted destination entry covering this egress, or None.

    Trusted destinations (Trusted-destinations list) deterministically allow an egress
    when the matched entry's ``classes`` cover everything leaving — a consented
    declassification. ``command`` entries match the terminal command; ``identity`` entries
    match the resolved recipient OR — for a store/draft/local write — the destination's
    connector id (the "trusted-by-connector-id" path, doc 06 §3.1). A store write carries
    no recipient arg, so without the connector-id candidate the "Trust this destination"
    permit would be a dead-end that never re-allows the action. Class coverage is mandatory,
    so an entry trusted for one class can never wave through another.
    """
    leaving = set(data_classes or set())
    entries = rules._trusted_recipients_snapshot()
    if action_family == "terminal_exec":
        command = tool_policy._terminal_command_for_args(args)
        if command:
            for entry in entries:
                if (
                    entry.get("kind") == "command"
                    and tool_policy._trusted_command_matches(entry.get("value"), command)
                    and _trusted_destination_classes_cover(entry.get("classes"), leaving)
                ):
                    return entry
    # Candidate identity tokens: the resolved recipient (messaging) and, for a non-messaging
    # store/draft/local write, the destination connector id. Both are matched RAW against the
    # ``identity`` entries exactly as the permit option stored them.
    candidates: set[str] = set()
    recipient = destinations._normalize_identity(tool_policy._recipient_raw_from_args(args))
    if recipient:
        candidates.add(recipient)
    if action_family not in capability._MESSAGING_FAMILIES:
        dest_id = destinations._normalize_identity(getattr(destination, "id", "") or "")
        if dest_id and dest_id != "messaging":
            candidates.add(dest_id)
    if candidates:
        for entry in entries:
            if (
                entry.get("kind") == "identity"
                and destinations._normalize_identity(entry.get("value")) in candidates
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
        action_detail=action_details._activity_action_detail(tool_name, args, action_family, destination),
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
      2. ``privacy.egress_safety == off`` disables ONLY private-egress checks (security still ran).
      3. Non-sink calls are reads (taint, never egress; charter invariant #3).
      4. A sink: build the Capability, resolve the runtime/persistent approval source, then
         call ``decide`` and map ALLOW/BLOCK/APPROVE onto the existing mechanics.
    """
    intrinsic_risk = tool_policy._intrinsic_risk_for_tool(tool_name, args)
    if intrinsic_risk:
        reason = str(intrinsic_risk.get("reason") or "intrinsic source-and-sink risk")
        action_family = str(intrinsic_risk.get("action_family") or "")
        destination = str(intrinsic_risk.get("destination") or "")
        data_classes = set(intrinsic_risk.get("data_classes") or [])
        _record_turn_external_denial(
            {
                "session_id": session_id,
                "tool_name": tool_name,
                "action_family": action_family,
                "destination": destination,
                "data_classes": data_classes,
                "destination_trust": "external",
                "purpose": "unknown",
                "recipient_identity": "none",
                "fingerprint": "",
            },
            {"source": "security_blocked", "reason": reason},
        )
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
        cron_notifications._notify_cron_failure_if_needed(
            session_id=session_id,
            tool_name=tool_name,
            decision="security_blocked",
            action_family=action_family,
            destination=destination,
            data_classes=data_classes,
            reason=reason,
        )
        return {"action": "block", "message": f"Blocked by {core._PLUGIN_NAME}: {reason}."}

    egress_safety = core._egress_safety_policy()
    action = tool_policy._egress_action_context_for_tool(tool_name, args, session_id)

    if egress_safety == "off":
        # off disables ONLY private-egress checks; security already ran (charter §5).
        _allow_privacy_off_tool_call(tool_name, args, session_id, action)
        return None

    if not action:
        # Non-sink: a read. Reads taint; they are never a blockable egress.
        _emit_read_activity_if_applicable(tool_name, args, session_id)
        _record_allowed_tool_side_effects(session_id, tool_name, args)
        return None

    action_family, destination = action.as_tuple()
    data_classes = tool_policy._data_classes_for_egress(session_id, args)
    # Resolve the Capability + decide() step ONCE up front so every emit path (approval
    # source match, block, approve, verifier) stamps the activity row with the SAME
    # destination trust + decide step (doc 03 §3.2). decide_with_step is pure; the outcome
    # it returns equals what the authoritative decide() below returns (asserted by test).
    cap = capability.classify(tool_name, args, session_id)
    decision, decision_step = policy.decide_with_step(cap, data_classes, action.purpose, egress_safety)
    destination_trust = _trust_label(getattr(cap.destination, "trust", None))
    shape = llm._approval_shape(
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

    # Persistent approval matching. decide step 5 (match_declassification_rule) stays pure;
    # this richer matcher is the authoritative source for an explicit user-granted
    # allow/deny (doc 04 §5 "Persistent privacy.rules semantics"). When a source matches
    # it wins.
    source = rules._approval_source(shape)
    if source:
        if source.get("effect") == "deny":
            return _block_for_privacy_rule(shape, tool_name, source)
        _allow_approved_tool_call(shape, source, tool_name, args)
        return None

    # No explicit approval source: the engine decision computed up front (doc 02 §3).
    if decision == policy._DECISION_ALLOW:
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

    if decision == policy._DECISION_BLOCK:
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
    trusted_destination = _trusted_destination_match(action_family, args, data_classes, cap.destination)
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
        suggestion = tool_policy._command_prefix_for_suggestion(tool_policy._terminal_command_for_args(args))
        if suggestion:
            activity_store._record_suggestion("command", suggestion)

    # decision == APPROVE: gate for human approval (doc 02 §3 step 6).
    # Cross-channel turn lockdown (channel-shopping defense): if a private outward export
    # was already withheld this turn, an AUTO-ALLOW (read-only preset OR llm verifier) is
    # downgraded only when the prior record matches this action as a likely reroute. The
    # verifier still runs and may deny on its own; lockdown only prevents channel-shopping
    # through a softer auto-approval path.
    lockdown = _turn_external_denial_hit(shape, args)

    if egress_safety == "llm" and tool_policy._tool_call_is_safe_local_metadata(tool_name, args):
        # Deterministic local metadata computations do not move the ambient private
        # classes to another party. Keep this as a structural allow, not a verifier
        # corroboration exception.
        _allow_safe_local_metadata_tool_call(shape, tool_name, args)
        return None

    if egress_safety == "llm" and tool_policy._tool_call_is_safe_remote_read(tool_name, args):
        # Deterministic public GET-style remote reads pull data into the agent; they do
        # not export the ambient private classes already in scope. A proven safe public
        # read should not become a manual approval because the ambient taint is broad or
        # a previous export was withheld.
        _allow_safe_remote_read_tool_call(shape, tool_name, args)
        return None

    if egress_safety == "read-only" and llm._read_only_auto_approves(shape, args):
        if lockdown:
            return _block_for_pending_approval(
                shape,
                tool_name,
                _lockdown_blocked_reason(lockdown),
                arm_lockdown=False,
            )
        # read-only's metadata-verified low-risk auto-approve preset (doc 02 §6): a
        # read-only auto-approval that happens today must still happen.
        _allow_read_only_tool_call(shape, tool_name, args)
        return None

    blocked_reason = "requires approval"
    lockdown_basis: dict[str, Any] | None = None
    if egress_safety == "llm":
        # llm mode: the verifier may UPGRADE the APPROVE to allow/hold/deny, including the
        # cron high-risk downgrade and _validated_llm_security_verdict — UNCHANGED.
        llm_result, llm_blocked_reason, llm_apply_allow, llm_lockdown_basis = _llm_policy_tool_call_result(
            shape,
            tool_name,
            args,
        )
        if llm_result is not None:
            return llm_result
        if llm_apply_allow is not None:
            # Verifier auto-approved. Honor that unless a matching turn-lockdown record says
            # this is a likely reroute of a withheld export. The auto_approved activity row
            # and allowed side effects are emitted ONLY here, so a lockdown block never leaves
            # a phantom auto_approved twin in the audit trail.
            if lockdown:
                return _block_for_pending_approval(
                    shape,
                    tool_name,
                    _lockdown_blocked_reason(lockdown),
                    arm_lockdown=False,
                )
            llm_apply_allow()
            return None
        else:
            blocked_reason = llm_blocked_reason or "requires approval"
            lockdown_basis = llm_lockdown_basis

    return _block_for_pending_approval(shape, tool_name, blocked_reason, lockdown_basis)


def _privacy_observe_tool_result(
    tool_name: str = "",
    result: Any = None,
    session_id: str = "",
    status: str = "",
) -> dict[str, Any] | None:
    if not isinstance(result, str) or not result:
        activity_store._record_tool_inventory(tool_name, result=True)
        return None

    parsed: Any
    parsed_ok = True
    try:
        parsed = json.loads(result)
    except (TypeError, ValueError):
        parsed_ok = False
        parsed = result

    local_system_policy = (
        tool_policy._consume_local_system_result_policy(session_id, tool_name)
        if tool_policy._is_local_system_tool(tool_name)
        else {}
    )
    public_remote_read = bool(local_system_policy.get("remote_read"))
    tool_args = tool_policy._consume_pending_tool_args(session_id, tool_name)
    # Provenance verdict, computed once here (the only place with the call's args) and reused
    # on the security inbound path so both sides agree on what "reference material" is.
    tool_policy._maybe_classify_unknown_read_source(
        tool_name,
        parsed,
        status=status,
        tool_args=tool_args,
    )
    is_reference_read = tool_policy._is_reference_read(tool_name, tool_args)
    read_activity = tool_policy._read_activity_for_tool(tool_name, tool_args, session_id)
    activity_store._record_tool_inventory(
        tool_name,
        result=True,
        read_family=read_activity[0] if read_activity else (
            "mcp_read" if tool_policy._is_mcp_doc_read(tool_name) else ""
        ),
        destination=read_activity[1] if read_activity else "",
    )
    source_default = tool_policy._is_source_default_read(tool_name, tool_args)
    strict_unknown_read = False
    taint_classes = tool_policy._taint_classes_for_tool_result(
        tool_name,
        parsed,
        status=status,
        session_id=session_id,
        local_system_policy=local_system_policy,
        tool_args=tool_args,
    )
    if taint_classes:
        strict_unknown_read = tool_policy._is_strict_unknown_read(
            tool_name, parsed, status=status, tool_args=tool_args
        )
    if taint_classes:
        tool_policy._taint_session(session_id, taint_classes)
        # Provenance retired (doc 02 §4): the read taints the session ambiently; there is
        # no read-time fingerprint index. ``decide`` reasons over this ambient taint. An
        # undeclared MCP doc-read carries the source_default reason so the operator can see
        # *why* it was tainted (and the activity row deep-links to the Reading picker).
        reason = (
            tool_policy._SOURCE_DEFAULT_REASON
            if source_default
            else tool_policy._STRICT_UNKNOWN_READ_REASON
            if strict_unknown_read
            else tool_policy._taint_reason_for_tool_result(tool_name, taint_classes)
        )
        activity_store._emit_activity(
            "tainted",
            session_id=session_id,
            tool_name=tool_name,
            data_classes=taint_classes,
            reason=reason,
            # The conservative-default taint row deep-links to the Reading picker so the
            # operator can classify the server one click away (see deepLinks.ts).
            decision_step=(
                tool_policy._SOURCE_DEFAULT_REASON
                if source_default
                else tool_policy._STRICT_UNKNOWN_READ_REASON
                if strict_unknown_read
                else ""
            ),
        )
    else:
        tool_policy._record_public_discovered_urls(
            session_id,
            tool_name,
            parsed,
            taint_classes=taint_classes,
            status=status,
        )

    # First time this session sees an undeclared MCP doc-read from a server, surface a
    # one-click classification suggestion (server prefix only, never content). Declaring the
    # server via the Reading picker silences it and sets the behavior.
    if tool_policy._is_mcp_doc_read(tool_name) and not is_reference_read and not tool_policy._reading_tool_source(tool_name):
        server = tool_policy._mcp_server_prefix(tool_name)
        if server and tool_policy._mark_source_suggested(session_id, server):
            activity_store._record_suggestion("source", server)

    if str(tool_name or "").lower().startswith("browser_"):
        url = tool_policy._extract_url(parsed)
        if url:
            tool_policy._set_browser_host(session_id, url)
        if tool_policy._browser_result_has_private_context(parsed):
            tool_policy._mark_browser_private_input(session_id)
            activity_store._emit_activity(
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
        "is_reference_read": is_reference_read,
    }
