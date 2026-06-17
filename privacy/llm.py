"""Approval matching, pending approval creation, and LLM verdict helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any
from urllib.parse import urlparse

from . import action_details
from . import approvals
from . import capability
from . import destinations
from . import rules
from . import tool_policy
from .. import core
from .. import state
from ..runtime import activity_store
from ..security import module as security_module

_LLM_SOURCE_RATIONALE_MAX_CHARS = 2000


def _guardian_hmac_key() -> bytes:
    try:
        if not state._GUARDIAN_HMAC_KEY_PATH.exists():
            state._GUARDIAN_HMAC_KEY_PATH.write_bytes(secrets.token_bytes(32))
            try:
                state._GUARDIAN_HMAC_KEY_PATH.chmod(0o600)
            except Exception:
                pass
        key = state._GUARDIAN_HMAC_KEY_PATH.read_bytes()
        if len(key) >= 32:
            return key
    except Exception as exc:
        core.logger.warning("%s: failed to load approval HMAC key: %s", core._PLUGIN_NAME, exc)
        raise RuntimeError("guardian HMAC key unavailable") from exc
    raise RuntimeError("guardian HMAC key was invalid")


def _args_hmac(args: Any) -> str:
    canonical = json.dumps(
        args,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hmac.new(_guardian_hmac_key(), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _approval_fingerprint(
    *,
    tool_name: str,
    action_family: str,
    destination: str,
    purpose: str,
    recipient_identity: str,
    data_classes: set[str],
    args: Any,
) -> str:
    arg_keys = sorted(str(k) for k in args.keys()) if isinstance(args, dict) else []
    payload = {
        "tool_name": tool_name,
        "action_family": action_family,
        "destination": destination,
        "purpose": tool_policy._normalize_rule_purpose(purpose, allow_star=False),
        "recipient_identity": tool_policy._normalize_rule_recipient_identity(recipient_identity, allow_star=False),
        "data_classes": sorted(data_classes),
        "arg_keys": arg_keys,
        "args_hmac": _args_hmac(args),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _permit_targets(action_family: str, args: Any) -> dict[str, str]:
    """Raw permit candidates captured at block time (doc 06 §4.1).

    These are the concrete values a structural permit would add to ``self.*`` /
    ``trusted_recipients`` — which the engine matches RAW. Unlike the pseudonymized
    ``recipient_identity``, they are kept verbatim, but ONLY in the short-lived
    pending-approval row (deleted on approve/dismiss/expiry), so the operator can later
    say "this recipient is me" / "trust this host" / "trust this command" without the
    raw target having to be re-typed or re-derived (doc 06 §4 decision).
    """
    family = str(action_family or "")
    recipient = host = command = ""
    if family in capability._MESSAGING_FAMILIES:
        recipient = tool_policy._recipient_raw_from_args(args)
    elif family == "terminal_exec":
        command = tool_policy._command_prefix_for_suggestion(
            tool_policy._terminal_command_for_args(args)
        )
        host = destinations._normalize_host(tool_policy._extract_url(args) or "")
    elif family in {"web_api", "web_read", "browser_read"}:
        host = destinations._normalize_host(tool_policy._extract_url(args) or "")
    return {
        "permit_recipient": str(recipient or "")[:200],
        "permit_host": str(host or "")[:200],
        "permit_command": str(command or "")[:200],
    }


def _approval_shape(
    *,
    session_id: str | None,
    tool_name: str,
    action_family: str,
    destination: str,
    purpose: str = "unknown",
    recipient_identity: str = "none",
    legacy_destination: str = "",
    data_classes: set[str],
    args: Any,
    destination_trust: str = "unknown",
    decision_step: str = "",
) -> dict[str, Any]:
    state = tool_policy._ensure_session(session_id)
    safe_purpose = tool_policy._normalize_rule_purpose(purpose, allow_star=False)
    safe_recipient_identity = tool_policy._normalize_rule_recipient_identity(recipient_identity, allow_star=False)
    permit_targets = _permit_targets(action_family, args)
    return {
        "session_id": tool_policy._normalize_session_id(session_id),
        "owner_hash": state.get("owner_hash") or "",
        "tool_name": tool_name,
        "action_family": action_family,
        "destination": destination,
        "purpose": safe_purpose,
        "recipient_identity": safe_recipient_identity,
        "legacy_destination": str(legacy_destination or ""),
        "data_classes": sorted(data_classes),
        # Destination-trust metadata (doc 03 §3.2). Carried on the shape so every emit
        # path (block / approve / verifier upgrade) can stamp the activity row with the
        # same trust + decide() step that produced the outcome. Enum/label only.
        "destination_trust": str(destination_trust or "unknown"),
        "decision_step": str(decision_step or ""),
        # Raw permit candidates (doc 06 §4.1), short-lived (pending-approval row only).
        "permit_recipient": permit_targets["permit_recipient"],
        "permit_host": permit_targets["permit_host"],
        "permit_command": permit_targets["permit_command"],
        "action_detail": action_details._activity_action_detail(tool_name, args, action_family, destination),
        "fingerprint": _approval_fingerprint(
            tool_name=tool_name,
            action_family=action_family,
            destination=destination,
            purpose=safe_purpose,
            recipient_identity=safe_recipient_identity,
            data_classes=data_classes,
            args=args,
        ),
    }


def _prune_expired() -> None:
    cutoff = state._now() - core._RECENT_COMMAND_TTL_SECONDS
    with state._LOCK:
        approvals._load_pending_approvals_from_store_unlocked()
        expired = [
            approval_id
            for approval_id, approval in state._PENDING_APPROVALS.items()
            if float(approval.get("expires_at", 0)) <= state._now()
        ]
        for approval_id in expired:
            state._PENDING_APPROVALS.pop(approval_id, None)
        if expired:
            approvals._delete_pending_approvals_from_store_unlocked(expired)
        for key, entries in list(state._RECENT_COMMAND_OWNERS.items()):
            fresh = [(ts, owner) for ts, owner in entries if ts >= cutoff]
            if fresh:
                state._RECENT_COMMAND_OWNERS[key] = fresh
            else:
                state._RECENT_COMMAND_OWNERS.pop(key, None)
        for owner_hash in list(state._OWNER_REQUEST_HISTORY):
            approvals._prune_owner_context_unlocked(owner_hash)


def _terminal_command_is_low_risk(args: Any) -> bool:
    command = ""
    if isinstance(args, dict):
        command = str(args.get("command") or args.get("cmd") or "")
    if not command:
        return False
    if core._READ_ONLY_AUTO_APPROVE_DENY_RE.search(command):
        return False
    return bool(core._READ_ONLY_TERMINAL_SAFE_RE.search(command))


def _read_only_auto_approves(shape: dict[str, Any], args: Any) -> bool:
    """Metadata-only low-risk verifier for read-only privacy policy.

    This deliberately does not inspect or transmit raw private content. Anything
    not recognized as low-risk falls back to manual approval.
    """
    if shape.get("action_family") == "terminal_exec":
        return _terminal_command_is_low_risk(args)
    return False


def _sanitize_url_for_llm(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        return "<redacted-url>"
    netloc = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{netloc}:{port}"
    path_marker = "/<path:redacted>" if parsed.path and parsed.path != "/" else ""
    return f"{parsed.scheme}://{netloc}{path_marker}"


def _redact_command_for_llm(command: str) -> str:
    command = re.sub(r"https?://[^\s\"'<>]+", lambda m: _sanitize_url_for_llm(m.group(0)), command)
    command = core._EMAIL_ADDRESS_RE.sub("<email>", command)
    command = core._PHONE_RE.sub("<phone>", command)
    command = re.sub(r"(['\"])(?:(?=(\\?))\2.)*?\1", lambda m: f"{m.group(1)}<string:{len(m.group(0))}>{m.group(1)}", command)
    command = re.sub(r"\b[A-Za-z0-9_-]{24,}\b", "<token-like>", command)
    return command[:500]


_LLM_PAYLOAD_VALUE_MAX_CHARS = 2000


def _payload_string_for_llm(value: str) -> str:
    """Return the real string for the verifier, with security-sensitive content removed.

    In llm mode the verifier sees the actual action payload (the same LLM/provider
    already processes all of this content as the agent), so it can judge whether the
    content matches the authorized intent. Security-sensitive content is still
    stripped: such args are hard-blocked upstream before privacy runs, and this is
    defense in depth. Credential-shaped tokens are removed even inside benign text,
    and length is bounded.
    """
    if security_module._sensitive_reason(value):
        return "<redacted: security-sensitive content>"
    redacted = re.sub(r"\b[A-Za-z0-9_-]{24,}\b", "<token-like>", value)
    if len(redacted) > _LLM_PAYLOAD_VALUE_MAX_CHARS:
        redacted = redacted[:_LLM_PAYLOAD_VALUE_MAX_CHARS] + "<...truncated>"
    return redacted


def _safe_arg_summary_for_llm(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "<max-depth>"
    if isinstance(value, dict):
        return {
            str(k)[:80]: _safe_arg_summary_for_llm(v, depth=depth + 1)
            for k, v in list(value.items())[:40]
        }
    if isinstance(value, list):
        return [_safe_arg_summary_for_llm(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, tuple):
        return [_safe_arg_summary_for_llm(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, str):
        return _payload_string_for_llm(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


def _sanitize_rationale(text: str, *, limit: int = 240) -> str:
    """Strip personal data from a verdict rationale before it is shown or stored.

    The rationale is persisted into activity/approval rows. The verifier is also
    prompted to keep it class-level, but redact defensively: emails, phones, and
    credential-shaped tokens never reach at-rest storage.
    """
    text = core._EMAIL_ADDRESS_RE.sub("<email>", str(text or ""))
    text = core._PHONE_RE.sub("<phone>", text)
    text = re.sub(r"\b[A-Za-z0-9_-]{24,}\b", "<token-like>", text)
    return text.strip()[:limit]


def _llm_hard_deny_reason(shape: dict[str, Any], args: Any) -> str | None:
    safe_remote_read = (
        shape.get("action_family") == "terminal_exec"
        and tool_policy._tool_call_is_safe_remote_read(shape.get("tool_name", ""), args)
    )
    text = security_module._stringify_for_scan({
        "tool_name": shape.get("tool_name", ""),
        "action_family": shape.get("action_family", ""),
        "destination": shape.get("destination", ""),
        "args": args,
    })
    if core._LLM_SECURITY_HARD_DENY_RE.search(text):
        return "explicit malicious or credential-exfiltration pattern"
    if core._UNTRUSTED_DROPBOX_ENDPOINT_RE.search(text) and not safe_remote_read:
        return "explicit malicious or credential-exfiltration pattern"
    return None


def _owner_context_present(shape: dict[str, Any]) -> bool:
    """True iff owner/cron authorization context is ACTUALLY attached for this verdict.

    Mirrors exactly the conditions under which ``_llm_verdict_input`` attaches
    ``user_request_context`` (sanitized owner-authored context from an authenticated
    session owner, with the owner-context channel enabled) or ``cron_context`` (the
    standing instruction of the cron job that owns this run, with the cron-context
    channel enabled). This is the corroboration signal: it is true only when Guardian holds
    concrete owner/cron authorization for this owner context — not merely because
    the model emitted ``explicit``/``substantive`` (both of those fields are model-emitted
    and therefore attacker-influenceable). The external-export allow gate combines the
    model's authorization_level with this independent presence check (doc 02 §3 / charter
    §2.1-§2.2): an external/unknown private export is auto-allowed only when BOTH agree.
    """
    if (
        rules._llm_user_context_enabled()
        and approvals._owner_context_for_verdict(shape, expanded=False)
    ):
        return True
    if (
        rules._llm_cron_context_enabled()
        and approvals._cron_instruction_for_session(shape.get("session_id"))
    ):
        return True
    return False


# The private POLICY classes whose external export needs owner corroboration: the
# personal-private vocabulary (calendar/contacts/communications/documents/memory — all
# collapse to ``personal_private``) plus private browser input. ``local_system`` is
# DELIBERATELY excluded: a session tainted only by ``local_system`` reads is the engine's
# "not personally-private" tier (a safe remote read pulling data IN, not exporting personal
# data OUT), and the charter requires reads/local-only flows stay unaffected by this gate.
# Unrecognized taint tokens fail closed to ``personal_private`` (see ``_taint_policy_classes``),
# so they are covered.
_CORROBORATION_PRIVATE_POLICY_CLASSES = frozenset(
    capability.PRIVATE_POLICY_CLASSES | {"browser_private"}
)


def _export_private_policy_classes(data_classes: Any) -> set[str]:
    """The corroboration-relevant private POLICY classes carried by ``data_classes``.

    Collapses the shape's fine taint classes to policy classes (via the engine's
    ``_taint_policy_classes`` — same adapter ``decide`` uses) and intersects with
    ``_CORROBORATION_PRIVATE_POLICY_CLASSES``. Empty means nothing personally-private (or
    private browser input) is leaving — e.g. a ``local_system``-only safe remote read.
    """
    from . import policy

    try:
        return set(policy._taint_policy_classes(data_classes)) & _CORROBORATION_PRIVATE_POLICY_CLASSES
    except Exception:
        return set()


def _is_external_private_export(shape: dict[str, Any]) -> bool:
    """True iff this egress sends personally-private data to an external/unknown destination.

    The two softest-trust labels (``external`` and the fail-closed ``unknown``, which
    ``decide`` treats as external — doc 01 §2) carrying a non-empty PRIVATE policy-class set
    (``_export_private_policy_classes`` — personal_private / browser_private, NOT
    local_system). Intra-boundary destinations (self / local_system / model_provider) and
    consented ``trusted_recipient`` destinations are excluded by the trust check; pure
    ``local_system`` reads are excluded by the private-class check. Only the genuinely
    outward, least-known sinks carrying personal data need the corroboration gate.
    """
    trust = str(shape.get("destination_trust") or "unknown").strip().lower()
    if trust not in {"external", "unknown"}:
        return False
    return bool(_export_private_policy_classes(shape.get("data_classes")))


def _llm_allow_lacks_owner_corroboration(
    shape: dict[str, Any],
    verdict: dict[str, str],
    owner_context_present: bool,
    *,
    safe_remote_read: bool = False,
) -> bool:
    return bool(_llm_corroboration_downgrade_reason(
        shape,
        verdict,
        owner_context_present,
        safe_remote_read=safe_remote_read,
    ))


def _llm_corroboration_downgrade_reason(
    shape: dict[str, Any],
    verdict: dict[str, str],
    owner_context_present: bool,
    *,
    safe_remote_read: bool = False,
) -> str:
    """Reason iff an ``allow`` verdict for a private external export must be downgraded.

    Deterministic corroboration applied UNIFORMLY across risk bands (doc 02 §3): the
    softest model-trust point is an ``allow`` of a private export to an external/unknown
    destination, where the prompt tells the model to wave through low/medium risk. Both
    ``risk_level`` and ``authorization_level`` are model-emitted, so the high-risk gate in
    ``_validated_llm_security_verdict`` gives only false determinism. This check requires,
    in ADDITION, that BOTH hold before such an allow is honored:
      (1) the model rated authorization ``explicit`` or ``substantive``, AND
      (2) Guardian ACTUALLY held owner/cron authorization context for this owner this
          window (``owner_context_present`` — see ``_owner_context_present``).
    If either is missing, the allow is downgraded to a manual gate. This is purely
    ADDITIVE: it can only turn an allow into a gate, never the reverse, and it never
    touches intra-boundary allows or reads (``_is_external_private_export`` excludes them).
    A low-risk verifier allow for a structurally safe public remote read is not a private
    export for corroboration purposes; the conservative safe-remote-read helper remains
    the eligibility boundary.
    """
    if verdict.get("outcome") != "allow":
        return ""
    if not _is_external_private_export(shape):
        return ""
    if str(verdict.get("risk_level") or "").strip().lower() == "low" and safe_remote_read:
        return ""
    authorization_level = str(verdict.get("authorization_level") or "").strip().lower()
    missing: list[str] = []
    if authorization_level not in {"explicit", "substantive"}:
        missing.append(f"verifier authorization was {authorization_level or 'unknown'}")
    if not owner_context_present:
        missing.append("owner/cron authorization context was absent")
    if not missing:
        return ""
    return "external private export lacks corroboration: " + "; ".join(missing)


def _llm_verdict_input(shape: dict[str, Any], args: Any, *, expand_owner_context: bool = False) -> dict[str, Any]:
    user_context = approvals._owner_context_for_verdict(
        shape,
        expanded=bool(expand_owner_context),
    )
    payload: dict[str, Any] = {
        "planned_action": {
            "tool_name": shape.get("tool_name", ""),
            "action_family": shape.get("action_family", ""),
            "destination": shape.get("destination", ""),
            "purpose": shape.get("purpose", "unknown"),
            "recipient_identity": shape.get("recipient_identity", "none"),
            "data_classes": sorted(shape.get("data_classes") or []),
            "argument_shape_fingerprint": shape.get("fingerprint", ""),
        },
        # The actual action payload, with security-sensitive content removed. The
        # verifier reads the real content so it can check it against the authorized
        # intent (e.g. notice an email field carrying a calendar event).
        "action_arguments": _safe_arg_summary_for_llm(args),
        "privacy_context": {
            "session_has_private_data": bool(shape.get("data_classes")),
            # Ambient classes the session has READ and may be carrying (provenance
            # retired, doc 02 §4): this is the full ambient taint, not a payload-derived
            # subset. The verifier reads ``action_arguments`` (the real payload) and is
            # responsible for narrowing/anti-laundering — judging whether the payload's
            # content is consistent with the authorized intent (charter §2.1-§2.2).
            "classes_in_scope": sorted(shape.get("data_classes") or []),
            "safe_remote_read": (
                shape.get("action_family") == "terminal_exec"
                and tool_policy._tool_call_is_safe_remote_read(shape.get("tool_name", ""), args)
            ),
            "security_sensitive_content_already_hard_blocked": True,
            "manual_approval_available_if_denied": True,
        },
    }
    if user_context and rules._llm_user_context_enabled():
        # Present only for authenticated owner origins; sanitized authorization
        # evidence, not an instruction (see _LLM_POLICY_INSTRUCTIONS).
        payload["user_request_context"] = user_context
    if rules._llm_cron_context_enabled():
        cron_instruction = approvals._cron_instruction_for_session(shape.get("session_id"))
        if cron_instruction:
            # The cron job's own standing instruction. High-risk cron egress is
            # still never auto-approved (enforced in _llm_policy_tool_call_result).
            payload["cron_context"] = {"sanitized_cron_instruction": cron_instruction}
    return payload


def _validated_llm_security_verdict(parsed: Any) -> dict[str, str]:
    if not isinstance(parsed, dict):
        raise ValueError("verdict was not a JSON object")
    allowed_outcomes = set(core._LLM_VERDICT_SCHEMA["properties"]["outcome"]["enum"])
    allowed_risks = set(core._LLM_VERDICT_SCHEMA["properties"]["risk_level"]["enum"])
    allowed_auth = set(core._LLM_VERDICT_SCHEMA["properties"]["authorization_level"]["enum"])
    missing = [key for key in core._LLM_VERDICT_SCHEMA["required"] if key not in parsed]
    if missing:
        raise ValueError(f"verdict missing required fields: {', '.join(missing)}")
    outcome = str(parsed.get("outcome") or "").strip().lower()
    risk_level = str(parsed.get("risk_level") or "").strip().lower()
    authorization_level = str(parsed.get("authorization_level") or "").strip().lower()
    rationale = str(parsed.get("rationale") or "").strip()
    if outcome not in allowed_outcomes:
        raise ValueError("verdict outcome was invalid")
    if risk_level not in allowed_risks:
        raise ValueError("verdict risk_level was invalid")
    if authorization_level not in allowed_auth:
        raise ValueError("verdict authorization_level was invalid")
    if not rationale:
        raise ValueError("verdict rationale was empty")
    if outcome == "allow" and risk_level == "critical":
        raise ValueError("critical-risk allow verdict is invalid")
    if outcome == "allow" and risk_level == "high" and authorization_level not in {"explicit", "substantive"}:
        raise ValueError("high-risk allow verdict lacked sufficient authorization")
    return {
        "outcome": outcome,
        "risk_level": risk_level[:32],
        "authorization_level": authorization_level[:32],
        "rationale": _sanitize_rationale(rationale),
    }


def _validated_llm_source_classification(parsed: Any) -> dict[str, Any]:
    if not isinstance(parsed, dict):
        raise ValueError("source classification was not a JSON object")
    allowed_sources = set(core._LLM_SOURCE_CLASSIFICATION_SCHEMA["properties"]["source"]["enum"])
    allowed_confidence = set(core._LLM_SOURCE_CLASSIFICATION_SCHEMA["properties"]["confidence"]["enum"])
    missing = [
        key
        for key in core._LLM_SOURCE_CLASSIFICATION_SCHEMA["required"]
        if key not in parsed
    ]
    if missing:
        raise ValueError(f"source classification missing required fields: {', '.join(missing)}")
    source = str(parsed.get("source") or "").strip().lower()
    confidence = str(parsed.get("confidence") or "").strip().lower()
    rationale = str(parsed.get("rationale") or "").strip()
    if source not in allowed_sources:
        raise ValueError("source classification source was invalid")
    if confidence not in allowed_confidence:
        raise ValueError("source classification confidence was invalid")
    if not rationale:
        raise ValueError("source classification rationale was empty")
    raw_taints = parsed.get("taints") if isinstance(parsed.get("taints"), list) else []
    taints = [
        str(cls).strip()
        for cls in raw_taints
        if str(cls).strip() in core._ALL_PRIVACY_CLASSES
    ][:8]
    if source != "private":
        taints = []
    elif not taints:
        taints = ["documents"]
    return {
        "source": source,
        "taints": taints,
        "confidence": confidence,
        "rationale": _sanitize_rationale(rationale, limit=_LLM_SOURCE_RATIONALE_MAX_CHARS),
    }


def _llm_source_classification(metadata: dict[str, Any]) -> dict[str, Any] | None:
    llm = state._PLUGIN_LLM
    if llm is None or not hasattr(llm, "complete_structured"):
        return None
    activity_store._perf_mark_llm_invoked()
    source_model = rules._llm_source_classifier_model()
    input_text = json.dumps(metadata, sort_keys=True)

    def _call(use_model: bool) -> Any:
        kwargs: dict[str, Any] = {
            "instructions": core._LLM_SOURCE_CLASSIFICATION_INSTRUCTIONS,
            "input": [{"type": "text", "text": input_text}],
            "json_schema": core._LLM_SOURCE_CLASSIFICATION_SCHEMA,
            "temperature": 0,
            "max_tokens": 180,
            "timeout": 20,
            "purpose": "hermes-guardian.source_llm",
            "schema_name": "hermes_guardian_source_classification",
        }
        if use_model and source_model:
            kwargs["model"] = source_model
        return llm.complete_structured(**kwargs)

    try:
        result = _call(use_model=True)
    except Exception as exc:
        if source_model:
            core.logger.warning(
                "%s: source classifier model override %r failed (%s); retrying on default model",
                core._PLUGIN_NAME, source_model, exc,
            )
            try:
                result = _call(use_model=False)
            except Exception as exc2:
                core.logger.warning("%s: LLM source classifier unavailable: %s", core._PLUGIN_NAME, exc2)
                return None
        else:
            core.logger.warning("%s: LLM source classifier unavailable: %s", core._PLUGIN_NAME, exc)
            return None

    try:
        parsed = getattr(result, "parsed", None)
        if parsed is None and getattr(result, "text", ""):
            parsed = json.loads(str(result.text))
        return _validated_llm_source_classification(parsed)
    except Exception as exc:
        core.logger.warning("%s: LLM source classifier returned invalid output: %s", core._PLUGIN_NAME, exc)
        return None


def _deny_cache_key(shape: dict[str, Any]) -> str:
    return "|".join([
        tool_policy._normalize_session_id(shape.get("session_id")),
        str(shape.get("owner_hash") or ""),
        str(shape.get("fingerprint") or ""),
        _verdict_context_digest(shape),
    ])


def _verdict_context_digest(shape: dict[str, Any]) -> str:
    context: dict[str, Any] = {}
    if rules._llm_user_context_enabled():
        user_context = approvals._owner_context_for_verdict(
            shape,
            expanded=approvals._owner_context_expansion_active_for_shape(shape),
        )
        if user_context:
            context["user_request_context"] = user_context
    if rules._llm_cron_context_enabled():
        cron_instruction = approvals._cron_instruction_for_session(shape.get("session_id"))
        if cron_instruction:
            context["cron_context"] = {"sanitized_cron_instruction": cron_instruction}
    if not context:
        return ""
    raw = json.dumps(context, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _cached_deny_verdict(shape: dict[str, Any]) -> dict[str, str] | None:
    """Return a recent cached DENY verdict for this exact action, if still fresh.

    Only denials are cached, so a stale hit can never become a false allow; at
    worst it re-denies an action that just became authorized, which self-corrects
    after the short TTL.
    """
    key = _deny_cache_key(shape)
    with state._LOCK:
        entry = state._LLM_DENY_VERDICT_CACHE.get(key)
        if not entry:
            return None
        timestamp, verdict = entry
        if state._now() - timestamp > core._LLM_DENY_VERDICT_TTL_SECONDS:
            state._LLM_DENY_VERDICT_CACHE.pop(key, None)
            return None
        return dict(verdict)


def _store_deny_verdict(shape: dict[str, Any], verdict: dict[str, str]) -> None:
    # Never cache an allow (would risk a false allow on context change) or a
    # transient fail-closed/unavailable verdict (risk_level "unknown").
    if verdict.get("outcome") == "allow" or verdict.get("risk_level") == "unknown":
        return
    with state._LOCK:
        if len(state._LLM_DENY_VERDICT_CACHE) > 512:
            cutoff = state._now() - core._LLM_DENY_VERDICT_TTL_SECONDS
            for cache_key, (timestamp, _v) in list(state._LLM_DENY_VERDICT_CACHE.items()):
                if timestamp < cutoff:
                    state._LLM_DENY_VERDICT_CACHE.pop(cache_key, None)
        state._LLM_DENY_VERDICT_CACHE[_deny_cache_key(shape)] = (state._now(), dict(verdict))


def _llm_verifier_unavailable_verdict(rationale: str) -> dict[str, str]:
    return {
        "outcome": "deny",
        "risk_level": "unknown",
        "authorization_level": "unknown",
        "rationale": rationale,
    }


def _llm_security_verdict(shape: dict[str, Any], args: Any) -> dict[str, str]:
    llm = state._PLUGIN_LLM
    if llm is None or not hasattr(llm, "complete_structured"):
        return _llm_verifier_unavailable_verdict("LLM verifier unavailable")
    activity_store._perf_mark_llm_invoked()
    verifier_model = rules._llm_verifier_model()

    def _input_text(expand_owner_context: bool) -> str:
        return json.dumps(
            _llm_verdict_input(shape, args, expand_owner_context=expand_owner_context),
            sort_keys=True,
        )

    def _call(input_text: str, use_model: bool) -> Any:
        kwargs: dict[str, Any] = {
            "instructions": core._LLM_POLICY_INSTRUCTIONS,
            "input": [{"type": "text", "text": input_text}],
            "json_schema": core._LLM_VERDICT_SCHEMA,
            "temperature": 0,
            "max_tokens": 240,
            "timeout": 20,
            "purpose": "hermes-guardian.security_llm",
            "schema_name": "hermes_guardian_verdict",
        }
        if use_model and verifier_model:
            kwargs["model"] = verifier_model
        return llm.complete_structured(**kwargs)

    def _verdict_for_input(input_text: str) -> dict[str, str]:
        try:
            result = _call(input_text, use_model=True)
        except Exception as exc:
            if verifier_model:
                # The model override can be rejected (e.g. allow_model_override not
                # granted in config) or the fast model may be unavailable. Never
                # fail-close the verifier on that: retry once on the default model so a
                # misconfiguration degrades to "slower", not "deny everything".
                core.logger.warning(
                    "%s: verifier model override %r failed (%s); retrying on default model",
                    core._PLUGIN_NAME, verifier_model, exc,
                )
                try:
                    result = _call(input_text, use_model=False)
                except Exception as exc2:
                    core.logger.warning("%s: LLM security verifier failed closed: %s", core._PLUGIN_NAME, exc2)
                    return _llm_verifier_unavailable_verdict("LLM verifier failed closed")
            else:
                core.logger.warning("%s: LLM security verifier failed closed: %s", core._PLUGIN_NAME, exc)
                return _llm_verifier_unavailable_verdict("LLM verifier failed closed")

        try:
            parsed = getattr(result, "parsed", None)
            if parsed is None and getattr(result, "text", ""):
                parsed = json.loads(str(result.text))
            return _validated_llm_security_verdict(parsed)
        except Exception as exc:
            core.logger.warning("%s: LLM security verifier failed closed: %s", core._PLUGIN_NAME, exc)
            return _llm_verifier_unavailable_verdict("LLM verifier failed closed")

    expanded = approvals._owner_context_expansion_active_for_shape(shape)
    verdict = _verdict_for_input(_input_text(expanded))
    if verdict.get("outcome") == "need_more_context":
        if not expanded and approvals._activate_owner_context_expansion_for_shape(shape):
            expanded = True
            verdict = _verdict_for_input(_input_text(expanded))
        if verdict.get("outcome") == "need_more_context":
            try:
                approvals._queue_owner_context_expansion_for_shape(shape)
            except Exception:
                pass
            return {
                "outcome": "deny",
                "risk_level": "high",
                "authorization_level": "unknown",
                "rationale": "verifier needed more owner context",
            }
    return verdict
