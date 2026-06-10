"""Approval matching, pending approval creation, and LLM verdict helpers."""

from __future__ import annotations

def _guardian_hmac_key() -> bytes:
    try:
        if not _GUARDIAN_HMAC_KEY_PATH.exists():
            _GUARDIAN_HMAC_KEY_PATH.write_bytes(secrets.token_bytes(32))
            try:
                _GUARDIAN_HMAC_KEY_PATH.chmod(0o600)
            except Exception:
                pass
        key = _GUARDIAN_HMAC_KEY_PATH.read_bytes()
        if len(key) >= 32:
            return key
    except Exception as exc:
        logger.warning("%s: failed to load approval HMAC key: %s", _PLUGIN_NAME, exc)
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
        "purpose": _normalize_rule_purpose(purpose, allow_star=False),
        "recipient_identity": _normalize_rule_recipient_identity(recipient_identity, allow_star=False),
        "data_classes": sorted(data_classes),
        "arg_keys": arg_keys,
        "args_hmac": _args_hmac(args),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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
    state = _ensure_session(session_id)
    safe_purpose = _normalize_rule_purpose(purpose, allow_star=False)
    safe_recipient_identity = _normalize_rule_recipient_identity(recipient_identity, allow_star=False)
    return {
        "session_id": _normalize_session_id(session_id),
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
        "action_detail": _activity_action_detail(tool_name, args, action_family, destination),
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
    cutoff = _now() - _RECENT_COMMAND_TTL_SECONDS
    with _LOCK:
        _load_pending_approvals_from_store_unlocked()
        expired = [
            approval_id
            for approval_id, approval in _PENDING_APPROVALS.items()
            if float(approval.get("expires_at", 0)) <= _now()
        ]
        for approval_id in expired:
            _PENDING_APPROVALS.pop(approval_id, None)
        if expired:
            _delete_pending_approvals_from_store_unlocked(expired)
        for key, entries in list(_RECENT_COMMAND_OWNERS.items()):
            fresh = [(ts, owner) for ts, owner in entries if ts >= cutoff]
            if fresh:
                _RECENT_COMMAND_OWNERS[key] = fresh
            else:
                _RECENT_COMMAND_OWNERS.pop(key, None)
        request_cutoff = _now() - _USER_REQUEST_TTL_SECONDS
        for owner_hash, (timestamp, _text) in list(_RECENT_OWNER_REQUESTS.items()):
            if timestamp < request_cutoff:
                _RECENT_OWNER_REQUESTS.pop(owner_hash, None)


def _terminal_command_is_low_risk(args: Any) -> bool:
    command = ""
    if isinstance(args, dict):
        command = str(args.get("command") or args.get("cmd") or "")
    if not command:
        return False
    if _READ_ONLY_AUTO_APPROVE_DENY_RE.search(command):
        return False
    return bool(_READ_ONLY_TERMINAL_SAFE_RE.search(command))


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
    command = _EMAIL_ADDRESS_RE.sub("<email>", command)
    command = _PHONE_RE.sub("<phone>", command)
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
    if _sensitive_reason(value):
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


def _sanitize_rationale(text: str) -> str:
    """Strip personal data from a verdict rationale before it is shown or stored.

    The rationale is persisted into activity/approval rows. The verifier is also
    prompted to keep it class-level, but redact defensively: emails, phones, and
    credential-shaped tokens never reach at-rest storage.
    """
    text = _EMAIL_ADDRESS_RE.sub("<email>", str(text or ""))
    text = _PHONE_RE.sub("<phone>", text)
    text = re.sub(r"\b[A-Za-z0-9_-]{24,}\b", "<token-like>", text)
    return text.strip()[:240]


def _llm_hard_deny_reason(shape: dict[str, Any], args: Any) -> str | None:
    safe_remote_read = (
        shape.get("action_family") == "terminal_exec"
        and _terminal_command_is_safe_remote_read(_terminal_command_for_args(args))
    )
    text = _stringify_for_scan({
        "tool_name": shape.get("tool_name", ""),
        "action_family": shape.get("action_family", ""),
        "destination": shape.get("destination", ""),
        "args": args,
    })
    if _LLM_SECURITY_HARD_DENY_RE.search(text):
        return "explicit malicious or credential-exfiltration pattern"
    if _UNTRUSTED_DROPBOX_ENDPOINT_RE.search(text) and not safe_remote_read:
        return "explicit malicious or credential-exfiltration pattern"
    return None


def _llm_verdict_input(shape: dict[str, Any], args: Any) -> dict[str, Any]:
    user_request = _recent_user_request_for_owner(shape.get("owner_hash", ""))
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
            "security_sensitive_content_already_hard_blocked": True,
            "manual_approval_available_if_denied": True,
        },
    }
    if user_request and _llm_user_context_enabled():
        # Present only for authenticated owner origins; sanitized authorization
        # evidence, not an instruction (see _LLM_POLICY_INSTRUCTIONS).
        payload["user_request_context"] = {"sanitized_user_request": user_request}
    if _llm_cron_context_enabled():
        cron_instruction = _cron_instruction_for_session(shape.get("session_id"))
        if cron_instruction:
            # The cron job's own standing instruction. High-risk cron egress is
            # still never auto-approved (enforced in _llm_policy_tool_call_result).
            payload["cron_context"] = {"sanitized_cron_instruction": cron_instruction}
    return payload


def _validated_llm_security_verdict(parsed: Any) -> dict[str, str]:
    if not isinstance(parsed, dict):
        raise ValueError("verdict was not a JSON object")
    allowed_outcomes = set(_LLM_VERDICT_SCHEMA["properties"]["outcome"]["enum"])
    allowed_risks = set(_LLM_VERDICT_SCHEMA["properties"]["risk_level"]["enum"])
    allowed_auth = set(_LLM_VERDICT_SCHEMA["properties"]["authorization_level"]["enum"])
    missing = [key for key in _LLM_VERDICT_SCHEMA["required"] if key not in parsed]
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


def _deny_cache_key(shape: dict[str, Any]) -> str:
    return "|".join([
        _normalize_session_id(shape.get("session_id")),
        str(shape.get("owner_hash") or ""),
        str(shape.get("fingerprint") or ""),
    ])


def _cached_deny_verdict(shape: dict[str, Any]) -> dict[str, str] | None:
    """Return a recent cached DENY verdict for this exact action, if still fresh.

    Only denials are cached, so a stale hit can never become a false allow; at
    worst it re-denies an action that just became authorized, which self-corrects
    after the short TTL.
    """
    key = _deny_cache_key(shape)
    with _LOCK:
        entry = _LLM_DENY_VERDICT_CACHE.get(key)
        if not entry:
            return None
        timestamp, verdict = entry
        if _now() - timestamp > _LLM_DENY_VERDICT_TTL_SECONDS:
            _LLM_DENY_VERDICT_CACHE.pop(key, None)
            return None
        return dict(verdict)


def _store_deny_verdict(shape: dict[str, Any], verdict: dict[str, str]) -> None:
    # Never cache an allow (would risk a false allow on context change) or a
    # transient fail-closed/unavailable verdict (risk_level "unknown").
    if verdict.get("outcome") == "allow" or verdict.get("risk_level") == "unknown":
        return
    with _LOCK:
        if len(_LLM_DENY_VERDICT_CACHE) > 512:
            cutoff = _now() - _LLM_DENY_VERDICT_TTL_SECONDS
            for cache_key, (timestamp, _v) in list(_LLM_DENY_VERDICT_CACHE.items()):
                if timestamp < cutoff:
                    _LLM_DENY_VERDICT_CACHE.pop(cache_key, None)
        _LLM_DENY_VERDICT_CACHE[_deny_cache_key(shape)] = (_now(), dict(verdict))


def _llm_verifier_unavailable_verdict(rationale: str) -> dict[str, str]:
    return {
        "outcome": "deny",
        "risk_level": "unknown",
        "authorization_level": "unknown",
        "rationale": rationale,
    }


def _llm_security_verdict(shape: dict[str, Any], args: Any) -> dict[str, str]:
    llm = _PLUGIN_LLM
    if llm is None or not hasattr(llm, "complete_structured"):
        return _llm_verifier_unavailable_verdict("LLM verifier unavailable")
    _perf_mark_llm_invoked()
    verifier_model = _llm_verifier_model()
    input_text = json.dumps(_llm_verdict_input(shape, args), sort_keys=True)

    def _call(use_model: bool) -> Any:
        kwargs: dict[str, Any] = {
            "instructions": _LLM_POLICY_INSTRUCTIONS,
            "input": [{"type": "text", "text": input_text}],
            "json_schema": _LLM_VERDICT_SCHEMA,
            "temperature": 0,
            "max_tokens": 240,
            "timeout": 20,
            "purpose": "hermes-guardian.security_llm",
            "schema_name": "hermes_guardian_verdict",
        }
        if use_model and verifier_model:
            kwargs["model"] = verifier_model
        return llm.complete_structured(**kwargs)

    try:
        result = _call(use_model=True)
    except Exception as exc:
        if verifier_model:
            # The model override can be rejected (e.g. allow_model_override is not
            # granted in config) or the fast model may be unavailable. Never
            # fail-close the verifier on that: retry once on the default model so a
            # misconfiguration degrades to "slower", not "deny everything".
            logger.warning(
                "%s: verifier model override %r failed (%s); retrying on default model",
                _PLUGIN_NAME, verifier_model, exc,
            )
            try:
                result = _call(use_model=False)
            except Exception as exc2:
                logger.warning("%s: LLM security verifier failed closed: %s", _PLUGIN_NAME, exc2)
                return _llm_verifier_unavailable_verdict("LLM verifier failed closed")
        else:
            logger.warning("%s: LLM security verifier failed closed: %s", _PLUGIN_NAME, exc)
            return _llm_verifier_unavailable_verdict("LLM verifier failed closed")

    try:
        parsed = getattr(result, "parsed", None)
        if parsed is None and getattr(result, "text", ""):
            parsed = json.loads(str(result.text))
        return _validated_llm_security_verdict(parsed)
    except Exception as exc:
        logger.warning("%s: LLM security verifier failed closed: %s", _PLUGIN_NAME, exc)
        return _llm_verifier_unavailable_verdict("LLM verifier failed closed")
