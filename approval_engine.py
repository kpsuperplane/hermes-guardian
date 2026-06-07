"""Modularized guardian runtime module."""

from __future__ import annotations

def _approval_fingerprint(
    *,
    tool_name: str,
    action_family: str,
    destination: str,
    data_classes: set[str],
    args: Any,
) -> str:
    arg_keys = sorted(str(k) for k in args.keys()) if isinstance(args, dict) else []
    payload = {
        "tool_name": tool_name,
        "action_family": action_family,
        "destination": destination,
        "data_classes": sorted(data_classes),
        "arg_keys": arg_keys,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _approval_shape(
    *,
    session_id: str | None,
    tool_name: str,
    action_family: str,
    destination: str,
    data_classes: set[str],
    args: Any,
) -> dict[str, Any]:
    state = _ensure_session(session_id)
    return {
        "session_id": _normalize_session_id(session_id),
        "owner_hash": state.get("owner_hash") or "",
        "tool_name": tool_name,
        "action_family": action_family,
        "destination": destination,
        "data_classes": sorted(data_classes),
        "action_detail": _activity_action_detail(tool_name, args, action_family, destination),
        "fingerprint": _approval_fingerprint(
            tool_name=tool_name,
            action_family=action_family,
            destination=destination,
            data_classes=data_classes,
            args=args,
        ),
    }


def _classes_are_covered(current: set[str], approved: list[str] | set[str]) -> bool:
    return current.issubset(set(approved))


def _rule_matches(rule: dict[str, Any], shape: dict[str, Any]) -> bool:
    rule_action = rule.get("action_family")
    rule_destination = rule.get("destination")
    return (
        (rule.get("owner_hash") == "*" or rule.get("owner_hash") == shape.get("owner_hash"))
        and (rule_action == "*" or rule_action == shape.get("action_family"))
        and (rule_destination == "*" or rule_destination == shape.get("destination"))
        and _classes_are_covered(set(shape.get("data_classes") or []), rule.get("data_classes") or [])
    )


def _env_allow_rules() -> list[dict[str, Any]]:
    """Parse env allowlist entries into non-persistent allow rules.

    Format:
      HERMES_GUARDIAN_ALLOWLIST="mcp_write:mcp:notion;browser_type:example.com"

    The first colon separates the action family from the destination, so
    destinations may contain additional colons. Add an optional class suffix
    with '#', for example 'mcp_write:mcp:notion#email+contacts'. Without a
    suffix, all known Guardian data classes are allowed for that action/destination.
    '*' is accepted for action or destination.
    """
    raw = _env(_ALLOWLIST_ENV, "")
    if not raw.strip():
        return []

    entries = [entry.strip() for entry in re.split(r"[;\n]+", raw) if entry.strip()]
    rules: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        class_part = ""
        if "#" in entry:
            entry, class_part = entry.split("#", 1)
        if ":" not in entry:
            logger.warning(
                "%s: ignoring invalid %s entry %r; expected action:destination",
                _PLUGIN_NAME,
                _ALLOWLIST_ENV,
                entry,
            )
            continue
        action_family, destination = entry.split(":", 1)
        action_family = action_family.strip().lower()
        destination = destination.strip().lower()
        if not action_family or not destination:
            continue
        if class_part.strip():
            data_classes = sorted({
                cls.strip()
                for cls in re.split(r"[,+]", class_part)
                if cls.strip() in _ALL_PRIVACY_CLASSES
            })
        else:
            data_classes = sorted(_ALL_PRIVACY_CLASSES)
        if not data_classes:
            continue
        digest = hashlib.sha256(f"{action_family}:{destination}:{','.join(data_classes)}".encode("utf-8")).hexdigest()
        rules.append({
            "rule_id": f"env_{digest[:8]}",
            "owner_hash": "*",
            "action_family": action_family,
            "destination": destination,
            "data_classes": data_classes,
            "created_at": 0,
            "source": "env",
            "index": index,
        })
    return rules


def _configured_allow_rules() -> list[dict[str, Any]]:
    return _env_allow_rules()


def _load_persistent_rules() -> dict[str, Any]:
    global _PERSISTENT_RULES_CACHE, _PERSISTENT_RULES_ERROR
    with _LOCK:
        if _PERSISTENT_RULES_CACHE is not None:
            return _PERSISTENT_RULES_CACHE
        try:
            if not _PERSISTENT_RULES_PATH.exists():
                _PERSISTENT_RULES_CACHE = {"rules": []}
            else:
                parsed = json.loads(_PERSISTENT_RULES_PATH.read_text())
                if not isinstance(parsed, dict) or not isinstance(parsed.get("rules"), list):
                    raise ValueError("invalid persistent rule file")
                _PERSISTENT_RULES_CACHE = parsed
            _PERSISTENT_RULES_ERROR = False
        except Exception as exc:
            logger.warning("%s: failed to load persistent allow rules: %s", _PLUGIN_NAME, exc)
            _PERSISTENT_RULES_CACHE = {"rules": []}
            _PERSISTENT_RULES_ERROR = True
        return _PERSISTENT_RULES_CACHE


def _save_persistent_rules(data: dict[str, Any]) -> bool:
    global _PERSISTENT_RULES_CACHE, _PERSISTENT_RULES_ERROR
    with _LOCK:
        try:
            tmp = _PERSISTENT_RULES_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            tmp.replace(_PERSISTENT_RULES_PATH)
            _PERSISTENT_RULES_CACHE = data
            _PERSISTENT_RULES_ERROR = False
            return True
        except Exception as exc:
            logger.warning("%s: failed to save persistent allow rules: %s", _PLUGIN_NAME, exc)
            _PERSISTENT_RULES_ERROR = True
            return False


def _prune_expired() -> None:
    cutoff = _now() - _RECENT_COMMAND_TTL_SECONDS
    with _LOCK:
        expired = [
            approval_id
            for approval_id, approval in _PENDING_APPROVALS.items()
            if float(approval.get("expires_at", 0)) <= _now()
        ]
        for approval_id in expired:
            _PENDING_APPROVALS.pop(approval_id, None)
        for key, entries in list(_RECENT_COMMAND_OWNERS.items()):
            fresh = [(ts, owner) for ts, owner in entries if ts >= cutoff]
            if fresh:
                _RECENT_COMMAND_OWNERS[key] = fresh
            else:
                _RECENT_COMMAND_OWNERS.pop(key, None)


def _is_approved(shape: dict[str, Any]) -> bool:
    return bool(_approval_source(shape))


def _approval_source(shape: dict[str, Any], *, consume_once: bool = True) -> dict[str, str] | None:
    with _LOCK:
        _prune_expired()
        sid = shape["session_id"]
        once_rules = _ONCE_APPROVALS.get(sid, [])
        for index, rule in enumerate(list(once_rules)):
            if rule.get("fingerprint") == shape.get("fingerprint") and _rule_matches(rule, shape):
                if consume_once:
                    del once_rules[index]
                return {"source": "once", "rule_id": ""}

        for rule in _SESSION_APPROVALS.get(sid, []):
            if _rule_matches(rule, shape):
                return {"source": "session", "rule_id": ""}

        for rule in _configured_allow_rules():
            if _rule_matches(rule, shape):
                return {"source": str(rule.get("source") or "env"), "rule_id": str(rule.get("rule_id") or "")}

        for rule in _load_persistent_rules().get("rules", []):
            if _rule_matches(rule, shape):
                return {"source": "persistent", "rule_id": str(rule.get("rule_id") or "")}
    return None


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
    if not parsed.scheme or not parsed.netloc:
        return value[:160]
    path = parsed.path or ""
    if len(path) > 80:
        path = path[:77] + "..."
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path}"


def _redact_command_for_llm(command: str) -> str:
    command = re.sub(r"https?://[^\s\"'<>]+", lambda m: _sanitize_url_for_llm(m.group(0)), command)
    command = _EMAIL_ADDRESS_RE.sub("<email>", command)
    command = _PHONE_RE.sub("<phone>", command)
    command = re.sub(r"(['\"])(?:(?=(\\?))\2.)*?\1", lambda m: f"{m.group(1)}<string:{len(m.group(0))}>{m.group(1)}", command)
    command = re.sub(r"\b[A-Za-z0-9_-]{24,}\b", "<token-like>", command)
    return command[:500]


def _safe_arg_summary_for_llm(value: Any, *, key: str = "", depth: int = 0) -> Any:
    if depth > 4:
        return "<max-depth>"
    key_l = str(key or "").lower()
    if isinstance(value, dict):
        return {
            str(k)[:80]: _safe_arg_summary_for_llm(v, key=str(k), depth=depth + 1)
            for k, v in list(value.items())[:40]
        }
    if isinstance(value, list):
        return [_safe_arg_summary_for_llm(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, tuple):
        return [_safe_arg_summary_for_llm(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, str):
        reason = _sensitive_reason(value)
        classes = sorted(_classes_from_content(value))
        if key_l in _LLM_URL_KEYS:
            return _sanitize_url_for_llm(value)
        if key_l in _LLM_COMMAND_OR_CODE_KEYS:
            return _redact_command_for_llm(value)
        if key_l in _LLM_CONTENT_KEYS or reason or classes:
            return {
                "redacted": True,
                "length": len(value),
                "privacy_classes": classes,
                "security_sensitive": bool(reason),
            }
        return value[:160]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


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
    return {
        "planned_action": {
            "tool_name": shape.get("tool_name", ""),
            "action_family": shape.get("action_family", ""),
            "destination": shape.get("destination", ""),
            "data_classes": sorted(shape.get("data_classes") or []),
            "argument_shape_fingerprint": shape.get("fingerprint", ""),
        },
        "sanitized_arguments": _safe_arg_summary_for_llm(args),
        "privacy_context": {
            "session_has_private_data": bool(shape.get("data_classes")),
            "classes_in_scope": sorted(shape.get("data_classes") or []),
            "security_sensitive_content_already_hard_blocked": True,
            "manual_approval_available_if_denied": True,
        },
    }


def _llm_security_verdict(shape: dict[str, Any], args: Any) -> dict[str, str]:
    llm = _PLUGIN_LLM
    if llm is None or not hasattr(llm, "complete_structured"):
        return {
            "outcome": "deny",
            "risk_level": "unknown",
            "authorization_level": "unknown",
            "rationale": "LLM verifier unavailable",
        }
    try:
        result = llm.complete_structured(
            instructions=_LLM_POLICY_INSTRUCTIONS,
            input=[{
                "type": "text",
                "text": json.dumps(_llm_verdict_input(shape, args), sort_keys=True),
            }],
            json_schema=_LLM_VERDICT_SCHEMA,
            temperature=0,
            max_tokens=240,
            timeout=20,
            purpose="hermes-guardian.security_llm",
            schema_name="hermes_guardian_verdict",
        )
        parsed = getattr(result, "parsed", None)
        if parsed is None and getattr(result, "text", ""):
            parsed = json.loads(str(result.text))
        if not isinstance(parsed, dict):
            raise ValueError("verdict was not a JSON object")
        outcome = str(parsed.get("outcome") or "deny").strip().lower()
        return {
            "outcome": "allow" if outcome == "allow" else "deny",
            "risk_level": str(parsed.get("risk_level") or "unknown")[:32],
            "authorization_level": str(parsed.get("authorization_level") or "unknown")[:32],
            "rationale": str(parsed.get("rationale") or "no rationale")[:1000],
        }
    except Exception as exc:
        logger.warning("%s: LLM security verifier failed closed: %s", _PLUGIN_NAME, exc)
        return {
            "outcome": "deny",
            "risk_level": "unknown",
            "authorization_level": "unknown",
            "rationale": "LLM verifier failed closed",
        }


def _approval_code_input(shape: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool_name": str(shape.get("tool_name") or "")[:80],
        "action_family": str(shape.get("action_family") or "")[:80],
        "destination": str(shape.get("destination") or "")[:120],
        "data_classes": sorted(shape.get("data_classes") or []),
        "action_detail": _redact_action_detail_text(str(shape.get("action_detail") or ""))[:240],
    }


def _approval_code_slug(value: str) -> str:
    value = str(value or "").lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    parts = [part for part in value.split("-") if part][:3]
    value = "-".join(parts)[:24].strip("-")
    if re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+){0,2}", value or ""):
        return value
    return ""


def _local_approval_slug(shape: dict[str, Any]) -> str:
    action_family = str(shape.get("action_family") or "approval").lower()
    destination = str(shape.get("destination") or "").lower()
    tool_name = str(shape.get("tool_name") or "").lower()

    if action_family == "mcp_write" and destination.startswith("mcp:"):
        service = destination.split(":", 1)[1].split(".", 1)[0]
        return _approval_code_slug(f"{service}-write")
    if action_family == "terminal_exec":
        detail = str(shape.get("action_detail") or "").lower()
        if "curl" in detail:
            host = ""
            match = re.search(r"https?://([^/\s\"']+)", detail)
            if match:
                host_parts = match.group(1).split(":")[0].split(".")
                host = host_parts[-2] if len(host_parts) > 1 else host_parts[0]
            return _approval_code_slug(f"{host}-curl" if host else "terminal-curl")
        return "terminal-run"
    if action_family.startswith("browser_"):
        return _approval_code_slug(action_family.replace("_", "-"))
    if action_family == "message_send":
        return "message-send"
    if action_family == "web_api":
        return "web-request"
    if action_family == "model_api":
        return "model-call"
    if action_family:
        return _approval_code_slug(action_family.replace("_", "-"))
    return _approval_code_slug(tool_name.replace("_", "-")) or "approval"


def _llm_approval_slug(shape: dict[str, Any]) -> str:
    llm = _PLUGIN_LLM
    if llm is None or not hasattr(llm, "complete_structured"):
        return ""
    try:
        result = llm.complete_structured(
            instructions=_LLM_APPROVAL_CODE_INSTRUCTIONS,
            input=[{
                "type": "text",
                "text": json.dumps(_approval_code_input(shape), sort_keys=True),
            }],
            json_schema=_LLM_APPROVAL_CODE_SCHEMA,
            temperature=0,
            max_tokens=80,
            timeout=10,
            purpose="hermes-guardian.approval_code",
            schema_name="hermes_guardian_approval_code",
        )
        parsed = getattr(result, "parsed", None)
        if parsed is None and getattr(result, "text", ""):
            parsed = json.loads(str(result.text))
        if not isinstance(parsed, dict):
            return ""
        return _approval_code_slug(str(parsed.get("code") or ""))
    except Exception as exc:
        logger.warning("%s: LLM approval code generation fell back: %s", _PLUGIN_NAME, exc)
        return ""


