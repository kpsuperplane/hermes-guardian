"""JSON-backed privacy rule loading, matching, and mutation."""

from __future__ import annotations

_PRIVACY_RULE_FILE_VERSION = 1
_PRIVACY_MODES = {"strict", "read-only", "llm", "off"}


def _default_privacy_config() -> dict[str, Any]:
    return {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "mode": "strict",
            "rules": [],
        },
    }


def _normalize_privacy_mode(value: Any) -> str:
    mode = str(value or "strict").strip().lower().replace("_", "-")
    return mode if mode in _PRIVACY_MODES else "strict"


def _normalize_rule_classes(raw: Any, *, allow_star: bool = True) -> list[str]:
    values = raw if isinstance(raw, list) else [raw]
    classes: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if allow_star and text == "*":
            return ["*"]
        if text in _ALL_PRIVACY_CLASSES and text not in classes:
            classes.append(text)
    return sorted(classes)


def _normalize_privacy_rule(rule: Any) -> dict[str, Any] | None:
    if not isinstance(rule, dict):
        return None
    effect = str(rule.get("effect") or "").strip().lower()
    if effect not in {"allow", "deny"}:
        return None
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    rule_id = str(rule.get("id") or rule.get("rule_id") or f"rule_{secrets.token_hex(4)}").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", rule_id):
        rule_id = f"rule_{secrets.token_hex(4)}"
    try:
        remaining = int(rule.get("remaining_invocations", -1))
    except (TypeError, ValueError):
        remaining = -1
    if remaining < -1:
        remaining = -1
    normalized = {
        "id": rule_id,
        "effect": effect,
        "enabled": bool(rule.get("enabled", True)),
        "match": {
            "tool_name": str(match.get("tool_name") or "*").strip() or "*",
            "action_family": str(match.get("action_family") or "*").strip().lower() or "*",
            "destination": str(match.get("destination") or "*").strip().lower() or "*",
            "data_classes": _normalize_rule_classes(match.get("data_classes", ["*"])) or ["*"],
        },
        "scope": {
            "owner_hash": str(scope.get("owner_hash") or rule.get("owner_hash") or "*").strip() or "*",
            "session_id": _normalize_session_id(scope.get("session_id") or rule.get("session_id") or "")
            if (scope.get("session_id") or rule.get("session_id")) else "",
            "cron_job_id": str(scope.get("cron_job_id") or rule.get("cron_job_id") or "").strip(),
            "cron_job_name": str(scope.get("cron_job_name") or rule.get("cron_job_name") or "").strip(),
        },
        "remaining_invocations": remaining,
        "created_at": int(float(rule.get("created_at") or 0)),
    }
    fingerprint = str(rule.get("fingerprint") or "").strip()
    if re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint):
        normalized["fingerprint"] = fingerprint
    return normalized


def _normalize_privacy_config(parsed: Any) -> dict[str, Any]:
    default = _default_privacy_config()
    if not isinstance(parsed, dict):
        return default
    privacy = parsed.get("privacy")
    if not isinstance(privacy, dict):
        return default
    normalized_rules = [
        normalized
        for normalized in (_normalize_privacy_rule(rule) for rule in privacy.get("rules", []))
        if normalized is not None
    ]
    return {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "mode": _normalize_privacy_mode(privacy.get("mode")),
            "rules": normalized_rules,
        },
    }


def _load_privacy_config() -> dict[str, Any]:
    global _PERSISTENT_RULES_CACHE, _PERSISTENT_RULES_ERROR, _PERSISTENT_RULES_MTIME
    with _LOCK:
        try:
            current_mtime = _PERSISTENT_RULES_PATH.stat().st_mtime if _PERSISTENT_RULES_PATH.exists() else None
        except Exception:
            current_mtime = None
        if (
            _PERSISTENT_RULES_CACHE is not None
            and _PERSISTENT_RULES_MTIME == current_mtime
            and isinstance(_PERSISTENT_RULES_CACHE.get("privacy"), dict)
        ):
            return _PERSISTENT_RULES_CACHE
        try:
            if not _PERSISTENT_RULES_PATH.exists():
                _PERSISTENT_RULES_CACHE = _default_privacy_config()
                _PERSISTENT_RULES_MTIME = None
            else:
                parsed = json.loads(_PERSISTENT_RULES_PATH.read_text())
                if not isinstance(parsed, dict) or "privacy" not in parsed:
                    raise ValueError("invalid privacy rule file")
                _PERSISTENT_RULES_CACHE = _normalize_privacy_config(parsed)
                _PERSISTENT_RULES_MTIME = current_mtime
            _PERSISTENT_RULES_ERROR = False
        except Exception as exc:
            logger.warning("%s: failed to load privacy rules: %s", _PLUGIN_NAME, exc)
            _PERSISTENT_RULES_CACHE = _default_privacy_config()
            _PERSISTENT_RULES_MTIME = None
            _PERSISTENT_RULES_ERROR = True
        return _PERSISTENT_RULES_CACHE


def _save_privacy_config(data: dict[str, Any]) -> bool:
    global _PERSISTENT_RULES_CACHE, _PERSISTENT_RULES_ERROR, _PERSISTENT_RULES_MTIME
    normalized = _normalize_privacy_config(data)
    with _LOCK:
        try:
            tmp = _PERSISTENT_RULES_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n")
            tmp.replace(_PERSISTENT_RULES_PATH)
            _PERSISTENT_RULES_CACHE = normalized
            try:
                _PERSISTENT_RULES_MTIME = _PERSISTENT_RULES_PATH.stat().st_mtime
            except Exception:
                _PERSISTENT_RULES_MTIME = None
            _PERSISTENT_RULES_ERROR = False
            return True
        except Exception as exc:
            logger.warning("%s: failed to save privacy rules: %s", _PLUGIN_NAME, exc)
            _PERSISTENT_RULES_ERROR = True
            return False


def _privacy_mode() -> str:
    return _normalize_privacy_mode(_load_privacy_config().get("privacy", {}).get("mode"))


def _set_privacy_mode(mode: str) -> tuple[bool, str]:
    normalized = _normalize_privacy_mode(mode)
    if normalized != str(mode or "").strip().lower().replace("_", "-"):
        return False, "Privacy mode must be one of: strict, read-only, llm, off."
    data = _load_privacy_config()
    data = {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "mode": normalized,
            "rules": list(data.get("privacy", {}).get("rules", [])),
        },
    }
    if not _save_privacy_config(data):
        return False, "Failed to save privacy mode; Guardian remains unchanged."
    return True, f"Privacy mode set to {normalized}."


def _persistent_privacy_rules() -> list[dict[str, Any]]:
    return list(_load_privacy_config().get("privacy", {}).get("rules", []))


def _save_persistent_privacy_rules(rules: list[dict[str, Any]]) -> bool:
    data = _load_privacy_config()
    return _save_privacy_config({
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "mode": _privacy_mode(),
            "rules": rules,
        },
    })


def _load_persistent_rules() -> dict[str, Any]:
    """Compatibility wrapper for callers that still expect a rule list."""
    config = _load_privacy_config()
    return {"rules": list(config.get("privacy", {}).get("rules", []))}


def _save_persistent_rules(data: dict[str, Any]) -> bool:
    """Compatibility wrapper around the new privacy config shape."""
    return _save_persistent_privacy_rules(list(data.get("rules", [])))


def _configured_allow_rules() -> list[dict[str, Any]]:
    return []


def _classes_are_covered(current: set[str], approved: list[str] | set[str]) -> bool:
    approved_set = set(approved or [])
    return "*" in approved_set or current.issubset(approved_set)


def _scope_matches(scope: dict[str, Any], shape: dict[str, Any]) -> bool:
    owner_hash = str(scope.get("owner_hash") or "*")
    session_id = str(scope.get("session_id") or "")
    cron_job_id = str(scope.get("cron_job_id") or "")
    return (
        (owner_hash == "*" or owner_hash == shape.get("owner_hash"))
        and (not session_id or session_id == shape.get("session_id"))
        and (not cron_job_id or cron_job_id == _cron_job_id_from_session(shape.get("session_id")))
    )


def _value_matches(rule_value: Any, actual: Any) -> bool:
    text = str(rule_value or "*").strip().lower()
    return text == "*" or text == str(actual or "").strip().lower()


def _rule_matches(rule: dict[str, Any], shape: dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    if not _scope_matches(rule.get("scope") if isinstance(rule.get("scope"), dict) else {}, shape):
        return False
    if not _value_matches(match.get("tool_name", "*"), shape.get("tool_name")):
        return False
    if not _value_matches(match.get("action_family", "*"), shape.get("action_family")):
        return False
    if not _value_matches(match.get("destination", "*"), shape.get("destination")):
        return False
    current_classes = set(shape.get("data_classes") or [])
    rule_classes = set(match.get("data_classes") or ["*"])
    if rule.get("effect") == "deny":
        return "*" in rule_classes or not rule_classes or bool(current_classes & rule_classes) or not current_classes
    return _classes_are_covered(current_classes, rule_classes)


def _consume_rule_invocation(rule: dict[str, Any], rules: list[dict[str, Any]] | None = None) -> None:
    try:
        remaining = int(rule.get("remaining_invocations", -1))
    except (TypeError, ValueError):
        remaining = -1
    if remaining < 0:
        return
    remaining -= 1
    rule["remaining_invocations"] = remaining
    if rules is not None and remaining <= 0:
        rules[:] = [candidate for candidate in rules if candidate.get("id") != rule.get("id")]


def _rule_source_payload(rule: dict[str, Any], source: str) -> dict[str, str]:
    return {
        "source": source,
        "rule_id": str(rule.get("id") or ""),
        "effect": str(rule.get("effect") or "allow"),
    }


def _approval_source(shape: dict[str, Any], *, consume_once: bool = True) -> dict[str, str] | None:
    with _LOCK:
        _prune_expired()
        sid = shape["session_id"]
        once_rules = _ONCE_APPROVALS.get(sid, [])
        for rule in list(once_rules):
            if rule.get("fingerprint") == shape.get("fingerprint") and _rule_matches(rule, shape):
                if consume_once:
                    _consume_rule_invocation(rule, once_rules)
                return _rule_source_payload(rule, "once")

        session_rules = _SESSION_APPROVALS.get(sid, [])
        for rule in list(session_rules):
            if _rule_matches(rule, shape):
                if consume_once:
                    _consume_rule_invocation(rule, session_rules)
                return _rule_source_payload(rule, "session")

        persistent_rules = _persistent_privacy_rules()
        changed = False
        for rule in list(persistent_rules):
            fingerprint = str(rule.get("fingerprint") or "")
            if fingerprint and fingerprint != str(shape.get("fingerprint") or ""):
                continue
            if not _rule_matches(rule, shape):
                continue
            if consume_once:
                before = json.dumps(persistent_rules, sort_keys=True)
                _consume_rule_invocation(rule, persistent_rules)
                changed = before != json.dumps(persistent_rules, sort_keys=True)
                if changed:
                    _save_persistent_privacy_rules(persistent_rules)
            return _rule_source_payload(rule, "persistent")
    return None


def _is_approved(shape: dict[str, Any]) -> bool:
    source = _approval_source(shape)
    return bool(source and source.get("effect") == "allow")


def _privacy_rules_for_owner(owner_hash: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for rule in _persistent_privacy_rules():
        scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
        rule_owner = str(scope.get("owner_hash") or "*")
        if owner_hash == _CLI_OWNER_HASH or rule_owner in {"*", owner_hash}:
            rules.append(rule)
    return rules
