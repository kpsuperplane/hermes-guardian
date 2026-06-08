"""JSON-backed privacy rule loading, matching, and mutation."""

from __future__ import annotations

_PRIVACY_RULE_FILE_VERSION = 1
_DEFAULT_PRIVACY_MODE = "llm"
_PRIVACY_MODES = {"strict", "read-only", "llm", "off"}
_SECURITY_RULE_DEFINITIONS = {
    "account_security_content": {
        "label": "Account security content",
        "description": "Block or suppress password reset, recovery, auth-code, magic-link, security-alert, redacted security, and similar account-security content.",
        "default_enabled": True,
    },
    "credential_content": {
        "label": "Credential content",
        "description": "Block or suppress private keys, cloud/API tokens, bearer tokens, JWTs, cookies, and .env-style secret assignments.",
        "default_enabled": True,
    },
    "sensitive_links": {
        "label": "Sensitive links",
        "description": "Block or suppress reset, recovery, verification, confirmation, magic-link, OTP, and 2FA URLs.",
        "default_enabled": True,
    },
    "intrinsic_exfiltration": {
        "label": "Intrinsic exfiltration",
        "description": "Block same-call local/browser secret reads combined with network sinks before session taint exists.",
        "default_enabled": True,
    },
    "private_network_reads": {
        "label": "Private-network remote reads",
        "description": "Prevent terminal remote-read shortcuts from treating localhost, private IPs, metadata hosts, and .local hosts as public reads.",
        "default_enabled": True,
    },
}
_SECURITY_RULE_IDS = tuple(_SECURITY_RULE_DEFINITIONS)
_LANGUAGE_PACK_APPLIED_IDS: tuple[str, ...] | None = None


def _config_bool(value: Any, *, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    return default


def _default_privacy_config() -> dict[str, Any]:
    return {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "mode": _DEFAULT_PRIVACY_MODE,
            "rules": [],
        },
        "security": {
            "rules": _default_security_rules(),
        },
        "language_packs": _default_language_pack_config(),
    }


def _normalize_privacy_mode(value: Any) -> str:
    mode = str(value or _DEFAULT_PRIVACY_MODE).strip().lower().replace("_", "-")
    return mode if mode in _PRIVACY_MODES else _DEFAULT_PRIVACY_MODE


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


def _default_security_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": rule_id,
            "enabled": bool(definition.get("default_enabled", True)),
        }
        for rule_id, definition in _SECURITY_RULE_DEFINITIONS.items()
    ]


def _normalize_security_rule(rule: Any) -> dict[str, Any] | None:
    if not isinstance(rule, dict):
        return None
    rule_id = str(rule.get("id") or rule.get("rule_id") or "").strip().lower().replace("-", "_")
    if rule_id not in _SECURITY_RULE_DEFINITIONS:
        return None
    return {
        "id": rule_id,
        "enabled": _config_bool(rule.get("enabled"), default=True),
    }


def _normalize_security_rules(raw: Any) -> list[dict[str, Any]]:
    configured = raw if isinstance(raw, list) else []
    by_id = {
        normalized["id"]: normalized
        for normalized in (_normalize_security_rule(rule) for rule in configured)
        if normalized is not None
    }
    rules: list[dict[str, Any]] = []
    for default_rule in _default_security_rules():
        rule = dict(default_rule)
        rule.update(by_id.get(rule["id"]) or {})
        rules.append(rule)
    return rules


def _available_language_pack_map() -> dict[str, dict[str, Any]]:
    try:
        packs = _language._available_language_packs()
    except Exception as exc:
        logger.warning("%s: failed to inspect language packs: %s", _PLUGIN_NAME, exc)
        packs = [{"id": "en", "name": "English", "default_enabled": True, "required": True}]
    return {str(pack.get("id") or ""): pack for pack in packs if pack.get("id")}


def _normalize_language_pack_ids(raw: Any = None) -> list[str]:
    available = _available_language_pack_map()
    if raw is None:
        normalized = list(_language._enabled_pack_ids())
    elif isinstance(raw, list):
        normalized = list(_language._enabled_pack_ids(",".join(str(item) for item in raw)))
    else:
        normalized = list(_language._enabled_pack_ids(str(raw or "")))
    ids: list[str] = []
    for pack_id in normalized:
        if pack_id in available and pack_id not in ids:
            ids.append(pack_id)
    if "en" in available and "en" not in ids:
        ids.insert(0, "en")
    return ids or ["en"]


def _default_language_pack_config() -> dict[str, Any]:
    return {
        "enabled": _normalize_language_pack_ids(None),
    }


def _normalize_language_pack_config(raw: Any) -> dict[str, Any]:
    config = raw if isinstance(raw, dict) else {}
    enabled = config.get("enabled", config.get("packs")) if config else None
    return {
        "enabled": _normalize_language_pack_ids(enabled),
    }


def _language_pack_ids_from_config(data: dict[str, Any]) -> list[str]:
    return _normalize_language_pack_config(data.get("language_packs") if isinstance(data, dict) else {}).get("enabled", ["en"])


def _apply_language_pack_config(data: dict[str, Any]) -> None:
    global _LANGUAGE_PACK_APPLIED_IDS
    ids = tuple(_language_pack_ids_from_config(data))
    if ids == _LANGUAGE_PACK_APPLIED_IDS:
        return
    try:
        _security._set_enabled_language_packs(",".join(ids))
        _LANGUAGE_PACK_APPLIED_IDS = ids
    except Exception as exc:
        logger.warning("%s: failed to apply language packs %s: %s", _PLUGIN_NAME, ",".join(ids), exc)


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
        privacy = {}
    security = parsed.get("security") if isinstance(parsed.get("security"), dict) else {}
    language_packs = parsed.get("language_packs") if isinstance(parsed.get("language_packs"), dict) else {}
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
        "security": {
            "rules": _normalize_security_rules(security.get("rules")),
        },
        "language_packs": _normalize_language_pack_config(language_packs),
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
            _apply_language_pack_config(_PERSISTENT_RULES_CACHE)
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
        _apply_language_pack_config(_PERSISTENT_RULES_CACHE)
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
            _apply_language_pack_config(_PERSISTENT_RULES_CACHE)
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
        "security": dict(data.get("security") or {}),
        "language_packs": dict(data.get("language_packs") or {}),
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
        "security": dict(data.get("security") or {}),
        "language_packs": dict(data.get("language_packs") or {}),
    })


def _security_rules() -> list[dict[str, Any]]:
    return list(_load_privacy_config().get("security", {}).get("rules", []))


def _security_rule_enabled(rule_id: str) -> bool:
    normalized_id = str(rule_id or "").strip().lower().replace("-", "_")
    if normalized_id not in _SECURITY_RULE_DEFINITIONS:
        return True
    for rule in _security_rules():
        if rule.get("id") == normalized_id:
            return _config_bool(rule.get("enabled"), default=True)
    return bool(_SECURITY_RULE_DEFINITIONS[normalized_id].get("default_enabled", True))


def _security_rules_snapshot() -> list[dict[str, Any]]:
    rules_by_id = {str(rule.get("id") or ""): rule for rule in _security_rules()}
    out: list[dict[str, Any]] = []
    for rule_id, definition in _SECURITY_RULE_DEFINITIONS.items():
        configured = rules_by_id.get(rule_id) or {}
        out.append({
            "id": rule_id,
            "rule_id": rule_id,
            "enabled": _config_bool(
                configured.get("enabled"),
                default=bool(definition.get("default_enabled", True)),
            ),
            "label": str(definition.get("label") or rule_id),
            "description": str(definition.get("description") or ""),
            "default_enabled": bool(definition.get("default_enabled", True)),
        })
    return out


def _set_security_rule(rule_id: str, enabled: bool) -> tuple[bool, str]:
    normalized_id = str(rule_id or "").strip().lower().replace("-", "_")
    if normalized_id not in _SECURITY_RULE_DEFINITIONS:
        return False, "Unknown security rule. Use /guardian security to list rule ids."
    desired = _config_bool(enabled, default=True)
    data = _load_privacy_config()
    security_rules = _normalize_security_rules(data.get("security", {}).get("rules"))
    for rule in security_rules:
        if rule["id"] == normalized_id:
            rule["enabled"] = desired
            break
    next_data = {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": dict(data.get("privacy") or {}),
        "security": {
            "rules": security_rules,
        },
        "language_packs": dict(data.get("language_packs") or {}),
    }
    if not _save_privacy_config(next_data):
        return False, "Failed to save security rule; Guardian remains unchanged."
    label = _SECURITY_RULE_DEFINITIONS[normalized_id]["label"]
    return True, f"{'Enabled' if desired else 'Disabled'} security rule {normalized_id} ({label})."


def _language_pack_ids() -> list[str]:
    return list(_load_privacy_config().get("language_packs", {}).get("enabled", ["en"]))


def _language_packs_snapshot() -> list[dict[str, Any]]:
    enabled = set(_language_pack_ids())
    out: list[dict[str, Any]] = []
    for pack_id, pack in _available_language_pack_map().items():
        out.append({
            "id": pack_id,
            "pack_id": pack_id,
            "name": str(pack.get("name") or pack_id),
            "enabled": pack_id in enabled,
            "required": bool(pack.get("required")),
            "default_enabled": bool(pack.get("default_enabled")),
        })
    return out


def _set_language_pack(pack_id: str, enabled: bool) -> tuple[bool, str]:
    normalized_id = str(pack_id or "").strip().lower()
    available = _available_language_pack_map()
    if normalized_id not in available:
        return False, "Unknown language pack. Use /guardian language-packs to list pack ids."
    desired = _config_bool(enabled, default=True)
    if normalized_id == "en" and not desired:
        return False, "English language pack is required and cannot be disabled."
    data = _load_privacy_config()
    ids = _language_pack_ids_from_config(data)
    if desired and normalized_id not in ids:
        ids.append(normalized_id)
    if not desired:
        ids = [existing for existing in ids if existing != normalized_id]
    ids = _normalize_language_pack_ids(ids)
    next_data = {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": dict(data.get("privacy") or {}),
        "security": dict(data.get("security") or {}),
        "language_packs": {
            "enabled": ids,
        },
    }
    if not _save_privacy_config(next_data):
        return False, "Failed to save language pack; Guardian remains unchanged."
    name = str(available[normalized_id].get("name") or normalized_id)
    return True, f"{'Enabled' if desired else 'Disabled'} language pack {normalized_id} ({name})."


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
