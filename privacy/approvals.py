"""Approval IDs, pending approvals, and approval rule materialization."""

from __future__ import annotations

def _pending_approval_from_row(row: sqlite3.Row) -> dict[str, Any] | None:
    approval_id = str(row["id"] or "").strip()
    if not re.fullmatch(r"[0-9]{4}", approval_id):
        return None
    data_classes = [
        cls.strip()
        for cls in str(row["data_classes"] or "").split(",")
        if cls.strip() in _ALL_PRIVACY_CLASSES
    ]
    return {
        "id": approval_id,
        "session_id": _normalize_session_id(row["session_id"]),
        "owner_hash": str(row["owner_hash"] or ""),
        "tool_name": str(row["tool_name"] or ""),
        "action_family": str(row["action_family"] or ""),
        "destination": str(row["destination"] or ""),
        "purpose": _normalize_rule_purpose(row["purpose"], allow_star=False) if "purpose" in row.keys() else "unknown",
        "recipient_identity": _normalize_rule_recipient_identity(row["recipient_identity"], allow_star=False)
        if "recipient_identity" in row.keys() else "none",
        "legacy_destination": str(row["legacy_destination"] or "") if "legacy_destination" in row.keys() else "",
        "data_classes": data_classes,
        "action_detail": str(row["action_detail"] or ""),
        "fingerprint": str(row["fingerprint"] or ""),
        "created_at": int(float(row["created_at"] or 0)),
        "expires_at": int(float(row["expires_at"] or 0)),
        "cron_job_id": str(row["cron_job_id"] or ""),
        "cron_job_name": str(row["cron_job_name"] or ""),
        "reason": str(row["reason"] or ""),
    }


def _load_pending_approvals_from_store_unlocked() -> None:
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT id, session_id, owner_hash, tool_name, action_family,
                       destination, purpose, recipient_identity, legacy_destination,
                       data_classes, action_detail, fingerprint,
                       created_at, expires_at, cron_job_id, cron_job_name, reason
                FROM pending_approvals
                WHERE expires_at > ?
                """,
                (int(_now()),),
            ).fetchall()
    except Exception as exc:
        logger.debug("%s: failed to load pending approvals: %s", _PLUGIN_NAME, exc)
        return
    for row in rows:
        approval = _pending_approval_from_row(row)
        if approval:
            _PENDING_APPROVALS.setdefault(approval["id"], approval)


def _pending_approval_from_store_unlocked(approval_id: str) -> dict[str, Any] | None:
    approval_id = str(approval_id or "").strip()
    if not re.fullmatch(r"[0-9]{4}", approval_id):
        return None
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            row = conn.execute(
                """
                SELECT id, session_id, owner_hash, tool_name, action_family,
                       destination, purpose, recipient_identity, legacy_destination,
                       data_classes, action_detail, fingerprint,
                       created_at, expires_at, cron_job_id, cron_job_name, reason
                FROM pending_approvals
                WHERE id = ?
                """,
                (approval_id,),
            ).fetchone()
    except Exception as exc:
        logger.debug("%s: failed to load stored approval %s: %s", _PLUGIN_NAME, approval_id, exc)
        return None
    return _pending_approval_from_row(row) if row else None


def _save_pending_approval_to_store_unlocked(approval: dict[str, Any]) -> None:
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pending_approvals (
                    id, session_id, owner_hash, tool_name, action_family,
                    destination, purpose, recipient_identity, legacy_destination,
                    data_classes, action_detail, fingerprint,
                    created_at, expires_at, cron_job_id, cron_job_name, reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(approval.get("id") or ""),
                    _normalize_session_id(approval.get("session_id")),
                    str(approval.get("owner_hash") or ""),
                    str(approval.get("tool_name") or ""),
                    str(approval.get("action_family") or ""),
                    str(approval.get("destination") or ""),
                    _normalize_rule_purpose(approval.get("purpose", "unknown"), allow_star=False),
                    _normalize_rule_recipient_identity(approval.get("recipient_identity", "none"), allow_star=False),
                    str(approval.get("legacy_destination") or ""),
                    ",".join(
                        sorted(
                            str(cls)
                            for cls in (approval.get("data_classes") or [])
                            if str(cls) in _ALL_PRIVACY_CLASSES
                        )
                    ),
                    str(approval.get("action_detail") or ""),
                    str(approval.get("fingerprint") or ""),
                    int(float(approval.get("created_at") or 0)),
                    int(float(approval.get("expires_at") or 0)),
                    str(approval.get("cron_job_id") or ""),
                    str(approval.get("cron_job_name") or ""),
                    str(approval.get("reason") or "")[:1000],
                ),
            )
    except Exception as exc:
        logger.warning("%s: failed to save pending approval: %s", _PLUGIN_NAME, exc)


def _delete_pending_approvals_from_store_unlocked(approval_ids: list[str] | set[str] | tuple[str, ...]) -> None:
    ids = [str(approval_id) for approval_id in approval_ids if str(approval_id)]
    if not ids:
        return
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.executemany("DELETE FROM pending_approvals WHERE id = ?", [(approval_id,) for approval_id in ids])
    except Exception as exc:
        logger.warning("%s: failed to delete pending approvals: %s", _PLUGIN_NAME, exc)


def _approval_id_compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _recent_approval_ids() -> set[str]:
    cutoff = int(_now() - _APPROVAL_ID_REUSE_SECONDS)
    recent: set[str] = set()
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT approval_id
                FROM activity
                WHERE ts >= ? AND approval_id GLOB '[0-9][0-9][0-9][0-9]'
                """,
                (cutoff,),
            ).fetchall()
            recent.update(str(row["approval_id"]) for row in rows if row["approval_id"])
    except Exception as exc:
        logger.debug("%s: failed to load recent approval ids: %s", _PLUGIN_NAME, exc)
    return recent


def _new_approval_id(shape: dict[str, Any] | None = None) -> str:
    with _LOCK:
        _prune_expired()
        _load_pending_approvals_from_store_unlocked()
        unavailable = set(_PENDING_APPROVALS) | _recent_approval_ids()
    start = secrets.randbelow(10_000)
    for offset in range(10_000):
        candidate = f"{(start + offset) % 10_000:04d}"
        if candidate not in unavailable:
            return candidate
    logger.warning("%s: exhausted 4-digit approval ID space; reusing a recent code", _PLUGIN_NAME)
    return f"{secrets.randbelow(10_000):04d}"


def _resolve_pending_approval_id(approval_id: str) -> str | None:
    approval_id = str(approval_id or "").strip().lower()
    if not approval_id:
        return None
    with _LOCK:
        _load_pending_approvals_from_store_unlocked()
        if approval_id in _PENDING_APPROVALS:
            return approval_id
        compact = _approval_id_compact(approval_id)
        matches = [
            stored_id
            for stored_id in _PENDING_APPROVALS
            if _approval_id_compact(stored_id) == compact
        ]
    return matches[0] if len(matches) == 1 else None


def _is_cron_session_id(session_id: str | None) -> bool:
    return bool(re.fullmatch(r"cron_[0-9a-f]{12}_\d{8}_\d{6}", _normalize_session_id(session_id), re.I))


def _cron_job_id_from_session(session_id: str | None) -> str:
    match = re.fullmatch(r"cron_([0-9a-f]{12})_\d{8}_\d{6}", _normalize_session_id(session_id), re.I)
    return match.group(1) if match else ""


def _configured_owner_values_from_env(*names: str) -> set[str]:
    values: set[str] = set()
    for name in names:
        raw = _env(name, "")
        for value in re.split(r"[,;\s]+", str(raw or "")):
            value = value.strip().strip("'\"[]")
            if value and value != "*":
                values.add(value)
    return values


def _configured_owner_hashes() -> set[str]:
    hashes: set[str] = set()
    for sender_id in _configured_owner_values_from_env(
        "TELEGRAM_ALLOWED_USERS",
        "TELEGRAM_GROUP_ALLOWED_USERS",
    ):
        hashes.add(_hash_identity("telegram", sender_id))
    for sender_id in _configured_owner_values_from_env("DISCORD_ALLOWED_USERS"):
        hashes.add(_hash_identity("discord", sender_id))
    return hashes


def _approval_owner_allowed(owner_hash: str, approval: dict[str, Any]) -> bool:
    if approval.get("owner_hash") == owner_hash or owner_hash == _CLI_OWNER_HASH:
        return True
    if _is_cron_session_id(approval.get("session_id")) and owner_hash in _configured_owner_hashes():
        return True
    return False


def _create_pending_approval(shape: dict[str, Any]) -> dict[str, Any]:
    cron_job_id = _cron_job_id_from_session(shape.get("session_id"))
    try:
        cron_job_name = _cron_job_name(cron_job_id) if cron_job_id else ""
    except Exception:
        cron_job_name = ""
    approval = {
        "id": _new_approval_id(shape),
        "session_id": shape["session_id"],
        "owner_hash": shape.get("owner_hash") or "",
        "tool_name": shape["tool_name"],
        "action_family": shape["action_family"],
        "destination": shape["destination"],
        "purpose": _normalize_rule_purpose(shape.get("purpose", "unknown"), allow_star=False),
        "recipient_identity": _normalize_rule_recipient_identity(shape.get("recipient_identity", "none"), allow_star=False),
        "legacy_destination": "",
        "data_classes": list(shape["data_classes"]),
        "action_detail": shape.get("action_detail") or "",
        "fingerprint": shape["fingerprint"],
        "created_at": int(_now()),
        "expires_at": int(_now() + _APPROVAL_TTL_SECONDS),
        "cron_job_id": cron_job_id,
        "cron_job_name": cron_job_name,
        "reason": "",
    }
    with _LOCK:
        _load_pending_approvals_from_store_unlocked()
        _PENDING_APPROVALS[approval["id"]] = approval
        _save_pending_approval_to_store_unlocked(approval)
    return approval


def _guardian_block_message(approval: dict[str, Any]) -> str:
    classes = ", ".join(approval.get("data_classes") or ["private"])
    action_detail = str(approval.get("action_detail") or "").strip()
    action_detail_line = f"Action detail: {action_detail}\n" if action_detail else ""
    return (
        "Hermes Guardian blocked this egress.\n\n"
        f"Approval ID: {approval['id']}\n"
        f"Action: {approval['action_family']}\n"
        f"Destination: {approval['destination']}\n"
        f"{action_detail_line}"
        f"Data classes: {classes}\n\n"
        "Kevin can approve with:\n"
        f"/guardian approve {approval['id']} once\n"
        f"/guardian approve {approval['id']} session\n"
        f"/guardian approve {approval['id']} always\n"
        "or dismiss with:\n"
        f"/guardian dismiss {approval['id']}"
    )


def _rule_from_approval(approval: dict[str, Any], *, persistent: bool = False) -> dict[str, Any]:
    cron_job_id = _cron_job_id_from_session(approval.get("session_id"))
    scope = {
        "owner_hash": approval.get("owner_hash") or "",
        "session_id": approval.get("session_id") or "",
        "cron_job_id": "",
        "cron_job_name": "",
    }
    if persistent and cron_job_id:
        scope["owner_hash"] = "*"
        scope["session_id"] = ""
        scope["cron_job_id"] = cron_job_id
        scope["cron_job_name"] = str(approval.get("cron_job_name") or "")
    rule = {
        "id": f"rule_{secrets.token_hex(4)}" if persistent else f"volatile_{secrets.token_hex(4)}",
        "effect": "allow",
        "enabled": True,
        "match": {
            "tool_name": approval.get("tool_name") or "*",
            "action_family": approval.get("action_family") or "*",
            "destination": approval.get("destination") or "*",
            "purpose": approval.get("purpose") or "*",
            "recipient_identity": approval.get("recipient_identity") or "*",
            "data_classes": list(approval.get("data_classes") or ["*"]),
        },
        "scope": scope,
        "remaining_invocations": -1,
        "created_at": int(_now()),
    }
    if not persistent:
        rule["fingerprint"] = approval.get("fingerprint") or ""
    return rule


def _rule_scope_label(rule: dict[str, Any]) -> str:
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    cron_job_id = str(scope.get("cron_job_id") or rule.get("cron_job_id") or "").strip()
    if cron_job_id:
        cron_job_name = str(scope.get("cron_job_name") or rule.get("cron_job_name") or "").strip()
        try:
            cron_job_name = cron_job_name or _cron_job_name(cron_job_id)
        except Exception:
            pass
        if cron_job_name:
            return f"cron job {cron_job_name} ({cron_job_id})"
        return f"cron job {cron_job_id}"
    if str(scope.get("session_id") or "").strip():
        return "session"
    if scope.get("owner_hash") == "*":
        return "all owners"
    return "owner"


def _rule_delete_owner_allowed(owner_hash: str, rule: dict[str, Any]) -> bool:
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    if owner_hash == _CLI_OWNER_HASH:
        return True
    if scope.get("owner_hash") == owner_hash:
        return True
    if scope.get("owner_hash") == "*" and scope.get("cron_job_id") and owner_hash in _configured_owner_hashes():
        return True
    return False


def _delete_persistent_rule(owner_hash: str, rule_id: str) -> tuple[bool, str, dict[str, Any] | None]:
    rule_id = str(rule_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", rule_id):
        return False, f"Invalid persistent rule id {rule_id or '(empty)'}.", None

    rules = _persistent_privacy_rules()
    removed: dict[str, Any] | None = None
    kept: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("id") == rule_id and _rule_delete_owner_allowed(owner_hash, rule):
            removed = rule
            continue
        kept.append(rule)

    if removed is None:
        return False, f"No matching privacy rule found for {rule_id}.", None

    if not _save_persistent_privacy_rules(kept):
        return False, "Failed to delete privacy rule; Hermes Guardian remains fail-closed.", None

    return True, f"Deleted privacy rule {rule_id}.", removed


def _remember_command_owner(raw_args: str, owner_hash: str) -> None:
    key = raw_args.strip()
    if not key:
        return
    with _LOCK:
        _RECENT_COMMAND_OWNERS.setdefault(key, []).append((_now(), owner_hash))


def _pop_command_owner(raw_args: str) -> str:
    key = raw_args.strip()
    with _LOCK:
        _prune_expired()
        entries = _RECENT_COMMAND_OWNERS.get(key) or []
        if entries:
            _RECENT_COMMAND_OWNERS[key] = entries[1:]
            if not _RECENT_COMMAND_OWNERS[key]:
                _RECENT_COMMAND_OWNERS.pop(key, None)
            return entries[0][1]
    return _CLI_OWNER_HASH


def _owner_session_ids(owner_hash: str) -> set[str]:
    if owner_hash == _CLI_OWNER_HASH:
        return set(_SESSIONS) or {_GLOBAL_SESSION_ID}
    return set(_OWNER_SESSIONS.get(owner_hash) or [])
