"""Modularized guardian runtime module."""

from __future__ import annotations

def _approval_id_compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _new_approval_id(shape: dict[str, Any] | None = None) -> str:
    slug = _approval_code_slug(_llm_approval_slug(shape or {}) or _local_approval_slug(shape or {}))
    with _LOCK:
        existing = set(_PENDING_APPROVALS)
        existing_compact = {_approval_id_compact(value) for value in existing}
    for _ in range(32):
        candidate = f"{slug}-{secrets.randbelow(10_000):04d}" if slug else (
            f"{secrets.choice(_APPROVAL_WORDS_LEFT)}-"
            f"{secrets.choice(_APPROVAL_WORDS_RIGHT)}-"
            f"{secrets.randbelow(10_000):04d}"
        )
        if candidate not in existing and _approval_id_compact(candidate) not in existing_compact:
            return candidate
    return f"guardian-{secrets.token_hex(4)}"


def _resolve_pending_approval_id(approval_id: str) -> str | None:
    approval_id = str(approval_id or "").strip().lower()
    if not approval_id:
        return None
    with _LOCK:
        if approval_id in _PENDING_APPROVALS:
            return approval_id
        compact = _approval_id_compact(approval_id)
        matches = [
            stored_id
            for stored_id in _PENDING_APPROVALS
            if _approval_id_compact(stored_id) == compact
        ]
    return matches[0] if len(matches) == 1 else None


def _create_pending_approval(shape: dict[str, Any]) -> dict[str, Any]:
    approval = {
        "id": _new_approval_id(shape),
        "session_id": shape["session_id"],
        "owner_hash": shape.get("owner_hash") or "",
        "tool_name": shape["tool_name"],
        "action_family": shape["action_family"],
        "destination": shape["destination"],
        "data_classes": list(shape["data_classes"]),
        "action_detail": shape.get("action_detail") or "",
        "fingerprint": shape["fingerprint"],
        "created_at": int(_now()),
        "expires_at": int(_now() + _APPROVAL_TTL_SECONDS),
    }
    with _LOCK:
        _PENDING_APPROVALS[approval["id"]] = approval
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
        "or deny with:\n"
        f"/guardian deny {approval['id']}"
    )


def _rule_from_approval(approval: dict[str, Any], *, persistent: bool = False) -> dict[str, Any]:
    rule = {
        "rule_id": f"rule_{secrets.token_hex(4)}" if persistent else "",
        "owner_hash": approval.get("owner_hash") or "",
        "session_id": approval.get("session_id") or "",
        "tool_name": approval.get("tool_name") or "",
        "action_family": approval.get("action_family") or "",
        "destination": approval.get("destination") or "",
        "data_classes": list(approval.get("data_classes") or []),
        "fingerprint": approval.get("fingerprint") or "",
        "created_at": int(_now()),
    }
    if not persistent:
        rule.pop("rule_id", None)
    return rule


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
