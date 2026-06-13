"""Approval IDs, pending approvals, and approval rule materialization."""

from __future__ import annotations

import re
import secrets
import sqlite3
from typing import Any

from . import capability
from . import destinations
from . import llm
from . import module as privacy_module
from . import rules as rules_mod
from . import tool_policy
from .. import core
from .. import state
from ..integrations import cron_notifications
from ..runtime import activity_store


def _pending_approval_from_row(row: sqlite3.Row) -> dict[str, Any] | None:
    approval_id = str(row["id"] or "").strip()
    if not re.fullmatch(r"[0-9]{4}", approval_id):
        return None
    data_classes = [
        cls.strip()
        for cls in str(row["data_classes"] or "").split(",")
        if cls.strip() in core._ALL_PRIVACY_CLASSES
    ]
    return {
        "id": approval_id,
        "session_id": tool_policy._normalize_session_id(row["session_id"]),
        "owner_hash": str(row["owner_hash"] or ""),
        "tool_name": str(row["tool_name"] or ""),
        "action_family": str(row["action_family"] or ""),
        "destination": str(row["destination"] or ""),
        "purpose": tool_policy._normalize_rule_purpose(row["purpose"], allow_star=False) if "purpose" in row.keys() else "unknown",
        "recipient_identity": tool_policy._normalize_rule_recipient_identity(row["recipient_identity"], allow_star=False)
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
        "destination_trust": str(row["destination_trust"] or "unknown")
        if "destination_trust" in row.keys() else "unknown",
        "decision_step": str(row["decision_step"] or "") if "decision_step" in row.keys() else "",
        "permit_recipient": str(row["permit_recipient"] or "") if "permit_recipient" in row.keys() else "",
        "permit_host": str(row["permit_host"] or "") if "permit_host" in row.keys() else "",
        "permit_command": str(row["permit_command"] or "") if "permit_command" in row.keys() else "",
    }


def _load_pending_approvals_from_store_unlocked() -> None:
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            rows = conn.execute(
                """
                SELECT id, session_id, owner_hash, tool_name, action_family,
                       destination, purpose, recipient_identity, legacy_destination,
                       data_classes, action_detail, fingerprint,
                       created_at, expires_at, cron_job_id, cron_job_name, reason,
                       destination_trust, decision_step,
                       permit_recipient, permit_host, permit_command
                FROM pending_approvals
                WHERE expires_at > ?
                """,
                (int(state._now()),),
            ).fetchall()
    except Exception as exc:
        core.logger.debug("%s: failed to load pending approvals: %s", core._PLUGIN_NAME, exc)
        return
    for row in rows:
        approval = _pending_approval_from_row(row)
        if approval:
            state._PENDING_APPROVALS.setdefault(approval["id"], approval)


def _pending_approval_from_store_unlocked(approval_id: str) -> dict[str, Any] | None:
    approval_id = str(approval_id or "").strip()
    if not re.fullmatch(r"[0-9]{4}", approval_id):
        return None
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            row = conn.execute(
                """
                SELECT id, session_id, owner_hash, tool_name, action_family,
                       destination, purpose, recipient_identity, legacy_destination,
                       data_classes, action_detail, fingerprint,
                       created_at, expires_at, cron_job_id, cron_job_name, reason,
                       destination_trust, decision_step,
                       permit_recipient, permit_host, permit_command
                FROM pending_approvals
                WHERE id = ?
                """,
                (approval_id,),
            ).fetchone()
    except Exception as exc:
        core.logger.debug("%s: failed to load stored approval %s: %s", core._PLUGIN_NAME, approval_id, exc)
        return None
    return _pending_approval_from_row(row) if row else None


def _save_pending_approval_to_store_unlocked(approval: dict[str, Any]) -> None:
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pending_approvals (
                    id, session_id, owner_hash, tool_name, action_family,
                    destination, purpose, recipient_identity, legacy_destination,
                    data_classes, action_detail, fingerprint,
                    created_at, expires_at, cron_job_id, cron_job_name, reason,
                    destination_trust, decision_step,
                    permit_recipient, permit_host, permit_command
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(approval.get("id") or ""),
                    tool_policy._normalize_session_id(approval.get("session_id")),
                    str(approval.get("owner_hash") or ""),
                    str(approval.get("tool_name") or ""),
                    str(approval.get("action_family") or ""),
                    str(approval.get("destination") or ""),
                    tool_policy._normalize_rule_purpose(approval.get("purpose", "unknown"), allow_star=False),
                    tool_policy._normalize_rule_recipient_identity(approval.get("recipient_identity", "none"), allow_star=False),
                    str(approval.get("legacy_destination") or ""),
                    ",".join(
                        sorted(
                            str(cls)
                            for cls in (approval.get("data_classes") or [])
                            if str(cls) in core._ALL_PRIVACY_CLASSES
                        )
                    ),
                    str(approval.get("action_detail") or ""),
                    str(approval.get("fingerprint") or ""),
                    int(float(approval.get("created_at") or 0)),
                    int(float(approval.get("expires_at") or 0)),
                    str(approval.get("cron_job_id") or ""),
                    str(approval.get("cron_job_name") or ""),
                    str(approval.get("reason") or "")[:1000],
                    activity_store._normalize_destination_trust_label(approval.get("destination_trust")),
                    activity_store._normalize_decision_step_label(approval.get("decision_step")),
                    str(approval.get("permit_recipient") or "")[:200],
                    str(approval.get("permit_host") or "")[:200],
                    str(approval.get("permit_command") or "")[:200],
                ),
            )
    except Exception as exc:
        core.logger.warning("%s: failed to save pending approval: %s", core._PLUGIN_NAME, exc)


def _delete_pending_approvals_from_store_unlocked(approval_ids: list[str] | set[str] | tuple[str, ...]) -> None:
    ids = [str(approval_id) for approval_id in approval_ids if str(approval_id)]
    if not ids:
        return
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
            conn.executemany("DELETE FROM pending_approvals WHERE id = ?", [(approval_id,) for approval_id in ids])
    except Exception as exc:
        core.logger.warning("%s: failed to delete pending approvals: %s", core._PLUGIN_NAME, exc)


def _approval_id_compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _recent_approval_ids() -> set[str]:
    cutoff = int(state._now() - core._APPROVAL_ID_REUSE_SECONDS)
    recent: set[str] = set()
    try:
        activity_store._ensure_activity_db()
        with activity_store._activity_connect() as conn:
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
        core.logger.debug("%s: failed to load recent approval ids: %s", core._PLUGIN_NAME, exc)
    return recent


def _new_approval_id(shape: dict[str, Any] | None = None) -> str:
    with state._LOCK:
        llm._prune_expired()
        _load_pending_approvals_from_store_unlocked()
        unavailable = set(state._PENDING_APPROVALS) | _recent_approval_ids()
    start = secrets.randbelow(10_000)
    for offset in range(10_000):
        candidate = f"{(start + offset) % 10_000:04d}"
        if candidate not in unavailable:
            return candidate
    core.logger.warning("%s: exhausted 4-digit approval ID space; reusing a recent code", core._PLUGIN_NAME)
    return f"{secrets.randbelow(10_000):04d}"


def _resolve_pending_approval_id(approval_id: str) -> str | None:
    approval_id = str(approval_id or "").strip().lower()
    if not approval_id:
        return None
    with state._LOCK:
        _load_pending_approvals_from_store_unlocked()
        if approval_id in state._PENDING_APPROVALS:
            return approval_id
        compact = _approval_id_compact(approval_id)
        matches = [
            stored_id
            for stored_id in state._PENDING_APPROVALS
            if _approval_id_compact(stored_id) == compact
        ]
    return matches[0] if len(matches) == 1 else None


def _is_cron_session_id(session_id: str | None) -> bool:
    return bool(re.fullmatch(r"cron_[0-9a-f]{12}_\d{8}_\d{6}", tool_policy._normalize_session_id(session_id), re.I))


def _cron_job_id_from_session(session_id: str | None) -> str:
    match = re.fullmatch(r"cron_([0-9a-f]{12})_\d{8}_\d{6}", tool_policy._normalize_session_id(session_id), re.I)
    return match.group(1) if match else ""


def _configured_owner_values_from_env(*names: str) -> set[str]:
    values: set[str] = set()
    for name in names:
        raw = state._env(name, "")
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
        hashes.add(tool_policy._hash_identity("telegram", sender_id))
    for sender_id in _configured_owner_values_from_env("DISCORD_ALLOWED_USERS"):
        hashes.add(tool_policy._hash_identity("discord", sender_id))
    return hashes


def _approval_owner_allowed(owner_hash: str, approval: dict[str, Any]) -> bool:
    if approval.get("owner_hash") == owner_hash or owner_hash == core._CLI_OWNER_HASH:
        return True
    if _is_cron_session_id(approval.get("session_id")) and owner_hash in _configured_owner_hashes():
        return True
    return False


def _create_pending_approval(shape: dict[str, Any]) -> dict[str, Any]:
    cron_job_id = _cron_job_id_from_session(shape.get("session_id"))
    try:
        cron_job_name = cron_notifications._cron_job_name(cron_job_id) if cron_job_id else ""
    except Exception:
        cron_job_name = ""
    approval = {
        "id": _new_approval_id(shape),
        "session_id": shape["session_id"],
        "owner_hash": shape.get("owner_hash") or "",
        "tool_name": shape["tool_name"],
        "action_family": shape["action_family"],
        "destination": shape["destination"],
        "purpose": tool_policy._normalize_rule_purpose(shape.get("purpose", "unknown"), allow_star=False),
        "recipient_identity": tool_policy._normalize_rule_recipient_identity(shape.get("recipient_identity", "none"), allow_star=False),
        "legacy_destination": "",
        "data_classes": list(shape["data_classes"]),
        "action_detail": shape.get("action_detail") or "",
        "fingerprint": shape["fingerprint"],
        "created_at": int(state._now()),
        "expires_at": int(state._now() + core._APPROVAL_TTL_SECONDS),
        "cron_job_id": cron_job_id,
        "cron_job_name": cron_job_name,
        "reason": "",
        # Resolved at decision time (doc 03 §3.2) so a pending block carries its trust
        # pill + decide() step into the dashboard. Metadata-only (enum label + step name).
        "destination_trust": activity_store._normalize_destination_trust_label(shape.get("destination_trust")),
        "decision_step": activity_store._normalize_decision_step_label(shape.get("decision_step")),
        # Raw permit candidates (doc 06 §4.1), short-lived: used to materialize a structural
        # permit (self.* / trusted_recipients), which the engine matches RAW.
        "permit_recipient": str(shape.get("permit_recipient") or ""),
        "permit_host": str(shape.get("permit_host") or ""),
        "permit_command": str(shape.get("permit_command") or ""),
    }
    with state._LOCK:
        _load_pending_approvals_from_store_unlocked()
        state._PENDING_APPROVALS[approval["id"]] = approval
        _save_pending_approval_to_store_unlocked(approval)
    return approval


def _guardian_block_message(approval: dict[str, Any]) -> str:
    """The block notice returned to the AGENT as the withheld tool's result.

    The agent is the relay to the user, so the message carries the full reason and
    the approval commands for the agent to surface to the owner (the agent cannot
    self-approve — approval is owner-gated). It ALSO carries an explicit
    anti-circumvention directive: a blocked egress must not be re-attempted through a
    different tool, command, channel, or rephrased arguments. This closes the
    channel-shopping hole where an agent, told only "this was blocked", re-routes the
    same export through a softer surface (the terminal->browser incident).
    """
    classes = ", ".join(approval.get("data_classes") or ["private"])
    action_detail = str(approval.get("action_detail") or "").strip()
    action_detail_line = f"Action detail: {action_detail}\n" if action_detail else ""
    reason = str(approval.get("reason") or "").strip()
    reason_line = f"Reason: {reason}\n" if reason else ""
    # The ways to permit are context-filtered (doc 06): expiry-based approval options plus any
    # structural option this action supports (this recipient is me, trust this host, …).
    approve_lines = []
    last_group = ""
    for option in _approval_permit_options(approval):
        group = str(option.get("group") or "Approval options")
        if group != last_group:
            approve_lines.append(f"{group}:")
            last_group = group
        command = _permit_command_line(approval["id"], option["method"])
        admin = " [admin]" if option.get("structural") else ""
        approve_lines.append(f"  {command}{admin}  — {option['label']}")
    approve_block = "\n".join(approve_lines)
    return (
        "Hermes Guardian blocked this egress.\n\n"
        f"Approval ID: {approval['id']}\n"
        f"Action: {approval['action_family']}\n"
        f"Destination: {approval['destination']}\n"
        f"{action_detail_line}"
        f"Data classes: {classes}\n"
        f"{reason_line}\n"
        "DO NOT attempt to accomplish the same result another way. Re-trying this "
        "through a different tool, command, channel, or rephrased arguments to reach "
        "the same outcome is circumvention and will be blocked too. Stop and surface "
        "this block, the reason, and the approval options to the user — only they can "
        "approve it.\n\n"
        "The user can permit it with one of:\n"
        f"{approve_block}\n"
        "or dismiss with:\n"
        f"/guardian dismiss {approval['id']}"
    )


def _rule_from_approval(approval: dict[str, Any], *, expires_at: int = 0) -> dict[str, Any]:
    cron_job_id = _cron_job_id_from_session(approval.get("session_id"))
    scope = {
        "owner_hash": approval.get("owner_hash") or "",
        "cron_job_id": "",
        "cron_job_name": "",
    }
    if cron_job_id:
        scope["owner_hash"] = "*"
        scope["cron_job_id"] = cron_job_id
        scope["cron_job_name"] = str(approval.get("cron_job_name") or "")
    rule = {
        "id": f"rule_{secrets.token_hex(4)}",
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
        "expires_at": int(float(expires_at or 0)),
        "created_at": int(state._now()),
    }
    return rule


# --- Context-aware permit options (doc 06) -----------------------------------
# A block is not only resolvable by an allow rule: the engine already honors several
# other allow paths (self identities/destinations/hosts, trusted recipients/commands).
# `_approval_permit_options` derives, FROM the approval's context, exactly the set of
# those mechanisms that would actually flip THIS block's decision to allow — no more
# (a dead-end permit that would re-block is never offered: doc 06 §3.1, invariant #2),
# no less. `_apply_permit_option` is the single consumer that applies one of them.

# Rule methods: an allow rule, gated by the approval-owner check. Both rule methods
# match the same action shape (tool/action/destination/purpose/recipient/classes); the
# only difference is expiry.
_RULE_PERMIT_METHODS = frozenset({"rule_5m", "rule_forever"})
# Structural methods (rows 4-5): widen what counts as yours/trusted. They are admin-gated
# because they change the trust boundary permanently (doc 06 §6), exactly as the
# /destinations/* surfaces are.
_STRUCTURAL_PERMIT_METHODS = frozenset(
    {"self_identity", "self_destination", "self_host", "trusted_identity", "trusted_command"}
)
_PERMIT_METHODS = _RULE_PERMIT_METHODS | _STRUCTURAL_PERMIT_METHODS

# The slash keyword each method is granted under (doc 06 §7). `mine`/`trust` are
# unambiguous within a single approval — a context offers at most one self_* and one
# trusted_* — so the keyword alone resolves the method.
_PERMIT_METHOD_KEYWORDS = {
    "rule_5m": "5m",
    "rule_forever": "forever",
    "self_identity": "mine",
    "self_destination": "mine",
    "self_host": "mine",
    "trusted_identity": "trust",
    "trusted_command": "trust",
}


def _permit_command_line(approval_id: str, method: str) -> str:
    """The `/guardian approve` command that grants ``method`` for ``approval_id``."""
    return f"/guardian approve {approval_id} {_PERMIT_METHOD_KEYWORDS.get(method, method)}"

# Destination kinds (capability._FAMILY_TO_DEST_KIND values) whose self-allowlist /
# trusted-by-id mechanisms the resolver consults (doc 06 §3.1). A `host`-kind family
# (web_api/web_read/browser_read) is resolved against self.hosts; a store/draft/local
# write is resolved against self.destinations + trusted-by-connector-id.
_PERMIT_STORE_KINDS = frozenset({"store", "draft", "local"})
_PERMIT_HOST_KINDS = frozenset({"host"})

_STRUCTURAL_ADMIN_DENIED = (
    "Permission denied: widening what counts as yours or trusted requires the CLI or a "
    "configured Guardian owner. You can still approve this action for 5 minutes or forever."
)


def _permit_recipient_value(approval: dict[str, Any]) -> str:
    """The RAW recipient to add to self.identities / trusted_recipients, or "".

    Read from the short-lived ``permit_recipient`` captured at block time (doc 06 §4.1) —
    NOT the pseudonymized ``recipient_identity``, which the engine never matches against.
    Conservative (doc 06 §3): a templated/empty recipient yields "" and is never offered
    as a self/trusted identity (it can't be proven).
    """
    return str(approval.get("permit_recipient") or "").strip()


def _permit_dest_id(approval: dict[str, Any]) -> str:
    """The bare connector id for a store write (e.g. ``notion`` for ``mcp:notion``).

    Prefers the structured ``dest_id`` captured at block time (doc 06 §4.1); falls back
    to parsing the legacy ``destination`` string so pre-migration approvals still resolve.
    """
    dest_id = str(approval.get("dest_id") or "").strip().lower()
    if dest_id:
        return dest_id
    destination = str(approval.get("destination") or "")
    if ":" in destination:
        return destination.split(":", 1)[1].strip().lower()
    return destination.strip().lower()


def _permit_host_value(approval: dict[str, Any], dest_kind: str) -> str:
    """The network host to add to self.hosts, normalized; "" when none is derivable."""
    host = str(approval.get("permit_host") or "")
    if not host and dest_kind in _PERMIT_HOST_KINDS:
        host = str(approval.get("dest_id") or approval.get("destination") or "")
    return destinations._normalize_host(host)


def _approval_permit_options(approval: dict[str, Any]) -> list[dict[str, Any]]:
    """The ordered, context-filtered ways to permit ``approval`` (doc 06 §2-3).

    Pure. Rows are ordered narrowest -> broadest. Rule rows are always present;
    structural rows appear only for the dimensions that (a) carry a concrete value and
    (b) the engine actually consults for this family (doc 06 §3.1). A block may yield
    SEVERAL structural rows (e.g. a terminal command to a host -> self_host + trusted_command).
    """
    family = str(approval.get("action_family") or "")
    tool_name = str(approval.get("tool_name") or "")
    data_classes = [
        cls for cls in (approval.get("data_classes") or []) if cls in core._ALL_PRIVACY_CLASSES
    ]
    options: list[dict[str, Any]] = []

    def add(method: str, label: str, detail: str = "", value: str = "", kind: str = "",
            structural: bool = False) -> None:
        if method in _RULE_PERMIT_METHODS:
            group = "Approval options"
        elif method.startswith("self_"):
            group = "Ownership options"
        else:
            group = "Trusted Destination Options"
        options.append({
            "method": method,
            "label": label,
            "detail": detail,
            "value": value,
            "kind": kind,
            "structural": structural,
            "data_classes": list(data_classes),
            "group": group,
        })

    # Approval rows: same shape, different expiry. Always available.
    add("rule_5m", "Approve for 5 minutes", "matching action shape until the rule expires")
    add("rule_forever", "Approve forever", "matching action shape with no expiry")

    dest_kind = str(approval.get("dest_kind") or "") or capability._dest_kind_for_family(family)
    subtype = str(approval.get("action_subtype") or "") or capability._action_subtype_for(
        family, tool_name
    )
    # Outward-sharing reaches other parties even on a self store, so the self_* claims are
    # suppressed (the engine resolves these to external regardless: doc 06 §3.1).
    cfg = destinations._destinations_config(None)
    allow_self = not destinations._is_outward_sharing(subtype, cfg)
    recipient = _permit_recipient_value(approval)

    if family in capability._MESSAGING_FAMILIES or dest_kind == "messaging":
        # §3.1 messaging row: trust is a property of the recipient, not a store/host.
        if recipient:
            if allow_self:
                add("self_identity", "This recipient is me", recipient, recipient, "identity", True)
            add("trusted_identity", "Trust this recipient", recipient, recipient, "identity", True)
    elif dest_kind in _PERMIT_STORE_KINDS:
        dest_id = _permit_dest_id(approval)
        if allow_self and dest_id and dest_id != "messaging":
            token = f"{dest_kind}:{dest_id}"
            add("self_destination", "This store is mine", token, token, "destination", True)
        if dest_id and dest_id != "messaging":
            add("trusted_identity", "Trust this destination", dest_id, dest_id, "identity", True)
    elif family == "terminal_exec" or dest_kind == "terminal":
        # A terminal action carries TWO independent dimensions (doc 06 §3): the host it
        # reaches (self.hosts) and the command itself (trusted command).
        host = _permit_host_value(approval, "terminal")
        command = str(approval.get("permit_command") or "")
        if allow_self and host:
            add("self_host", "This host is mine", host, host, "host", True)
        if command:
            add("trusted_command", "Trust this command", command, command, "command", True)
    elif dest_kind in _PERMIT_HOST_KINDS:
        host = _permit_host_value(approval, dest_kind)
        if allow_self and host:
            add("self_host", "This host is mine", host, host, "host", True)

    group_order = {"Approval options": 0, "Trusted Destination Options": 1, "Ownership options": 2}
    ordered = sorted(
        enumerate(options),
        key=lambda item: (group_order.get(str(item[1].get("group") or ""), 99), item[0]),
    )
    return [option for _index, option in ordered]


def _permit_option_for(approval: dict[str, Any], method: str) -> dict[str, Any] | None:
    for option in _approval_permit_options(approval):
        if option["method"] == method:
            return option
    return None


def _apply_structural_permit(method: str, option: dict[str, Any]) -> tuple[bool, str]:
    """Apply a structural (self_*/trusted_*) permit by calling the same config mutators
    the /destinations/* surfaces use. Trusted entries are scoped to the approval's data
    classes (doc 06 invariant #6), never widened to ``*``."""
    value = str(option.get("value") or "")
    classes = option.get("data_classes") or None
    note = "approved from a guardian block"
    if method == "self_identity":
        return rules_mod._add_self_destination("identity", value)
    if method == "self_destination":
        return rules_mod._add_self_destination("destination", value)
    if method == "self_host":
        return rules_mod._add_self_destination("host", value)
    if method == "trusted_identity":
        return rules_mod._add_trusted_recipient(value, classes=classes, note=note)
    if method == "trusted_command":
        return rules_mod._add_trusted_command(value, classes=classes, note=note)
    return False, f"Unknown permit option {method}."


def _materialize_permit(
    approval: dict[str, Any], method: str, option: dict[str, Any] | None
) -> tuple[bool, str, str, str]:
    """Apply one permit method. Returns ``(ok, message, rule_id, rule_source)``.

    Rule methods create saved allow rules; structural methods call the config mutators.
    """
    if method in _RULE_PERMIT_METHODS:
        expires_at = int(state._now() + 300) if method == "rule_5m" else 0
        rule = _rule_from_approval(approval, expires_at=expires_at)
        rules = rules_mod._persistent_privacy_rules()
        rules.append(rule)
        if not rules_mod._save_persistent_privacy_rules(rules):
            return False, "Failed to save privacy approval; Hermes Guardian remains blocked.", "", ""
        scope_word = "5m" if method == "rule_5m" else "forever"
        scope_label = "5 minutes" if method == "rule_5m" else f"forever for {_rule_scope_label(rule)}"
        classes = ", ".join(approval.get("data_classes") or ["private"])
        message = (
            f"Approved {approval.get('action_family', '')} -> {approval.get('destination', '')} "
            f"for {classes} ({scope_label})."
        )
        return True, message, rule.get("id", ""), scope_word

    ok, mutator_message = _apply_structural_permit(method, option or {})
    return ok, mutator_message, "", method


def _apply_permit_option(owner_hash: str, approval_id: str, method: str) -> tuple[bool, str]:
    """Resolve, gate, and apply one permit method for a pending approval (doc 06 §5).

    The single consumer for BOTH surfaces, so the security gate (doc 06 §6) lives in
    one place: approval rule methods require the approval-owner check; structural methods additionally
    require the admin check (CLI or a configured owner). A method not offered for this
    approval is refused (no dead-end permits).
    """
    requested_id = approval_id
    if method not in _PERMIT_METHODS:
        return False, f"Unknown permit option {method}."
    structural = method in _STRUCTURAL_PERMIT_METHODS
    with state._LOCK:
        llm._prune_expired()
        resolved_id = _resolve_pending_approval_id(approval_id) or ""
        approval = state._PENDING_APPROVALS.get(resolved_id)
        if not approval:
            return False, f"No pending approval found for {requested_id}."
        if not _approval_owner_allowed(owner_hash, approval):
            return False, "Approval denied: this request belongs to a different user/session."
        if structural and not _owner_is_authenticated(owner_hash):
            return False, _STRUCTURAL_ADMIN_DENIED
        option = _permit_option_for(approval, method)
        if structural and (option is None or not option.get("value")):
            return False, "That permit option isn't available for this action."
        # Consume first; restore on failure so a failed write leaves the approval available.
        state._PENDING_APPROVALS.pop(resolved_id, None)
        _delete_pending_approvals_from_store_unlocked([resolved_id])
        ok, message, rule_id, rule_source = _materialize_permit(approval, method, option)
        if not ok:
            state._PENDING_APPROVALS[resolved_id] = approval
            _save_pending_approval_to_store_unlocked(approval)
            return False, message
    activity_store._emit_activity(
        "manual_approved",
        session_id=approval.get("session_id", ""),
        owner_hash=approval.get("owner_hash", ""),
        tool_name=approval.get("tool_name", ""),
        action_family=approval.get("action_family", ""),
        destination=approval.get("destination", ""),
        purpose=approval.get("purpose", "unknown"),
        recipient_identity=approval.get("recipient_identity", "none"),
        data_classes=approval.get("data_classes") or [],
        reason=f"approved {rule_source or method}",
        approval_id=resolved_id,
        rule_id=rule_id,
        rule_source=rule_source,
        action_detail=approval.get("action_detail", ""),
    )
    return True, message


def _rule_scope_label(rule: dict[str, Any]) -> str:
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    cron_job_id = str(scope.get("cron_job_id") or rule.get("cron_job_id") or "").strip()
    if cron_job_id:
        cron_job_name = str(scope.get("cron_job_name") or rule.get("cron_job_name") or "").strip()
        try:
            cron_job_name = cron_job_name or cron_notifications._cron_job_name(cron_job_id)
        except Exception:
            pass
        if cron_job_name:
            return f"cron job {cron_job_name} ({cron_job_id})"
        return f"cron job {cron_job_id}"
    if scope.get("owner_hash") == "*":
        return "all owners"
    return "owner"


def _rule_delete_owner_allowed(owner_hash: str, rule: dict[str, Any]) -> bool:
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else {}
    if owner_hash == core._CLI_OWNER_HASH:
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

    rules = rules_mod._persistent_privacy_rules()
    removed: dict[str, Any] | None = None
    kept: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("id") == rule_id and _rule_delete_owner_allowed(owner_hash, rule):
            removed = rule
            continue
        kept.append(rule)

    if removed is None:
        return False, f"No matching privacy rule found for {rule_id}.", None

    if not rules_mod._save_persistent_privacy_rules(kept):
        return False, "Failed to delete privacy rule; Hermes Guardian remains fail-closed.", None

    return True, f"Deleted privacy rule {rule_id}.", removed


# Fail-closed sentinel for a `/guardian` command whose owner was never positively
# recorded by `pre_gateway_dispatch` (`_remember_command_owner`). It must NOT equal
# `core._CLI_OWNER_HASH` and must NOT be a configured gateway owner, so it satisfies
# neither `_approval_owner_allowed` nor `_owner_is_authenticated`. Any handler path that
# reaches `_pop_command_owner` without a recorded owner — agent-emitted slash text, a
# programmatic dispatch, a TTL/whitespace skew — is therefore treated as an
# unauthenticated stranger and DENIED, instead of inheriting CLI-owner admin power.
_UNAUTHENTICATED_OWNER_HASH = "__unauthenticated__"


def _remember_command_owner(
    raw_args: str,
    owner_hash: str,
    *,
    platform: str = "",
    chat_type: str = "",
) -> None:
    key = raw_args.strip()
    if not key:
        return
    with state._LOCK:
        state._RECENT_COMMAND_OWNERS.setdefault(key, []).append((state._now(), owner_hash))
        state._RECENT_COMMAND_CONTEXTS.setdefault(key, []).append({
            "ts": state._now(),
            "owner_hash": owner_hash,
            "platform": str(platform or "").strip().lower(),
            "chat_type": str(chat_type or "").strip().lower(),
        })


def _owner_is_authenticated(owner_hash: str) -> bool:
    """True only for the CLI owner or a configured gateway owner.

    Group/cron/unauthenticated senders are excluded, so their inbound text is
    never trusted as authorization evidence for the LLM verifier.
    """
    return bool(owner_hash) and (
        owner_hash == core._CLI_OWNER_HASH or owner_hash in _configured_owner_hashes()
    )


def _remember_user_request(event: Any) -> None:
    """Cache a sanitized excerpt of an authenticated owner's inbound message.

    Stored in volatile, owner-keyed process state only. The raw text is never
    persisted; emails, phones, tokens, and URL paths are redacted before storage.
    """
    text = getattr(event, "text", "")
    if not isinstance(text, str) or not text.strip():
        return
    owner_hash = tool_policy._owner_hash_from_event(event)
    if not _owner_is_authenticated(owner_hash):
        return
    # A new owner message starts a fresh turn: reset the cross-channel egress lockdown
    # so a denial in the previous turn does not persist into this one, and rotate the
    # turn_id so subsequent activity groups under this prompt.
    privacy_module._clear_turn_external_denials_for_owner(owner_hash)
    tool_policy._rotate_turn_id_for_owner(owner_hash)
    sanitized = llm._redact_command_for_llm(text.strip())
    if not sanitized:
        return
    with state._LOCK:
        state._RECENT_OWNER_REQUESTS[owner_hash] = (state._now(), sanitized)


def _recent_user_request_for_owner(owner_hash: str) -> str:
    """Most recent fresh sanitized request for an authenticated owner, else ""."""
    if not _owner_is_authenticated(owner_hash):
        return ""
    with state._LOCK:
        entry = state._RECENT_OWNER_REQUESTS.get(owner_hash)
        if not entry:
            return ""
        timestamp, sanitized = entry
        if state._now() - timestamp > core._USER_REQUEST_TTL_SECONDS:
            state._RECENT_OWNER_REQUESTS.pop(owner_hash, None)
            return ""
        return sanitized


def _cron_instruction_for_session(session_id: str | None) -> str:
    """Sanitized standing instruction for a cron session's job, else "".

    Sourced from the owner-authored job record (creation-time), never from live
    run context. The raw prompt is redacted the same way as a user request.
    """
    if not _is_cron_session_id(session_id):
        return ""
    job_id = _cron_job_id_from_session(session_id)
    if not job_id:
        return ""
    job = cron_notifications._cron_job_record(job_id)
    instruction = str(job.get("prompt") or job.get("name") or "").strip()
    if not instruction:
        return ""
    return llm._redact_command_for_llm(instruction)


def _pop_command_context(raw_args: str) -> dict[str, str]:
    key = raw_args.strip()
    with state._LOCK:
        llm._prune_expired()
        contexts = state._RECENT_COMMAND_CONTEXTS.get(key) or []
        context = contexts.pop(0) if contexts else None
        if contexts:
            state._RECENT_COMMAND_CONTEXTS[key] = contexts
        else:
            state._RECENT_COMMAND_CONTEXTS.pop(key, None)
        entries = state._RECENT_COMMAND_OWNERS.get(key) or []
        if entries:
            state._RECENT_COMMAND_OWNERS[key] = entries[1:]
            if not state._RECENT_COMMAND_OWNERS[key]:
                state._RECENT_COMMAND_OWNERS.pop(key, None)
            owner_hash = entries[0][1]
        else:
            owner_hash = ""
        if context:
            return {
                "owner_hash": str(context.get("owner_hash") or owner_hash or _UNAUTHENTICATED_OWNER_HASH),
                "platform": str(context.get("platform") or "").strip().lower(),
                "chat_type": str(context.get("chat_type") or "").strip().lower(),
            }
        if owner_hash:
            return {"owner_hash": owner_hash, "platform": "", "chat_type": ""}
    # Cache miss: the gateway never positively recorded an owner for this command.
    # A trusted local-CLI/host context (which drives the handler directly, with no
    # gateway dispatch) opts into the local-operator identity. Otherwise fail CLOSED
    # with an unauthenticated identity rather than the all-powerful CLI owner, so an
    # approve that did not transit `pre_gateway_dispatch` (agent-emitted slash text, a
    # lost/stale gateway record) is denied instead of silently self-approving.
    if state._TRUSTED_LOCAL_COMMAND_CONTEXT:
        return {"owner_hash": core._CLI_OWNER_HASH, "platform": "cli", "chat_type": ""}
    return {"owner_hash": _UNAUTHENTICATED_OWNER_HASH, "platform": "", "chat_type": ""}


def _pop_command_owner(raw_args: str) -> str:
    return _pop_command_context(raw_args).get("owner_hash") or _UNAUTHENTICATED_OWNER_HASH


def _owner_session_ids(owner_hash: str) -> set[str]:
    if owner_hash == core._CLI_OWNER_HASH:
        return set(state._SESSIONS) or {core._GLOBAL_SESSION_ID}
    return set(state._OWNER_SESSIONS.get(owner_hash) or [])
