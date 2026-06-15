"""JSON-backed privacy rule loading, matching, and mutation."""

from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from . import llm
from . import tool_policy
from .. import core
from .. import state
from ..integrations import cron_notifications
from ..runtime import activity_store


_PRIVACY_RULE_FILE_VERSION = 4
_DEFAULT_EGRESS_SAFETY = "llm"
_EGRESS_SAFETY_MODES = {"strict", "read-only", "llm", "off"}
_DEFAULT_TAINT_CLASSIFICATION = "balanced"
_TAINT_CLASSIFICATION_MODES = {"balanced", "strict", "relaxed"}
# Metadata-only LLM source classification for otherwise-unknown reads. Defaults on:
# it writes ordinary Reading tool classifications so the same source is not re-judged.
_DEFAULT_LLM_SOURCE_CLASSIFICATION = True
# Whether the llm-mode verifier receives sanitized authorization-evidence context.
# User context (authenticated owner's inbound request) and cron context (a job's
# own stored instruction) default on. High-risk cron egress still falls back to
# manual approval in the verifier path.
_DEFAULT_LLM_USER_CONTEXT = True
_DEFAULT_LLM_CRON_CONTEXT = True
# Opt-in debugging: persist the (already-sanitized) user/cron prompt onto activity rows
# so dashboard history groups can show what was asked. Default OFF — it relaxes the
# "prompt is never persisted" invariant, so it is confirmation-gated on every surface.
_DEFAULT_PERSIST_PROMPTS = False
# Optional model the llm-mode verifier should run on (empty = Hermes default).
# A fast classification model (e.g. a "mini" variant) cuts verifier latency
# dramatically vs. a reasoning model. Requires the operator to grant
# plugins.entries.hermes-guardian.llm.allow_model_override in config.yaml.
_DEFAULT_LLM_VERIFIER_MODEL = ""
# Action families a user may assign to a custom/unknown tool via a Sharing tool
# classification. "ignore" marks a tool as a safe non-sink; "gate" forces
# tool_unknown gating.
_SHARING_TOOL_EGRESS_FAMILIES = {
    "message_send",
    "web_api",
    "mcp_write",
    "mcp_read_query",
    "local_write",
    "terminal_exec",
    "model_api",
    "tool_write",
    "delegate_task",
    "computer_use",
    "kanban_write",
    "cron_write",
    "homeassistant_write",
}
_SHARING_TOOL_EGRESS_VALUES = {"ignore", "gate"} | _SHARING_TOOL_EGRESS_FAMILIES
# Source-provenance classification mode for a doc-read tool. `reference` routes reads
# through the placeholder-tolerant relaxed scan (operator-installed reference material);
# `private` always taints the read as personal data; `public` never privacy-taints from
# the read. Empty means "use the tiered default" (provenance for reference reads,
# conservative for undeclared MCP doc-reads). For an MCP server, declare the whole server
# at once with a prefix match (e.g. match = "crm_*").
_READING_TOOL_SOURCES = {"reference", "private", "public", "unknown"}
_TOOL_CLASSIFICATION_NOTE_MAX_CHARS = 2000
# Env vars that override the named `retention` / `dashboard` config blocks (doc 03
# §1.2). The document is the source of truth; these env vars remain readable as ops
# overrides and are surfaced in `/guardian status` so they are never invisible.
_RETENTION_ENV_OVERRIDES = (
    ("max_rows", "HERMES_GUARDIAN_ACTIVITY_MAX_ROWS"),
    ("max_age_days", "HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS"),
)
_DASHBOARD_ENV_OVERRIDES = (
    ("mutations", "HERMES_GUARDIAN_DASHBOARD_MUTATIONS"),
    ("admin_token_env", "HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN"),
)
_DEFAULT_RETENTION_MAX_ROWS = 100
_DEFAULT_RETENTION_MAX_AGE_DAYS = 7
_DEFAULT_DASHBOARD_MUTATIONS = "auto"
_DEFAULT_DASHBOARD_ADMIN_TOKEN_ENV = "HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN"
# --- Destination-trust config defaults (doc 01 §4) ----------------------------
# These seed the `self` / `trusted_recipients` / `outward_sharing` blocks of the
# privacy config. The destination-trust resolver (privacy/destinations.py) reads
# them during active capability classification.
#
# Conservative-but-useful defaults (doc 01 §4):
#  - destinations: the first-party single-operator-owned Hermes stores + draft:*
#    (writes here reach no new party because the operator authenticated as
#    themselves). Third-party MCP connectors are NOT seeded here: a connector is
#    self only when the operator explicitly adds an `mcp:<name>` self entry, never
#    by a `store:<name>` name collision (a malicious MCP server must not inherit
#    trust by naming its tool `mcp_<seeded-name>_*`).
#  - identities / hosts: EMPTY — send-to-self and own-infra are powerful `self`
#    grants the operator must opt into; an unfilled list fails closed to external.
#  - outward_sharing.builtin: the six subtypes that reach other parties even on a
#    self store. NOT narrowable — parsing ignores attempts to remove a builtin;
#    `extra` may only add.
_DEFAULT_SELF_DESTINATIONS = (
    "store:files",
    "store:memory",
    "store:todo",
    "store:calendar",
    "store:drive",
    "draft:*",
)
_OUTWARD_SHARING_BUILTIN_SUBTYPES = (
    "share",
    "invite",
    "publish",
    "add_collaborator",
    "make_public",
    "set_permissions",
)
# Class labels a trusted-recipient entry may scope itself to (doc 01 §4 example).
# Reuses the existing privacy data-class vocabulary; unknown classes are dropped.
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
            "egress_safety": _DEFAULT_EGRESS_SAFETY,
            "taint_classification": _DEFAULT_TAINT_CLASSIFICATION,
            "llm_source_classification": _DEFAULT_LLM_SOURCE_CLASSIFICATION,
            "llm_user_context": _DEFAULT_LLM_USER_CONTEXT,
            "llm_cron_context": _DEFAULT_LLM_CRON_CONTEXT,
            "llm_verifier_model": _DEFAULT_LLM_VERIFIER_MODEL,
            "rules": [],
            "reading_tools": [],
            "sharing_tools": [],
        },
        "self": _default_self_config(),
        "trusted_recipients": _default_trusted_recipients_config(),
        "outward_sharing": _default_outward_sharing_config(),
        "security": {
            "rules": _default_security_rules(),
        },
        "language_packs": _default_language_pack_config(),
        "retention": _default_retention_config(),
        "dashboard": _default_dashboard_config(),
    }


def _default_retention_config() -> dict[str, Any]:
    return {
        "max_rows": _DEFAULT_RETENTION_MAX_ROWS,
        "max_age_days": _DEFAULT_RETENTION_MAX_AGE_DAYS,
    }


def _default_dashboard_config() -> dict[str, Any]:
    return {
        "mutations": _DEFAULT_DASHBOARD_MUTATIONS,
        "admin_token_env": _DEFAULT_DASHBOARD_ADMIN_TOKEN_ENV,
        "persist_prompts": _DEFAULT_PERSIST_PROMPTS,
    }


def _normalize_retention_config(raw: Any) -> dict[str, Any]:
    """Normalize the ``retention`` block (doc 03 §1.2), fail closed to defaults.

    Values are non-negative integers; 0 disables the corresponding limit (matching
    the existing env semantics). A malformed value drops to the default for that key.
    """
    block = raw if isinstance(raw, dict) else {}

    def as_int(value: Any, default: int) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return default

    return {
        "max_rows": as_int(block.get("max_rows"), _DEFAULT_RETENTION_MAX_ROWS),
        "max_age_days": as_int(block.get("max_age_days"), _DEFAULT_RETENTION_MAX_AGE_DAYS),
    }


def _normalize_dashboard_config(raw: Any) -> dict[str, Any]:
    """Normalize the runtime/dashboard block, fail closed to defaults.

    Reads the v4 ``protection.runtime`` key ``dashboard_mutations`` (doc 04 §2) and
    the internal ``mutations`` alias so the internal structure is identical whether
    sourced from the on-disk file or an in-memory mutation.
    """
    block = raw if isinstance(raw, dict) else {}
    mutations = str(
        block.get("dashboard_mutations") or block.get("mutations") or _DEFAULT_DASHBOARD_MUTATIONS
    ).strip().lower()
    if mutations not in {"auto", "on", "off"}:
        mutations = _DEFAULT_DASHBOARD_MUTATIONS
    token_env = str(block.get("admin_token_env") or _DEFAULT_DASHBOARD_ADMIN_TOKEN_ENV).strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{1,80}", token_env):
        token_env = _DEFAULT_DASHBOARD_ADMIN_TOKEN_ENV
    persist_prompts = _config_bool(block.get("persist_prompts"), default=_DEFAULT_PERSIST_PROMPTS)
    return {"mutations": mutations, "admin_token_env": token_env, "persist_prompts": persist_prompts}


def _default_self_config() -> dict[str, Any]:
    return {
        "destinations": list(_DEFAULT_SELF_DESTINATIONS),
        "identities": [],
        "hosts": [],
    }


def _default_trusted_recipients_config() -> dict[str, Any]:
    return {"entries": []}


def _default_outward_sharing_config() -> dict[str, Any]:
    return {
        "builtin": list(_OUTWARD_SHARING_BUILTIN_SUBTYPES),
        "extra": [],
    }


def _strict_privacy_config() -> dict[str, Any]:
    config = _default_privacy_config()
    config["privacy"]["egress_safety"] = "strict"
    config["privacy"]["rules"] = []
    return config


def _normalize_egress_safety(value: Any) -> str:
    mode = str(value or _DEFAULT_EGRESS_SAFETY).strip().lower().replace("_", "-")
    return mode if mode in _EGRESS_SAFETY_MODES else _DEFAULT_EGRESS_SAFETY


def _normalize_taint_classification(value: Any) -> str:
    mode = str(value or _DEFAULT_TAINT_CLASSIFICATION).strip().lower().replace("_", "-")
    return mode if mode in _TAINT_CLASSIFICATION_MODES else _DEFAULT_TAINT_CLASSIFICATION


# Legacy data-class aliases. The old "email" class was split into "contacts"
# (a bare address) and "communications" (message bodies); existing persisted
# rules and saved approvals still reference it. Map to "communications" — the
# dominant intent of an email egress rule is the correspondence content, and
# mapping to a single class keeps allow rules from silently widening to permit
# contact egress as well.
_CLASS_ALIASES = {"email": "communications"}


def _normalize_rule_classes(raw: Any, *, allow_star: bool = True) -> list[str]:
    values = raw if isinstance(raw, list) else [raw]
    classes: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if allow_star and text == "*":
            return ["*"]
        text = _CLASS_ALIASES.get(text, text)
        if text in core._ALL_PRIVACY_CLASSES and text not in classes:
            classes.append(text)
    return sorted(classes)


def _normalize_verifier_model(value: Any) -> str:
    text = str(value or "").strip()
    if not text or text.lower() in {"none", "default", "auto"}:
        return ""
    text = re.sub(r"[^A-Za-z0-9_.:/@-]+", "", text)
    return text[:120]


def _normalize_tool_match(value: Any) -> str:
    """Normalize a tool-classification matcher: exact name or single trailing-* prefix."""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    star = text.endswith("*")
    base = text[:-1] if star else text
    base = re.sub(r"[^a-z0-9_.:-]+", "", base)
    if not base:
        return ""
    return f"{base}*" if star else base


def _normalize_tool_note(value: Any) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t\f\v]+", " ", line).strip() for line in text.split("\n")]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    return text[:_TOOL_CLASSIFICATION_NOTE_MAX_CHARS].rstrip()


def _normalize_reading_tool(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    match = _normalize_tool_match(
        entry.get("match") or entry.get("tool") or entry.get("tool_name")
    )
    if not match:
        return None
    taints = _normalize_rule_classes(entry.get("taints", entry.get("taint", [])), allow_star=False)
    source_raw = str(entry.get("source") or "").strip().lower()
    source = source_raw if source_raw in _READING_TOOL_SOURCES else ""
    if source_raw and not source:
        # Fail toward the conservative default, never toward `reference`: drop the unknown
        # value rather than guess. The read then follows the tiered default for its kind.
        core.logger.warning(
            "%s: ignoring unknown reading tool source %r (expected one of: %s).",
            core._PLUGIN_NAME, source_raw, ", ".join(sorted(_READING_TOOL_SOURCES)),
        )
    if source == "public" and taints:
        core.logger.warning(
            "%s: ignoring public reading tool %r with taints; public sources cannot apply privacy classes.",
            core._PLUGIN_NAME, match,
        )
        return None
    note = _normalize_tool_note(entry.get("note"))
    override_id = str(entry.get("id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", override_id):
        override_id = f"source_tool_{secrets.token_hex(4)}"
    return {
        "id": override_id,
        "match": match,
        "taints": taints,
        "source": source,
        "enabled": _config_bool(entry.get("enabled"), default=True),
        "note": note,
    }


def _normalize_sharing_tool(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    match = _normalize_tool_match(
        entry.get("match") or entry.get("tool") or entry.get("tool_name")
    )
    if not match:
        return None
    egress_raw = str(entry.get("egress") or "").strip().lower()
    egress = egress_raw if egress_raw in _SHARING_TOOL_EGRESS_VALUES else ""
    destination = (
        tool_policy._safe_policy_token(entry.get("destination"), default="", limit=80)
        if entry.get("destination")
        else ""
    )
    note = _normalize_tool_note(entry.get("note"))
    override_id = str(entry.get("id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", override_id):
        override_id = f"sharing_tool_{secrets.token_hex(4)}"
    return {
        "id": override_id,
        "match": match,
        "egress": egress,
        "destination": destination,
        "enabled": _config_bool(entry.get("enabled"), default=True),
        "note": note,
    }


def _normalize_reading_tools(raw: Any) -> list[dict[str, Any]]:
    items = raw if isinstance(raw, list) else []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in items:
        normalized = _normalize_reading_tool(entry)
        if normalized is None:
            continue
        if normalized["id"] in seen:
            normalized["id"] = f"source_tool_{secrets.token_hex(4)}"
        seen.add(normalized["id"])
        out.append(normalized)
    return out


def _normalize_sharing_tools(raw: Any) -> list[dict[str, Any]]:
    items = raw if isinstance(raw, list) else []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in items:
        normalized = _normalize_sharing_tool(entry)
        if normalized is None:
            continue
        if normalized["id"] in seen:
            normalized["id"] = f"sharing_tool_{secrets.token_hex(4)}"
        seen.add(normalized["id"])
        out.append(normalized)
    return out


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


def _normalize_destination_token(value: Any) -> str:
    """Normalize a self-destination allowlist token: ``kind:id`` or ``kind:*``.

    Lowercased; restricted to a conservative charset. A trailing ``*`` (prefix
    match) is preserved. Returns "" for unusable input so malformed entries are
    dropped (fail closed) rather than crashing the load.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    star = text.endswith("*")
    base = text[:-1] if star else text
    base = re.sub(r"[^a-z0-9_.:/-]+", "", base)
    if not base:
        return ""
    return f"{base}*" if star else base


def _normalize_identity_token(value: Any) -> str:
    """Normalize an own-identity / host / recipient identity string.

    Lowercased and length-bounded; emails/handles/hostnames pass through. Empty
    or whitespace-only input is dropped.
    """
    text = re.sub(r"\s+", "", str(value or "")).strip().lower()
    return text[:200]


def _normalize_string_list(raw: Any, normalizer) -> list[str]:
    """Normalize a list of strings with ``normalizer``, dropping empties/dupes."""
    items = raw if isinstance(raw, list) else []
    out: list[str] = []
    for value in items:
        token = normalizer(value)
        if token and token not in out:
            out.append(token)
    return out


def _normalize_self_config(raw: Any) -> dict[str, Any]:
    """Normalize the ``self`` block (doc 01 §4), failing closed on malformed input.

    A non-dict (wholly corrupt) block drops to the safe default subset
    (default destinations + empty identities/hosts). Individual malformed entries
    inside otherwise-valid lists are dropped, not fatal. ``identities`` and
    ``hosts`` default EMPTY, so the absence of a valid block never widens `self`.
    """
    if not isinstance(raw, dict):
        return _default_self_config()
    destinations = _normalize_string_list(
        raw.get("destinations"), _normalize_destination_token
    )
    if not destinations and not isinstance(raw.get("destinations"), list):
        # No destinations key supplied at all -> seed the safe defaults so the
        # common FP cases vanish out of the box (doc 01 §4). An explicitly empty
        # list is honored as-is (operator chose to clear it).
        destinations = list(_DEFAULT_SELF_DESTINATIONS)
    return {
        "destinations": destinations,
        # CONSERVATIVE: identities/hosts are never defaulted to a non-empty set.
        "identities": _normalize_string_list(raw.get("identities"), _normalize_identity_token),
        "hosts": _normalize_string_list(raw.get("hosts"), _normalize_identity_token),
    }


def _normalize_trusted_recipient_entry(entry: Any) -> dict[str, Any] | None:
    """Normalize a Trusted-destinations entry to ``{kind, value, classes, note}``.

    ``kind`` is ``identity`` (an address/handle, default) or ``command`` (a terminal
    command prefix / skills-directory wildcard). Legacy entries carrying only
    ``identity`` upgrade to ``kind="identity"``. Malformed entries drop to None.
    """
    if not isinstance(entry, dict):
        return None
    kind = str(entry.get("kind") or "identity").strip().lower()
    classes = _normalize_rule_classes(entry.get("classes", entry.get("class", ["*"]))) or ["*"]
    note = re.sub(r"\s+", " ", str(entry.get("note") or "")).strip()[:200]
    if kind == "command":
        value = tool_policy._normalize_trusted_command(entry.get("value") or entry.get("command"))
        if not value:
            return None
        return {"kind": "command", "value": value, "classes": classes, "note": note}
    value = _normalize_identity_token(entry.get("value") or entry.get("identity") or entry.get("recipient"))
    if not value:
        return None
    return {"kind": "identity", "value": value, "classes": classes, "note": note}


def _normalize_trusted_recipients(raw: Any) -> dict[str, Any]:
    """Normalize the Trusted-destinations block (doc 01 §4), fail closed.

    A non-dict block, or a non-list ``entries``, drops to the safe empty default.
    Malformed individual entries are dropped; dedup is per ``(kind, value)``.
    """
    if not isinstance(raw, dict):
        return _default_trusted_recipients_config()
    entries_raw = raw.get("entries")
    if not isinstance(entries_raw, list):
        return _default_trusted_recipients_config()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries_raw:
        normalized = _normalize_trusted_recipient_entry(entry)
        if normalized is None:
            continue
        key = (normalized["kind"], normalized["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return {"entries": out}


def _normalize_rule_expires_at(value: Any) -> int:
    try:
        expires_at = int(float(value or 0))
    except (TypeError, ValueError):
        return 0
    return max(0, expires_at)


def _rule_is_expired(rule: dict[str, Any], *, now: int | None = None) -> bool:
    expires_at = _normalize_rule_expires_at(rule.get("expires_at"))
    return bool(expires_at and expires_at <= int(state._now() if now is None else now))


def _normalize_outward_sharing(raw: Any) -> dict[str, Any]:
    """Normalize the ``outward_sharing`` block (doc 01 §4), fail closed.

    The builtin set is NOT narrowable: the result's ``builtin`` is always exactly
    the hard-coded builtin subtypes, regardless of what config supplies (an
    operator attempt to remove one is ignored). ``extra`` may only ADD subtypes
    and is normalized; builtin members are never duplicated into ``extra``.
    """
    block = raw if isinstance(raw, dict) else {}
    builtin = set(_OUTWARD_SHARING_BUILTIN_SUBTYPES)
    extra: list[str] = []
    for key in ("extra", "builtin"):
        # Read both lists for `extra` candidates: any config-supplied subtype that
        # is not already a builtin becomes an `extra` addition. This lets operators
        # add via either key while making builtin removal impossible.
        candidates = block.get(key)
        if not isinstance(candidates, list):
            continue
        for value in candidates:
            token = str(value or "").strip().lower()
            token = re.sub(r"[^a-z0-9_]+", "", token)
            if token and token not in builtin and token not in extra:
                extra.append(token)
    return {
        "builtin": list(_OUTWARD_SHARING_BUILTIN_SUBTYPES),
        "extra": extra,
    }


def _available_language_pack_map() -> dict[str, dict[str, Any]]:
    try:
        packs = core._language._available_language_packs()
    except Exception as exc:
        core.logger.warning("%s: failed to inspect language packs: %s", core._PLUGIN_NAME, exc)
        packs = [{"id": "en", "name": "English", "default_enabled": True, "required": True}]
    return {str(pack.get("id") or ""): pack for pack in packs if pack.get("id")}


def _normalize_language_pack_ids(raw: Any = None) -> list[str]:
    available = _available_language_pack_map()
    if raw is None:
        normalized = list(core._language._enabled_pack_ids())
    elif isinstance(raw, list):
        normalized = list(core._language._enabled_pack_ids(",".join(str(item) for item in raw)))
    else:
        normalized = list(core._language._enabled_pack_ids(str(raw or "")))
    selected: set[str] = {pack_id for pack_id in normalized if pack_id in available}
    if "en" in available:
        selected.add("en")
    # Emit in a CANONICAL order (the available-pack definition order, `en` first) so the
    # result is independent of the input order. This keeps the internal structure stable
    # across a v4 round-trip, where `sort_keys=True` serialization reorders the on-disk
    # toggle map and would otherwise leak an alphabetical ordering back into `enabled`.
    ordered = (["en"] if "en" in selected else []) + [
        pack_id for pack_id in available if pack_id != "en" and pack_id in selected
    ]
    return ordered or ["en"]


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
    applied_ids = tuple(getattr(core._security._COMPILED_LANGUAGE_PACKS, "ids", ()))
    if ids == _LANGUAGE_PACK_APPLIED_IDS and ids == applied_ids:
        core._PRIVATE_FIELD_RE = core._security._PRIVATE_FIELD_RE
        core._LANGUAGE_PACKS = core._security._COMPILED_LANGUAGE_PACKS
        return
    try:
        core._security._set_enabled_language_packs(",".join(ids))
        core._PRIVATE_FIELD_RE = core._security._PRIVATE_FIELD_RE
        core._LANGUAGE_PACKS = core._security._COMPILED_LANGUAGE_PACKS
        _LANGUAGE_PACK_APPLIED_IDS = ids
    except Exception as exc:
        core.logger.warning("%s: failed to apply language packs %s: %s", core._PLUGIN_NAME, ",".join(ids), exc)


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
    if "expires_at" not in rule and "expires" not in rule:
        try:
            legacy_remaining = int(rule.get("remaining_invocations", -1))
        except (TypeError, ValueError):
            legacy_remaining = -1
        if legacy_remaining >= 0:
            return None
    expires_at = _normalize_rule_expires_at(rule.get("expires_at", rule.get("expires", 0)))
    normalized = {
        "id": rule_id,
        "effect": effect,
        "enabled": bool(rule.get("enabled", True)),
        "match": {
            "tool_name": str(match.get("tool_name") or "*").strip() or "*",
            "action_family": str(match.get("action_family") or "*").strip().lower() or "*",
            "destination": str(match.get("destination") or "*").strip().lower() or "*",
            "purpose": tool_policy._normalize_rule_purpose(match.get("purpose", "*")),
            "recipient_identity": tool_policy._normalize_rule_recipient_identity(
                match.get("recipient_identity", match.get("recipient", "*"))
            ),
            "data_classes": _normalize_rule_classes(match.get("data_classes", ["*"])) or ["*"],
        },
        "scope": {
            "owner_hash": str(scope.get("owner_hash") or rule.get("owner_hash") or "*").strip() or "*",
            "cron_job_id": str(scope.get("cron_job_id") or rule.get("cron_job_id") or "").strip(),
            "cron_job_name": str(scope.get("cron_job_name") or rule.get("cron_job_name") or "").strip(),
        },
        "expires_at": expires_at,
        "created_at": int(float(rule.get("created_at") or 0)),
    }
    return normalized


# --- v4 IA schema (refactor doc 04) ------------------------------------------
# The ON-DISK policy file is organized into the IA concepts, in `decide` order:
# `whats_yours`, `reading`, `sharing`, `protection`, plus `version`/meta.
# (Activity has no configuration.) The loader parses these blocks DIRECTLY into
# the unchanged internal in-memory structure the engine already consumes — only
# this parsing front-end is aware of the file shape. There is no back-compat:
# old-shape files are not migrated; they surface as the normal fail-closed path.
#
# The conceptual correspondence (doc 04 §3), file block -> internal key:
#   whats_yours.stores/.identities/.hosts -> self.destinations/.identities/.hosts
#   reading.taint_classification          -> privacy.taint_classification
#   reading.llm_source_classification     -> privacy.llm_source_classification
#   reading.tools                         -> privacy.reading_tools
#   sharing.trusted_recipients            -> trusted_recipients.entries
#   sharing.rules                         -> privacy.rules
#   sharing.tools                         -> privacy.sharing_tools
#   sharing.outward.extra                 -> outward_sharing.extra (builtin code-owned)
#   sharing.egress_safety/.owner_context/.cron_context/.verifier_model
#                                         -> privacy.egress_safety/.llm_user_context/...
#   protection.security                   -> security.rules
#   protection.language_packs             -> language_packs.enabled
#   protection.retention                  -> retention
#   protection.runtime                    -> dashboard
#
# The model-override grant lives host-side in config.yaml, not in this document.
# The loader never branches on `version`.
_V4_TOP_LEVEL_BLOCKS = ("whats_yours", "reading", "sharing", "protection")


def _looks_like_v4_config(parsed: Any) -> bool:
    """True iff ``parsed`` is recognizably a v4 IA document.

    A wholly empty object is treated as v4 (every block fills from safe defaults).
    A document carrying ONLY old-shape top-level keys (``privacy`` / ``self`` /
    ``trusted_recipients`` / ``outward_sharing`` / ``language_packs`` / ``retention`` /
    ``dashboard`` and no v4 block) is an old-shape file and is rejected so it fails
    closed to strict rather than silently half-loading. ``version``/``security`` are
    ambiguous (present in both), so they don't count toward recognition.
    """
    if not isinstance(parsed, dict):
        return False
    if any(block in parsed for block in _V4_TOP_LEVEL_BLOCKS):
        return True
    legacy_keys = (
        "privacy",
        "self",
        "trusted_recipients",
        "outward_sharing",
        "language_packs",
        "retention",
        "dashboard",
    )
    if any(key in parsed for key in legacy_keys):
        return False
    # No v4 blocks and no old-shape keys: an empty/meta-only object. Treat as v4 so
    # the safe defaults seed every block (a bare `{"version": 4}` is a valid file).
    return True


def _v4_whats_yours_to_self(raw: Any) -> dict[str, Any]:
    """Parse the v4 ``whats_yours`` block into the internal ``self`` structure.

    `stores` maps to the internal `destinations` allowlist; `identities`/`hosts`
    pass through. Reuses `_normalize_self_config` so the same fail-closed / safe-seed
    semantics apply (a non-dict or missing block -> default stores + empty id/hosts).
    """
    block = raw if isinstance(raw, dict) else {}
    return _normalize_self_config(
        {
            "destinations": block.get("stores"),
            "identities": block.get("identities"),
            "hosts": block.get("hosts"),
        }
        if isinstance(raw, dict)
        else raw
    )


def _v4_sharing_rules(raw: Any) -> list[dict[str, Any]]:
    """Parse the v4 ``sharing.rules`` list into internal privacy rules, fail closed.

    A malformed (non-list) ``sharing.rules`` drops to an empty rule list (doc 04 §5.3);
    individual malformed entries are dropped by `_normalize_privacy_rule`.
    """
    items = raw if isinstance(raw, list) else []
    out: list[dict[str, Any]] = []
    for entry in items:
        normalized = _normalize_privacy_rule(entry)
        if normalized is not None:
            out.append(normalized)
    return out


def _v4_outward_extra(raw: Any) -> dict[str, Any]:
    """Parse the v4 ``sharing.outward`` block; builtin subtypes stay code-owned.

    Only ``extra`` is honored as an ADD; the builtin set is never narrowable and is
    never read from config (doc 04 §3/§5.5). `_normalize_outward_sharing` enforces
    both — an operator-supplied ``builtin`` only contributes non-builtin additions.
    """
    block = raw if isinstance(raw, dict) else {}
    return _normalize_outward_sharing({"extra": block.get("extra"), "builtin": block.get("builtin")})


def _v4_protection_security_to_rules(raw: Any) -> list[dict[str, Any]]:
    """Parse the v4 ``protection.security`` toggle MAP into internal rule entries.

    The v4 shape is ``{rule_id: bool, ...}`` (doc 04 §2). A list of ``{id, enabled}``
    objects is also accepted (the internal shape) so a round-tripped document still
    loads. Unknown ids are dropped; missing ids default to their safe default-enabled.
    """
    if isinstance(raw, dict):
        rules = [{"id": rid, "enabled": enabled} for rid, enabled in raw.items()]
    elif isinstance(raw, list):
        rules = raw
    else:
        rules = []
    return _normalize_security_rules(rules)


def _v4_protection_language_packs(raw: Any) -> dict[str, Any]:
    """Parse the v4 ``protection.language_packs`` toggle MAP into the internal block.

    The v4 shape is ``{pack_id: bool, ...}`` (doc 04 §2): a pack is enabled iff its
    value is truthy. English is always kept available. An ``{"enabled": [...]}`` list
    (the internal shape) is also accepted for round-trip stability.
    """
    if isinstance(raw, dict) and "enabled" in raw:
        return _normalize_language_pack_config(raw)
    if isinstance(raw, dict):
        enabled = [pack_id for pack_id, on in raw.items() if _config_bool(on, default=False)]
        return _normalize_language_pack_config({"enabled": enabled})
    return _default_language_pack_config()


def _normalize_privacy_config(parsed: Any) -> dict[str, Any]:
    """Parse the on-disk v4 IA schema into the internal engine structure.

    The internal structure is byte-for-byte the same one the engine consumed before
    the reshape — only the parsing of the file changed. An object that is not a
    recognizable v4 document (e.g. an old-shape file) raises ``ValueError`` so the
    caller fails closed to strict with a clear log line, rather than half-loading.
    """
    if not _looks_like_v4_config(parsed):
        raise ValueError(
            "unrecognized config shape — re-author per the v4 schema "
            "(whats_yours / reading / sharing / protection)"
        )
    whats_yours = parsed.get("whats_yours")
    reading = parsed.get("reading") if isinstance(parsed.get("reading"), dict) else {}
    sharing = parsed.get("sharing") if isinstance(parsed.get("sharing"), dict) else {}
    protection = parsed.get("protection") if isinstance(parsed.get("protection"), dict) else {}
    return {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            # 3 — SHARING: case-by-case egress judgment (decide step 6).
            "egress_safety": _normalize_egress_safety(sharing.get("egress_safety")),
            # 2.5 — READING: source/sink fallback classification.
            "taint_classification": _normalize_taint_classification(
                reading.get("taint_classification")
            ),
            "llm_source_classification": _config_bool(
                reading.get("llm_source_classification"),
                default=_DEFAULT_LLM_SOURCE_CLASSIFICATION,
            ),
            "llm_user_context": _config_bool(
                sharing.get("owner_context"), default=_DEFAULT_LLM_USER_CONTEXT
            ),
            "llm_cron_context": _config_bool(
                sharing.get("cron_context"), default=_DEFAULT_LLM_CRON_CONTEXT
            ),
            "llm_verifier_model": _normalize_verifier_model(sharing.get("verifier_model")),
            # 3 — SHARING: standing authorization (decide step 5).
            "rules": _v4_sharing_rules(sharing.get("rules")),
            # 2.5 — READING: source classification.
            "reading_tools": _normalize_reading_tools(reading.get("tools")),
            # 3 — SHARING: egress classification.
            "sharing_tools": _normalize_sharing_tools(sharing.get("tools")),
        },
        # 2 — WHAT'S YOURS: destination trust (decide steps 2–3).
        "self": _v4_whats_yours_to_self(whats_yours),
        # 3 — SHARING: trusted recipients + outward-sharing extras (decide step 5).
        "trusted_recipients": _normalize_trusted_recipients(
            {"entries": sharing.get("trusted_recipients")}
        ),
        "outward_sharing": _v4_outward_extra(sharing.get("outward")),
        # 5 — PROTECTION: the floor + machinery.
        "security": {
            "rules": _v4_protection_security_to_rules(protection.get("security")),
        },
        "language_packs": _v4_protection_language_packs(protection.get("language_packs")),
        "retention": _normalize_retention_config(protection.get("retention")),
        "dashboard": _normalize_dashboard_config(protection.get("runtime")),
    }


def _validate_persistent_privacy_config(parsed: Any) -> None:
    """Reject a structurally broken v4 document so the load fails closed to strict.

    Block-level malformations (e.g. a non-list ``sharing.rules``) are NOT fatal here —
    they drop to their safe default in the normalizer (doc 04 §5.3). This validator
    only rejects shapes that signal a wholly wrong document: a non-object top level, a
    non-recognizable (old-shape) file, an obsolete ``review`` block, an invalid
    ``sharing.egress_safety``, or a hard-typed ``sharing`` context flag — each of
    which must fail closed rather than half-load.
    """
    if not isinstance(parsed, dict):
        raise ValueError("privacy rule file must be a JSON object")
    if not _looks_like_v4_config(parsed):
        raise ValueError(
            "unrecognized config shape — re-author per the v4 schema "
            "(whats_yours / reading / sharing / protection)"
        )
    review = parsed.get("review")
    if review is not None:
        raise ValueError("privacy rule file has obsolete review block")
    for block_name in ("reading", "sharing", "protection"):
        block = parsed.get(block_name)
        if block is not None and not isinstance(block, dict):
            raise ValueError(f"privacy rule file {block_name} must be an object")
    reading = parsed.get("reading")
    if isinstance(reading, dict):
        if "llm_source_classification" in reading and not isinstance(
            reading.get("llm_source_classification"), (bool, int, str)
        ):
            raise ValueError("privacy rule file has invalid reading.llm_source_classification")
        for index, entry in enumerate(reading.get("tools") or []):
            if isinstance(entry, dict):
                for mixed_key in ("egress", "destination", "direction"):
                    if mixed_key in entry:
                        raise ValueError(f"privacy rule file has invalid reading.tools[{index}].{mixed_key}")
    sharing = parsed.get("sharing")
    if isinstance(sharing, dict):
        if "egress_safety" in sharing:
            raw_mode = str(sharing.get("egress_safety") or "").strip().lower().replace("_", "-")
            if raw_mode not in _EGRESS_SAFETY_MODES:
                raise ValueError("privacy rule file has invalid sharing.egress_safety")
        for context_key in ("owner_context", "cron_context"):
            if context_key in sharing and not isinstance(sharing.get(context_key), (bool, int, str)):
                raise ValueError(f"privacy rule file has invalid sharing.{context_key}")
        if "verifier_model" in sharing and not isinstance(sharing.get("verifier_model"), str):
            raise ValueError("privacy rule file has invalid sharing.verifier_model")
        for index, entry in enumerate(sharing.get("tools") or []):
            if isinstance(entry, dict):
                for mixed_key in ("taints", "taint", "source", "direction"):
                    if mixed_key in entry:
                        raise ValueError(f"privacy rule file has invalid sharing.tools[{index}].{mixed_key}")
    protection = parsed.get("protection")
    if isinstance(protection, dict):
        for obsolete_key in ("unknown_tools", "taint_classification", "tools"):
            if obsolete_key in protection:
                raise ValueError(f"privacy rule file has obsolete protection.{obsolete_key}")


def _load_privacy_config() -> dict[str, Any]:
    with state._LOCK:
        try:
            current_mtime = state._PERSISTENT_RULES_PATH.stat().st_mtime if state._PERSISTENT_RULES_PATH.exists() else None
        except Exception:
            current_mtime = None
        if (
            state._PERSISTENT_RULES_CACHE is not None
            and state._PERSISTENT_RULES_MTIME == current_mtime
            and isinstance(state._PERSISTENT_RULES_CACHE.get("privacy"), dict)
        ):
            _apply_language_pack_config(state._PERSISTENT_RULES_CACHE)
            return state._PERSISTENT_RULES_CACHE
        try:
            if not state._PERSISTENT_RULES_PATH.exists():
                state._PERSISTENT_RULES_CACHE = _default_privacy_config()
                state._PERSISTENT_RULES_MTIME = None
            else:
                parsed = json.loads(state._PERSISTENT_RULES_PATH.read_text())
                _validate_persistent_privacy_config(parsed)
                state._PERSISTENT_RULES_CACHE = _normalize_privacy_config(parsed)
                state._PERSISTENT_RULES_MTIME = current_mtime
            state._PERSISTENT_RULES_ERROR = False
        except Exception as exc:
            core.logger.warning("%s: failed to load privacy rules: %s", core._PLUGIN_NAME, exc)
            state._PERSISTENT_RULES_CACHE = _strict_privacy_config()
            state._PERSISTENT_RULES_MTIME = None
            state._PERSISTENT_RULES_ERROR = True
        _apply_language_pack_config(state._PERSISTENT_RULES_CACHE)
        return state._PERSISTENT_RULES_CACHE


def _normalize_internal_config(data: Any) -> dict[str, Any]:
    """Normalize the INTERNAL (engine-facing) config structure in place.

    The mutators (`_config_for_save` + the per-block setters) operate on the internal
    structure, not on the on-disk v4 file. This re-normalizes that internal structure so
    a save is always clean and idempotent, independent of the on-disk schema. The result
    is the same internal shape the loader produces; `_serialize_config_to_v4` then encodes
    it to the v4 file. (Splitting this from `_normalize_privacy_config`, which parses the
    v4 file, is what lets docs 02/03's mutators stay config-shape-agnostic — doc 04 §4.)
    """
    default = _default_privacy_config()
    if not isinstance(data, dict):
        return default
    privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
    security = data.get("security") if isinstance(data.get("security"), dict) else {}
    language_packs = data.get("language_packs") if isinstance(data.get("language_packs"), dict) else {}
    normalized_rules = [
        normalized
        for normalized in (_normalize_privacy_rule(rule) for rule in privacy.get("rules", []))
        if normalized is not None
    ]
    return {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "egress_safety": _normalize_egress_safety(privacy.get("egress_safety")),
            "taint_classification": _normalize_taint_classification(
                privacy.get("taint_classification")
            ),
            "llm_source_classification": _config_bool(
                privacy.get("llm_source_classification"),
                default=_DEFAULT_LLM_SOURCE_CLASSIFICATION,
            ),
            "llm_user_context": _config_bool(
                privacy.get("llm_user_context"), default=_DEFAULT_LLM_USER_CONTEXT
            ),
            "llm_cron_context": _config_bool(
                privacy.get("llm_cron_context"), default=_DEFAULT_LLM_CRON_CONTEXT
            ),
            "llm_verifier_model": _normalize_verifier_model(privacy.get("llm_verifier_model")),
            "rules": normalized_rules,
            "reading_tools": _normalize_reading_tools(privacy.get("reading_tools")),
            "sharing_tools": _normalize_sharing_tools(privacy.get("sharing_tools")),
        },
        "self": _normalize_self_config(data.get("self")),
        "trusted_recipients": _normalize_trusted_recipients(data.get("trusted_recipients")),
        "outward_sharing": _normalize_outward_sharing(data.get("outward_sharing")),
        "security": {"rules": _normalize_security_rules(security.get("rules"))},
        "language_packs": _normalize_language_pack_config(language_packs),
        "retention": _normalize_retention_config(data.get("retention")),
        "dashboard": _normalize_dashboard_config(data.get("dashboard")),
    }


def _serialize_config_to_v4(internal: dict[str, Any]) -> dict[str, Any]:
    """Encode the internal engine structure to the on-disk v4 IA schema.

    The inverse of `_normalize_privacy_config`'s parse: the IA blocks in `decide`
    order. Security/language-pack toggles are written as the v4 ``{id: bool}`` maps;
    outward-sharing writes only the operator ``extra`` additions (builtin is code-owned
    and never serialized). Round-tripping load->serialize->load is the internal-identity
    floor (doc 04 §5.6).
    """
    privacy = internal.get("privacy") if isinstance(internal.get("privacy"), dict) else {}
    self_block = internal.get("self") if isinstance(internal.get("self"), dict) else {}
    trusted = internal.get("trusted_recipients") if isinstance(internal.get("trusted_recipients"), dict) else {}
    outward = internal.get("outward_sharing") if isinstance(internal.get("outward_sharing"), dict) else {}
    security_rules = (internal.get("security") or {}).get("rules") or []
    lang = (internal.get("language_packs") or {}).get("enabled") or []
    retention = internal.get("retention") if isinstance(internal.get("retention"), dict) else {}
    dashboard = internal.get("dashboard") if isinstance(internal.get("dashboard"), dict) else {}
    available_packs = _available_language_pack_map()
    enabled_packs = set(lang)
    # Serialize the toggle map enabled-first, in the internal `enabled` order, so a
    # load->serialize->load round-trip preserves order (JSON object keys are ordered;
    # the v4 parser rebuilds `enabled` from this iteration order). Doc 04 §5.6 floor.
    ordered_pack_ids = [pack_id for pack_id in lang if pack_id in available_packs]
    ordered_pack_ids += [pack_id for pack_id in available_packs if pack_id not in enabled_packs]
    return {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "whats_yours": {
            "stores": list(self_block.get("destinations") or []),
            "identities": list(self_block.get("identities") or []),
            "hosts": list(self_block.get("hosts") or []),
        },
        "reading": {
            "taint_classification": _normalize_taint_classification(
                privacy.get("taint_classification")
            ),
            "llm_source_classification": _config_bool(
                privacy.get("llm_source_classification"),
                default=_DEFAULT_LLM_SOURCE_CLASSIFICATION,
            ),
            "tools": list(privacy.get("reading_tools") or []),
        },
        "sharing": {
            "egress_safety": _normalize_egress_safety(privacy.get("egress_safety")),
            "owner_context": _config_bool(
                privacy.get("llm_user_context"), default=_DEFAULT_LLM_USER_CONTEXT
            ),
            "cron_context": _config_bool(
                privacy.get("llm_cron_context"), default=_DEFAULT_LLM_CRON_CONTEXT
            ),
            "verifier_model": _normalize_verifier_model(privacy.get("llm_verifier_model")),
            "trusted_recipients": [
                {
                    "kind": str(entry.get("kind") or "identity"),
                    "value": str(entry.get("value") or entry.get("identity") or ""),
                    "classes": list(entry.get("classes") or ["*"]),
                    "note": str(entry.get("note") or ""),
                }
                for entry in (trusted.get("entries") or [])
                if isinstance(entry, dict)
            ],
            "rules": list(privacy.get("rules") or []),
            "tools": list(privacy.get("sharing_tools") or []),
            "outward": {"extra": list(outward.get("extra") or [])},
        },
        "protection": {
            "security": {
                str(rule.get("id")): bool(rule.get("enabled", True))
                for rule in security_rules
                if isinstance(rule, dict) and rule.get("id")
            },
            "language_packs": {pack_id: (pack_id in enabled_packs) for pack_id in ordered_pack_ids},
            "retention": {
                "max_rows": int(retention.get("max_rows", _DEFAULT_RETENTION_MAX_ROWS)),
                "max_age_days": int(retention.get("max_age_days", _DEFAULT_RETENTION_MAX_AGE_DAYS)),
            },
            "runtime": {
                "dashboard_mutations": str(dashboard.get("mutations") or _DEFAULT_DASHBOARD_MUTATIONS),
                "admin_token_env": str(
                    dashboard.get("admin_token_env") or _DEFAULT_DASHBOARD_ADMIN_TOKEN_ENV
                ),
                "persist_prompts": _config_bool(
                    dashboard.get("persist_prompts"), default=_DEFAULT_PERSIST_PROMPTS
                ),
            },
        },
    }


def _save_privacy_config(data: dict[str, Any]) -> bool:
    normalized = _normalize_internal_config(data)
    on_disk = _serialize_config_to_v4(normalized)
    with state._LOCK:
        try:
            tmp = state._PERSISTENT_RULES_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(on_disk, indent=2, sort_keys=True) + "\n")
            tmp.replace(state._PERSISTENT_RULES_PATH)
            state._PERSISTENT_RULES_CACHE = normalized
            _apply_language_pack_config(state._PERSISTENT_RULES_CACHE)
            try:
                state._PERSISTENT_RULES_MTIME = state._PERSISTENT_RULES_PATH.stat().st_mtime
            except Exception:
                state._PERSISTENT_RULES_MTIME = None
            state._PERSISTENT_RULES_ERROR = False
            return True
        except Exception as exc:
            core.logger.warning("%s: failed to save privacy rules: %s", core._PLUGIN_NAME, exc)
            state._PERSISTENT_RULES_ERROR = True
            return False


def _config_for_save(data: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Rebuild the full config dict for a save, preserving EVERY block.

    Rule-mutation helpers preserve operator-customized ``self``,
    ``trusted_recipients``, ``outward_sharing``, ``retention``, and ``dashboard``
    blocks by round-tripping all blocks through every mutation. This helper starts
    from the loaded config and applies only the block(s) the caller is changing. Each
    mutation helper passes the one or two blocks it touches as ``overrides``; the rest
    survive verbatim (re-normalized on save, which is idempotent for an already-valid
    block).
    """
    base = data if isinstance(data, dict) else {}
    out: dict[str, Any] = {
        "version": _PRIVACY_RULE_FILE_VERSION,
        "privacy": dict(base.get("privacy") or {}),
        "self": _normalize_self_config(base.get("self")),
        "trusted_recipients": _normalize_trusted_recipients(base.get("trusted_recipients")),
        "outward_sharing": _normalize_outward_sharing(base.get("outward_sharing")),
        "security": dict(base.get("security") or {}),
        "language_packs": dict(base.get("language_packs") or {}),
        "retention": _normalize_retention_config(base.get("retention")),
        "dashboard": _normalize_dashboard_config(base.get("dashboard")),
    }
    out.update(overrides)
    return out


def _egress_safety_mode() -> str:
    return _normalize_egress_safety(
        _load_privacy_config().get("privacy", {}).get("egress_safety")
    )


def _set_egress_safety_mode(mode: str) -> tuple[bool, str]:
    normalized = _normalize_egress_safety(mode)
    if normalized != str(mode or "").strip().lower().replace("_", "-"):
        return False, "Egress Safety must be one of: strict, read-only, llm, off."
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["egress_safety"] = normalized
    if not _save_privacy_config(_config_for_save(data, privacy=privacy)):
        return False, "Failed to save Egress Safety; Guardian remains unchanged."
    return True, f"Egress Safety set to {normalized}."


def _persistent_privacy_rules() -> list[dict[str, Any]]:
    rules = list(_load_privacy_config().get("privacy", {}).get("rules", []))
    active = [rule for rule in rules if not _rule_is_expired(rule)]
    if len(active) != len(rules):
        try:
            _save_persistent_privacy_rules(active)
        except Exception as exc:
            core.logger.debug("%s: failed to prune expired privacy rules: %s", core._PLUGIN_NAME, exc)
    return active


def _save_persistent_privacy_rules(rules: list[dict[str, Any]]) -> bool:
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["egress_safety"] = _egress_safety_mode()
    privacy["rules"] = rules
    return _save_privacy_config(_config_for_save(data, privacy=privacy))


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
    next_data = _config_for_save(data, security={"rules": security_rules})
    if not _save_privacy_config(next_data):
        return False, "Failed to save security rule; Guardian remains unchanged."
    label = _SECURITY_RULE_DEFINITIONS[normalized_id]["label"]
    return True, f"{'Enabled' if desired else 'Disabled'} security rule {normalized_id} ({label})."


def _taint_classification_mode() -> str:
    return _normalize_taint_classification(
        _load_privacy_config().get("privacy", {}).get("taint_classification")
    )


def _set_taint_classification_mode(mode: str) -> tuple[bool, str]:
    requested = str(mode or "").strip().lower().replace("_", "-")
    normalized = _normalize_taint_classification(requested)
    if requested not in _TAINT_CLASSIFICATION_MODES:
        return False, "Taint Classification must be one of: balanced, strict, relaxed."
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["taint_classification"] = normalized
    if not _save_privacy_config(_config_for_save(data, privacy=privacy)):
        return False, "Failed to save Taint Classification; Guardian remains unchanged."
    return True, f"Taint Classification set to {normalized}."


def _llm_source_classification_enabled() -> bool:
    return _config_bool(
        _load_privacy_config().get("privacy", {}).get("llm_source_classification"),
        default=_DEFAULT_LLM_SOURCE_CLASSIFICATION,
    )


def _set_llm_source_classification(enabled: bool) -> tuple[bool, str]:
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["llm_source_classification"] = bool(enabled)
    if not _save_privacy_config(_config_for_save(data, privacy=privacy)):
        return False, "Failed to save LLM source classification; Guardian remains unchanged."
    return True, f"LLM source classification {'enabled' if enabled else 'disabled'}."


def _llm_user_context_enabled() -> bool:
    return _config_bool(
        _load_privacy_config().get("privacy", {}).get("llm_user_context"),
        default=_DEFAULT_LLM_USER_CONTEXT,
    )


def _llm_cron_context_enabled() -> bool:
    return _config_bool(
        _load_privacy_config().get("privacy", {}).get("llm_cron_context"),
        default=_DEFAULT_LLM_CRON_CONTEXT,
    )


def _set_llm_context_flag(key: str, enabled: bool, label: str) -> tuple[bool, str]:
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy[key] = bool(enabled)
    if not _save_privacy_config(_config_for_save(data, privacy=privacy)):
        return False, f"Failed to save {label} setting; Guardian remains unchanged."
    return True, f"LLM {label} turned {'on' if enabled else 'off'}."


def _persist_prompts_enabled() -> bool:
    return _config_bool(
        _load_privacy_config().get("dashboard", {}).get("persist_prompts"),
        default=_DEFAULT_PERSIST_PROMPTS,
    )


def _set_persist_prompts(enabled: bool) -> tuple[bool, str]:
    data = _load_privacy_config()
    dashboard = dict(data.get("dashboard") or {})
    dashboard["persist_prompts"] = bool(enabled)
    if not _save_privacy_config(_config_for_save(data, dashboard=dashboard)):
        return False, "Failed to save prompt-persistence setting; Guardian remains unchanged."
    if enabled:
        return True, (
            "Prompt persistence turned on. Sanitized user/cron prompts are now written to "
            "the activity log for debugging. Turn off when done."
        )
    return True, "Prompt persistence turned off."


def _set_llm_user_context(enabled: bool) -> tuple[bool, str]:
    return _set_llm_context_flag("llm_user_context", enabled, "user-prompt context")


def _set_llm_cron_context(enabled: bool) -> tuple[bool, str]:
    return _set_llm_context_flag("llm_cron_context", enabled, "cron context")


def _llm_verifier_model() -> str:
    return _normalize_verifier_model(
        _load_privacy_config().get("privacy", {}).get("llm_verifier_model")
    )


def _set_llm_verifier_model(model: str) -> tuple[bool, str]:
    normalized = _normalize_verifier_model(model)
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["llm_verifier_model"] = normalized
    if not _save_privacy_config(_config_for_save(data, privacy=privacy)):
        return False, "Failed to save verifier model; Guardian remains unchanged."
    if normalized:
        return True, (
            f"LLM verifier model set to {normalized}. Requires "
            "plugins.entries.hermes-guardian.llm.allow_model_override in config; "
            "Guardian falls back to the default model if the override is rejected."
        )
    return True, "LLM verifier model cleared (using the Hermes default model)."


def _hermes_home_dir() -> Path:
    raw = os.environ.get("HERMES_HOME", "").strip()
    return Path(raw).expanduser() if raw else (Path.home() / ".hermes")


def _read_host_yaml_best_effort(path: Path) -> dict[str, Any]:
    """Read a host YAML file (config / model cache) defensively.

    PyYAML ships with the Hermes runtime venv but is not a hard dependency of this
    plugin, so the import and the read are both optional: any failure returns {}.
    Only model-name strings are ever extracted; the rest of the file (which may
    contain secrets) is parsed transiently and discarded, never stored or logged.
    """
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    try:
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _discover_verifier_model_options() -> list[str]:
    """Best-effort list of models the operator has made selectable for the verifier.

    Source of truth is the operator's own Hermes config: a plugin may only run on
    a model the host trust gate permits, so the dropdown mirrors exactly that. When
    `allow_model_override` is granted with a concrete `allowed_models` list, those
    are the options; with a wildcard (any model) we suggest models already seen on
    this install. Without the grant nothing is selectable (it would not take effect).
    """
    home = _hermes_home_dir()
    config = _read_host_yaml_best_effort(home / "config.yaml")
    plugin_llm = (
        (((config.get("plugins") or {}).get("entries") or {}).get(core._PLUGIN_NAME) or {}).get("llm")
        if isinstance(config, dict)
        else None
    )
    options: list[str] = []
    if isinstance(plugin_llm, dict) and _config_bool(plugin_llm.get("allow_model_override"), default=False):
        allowed = plugin_llm.get("allowed_models")
        allowed_list = allowed if isinstance(allowed, list) else ([allowed] if allowed else [])
        concrete = [str(model) for model in allowed_list if model and str(model) != "*"]
        if concrete:
            options += concrete
        else:
            default_model = str((config.get("model") or {}).get("default") or "")
            if default_model:
                options.append(default_model)
            cache = _read_host_yaml_best_effort(home / "context_length_cache.yaml")
            for key in (cache.get("context_lengths") or {}):
                options.append(str(key).split("@", 1)[0].strip())
    seen: set[str] = set()
    out: list[str] = []
    for model in options:
        normalized = _normalize_verifier_model(model)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
        if len(out) >= 40:
            break
    return out


def _verifier_model_options() -> list[str]:
    options = _discover_verifier_model_options()
    current = _llm_verifier_model()
    if current and current not in options:
        options.append(current)
    return options


def _reading_tools() -> list[dict[str, Any]]:
    return list(_load_privacy_config().get("privacy", {}).get("reading_tools", []))


def _sharing_tools() -> list[dict[str, Any]]:
    return list(_load_privacy_config().get("privacy", {}).get("sharing_tools", []))


def _reading_tools_snapshot() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for override in _reading_tools():
        out.append({
            "id": str(override.get("id") or ""),
            "match": str(override.get("match") or ""),
            "taints": sorted(override.get("taints") or []),
            "source": str(override.get("source") or ""),
            "enabled": bool(override.get("enabled", True)),
            "note": str(override.get("note") or ""),
        })
    return out


def _sharing_tools_snapshot() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for override in _sharing_tools():
        out.append({
            "id": str(override.get("id") or ""),
            "match": str(override.get("match") or ""),
            "egress": str(override.get("egress") or ""),
            "destination": str(override.get("destination") or ""),
            "enabled": bool(override.get("enabled", True)),
            "note": str(override.get("note") or ""),
        })
    return out


def _save_reading_tools(overrides: list[dict[str, Any]]) -> bool:
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["reading_tools"] = overrides
    return _save_privacy_config(_config_for_save(data, privacy=privacy))


def _save_sharing_tools(overrides: list[dict[str, Any]]) -> bool:
    data = _load_privacy_config()
    privacy = dict(data.get("privacy") or {})
    privacy["sharing_tools"] = overrides
    return _save_privacy_config(_config_for_save(data, privacy=privacy))


def _set_reading_tool(
    match: str,
    *,
    taints: Any = None,
    source: Any = None,
    note: Any = None,
    enabled: Any = None,
) -> tuple[bool, str]:
    normalized_match = _normalize_tool_match(match)
    if not normalized_match:
        return False, "Tool match must be a tool name or a prefix like mcp_acme_*."
    if source is not None:
        source_text = str(source).strip().lower()
        if source_text and source_text not in _READING_TOOL_SOURCES:
            return False, "source must be one of: reference, private, public, unknown."
    if taints is not None:
        requested = taints if isinstance(taints, list) else [taints]
        invalid = [
            str(cls).strip()
            for cls in requested
            if str(cls).strip() and str(cls).strip() not in core._ALL_PRIVACY_CLASSES
        ]
        if invalid:
            return False, "Unknown data class(es): " + ", ".join(sorted(set(invalid))) + "."
    overrides = _reading_tools()
    existing = next((o for o in overrides if o.get("match") == normalized_match), None)
    payload = dict(existing) if existing else {"match": normalized_match}
    candidate_source = str(source if source is not None else payload.get("source") or "").strip().lower()
    candidate_taints = taints if taints is not None else payload.get("taints", [])
    if candidate_source == "public":
        requested_taints = candidate_taints if isinstance(candidate_taints, list) else [candidate_taints]
        if any(str(cls).strip() for cls in requested_taints):
            return False, "source=public cannot be combined with taints."
    payload["match"] = normalized_match
    if taints is not None:
        payload["taints"] = taints
    if source is not None:
        payload["source"] = source
    if note is not None:
        payload["note"] = note
    if enabled is not None:
        payload["enabled"] = enabled
    normalized = _normalize_reading_tool(payload)
    if normalized is None:
        return False, "Invalid Reading tool classification."
    if existing:
        normalized["id"] = existing.get("id") or normalized["id"]
        overrides = [normalized if o.get("id") == existing.get("id") else o for o in overrides]
    else:
        overrides.append(normalized)
    if not _save_reading_tools(overrides):
        return False, "Failed to save Reading tool classification; Guardian remains unchanged."
    return True, f"Saved Reading tool classification {normalized['id']} for {normalized_match}."


def _set_sharing_tool(
    match: str,
    *,
    egress: Any = None,
    destination: Any = None,
    note: Any = None,
    enabled: Any = None,
) -> tuple[bool, str]:
    normalized_match = _normalize_tool_match(match)
    if not normalized_match:
        return False, "Tool match must be a tool name or a prefix like mcp_acme_*."
    if egress is not None:
        egress_text = str(egress).strip().lower()
        if egress_text and egress_text not in _SHARING_TOOL_EGRESS_VALUES:
            return False, (
                "egress must be one of: ignore, gate, or a known action family "
                f"({', '.join(sorted(_SHARING_TOOL_EGRESS_FAMILIES))})."
            )
    overrides = _sharing_tools()
    existing = next((o for o in overrides if o.get("match") == normalized_match), None)
    payload = dict(existing) if existing else {"match": normalized_match}
    payload["match"] = normalized_match
    if egress is not None:
        payload["egress"] = egress
    if destination is not None:
        payload["destination"] = destination
    if note is not None:
        payload["note"] = note
    if enabled is not None:
        payload["enabled"] = enabled
    normalized = _normalize_sharing_tool(payload)
    if normalized is None:
        return False, "Invalid Sharing tool classification."
    if existing:
        normalized["id"] = existing.get("id") or normalized["id"]
        overrides = [normalized if o.get("id") == existing.get("id") else o for o in overrides]
    else:
        overrides.append(normalized)
    if not _save_sharing_tools(overrides):
        return False, "Failed to save Sharing tool classification; Guardian remains unchanged."
    return True, f"Saved Sharing tool classification {normalized['id']} for {normalized_match}."


def _delete_reading_tool(match_or_id: str) -> tuple[bool, str]:
    target = str(match_or_id or "").strip()
    target_match = _normalize_tool_match(target)
    overrides = _reading_tools()
    remaining = [
        o
        for o in overrides
        if o.get("id") != target and o.get("match") != target_match
    ]
    if len(remaining) == len(overrides):
        return False, f"No matching Reading tool classification found for {match_or_id}."
    if not _save_reading_tools(remaining):
        return False, "Failed to save Reading tool classifications; Guardian remains unchanged."
    return True, f"Deleted Reading tool classification {match_or_id}."


def _delete_sharing_tool(match_or_id: str) -> tuple[bool, str]:
    target = str(match_or_id or "").strip()
    target_match = _normalize_tool_match(target)
    overrides = _sharing_tools()
    remaining = [
        o
        for o in overrides
        if o.get("id") != target and o.get("match") != target_match
    ]
    if len(remaining) == len(overrides):
        return False, f"No matching Sharing tool classification found for {match_or_id}."
    if not _save_sharing_tools(remaining):
        return False, "Failed to save Sharing tool classifications; Guardian remains unchanged."
    return True, f"Deleted Sharing tool classification {match_or_id}."


def _set_reading_tool_enabled(override_id: str, enabled: bool) -> tuple[bool, str]:
    target = str(override_id or "").strip()
    target_match = _normalize_tool_match(target)
    desired = _config_bool(enabled, default=True)
    overrides = _reading_tools()
    found = False
    for override in overrides:
        if override.get("id") == target or override.get("match") == target_match:
            override["enabled"] = desired
            found = True
            break
    if not found:
        return False, f"No matching Reading tool classification found for {override_id}."
    if not _save_reading_tools(overrides):
        return False, "Failed to save Reading tool classification; Guardian remains unchanged."
    return True, f"{'Enabled' if desired else 'Disabled'} Reading tool classification {target}."


def _set_sharing_tool_enabled(override_id: str, enabled: bool) -> tuple[bool, str]:
    target = str(override_id or "").strip()
    target_match = _normalize_tool_match(target)
    desired = _config_bool(enabled, default=True)
    overrides = _sharing_tools()
    found = False
    for override in overrides:
        if override.get("id") == target or override.get("match") == target_match:
            override["enabled"] = desired
            found = True
            break
    if not found:
        return False, f"No matching Sharing tool classification found for {override_id}."
    if not _save_sharing_tools(overrides):
        return False, "Failed to save Sharing tool classification; Guardian remains unchanged."
    return True, f"{'Enabled' if desired else 'Disabled'} Sharing tool classification {target}."


def _reading_tool_for(tool_name: str) -> dict[str, Any] | None:
    name = str(tool_name or "").strip().lower()
    if not name:
        return None
    best: dict[str, Any] | None = None
    best_len = -1
    for override in _reading_tools():
        if not override.get("enabled", True):
            continue
        match = str(override.get("match") or "")
        if not match:
            continue
        if match.endswith("*"):
            prefix = match[:-1]
            if name.startswith(prefix) and len(prefix) > best_len:
                best = override
                best_len = len(prefix)
        elif name == match:
            return override
    return best


def _sharing_tool_for(tool_name: str) -> dict[str, Any] | None:
    name = str(tool_name or "").strip().lower()
    if not name:
        return None
    best: dict[str, Any] | None = None
    best_len = -1
    for override in _sharing_tools():
        if not override.get("enabled", True):
            continue
        match = str(override.get("match") or "")
        if not match:
            continue
        if match.endswith("*"):
            prefix = match[:-1]
            if name.startswith(prefix) and len(prefix) > best_len:
                best = override
                best_len = len(prefix)
        elif name == match:
            return override
    return best


# --- Destination-trust config read/mutation (doc 03 §1.2, §2) ----------------
# These expose the `self` / `trusted_recipients` / `outward_sharing` blocks for the
# slash commands and dashboard. Every mutation round-trips the full config via
# _config_for_save, so an edit to one block never drops another.
_SELF_DESTINATION_KINDS = {"destination", "identity", "host"}


def _self_config_snapshot() -> dict[str, Any]:
    block = _load_privacy_config().get("self") or {}
    return {
        "destinations": list(block.get("destinations") or []),
        "identities": list(block.get("identities") or []),
        "hosts": list(block.get("hosts") or []),
    }


def _trusted_recipients_snapshot() -> list[dict[str, Any]]:
    block = _load_privacy_config().get("trusted_recipients") or {}
    entries = block.get("entries") if isinstance(block.get("entries"), list) else []
    out: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind") or "identity")
        value = str(entry.get("value") or entry.get("identity") or "")
        out.append({
            "kind": kind,
            "value": value,
            # `identity` retained so existing identity-only readers keep working.
            "identity": value if kind == "identity" else "",
            "classes": sorted(entry.get("classes") or ["*"]),
            "note": str(entry.get("note") or ""),
        })
    return out


def _outward_sharing_snapshot() -> dict[str, Any]:
    block = _load_privacy_config().get("outward_sharing") or {}
    return {
        "builtin": list(block.get("builtin") or _OUTWARD_SHARING_BUILTIN_SUBTYPES),
        "extra": list(block.get("extra") or []),
    }


def _self_grants_present() -> bool:
    """True iff the operator has granted any send-to-self identity or own-infra host.

    Drives the doc 03 §3.3 informational banner: a non-empty ``identities`` or
    ``hosts`` is a real `self` trust grant and must never be invisible.
    """
    snapshot = _self_config_snapshot()
    return bool(snapshot.get("identities") or snapshot.get("hosts"))


def _save_self_config(self_block: dict[str, Any]) -> bool:
    data = _load_privacy_config()
    return _save_privacy_config(_config_for_save(data, self=_normalize_self_config(self_block)))


def _add_self_destination(kind: str, value: str) -> tuple[bool, str]:
    normalized_kind = str(kind or "").strip().lower()
    if normalized_kind not in _SELF_DESTINATION_KINDS:
        return False, "Self kind must be one of: destination, identity, host."
    if normalized_kind == "destination":
        token = _normalize_destination_token(value)
        field = "destinations"
        if not token:
            return False, "Destination must be a kind:id token like store:crm or draft:*."
    else:
        token = _normalize_identity_token(value)
        field = "identities" if normalized_kind == "identity" else "hosts"
        if not token:
            return False, f"{normalized_kind.capitalize()} value must be a non-empty address/handle/host."
    snapshot = _self_config_snapshot()
    if token in snapshot[field]:
        return False, f"{normalized_kind} {token} is already in the self allowlist."
    snapshot[field].append(token)
    if not _save_self_config(snapshot):
        return False, "Failed to save self allowlist; Guardian remains unchanged."
    return True, f"Added {normalized_kind} {token} to the self allowlist."


def _remove_self_destination(kind: str, value: str) -> tuple[bool, str]:
    normalized_kind = str(kind or "").strip().lower()
    if normalized_kind not in _SELF_DESTINATION_KINDS:
        return False, "Self kind must be one of: destination, identity, host."
    if normalized_kind == "destination":
        token = _normalize_destination_token(value)
        field = "destinations"
    else:
        token = _normalize_identity_token(value)
        field = "identities" if normalized_kind == "identity" else "hosts"
    snapshot = _self_config_snapshot()
    if token not in snapshot[field]:
        return False, f"No {normalized_kind} {value} found in the self allowlist."
    snapshot[field] = [item for item in snapshot[field] if item != token]
    if not _save_self_config(snapshot):
        return False, "Failed to save self allowlist; Guardian remains unchanged."
    return True, f"Removed {normalized_kind} {token} from the self allowlist."


def _trusted_destination_entries_for_save() -> list[dict[str, Any]]:
    """Current entries as ``{kind, value, classes, note}`` for re-normalization."""
    return [
        {
            "kind": entry["kind"],
            "value": entry["value"],
            "classes": entry["classes"],
            "note": entry["note"],
        }
        for entry in _trusted_recipients_snapshot()
    ]


def _save_trusted_destinations(entries: list[dict[str, Any]], failure: str) -> bool:
    next_data = _config_for_save(
        _load_privacy_config(),
        trusted_recipients=_normalize_trusted_recipients({"entries": entries}),
    )
    return _save_privacy_config(next_data)


def _classes_arg_or_star(classes: Any) -> list[str]:
    if classes is None or (isinstance(classes, str) and not classes.strip()):
        return ["*"]
    return _normalize_rule_classes(classes) or ["*"]


def _add_trusted_recipient(identity: str, *, classes: Any = None, note: str = "") -> tuple[bool, str]:
    token = _normalize_identity_token(identity)
    if not token:
        return False, "Trusted destination identity must be a non-empty address/handle."
    normalized_classes = _classes_arg_or_star(classes)
    note_text = re.sub(r"\s+", " ", str(note or "")).strip()[:200]
    entries = [e for e in _trusted_destination_entries_for_save() if not (e["kind"] == "identity" and e["value"] == token)]
    entries.append({"kind": "identity", "value": token, "classes": normalized_classes, "note": note_text})
    if not _save_trusted_destinations(entries, "recipient"):
        return False, "Failed to save trusted destination; Guardian remains unchanged."
    return True, f"Added trusted destination {token} ({','.join(normalized_classes)})."


def _remove_trusted_recipient(identity: str) -> tuple[bool, str]:
    token = _normalize_identity_token(identity)
    entries = _trusted_destination_entries_for_save()
    remaining = [e for e in entries if not (e["kind"] == "identity" and e["value"] == token)]
    if len(remaining) == len(entries):
        return False, f"No trusted destination found for {identity}."
    if not _save_trusted_destinations(remaining, "recipient"):
        return False, "Failed to save trusted destination; Guardian remains unchanged."
    return True, f"Removed trusted destination {token}."


def _trusted_destination_suggestions(limit: int = 60) -> list[dict[str, Any]]:
    """Pickable trusted-command candidates: recently gated commands first (most
    contextual), then scripts discovered under the skills tree. Already-trusted
    commands are excluded."""
    trusted = {e["value"] for e in _trusted_recipients_snapshot() if e["kind"] == "command"}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in activity_store._recent_suggestions("command", limit=20):
        value = str(row.get("prefix") or "")
        if not value or value in trusted or value in seen:
            continue
        seen.add(value)
        out.append({
            "value": value,
            "label": value,
            "kind": "command",
            "wildcard": tool_policy._trusted_command_is_wildcard(value),
            "source": "recent",
        })
    for item in tool_policy._skills_command_suggestions(limit=200):
        value = str(item.get("value") or "")
        if not value or value in trusted or value in seen:
            continue
        seen.add(value)
        out.append(item)
        if len(out) >= limit:
            break
    return out[:limit]


def _source_classification_suggestions(limit: int = 40) -> list[dict[str, Any]]:
    """MCP server prefixes whose doc-reads hit the conservative source-default and are not yet
    declared (Protection "Sources seen" picker). Newest first; already-declared servers drop
    out once the operator classifies them. Server prefixes only — never content."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in activity_store._recent_suggestions("source", limit=max(1, min(int(limit or 40), 100))):
        server = str(row.get("prefix") or "")
        if not server or server in seen:
            continue
        seen.add(server)
        # A declaration scopes the whole server via a prefix match; a representative read tool
        # resolves it. Already-classified servers no longer need a suggestion.
        if tool_policy._reading_tool_source(f"{server}_read_resource"):
            continue
        out.append({
            "server": server,
            "last_ts": int(row.get("last_ts") or 0),
            "hits": int(row.get("hits") or 0),
        })
        if len(out) >= limit:
            break
    return out


def _set_source_classification(server: str, mode: str) -> tuple[bool, str]:
    """Declare an MCP server's doc-reads from the picker — a
    prefix-scoped Reading tool classification (``<server>_*``). Mirrors the
    trusted-destination picker flow."""
    name = re.sub(r"[^a-z0-9_]+", "_", str(server or "").strip().lower()).strip("_")
    if not name:
        return False, "Provide an MCP server prefix (e.g. crm)."
    if str(mode or "").strip().lower() not in _READING_TOOL_SOURCES:
        return False, "Mode must be one of: reference, private, public, unknown."
    return _set_reading_tool(f"{name}_*", source=str(mode).strip().lower())


def _add_trusted_command(command: str, *, classes: Any = None, note: str = "") -> tuple[bool, str]:
    token = tool_policy._normalize_trusted_command(command)
    if not token:
        return False, "Trusted command must be non-empty and free of shell metacharacters (; | & > < ` $())."
    if tool_policy._trusted_command_is_wildcard(token) and not tool_policy._trusted_command_wildcard_under_skills(token):
        return False, "A wildcard trusted command must resolve under the Hermes skills directory."
    normalized_classes = _classes_arg_or_star(classes)
    note_text = re.sub(r"\s+", " ", str(note or "")).strip()[:200]
    entries = [e for e in _trusted_destination_entries_for_save() if not (e["kind"] == "command" and e["value"] == token)]
    entries.append({"kind": "command", "value": token, "classes": normalized_classes, "note": note_text})
    if not _save_trusted_destinations(entries, "command"):
        return False, "Failed to save trusted command; Guardian remains unchanged."
    return True, f"Added trusted command ({','.join(normalized_classes)})."


def _remove_trusted_command(command: str) -> tuple[bool, str]:
    token = tool_policy._normalize_trusted_command(command)
    entries = _trusted_destination_entries_for_save()
    remaining = [e for e in entries if not (e["kind"] == "command" and e["value"] == token)]
    if len(remaining) == len(entries):
        return False, "No trusted command found for that value."
    if not _save_trusted_destinations(remaining, "command"):
        return False, "Failed to save trusted command; Guardian remains unchanged."
    return True, "Removed trusted command."


def _add_outward_sharing_subtype(subtype: str) -> tuple[bool, str]:
    token = re.sub(r"[^a-z0-9_]+", "", str(subtype or "").strip().lower())
    if not token:
        return False, "Sharing subtype must be a non-empty token like share or invite."
    if token in set(_OUTWARD_SHARING_BUILTIN_SUBTYPES):
        return False, f"{token} is a builtin outward-sharing subtype (already enforced)."
    snapshot = _outward_sharing_snapshot()
    if token in snapshot["extra"]:
        return False, f"Outward-sharing subtype {token} is already configured."
    snapshot["extra"].append(token)
    data = _load_privacy_config()
    next_data = _config_for_save(data, outward_sharing=_normalize_outward_sharing(snapshot))
    if not _save_privacy_config(next_data):
        return False, "Failed to save outward-sharing subtype; Guardian remains unchanged."
    return True, f"Added outward-sharing subtype {token}."


def _remove_outward_sharing_subtype(subtype: str) -> tuple[bool, str]:
    token = re.sub(r"[^a-z0-9_]+", "", str(subtype or "").strip().lower())
    if token in set(_OUTWARD_SHARING_BUILTIN_SUBTYPES):
        return False, f"{token} is a builtin outward-sharing subtype and cannot be removed."
    snapshot = _outward_sharing_snapshot()
    if token not in snapshot["extra"]:
        return False, f"No extra outward-sharing subtype {subtype} found."
    snapshot["extra"] = [item for item in snapshot["extra"] if item != token]
    data = _load_privacy_config()
    next_data = _config_for_save(data, outward_sharing=_normalize_outward_sharing(snapshot))
    if not _save_privacy_config(next_data):
        return False, "Failed to save outward-sharing subtype; Guardian remains unchanged."
    return True, f"Removed outward-sharing subtype {token}."


# --- Retention / dashboard settings with env overrides (doc 03 §1.2) ----------
def _retention_setting(key: str, env_var: str, default: int) -> tuple[int, bool]:
    """Effective retention value + whether an env var overrides the document.

    The document is the source of truth, but the env var still overrides for ops; the
    boolean lets `/guardian status` surface the override so it is never invisible.
    """
    block = _load_privacy_config().get("retention") or {}
    try:
        doc_value = max(0, int(block.get(key, default)))
    except (TypeError, ValueError):
        doc_value = default
    raw = os.environ.get(env_var)
    if raw is not None and str(raw).strip() != "":
        try:
            return max(0, int(str(raw).strip())), True
        except ValueError:
            return doc_value, False
    return doc_value, False


def _dashboard_setting(key: str, env_var: str, default: str) -> tuple[str, bool]:
    block = _load_privacy_config().get("dashboard") or {}
    doc_value = str(block.get(key) or default)
    raw = os.environ.get(env_var)
    if raw is not None and str(raw).strip() != "":
        return str(raw).strip(), True
    return doc_value, False


def _active_env_overrides() -> list[str]:
    """Labels for env vars currently overriding named config (doc 03 §1.2, §2).

    Surfaced in `/guardian status` so an operator can see which posture knobs are being
    driven by the environment rather than the policy document.
    """
    overrides: list[str] = []
    for key, env_var in _RETENTION_ENV_OVERRIDES:
        if str(os.environ.get(env_var) or "").strip():
            overrides.append(f"retention.{key} <- {env_var}={os.environ.get(env_var).strip()}")
    for env_var in (
        "HERMES_GUARDIAN_DASHBOARD_MUTATIONS",
        "HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS",
        "HERMES_GUARDIAN_CRON_NOTIFY_TO",
    ):
        if str(os.environ.get(env_var) or "").strip():
            overrides.append(f"{env_var}={os.environ.get(env_var).strip()}")
    return overrides


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
    next_data = _config_for_save(data, language_packs={"enabled": ids})
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
    cron_job_id = str(scope.get("cron_job_id") or "")
    return (
        (owner_hash == "*" or owner_hash == shape.get("owner_hash"))
        and (not cron_job_id or cron_job_id == cron_notifications._cron_job_id_from_session(shape.get("session_id")))
    )


def _value_matches(rule_value: Any, actual: Any) -> bool:
    text = str(rule_value or "*").strip().lower()
    return text == "*" or text == str(actual or "").strip().lower()


def _destination_matches(rule_value: Any, shape: dict[str, Any]) -> bool:
    if _value_matches(rule_value, shape.get("destination")):
        return True
    if str(shape.get("action_family") or "") != "message_send":
        return False
    return _value_matches(rule_value, shape.get("legacy_destination"))


def _rule_matches(rule: dict[str, Any], shape: dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False
    if _rule_is_expired(rule):
        return False
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    if not _scope_matches(rule.get("scope") if isinstance(rule.get("scope"), dict) else {}, shape):
        return False
    if not _value_matches(match.get("tool_name", "*"), shape.get("tool_name")):
        return False
    if not _value_matches(match.get("action_family", "*"), shape.get("action_family")):
        return False
    if not _destination_matches(match.get("destination", "*"), shape):
        return False
    if not _value_matches(match.get("purpose", "*"), shape.get("purpose", "unknown")):
        return False
    if not _value_matches(match.get("recipient_identity", "*"), shape.get("recipient_identity", "none")):
        return False
    current_classes = set(shape.get("data_classes") or [])
    rule_classes = set(match.get("data_classes") or ["*"])
    if rule.get("effect") == "deny":
        return "*" in rule_classes or not rule_classes or bool(current_classes & rule_classes) or not current_classes
    return _classes_are_covered(current_classes, rule_classes)


def _rule_source_payload(rule: dict[str, Any], source: str) -> dict[str, str]:
    return {
        "source": source,
        "rule_id": str(rule.get("id") or ""),
        "effect": str(rule.get("effect") or "allow"),
    }


def _approval_source(shape: dict[str, Any]) -> dict[str, str] | None:
    with state._LOCK:
        llm._prune_expired()
        persistent_rules = _persistent_privacy_rules()
        for rule in list(persistent_rules):
            if not _rule_matches(rule, shape):
                continue
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
        if owner_hash == core._CLI_OWNER_HASH or rule_owner in {"*", owner_hash}:
            rules.append(rule)
    return rules
