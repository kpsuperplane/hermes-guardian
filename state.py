"""Mutable process state, state-dir paths, and clock/env helpers.

This module owns every piece of mutable runtime state for the plugin, the
resolved on-disk state-dir paths, and the small clock/env helpers. It is a
self-contained, normally-importable module: `core.py` loads it as the `state`
submodule of the plugin package and every other module imports it directly, so
they reference these names as `state.<name>`.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PLUGIN_NAME = "hermes-guardian"
_PLUGIN_ROOT = Path(__file__).parent

# Persistent state (activity DB, allow rules, HMAC key, diagnostics flag) lives
# next to the plugin code by default. Set HERMES_GUARDIAN_STATE_DIR to point every
# runtime context (gateway, CLI, cron) at one shared directory; legacy co-located
# files are migrated into it on first use so the dashboard never loses history or
# the operator's saved allow rules.
_STATE_FILENAMES = ("guardian-rules.json", "activity.sqlite3", ".guardian-hmac-key", ".unsafe-diagnostics")


def _migrate_legacy_state(legacy_dir: Path, state_dir: Path) -> None:
    if legacy_dir == state_dir:
        return
    for name in _STATE_FILENAMES:
        src = legacy_dir / name
        dst = state_dir / name
        if not src.exists() or dst.exists():
            continue
        tmp = dst.with_name(dst.name + ".migrating.tmp")
        tmp.write_bytes(src.read_bytes())
        if name == ".guardian-hmac-key":
            try:
                tmp.chmod(0o600)
            except OSError:
                pass
        os.replace(tmp, dst)


def _resolve_state_dir() -> Path:
    override = os.environ.get("HERMES_GUARDIAN_STATE_DIR", "").strip()
    if not override:
        return _PLUGIN_ROOT
    state_dir = Path(override).expanduser()
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        _migrate_legacy_state(_PLUGIN_ROOT, state_dir)
    except Exception as exc:
        logger.warning(
            "%s: state dir %s unusable (%s); falling back to plugin dir",
            _PLUGIN_NAME, state_dir, exc,
        )
        return _PLUGIN_ROOT
    return state_dir


_STATE_DIR = _resolve_state_dir()
_UNSAFE_DIAGNOSTICS_FLAG = _STATE_DIR / ".unsafe-diagnostics"
_PERSISTENT_RULES_PATH = _STATE_DIR / "guardian-rules.json"
_PERSISTENT_RULES_MTIME: float | None = None
_ACTIVITY_DB_PATH = _STATE_DIR / "activity.sqlite3"
_GUARDIAN_HMAC_KEY_PATH = _STATE_DIR / ".guardian-hmac-key"

_LOCK = threading.RLock()
_SESSIONS: dict[str, dict[str, Any]] = {}
_OWNER_SESSIONS: dict[str, set[str]] = {}
_PENDING_APPROVALS: dict[str, dict[str, Any]] = {}
_ONCE_APPROVALS: dict[str, list[dict[str, Any]]] = {}
_SESSION_APPROVALS: dict[str, list[dict[str, Any]]] = {}
_RECENT_COMMAND_OWNERS: dict[str, list[tuple[float, str]]] = {}
# Volatile, owner-keyed cache of the most recent sanitized user request captured
# at gateway dispatch. Used only as authorization evidence for the LLM verifier.
# Never persisted; pruned by _USER_REQUEST_TTL_SECONDS.
_RECENT_OWNER_REQUESTS: dict[str, tuple[float, str]] = {}
# Cross-channel turn lockdown (channel-shopping defense). Per session, the set of
# egress-gating POLICY classes whose export to an EXTERNAL destination was withheld
# this turn. Once present, the verifier (and read-only) may not auto-allow another
# export of those classes to external in the same turn — it gates for the human,
# regardless of which tool/channel is used. Turn-scoped: cleared on the next user
# input (per owner) and on session reset. Volatile, never persisted.
_TURN_DENIED_EXTERNAL: dict[str, set[str]] = {}
_PERSISTENT_RULES_CACHE: dict[str, Any] | None = None
_PERSISTENT_RULES_ERROR = False
_ACTIVITY_DB_INITIALIZED = False
_LAST_ACTIVITY_PRUNE = 0.0
_PLUGIN_LLM: Any | None = None
_CRON_NOTIFICATIONS_SENT: set[str] = set()
# Per-thread scratch state for measuring how long each Guardian hook check takes
# (and whether it invoked the LLM verifier). Reset at the start of each hook.
_CHECK_TIMING_STATE = threading.local()
# Short-TTL cache of recent DENY verdicts, keyed by session + owner + exact action
# fingerprint. Replaying a deny is fail-safe (it can never cause a false allow), so
# this only spares the verifier latency on retried/looping blocked actions.
_LLM_DENY_VERDICT_CACHE: dict[str, tuple[float, dict[str, str]]] = {}


def _now() -> float:
    return time.time()


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is not None:
        return value
    return default
