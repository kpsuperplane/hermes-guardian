"""Hermes Guardian plugin façade."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from typing import Any, Callable


def _load_sibling_module(name: str) -> Any:
    """Load a sibling file module by absolute filesystem path."""
    module_name = f"{__name__}.{name}"
    module_path = Path(__file__).with_name(f"{name}.py")

    if module_name in sys.modules:
        return sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_core_module() -> Any:
    core_name = f"{__name__}.core"
    # core anchors the logic tree under the canonical `_hermes_guardian` package and
    # loads `state`, the reusable helpers, and every logic module as its submodules.
    # Drop that whole package (and this façade's own core alias) so a fresh façade load
    # gets fresh mutable process state — each test's load_plugin() must start from a
    # clean slate, not leak _SESSIONS/_PENDING_APPROVALS/etc. across loads.
    for name in list(sys.modules):
        if name == "_hermes_guardian" or name.startswith("_hermes_guardian."):
            sys.modules.pop(name, None)
    sys.modules.pop(f"{core_name}.state", None)
    sys.modules.pop(core_name, None)
    return _load_sibling_module("core")


_CORE = _load_core_module()
_STATE = _CORE.state

# Mutable process state, the state-dir paths, and the clock/env helpers live in the
# self-contained `state` module bound on core as `core.state`. Tests and Hermes patch
# these names on the facade, so they are bridged to/from `core.state` rather than core.
# Limited to the names that moved out of core (not state.py's private load-time copies
# of _PLUGIN_NAME/_PLUGIN_ROOT/_STATE_FILENAMES/logger).
_STATE_KEYS = [
    "_STATE_DIR",
    "_UNSAFE_DIAGNOSTICS_FLAG",
    "_PERSISTENT_RULES_PATH",
    "_ACTIVITY_DB_PATH",
    "_GUARDIAN_HMAC_KEY_PATH",
    "_PERSISTENT_RULES_MTIME",
    "_LOCK",
    "_SESSIONS",
    "_OWNER_SESSIONS",
    "_PENDING_APPROVALS",
    "_ONCE_APPROVALS",
    "_SESSION_APPROVALS",
    "_RECENT_COMMAND_OWNERS",
    "_RECENT_OWNER_REQUESTS",
    "_TURN_DENIED_EXTERNAL",
    "_PERSISTENT_RULES_CACHE",
    "_PERSISTENT_RULES_ERROR",
    "_ACTIVITY_DB_INITIALIZED",
    "_LAST_ACTIVITY_PRUNE",
    "_PLUGIN_LLM",
    "_CRON_NOTIFICATIONS_SENT",
    "_CHECK_TIMING_STATE",
    "_LLM_DENY_VERDICT_CACHE",
    "_now",
    "_env",
]
_STATE_VALUE_KEYS = [name for name in _STATE_KEYS if not callable(getattr(_STATE, name))]

_SYNC_STATE_KEYS = [
    name
    for name in dir(_CORE)
    if name.startswith("_") and not (name.startswith("__") and name.endswith("__"))
    and not isinstance(getattr(_CORE, name), (types.ModuleType, type, type(lambda: None)))
]

_SYNC_TO_CORE_KEYS = set(_SYNC_STATE_KEYS)
_SYNC_SKIP_FROM_CORE: set[str] = set()
_FACADE_CALLABLE_DENYLIST = {
    "_assert_core_logic_contract",
    "_core_logic_missing_required_symbols",
    "_import_logic",
    "_load_relative_module",
    "_propagate_to_owners",
    "_reexport_logic_symbols",
}


def _sync_to_core() -> None:
    for name in _SYNC_TO_CORE_KEYS:
        if name in globals():
            try:
                setattr(_CORE, name, globals()[name])
            except Exception:
                pass
    for name in _STATE_KEYS:
        if name in globals():
            try:
                setattr(_STATE, name, globals()[name])
            except Exception:
                pass


def _sync_from_core() -> None:
    for name in _SYNC_STATE_KEYS:
        if name in _SYNC_SKIP_FROM_CORE:
            continue
        try:
            globals()[name] = getattr(_CORE, name)
        except Exception:
            pass
    for name in _STATE_VALUE_KEYS:
        try:
            globals()[name] = getattr(_STATE, name)
        except Exception:
            pass


def _make_bridge(name: str) -> Callable[..., Any]:
    core_fn = getattr(_CORE, name)

    def _bridge(*args: Any, **kwargs: Any) -> Any:
        _sync_to_core()
        result = core_fn(*args, **kwargs)
        _sync_from_core()
        return result

    _bridge.__name__ = name
    _bridge.__doc__ = getattr(core_fn, "__doc__", None)
    return _bridge


for _name in dir(_CORE):
    if not _name.startswith("_") or (_name.startswith("__") and _name.endswith("__")):
        continue
    _value = getattr(_CORE, _name)
    if callable(_value):
        if _name in _FACADE_CALLABLE_DENYLIST:
            continue
        if isinstance(_value, type):
            globals()[_name] = _value
            continue
        globals()[_name] = _make_bridge(_name)
    else:
        globals()[_name] = _value

# Expose the moved state names on the facade. Values are copied (and re-synced from
# core.state after every bridged call); the helpers (_now/_env) are exposed as plain
# attributes so monkeypatching them on the facade reaches core.state via _sync_to_core.
for _name in _STATE_KEYS:
    globals()[_name] = getattr(_STATE, _name)

# Expose the state module itself so tests/tools can reach its load-time helpers
# (_resolve_state_dir, _migrate_legacy_state) and the real moved state directly.
state = _STATE


if hasattr(_CORE, "register") and callable(getattr(_CORE, "register")):
    globals()["register"] = _make_bridge("register")


_sync_from_core()
