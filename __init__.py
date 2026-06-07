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
    sys.modules.pop(core_name, None)
    return _load_sibling_module("core")


_CORE = _load_core_module()

_SYNC_STATE_KEYS = [
    name
    for name in dir(_CORE)
    if name.startswith("_") and not (name.startswith("__") and name.endswith("__"))
    and not isinstance(getattr(_CORE, name), (types.ModuleType, type, type(lambda: None)))
]

_SYNC_TO_CORE_KEYS = set(_SYNC_STATE_KEYS) | {"_now", "_env"}
_SYNC_SKIP_FROM_CORE = {"_now", "_env"}


def _sync_to_core() -> None:
    for name in _SYNC_TO_CORE_KEYS:
        if name in globals():
            try:
                setattr(_CORE, name, globals()[name])
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
        if _name == "_load_sibling_module":
            continue
        if isinstance(_value, type):
            globals()[_name] = _value
            continue
        globals()[_name] = _make_bridge(_name)
    else:
        globals()[_name] = _value


if hasattr(_CORE, "register") and callable(getattr(_CORE, "register")):
    globals()["register"] = _make_bridge("register")


_sync_from_core()
