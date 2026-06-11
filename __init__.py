"""Hermes Guardian plugin façade.

Thin re-export layer. The real implementation lives in ``core`` (the entrypoints
and load-time wiring) and in the genuine logic submodules under the canonical
``_hermes_guardian`` package. This façade loads ``core``, then re-exports the
public surface — by reference, with no per-call sync wrappers — so Hermes and the
test-suite can reach ``register``, the hook/command/CLI callbacks, every
handler/helper, the logic modules themselves, and the ``state`` module.

There is a SINGLE SOURCE OF TRUTH: all mutable process state, the on-disk paths,
and the clock/env helpers live in the ``state`` module (exposed here as
``plugin.state``). The functions are the real objects. So there is nothing to
sync: rebinding ``plugin.state.<name>`` is observed by the engine, and in-place
container mutations through ``plugin.<container>`` act on the shared ``state``
object.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


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
state = _CORE.state


def _is_public(name: str) -> bool:
    # Re-export the plugin's own underscore-prefixed handlers/helpers/constants too;
    # only Python dunders stay private. (callable names like `register` are public.)
    return not (name.startswith("__") and name.endswith("__"))


def _reexport(module: Any) -> None:
    """Bind every public top-level name of ``module`` onto this façade by reference."""
    g = globals()
    for name in vars(module):
        if not _is_public(name):
            continue
        g[name] = getattr(module, name)


# Build the public surface by reference. Mirror the engine's own precedence: the
# logic modules contribute their public handlers/helpers first (in load order, so a
# legitimately re-bound name resolves to its last owner), then `state` and `core`
# win — they own the canonical mutable state and the registered entrypoints.
for _dotted in _CORE._CORE_LOGIC_MODULES:
    _logic_module = sys.modules.get(f"_hermes_guardian.{_dotted.replace('/', '.')}")
    if _logic_module is not None:
        _reexport(_logic_module)

# `state` is the single source of truth: re-export its names by reference so reads
# (and in-place container mutations) go through the shared objects, and expose the
# module itself so tests rebind scalars/paths/clock as `plugin.state.<name> = ...`.
_reexport(state)

# core owns the entrypoints (`register`, the hook callbacks, the command/CLI
# handlers) and the plugin-level constants; it wins over the logic re-exports.
_reexport(_CORE)
