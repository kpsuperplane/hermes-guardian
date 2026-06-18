from __future__ import annotations

import ast
import sys
from pathlib import Path

from support import *  # noqa: F403


ROOT = Path(__file__).resolve().parents[1]


def _top_level_defs(module_name: str) -> list[tuple[str, int, str]]:
    path = ROOT / f"{module_name}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    defs: list[tuple[str, int, str]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defs.append((node.name, node.lineno, type(node).__name__))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defs.append((target.id, node.lineno, type(node).__name__))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defs.append((node.target.id, node.lineno, type(node).__name__))
    return defs


def _plugin_yaml_hooks() -> list[str]:
    hooks: list[str] = []
    in_hooks = False
    for line in (ROOT / "plugin.yaml").read_text(encoding="utf-8").splitlines():
        if line.strip() == "provides_hooks:":
            in_hooks = True
            continue
        if in_hooks:
            if line.startswith("  - "):
                hooks.append(line.split("- ", 1)[1].strip())
            elif line.strip():
                break
    return hooks


def test_core_logic_modules_are_single_ordered_contract():
    plugin = load_plugin()

    assert plugin._CORE._CORE_LOGIC_MODULES == (
        "runtime/shared_context",
        "security/module",
        "runtime/activity_store",
        "runtime/activity_rows",
        "privacy/taint",
        "privacy/destinations",
        "privacy/terminal_analysis",
        "privacy/tool_policy",
        "privacy/capability",
        "privacy/policy",
        "privacy/action_details",
        "privacy/llm",
        "privacy/rules",
        "privacy/approvals",
        "privacy/module",
        "integrations/cron_notifications",
        "ui/dashboard",
        "ui/commands",
        "hooks",
        "runtime/state",
    )


def test_core_logic_has_no_unallowlisted_duplicate_defs():
    plugin = load_plugin()
    definitions: dict[str, list[str]] = {}
    for module_name in plugin._CORE._CORE_LOGIC_MODULES:
        for name, _line, _kind in _top_level_defs(module_name):
            if name.startswith("__"):
                continue
            definitions.setdefault(name, []).append(module_name)

    duplicates = {
        name: tuple(modules)
        for name, modules in definitions.items()
        if len(modules) > 1
    }

    assert duplicates == plugin._CORE._CORE_LOGIC_ALLOWED_REBINDS


def test_core_logic_required_symbols_are_loaded():
    plugin = load_plugin()

    # Single source of truth: each required handler/helper resolves to a callable on
    # core itself (the entrypoints register() wires) or on one of the real logic
    # modules that owns it — there is no re-export onto core to satisfy this.
    assert plugin._CORE._core_logic_missing_required_symbols() == ()
    namespaces = (vars(plugin._CORE), *(vars(m) for m in plugin._CORE._LOADED_LOGIC_MODULES))
    for name in plugin._CORE._CORE_LOGIC_REQUIRED_SYMBOLS:
        assert any(callable(ns.get(name)) for ns in namespaces), name


def test_facade_and_core_have_no_sync_bridge_machinery():
    # The Phase 3 transitional shims are gone: the façade is a by-reference re-export
    # with no per-call state-sync wrappers, and core no longer subclasses ModuleType to
    # propagate patches. Tests patch the OWNING module/state directly instead.
    facade_src = (ROOT / "__init__.py").read_text(encoding="utf-8")
    for forbidden in ("_make_bridge", "_sync_to_core", "_sync_from_core"):
        assert forbidden not in facade_src, f"facade still has sync bridge: {forbidden}"

    core_src = (ROOT / "core.py").read_text(encoding="utf-8")
    for forbidden in ("_CoreModule", "_reexport_logic_symbols", "_propagate_to_owners"):
        assert forbidden not in core_src, f"core still has re-export shim: {forbidden}"


def test_core_has_no_exec_based_logic_loader():
    # The logic files are real, normally-importable modules now; core must not carry
    # the old exec/compile shared-namespace loader.
    core_src = (ROOT / "core.py").read_text(encoding="utf-8")
    for forbidden in ("_load_core_logic", "_load_logic_module", "exec("):
        assert forbidden not in core_src, f"exec-loader remnant in core.py: {forbidden}"


def test_logic_modules_are_real_importable_modules():
    # Each _CORE_LOGIC_MODULES entry is a genuine module object reachable through the
    # canonical package, not a namespace fragment exec'd into core's globals.
    import types

    plugin = load_plugin()
    pkg = sys.modules["_hermes_guardian"]
    assert isinstance(pkg, types.ModuleType)
    for module_name in plugin._CORE._CORE_LOGIC_MODULES:
        dotted = "_hermes_guardian." + module_name.replace("/", ".")
        module = sys.modules.get(dotted)
        assert isinstance(module, types.ModuleType), f"{dotted} is not a real module"


def test_facade_reexports_modules_by_reference():
    # The façade is thin: the logic modules and `state` are re-exported BY REFERENCE,
    # so `plugin.<module>` is the identical object the live call path uses. Patching it
    # (no propagation shim) is therefore observed by the engine.
    plugin = load_plugin()
    assert plugin.state is sys.modules["_hermes_guardian.state"]
    assert plugin.policy is sys.modules["_hermes_guardian.privacy.policy"]
    assert plugin.rules is sys.modules["_hermes_guardian.privacy.rules"]
    assert plugin.privacy_module is sys.modules["_hermes_guardian.privacy.module"]


def test_state_rebind_is_observed_by_the_engine(monkeypatch):
    # Single source of truth: rebinding a scalar/clock on `plugin.state` is seen by the
    # engine directly — there is no façade-to-core sync to perform.
    plugin = load_plugin()

    monkeypatch.setattr(plugin.state, "_now", lambda: 123.0)

    plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")

    assert plugin._CORE.state._now() == 123.0


def test_patching_owning_module_is_seen_by_the_live_call_path(monkeypatch):
    # With the propagation shim gone, a function patch must target the module that OWNS
    # the symbol the live path calls (here hooks.py calls privacy_module._privacy_pre_tool_call).
    plugin = load_plugin()

    def boom(*_args, **_kwargs):
        raise RuntimeError("patched privacy failure")

    monkeypatch.setattr(plugin.privacy_module, "_privacy_pre_tool_call", boom)

    result = plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    assert result == {
        "action": "block",
        "message": (
            "Hermes Guardian had an internal policy error, so this tool call "
            "was blocked fail-closed."
        ),
    }


def test_plugin_yaml_hooks_match_register_contract():
    plugin = load_plugin()

    class FakeContext:
        def __init__(self):
            self.hooks = []

        def register_hook(self, name, callback):
            self.hooks.append((name, callback))

    ctx = FakeContext()
    plugin.register(ctx)

    assert _plugin_yaml_hooks() == list(plugin._CORE._REGISTERED_HOOKS)
    assert [name for name, _callback in ctx.hooks] == list(plugin._CORE._REGISTERED_HOOKS)
