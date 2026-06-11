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

    assert plugin._CORE._core_logic_missing_required_symbols() == ()
    for name in plugin._CORE._CORE_LOGIC_REQUIRED_SYMBOLS:
        assert callable(getattr(plugin._CORE, name))


def test_facade_keeps_loader_helpers_private():
    plugin = load_plugin()

    for name in plugin._FACADE_CALLABLE_DENYLIST:
        assert not hasattr(plugin, name)


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


def test_logic_modules_import_without_cycle_errors():
    # Loading the plugin imports every logic module in dependency order; the call-time
    # module-object references must tolerate the mutual import edges (rules<->llm,
    # approvals<->cron_notifications, ...) without raising at import.
    plugin = load_plugin()
    assert plugin._CORE._core_logic_missing_required_symbols() == ()


def test_core_monkeypatch_propagates_to_owning_module():
    # Patching core.<name> for a re-exported logic symbol must reach the module that
    # actually defines it, since the logic modules call each other by module attribute.
    plugin = load_plugin()
    rules_mod = sys.modules["_hermes_guardian.privacy.rules"]
    original = plugin._CORE._security_rule_enabled
    sentinel = object()
    try:
        setattr(plugin._CORE, "_security_rule_enabled", sentinel)
        assert rules_mod._security_rule_enabled is sentinel
    finally:
        setattr(plugin._CORE, "_security_rule_enabled", original)


def test_facade_monkeypatches_sync_to_core_for_bridged_calls(monkeypatch):
    plugin = load_plugin()

    monkeypatch.setattr(plugin, "_now", lambda: 123.0)

    plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")

    assert plugin._CORE.state._now() == 123.0


def test_core_monkeypatches_are_seen_by_facade_hook_bridges(monkeypatch):
    plugin = load_plugin()

    def boom(*_args, **_kwargs):
        raise RuntimeError("patched privacy failure")

    monkeypatch.setattr(plugin._CORE, "_privacy_pre_tool_call", boom)

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
