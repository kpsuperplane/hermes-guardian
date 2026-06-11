#!/usr/bin/env python3
"""Static guard for the real-module loader: every plugin module must resolve all
of its names through imports or local definitions — never through a shared
namespace.

`core.py` no longer exec-loads logic files into one global namespace; each file
under `privacy/`, `runtime/`, `ui/`, `integrations/`, plus `hooks.py`, `core.py`,
and `state.py`, is a real importable module. This script confirms that property
by checking, for every such module, that it has no UNRESOLVED FREE NAMES — names
it reads but neither imports nor defines.

Usage:
    python3 scripts/_refactor_analysis.py check

Exit code is non-zero if any module has unresolved free names (suitable for CI /
pre-commit). The analysis is intentionally conservative: a name counts as
resolved if it is a builtin, imported anywhere in the module, or bound anywhere
in the module (def/class/assignment/arg/except/import). That can't produce false
alarms for the loader invariant we care about — a genuinely missing cross-module
import shows up as an unresolved name.
"""

from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

# The real modules that make up the plugin (the former exec-loaded set plus the
# composition root and the state module). Reusable standalone modules
# (security/scanner, language_packs/runtime, ui/presentation) are independently
# importable and analyzed too.
_MODULES = (
    "core",
    "state",
    "hooks",
    "runtime/shared_context",
    "runtime/activity_store",
    "runtime/activity_rows",
    "runtime/state",
    "security/module",
    "security/scanner",
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
    "ui/presentation",
    "language_packs/runtime",
)

_BUILTINS = set(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__package__", "__loader__",
    "__spec__", "__path__", "__builtins__", "__class__", "__dict__",
}


def _bound_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
    return names


def _unresolved(rel: str) -> list[str]:
    tree = ast.parse((_ROOT / f"{rel}.py").read_text())
    bound = _bound_names(tree)
    used = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    return sorted(used - bound - _BUILTINS)


def check() -> int:
    failures = 0
    for rel in _MODULES:
        missing = _unresolved(rel)
        if missing:
            print(f"  {rel}: UNRESOLVED {missing}")
            failures += 1
    if failures:
        print(f"FAIL: {failures} module(s) with unresolved free names.")
        return 1
    print("OK: zero unresolved free names in every module.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] != "check":
        print(__doc__)
        return 2
    return check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
