"""Plugin loading robustness + persistent-state location.

- Regression for "No module named 'language_packs'": the plugin must import
  cleanly regardless of the current working directory (it self-registers its
  own directory on sys.path), so the gateway and the `hermes` CLI both load it.
- HERMES_GUARDIAN_STATE_DIR lets every runtime context share one state
  directory; adopting it migrates the legacy co-located files instead of
  orphaning the dashboard's history and the operator's saved allow rules.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from support import load_plugin

PLUGIN_INIT = Path(__file__).resolve().parents[1] / "__init__.py"


def test_plugin_imports_from_foreign_cwd_and_language_packs_resolves(monkeypatch, tmp_path):
    # Keep any lazily-created state out of the real plugin dir.
    monkeypatch.setenv("HERMES_GUARDIAN_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.chdir(tmp_path)

    spec = importlib.util.spec_from_file_location("hermes_guardian_foreign_cwd", PLUGIN_INIT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)  # must not raise No module named 'language_packs'
        assert callable(module._on_pre_tool_call)
        assert importlib.util.find_spec("language_packs") is not None
    finally:
        sys.modules.pop(spec.name, None)


def test_migrate_legacy_state_copies_without_overwriting(tmp_path):
    plugin = load_plugin()
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "guardian-rules.json").write_text('{"version": 1}')
    (legacy / "activity.sqlite3").write_bytes(b"sqlite-bytes")
    (legacy / ".guardian-hmac-key").write_bytes(b"k" * 32)
    state = tmp_path / "state"
    state.mkdir()

    plugin._migrate_legacy_state(legacy, state)

    assert (state / "guardian-rules.json").read_text() == '{"version": 1}'
    assert (state / "activity.sqlite3").read_bytes() == b"sqlite-bytes"
    assert (state / ".guardian-hmac-key").read_bytes() == b"k" * 32

    # Existing target files are never clobbered by a later migration.
    (state / "guardian-rules.json").write_text('{"version": 2}')
    plugin._migrate_legacy_state(legacy, state)
    assert (state / "guardian-rules.json").read_text() == '{"version": 2}'


def test_state_dir_defaults_to_plugin_dir_when_unset(monkeypatch):
    monkeypatch.delenv("HERMES_GUARDIAN_STATE_DIR", raising=False)
    plugin = load_plugin()
    assert plugin._resolve_state_dir() == plugin._PLUGIN_ROOT


def test_state_dir_override_is_honored_and_created(monkeypatch, tmp_path):
    state = tmp_path / "shared"
    monkeypatch.setenv("HERMES_GUARDIAN_STATE_DIR", str(state))
    plugin = load_plugin()
    resolved = plugin._resolve_state_dir()
    assert resolved == state
    assert state.is_dir()
