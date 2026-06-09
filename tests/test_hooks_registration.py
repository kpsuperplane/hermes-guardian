from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import re
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from support import *  # noqa: F403


def test_pre_gateway_dispatch_skips_sensitive_message():
    plugin = load_plugin()

    result = plugin._on_pre_gateway_dispatch(event=gateway_event("Your password reset code is 123456"))

    assert result == {
        "action": "skip",
        "reason": "security-sensitive content suppressed before model dispatch",
    }


def test_pre_gateway_dispatch_records_guardian_command_owner_but_allows_dispatch():
    plugin = load_plugin()

    result = plugin._on_pre_gateway_dispatch(event=gateway_event("/guardian status"))

    assert result is None
    assert plugin._RECENT_COMMAND_OWNERS["status"]


def test_transform_llm_output_removes_sensitive_email_rows_from_final_response():
    plugin = load_plugin()

    transformed = plugin._on_transform_llm_output(
        response_text=(
            "Loaded your 3 most recent inbox emails:\n\n"
            "1. From: Alex Rivera <...@hotmail.com>\n"
            "   Subject: Hello\n"
            "   ID: normal\n\n"
            "2. From: GitHub <noreply@github.com>\n"
            "   Subject: [redacted sensitive subject]\n"
            "   ID: sensitive-a\n\n"
            "3. From: Alex Rivera <...@hotmail.com>\n"
            "   Subject: One time [redacted]\n"
            "   ID: sensitive-b\n"
        )
    )

    assert transformed is not None
    assert "Subject: Hello" in transformed
    assert "sensitive-a" not in transformed
    assert "sensitive-b" not in transformed
    assert "hermes-guardian omitted 2 security-sensitive email record(s)" in transformed


def test_transform_llm_output_omits_all_sensitive_rows_without_leaking_original_text():
    plugin = load_plugin()

    transformed = plugin._on_transform_llm_output(
        response_text=(
            "Loaded your inbox emails:\n\n"
            "1. From: GitHub <noreply@github.com>\n"
            "   Subject: A new SSH key was added\n"
            "   ID: sensitive-a\n\n"
            "2. From: Example <security@example.com>\n"
            "   Subject: Your verification code is 123456\n"
            "   ID: sensitive-b\n"
        )
    )

    assert transformed == "[hermes-guardian omitted 2 security-sensitive email record(s).]"
    assert "sensitive-a" not in transformed
    assert "123456" not in transformed


def test_register_wires_expected_hooks_and_command():
    plugin = load_plugin()

    class FakeContext:
        def __init__(self):
            self.hooks = []
            self.commands = []
            self.cli_commands = []
            self.llm = object()

        def register_hook(self, name, callback):
            self.hooks.append((name, callback))

        def register_command(self, name, handler, description="", args_hint=""):
            self.commands.append((name, handler, description, args_hint))

        def register_cli_command(self, name, help_text, setup_fn, handler_fn=None, description=""):
            self.cli_commands.append((name, help_text, setup_fn, handler_fn, description))

    ctx = FakeContext()
    plugin.register(ctx)

    assert [name for name, _ in ctx.hooks] == [
        "pre_tool_call",
        "transform_tool_result",
        "pre_gateway_dispatch",
        "transform_llm_output",
        "pre_llm_call",
        "on_session_reset",
        "on_session_end",
    ]
    assert ctx.commands[0][0] == "guardian"
    assert "dashboard" not in ctx.commands[0][3]
    assert ctx.cli_commands[0][0] == "guardian"
    assert ctx.cli_commands[0][1] == "Manage Hermes Guardian"
    assert ctx.cli_commands[0][3] is None
    assert plugin._PLUGIN_LLM is ctx.llm


def test_dashboard_plugin_api_loader_imports_plugin_without_package_split_breakage():
    server_path = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("hermes_guardian_dashboard_api", server_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    plugin = module._guardian()

    assert plugin._PLUGIN_NAME == "hermes-guardian"
    assert callable(plugin._dashboard_rule_create_action)


def test_dashboard_plugin_api_loader_works_outside_plugin_cwd(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    server_path = root / "dashboard" / "plugin_api.py"
    old_path = list(sys.path)
    for name in list(sys.modules):
        if name == "_hermes_guardian_dashboard_facade" or name.startswith("language_packs"):
            sys.modules.pop(name, None)
    monkeypatch.chdir(tmp_path)
    try:
        sys.path[:] = [
            path
            for path in sys.path
            if not path or Path(path).resolve() != root
        ]
        spec = importlib.util.spec_from_file_location("hermes_guardian_dashboard_api_tmp_cwd", server_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        plugin = module._guardian()
        policy = plugin._policy_snapshot()

        assert plugin._PLUGIN_NAME == "hermes-guardian"
        assert "security_rules" in policy
        assert callable(plugin._activity_datatables_payload)
    finally:
        sys.path[:] = old_path
