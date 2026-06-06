from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace


def load_plugin():
    plugin_path = Path(__file__).resolve().parents[1] / "__init__.py"
    spec = importlib.util.spec_from_file_location("security_sensitive_filter", plugin_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def parse_json(value: str):
    return json.loads(value)


def test_sensitive_reason_detects_core_security_flows():
    plugin = load_plugin()

    cases = [
        ("Reset your password using this link", "password reset"),
        ("We received an account recovery request", "account recovery"),
        ("Your verification code is 123456", "auth code"),
        ("Use this one-time code: 123456", "one-time code"),
        ("Open your magic link to sign in", "magic link"),
        ("Security alert: new sign-in detected", "security alert"),
        ("https://example.com/reset-password?token=abc", "sensitive link"),
        ("[sensitive email subject redacted]", "redacted sensitive email"),
    ]

    for text, expected in cases:
        assert plugin._sensitive_reason(text) == expected


def test_sensitive_reason_ignores_normal_content():
    plugin = load_plugin()

    assert plugin._sensitive_reason("Lunch at noon tomorrow") is None
    assert plugin._sensitive_reason({"url": "https://example.com/docs"}) is None
    assert plugin._sensitive_reason({"items": [{"title": "normal status update"}]}) is None


def test_sensitive_finding_includes_match_and_context():
    plugin = load_plugin()

    finding = plugin._sensitive_finding(
        "Please open https://example.com/reset-password?token=abc to continue"
    )

    assert finding == {
        "reason": "sensitive link",
        "match": "https://example.com/reset-password?token=abc",
        "context": "Please open https://example.com/reset-password?token=abc to continue",
    }


def test_unsafe_diagnostic_logging_is_opt_in(monkeypatch, caplog):
    plugin = load_plugin()
    text = "Your verification code is 123456"
    monkeypatch.setattr(plugin, "_UNSAFE_DIAGNOSTICS_FLAG", Path("/tmp/missing-unsafe-diagnostic-flag"))
    monkeypatch.delenv("SECURITY_SENSITIVE_FILTER_UNSAFE_DIAGNOSTICS", raising=False)

    with caplog.at_level(logging.WARNING):
        plugin._log_unsafe_diagnostic("test", text)
    assert "UNSAFE diagnostic" not in caplog.text

    caplog.clear()
    monkeypatch.setenv("SECURITY_SENSITIVE_FILTER_UNSAFE_DIAGNOSTICS", "1")
    with caplog.at_level(logging.WARNING):
        plugin._log_unsafe_diagnostic("test", text)

    assert "UNSAFE diagnostic" in caplog.text
    assert "reason=auth code" in caplog.text
    assert "Your verification code is 123456" in caplog.text


def test_recursive_scan_checks_unexpected_nested_fields():
    plugin = load_plugin()

    payload = {
        "payload": {
            "items": [
                {
                    "providerSpecificPreviewField": (
                        "Your authentication code is 123456"
                    )
                }
            ]
        }
    }

    assert plugin._sensitive_reason(payload) == "auth code"


def test_pre_tool_call_blocks_sensitive_browser_url_before_execution():
    plugin = load_plugin()

    result = plugin._on_pre_tool_call(
        tool_name="browser_navigate",
        args={"url": "https://example.com/reset-password?token=abc"},
    )

    assert result == {
        "action": "block",
        "message": "Blocked by security-sensitive-filter: sensitive link detected in tool arguments.",
    }


def test_pre_tool_call_blocks_sensitive_mcp_query_before_execution():
    plugin = load_plugin()

    result = plugin._on_pre_tool_call(
        tool_name="mcp_gmail_search",
        args={"query": "open the magic link from the latest email"},
    )

    assert result is not None
    assert result["action"] == "block"
    assert "magic link" in result["message"]


def test_pre_tool_call_allows_normal_arguments():
    plugin = load_plugin()

    assert plugin._on_pre_tool_call(
        tool_name="browser_navigate",
        args={"url": "https://example.com/docs"},
    ) is None


def test_transform_tool_result_replaces_sensitive_plain_text_result():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="terminal",
        result="Your password reset code is 123456",
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == "[suppressed by security-sensitive-filter]"
    assert parsed["security_sensitive_filter"] == {
        "suppressed": True,
        "suppressed_count": 1,
        "reason": "password reset",
    }


def test_transform_tool_result_leaves_normal_plain_text_unchanged():
    plugin = load_plugin()

    assert plugin._on_transform_tool_result(
        tool_name="terminal",
        result="normal command output",
    ) is None


def test_transform_tool_result_replaces_sensitive_result_string_in_json():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="mcp_read_message",
        result=json.dumps({"result": "Your verification code is 123456"}),
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == "[suppressed by security-sensitive-filter]"
    assert parsed["security_sensitive_filter"]["reason"] == "auth code"


def test_transform_tool_result_removes_sensitive_list_items_entirely():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="mcp_search",
        result=json.dumps({
            "result": [
                {
                    "id": "1",
                    "unexpected_title": "[sensitive email subject redacted]",
                    "provider": "mail",
                },
                {
                    "id": "2",
                    "unexpected_title": "Lunch",
                    "provider": "mail",
                },
            ]
        }),
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == [
        {"id": "2", "unexpected_title": "Lunch", "provider": "mail"}
    ]
    assert parsed["security_sensitive_filter"]["suppressed_count"] == 1
    assert parsed["security_sensitive_filter"]["reason"] == "redacted sensitive email"


def test_transform_tool_result_removes_sensitive_nested_list_items():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="unknown_tool",
        result=json.dumps({
            "payload": {
                "items": [
                    {"preview_text": "Your one-time code is 123456"},
                    {"preview_text": "normal"},
                ]
            }
        }),
    )

    parsed = parse_json(transformed)
    assert parsed["payload"]["items"] == [{"preview_text": "normal"}]
    assert parsed["payload"]["security_sensitive_filter"]["reason"] == "one-time code"
    assert parsed["security_sensitive_filter"]["reason"] == "one-time code"


def test_transform_tool_result_replaces_top_level_sensitive_message_record():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="mcp_read_message",
        result=json.dumps({
            "subject": "Password reset",
            "from": "security@example.com",
            "body": "Reset your password using this link",
        }),
    )

    parsed = parse_json(transformed)
    assert parsed["result"] == "[suppressed by security-sensitive-filter]"
    assert parsed["security_sensitive_filter"]["reason"] == "password reset"


def test_transform_tool_result_leaves_normal_json_unchanged():
    plugin = load_plugin()

    assert plugin._on_transform_tool_result(
        tool_name="mcp_search",
        result=json.dumps({"result": [{"subject": "Lunch", "body": "noon"}]}),
    ) is None


def test_pre_gateway_dispatch_skips_sensitive_message():
    plugin = load_plugin()
    event = SimpleNamespace(text="Your password reset code is 123456")

    result = plugin._on_pre_gateway_dispatch(event=event)

    assert result == {
        "action": "skip",
        "reason": "security-sensitive content suppressed before model dispatch",
    }


def test_pre_gateway_dispatch_allows_normal_message():
    plugin = load_plugin()
    event = SimpleNamespace(text="Can you summarize my calendar?")

    assert plugin._on_pre_gateway_dispatch(event=event) is None


def test_pre_gateway_dispatch_ignores_missing_or_non_text_events():
    plugin = load_plugin()

    assert plugin._on_pre_gateway_dispatch(event=SimpleNamespace()) is None
    assert plugin._on_pre_gateway_dispatch(event=SimpleNamespace(text=None)) is None
    assert plugin._on_pre_gateway_dispatch(event=SimpleNamespace(text=123)) is None


def test_register_wires_all_expected_hooks():
    plugin = load_plugin()

    class FakeContext:
        def __init__(self):
            self.hooks = []

        def register_hook(self, name, callback):
            self.hooks.append((name, callback))

    ctx = FakeContext()
    plugin.register(ctx)

    assert [name for name, _ in ctx.hooks] == [
        "pre_tool_call",
        "transform_tool_result",
        "pre_gateway_dispatch",
    ]
    assert ctx.hooks[0][1] is plugin._on_pre_tool_call
    assert ctx.hooks[1][1] is plugin._on_transform_tool_result
    assert ctx.hooks[2][1] is plugin._on_pre_gateway_dispatch
