from __future__ import annotations

import json
from types import SimpleNamespace

from support import *  # noqa: F403


def _use_rules_path(plugin, path):
    plugin.state._PERSISTENT_RULES_PATH = path
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None
    plugin.state._PERSISTENT_RULES_ERROR = False


def _allow_verdict():
    return {
        "outcome": "allow",
        "risk_level": "low",
        "authorization_level": "explicit",
        "rationale": "narrow benign action",
    }


class RaisingLlm:
    def __init__(self, exc: Exception):
        self.exc = exc
        self.calls = []

    def complete_structured(self, **kwargs):
        self.calls.append(kwargs)
        raise self.exc


class TextOnlyLlm:
    def __init__(self, text: str):
        self.text = text
        self.calls = []

    def complete_structured(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(parsed=None, text=self.text)


def test_missing_privacy_policy_file_keeps_normal_default(tmp_path):
    plugin = load_plugin()
    rules_path = tmp_path / "guardian-rules.json"
    _use_rules_path(plugin, rules_path)

    assert not rules_path.exists()
    assert plugin._privacy_policy() == "llm"
    assert plugin.state._PERSISTENT_RULES_ERROR is False


def test_corrupt_privacy_policy_file_forces_strict_without_llm_auto_allow(tmp_path):
    plugin = load_plugin()
    rules_path = tmp_path / "guardian-rules.json"
    rules_path.write_text("{not json")
    _use_rules_path(plugin, rules_path)
    fake_llm = FakeSecurityLlm(_allow_verdict())
    plugin.state._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    result = plugin._on_pre_tool_call("terminal", {"command": "pwd"}, session_id="s1")

    assert plugin._privacy_policy() == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True
    assert result is not None
    assert "Approval ID:" in result["message"]
    assert not fake_llm.calls


def test_malformed_privacy_policy_file_forces_strict(tmp_path):
    plugin = load_plugin()
    rules_path = tmp_path / "guardian-rules.json"
    # An invalid v4 review.mode is rejected at validation, forcing fail-closed strict.
    rules_path.write_text(json.dumps({"version": 4, "review": {"mode": "auto-approve"}}))
    _use_rules_path(plugin, rules_path)

    assert plugin._privacy_policy() == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True


def test_unreadable_privacy_policy_path_forces_strict(tmp_path):
    plugin = load_plugin()
    rules_path = tmp_path / "guardian-rules.json"
    rules_path.mkdir()
    _use_rules_path(plugin, rules_path)

    assert plugin._privacy_policy() == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True


def test_incomplete_llm_allow_verdict_falls_back_to_manual_approval():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = FakeSecurityLlm({"outcome": "allow"})
    plugin.state._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert result is not None
    assert "Approval ID:" in result["message"]
    assert len(fake_llm.calls) == 1
    assert plugin._PENDING_APPROVALS


def test_invalid_llm_allow_verdict_falls_back_to_manual_approval():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = FakeSecurityLlm({
        "outcome": "allow",
        "risk_level": "critical",
        "authorization_level": "explicit",
        "rationale": "critical is never auto-allowed",
    })
    plugin.state._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call("terminal", {"command": "pwd"}, session_id="s1")

    assert result is not None
    assert "Approval ID:" in result["message"]
    assert plugin._PENDING_APPROVALS


def test_llm_timeout_falls_back_to_manual_approval():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = RaisingLlm(TimeoutError("verifier timeout"))
    plugin.state._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    result = plugin._on_pre_tool_call("terminal", {"command": "pwd"}, session_id="s1")

    assert result is not None
    assert "Approval ID:" in result["message"]
    assert len(fake_llm.calls) == 1
    assert plugin._PENDING_APPROVALS


def test_malformed_llm_text_falls_back_to_manual_approval():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = TextOnlyLlm("not json")
    plugin.state._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    result = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1")

    assert result is not None
    assert "Approval ID:" in result["message"]
    assert len(fake_llm.calls) == 1
    assert plugin._PENDING_APPROVALS


def test_throwing_security_pre_tool_hook_blocks_fail_closed(monkeypatch):
    plugin = load_plugin()

    def boom(*_args, **_kwargs):
        raise RuntimeError("security boom")

    monkeypatch.setattr(plugin.security_module, "_security_pre_tool_call", boom)

    result = plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")

    assert result is not None
    assert result["action"] == "block"
    assert "fail-closed" in result["message"]


def test_throwing_security_result_hook_suppresses_fail_closed(monkeypatch):
    plugin = load_plugin()

    def boom(*_args, **_kwargs):
        raise RuntimeError("security result boom")

    monkeypatch.setattr(plugin.security_module, "_security_transform_tool_result", boom)

    result = plugin._on_transform_tool_result("mcp_gmail_read", '{"body":"private note"}', session_id="s1")
    parsed = json.loads(result)

    assert parsed["hermes_guardian"]["suppressed"] is True
    assert "fail-closed" in parsed["hermes_guardian"]["reason"]


def test_throwing_pre_gateway_recovery_rescan_suppresses_fail_closed(monkeypatch):
    plugin = load_plugin()

    def boom(*_args, **_kwargs):
        raise RuntimeError("scanner boom")

    # Break the primary dispatch path AND the recovery re-scan: the original
    # failure is inside the scanner, so the recovery _sensitive_reason re-run
    # would re-raise. The hook must not propagate; it must fail closed.
    monkeypatch.setattr(plugin.security_module, "_security_pre_gateway_dispatch", boom)
    monkeypatch.setattr(plugin.security_module, "_sensitive_reason", boom)

    result = plugin._on_pre_gateway_dispatch(event=gateway_event("hello there"))

    assert result == {
        "action": "skip",
        "reason": "security-sensitive content suppressed before model dispatch",
    }


def test_pending_approval_storage_failure_still_blocks(monkeypatch):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    def boom():
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(plugin.activity_store, "_activity_connect", boom)

    result = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "raw private"}, session_id="s1")

    assert result is not None
    assert "Approval ID:" in result["message"]
    assert "raw private" not in result["message"]
    assert plugin._PENDING_APPROVALS


def test_unavailable_hmac_key_blocks_approval_fail_closed(tmp_path):
    plugin = load_plugin()
    bad_key_path = tmp_path / "hmac-key-is-directory"
    bad_key_path.mkdir()
    plugin.state._GUARDIAN_HMAC_KEY_PATH = bad_key_path
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "private summary"}, session_id="s1")

    assert result is not None
    assert result["action"] == "block"
    assert "fail-closed" in result["message"]
    assert not plugin._PENDING_APPROVALS


def test_tainted_final_response_to_unknown_destination_is_suppressed():
    plugin = load_plugin()
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output("private summary", session_id="s1")

    assert out is not None
    assert "suppressed" in out.lower()
    approval_id = first_pending_id(plugin)
    approval = plugin._PENDING_APPROVALS[approval_id]
    assert approval["tool_name"] == "llm_output"
    assert approval["action_family"] == "final_response"
    assert approval["destination"] == "unknown"
    assert approval["data_classes"] == ["communications"]
    assert approval["reason"] == "tainted final response to non-owner destination"
    assert [option["method"] for option in plugin._approval_permit_options(approval)] == [
        "rule_5m",
        "rule_forever",
    ]
    rows = plugin._activity_rows({"decision": "blocked"}, limit=1)
    assert rows[0]["approval_id"] == approval_id


def test_tainted_final_response_with_bound_owner_but_missing_destination_metadata_is_suppressed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output("private summary", session_id="s1")

    assert out is not None
    assert "suppressed" in out.lower()
    assert plugin._PENDING_APPROVALS


def test_tainted_final_response_pending_approval_can_create_allow_rule():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts", "documents"})

    out = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="even-ai",
    )
    assert out is not None
    approval_id = first_pending_id(plugin)

    ok, message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "rule_5m")

    assert ok, message
    assert approval_id not in plugin._PENDING_APPROVALS
    rules = plugin._persistent_privacy_rules()
    assert len(rules) == 1
    match = rules[0]["match"]
    assert match["tool_name"] == "llm_output"
    assert match["action_family"] == "final_response"
    assert match["destination"] == "even-ai"
    assert set(match["data_classes"]) == {"contacts", "documents"}

    retry = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="even-ai",
    )
    assert retry is None


def test_tainted_final_response_to_owner_private_destination_is_allowed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="telegram",
        sender_id="owner",
        chat_type="private",
    )

    assert out is None


def test_tainted_final_response_to_group_can_be_allowed_by_rule():
    plugin = load_plugin()
    bind_owner(plugin)
    save_privacy_config(
        plugin,
        rules=[
            privacy_rule(
                rule_id="allow_group_final",
                action_family="final_response",
                destination="discord:group",
                data_classes=["communications"],
            )
        ],
    )
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="discord",
        sender_id="owner",
        chat_type="group",
    )

    assert out is None
    rows = plugin._activity_rows({"decision": "allowed"}, limit=1)
    assert rows[0]["tool_name"] == "llm_output"
    assert rows[0]["action_family"] == "final_response"
    assert rows[0]["destination"] == "discord:group"
    assert rows[0]["reason"] == "matched allow rule"
    assert rows[0]["rule_id"] == "allow_group_final"


def test_tainted_final_response_to_matching_sender_without_private_chat_metadata_is_suppressed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="telegram",
        sender_id="owner",
    )

    assert out is not None
    assert "suppressed" in out.lower()


def test_tainted_final_response_to_private_chat_without_sender_metadata_is_suppressed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output(
        "private summary",
        session_id="s1",
        platform="telegram",
        chat_type="private",
    )

    assert out is not None
    assert "suppressed" in out.lower()


def test_tainted_final_response_to_cli_destination_is_allowed_without_sender_metadata():
    plugin = load_plugin()
    plugin._on_pre_llm_call(session_id="s1", platform="cli")
    plugin._taint_session("s1", {"communications"})

    out = plugin._on_transform_llm_output("private summary", session_id="s1", platform="cli")

    assert out is None


def test_tainted_final_response_to_cron_session_is_allowed():
    plugin = load_plugin()
    cron_session = "cron_aaaaaaaaaaaa_20260607_030107"
    plugin._taint_session(cron_session, {"communications"})

    out = plugin._on_transform_llm_output("private summary", session_id=cron_session, platform="cron")

    assert out is None
    rows = plugin._activity_rows({"decision": "allowed"}, limit=1)
    assert rows[0]["tool_name"] == "llm_output"
    assert rows[0]["action_family"] == "final_response"
    assert rows[0]["destination"] == "cron"
    assert rows[0]["destination_trust"] == "self"
    assert rows[0]["reason"] == "owner-configured cron final response"


def test_tainted_final_response_to_cron_session_can_be_denied_by_rule():
    plugin = load_plugin()
    cron_session = "cron_aaaaaaaaaaaa_20260607_030107"
    save_privacy_config(
        plugin,
        rules=[
            privacy_rule(
                rule_id="deny_cron_final",
                effect="deny",
                action_family="final_response",
                destination="cron",
                data_classes=["communications"],
            )
        ],
    )
    plugin._taint_session(cron_session, {"communications"})

    out = plugin._on_transform_llm_output("private summary", session_id=cron_session, platform="cron")

    assert out is not None
    assert "suppressed" in out.lower()
    rows = plugin._activity_rows({"decision": "blocked"}, limit=1)
    assert rows[0]["tool_name"] == "llm_output"
    assert rows[0]["action_family"] == "final_response"
    assert rows[0]["destination"] == "cron"
    assert rows[0]["reason"] == "matched deny rule"
    assert rows[0]["rule_id"] == "deny_cron_final"


def test_privacy_off_and_allow_rules_do_not_bypass_security_module():
    plugin = load_plugin()
    save_privacy_config(
        plugin,
        mode="off",
        rules=[privacy_rule(action_family="message_send", destination="friend")],
    )

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "Your password reset code is 123456"},
        session_id="s1",
    )

    assert result is not None
    assert result["action"] == "block"
    assert "password reset" in result["message"] or "auth code" in result["message"]
