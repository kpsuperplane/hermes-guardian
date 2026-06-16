"""Context-aware permit options for a block (doc 06 §2-6).

Covers the pure resolver `_approval_permit_options` (which permit methods a block offers,
given its context) and the dispatcher `_apply_permit_option` (apply one method, with the
structural admin gate). The resolver is the single source of truth both surfaces consume.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only synthetic
placeholders (example.com addresses, made-up store ids, synthetic session ids).
"""

from __future__ import annotations

from support import *  # noqa: F403


# --- Resolver helpers --------------------------------------------------------
def _methods(plugin, approval):
    return {opt["method"] for opt in plugin._approval_permit_options(approval)}


def _option(plugin, approval, method):
    for opt in plugin._approval_permit_options(approval):
        if opt["method"] == method:
            return opt
    raise AssertionError(f"{method} not offered; got {_methods(plugin, approval)}")


_RULE_METHODS = {"rule_5m", "rule_forever"}


def _approval(**overrides):
    base = {
        "action_family": "",
        "tool_name": "",
        "destination": "",
        "recipient_identity": "none",
        "data_classes": ["communications"],
    }
    base.update(overrides)
    return base


# --- 1. The two approval rows are always present, short-lived -> permanent. ----
def test_rule_rows_always_offered_in_breadth_order():
    plugin = load_plugin()
    methods = [opt["method"] for opt in plugin._approval_permit_options(_approval())]
    assert methods[:2] == ["rule_5m", "rule_forever"]
    labels = [opt["label"] for opt in plugin._approval_permit_options(_approval())]
    assert labels[:2] == ["Approve for 5 minutes", "Approve forever"]
    assert {opt["group"] for opt in plugin._approval_permit_options(_approval())} == {"Approval options"}


# --- 2. Messaging offers self-identity + trusted-recipient on the recipient. ---
def test_messaging_offers_identity_dimensions_only():
    plugin = load_plugin()
    approval = _approval(
        action_family="message_send",
        tool_name="send_message",
        destination="messaging",
        permit_recipient="alice@example.com",
    )
    assert _methods(plugin, approval) == _RULE_METHODS | {"self_identity", "trusted_identity"}
    # The guardrail (doc 06 §3.1): a messaging block never offers self_host — the engine
    # judges the recipient, not a host, so adding example.com would be a dead-end permit.
    assert "self_host" not in _methods(plugin, approval)
    assert _option(plugin, approval, "self_identity")["value"] == "alice@example.com"
    # Trusted recipient is scoped to the approval's classes, not widened to "*".
    assert _option(plugin, approval, "trusted_identity")["data_classes"] == ["communications"]


# --- 3. An unresolvable recipient yields no identity options. ------------------
def test_messaging_templated_recipient_offers_no_structural():
    plugin = load_plugin()
    approval = _approval(
        action_family="message_send",
        tool_name="send_message",
        destination="messaging",
        recipient_identity="none",
    )
    assert _methods(plugin, approval) == _RULE_METHODS


# --- 4. A store write offers self-destination + trusted-by-connector-id. -------
def test_store_write_offers_destination_dimensions():
    plugin = load_plugin()
    approval = _approval(
        action_family="mcp_write",
        tool_name="notion_create_page",
        destination="mcp:notion",
        data_classes=["documents"],
    )
    assert _methods(plugin, approval) == _RULE_METHODS | {"self_destination", "trusted_identity"}
    assert _option(plugin, approval, "self_destination")["value"] == "store:notion"
    assert _option(plugin, approval, "trusted_identity")["value"] == "notion"


# --- 5. A web/host action offers self-host. ------------------------------------
def test_web_action_offers_self_host():
    plugin = load_plugin()
    approval = _approval(
        action_family="web_api",
        tool_name="http_post",
        destination="api.example.com",
        data_classes=["documents"],
    )
    assert _methods(plugin, approval) == _RULE_METHODS | {"self_host"}
    assert _option(plugin, approval, "self_host")["value"] == "api.example.com"


# --- 6. A terminal command to a host offers BOTH host + command (doc 06 §3). ---
def test_terminal_to_host_offers_two_structural_dimensions():
    plugin = load_plugin()
    approval = _approval(
        action_family="terminal_exec",
        tool_name="Bash",
        destination="terminal",
        permit_host="api.example.com",
        permit_command="curl",
        data_classes=["local_system"],
    )
    assert _methods(plugin, approval) == _RULE_METHODS | {"self_host", "trusted_command"}
    assert _option(plugin, approval, "self_host")["value"] == "api.example.com"
    assert _option(plugin, approval, "trusted_command")["value"] == "curl"


# --- 7. A terminal command with no host offers only the command dimension. -----
def test_terminal_without_host_offers_command_only():
    plugin = load_plugin()
    approval = _approval(
        action_family="terminal_exec",
        tool_name="Bash",
        destination="terminal",
        permit_command="ls",
        data_classes=["local_system"],
    )
    assert _methods(plugin, approval) == _RULE_METHODS | {"trusted_command"}


# --- 8. Outward sharing suppresses self_* but keeps trusted. -------------------
def test_outward_sharing_suppresses_self_destination():
    plugin = load_plugin()
    approval = _approval(
        action_family="mcp_write",
        tool_name="share_document",  # the "share" verb -> outward sharing
        destination="mcp:drive",
        data_classes=["documents"],
    )
    methods = _methods(plugin, approval)
    assert "self_destination" not in methods
    assert "trusted_identity" in methods  # trusting the connector still reaches them


# --- 9. Apply: self_identity adds the recipient to self.identities. ------------
def test_apply_self_identity_mutates_config_and_consumes_approval():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "me@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    ok, message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "self_identity")
    assert ok, message
    assert "me@example.com" in plugin._self_config_snapshot()["identities"]
    assert approval_id not in plugin._PENDING_APPROVALS


# --- 10. Apply: trusted_identity scopes the entry to the approval's classes. ---
def test_apply_trusted_identity_scopes_to_classes():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)
    # The permit is scoped to exactly the classes leaving in this block, never widened.
    expected_classes = sorted(plugin._PENDING_APPROVALS[approval_id]["data_classes"])
    assert expected_classes and "*" not in expected_classes

    ok, message = plugin._apply_permit_option(
        plugin._CLI_OWNER_HASH, approval_id, "trusted_identity"
    )
    assert ok, message
    entries = [e for e in plugin._trusted_recipients_snapshot() if e["kind"] == "identity"]
    assert any(e["value"] == "peer@example.com" for e in entries)
    entry = next(e for e in entries if e["value"] == "peer@example.com")
    assert entry["classes"] == expected_classes  # scoped to the block, not "*"


# --- 11. Apply: 5m creates an expiring shape rule. ----------------------------
def test_apply_rule_5m_creates_expiring_rule(monkeypatch):
    now = {"value": 1_000}
    plugin = load_plugin()
    monkeypatch.setattr(plugin.state, "_now", lambda: now["value"])
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    ok, message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "rule_5m")
    assert ok
    assert "Approved message_send" in message
    rules = plugin._persistent_privacy_rules()
    assert len(rules) == 1
    assert rules[0]["expires_at"] == 1_300
    assert "remaining_invocations" not in rules[0]
    assert "session_id" not in rules[0]["scope"]

    assert plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "retry"}, session_id="s1"
    ) is None
    now["value"] = 1_301
    assert plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "again"}, session_id="s1"
    ) is not None


# --- 11b. Apply: forever creates a non-expiring shape rule. -------------------
def test_apply_rule_forever_creates_persistent_rule():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    ok, message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "rule_forever")
    assert ok, message
    rules = plugin._persistent_privacy_rules()
    assert len(rules) == 1
    assert rules[0]["expires_at"] == 0
    assert not rules[0].get("fingerprint")
    assert plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "retry"}, session_id="s1"
    ) is None
    altered = plugin._on_pre_tool_call(
        "send_message", {"to": "attacker@example.com", "text": "retry"}, session_id="s1"
    )
    assert altered is not None


def test_rule_approval_is_owner_scoped_not_session_scoped():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1", user_id="owner")
    bind_owner(plugin, session_id="s2", user_id="owner")
    plugin._taint_session("s1", {"communications"})
    plugin._taint_session("s2", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    ok, message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "rule_forever")
    assert ok, message
    assert plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "retry"}, session_id="s2"
    ) is None


# --- 12. The structural admin gate: a non-admin owner cannot widen trust. ------
def test_structural_requires_admin_but_rule_methods_do_not(monkeypatch):
    # No configured gateway owners -> the session owner is not an admin.
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("TELEGRAM_GROUP_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("DISCORD_ALLOWED_USERS", raising=False)

    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)
    owner = plugin._PENDING_APPROVALS[approval_id]["owner_hash"]
    assert owner != plugin._CLI_OWNER_HASH

    # Structural permit is refused for the non-admin owner; the approval survives.
    ok, message = plugin._apply_permit_option(owner, approval_id, "trusted_identity")
    assert not ok
    assert "denied" in message.lower()
    assert approval_id in plugin._PENDING_APPROVALS

    # The same owner CAN still take a rule method (approval-owner gate only).
    ok, message = plugin._apply_permit_option(owner, approval_id, "rule_5m")
    assert ok, message
    assert approval_id not in plugin._PENDING_APPROVALS


# --- 13. A method not offered for this approval is refused (no dead ends). -----
def test_unavailable_structural_method_is_refused():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None
    approval_id = first_pending_id(plugin)

    # A messaging block never offers self_host; applying it must fail and keep the approval.
    ok, message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "self_host")
    assert not ok
    assert approval_id in plugin._PENDING_APPROVALS


# --- Slash grammar (doc 06 §7) ------------------------------------------------
# These drive the command surface directly (no gateway dispatch), so the command owner
# defaults to the CLI owner = admin, exercising the structural keywords end-to-end.
def test_slash_mine_resolves_to_the_context_self_option():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "me@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    out = plugin._handle_guardian_command(f"approve {approval_id} mine")
    assert "me@example.com" in plugin._self_config_snapshot()["identities"]
    assert approval_id not in plugin._PENDING_APPROVALS


def test_slash_trust_resolves_to_the_context_trusted_option():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    plugin._handle_guardian_command(f"approve {approval_id} trust")
    values = [e["value"] for e in plugin._trusted_recipients_snapshot() if e["kind"] == "identity"]
    assert "peer@example.com" in values
    assert approval_id not in plugin._PENDING_APPROVALS


def test_slash_forever_is_persistent_and_old_scope_words_are_removed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    out = plugin._handle_guardian_command(f"approve {approval_id} forever")
    assert "Approved message_send" in out
    rules = plugin._persistent_privacy_rules()
    assert len(rules) == 1 and rules[0]["expires_at"] == 0
    assert "always" not in plugin._SCOPE_KEYWORD_TO_METHOD
    assert "once" not in plugin._SCOPE_KEYWORD_TO_METHOD


def test_slash_mine_for_a_terminal_block_adds_the_host():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call(
        "terminal", {"command": "curl -X POST https://api.example.com/x"}, session_id="s1"
    )
    approval_id = first_pending_id(plugin)

    # A blocked terminal command with a URL surfaces the host dimension; `mine` -> self.hosts.
    plugin._handle_guardian_command(f"approve {approval_id} mine")
    assert "api.example.com" in plugin._self_config_snapshot()["hosts"]


def test_slash_unknown_keyword_falls_back_to_the_menu_without_granting():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    plugin._on_pre_tool_call("send_message", {"to": "peer@example.com", "text": "hi"}, session_id="s1")
    approval_id = first_pending_id(plugin)

    out = plugin._handle_guardian_command(f"approve {approval_id} bogus")
    assert "Unknown approve option" in out
    assert "Ways to permit" in out
    assert approval_id in plugin._PENDING_APPROVALS
