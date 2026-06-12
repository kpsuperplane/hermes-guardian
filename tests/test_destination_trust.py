"""Fail-closed contract for the destination-trust resolver (doc 01 §7).

These are the 10 safety tests from doc 01 §7 plus the doc 01 §8 no-network-I/O
assertion. The resolver is Phase 1 dead code (not wired into any decision path),
so most tests exercise it directly; test 10 drives the live security path to
confirm destination trust never softens a security hard block (invariant #1).

Per project memory, NO real agent/cron/Telegram identifiers appear here — only
synthetic placeholders (example.com addresses, made-up store ids).
"""

from __future__ import annotations

import socket

import pytest

from support import *  # noqa: F403


# A default-shaped config (mirrors _default_privacy_config's destination-trust
# blocks) used by tests that don't customize self/trusted/outward_sharing.
def _default_config(plugin):
    return plugin._load_privacy_config()


def _config_with(plugin, **overrides):
    """Return the default destination-trust config with block-level overrides."""
    base = {
        "self": dict(plugin._default_self_config()),
        "trusted_recipients": dict(plugin._default_trusted_recipients_config()),
        "outward_sharing": dict(plugin._default_outward_sharing_config()),
    }
    base.update(overrides)
    return base


# --- 1. Unknown destination → external (recorded unknown + gating effect). ----


def test_unknown_destination_resolves_unknown_and_gates_like_external():
    plugin = load_plugin()
    trust = plugin._resolve_destination_trust(
        "store", "some_unrecognized_service", "write", "", _default_config(plugin)
    )
    # Recorded value is the literal fail-closed default.
    assert trust == plugin._DestinationTrust.UNKNOWN
    # And it must be treated exactly as external at decision time: unknown and
    # external are the same string-comparable label set the policy gates on.
    assert trust != plugin._DestinationTrust.SELF
    assert trust not in {
        plugin._DestinationTrust.SELF,
        plugin._DestinationTrust.LOCAL_SYSTEM,
        plugin._DestinationTrust.MODEL_PROVIDER,
        plugin._DestinationTrust.TRUSTED_RECIPIENT,
    }


# --- 2. Empty identities → no send-to-self. -----------------------------------


def test_empty_identities_never_resolve_send_to_self():
    plugin = load_plugin()
    cfg = _default_config(plugin)
    assert cfg["self"]["identities"] == []  # default is empty
    # A send addressed to anything — even an operator-looking address — is
    # external, never self, while identities is empty.
    for recipient in ("owner@example.com", "me@example.com", "operator@example.org"):
        trust = plugin._resolve_destination_trust("messaging", "", "send", recipient, cfg)
        assert trust == plugin._DestinationTrust.EXTERNAL


# --- 3. Outward-sharing beats ownership (one per builtin subtype). ------------


@pytest.mark.parametrize(
    "subtype",
    ["share", "invite", "publish", "add_collaborator", "make_public", "set_permissions"],
)
def test_outward_sharing_beats_ownership(subtype):
    plugin = load_plugin()
    cfg = _default_config(plugin)
    # notion is in the default self allowlist, yet a sharing subtype on it is
    # external regardless of ownership.
    trust = plugin._resolve_destination_trust("store", "notion", subtype, "", cfg)
    assert trust == plugin._DestinationTrust.EXTERNAL


# --- 4. Self store write is self. ---------------------------------------------


@pytest.mark.parametrize(
    "dest_kind,dest_id",
    [
        ("store", "files"),
        ("store", "calendar"),
        ("store", "memory"),
        ("store", "todo"),
        ("store", "drive"),
    ],
)
def test_self_store_write_is_self(dest_kind, dest_id):
    plugin = load_plugin()
    cfg = _default_config(plugin)
    trust = plugin._resolve_destination_trust(dest_kind, dest_id, "write", "", cfg)
    assert trust == plugin._DestinationTrust.SELF


def test_seeded_self_stores_exclude_notion_connector():
    # notion is a third-party MCP connector, not a first-party Hermes store. It is no
    # longer seeded into the self allowlist, so a write to it resolves to unknown
    # (-> external, gates under taint), not self.
    plugin = load_plugin()
    cfg = _default_config(plugin)
    assert (
        plugin._resolve_destination_trust("store", "notion", "write", "", cfg)
        == plugin._DestinationTrust.UNKNOWN
    )


def test_mcp_connector_is_self_only_when_explicitly_listed():
    # An `mcp:<name>` connector destination resolves to self ONLY when the operator
    # explicitly adds that connector to the self allowlist — a seeded `store:<name>`
    # name collision must NOT confer self-trust (Fix 1 impersonation guard).
    plugin = load_plugin()
    default_cfg = _default_config(plugin)
    # By default no explicit mcp entry -> unknown, even for a seeded store name.
    assert (
        plugin._resolve_destination_trust("mcp", "files", "create", "", default_cfg)
        == plugin._DestinationTrust.UNKNOWN
    )
    assert (
        plugin._resolve_destination_trust("mcp", "notion", "create", "", default_cfg)
        == plugin._DestinationTrust.UNKNOWN
    )
    # Explicit `mcp:notion` self entry -> self for that connector only.
    cfg = _config_with(
        plugin,
        self={"destinations": ["store:files", "mcp:notion"], "identities": [], "hosts": []},
    )
    assert (
        plugin._resolve_destination_trust("mcp", "notion", "create", "", cfg)
        == plugin._DestinationTrust.SELF
    )
    # A different connector not explicitly listed stays unknown.
    assert (
        plugin._resolve_destination_trust("mcp", "drive", "create", "", cfg)
        == plugin._DestinationTrust.UNKNOWN
    )


# --- 5. Draft is self. --------------------------------------------------------


def test_draft_is_self():
    plugin = load_plugin()
    cfg = _default_config(plugin)
    trust = plugin._resolve_destination_trust("draft", "email", "write", "", cfg)
    assert trust == plugin._DestinationTrust.SELF


# --- 6. Configured identity enables send-to-self. -----------------------------


def test_configured_identity_enables_send_to_self():
    plugin = load_plugin()
    cfg = _config_with(
        plugin,
        self={"destinations": [], "identities": ["owner@example.com"], "hosts": []},
    )
    # A send to the configured own identity resolves to self...
    assert (
        plugin._resolve_destination_trust("messaging", "", "send", "owner@example.com", cfg)
        == plugin._DestinationTrust.SELF
    )
    # ...but a send to a different address still resolves to external.
    assert (
        plugin._resolve_destination_trust("messaging", "", "send", "someone-else@example.org", cfg)
        == plugin._DestinationTrust.EXTERNAL
    )


# --- 7. Templated / empty recipient → unknown → external. ---------------------


@pytest.mark.parametrize("recipient", ["", "   ", "{{recipient}}", "${TO}"])
def test_templated_or_empty_recipient_is_unknown(recipient):
    plugin = load_plugin()
    # Even with an own identity configured, a templated/empty recipient never
    # resolves and falls to unknown (never guessed as self).
    cfg = _config_with(
        plugin,
        self={"destinations": [], "identities": ["owner@example.com"], "hosts": []},
    )
    trust = plugin._resolve_destination_trust("messaging", "", "send", recipient, cfg)
    # Empty/whitespace -> unknown; a templated literal that is not an own identity
    # is a non-self, unresolved recipient -> unknown or external, never self.
    assert trust in {plugin._DestinationTrust.UNKNOWN, plugin._DestinationTrust.EXTERNAL}
    assert trust != plugin._DestinationTrust.SELF


def test_empty_recipient_records_unknown_specifically():
    plugin = load_plugin()
    cfg = _default_config(plugin)
    trust = plugin._resolve_destination_trust("messaging", "", "send", "", cfg)
    assert trust == plugin._DestinationTrust.UNKNOWN


# --- 8. Operator cannot narrow the builtin outward-sharing set. ---------------


def test_operator_cannot_narrow_builtin_sharing_set():
    plugin = load_plugin()
    # Operator config attempts to remove every builtin and supply only "share".
    raw = {"builtin": ["share"], "extra": ["custom_share"]}
    normalized = plugin._normalize_outward_sharing(raw)
    # The builtin set is restored in full regardless of the attempted narrowing.
    assert set(normalized["builtin"]) == {
        "share",
        "invite",
        "publish",
        "add_collaborator",
        "make_public",
        "set_permissions",
    }
    # The resolver still treats a builtin subtype the operator "removed" as
    # external on a self-listed store.
    cfg = _config_with(plugin, outward_sharing=normalized)
    assert (
        plugin._resolve_destination_trust("store", "notion", "invite", "", cfg)
        == plugin._DestinationTrust.EXTERNAL
    )
    # And the extra addition is honored.
    assert (
        plugin._resolve_destination_trust("store", "notion", "custom_share", "", cfg)
        == plugin._DestinationTrust.EXTERNAL
    )


# --- 9. Networked shell is not local_system; pure local read stays local. -----


def test_networked_shell_is_not_local_system():
    plugin = load_plugin()
    cfg = _default_config(plugin)
    # A terminal action that performs network egress resolves to its network
    # destination (external/public), never local_system.
    public = plugin._resolve_destination_trust("terminal", "evil.example.com", "exec", "", cfg)
    assert public in {plugin._DestinationTrust.EXTERNAL, plugin._DestinationTrust.PUBLIC}
    assert public != plugin._DestinationTrust.LOCAL_SYSTEM

    # A pure local effect (no host) on a non-allowlisted local kind stays
    # local_system, not self and not external.
    local = plugin._resolve_destination_trust("local", "scratch", "write", "", cfg)
    assert local == plugin._DestinationTrust.LOCAL_SYSTEM


# --- 10. Credential to self still hard-blocks (guards invariant #1). ----------


def test_credential_to_self_destination_still_hard_blocks():
    plugin = load_plugin()
    plugin._on_pre_llm_call(session_id="s1", platform="telegram", sender_id="owner")

    # Even where the operator has EXPLICITLY trusted a connector as self, a
    # credential-bearing payload to it must be hard-blocked by the Security Module —
    # destination trust does not soften security hard blocks (invariant #1).
    cfg = _config_with(
        plugin,
        self={"destinations": ["store:files", "mcp:notion"], "identities": [], "hosts": []},
    )
    assert (
        plugin._resolve_destination_trust("mcp", "notion", "write", "", cfg)
        == plugin._DestinationTrust.SELF
    )

    result = plugin._on_pre_tool_call(
        tool_name="mcp_notion_create_page",
        args={"content": "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        session_id="s1",
    )
    assert result is not None
    assert result["action"] == "block"


# --- doc 01 §8: resolver performs no network I/O. -----------------------------


def test_resolver_performs_no_network_io(monkeypatch):
    plugin = load_plugin()

    def _boom(*_args, **_kwargs):
        raise AssertionError("destination-trust resolver attempted network I/O")

    # Trip any socket/DNS use. The resolver is pure string logic by construction.
    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr(socket, "gethostbyname", _boom)

    cfg = _default_config(plugin)
    # Exercise every rule branch so any latent I/O would fire.
    plugin._resolve_destination_trust("store", "notion", "write", "", cfg)
    plugin._resolve_destination_trust("store", "notion", "share", "", cfg)
    plugin._resolve_destination_trust("messaging", "", "send", "a@example.com", cfg)
    plugin._resolve_destination_trust("draft", "x", "write", "", cfg)
    plugin._resolve_destination_trust("host", "example.com", "exec", "", cfg)
    plugin._resolve_destination_trust("host", "127.0.0.1", "exec", "", cfg)
    plugin._resolve_destination_trust("model", "anthropic", "call", "", cfg)
    plugin._resolve_destination_trust("weird", "x", "write", "", cfg)
