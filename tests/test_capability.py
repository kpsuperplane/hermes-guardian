"""Capability classifier tests (doc 02 §9, capability-side).

These drive ``classify`` (and the policy/tag split, doc 02 §5) through the facade. The
decision-engine tests live in ``test_policy_engine.py``; the corpus floor gate (test 10)
lives there too.
"""

from __future__ import annotations

from support import *  # noqa: F403


def _trust(plugin):
    return plugin._DestinationTrust


def test_classify_mcp_connector_write_is_connector_kind_not_self():
    # An MCP connector write resolves under the distinct `mcp` kind, NOT the first-party
    # store kind. By default (no explicit `mcp:notion` self entry) it is not self, so a
    # malicious server naming its tool `mcp_notion_*` cannot impersonate a seeded store.
    plugin = load_plugin()
    cap = plugin._classify("mcp_notion_create_page", {"title": "Contact notes"}, "s1")
    assert cap.direction == "write"
    assert cap.destination.kind == "mcp"
    assert cap.destination.id == "notion"
    assert cap.destination.trust in {
        _trust(plugin).UNKNOWN,
        _trust(plugin).EXTERNAL,
    }


def test_classify_mcp_connector_write_is_self_when_explicitly_listed():
    # When the operator EXPLICITLY adds the connector to the self allowlist, an MCP
    # write to it resolves to self.
    plugin = load_plugin()
    plugin._save_privacy_config({
        "version": plugin._PRIVACY_RULE_FILE_VERSION,
        "self": {"destinations": ["store:files", "mcp:notion"], "identities": [], "hosts": []},
    })
    cap = plugin._classify("mcp_notion_create_page", {"title": "Contact notes"}, "s1")
    assert cap.direction == "write"
    assert cap.destination.kind == "mcp"
    assert cap.destination.id == "notion"
    assert cap.destination.trust == _trust(plugin).SELF


def test_classify_external_send_resolves_external():
    plugin = load_plugin()
    cap = plugin._classify(
        "send_message", {"to": "stranger@example.com", "text": "hi"}, "s1"
    )
    assert cap.direction == "write"
    assert cap.destination.kind == "messaging"
    assert cap.destination.trust == _trust(plugin).EXTERNAL


def test_classify_local_write_resolves_intra_boundary():
    plugin = load_plugin()
    cap = plugin._classify("write_file", {"path": "/tmp/x", "content": "y"}, "s1")
    assert cap.direction == "write"
    assert cap.destination.trust in {
        _trust(plugin).SELF,
        _trust(plugin).LOCAL_SYSTEM,
    }


def test_classify_unknown_tool_under_taint_is_external():
    plugin = load_plugin()
    plugin._taint_session("s1", {"communications"})
    cap = plugin._classify("frobnicate_widget", {"body": "hello"}, "s1")
    assert cap.direction == "write"
    # Unknown tool -> store-kind id not in self allowlist -> unknown -> treated external.
    assert cap.destination.trust in {
        _trust(plugin).UNKNOWN,
        _trust(plugin).EXTERNAL,
    }


def test_classify_read_direction_for_non_sink():
    plugin = load_plugin()
    # An MCP read with NO session taint is not a sink (no tainted query to leak) ->
    # read direction (charter invariant #3: reads never egress).
    cap = plugin._classify("mcp_gmail_search_threads", {"query": "hi"}, "s1")
    assert cap.direction == "read"


def test_policy_class_collapse_keeps_fine_tag():
    plugin = load_plugin()
    plugin._taint_session("s1", {"communications"})
    cap = plugin._classify(
        "send_message", {"to": "stranger@example.com", "text": "summary"}, "s1"
    )
    # Fine class collapses to the single policy class...
    assert "personal_private" in cap.data_classes
    # ...while the fine class is preserved as a descriptive tag (invariant #6).
    assert "communications" in cap.data_tags


def test_policy_and_tag_constant_split():
    plugin = load_plugin()
    assert plugin._PRIVATE_POLICY_CLASSES == frozenset({"personal_private"})
    assert plugin._POLICY_CLASSES == frozenset(
        {"personal_private", "local_system", "browser_private", "public"}
    )
    assert plugin._DATA_TAGS == frozenset(
        {"communications", "contacts", "calendar", "documents", "memory"}
    )


def test_share_subtype_on_self_store_resolves_external():
    plugin = load_plugin()
    # A publish/share verb reaches other parties even on a self connector (doc 01 §3.1).
    cap = plugin._classify(
        "mcp_notion_share_page",
        {"page_id": "page_synthetic_1", "email": "stranger@example.com"},
        "s1",
    )
    assert cap.destination.trust == _trust(plugin).EXTERNAL
