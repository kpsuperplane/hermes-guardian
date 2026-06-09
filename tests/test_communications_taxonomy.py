"""Taxonomy split (email -> contacts + communications) and confidence-gated
browser tainting.

A bare email address is an identifier (contacts); message bodies / email-record
headers are correspondence content (communications). Web/browser reads only taint
on contact-shaped content when the host carries private context, and never on
business/public-facing addresses (support@…, hello@kevinpei.com).
"""

from __future__ import annotations

import json

from support import *  # noqa: F403


# --- taxonomy split -------------------------------------------------------

def test_bare_email_address_classifies_as_contacts():
    plugin = load_plugin()
    bind_owner(plugin)
    classes = plugin._data_classes_for_egress("s1", {"text": "reach me at jane@gmail.com"})
    assert classes == {"contacts"}


def test_email_record_headers_classify_as_communications():
    plugin = load_plugin()
    bind_owner(plugin)
    text = "From: Alice\nSubject: Q3 plans\nUnread: 3"
    classes = plugin._data_classes_for_egress("s1", {"text": text})
    assert classes == {"communications"}


def test_message_tool_result_taints_communications():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._on_transform_tool_result(
        tool_name="read_inbox",
        result=json.dumps({"messages": ["hi there"]}),
        session_id="s1",
    )
    assert plugin._session_taint("s1") == {"communications"}


def test_contacts_tool_result_still_taints_contacts():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._on_transform_tool_result(
        tool_name="mcp_dex_search",
        result=json.dumps({"people": [{"name": "Alice"}]}),
        session_id="s1",
    )
    assert plugin._session_taint("s1") == {"contacts"}


# --- ambient-business-email predicate ------------------------------------

def test_email_is_ambient_business_predicate():
    plugin = load_plugin()
    assert plugin._email_is_ambient_business("support@gmail.com") is True   # role mailbox
    assert plugin._email_is_ambient_business("hello@kevinpei.com") is True  # role + vanity domain
    assert plugin._email_is_ambient_business("kevin@kevinpei.com") is True  # vanity domain
    assert plugin._email_is_ambient_business("jane@gmail.com") is False     # personal consumer
    assert plugin._email_is_ambient_business("john.smith@outlook.com") is False


# --- confidence-gated browser tainting -----------------------------------

def test_public_browser_page_business_email_does_not_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://acme.com/contact")
    plugin._on_transform_tool_result(
        tool_name="browser_navigate",
        result="Questions? Email support@acme.com or hello@kevinpei.com",
        session_id="s1",
    )
    assert plugin._session_taint("s1") == set()


def test_public_browser_page_personal_email_does_not_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://forum.example.com/thread")
    plugin._on_transform_tool_result(
        tool_name="browser_navigate",
        result="A user posted: ping me at jane@gmail.com",
        session_id="s1",
    )
    # No private context on a public host -> ambient contact signal suppressed.
    assert "contacts" not in plugin._session_taint("s1")


def test_private_browser_page_personal_email_taints_contacts():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://mail.example.com/inbox")
    plugin._mark_browser_private_input("s1")  # operator typed credentials on this host
    plugin._on_transform_tool_result(
        tool_name="browser_navigate",
        result="Your friend's address is jane@gmail.com",
        session_id="s1",
    )
    assert "contacts" in plugin._session_taint("s1")


def test_private_browser_page_business_email_still_suppressed():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://crm.example.com")
    plugin._mark_browser_private_input("s1")
    plugin._on_transform_tool_result(
        tool_name="browser_navigate",
        result="Reach the team at hello@kevinpei.com",
        session_id="s1",
    )
    assert "contacts" not in plugin._session_taint("s1")


def test_browser_ssn_taints_regardless_of_context():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://public.example.com")
    plugin._on_transform_tool_result(
        tool_name="browser_navigate",
        result="Leaked record: 123-45-6789",
        session_id="s1",
    )
    assert "documents" in plugin._session_taint("s1")


def test_bare_email_address_is_not_private_browser_context():
    plugin = load_plugin()
    # A public page's support@ address must not be read as proof of a logged-in
    # context, or it would defeat ambient-business-email suppression.
    assert plugin._browser_result_has_private_context("Email us at support@acme.com") is False
    assert plugin._browser_result_has_private_context("Welcome back — Sign out") is True


# --- legacy alias migration ----------------------------------------------

def test_legacy_email_class_in_persisted_rule_maps_to_communications():
    plugin = load_plugin()
    assert plugin._normalize_rule_classes(["email"]) == ["communications"]
    assert plugin._normalize_rule_classes(["email", "contacts"]) == ["communications", "contacts"]
