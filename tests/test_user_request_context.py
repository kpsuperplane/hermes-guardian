"""Tests for owner-scoped user-request context fed to the LLM verifier.

The LLM privacy verifier is otherwise blind to the conversation. These tests
cover the narrow authorization-evidence channel: the most recent inbound message
from an authenticated session owner, captured at gateway dispatch, sanitized, and
attached to the verdict input as `user_request_context`. It must never appear for
group/cron/unauthenticated origins, never carry raw PII, and never be persisted.
"""

from __future__ import annotations

import json

from support import *  # noqa: F403

_NEWSLETTER_REQUEST = (
    "I want to subscribe to this newsletter, can you submit this form for me? "
    "https://docs.google.com/forms/d/abc123/edit"
)


def _allow_llm():
    return FakeSecurityLlm({
        "outcome": "allow",
        "risk_level": "high",
        "authorization_level": "explicit",
        "rationale": "user explicitly asked to submit this newsletter form",
    })


def _deny_llm():
    return FakeSecurityLlm({
        "outcome": "deny",
        "risk_level": "high",
        "authorization_level": "unknown",
        "rationale": "no evidence of authorization",
    })


def _submit_form(plugin, session_id="s1"):
    return plugin._on_pre_tool_call(
        "browser_type",
        {"text": "reader@example.com", "selector": "#email"},
        session_id=session_id,
    )


def test_authenticated_owner_request_is_attached_and_enables_allow(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = _allow_llm()
    plugin._PLUGIN_LLM = fake_llm

    plugin._on_pre_gateway_dispatch(gateway_event(_NEWSLETTER_REQUEST, user_id="owner"))
    bind_owner(plugin)
    plugin._taint_session("s1", {"email", "contacts"})

    result = _submit_form(plugin)

    assert result is None
    assert not plugin._PENDING_APPROVALS
    payload = json.loads(fake_llm.calls[0]["input"][0]["text"])
    request = payload["user_request_context"]["sanitized_user_request"]
    assert "newsletter" in request
    assert "submit this form" in request


def test_unauthenticated_sender_request_is_not_attached(monkeypatch):
    # No configured owner: a gateway message is not trusted as authorization.
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = _deny_llm()
    plugin._PLUGIN_LLM = fake_llm

    plugin._on_pre_gateway_dispatch(gateway_event(_NEWSLETTER_REQUEST, user_id="stranger"))
    bind_owner(plugin, user_id="stranger")
    plugin._taint_session("s1", {"email"})

    _submit_form(plugin)

    payload = json.loads(fake_llm.calls[0]["input"][0]["text"])
    assert "user_request_context" not in payload


def test_non_owner_in_group_cannot_authorize_for_owner(monkeypatch):
    # Owner is owner; an unrelated group participant's message must not become
    # authorization evidence for the owner's session.
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = _deny_llm()
    plugin._PLUGIN_LLM = fake_llm

    plugin._on_pre_gateway_dispatch(gateway_event(_NEWSLETTER_REQUEST, user_id="attacker"))
    bind_owner(plugin)  # session owned by owner
    plugin._taint_session("s1", {"email"})

    _submit_form(plugin)

    payload = json.loads(fake_llm.calls[0]["input"][0]["text"])
    assert "user_request_context" not in payload


def test_security_sensitive_message_is_not_cached(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()

    plugin._on_pre_gateway_dispatch(
        gateway_event("My password reset code is 123456", user_id="owner")
    )

    owner_hash = plugin._hash_identity("telegram", "owner")
    assert plugin._recent_user_request_for_owner(owner_hash) == ""


def test_cached_request_redacts_pii_before_storage(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = _allow_llm()
    plugin._PLUGIN_LLM = fake_llm

    plugin._on_pre_gateway_dispatch(
        gateway_event("sign me up with alice@example.com for the newsletter", user_id="owner")
    )
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    _submit_form(plugin)

    payload = json.loads(fake_llm.calls[0]["input"][0]["text"])
    encoded = json.dumps(payload, sort_keys=True)
    assert "alice@example.com" not in encoded
    assert "<email>" in payload["user_request_context"]["sanitized_user_request"]


def test_user_request_is_never_persisted(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    plugin._PLUGIN_LLM = _deny_llm()

    plugin._on_pre_gateway_dispatch(gateway_event(_NEWSLETTER_REQUEST, user_id="owner"))
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    _submit_form(plugin)

    # Denied -> a pending approval exists; neither it nor activity rows may carry
    # the user request text.
    for approval in plugin._PENDING_APPROVALS.values():
        assert "newsletter" not in json.dumps(approval).lower()
    for row in plugin._activity_rows({}, limit=10):
        assert "newsletter" not in json.dumps(row).lower()


def test_stale_request_beyond_ttl_is_ignored(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = _deny_llm()
    plugin._PLUGIN_LLM = fake_llm

    plugin._on_pre_gateway_dispatch(gateway_event(_NEWSLETTER_REQUEST, user_id="owner"))
    owner_hash = plugin._hash_identity("telegram", "owner")
    # Age the cached entry past its TTL.
    timestamp, text = plugin._RECENT_OWNER_REQUESTS[owner_hash]
    plugin._RECENT_OWNER_REQUESTS[owner_hash] = (
        timestamp - plugin._USER_REQUEST_TTL_SECONDS - 1,
        text,
    )

    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})
    _submit_form(plugin)

    payload = json.loads(fake_llm.calls[0]["input"][0]["text"])
    assert "user_request_context" not in payload
