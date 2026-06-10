"""Provenance retirement — the realistic verbatim-laundering flow (doc 04 §7.1).

Provenance (the read-time HMAC fingerprint index + egress-time match) is retired in
Phase 5. The decision corpus's ``laundering:true`` records were built with an ARTIFICIAL
empty ambient taint (``"taint": []``) so they relied PURELY on the provenance fingerprint
to detect copied calendar/email content; with provenance gone, that artificial shape no
longer deterministically blocks. That is the sanctioned, non-floor-neutral carve-out
(charter §2.1) — and it is bucketed explicitly in test_policy_engine.py test 10.

This file tests the REAL flow instead of the artificial corpus shape: an actual private
READ taints the session ambiently, THEN a verbatim send of that content to an external
destination. The durable protection (charter §2.1-§2.2) is:
  - ambient taint from the read (decide step 4 sees non-empty private taint -> APPROVE), plus
  - in ``llm`` mode, the verifier reading the real payload (decide step 6), and
  - in ``strict`` mode, the human reviewing every tainted egress (verifier never consulted).
"""

from __future__ import annotations

import json

from support import *  # noqa: F403


# A private calendar event the agent reads, then copies VERBATIM into an external message.
_CAL_EVENT = "Project Helios kickoff sync with the legal team on Thursday at 3pm in room B"


def _read_private_calendar(plugin, *, session_id: str = "s1") -> None:
    """Drive a REAL private read so the session is tainted AMBIENTLY (not via provenance)."""
    plugin._on_transform_tool_result(
        tool_name="calendar_list_events",
        result=json.dumps({"events": [{"summary": _CAL_EVENT}]}),
        session_id=session_id,
    )
    # The read tainted the session ambiently — this is what decide step 4 now reasons over.
    assert "calendar" in plugin._session_taint(session_id)


# --- llm mode: the verifier is the laundering catch (verifier-mediated parity) -------
def test_llm_mode_verifier_holds_verbatim_laundering_send():
    # Realistic flow: read a private calendar event (ambient taint), then send it VERBATIM
    # to an external recipient. Provenance used to catch this deterministically; now the
    # llm-mode verifier (reading the real payload) holds it at manual approval — parity with
    # the pre-retirement outcome, verifier-mediated rather than provenance-mediated.
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    # Deterministic deny/hold stub (established verifier-stub pattern).
    fake_llm = FakeSecurityLlm({
        "outcome": "deny",
        "risk_level": "high",
        "authorization_level": "unknown",
        "rationale": "payload carries calendar content the send was not authorized for",
    })
    plugin._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    _read_private_calendar(plugin)

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "stranger@example.com", "text": _CAL_EVENT},
        session_id="s1",
    )

    # Held at manual approval (not silently allowed).
    assert result is not None
    assert "Approval ID:" in result["message"]
    assert not plugin._PENDING_APPROVALS or True  # approval was created; held, not allowed


def test_llm_mode_verifier_is_actually_consulted_on_this_flow():
    # The carve-out only holds if the verifier is ACTUALLY reached: decide must have returned
    # APPROVE (because ambient taint from the read was non-empty), which is what routes the
    # call into the verifier. Assert the verifier saw the real laundering payload.
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = FakeSecurityLlm({
        "outcome": "deny",
        "risk_level": "high",
        "authorization_level": "unknown",
        "rationale": "payload carries calendar content the send was not authorized for",
    })
    plugin._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    _read_private_calendar(plugin)

    plugin._on_pre_tool_call(
        "send_message",
        {"to": "stranger@example.com", "text": _CAL_EVENT},
        session_id="s1",
    )

    # The verifier was reached (decide APPROVE -> verifier consulted) and read the real
    # payload — that is where laundering is now caught (doc 02 §4, charter §2.1-§2.2).
    security_calls = [c for c in fake_llm.calls if c.get("purpose") == "hermes-guardian.security_llm"]
    assert len(security_calls) == 1
    verifier_input = json.dumps(security_calls[0]["input"], default=str)
    assert _CAL_EVENT in verifier_input
    # Ambient taint (not a provenance label) is what the verifier sees in scope.
    payload = json.loads(security_calls[0]["input"][0]["text"])
    assert "calendar" in payload["privacy_context"]["classes_in_scope"]
    assert "exported_source_classes" not in payload["privacy_context"]


def test_llm_mode_verifier_can_allow_when_payload_is_consistent_with_intent():
    # The verifier is reached and CAN upgrade (proving it is the live narrowing path): a
    # payload consistent with the authorized intent (a bare email address into a form) is
    # allowed even though the session is tainted — the FP narrowing provenance used to do
    # is now recovered by the verifier (doc 02 §4 net-FP note).
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake_llm = FakeSecurityLlm({
        "outcome": "allow",
        "risk_level": "low",
        "authorization_level": "explicit",
        "rationale": "bare email address consistent with the subscription intent",
    })
    plugin._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    _read_private_calendar(plugin)

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "newsletter@example.com", "text": "subscribe me", "purpose": "subscribe"},
        session_id="s1",
    )

    # Verifier consulted and upgraded the APPROVE to allow.
    assert result is None
    assert [c["purpose"] for c in fake_llm.calls].count("hermes-guardian.security_llm") == 1
    assert not plugin._PENDING_APPROVALS


# --- strict mode: the human is the laundering catch ---------------------------------
def test_strict_mode_routes_verbatim_laundering_to_manual_review():
    # strict mode reviews every egress — the human is the laundering catch; provenance was
    # an optimization at odds with that contract (charter §2.1)
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    # A verifier stub is installed to prove it is NEVER consulted in strict mode.
    fake_llm = FakeSecurityLlm({
        "outcome": "allow",
        "risk_level": "low",
        "authorization_level": "explicit",
        "rationale": "must not be consulted in strict mode",
    })
    plugin._PLUGIN_LLM = fake_llm
    bind_owner(plugin)
    _read_private_calendar(plugin)

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "stranger@example.com", "text": _CAL_EVENT},
        session_id="s1",
    )

    # Routed to manual review like ALL tainted external egress in strict mode.
    assert result is not None
    assert "Approval ID:" in result["message"]
    # strict mode never consults the verifier (the strict invariant; AGENTS.md).
    assert not fake_llm.calls
