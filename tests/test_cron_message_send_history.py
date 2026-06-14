"""Regression: a cron message_send blocked for approval must be recorded in
dashboard history, not only delivered to chat.

Reproduces the incident where the chat notification fired ("requires approval
(llm unknown: LLM verifier unavailable)") but no activity row reached the
dashboard DB, so the block was invisible in History / Recent Blocks.
"""
from __future__ import annotations

import re

from support import *  # noqa: F403


def test_cron_message_send_block_recorded_in_dashboard_history(monkeypatch):
    plugin = load_plugin()
    cron_session = "cron_aaaaaaaaaaaa_20260608_093642"

    # Incident conditions: llm mode (default) with the verifier unavailable.
    assert plugin._egress_safety_policy() == "llm"
    plugin.state._PLUGIN_LLM = None  # -> "LLM verifier unavailable"

    # Pin the notify target so the test is hermetic: the default "origin"
    # policy resolves targets from the host's ~/.hermes/cron/jobs.json, which
    # is absent on CI runners (no target -> no notification thread).
    monkeypatch.setenv("HERMES_GUARDIAN_CRON_NOTIFY_TO", "telegram:guardian-test")

    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(
        plugin.cron_notifications,
        "_cron_job_name",
        lambda _job_id: "Example Availability Check",
    )
    monkeypatch.setattr(
        plugin.cron_notifications,
        "_send_cron_notification_message",
        lambda message, target: sent.append((message, target)),
    )

    bind_owner(plugin, session_id=cron_session)
    plugin._taint_session(cron_session, {"communications"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "availability report"},
        session_id=cron_session,
    )

    # 1. Blocked, and the chat notification the user already receives.
    assert result is not None and result["action"] == "block"
    assert wait_for(lambda: len(sent) == 1)
    message, _target = sent[0]
    approval = re.search(r"(?m)^/guardian approve (\d{4}) forever$", message)
    assert approval, message
    approval_id = approval.group(1)
    assert "Action: message_send" in message
    assert "LLM verifier unavailable" in message

    # 2. Recorded in dashboard History (the datatables table view).
    payload = plugin._activity_datatables_payload(
        {"draw": "1", "start": "0", "length": "25"}
    )
    history = [r for r in payload["data"] if r["action_family"] == "message_send"]
    assert len(history) == 1, payload["data"]
    assert history[0]["decision"] == "blocked"
    assert history[0]["approval_id"] == approval_id
    assert "LLM verifier unavailable" in history[0]["reason"]

    # 3. Shown in the Recent Blocks widget, and the approval is resolvable.
    blocks = plugin._dashboard_recent_blocks(list(plugin._PENDING_APPROVALS.values()))
    assert any(b["action_family"] == "message_send" and b["pending"] for b in blocks)
    assert approval_id in plugin._PENDING_APPROVALS
