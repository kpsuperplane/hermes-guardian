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


def test_cron_block_sends_one_sanitized_home_channel_notification(monkeypatch):
    plugin = load_plugin()
    sent = []
    cron_session = "cron_41c2974734f8_20260607_030107"

    monkeypatch.setenv("HERMES_GUARDIAN_CRON_NOTIFY_TO", "telegram")
    monkeypatch.setattr(plugin._CORE, "_cron_job_name", lambda _job_id: "Ritz-Carlton AX 2026 availability check")
    monkeypatch.setattr(
        plugin._CORE,
        "_send_cron_notification_message",
        lambda message, target: sent.append((message, target)),
    )
    bind_owner(plugin, session_id=cron_session)
    plugin._taint_session(cron_session, {"email"})

    first = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "raw private sentence must not appear"},
        session_id=cron_session,
    )
    second = plugin._on_pre_tool_call(
        "browser_type",
        {"text": "another raw private sentence"},
        session_id=cron_session,
    )

    assert first is not None
    assert second is not None
    assert wait_for(lambda: len(sent) == 1)
    message, target = sent[0]
    assert target == "telegram"
    assert "Hermes Guardian blocked a cron job action." in message
    assert "Job: Ritz-Carlton AX 2026 availability check" in message
    assert "Job ID: 41c2974734f8" in message
    assert "Action: message_send" in message
    assert "Destination: friend" in message
    assert "Data classes: email" in message
    assert "Approval ID:" not in message
    assert "Decision:" not in message
    assert "Approve future runs:" not in message
    assert "Approve only this run:" not in message
    assert re.search(r"(?m)^/guardian approve \d{4} always$", message)
    assert " always" in message
    assert " once" not in message
    assert "Review: /guardian failures" not in message
    assert "raw private sentence" not in message


def test_cron_notification_defaults_to_job_delivery_targets(monkeypatch):
    plugin = load_plugin()
    sent = []
    cron_session = "cron_41c2974734f8_20260607_030107"

    monkeypatch.setattr(
        plugin._CORE,
        "_cron_job_record",
        lambda _job_id: {
            "id": "41c2974734f8",
            "name": "Ritz-Carlton AX 2026 availability check",
            "deliver": ["telegram:-1003947695146:75", "local"],
        },
    )
    monkeypatch.setattr(
        plugin._CORE,
        "_send_cron_notification_message",
        lambda message, target: sent.append((message, target)),
    )
    bind_owner(plugin, session_id=cron_session)
    plugin._taint_session(cron_session, {"email"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello"},
        session_id=cron_session,
    )

    assert result is not None
    assert wait_for(lambda: len(sent) == 1)
    message, target = sent[0]
    assert target == "telegram:-1003947695146:75"
    assert "Job: Ritz-Carlton AX 2026 availability check" in message


def test_cron_notification_uses_telegram_copy_button_sender(monkeypatch):
    plugin = load_plugin()
    sent = []

    monkeypatch.setattr(
        plugin._CORE,
        "_send_telegram_cron_notification_message",
        lambda message, target, approval_id: sent.append((message, target, approval_id)) or True,
    )
    monkeypatch.setattr(
        plugin._CORE.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("telegram copy-button sender should avoid CLI fallback"),
    )

    plugin._send_cron_notification_message(
        "Hermes Guardian blocked a cron job action.\n\n/guardian approve 1234 always\n",
        "telegram:-1003947695146:75",
    )

    assert sent == [(
        "Hermes Guardian blocked a cron job action.\n\n/guardian approve 1234 always\n",
        "telegram:-1003947695146:75",
        "/guardian approve 1234 always",
    )]


def test_cron_notification_telegram_copy_markup_has_one_approval_button(monkeypatch):
    plugin = load_plugin()

    class FakeCopyTextButton:
        def __init__(self, text):
            self.text = text

    class FakeInlineKeyboardButton:
        def __init__(self, text, copy_text=None):
            self.text = text
            self.copy_text = copy_text

    class FakeInlineKeyboardMarkup:
        def __init__(self, rows):
            self.rows = rows

    monkeypatch.setitem(
        sys.modules,
        "telegram",
        SimpleNamespace(
            CopyTextButton=FakeCopyTextButton,
            InlineKeyboardButton=FakeInlineKeyboardButton,
            InlineKeyboardMarkup=FakeInlineKeyboardMarkup,
        ),
    )

    markup = plugin._telegram_copy_reply_markup("/guardian approve 1234 always")

    assert len(markup.rows) == 1
    assert len(markup.rows[0]) == 1
    button = markup.rows[0][0]
    assert button.text == "Copy approval"
    assert button.copy_text.text == "/guardian approve 1234 always"


def test_cron_notification_falls_back_to_cli_when_telegram_copy_sender_fails(monkeypatch):
    plugin = load_plugin()
    calls = []

    monkeypatch.setattr(plugin._CORE, "_send_telegram_cron_notification_message", lambda *_args: False)
    monkeypatch.setattr(
        plugin._CORE.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)),
    )

    plugin._send_cron_notification_message(
        "Hermes Guardian blocked a cron job action.\n\n/guardian approve 1234 always\n",
        "telegram:-1003947695146:75",
    )

    assert calls
    command, kwargs = calls[0]
    assert command == [plugin._hermes_cli_path(), "send", "--to", "telegram:-1003947695146:75", "--quiet", "--file", "-"]
    assert kwargs["input"] == "Hermes Guardian blocked a cron job action.\n\n/guardian approve 1234 always\n"


def test_cron_notification_can_be_disabled(monkeypatch):
    plugin = load_plugin()
    sent = []
    cron_session = "cron_41c2974734f8_20260607_030107"

    monkeypatch.setenv("HERMES_GUARDIAN_CRON_NOTIFY_TO", "off")
    monkeypatch.setattr(
        plugin._CORE,
        "_send_cron_notification_message",
        lambda message, target: sent.append((message, target)),
    )
    bind_owner(plugin, session_id=cron_session)
    plugin._taint_session(cron_session, {"email"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello"},
        session_id=cron_session,
    )

    assert result is not None
    time.sleep(0.05)
    assert sent == []


def test_non_cron_block_does_not_send_cron_notification(monkeypatch):
    plugin = load_plugin()
    sent = []

    monkeypatch.setenv("HERMES_GUARDIAN_CRON_NOTIFY_TO", "telegram")
    monkeypatch.setattr(
        plugin._CORE,
        "_send_cron_notification_message",
        lambda message, target: sent.append((message, target)),
    )
    bind_owner(plugin)
    plugin._taint_session("s1", {"email"})

    result = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "hello"},
        session_id="s1",
    )

    assert result is not None
    time.sleep(0.05)
    assert sent == []
