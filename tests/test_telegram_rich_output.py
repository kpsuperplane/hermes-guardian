from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from support import *  # noqa: F403


def _dispatch_command(plugin, raw: str, *, platform: str = "telegram", user_id: str = "owner") -> str:
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian {raw}", platform=platform, user_id=user_id))
    return plugin._handle_guardian_command(raw)


def test_telegram_status_uses_rich_markdown_but_discord_stays_plain():
    plugin = load_plugin()

    telegram = _dispatch_command(plugin, "status", platform="telegram")
    discord = _dispatch_command(plugin, "status", platform="discord")

    assert telegram.startswith("## Hermes Guardian Status")
    assert "| Signal | Value |" in telegram
    assert "Privacy mode" in telegram
    assert discord.startswith("Hermes Guardian status")
    assert "| Signal | Value |" not in discord
    assert not discord.startswith("##")


def test_telegram_approvals_and_permit_menu_are_rich_and_sanitized():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1", user_id="owner")
    plugin._taint_session("s1", {"communications"})

    blocked = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "raw private sentence must not appear"},
        session_id="s1",
    )
    assert blocked is not None
    approval_id = next(iter(plugin.state._PENDING_APPROVALS))

    approvals = _dispatch_command(plugin, "approvals", platform="telegram")
    menu = _dispatch_command(plugin, f"approve {approval_id}", platform="telegram")

    assert approvals.startswith("## Pending Guardian Approvals")
    assert "| ID | Action | Destination | Trust | Classes |" in approvals
    assert approval_id in approvals
    assert "raw private sentence" not in approvals
    assert menu.startswith(f"## Permit Approval {approval_id}")
    assert "| Command | Scope | Admin |" in menu
    assert f"`/guardian approve {approval_id} 5m`" in menu
    assert "<details>" in menu
    assert "raw private sentence" not in menu


def test_local_direct_command_does_not_use_telegram_rich_output():
    plugin = load_plugin()

    output = plugin._handle_guardian_command("review")

    assert output.startswith("Privacy mode:")
    assert "| Setting | Value |" not in output


def test_telegram_activity_and_why_use_rich_shapes_without_raw_payload():
    plugin = load_plugin()
    bind_owner(plugin, session_id="s1", user_id="owner")
    plugin._taint_session("s1", {"communications"})
    blocked = plugin._on_pre_tool_call(
        "send_message",
        {"to": "friend", "text": "raw private sentence must not appear"},
        session_id="s1",
    )
    assert blocked is not None
    approval_id = next(iter(plugin.state._PENDING_APPROVALS))

    activity = _dispatch_command(plugin, "activity", platform="telegram")
    why = _dispatch_command(plugin, f"why {approval_id}", platform="telegram")

    assert activity.startswith("## Guardian Activity")
    assert "- [ ] **send_message**" in activity
    assert "raw private sentence" not in activity
    assert why.startswith(f"## Guardian Decision {approval_id}")
    assert "| Field | Value |" in why
    assert "<details>" in why
    assert "raw private sentence" not in why


def test_telegram_cron_notification_prefers_rich_send(monkeypatch):
    plugin = load_plugin()
    calls = []

    class FakeBot:
        def __init__(self, token, **kwargs):
            self.token = token

        async def send_rich_message(self, **kwargs):
            calls.append(("rich", kwargs))

        async def send_message(self, **kwargs):
            calls.append(("plain", kwargs))

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

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setitem(
        sys.modules,
        "telegram",
        SimpleNamespace(
            Bot=FakeBot,
            CopyTextButton=FakeCopyTextButton,
            InlineKeyboardButton=FakeInlineKeyboardButton,
            InlineKeyboardMarkup=FakeInlineKeyboardMarkup,
        ),
    )

    ok = plugin._send_telegram_cron_notification_message(
        "Hermes Guardian blocked a cron job action.\n\n"
        "Job: Example Availability Check\n"
        "Job ID: aaaaaaaaaaaa\n"
        "Action: message_send\n"
        "Destination: messaging\n"
        "Data classes: communications\n"
        "Reason: requires approval\n\n"
        "/guardian approve 1234 forever\n",
        "telegram:-1000000000000:75",
        "/guardian approve 1234 forever",
    )

    assert ok is True
    assert [kind for kind, _ in calls] == ["rich"]
    rich = calls[0][1]["text"]
    assert rich.startswith("## Hermes Guardian Cron Block")
    assert "| Field | Value |" in rich
    assert "<details>" in rich
    assert "raw private sentence" not in rich


def test_telegram_cron_notification_falls_back_on_rich_capability_error(monkeypatch):
    plugin = load_plugin()
    calls = []

    class FakeBot:
        def __init__(self, token, **kwargs):
            self.token = token

        async def send_rich_message(self, **kwargs):
            raise TypeError("unsupported keyword")

        async def send_message(self, **kwargs):
            calls.append(("plain", kwargs))

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

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setitem(
        sys.modules,
        "telegram",
        SimpleNamespace(
            Bot=FakeBot,
            CopyTextButton=FakeCopyTextButton,
            InlineKeyboardButton=FakeInlineKeyboardButton,
            InlineKeyboardMarkup=FakeInlineKeyboardMarkup,
        ),
    )

    ok = plugin._send_telegram_cron_notification_message(
        "Hermes Guardian blocked a cron job action.\n\n/guardian approve 1234 forever\n",
        "telegram:-1000000000000:75",
        "/guardian approve 1234 forever",
    )

    assert ok is True
    assert [kind for kind, _ in calls] == ["plain"]


def test_telegram_cron_notification_suppresses_legacy_fallback_on_uncertain_rich_send(monkeypatch):
    plugin = load_plugin()
    calls = []

    class FakeBot:
        def __init__(self, token, **kwargs):
            self.token = token

        async def send_rich_message(self, **kwargs):
            raise TimeoutError("timed out after request write")

        async def send_message(self, **kwargs):
            calls.append(("plain", kwargs))

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

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setitem(
        sys.modules,
        "telegram",
        SimpleNamespace(
            Bot=FakeBot,
            CopyTextButton=FakeCopyTextButton,
            InlineKeyboardButton=FakeInlineKeyboardButton,
            InlineKeyboardMarkup=FakeInlineKeyboardMarkup,
        ),
    )

    ok = plugin._send_telegram_cron_notification_message(
        "Hermes Guardian blocked a cron job action.\n\n/guardian approve 1234 forever\n",
        "telegram:-1000000000000:75",
        "/guardian approve 1234 forever",
    )

    assert ok is True
    assert calls == []
