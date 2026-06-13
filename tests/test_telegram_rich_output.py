import sys
from types import SimpleNamespace

from support import *  # noqa: F403


def test_telegram_slash_command_uses_shared_plain_output():
    plugin = load_plugin()

    plugin._on_pre_gateway_dispatch(gateway_event("/guardian status", platform="telegram"))
    output = plugin._handle_guardian_command("status")

    assert output.startswith("Hermes Guardian status")
    assert "| Signal | Value |" not in output
    assert not output.startswith("##")


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
    plain_message = (
        "Hermes Guardian blocked a cron job action.\n\n"
        "Job: Example Availability Check\n"
        "Action: message_send\n\n"
        "/guardian approve 1234 forever\n"
    )

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
        plain_message,
        "telegram:-1000000000000:75",
        "/guardian approve 1234 forever",
    )

    assert ok is True
    assert [kind for kind, _ in calls] == ["plain"]
    assert calls[0][1]["text"] == plain_message
    assert calls[0][1]["parse_mode"] is None
    assert "\n\nJob: Example Availability Check\nAction: message_send\n\n" in calls[0][1]["text"]


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
