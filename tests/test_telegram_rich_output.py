import sys
from types import SimpleNamespace

from support import *  # noqa: F403


def _dispatch_command(plugin, raw: str, *, platform: str = "telegram", user_id: str = "owner") -> str:
    plugin._on_pre_gateway_dispatch(gateway_event(f"/guardian {raw}", platform=platform, user_id=user_id))
    return plugin._handle_guardian_command(raw)


def test_telegram_slash_command_uses_rich_output_when_hermes_supports_it(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setattr(plugin._m_commands, "_telegram_rich_slash_supported", lambda: True)

    output = _dispatch_command(plugin, "status", platform="telegram")

    assert output.startswith("## Hermes Guardian Status")
    assert "| Signal | Value |" in output
    assert "Privacy mode" in output


def test_telegram_slash_command_falls_back_to_shared_output_without_hermes_support(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setattr(plugin._m_commands, "_telegram_rich_slash_supported", lambda: False)

    output = _dispatch_command(plugin, "status", platform="telegram")

    assert output.startswith("Hermes Guardian status")
    assert "| Signal | Value |" not in output
    assert not output.startswith("##")


def test_non_telegram_slash_command_uses_shared_output_even_when_rich_exists(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setattr(plugin._m_commands, "_telegram_rich_slash_supported", lambda: True)

    output = _dispatch_command(plugin, "status", platform="discord")

    assert output.startswith("Hermes Guardian status")
    assert "| Signal | Value |" not in output
    assert not output.startswith("##")


def test_local_direct_command_does_not_use_telegram_rich_output(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setattr(plugin._m_commands, "_telegram_rich_slash_supported", lambda: True)

    output = plugin._handle_guardian_command("review")

    assert output.startswith("Privacy mode:")
    assert "| Setting | Value |" not in output


def test_telegram_approvals_and_permit_menu_are_rich_and_sanitized(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setattr(plugin._m_commands, "_telegram_rich_slash_supported", lambda: True)
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


def test_telegram_activity_and_why_use_rich_shapes_without_raw_payload(monkeypatch):
    plugin = load_plugin()
    monkeypatch.setattr(plugin._m_commands, "_telegram_rich_slash_supported", lambda: True)
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
    assert "**❌ send_message**" in activity
    assert "Decision: `blocked` · Classes: `communications`" in activity
    assert "Reason: blocked · requires approval" in activity
    assert "<details>" in activity
    assert "<summary>User turn</summary>" in activity
    assert "<summary>Reason</summary>" not in activity
    assert "| Tool | Decision | Classes | LLM | Time |" not in activity
    assert "- [ ]" not in activity
    assert "- [x]" not in activity
    assert "- **send_message**" not in activity
    assert "raw private sentence" not in activity
    assert why.startswith(f"## Guardian Decision {approval_id}")
    assert "| Field | Value |" in why
    assert "<details>" in why
    assert "raw private sentence" not in why


def test_guardian_help_uses_markdown_safe_command_rows():
    plugin = load_plugin()

    output = plugin._handle_guardian_command("help")

    assert "- `/guardian why <id>`" in output
    assert "- `/guardian approve <id> 5m|forever`" in output
    assert "- `/guardian sharing preview <action> <destination> <class>`" in output
    assert "- `/guardian protection security enable|disable <rule_id>`" in output
    assert "  why <id>" not in output


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
