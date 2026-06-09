from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def clear_guardian_env(monkeypatch):
    monkeypatch.delenv("HERMES_GUARDIAN_ALLOWLIST", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_PRIVACY", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_HISTORY_TIMEZONE", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_STATE_DIR", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_LANGUAGE_PACKS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_CRON_NOTIFY_TO", raising=False)
    # Safety net: never let a test reach the real Telegram sender. Even if a test
    # resolves a delivery target and forgets to stub the send, the CLI fallback is
    # a no-op and there is no bot token. Tests use synthetic cron job ids, so the
    # default "origin" policy also resolves no real target.
    monkeypatch.setenv("HERMES_GUARDIAN_HERMES_CLI", "/bin/true")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("TELEGRAM_GROUP_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("DISCORD_ALLOWED_USERS", raising=False)
