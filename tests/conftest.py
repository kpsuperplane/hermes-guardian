from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def clear_guardian_env(monkeypatch):
    monkeypatch.delenv("HERMES_GUARDIAN_ALLOWLIST", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_PRIVACY", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_HISTORY_TIMEZONE", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_LANGUAGE_PACKS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_CRON_NOTIFY_TO", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_HERMES_CLI", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", raising=False)
    monkeypatch.delenv("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("TELEGRAM_GROUP_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("DISCORD_ALLOWED_USERS", raising=False)
