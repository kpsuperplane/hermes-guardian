from __future__ import annotations

import os
from pathlib import Path

import pytest


def _load_dotenv() -> None:
    """Populate os.environ from a gitignored repo-root `.env`, if present.

    Convenience for running the live LLM verifier tests locally without exporting
    shell variables (OPENROUTER_API_KEY, GUARDIAN_LLM_TEST_MODEL, ...). Stdlib only,
    matching the plugin's no-runtime-dependency policy. Existing environment values
    always win, so CI secrets are never overridden by a stray local file.
    """
    env_path = Path(__file__).resolve().parents[1] / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


def pytest_addoption(parser):
    parser.addoption(
        "--run-llm",
        action="store_true",
        default=False,
        help="run the live LLM verifier test (otherwise skipped; also enabled by GUARDIAN_RUN_LLM=1)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip `@pytest.mark.llm` tests unless explicitly opted in.

    The live LLM verifier test calls an external API; it must never run during a
    normal local `pytest`. It runs only on explicit request — `pytest --run-llm` (or
    `GUARDIAN_RUN_LLM=1`) — which is also what CI passes.
    """
    if config.getoption("--run-llm") or os.environ.get("GUARDIAN_RUN_LLM"):
        return
    skip = pytest.mark.skip(reason="live LLM test; run with --run-llm or GUARDIAN_RUN_LLM=1")
    for item in items:
        if "llm" in item.keywords:
            item.add_marker(skip)


def _purge_test_tmp_artifacts() -> None:
    """Remove the per-run scratch files `load_plugin()` leaves in the temp dir.

    Each `load_plugin()` mints an activity DB path keyed by `id(module)` (plus its
    `-wal`/`-shm` siblings) and never deletes it, so the files accumulate across
    runs until the temp filesystem fills and unrelated tests start failing with
    "No space left on device". Sweep them at session start and end so a single run
    cleans up after itself and inherits a clean slate from prior runs.
    """
    tmp = Path("/tmp")
    for pattern in ("hermes-guardian-test-activity-*", "hermes-guardian-test-hmac-*"):
        for path in tmp.glob(pattern):
            try:
                path.unlink()
            except OSError:
                pass


@pytest.fixture(scope="session", autouse=True)
def _clean_test_tmp_artifacts():
    _purge_test_tmp_artifacts()
    yield
    _purge_test_tmp_artifacts()


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
