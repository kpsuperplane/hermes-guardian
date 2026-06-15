from __future__ import annotations

import live_llm


def _clear_live_env(monkeypatch):
    for name in (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
        "GUARDIAN_LLM_TEST_MODEL",
        "OPENROUTER_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_openrouter_model_is_live_model_fallback(monkeypatch):
    _clear_live_env(monkeypatch)
    monkeypatch.setenv("OPENROUTER_MODEL", "openai/gpt-4o-mini, anthropic/claude-3.5-haiku")

    assert live_llm.live_models() == ["openai/gpt-4o-mini", "anthropic/claude-3.5-haiku"]


def test_guardian_llm_test_model_overrides_openrouter_model(monkeypatch):
    _clear_live_env(monkeypatch)
    monkeypatch.setenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    monkeypatch.setenv("GUARDIAN_LLM_TEST_MODEL", "google/gemini-2.5-flash")

    assert live_llm.live_models() == ["google/gemini-2.5-flash"]


def test_openrouter_model_prefers_openrouter_backend_when_gemini_key_exists(monkeypatch):
    _clear_live_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")

    backend = live_llm._select_backend()

    assert backend is not None
    assert backend.label == "OpenRouter"
    assert backend.mode == "openai"
