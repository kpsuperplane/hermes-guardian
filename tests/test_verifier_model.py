"""Verifier model override (fail-safe) and the deny-only verdict cache."""

from __future__ import annotations

from types import SimpleNamespace

from support import *  # noqa: F403


def _deny_llm(risk="high"):
    return FakeSecurityLlm({
        "outcome": "deny",
        "risk_level": risk,
        "authorization_level": "unknown",
        "rationale": "blocked",
    })


def _allow_llm():
    return FakeSecurityLlm({
        "outcome": "allow",
        "risk_level": "low",
        "authorization_level": "substantive",
        "rationale": "fine",
    })


# --- setting ---------------------------------------------------------------

def test_verifier_model_default_empty_and_set_clear(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    assert plugin._llm_verifier_model() == ""

    assert plugin._set_llm_verifier_model("gpt-5.4-mini")[0]
    assert plugin._llm_verifier_model() == "gpt-5.4-mini"
    # Survives an unrelated mutation.
    assert plugin._set_unknown_tools_mode("allow")[0]
    assert plugin._llm_verifier_model() == "gpt-5.4-mini"

    assert plugin._set_llm_verifier_model("none")[0]
    assert plugin._llm_verifier_model() == ""


def test_verifier_model_normalizes_and_snapshot_exposes_it():
    plugin = load_plugin()
    plugin._set_llm_verifier_model("  weird model!! ")
    assert plugin._llm_verifier_model() == "weirdmodel"
    assert plugin._policy_snapshot()["llm_verifier_model"] == "weirdmodel"


# --- passthrough + fail-safe ----------------------------------------------

def test_verifier_model_is_passed_to_completion():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    plugin._set_llm_verifier_model("gpt-5.4-mini")
    fake = _deny_llm("medium")
    plugin.state._PLUGIN_LLM = fake
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "a", "text": "hi"}, session_id="s1")

    assert fake.calls[0].get("model") == "gpt-5.4-mini"


def test_rejected_model_override_falls_back_instead_of_failing_closed(monkeypatch):
    # If the override is rejected (e.g. allow_model_override not granted), the
    # verifier must retry on the default model, not deny everything.
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "owner")

    class FlakyLLM:
        def __init__(self):
            self.calls = []

        def complete_structured(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs.get("model"):
                raise RuntimeError("model override not allowed")
            return SimpleNamespace(
                parsed={
                    "outcome": "allow",
                    "risk_level": "low",
                    "authorization_level": "substantive",
                    "rationale": "ok on default",
                },
                text="",
            )

    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    plugin._set_llm_verifier_model("gpt-5.4-mini")
    plugin.state._PLUGIN_LLM = FlakyLLM()
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    # Owner authorization context present so the verifier auto-allow of this external
    # private export is honored (doc 02 §3 corroboration gate); the focus here is the
    # model-override fallback, not the corroboration check.
    plugin._on_pre_gateway_dispatch(gateway_event("message a with the update", user_id="owner"))

    result = plugin._on_pre_tool_call("send_message", {"to": "a", "text": "hi"}, session_id="s1")

    # Two attempts: override (rejected) then default (allowed) -> action allowed.
    assert len(plugin.state._PLUGIN_LLM.calls) == 2
    assert result is None


# --- deny-only verdict cache ----------------------------------------------

def test_repeated_denied_action_hits_cache():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake = _deny_llm()
    plugin.state._PLUGIN_LLM = fake
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    args = {"to": "a", "text": "hi"}
    plugin._on_pre_tool_call("send_message", args, session_id="s1")
    plugin._on_pre_tool_call("send_message", args, session_id="s1")

    assert len(fake.calls) == 1  # second call served from cache


def test_allow_verdicts_are_not_cached():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake = _allow_llm()
    plugin.state._PLUGIN_LLM = fake
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    args = {"to": "a", "text": "hi"}
    plugin._on_pre_tool_call("send_message", args, session_id="s1")
    plugin._on_pre_tool_call("send_message", args, session_id="s1")

    # Allows are never cached (a stale allow could become a false allow).
    assert len(fake.calls) == 2


def test_cache_does_not_serve_across_different_actions():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake = _deny_llm()
    plugin.state._PLUGIN_LLM = fake
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})

    plugin._on_pre_tool_call("send_message", {"to": "a", "text": "hi"}, session_id="s1")
    plugin._on_pre_tool_call("send_message", {"to": "b", "text": "different"}, session_id="s1")

    assert len(fake.calls) == 2  # distinct fingerprints, no cache reuse


# --- per-install model option discovery -----------------------------------

def _write_config(tmp_path, body):
    (tmp_path / "config.yaml").write_text(body)


def test_options_empty_without_override_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _write_config(tmp_path, "model:\n  default: gpt-5.5\nplugins:\n  enabled: [hermes-guardian]\n")
    plugin = load_plugin()
    # No grant -> nothing selectable (an override would not take effect anyway).
    assert plugin._verifier_model_options() == []


def test_options_come_from_allowed_models(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _write_config(
        tmp_path,
        "plugins:\n  entries:\n    hermes-guardian:\n      llm:\n"
        "        allow_model_override: true\n"
        "        allowed_models: [gpt-5.4-mini, gpt-5.5]\n",
    )
    plugin = load_plugin()
    assert plugin._verifier_model_options() == ["gpt-5.4-mini", "gpt-5.5"]
    assert plugin._policy_snapshot()["llm_verifier_model_options"] == ["gpt-5.4-mini", "gpt-5.5"]


def test_wildcard_grant_suggests_known_install_models(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _write_config(
        tmp_path,
        "model:\n  default: gpt-5.5\nplugins:\n  entries:\n    hermes-guardian:\n      llm:\n"
        "        allow_model_override: true\n        allowed_models: ['*']\n",
    )
    (tmp_path / "context_length_cache.yaml").write_text(
        "context_lengths:\n  gpt-5.4-mini@https://x/codex: 1\n  gpt-5.5@https://x/codex: 1\n"
    )
    plugin = load_plugin()
    options = plugin._verifier_model_options()
    assert "gpt-5.4-mini" in options and "gpt-5.5" in options


def test_current_model_always_in_options(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _write_config(tmp_path, "plugins:\n  enabled: [hermes-guardian]\n")  # no grant -> base options []
    plugin = load_plugin()
    plugin._set_llm_verifier_model("gpt-5.4-mini")
    assert "gpt-5.4-mini" in plugin._verifier_model_options()


def test_missing_or_unreadable_config_yields_no_options(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))  # no config.yaml written
    plugin = load_plugin()
    assert plugin._verifier_model_options() == []


def test_expired_cache_entry_is_reevaluated(monkeypatch):
    plugin = load_plugin()
    save_privacy_config(plugin, mode="llm")
    fake = _deny_llm()
    plugin.state._PLUGIN_LLM = fake
    bind_owner(plugin)
    plugin._taint_session("s1", {"communications"})
    args = {"to": "a", "text": "hi"}

    plugin._on_pre_tool_call("send_message", args, session_id="s1")
    # Age the cached entry past its TTL.
    for key, (ts, verdict) in list(plugin._LLM_DENY_VERDICT_CACHE.items()):
        plugin._LLM_DENY_VERDICT_CACHE[key] = (ts - plugin._LLM_DENY_VERDICT_TTL_SECONDS - 1, verdict)
    plugin._on_pre_tool_call("send_message", args, session_id="s1")

    assert len(fake.calls) == 2  # stale entry re-evaluated
