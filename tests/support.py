from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace


def _purge_plugin_modules():
    prefixes = (
        "hermes_guardian",
        "_hermes_guardian",
        "_hermes_guardian_dashboard_facade",
    )
    for name in list(sys.modules):
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes):
            sys.modules.pop(name, None)


def load_plugin():
    _purge_plugin_modules()
    plugin_path = Path(__file__).resolve().parents[1] / "__init__.py"
    spec = importlib.util.spec_from_file_location("hermes_guardian", plugin_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    # Mutable state, the on-disk paths, and the clock/env helpers are the single
    # source of truth in `module.state`; rebind them there so the engine observes it.
    test_name = os.environ.get("PYTEST_CURRENT_TEST", "default").split(" ", 1)[0]
    test_digest = hashlib.sha256(test_name.encode("utf-8")).hexdigest()[:16]
    load_nonce = time.time_ns()
    module.state._PERSISTENT_RULES_PATH = Path(
        f"/tmp/hermes-guardian-test-rules-{os.getpid()}-{test_digest}-{load_nonce}.json"
    )
    module.state._PERSISTENT_RULES_PATH.unlink(missing_ok=True)
    module.state._PERSISTENT_RULES_CACHE = module._default_privacy_config()
    module._apply_language_pack_config(module.state._PERSISTENT_RULES_CACHE)
    module.state._PERSISTENT_RULES_MTIME = None
    module.state._PERSISTENT_RULES_ERROR = False
    module.state._ACTIVITY_DB_PATH = Path(
        f"/tmp/hermes-guardian-test-activity-{os.getpid()}-{test_digest}-{load_nonce}.sqlite3"
    )
    module.state._GUARDIAN_HMAC_KEY_PATH = Path(f"/tmp/hermes-guardian-test-hmac-{test_digest}.key")
    for path in [module.state._ACTIVITY_DB_PATH, module.state._ACTIVITY_DB_PATH.with_suffix(".sqlite3-wal"), module.state._ACTIVITY_DB_PATH.with_suffix(".sqlite3-shm")]:
        path.unlink(missing_ok=True)
    module.state._ACTIVITY_DB_INITIALIZED = False
    # Tests drive `_handle_guardian_command` directly, modeling the trusted local
    # operator. Production reaches the handler only via the gateway (which records the
    # real owner), where this stays False and an unrecorded command fails closed.
    module.state._TRUSTED_LOCAL_COMMAND_CONTEXT = True
    return module


def privacy_rule(
    *,
    rule_id: str = "rule_test",
    effect: str = "allow",
    action_family: str = "mcp_write",
    destination: str = "mcp:notion",
    purpose: str = "*",
    recipient_identity: str = "*",
    data_classes: list[str] | None = None,
    owner_hash: str = "*",
    cron_job_id: str = "",
    cron_job_name: str = "",
    expires_at: int = 0,
    remaining_invocations: int | None = None,
    enabled: bool = True,
):
    rule = {
        "id": rule_id,
        "effect": effect,
        "enabled": enabled,
        "match": {
            "tool_name": "*",
            "action_family": action_family,
            "destination": destination,
            "purpose": purpose,
            "recipient_identity": recipient_identity,
            "data_classes": data_classes or ["*"],
        },
        "scope": {
            "owner_hash": owner_hash,
            "cron_job_id": cron_job_id,
            "cron_job_name": cron_job_name,
        },
        "expires_at": expires_at,
        "created_at": 0,
    }
    if remaining_invocations is not None:
        rule.pop("expires_at", None)
        rule["remaining_invocations"] = remaining_invocations
    return rule


def save_privacy_config(plugin, *, mode: str = "strict", rules: list[dict] | None = None):
    # The mutators operate on the INTERNAL config structure (doc 04 §4); the loader
    # serializes it to the v4 IA file. This helper authors that internal shape
    # directly (Egress Safety + rules), exactly as the engine consumes it. `_save_privacy_config`
    # normalizes it and writes the v4 file to disk.
    assert plugin._save_privacy_config({
        "version": plugin._PRIVACY_RULE_FILE_VERSION,
        "privacy": {
            "egress_safety": mode,
            "rules": rules or [],
        },
    })


def parse_json(value: str):
    return json.loads(value)


def gateway_event(text: str, *, user_id: str = "owner", platform: str = "telegram"):
    return SimpleNamespace(
        text=text,
        source=SimpleNamespace(
            platform=SimpleNamespace(value=platform),
            user_id=user_id,
            chat_id="chat-1",
        ),
    )


def bind_owner(plugin, *, session_id: str = "s1", user_id: str = "owner"):
    plugin._on_pre_llm_call(session_id=session_id, platform="telegram", sender_id=user_id)


class FakeSecurityLlm:
    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = []

    def complete_structured(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(parsed=self.verdict, text=json.dumps(self.verdict))


def first_pending_id(plugin):
    assert plugin._PENDING_APPROVALS
    return next(iter(plugin._PENDING_APPROVALS))


def wait_for(predicate, *, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()
