from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace


def load_plugin():
    plugin_path = Path(__file__).resolve().parents[1] / "__init__.py"
    spec = importlib.util.spec_from_file_location("hermes_guardian", plugin_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module._PERSISTENT_RULES_PATH = Path("/tmp/hermes-guardian-test-rules.json")
    module._PERSISTENT_RULES_PATH.unlink(missing_ok=True)
    module._PERSISTENT_RULES_CACHE = module._default_privacy_config()
    module._apply_language_pack_config(module._PERSISTENT_RULES_CACHE)
    module._PERSISTENT_RULES_MTIME = None
    module._PERSISTENT_RULES_ERROR = False
    module._ACTIVITY_DB_PATH = Path(f"/tmp/hermes-guardian-test-activity-{id(module)}.sqlite3")
    test_name = os.environ.get("PYTEST_CURRENT_TEST", "default").split(" ", 1)[0]
    test_digest = hashlib.sha256(test_name.encode("utf-8")).hexdigest()[:16]
    module._GUARDIAN_HMAC_KEY_PATH = Path(f"/tmp/hermes-guardian-test-hmac-{test_digest}.key")
    for path in [module._ACTIVITY_DB_PATH, module._ACTIVITY_DB_PATH.with_suffix(".sqlite3-wal"), module._ACTIVITY_DB_PATH.with_suffix(".sqlite3-shm")]:
        path.unlink(missing_ok=True)
    module._ACTIVITY_DB_INITIALIZED = False
    return module


def privacy_rule(
    *,
    rule_id: str = "rule_test",
    effect: str = "allow",
    action_family: str = "mcp_write",
    destination: str = "mcp:notion",
    data_classes: list[str] | None = None,
    owner_hash: str = "*",
    session_id: str = "",
    cron_job_id: str = "",
    cron_job_name: str = "",
    remaining_invocations: int = -1,
    enabled: bool = True,
):
    return {
        "id": rule_id,
        "effect": effect,
        "enabled": enabled,
        "match": {
            "tool_name": "*",
            "action_family": action_family,
            "destination": destination,
            "data_classes": data_classes or ["*"],
        },
        "scope": {
            "owner_hash": owner_hash,
            "session_id": session_id,
            "cron_job_id": cron_job_id,
            "cron_job_name": cron_job_name,
        },
        "remaining_invocations": remaining_invocations,
        "created_at": 0,
    }


def save_privacy_config(plugin, *, mode: str = "strict", rules: list[dict] | None = None):
    assert plugin._save_privacy_config({
        "version": 1,
        "privacy": {
            "mode": mode,
            "rules": rules or [],
        },
    })


def parse_json(value: str):
    return json.loads(value)


def gateway_event(text: str, *, user_id: str = "kevin", platform: str = "telegram"):
    return SimpleNamespace(
        text=text,
        source=SimpleNamespace(
            platform=SimpleNamespace(value=platform),
            user_id=user_id,
            chat_id="chat-1",
        ),
    )


def bind_owner(plugin, *, session_id: str = "s1", user_id: str = "kevin"):
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


def wait_for(predicate, *, timeout: float = 1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()
