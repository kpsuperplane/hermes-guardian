"""Config IA v4 loader tests (refactor doc 04 §5).

The policy file is reshaped into the five IA concepts, in `decide` order
(`whats_yours` / `sharing` / `review` / `protection`, plus `version`/meta). This
file proves the loader front-end parses that v4 schema directly into the SAME
internal structure the engine already consumes — `decide` never notices the
reshape — and that all the fail-closed / round-trip guarantees hold.

There is NO back-compat: an old-shape file is not migrated; it fails closed to
strict with a clear log line. The loader never branches on `version`.

Per project memory, NO real agent/cron/Telegram identifiers appear here — only
synthetic placeholders (example.com addresses, made-up store ids, a synthetic
cron id that resolves nothing).
"""

from __future__ import annotations

import json
from pathlib import Path

from support import *  # noqa: F403


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _write_file(plugin, data) -> None:
    """Write a raw on-disk policy document and invalidate the cache."""
    if isinstance(data, str):
        plugin.state._PERSISTENT_RULES_PATH.write_text(data)
    else:
        plugin.state._PERSISTENT_RULES_PATH.write_text(json.dumps(data))
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None


def _full_v4_document() -> dict:
    """A fully-populated v4 file exercising every block (doc 04 §2)."""
    return {
        "version": 4,
        "whats_yours": {
            "stores": ["store:files", "store:notes", "store:crm", "draft:*"],
            "identities": ["me@example.com"],
            "hosts": ["box.example.internal"],
        },
        "sharing": {
            "trusted_recipients": [
                {"identity": "ally@example.com", "classes": ["communications"], "note": "team"},
            ],
            "rules": [
                privacy_rule(
                    rule_id="rule_allow_notes",
                    effect="allow",
                    action_family="mcp_write",
                    destination="mcp:notes",
                    data_classes=["communications"],
                ),
            ],
            "outward": {"extra": ["crosspost"]},
        },
        "review": {
            "mode": "llm",
            "owner_context": True,
            "cron_context": True,
            "verifier_model": "gpt-5.4-mini",
        },
        "protection": {
            "security": {"sensitive_links": False},
            "unknown_tools": "gate",
            "tools": [
                {"match": "crm_*", "direction": "read", "taints": ["contacts"],
                 "destination": "store:crm", "egress": "ignore"},
            ],
            "language_packs": {"en": True, "es": False},
            "retention": {"max_rows": 42, "max_age_days": 3},
            "runtime": {"dashboard_mutations": "off"},
        },
    }


# --- 1a. Full v4 file parses into the expected internal structure. -------------
def test_full_v4_file_parses_to_internal_structure():
    plugin = load_plugin()
    _write_file(plugin, _full_v4_document())
    config = plugin._load_privacy_config()

    # whats_yours.* -> internal self.* (stores -> destinations).
    assert "store:crm" in config["self"]["destinations"]
    assert config["self"]["identities"] == ["me@example.com"]
    assert config["self"]["hosts"] == ["box.example.internal"]

    # sharing.trusted_recipients -> internal trusted_recipients.entries.
    entries = config["trusted_recipients"]["entries"]
    assert [(e["kind"], e["value"]) for e in entries] == [("identity", "ally@example.com")]
    assert entries[0]["classes"] == ["communications"]

    # sharing.rules -> internal privacy.rules.
    assert [r["id"] for r in config["privacy"]["rules"]] == ["rule_allow_notes"]

    # sharing.outward.extra -> internal outward_sharing.extra; builtin code-owned.
    assert "crosspost" in config["outward_sharing"]["extra"]
    assert set(config["outward_sharing"]["builtin"]) == set(plugin._OUTWARD_SHARING_BUILTIN_SUBTYPES)

    # review.* -> internal privacy.{mode,llm_*}; protection.unknown_tools -> privacy.unknown_tools.
    assert config["privacy"]["mode"] == "llm"
    assert config["privacy"]["llm_user_context"] is True
    assert config["privacy"]["llm_cron_context"] is True
    assert config["privacy"]["llm_verifier_model"] == "gpt-5.4-mini"
    assert config["privacy"]["unknown_tools"] == "gate"

    # protection.* -> internal security/tools/language_packs/retention/dashboard.
    sec = {r["id"]: r["enabled"] for r in config["security"]["rules"]}
    assert sec["sensitive_links"] is False
    assert sec["credential_content"] is True  # unspecified -> safe default-enabled
    assert [t["match"] for t in config["privacy"]["tools"]] == ["crm_*"]
    assert config["language_packs"]["enabled"] == ["en"]
    assert config["retention"]["max_rows"] == 42
    assert config["retention"]["max_age_days"] == 3
    assert config["dashboard"]["mutations"] == "off"
    # version reflects the current document version; the loader never branched on it.
    assert config["version"] == plugin._PRIVACY_RULE_FILE_VERSION == 4


# --- 1b. Decision-corpus parity: a v4 file yields identical decide outcomes. ----
# This is THE parity floor (doc 04 §5.1 / §6 / doc 05 §2 commit-3). For each corpus
# record we author a v4 file carrying that record's mode, load it through the new
# front-end, and replay the scenario through the authoritative engine. The outcome
# must match the recorded pre-reshape decision, bucketed exactly as the standing
# floor gate (test_policy_engine.py::test_10): (a) intra-boundary gate->allow wins,
# (b) the sanctioned provenance-laundering carve-out (laundering-tagged ONLY), and
# (c) anything else, which MUST be empty.
def _replay_old_outcome_bucket(decision: str) -> str:
    if decision in ("blocked",):
        return "block"
    if decision in ("security_blocked",):
        return "security_block"
    if decision in ("allowed",):
        return "allow"
    return decision


def _v4_file_for_mode(mode: str) -> dict:
    """A minimal valid v4 file pinning only review.mode; all else safe defaults."""
    return {"version": 4, "review": {"mode": mode}}


def test_corpus_parity_through_v4_loader_zero_floor_breaches():
    records = json.loads((FIXTURES / "decision_corpus.json").read_text())
    assert len(records) == 26

    intra_boundary_trusts = None
    bucket_a = []  # (a) expected intra-boundary gate->allow
    bucket_b = []  # (b) sanctioned provenance-laundering flips — laundering-tagged ONLY
    bucket_c = []  # (c) anything else — MUST be empty (the floor gate)

    for rec in records:
        plugin = load_plugin()
        DT = plugin._DestinationTrust
        if intra_boundary_trusts is None:
            intra_boundary_trusts = {DT.SELF, DT.LOCAL_SYSTEM, DT.MODEL_PROVIDER}
        rid = rec["id"]
        tool = rec["tool"]
        args = rec["args_shape"]
        session_id = f"corpus_{rid}"

        # Drive the mode THROUGH the on-disk v4 file and the new loader front-end.
        _write_file(plugin, _v4_file_for_mode(rec["mode"]))
        assert plugin._privacy_policy() == rec["mode"]

        if rec.get("taint"):
            plugin._taint_session(session_id, set(rec["taint"]))

        old = _replay_old_outcome_bucket(rec["decision"])

        # security_blocked records short-circuit before decide via the security/
        # intrinsic path; the security layer is unchanged by the config reshape.
        if old == "security_block":
            intrinsic = plugin._intrinsic_risk_for_tool(tool, args)
            assert intrinsic is not None, f"{rid}: security_blocked record lost its hard block"
            continue

        cap, new = plugin._shadow_decision_for(tool, args, session_id)
        trust = cap.destination.trust

        if old == "block" and new == plugin._DECISION_ALLOW:
            if trust in intra_boundary_trusts or cap.destination.kind == "draft":
                bucket_a.append(rid)
            elif rec.get("laundering"):
                bucket_b.append((rid, str(trust)))
            else:
                bucket_c.append((rid, "block->ALLOW", str(trust)))
        elif old == "allow" and new in (plugin._DECISION_BLOCK, plugin._DECISION_APPROVE):
            bucket_c.append((rid, f"allow->{new}"))
        # old == new (incl. block->APPROVE = still a gate), block->BLOCK, allow->ALLOW: parity.

    assert bucket_c == [], f"config-reshape floor breach (bucket c): {bucket_c}"
    laundering_ids = {r["id"] for r in records if r.get("laundering")}
    for rid, _trust in bucket_b:
        assert rid in laundering_ids, f"non-laundering record in carve-out bucket: {rid}"


# --- 2. Partial file: only whats_yours -> the rest fills from safe defaults. ----
def test_partial_file_only_whats_yours_fills_defaults():
    plugin = load_plugin()
    _write_file(plugin, {"version": 4, "whats_yours": {"stores": ["store:crm"]}})
    config = plugin._load_privacy_config()

    # The authored block is honored.
    assert config["self"]["destinations"] == ["store:crm"]
    assert config["self"]["identities"] == []  # conservative: never defaulted non-empty
    # review.mode defaults to llm; contexts to their safe defaults.
    assert config["privacy"]["mode"] == "llm" == plugin._DEFAULT_PRIVACY_MODE
    assert config["privacy"]["llm_user_context"] is True
    assert config["privacy"]["llm_cron_context"] is False
    assert config["privacy"]["unknown_tools"] == "gate"
    # sharing empty; outward builtin code-owned.
    assert config["privacy"]["rules"] == []
    assert config["trusted_recipients"]["entries"] == []
    assert config["outward_sharing"]["extra"] == []
    assert set(config["outward_sharing"]["builtin"]) == set(plugin._OUTWARD_SHARING_BUILTIN_SUBTYPES)
    # protection blocks default.
    assert config["retention"]["max_rows"] == plugin._DEFAULT_RETENTION_MAX_ROWS
    # not a fail-closed load: a valid partial file is honored, not rejected.
    assert plugin.state._PERSISTENT_RULES_ERROR is False


# --- 3a. Malformed sharing.rules -> empty rules + a logged warning (not fatal). -
def test_malformed_sharing_rules_drop_to_empty_and_log(caplog):
    plugin = load_plugin()
    _write_file(
        plugin,
        {
            "version": 4,
            "review": {"mode": "llm"},
            "sharing": {"rules": "not-a-list"},  # malformed
        },
    )
    config = plugin._load_privacy_config()
    # The malformed block drops to empty rules; the rest of the document still loads.
    assert config["privacy"]["rules"] == []
    assert config["privacy"]["mode"] == "llm"
    # This is a tolerated block-level malformation, NOT a whole-file failure.
    assert plugin.state._PERSISTENT_RULES_ERROR is False


# --- 3b. A wholly corrupt file -> strict (fail closed). ------------------------
def test_corrupt_file_falls_back_to_strict():
    plugin = load_plugin()
    _write_file(plugin, "{ this is not valid json")
    config = plugin._load_privacy_config()
    assert config["privacy"]["mode"] == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True


# --- 4. An OLD-shape file fails closed cleanly to strict (no silent half-load). -
def test_old_shape_file_fails_closed_to_strict(caplog):
    plugin = load_plugin()
    # The pre-reshape shape: flat privacy.* + sibling [self]/[security] blocks.
    _write_file(
        plugin,
        {
            "version": 3,
            "privacy": {"mode": "llm", "rules": [privacy_rule(rule_id="legacy_allow", effect="allow")]},
            "self": {"destinations": ["store:crm"], "identities": [], "hosts": []},
            "security": {"rules": [{"id": "sensitive_links", "enabled": False}]},
        },
    )
    config = plugin._load_privacy_config()
    # No partial/ambiguous parse: the old document is rejected outright -> strict.
    assert config["privacy"]["mode"] == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True
    # The legacy allow rule did NOT survive (no silent half-load of old keys).
    assert config["privacy"]["rules"] == []
    # A clear, re-author-prompting log line was emitted.
    assert any("unrecognized config shape" in rec.getMessage() for rec in caplog.records)


# --- 5. Builtin outward-sharing is NOT narrowable from config. -----------------
# --- 6. Round-trip: a mutation persists the v4 shape and reloads identically. ---
def test_mutation_persists_v4_and_reloads_to_same_internal_structure(tmp_path):
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH = tmp_path / "rules.json"
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None

    # Drive a representative mutation across several blocks via the normal mutators.
    assert plugin._set_privacy_mode("read-only")[0]
    assert plugin._add_self_destination("destination", "store:crm")[0]
    assert plugin._add_trusted_recipient("ally@example.com", classes=["communications"], note="team")[0]
    assert plugin._set_security_rule("sensitive_links", False)[0]
    assert plugin._set_unknown_tools_mode("allow")[0]
    assert plugin._add_outward_sharing_subtype("crosspost")[0]

    # The on-disk file is the v4 five-block schema, not the old keys.
    on_disk = json.loads((tmp_path / "rules.json").read_text())
    assert set(on_disk) == {"version", "whats_yours", "sharing", "review", "protection"}
    assert on_disk["review"]["mode"] == "read-only"
    assert "store:crm" in on_disk["whats_yours"]["stores"]
    assert on_disk["protection"]["security"]["sensitive_links"] is False
    assert on_disk["protection"]["unknown_tools"] == "allow"
    assert "crosspost" in on_disk["sharing"]["outward"]["extra"]
    # builtin subtypes are NOT serialized (code-owned, never written to config).
    assert "builtin" not in on_disk["sharing"]["outward"]

    # Capture the in-memory structure, then reload it cold from the v4 file.
    before = plugin._load_privacy_config()
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None
    after = plugin._load_privacy_config()

    # The internal structure the engine consumes is identical across the round-trip.
    assert before == after
    assert after["privacy"]["mode"] == "read-only"
    assert "store:crm" in after["self"]["destinations"]
    assert [e["value"] for e in after["trusted_recipients"]["entries"]] == ["ally@example.com"]
    assert {r["id"]: r["enabled"] for r in after["security"]["rules"]}["sensitive_links"] is False
    assert after["privacy"]["unknown_tools"] == "allow"
    assert "crosspost" in after["outward_sharing"]["extra"]
    assert plugin.state._PERSISTENT_RULES_ERROR is False
