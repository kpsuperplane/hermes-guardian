"""Cross-cutting invariant tripwires (doc 04 §8, charter §5).

These assert the seven global invariants directly, independent of any single doc's
per-feature tests. They are the regression tripwires that must stay green every phase
(CI runs them on 3.11/3.12/3.13 alongside the suite). NO real agent/cron/Telegram
identifiers appear here (synthetic placeholders only).
"""

from __future__ import annotations

import json
import random

from support import *  # noqa: F403


# --- Invariant 1: Security before privacy (charter §5 #1) ----------------------------
def test_invariant_1_credential_to_self_still_hard_blocks_and_skips_privacy(monkeypatch):
    # A hard-block credential payload blocks regardless of destination.trust — INCLUDING a
    # self destination — and the privacy/capability engine is never consulted after the
    # security block short-circuits.
    plugin = load_plugin()
    save_privacy_config(plugin, mode="off")  # privacy disabled: only security can block.

    # Spy: if the privacy engine were consulted after a security block, decide would run.
    consulted = {"decide": False}
    original_decide = plugin.policy.decide

    def _spy_decide(*args, **kwargs):
        consulted["decide"] = True
        return original_decide(*args, **kwargs)

    monkeypatch.setattr(plugin.policy, "decide", _spy_decide)

    # Destination is the user's OWN note store (self), payload is a credential/reset code.
    result = plugin._on_pre_tool_call(
        "todo",
        {"action": "add", "content": "Your password reset code is 123456"},
        session_id="s1",
    )

    assert result is not None
    assert result["action"] == "block"
    assert consulted["decide"] is False, "privacy engine was consulted after a security block"


# --- Invariant 2: Fail-closed resolver (charter §5 #2) -------------------------------
def test_invariant_2_resolver_never_returns_self_without_a_match_and_defaults_unknown():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    save_privacy_config(plugin, mode="strict")  # no self allowlist configured.

    rng = random.Random(1729)
    # ``draft`` and the seven seeded self-store kinds resolve to self via the floor-safe
    # builtin allowlist (the user's OWN stores; doc 02 §7, charter back-compat). They are a
    # legitimate config-backed match, so they are excluded from the "never self without a
    # match" fuzz — the leak vector this invariant guards is an OUTWARD kind (host /
    # messaging / opaque / unknown) being mislabeled self with no allowlist entry.
    builtin_self_ids = {d.split(":", 1)[1] for d in plugin._DEFAULT_SELF_DESTINATIONS
                        if d.startswith("store:")}
    kinds = ["host", "messaging", "opaque", "model", "browser", "terminal",
             "subagent", "garbage_kind", ""]
    subtypes = ["write", "send", "share", "invite", "publish", "read", "query",
                "exec", "delete", "garbage_verb", ""]

    for _ in range(2000):
        kind = rng.choice(kinds)
        dest_id = "".join(rng.choice("abcdefghij._:-@0123456789") for _ in range(rng.randint(0, 18)))
        recipient = "".join(rng.choice("xyz@.0123456789") for _ in range(rng.randint(0, 14)))
        subtype = rng.choice(subtypes)
        trust = plugin._resolve_destination_trust(kind, dest_id, subtype, recipient)
        # With no config match, the resolver must NEVER claim self ownership out of thin air;
        # every unprovable OUTWARD destination resolves to unknown/external, never self.
        # SELF is the only true leak vector ("Mislabeling external as self is the only way
        # this design leaks", charter §5 #2): the resolver must NEVER return SELF for an
        # unprovable destination. (``model`` legitimately resolves MODEL_PROVIDER by kind —
        # the model is inside the trust boundary, doc 01 — which is not a leak.)
        assert trust != DT.SELF, \
            f"resolver returned SELF without a match: ({kind},{dest_id},{subtype},{recipient})"
        # A wholly unrecognized destination defaults to unknown — or external when an
        # outward-sharing subtype fires the §3.1 guard. Both are outward (decide treats
        # unknown == external); the point is it is NEVER self.
        if kind in ("garbage_kind", ""):
            assert trust in (DT.UNKNOWN, DT.EXTERNAL)

    # Even a ``store`` kind only resolves self for a SEEDED builtin id; a random store id
    # with no allowlist entry must not be self.
    assert plugin._resolve_destination_trust("store", "no_such_random_store_99", "write", "") != DT.SELF
    # ...whereas a seeded builtin store id is the legitimate self match (sanity anchor).
    sample_builtin = sorted(builtin_self_ids)[0]
    assert plugin._resolve_destination_trust("store", sample_builtin, "write", "") == DT.SELF


# --- Invariant 3: Unknown == external in decide (charter §5 #2; doc 02 §9 #4) --------
def test_invariant_3_unknown_equals_external_in_decide():
    plugin = load_plugin()
    DT = plugin._DestinationTrust

    def cap(trust):
        dest = plugin._Destination(kind="store", id="x", trust=trust)
        return plugin._Capability(direction="write", destination=dest,
                                  data_classes=frozenset(), data_tags=frozenset(),
                                  action_subtype="send")

    for classes in (set(), {"communications"}, {"local_system"}, {"documents"}):
        for mode in ("strict", "llm", "read-only"):
            assert plugin._decide(cap(DT.UNKNOWN), classes, "unknown", mode) == \
                   plugin._decide(cap(DT.EXTERNAL), classes, "unknown", mode)


# --- Invariant 4: Conservative default post-provenance (charter §5 #4; doc 02 §9 #5) -
def test_invariant_4_conservative_ambient_default_never_allows_on_absence():
    # Under taint to an external destination with no rule and no verifier allow, decide
    # NEVER returns ALLOW on the basis that no private content was detected — it uses the
    # ambient taint and routes to APPROVE. (Post-provenance: there is no payload-level
    # "absence means safe" inference.)
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    dest = plugin._Destination(kind="store", id="x", trust=DT.EXTERNAL)
    cap = plugin._Capability(direction="write", destination=dest,
                             data_classes=frozenset(), data_tags=frozenset(),
                             action_subtype="send")
    # Ambient taint present, no rule -> APPROVE (a gate), never ALLOW.
    for fine in ("communications", "contacts", "calendar", "documents", "memory",
                 "local_system", "browser_private_input"):
        assert plugin._decide(cap, {fine}, "unknown", "strict") == plugin._DECISION_APPROVE
        assert plugin._decide(cap, {fine}, "unknown", "llm") == plugin._DECISION_APPROVE
    # An UNRECOGNIZED ambient taint token fails closed to personal_private (not dropped) —
    # so an upstream/unknown taint label still gates rather than leaking.
    assert plugin._decide(cap, {"some_future_class"}, "unknown", "strict") == plugin._DECISION_APPROVE


# --- Invariant 5: Corrupt config -> strict (charter §5 #2; doc 04 §8 #5) -------------
def test_invariant_5_corrupt_config_loads_as_strict_not_permissive():
    plugin = load_plugin()
    plugin.state._PERSISTENT_RULES_PATH.write_text("{ not valid json at all ")
    plugin.state._PERSISTENT_RULES_CACHE = None
    plugin.state._PERSISTENT_RULES_MTIME = None

    config = plugin._load_privacy_config()

    assert config["privacy"]["egress_safety"] == "strict"
    assert plugin.state._PERSISTENT_RULES_ERROR is True
    # A corrupt store falls back to STRICT mode and only the floor-safe BUILTIN self
    # destinations (the user's own stores) — it must NOT inject any operator-supplied
    # permissive self IDENTITIES or HOSTS (those are the actual outward leak vectors;
    # a corrupt config must never mark an external identity/host as self).
    assert set(config["self"]["destinations"]) == set(plugin._DEFAULT_SELF_DESTINATIONS)
    assert config["self"]["identities"] == []
    assert config["self"]["hosts"] == []


# --- Invariant 6: At-rest metadata-only (charter §5 #5; doc 04 §8 #6) ----------------
def test_invariant_6_persisted_rows_are_metadata_only_after_collapse():
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin)
    plugin._taint_session("s1", {"calendar"})

    secret_body = "Project Helios kickoff sync with the legal team on Thursday at 3pm"
    plugin._on_pre_tool_call(
        "send_message",
        {"to": "stranger@example.com", "text": secret_body},
        session_id="s1",
    )

    rows = plugin._activity_rows({}, limit=20)
    blob = json.dumps(rows, sort_keys=True)
    # Raw payload content must never be persisted.
    assert secret_body not in blob
    assert "stranger@example.com" not in blob
    # The new destination-trust fields are enums/labels only.
    row = next(r for r in rows if r["decision"] == "blocked")
    assert row["destination_trust"] in {
        "self", "trusted_recipient", "local_system", "model_provider",
        "external", "public", "unknown",
    }
    assert row["decision_step"].startswith("step")


# --- Invariant 7: Audit fidelity — fine tag survives the class collapse --------------
def test_invariant_7_audit_record_keeps_fine_tag_after_collapse():
    # decide reasons over the POLICY class (personal_private), but the audit record must
    # still expose the FINE tag at today's granularity (charter §5 #6, doc 02 §5).
    plugin = load_plugin()
    save_privacy_config(plugin, mode="strict")
    bind_owner(plugin)
    plugin._taint_session("s1", {"calendar"})

    plugin._on_pre_tool_call(
        "send_message",
        {"to": "stranger@example.com", "text": "see attached"},
        session_id="s1",
    )

    row = next(r for r in plugin._activity_rows({}, limit=20) if r["decision"] == "blocked")
    recorded = set(row["data_classes"].split(",")) if row["data_classes"] else set()
    # The fine calendar tag survives — the record is NOT collapsed to "personal_private".
    assert "calendar" in recorded
    assert "personal_private" not in recorded
