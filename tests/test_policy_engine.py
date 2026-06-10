"""Policy engine (``decide``) tests — doc 02 §9 tests 1-10.

Test 10 (corpus parity replay) is THE FLOOR GATE: it asserts bucket (b) — floor breaches
— is empty.
"""

from __future__ import annotations

import json
from pathlib import Path

from support import *  # noqa: F403


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _mk_cap(plugin, *, direction="write", trust=None, kind="store", dest_id="x",
            data_tags=frozenset()):
    DT = plugin._DestinationTrust
    if trust is None:
        trust = DT.EXTERNAL
    dest = plugin._Destination(kind=kind, id=dest_id, trust=trust)
    return plugin._Capability(
        direction=direction,
        destination=dest,
        data_classes=frozenset({"personal_private"}) if data_tags else frozenset(),
        data_tags=frozenset(data_tags),
        action_subtype="send",
    )


# --- Test 1: decide is total and pure ----------------------------------------
def test_1_decide_is_total_and_pure():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    directions = ["read", "write"]
    trusts = list(DT)
    class_sets = [set(), {"communications"}, {"local_system"}, {"personal_private"},
                  {"communications", "documents"}, {"garbage_class"}]
    modes = ["strict", "llm", "read-only", "off"]
    valid = {plugin._DECISION_ALLOW, plugin._DECISION_APPROVE, plugin._DECISION_BLOCK}

    for direction in directions:
        for trust in trusts:
            for classes in class_sets:
                for mode in modes:
                    cap = _mk_cap(plugin, direction=direction, trust=trust)
                    # Pure: re-calling with identical inputs yields the identical result
                    # and raises nothing (no I/O / side-effect state to witness now that
                    # the shadow-comparison scaffolding is retired — decide is authoritative).
                    result = plugin._decide(cap, classes, "unknown", mode)
                    assert result in valid
                    assert plugin._decide(cap, set(classes), "unknown", mode) == result


# --- Test 2: self/local/model never gate -------------------------------------
def test_2_intra_boundary_never_gates():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    for trust in (DT.SELF, DT.LOCAL_SYSTEM, DT.MODEL_PROVIDER):
        cap = _mk_cap(plugin, trust=trust)
        # Full personal taint still allows on an intra-boundary destination.
        assert plugin._decide(cap, {"communications"}, "unknown", "strict") == plugin._DECISION_ALLOW


# --- Test 3: external + private rule matrix -----------------------------------
def test_3_external_private_no_rule_approve_deny_block_allow_allow():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    cap = _mk_cap(plugin, trust=DT.EXTERNAL)
    # No rule -> APPROVE.
    assert plugin._decide(cap, {"communications"}, "unknown", "strict") == plugin._DECISION_APPROVE

    # Deny rule -> BLOCK.
    deny = privacy_rule(rule_id="r_deny", effect="deny", action_family="*",
                        destination="*", data_classes=["personal_private"])
    plugin._PERSISTENT_RULES_CACHE["privacy"]["rules"] = [deny]
    assert plugin._decide(cap, {"communications"}, "unknown", "strict") == plugin._DECISION_BLOCK

    # Allow rule -> ALLOW.
    allow = privacy_rule(rule_id="r_allow", effect="allow", action_family="*",
                         destination="*", data_classes=["personal_private"])
    plugin._PERSISTENT_RULES_CACHE["privacy"]["rules"] = [allow]
    assert plugin._decide(cap, {"communications"}, "unknown", "strict") == plugin._DECISION_ALLOW


# --- Test 4: unknown == external in decide ------------------------------------
def test_4_unknown_equals_external():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    cap_unknown = _mk_cap(plugin, trust=DT.UNKNOWN)
    cap_external = _mk_cap(plugin, trust=DT.EXTERNAL)
    for classes in (set(), {"communications"}, {"documents"}):
        for mode in ("strict", "llm"):
            assert plugin._decide(cap_unknown, classes, "unknown", mode) == \
                   plugin._decide(cap_external, classes, "unknown", mode)


# --- Test 5: conservative ambient default; verifier-upgrade seam --------------
def test_5_conservative_ambient_default_and_verifier_seam():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    cap = _mk_cap(plugin, trust=DT.EXTERNAL)
    # Under taint, external, no rule -> APPROVE using ambient classes (never ALLOW on the
    # basis that no private content was detected).
    assert plugin._decide(cap, {"communications"}, "unknown", "strict") == plugin._DECISION_APPROVE
    assert plugin._decide(cap, {"communications"}, "unknown", "llm") == plugin._DECISION_APPROVE
    # The verifier upgrade is the caller's, gated by mode (the seam). strict never allows
    # a verifier upgrade; llm does. decide itself stays at APPROVE in both.
    assert plugin._decide_mode_allows_verifier_upgrade("strict") is False
    assert plugin._decide_mode_allows_verifier_upgrade("llm") is True
    assert plugin._decide_mode_allows_verifier_upgrade("read-only") is False


# --- Test 6: class collapse preserves blocks ---------------------------------
def test_6_class_collapse_preserves_blocks():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    cap = _mk_cap(plugin, trust=DT.EXTERNAL)
    for fine in ("communications", "contacts", "calendar", "documents", "memory"):
        # Each fine class collapses to personal_private and still gates an external write.
        assert plugin._decide(cap, {fine}, "unknown", "strict") == plugin._DECISION_APPROVE


# --- Test 7: tag misfire changes no decision ---------------------------------
def test_7_tag_misfire_changes_no_decision():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    # A wrong fine TAG on the capability is descriptive only; the decision is driven by
    # the ambient taint argument, not the tag.
    cap_wrong_tag = _mk_cap(plugin, trust=DT.EXTERNAL, data_tags={"calendar"})
    cap_no_tag = _mk_cap(plugin, trust=DT.EXTERNAL)
    for classes in (set(), {"communications"}):
        assert plugin._decide(cap_wrong_tag, classes, "unknown", "strict") == \
               plugin._decide(cap_no_tag, classes, "unknown", "strict")


# --- Test 8: mode unification parity -----------------------------------------
def test_8_mode_unification_parity():
    plugin = load_plugin()
    DT = plugin._DestinationTrust
    cap = _mk_cap(plugin, trust=DT.EXTERNAL)
    # strict == verifier-off: step 6 APPROVE stands deterministically.
    assert plugin._decide(cap, {"communications"}, "unknown", "strict") == plugin._DECISION_APPROVE
    # read-only is a preset rule bundle, not a code branch in decide: decide produces the
    # same deterministic outcome regardless of the read-only/strict label.
    assert plugin._decide(cap, {"communications"}, "unknown", "read-only") == plugin._DECISION_APPROVE
    # Intra-boundary self-write allows in every mode.
    cap_self = _mk_cap(plugin, trust=DT.SELF)
    for mode in ("strict", "read-only", "llm"):
        assert plugin._decide(cap_self, {"communications"}, "unknown", mode) == plugin._DECISION_ALLOW


# --- Test 9: draft / idempotent self-write no longer gates --------------------
def test_9_draft_and_self_write_no_longer_gate():
    plugin = load_plugin()
    # A compose-draft resolves to a self destination (draft:* allowlist) -> ALLOW even
    # under full taint, where it gated pre-refactor.
    plugin._taint_session("s9", {"communications"})
    draft_cap = plugin._classify(
        "mcp_gmail_create_draft",
        {"to": "stranger@example.com", "subject": "d", "body": "b"},
        "s9",
    )
    draft_taint = plugin._data_classes_for_egress("s9", {"to": "stranger@example.com", "body": "b"})
    assert plugin._decide(draft_cap, draft_taint, "unknown", "strict") == plugin._DECISION_ALLOW

    # A self-store update (todo) under taint -> ALLOW.
    todo_cap = plugin._classify("todo", {"action": "add", "content": "buy milk"}, "s9")
    assert plugin._decide(todo_cap, {"communications"}, "unknown", "strict") == plugin._DECISION_ALLOW


# --- Test 10: corpus parity replay — THE FLOOR GATE --------------------------
def _replay_old_outcome_bucket(decision: str) -> str:
    """Map a recorded OLD ``decision`` to decide's vocabulary for comparison."""
    if decision in ("blocked",):
        return "block"
    if decision in ("security_blocked",):
        return "security_block"
    if decision in ("allowed",):
        return "allow"
    return decision


def test_10_corpus_parity_replay_zero_floor_breaches():
    records = json.loads((FIXTURES / "decision_corpus.json").read_text())
    assert len(records) == 26

    intra_boundary_trusts = None

    bucket_a = []  # expected intra-boundary gate->allow (FP wins)
    bucket_b = []  # floor breach (old block -> new ALLOW, not intra-boundary) — MUST be 0
    bucket_c = []  # new block (old allow -> new BLOCK/APPROVE)

    for rec in records:
        plugin = load_plugin()
        DT = plugin._DestinationTrust
        if intra_boundary_trusts is None:
            intra_boundary_trusts = {DT.SELF, DT.LOCAL_SYSTEM, DT.MODEL_PROVIDER}
        rid = rec["id"]
        tool = rec["tool"]
        args = rec["args_shape"]
        session_id = f"corpus_{rid}"
        # Reconstruct ambient session taint.
        if rec.get("taint"):
            plugin._taint_session(session_id, set(rec["taint"]))
        # Set the mode the record was captured under.
        plugin._PERSISTENT_RULES_CACHE["privacy"]["mode"] = rec["mode"]

        old = _replay_old_outcome_bucket(rec["decision"])

        # security_blocked records short-circuit BEFORE decide via the security/intrinsic
        # path; assert they still hard-block there and do NOT reach decide-ALLOW.
        if old == "security_block":
            intrinsic = plugin._intrinsic_risk_for_tool(tool, args)
            assert intrinsic is not None, f"{rid}: security_blocked record lost its hard block"
            continue

        cap, new = plugin._shadow_decision_for(tool, args, session_id)
        trust = cap.destination.trust

        if old == "block" and new == plugin._DECISION_ALLOW:
            if trust in intra_boundary_trusts or cap.destination.kind == "draft":
                bucket_a.append(rid)
            else:
                bucket_b.append((rid, str(trust)))
        elif old == "allow" and new in (plugin._DECISION_BLOCK, plugin._DECISION_APPROVE):
            bucket_c.append((rid, new))
        # old == new (incl. block->APPROVE which is still a gate = parity), or
        # block->BLOCK, or allow->ALLOW: parity, nothing to bucket.

        # Laundering records must NOT become decide-ALLOW (provenance carve-out is Phase 5;
        # here just confirm they stay gated/blocked).
        if rec.get("laundering"):
            assert new != plugin._DECISION_ALLOW, f"{rid}: laundering case flipped to ALLOW"

    # THE FLOOR GATE.
    assert bucket_b == [], f"floor breaches (bucket b): {bucket_b}"
    # Record buckets a/c for the report (visible on -s / failure).
    print("bucket_a (intra-boundary gate->allow):", bucket_a)
    print("bucket_c (new block):", bucket_c)
