"""Source provenance — tiering doc-read taint by where the content comes from.

Background: 0818f09 relaxed the doc-read taint path so placeholder contacts in
operator-installed skill docs stop producing false-positive egress gates, but it
keyed the relaxation on tool-*name* shape. The property that made relaxation safe is
*provenance* (skill docs are reference material), so a generic MCP resource read of
genuinely personal content used to read untainted — a silent false negative. These
tests pin the tiered model: reference-by-provenance (relaxed), declared (authoritative),
and undeclared MCP doc-read (conservative-until-declared).
"""

from __future__ import annotations

import os

from support import *  # noqa: F403

# Expanded Hermes home, resolved exactly like the matcher does, so path assertions
# hold on any host (mirrors tests/test_trusted_destinations.py).
_HERMES_HOME = os.environ.get("HERMES_HOME") or os.path.join(
    os.environ.get("HOME") or os.path.expanduser("~"), ".hermes"
)
_SKILLS_DOC = f"{_HERMES_HOME}/skills/productivity/crm/REFERENCE.md"


# --- Phase 0: pending-tool-args stash (pure plumbing, no behavior change) -----

def test_pending_tool_args_round_trip():
    plugin = load_plugin()
    plugin._stash_pending_tool_args("s1", "crm_read_document", {"path": "/x"})
    # Consumed once, keyed to the matching tool name...
    assert plugin._consume_pending_tool_args("s1", "crm_read_document") == {"path": "/x"}
    # ...and the slot is cleared afterward.
    assert plugin._consume_pending_tool_args("s1", "crm_read_document") is None


def test_pending_tool_args_tool_name_mismatch_clears_slot():
    plugin = load_plugin()
    plugin._stash_pending_tool_args("s1", "crm_read_document", {"path": "/x"})
    # A result for a different tool must not consume another tool's stashed args,
    # and the stale slot is cleared so it can never be mismatched later.
    assert plugin._consume_pending_tool_args("s1", "other_tool") is None
    assert plugin._consume_pending_tool_args("s1", "crm_read_document") is None


def test_pre_tool_call_stashes_args_consumed_by_result():
    plugin = load_plugin()
    bind_owner(plugin)
    sid = plugin._normalize_session_id("s1")

    plugin._on_pre_tool_call("skill_view", {"name": "deep-research"}, session_id="s1")
    assert sid in plugin.state._PENDING_TOOL_ARGS

    # Observing the result consumes (clears) the stash.
    plugin._on_transform_tool_result(tool_name="skill_view", result="hello", session_id="s1")
    assert sid not in plugin.state._PENDING_TOOL_ARGS


# --- Phase 1: relaxation keyed on provenance, not name ------------------------

# A placeholder business address taints under the generic content scan (any email is
# contact info) but NOT under the relaxed reference scan (which tolerates placeholders).
# It is the clean discriminator between "took the reference path" and "took the floor".
_PLACEHOLDER_DOC = "Configure: email = \"you@example.com\". Sample SMS: +1-415-555-1212."


def test_skills_path_read_via_generic_tool_name_stays_untainted():
    # Provenance, not name: a generically-named read whose target path resolves under the
    # skills tree is reference material, so the relaxed scan applies and placeholders are
    # tolerated — even though the tool is not skill_view and not an MCP doc-read by shape.
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_pre_tool_call("crm_fetch", {"path": _SKILLS_DOC}, session_id="ref")
    plugin._on_transform_tool_result(tool_name="crm_fetch", result=_PLACEHOLDER_DOC, session_id="ref")
    assert plugin._session_taint("ref") == set()


def test_undeclared_mcp_read_falls_to_generic_floor():
    # ``…_read_resource`` / ``…_get_resource`` are the live false-negative surface: their names
    # match no source-taint rule, so pre-0818f09 they reached the doc-read branch and, after
    # 0818f09, the relaxed scan — reading real personal content untainted. With provenance
    # tiering an undeclared one falls to the generic floor, which catches a real consumer
    # address (the FN starts closing; phases 2-3 refine the undeclared case).
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_transform_tool_result(
        tool_name="crm_read_resource",
        result="Reach the client at jane.doe@gmail.com about the renewal.",
        session_id="floor",
    )
    assert "contacts" in plugin._session_taint("floor")

    # And the placeholder discriminator: an undeclared MCP read of a placeholder-only doc
    # taints under the floor (interim conservative behavior), whereas the same content via a
    # skills-path read above did not — proving the two go through different scans.
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_PLACEHOLDER_DOC, session_id="floor2"
    )
    assert "contacts" in plugin._session_taint("floor2")


def test_reference_by_path_skips_inbound_sensitive_link_suppression():
    # The security inbound path consumes the same provenance verdict: a skills-path read skips
    # the "sensitive link" suppression (benign doc URL), an undeclared MCP read does not.
    plugin = load_plugin()
    bind_owner(plugin)
    doc = "# Setup\nVisit https://app.example.com/settings/verify and confirm.\n"

    plugin._on_pre_tool_call("crm_fetch", {"path": _SKILLS_DOC}, session_id="ref")
    assert plugin._on_transform_tool_result(tool_name="crm_fetch", result=doc, session_id="ref") is None

    # Same generic name, no skills-path provenance → not reference → suppressed.
    suppressed = plugin._on_transform_tool_result(
        tool_name="crm_read_document", result=doc, session_id="nope"
    )
    assert suppressed is not None
    assert parse_json(suppressed)["hermes_guardian"]["reason"] == "sensitive link"


# --- Phase 2: source declarations in the override registry -------------------

# Signal-less personal prose: no email/phone/SSN/iCal, so every content scan returns
# nothing. Only an authoritative declaration (or phase 3's conservative default) taints it.
_SIGNALLESS_PROSE = "The quarterly review went well and the client was pleased with progress."


def test_declared_reference_relaxes_to_placeholder_tolerant_scan():
    # A whole MCP server declared `source = "reference"` (prefix match) routes its doc-reads
    # through the relaxed scan: placeholders are tolerated where the undeclared floor taints.
    plugin = load_plugin()
    bind_owner(plugin)
    ok, _ = plugin._set_tool_override("crm_*", source="reference")
    assert ok

    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_PLACEHOLDER_DOC, session_id="ref"
    )
    assert plugin._session_taint("ref") == set()

    # Relaxed, not blanket-ignored: a real consumer-provider address in a reference doc
    # still taints (the same semantics as a skill doc).
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result="client jane.doe@gmail.com", session_id="real"
    )
    assert "contacts" in plugin._session_taint("real")


def test_declared_reference_overrides_name_rule_taint():
    # `…_read_document` matches the `document` source rule (→ documents) before any doc-read
    # branch; a declaration is authoritative and relaxes it anyway.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_tool_override("crm_*", source="reference")

    plugin._on_transform_tool_result(
        tool_name="crm_read_document", result=_PLACEHOLDER_DOC, session_id="ref"
    )
    assert plugin._session_taint("ref") == set()


def test_declared_private_taints_signalless_prose():
    # `source = "private"` always taints, even content with no structural signal — exactly the
    # case the undeclared floor misses (the FN phase 3 closes for undeclared servers).
    plugin = load_plugin()
    bind_owner(plugin)

    # Baseline: undeclared, signal-less prose taints nothing (the floor sees no signal).
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="undeclared"
    )
    assert plugin._session_taint("undeclared") == set()

    plugin._set_tool_override("crm_*", source="private")
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="declared"
    )
    assert plugin._session_taint("declared") == {"documents"}


def test_unknown_source_value_is_conservative():
    plugin = load_plugin()
    bind_owner(plugin)
    # The setter rejects an unknown mode outright...
    ok, message = plugin._set_tool_override("crm_*", source="trusted")
    assert not ok and "reference" in message
    # ...and the config loader drops it (fails toward the conservative default, never reference).
    normalized = plugin._normalize_tool_override({"match": "crm_*", "source": "trusted"})
    assert normalized is not None and normalized["source"] == ""
