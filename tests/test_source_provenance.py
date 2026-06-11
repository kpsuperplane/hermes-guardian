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
