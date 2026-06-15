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
from types import SimpleNamespace

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


class SourceFakeLLM:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def complete_structured(self, **kwargs):
        self.calls.append(kwargs)
        if not self.responses:
            raise RuntimeError("unexpected source classifier call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return SimpleNamespace(parsed=response)


def test_balanced_unknown_non_mcp_read_of_signalless_prose_stays_untainted():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classification(False)

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note", result=_SIGNALLESS_PROSE, session_id="balanced"
    )

    assert plugin._taint_classification_mode() == "balanced"
    assert plugin._session_taint("balanced") == set()


def test_relaxed_unknown_non_mcp_read_of_signalless_prose_stays_untainted():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classification(False)
    assert plugin._set_taint_classification_mode("relaxed")[0]

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note", result=_SIGNALLESS_PROSE, session_id="relaxed"
    )

    assert plugin._session_taint("relaxed") == set()


def test_strict_unknown_non_mcp_read_of_signalless_prose_taints_documents():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classification(False)
    assert plugin._set_taint_classification_mode("strict")[0]

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note", result=_SIGNALLESS_PROSE, session_id="strict"
    )

    assert plugin._session_taint("strict") == {"documents"}
    rows = _tainted_rows(plugin)
    assert rows and rows[0]["reason"] == "source_default:unknown_read"


def test_strict_unknown_non_mcp_read_preserves_specific_content_classes():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classification(False)
    assert plugin._set_taint_classification_mode("strict")[0]

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note", result="Reach Jane at jane.doe@gmail.com", session_id="strict"
    )

    assert plugin._session_taint("strict") == {"contacts"}


def test_strict_does_not_change_web_browser_or_error_result_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classification(False)
    assert plugin._set_taint_classification_mode("strict")[0]

    plugin._on_transform_tool_result(
        tool_name="browser_read",
        result="Your reservation is confirmed for 7:30 PM.",
        session_id="browser",
    )
    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        status="error",
        session_id="error",
    )
    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result="",
        session_id="empty",
    )
    plugin._privacy_observe_tool_result(
        tool_name="fetch_personal_note",
        result={"text": _SIGNALLESS_PROSE},
        session_id="structured",
    )

    assert plugin._session_taint("browser") == set()
    assert plugin._session_taint("error") == set()
    assert plugin._session_taint("empty") == set()
    assert plugin._session_taint("structured") == set()


def test_source_overrides_apply_to_arbitrary_unknown_reads():
    plugin = load_plugin()
    bind_owner(plugin)

    assert plugin._set_reading_tool("fetch_personal_note", source="private")[0]
    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note", result=_SIGNALLESS_PROSE, session_id="private"
    )
    assert plugin._session_taint("private") == {"documents"}

    assert plugin._set_reading_tool("fetch_reference_note", source="reference")[0]
    plugin._on_transform_tool_result(
        tool_name="fetch_reference_note", result=_PLACEHOLDER_DOC, session_id="reference"
    )
    assert plugin._session_taint("reference") == set()


def test_declared_unknown_source_keeps_balanced_fallback_and_suppresses_suggestions():
    plugin = load_plugin()
    bind_owner(plugin)

    assert plugin._set_source_classification("crm", "unknown")[0]
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="unknown"
    )

    assert plugin._session_taint("unknown") == {"documents"}
    assert plugin._source_classification_suggestions() == []


def test_declared_public_source_never_privacy_taints():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._set_reading_tool("clock_*", source="public")[0]

    plugin._on_transform_tool_result(
        tool_name="clock_now",
        result="client jane.doe@gmail.com and SSN 123-45-6789",
        session_id="public",
    )

    assert plugin._session_taint("public") == set()


def test_declared_public_source_ignores_strict_unknown_read_default():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._set_taint_classification_mode("strict")[0]
    assert plugin._set_reading_tool("clock_*", source="public")[0]

    plugin._on_transform_tool_result(
        tool_name="clock_now",
        result=_SIGNALLESS_PROSE,
        session_id="public-strict",
    )

    assert plugin._session_taint("public-strict") == set()


def test_public_source_classification_suppresses_suggestions():
    plugin = load_plugin()
    bind_owner(plugin)

    assert plugin._set_source_classification("time", "public")[0]

    assert plugin._source_classification_suggestions() == []
    assert plugin._reading_tool_for("time_read_resource")["source"] == "public"


def test_public_source_does_not_bypass_security_suppression():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._set_reading_tool("clock_*", source="public")[0]

    transformed = plugin._on_transform_tool_result(
        tool_name="clock_now",
        result="Your password reset code is 123456",
        session_id="public-security",
    )

    assert transformed is not None
    parsed = parse_json(transformed)
    assert parsed["hermes_guardian"]["suppressed"] is True
    assert parsed["security_sensitive_filter"]["reason"] == "password reset"
    assert plugin._session_taint("public-security") == set()


def test_llm_source_classifier_private_saves_rule_taints_and_does_not_repeat():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "private",
            "taints": ["memory"],
            "confidence": "high",
            "rationale": "tool metadata implies personal notes",
        }
    )

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-private",
    )
    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-private-again",
    )

    assert plugin._session_taint("llm-private") == {"memory"}
    assert plugin._session_taint("llm-private-again") == {"memory"}
    tools = plugin._reading_tools()
    assert len(tools) == 1
    assert tools[0]["match"] == "fetch_personal_note"
    assert tools[0]["source"] == "private"
    assert tools[0]["taints"] == ["memory"]
    assert len(plugin.state._PLUGIN_LLM.calls) == 1


def test_llm_source_classifier_persists_long_rationale_in_tool_note():
    plugin = load_plugin()
    bind_owner(plugin)
    rationale = " ".join(f"metadata-signal-{index}" for index in range(90))
    assert len(rationale) > 1000
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "private",
            "taints": ["memory"],
            "confidence": "high",
            "rationale": rationale,
        }
    )

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-long-rationale",
    )

    note = plugin._reading_tools()[0]["note"]
    assert note.startswith("LLM source classifier: metadata-signal-0")
    assert "metadata-signal-89" in note
    assert len(note) > 1000


def test_llm_source_classifier_uses_own_model_override():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classifier_model("gpt-5.4-flash")
    plugin._set_llm_verifier_model("gpt-5.4-mini")
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "private",
            "taints": ["memory"],
            "confidence": "high",
            "rationale": "tool metadata implies personal notes",
        }
    )

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-source-model",
    )

    assert plugin.state._PLUGIN_LLM.calls[0].get("model") == "gpt-5.4-flash"


def test_llm_source_classifier_model_override_falls_back_to_default():
    class FlakySourceLLM:
        def __init__(self):
            self.calls = []

        def complete_structured(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs.get("model"):
                raise RuntimeError("model override not allowed")
            return SimpleNamespace(
                parsed={
                    "source": "private",
                    "taints": ["memory"],
                    "confidence": "high",
                    "rationale": "ok on default",
                }
            )

    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_llm_source_classifier_model("gpt-5.4-flash")
    plugin.state._PLUGIN_LLM = FlakySourceLLM()

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-source-model-fallback",
    )

    assert len(plugin.state._PLUGIN_LLM.calls) == 2
    assert plugin.state._PLUGIN_LLM.calls[0].get("model") == "gpt-5.4-flash"
    assert "model" not in plugin.state._PLUGIN_LLM.calls[1]
    assert plugin._session_taint("llm-source-model-fallback") == {"memory"}


def test_llm_source_classifier_reference_saves_rule_and_relaxes_mcp_read():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "reference",
            "taints": ["documents"],
            "confidence": "high",
            "rationale": "tool metadata implies reference docs",
        }
    )

    plugin._on_transform_tool_result(
        tool_name="crm_read_resource",
        result=_SIGNALLESS_PROSE,
        session_id="llm-reference",
    )
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource",
        result=_SIGNALLESS_PROSE,
        session_id="llm-reference-again",
    )

    assert plugin._session_taint("llm-reference") == set()
    assert plugin._session_taint("llm-reference-again") == set()
    tools = plugin._reading_tools()
    assert len(tools) == 1
    assert tools[0]["match"] == "crm_*"
    assert tools[0]["source"] == "reference"
    assert tools[0]["taints"] == []
    assert len(plugin.state._PLUGIN_LLM.calls) == 1


def test_llm_source_classifier_public_saves_rule_and_does_not_taint():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "public",
            "taints": ["documents"],
            "confidence": "high",
            "rationale": "tool metadata implies current time",
        }
    )

    plugin._on_transform_tool_result(
        tool_name="mcp_google_workspace_time_getcurrenttime",
        result="2026-06-15T12:00:00Z",
        session_id="llm-public",
    )
    plugin._on_transform_tool_result(
        tool_name="mcp_google_workspace_time_getcurrenttime",
        result="client jane.doe@gmail.com",
        session_id="llm-public-again",
    )

    assert plugin._session_taint("llm-public") == set()
    assert plugin._session_taint("llm-public-again") == set()
    tools = plugin._reading_tools()
    assert len(tools) == 1
    assert tools[0]["match"] == "mcp_google_workspace_time_getcurrenttime"
    assert tools[0]["source"] == "public"
    assert tools[0]["taints"] == []
    assert len(plugin.state._PLUGIN_LLM.calls) == 1


def test_llm_source_classifier_public_requires_high_confidence():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "public",
            "taints": [],
            "confidence": "medium",
            "rationale": "tool metadata weakly implies current time",
        }
    )

    plugin._on_transform_tool_result(
        tool_name="mcp_google_workspace_time_getcurrenttime",
        result="2026-06-15T12:00:00Z",
        session_id="llm-public-medium",
    )

    tools = plugin._reading_tools()
    assert len(tools) == 1
    assert tools[0]["source"] == "unknown"
    assert plugin._session_taint("llm-public-medium") == set()


def test_llm_source_classifier_unknown_saves_rule_and_preserves_fallback():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "unknown",
            "taints": ["documents"],
            "confidence": "low",
            "rationale": "metadata is ambiguous",
        }
    )

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-unknown",
    )
    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-unknown-again",
    )

    assert plugin._session_taint("llm-unknown") == set()
    assert plugin._session_taint("llm-unknown-again") == set()
    tools = plugin._reading_tools()
    assert len(tools) == 1
    assert tools[0]["source"] == "unknown"
    assert tools[0]["taints"] == []
    assert len(plugin.state._PLUGIN_LLM.calls) == 1


def test_llm_source_classifier_sends_only_metadata_not_raw_values():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(
        {
            "source": "unknown",
            "taints": [],
            "confidence": "low",
            "rationale": "metadata is ambiguous",
        }
    )

    plugin._on_pre_tool_call(
        "fetch_personal_note",
        {
            "query": "Jennifer dinner private thought",
            "limit": 3,
            "filters": {"person": "Jennifer"},
        },
        session_id="metadata",
    )
    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result='{"Jennifer": "Felt weird after dinner yesterday."}',
        session_id="metadata",
    )

    call_text = plugin.state._PLUGIN_LLM.calls[0]["input"][0]["text"]
    assert "Jennifer dinner private thought" not in call_text
    assert "Felt weird after dinner yesterday" not in call_text
    assert '"query"' in call_text
    assert '"filters"' in call_text
    assert '"Jennifer"' in call_text  # JSON keys are allowed metadata.


def test_llm_source_classifier_error_saves_no_rule_and_falls_back():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin.state._PLUGIN_LLM = SourceFakeLLM(RuntimeError("boom"))

    plugin._on_transform_tool_result(
        tool_name="fetch_personal_note",
        result=_SIGNALLESS_PROSE,
        session_id="llm-error",
    )

    assert plugin._session_taint("llm-error") == set()
    assert plugin._reading_tools() == []


def test_source_reference_does_not_override_known_private_source_names():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._set_reading_tool("gmail_*", source="reference")[0]

    plugin._on_transform_tool_result(
        tool_name="gmail_fetch", result=_PLACEHOLDER_DOC, session_id="gmail"
    )

    assert plugin._session_taint("gmail") == {"communications"}


def test_source_public_does_not_override_known_private_source_names():
    plugin = load_plugin()
    bind_owner(plugin)
    assert plugin._set_reading_tool("mcp_gmail_*", source="public")[0]

    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_read_resource",
        result="2026-06-15T12:00:00Z",
        session_id="gmail-public",
    )

    assert plugin._session_taint("gmail-public") == {"communications"}


def test_declared_reference_relaxes_to_placeholder_tolerant_scan():
    # A whole MCP server declared `source = "reference"` (prefix match) routes its doc-reads
    # through the relaxed scan: placeholders are tolerated where the undeclared floor taints.
    plugin = load_plugin()
    bind_owner(plugin)
    ok, _ = plugin._set_reading_tool("crm_*", source="reference")
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
    plugin._set_reading_tool("crm_*", source="reference")

    plugin._on_transform_tool_result(
        tool_name="crm_read_document", result=_PLACEHOLDER_DOC, session_id="ref"
    )
    assert plugin._session_taint("ref") == set()


def test_declared_private_taints_signalless_prose():
    # `source = "private"` always taints `documents`, even content with no structural signal.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_reading_tool("crm_*", source="private")
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="declared"
    )
    assert plugin._session_taint("declared") == {"documents"}


def test_unknown_source_value_is_conservative():
    plugin = load_plugin()
    bind_owner(plugin)
    ok, _ = plugin._set_reading_tool("crm_*", source="unknown")
    assert ok
    assert plugin._reading_tools()[0]["source"] == "unknown"
    # Truly invalid modes are still rejected outright...
    ok, message = plugin._set_reading_tool("crm_*", source="trusted")
    assert not ok and "unknown" in message
    # ...and the config loader drops it (fails toward the conservative default, never reference).
    normalized = plugin._normalize_reading_tool({"match": "crm_*", "source": "trusted"})
    assert normalized is not None and normalized["source"] == ""


# --- Phase 3: undeclared MCP doc-reads fail closed, with a one-click exit -----

def _tainted_rows(plugin):
    return plugin._activity_rows({"decision": "tainted"}, limit=20)


def test_undeclared_mcp_read_of_signalless_prose_taints_the_fn_closes():
    # THE headline: signal-less personal prose from an undeclared MCP doc-read used to read
    # untainted (the false negative). It now taints `documents` conservatively, with the
    # source_default reason carried into the activity row and a Reading deep-link.
    plugin = load_plugin()
    bind_owner(plugin)

    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="fn"
    )
    assert plugin._session_taint("fn") == {"documents"}

    rows = _tainted_rows(plugin)
    assert rows and rows[0]["reason"] == "source_default:undeclared_mcp_read"
    # The row deep-links to the Reading picker (decision_step base maps there).
    assert rows[0]["decision_step"].split(":")[0] == "source_default"


def test_undeclared_mcp_read_records_one_suggestion_per_server_per_session():
    plugin = load_plugin()
    bind_owner(plugin)

    for _ in range(3):
        plugin._on_transform_tool_result(
            tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="s1"
        )
    # A second tool on the same server prefix is still the same server.
    plugin._on_transform_tool_result(
        tool_name="crm_get_resource", result=_SIGNALLESS_PROSE, session_id="s1"
    )
    suggestions = plugin._source_classification_suggestions()
    servers = [s["server"] for s in suggestions]
    assert servers.count("crm") == 1


def test_picker_round_trip_declare_reference_flips_to_relaxed():
    # Declaring the seen server as reference (via the picker setter) flips subsequent reads to
    # the relaxed path, and the server drops out of the suggestions list.
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_PLACEHOLDER_DOC, session_id="s1"
    )
    assert plugin._session_taint("s1") == {"documents"}
    assert any(s["server"] == "crm" for s in plugin._source_classification_suggestions())

    ok, _ = plugin._set_source_classification("crm", "reference")
    assert ok
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_PLACEHOLDER_DOC, session_id="s2"
    )
    assert plugin._session_taint("s2") == set()  # relaxed: placeholders tolerated
    assert not any(s["server"] == "crm" for s in plugin._source_classification_suggestions())


def test_picker_declare_private_taints_with_declared_reason_not_default():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_source_classification("crm", "private")
    plugin._on_transform_tool_result(
        tool_name="crm_read_resource", result=_SIGNALLESS_PROSE, session_id="s1"
    )
    assert plugin._session_taint("s1") == {"documents"}
    # Declared, so NOT the source_default reason.
    rows = _tainted_rows(plugin)
    assert rows and rows[0]["reason"] != "source_default:undeclared_mcp_read"


def test_skills_reads_never_record_a_source_suggestion():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._on_transform_tool_result(tool_name="skill_view", result=_SIGNALLESS_PROSE, session_id="s1")
    plugin._on_pre_tool_call("crm_fetch", {"path": _SKILLS_DOC}, session_id="s1")
    plugin._on_transform_tool_result(tool_name="crm_fetch", result=_SIGNALLESS_PROSE, session_id="s1")
    assert plugin._source_classification_suggestions() == []
