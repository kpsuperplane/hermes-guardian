#!/usr/bin/env python3
"""Phase 0 decision-corpus generator (refactor doc 04 §2).

Drives a fixed, scripted set of tool calls through the REAL current privacy
decision path and records the observed (pre-refactor) decision for each. The
output `decision_corpus.json` is the "floor ground truth": a later phase replays
it and asserts that no previously-correct block silently becomes an allow, with a
single sanctioned carve-out for the provenance-laundering cases (tagged
`laundering: true`).

Decisions are OBSERVED, never hand-authored. We run each scenario through
`_on_pre_tool_call` (the privacy hook) exactly the way the existing tests do
(via tests/support.py), then read the resulting decision off the activity log so
the corpus reflects true current behavior.

Run reproducibly with:

    python3 tests/fixtures/_build_decision_corpus.py

IMPORTANT (project memory): no real agent/cron/Telegram identifiers appear in
any scenario — they resolve real delivery targets. All recipients, session ids,
and the synthetic cron id below are placeholders that resolve nothing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make tests/support.py importable the same way the test suite does (pytest adds
# the tests dir to sys.path; we replicate that for standalone execution).
_TESTS_DIR = Path(__file__).resolve().parents[1]
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from support import (  # noqa: E402
    FakeSecurityLlm,
    bind_owner,
    load_plugin,
    save_privacy_config,
)

OUT_PATH = Path(__file__).resolve().parent / "decision_corpus.json"

# A synthetic cron session id matching the cron_<12hex>_<date>_<time> shape the
# plugin recognizes (privacy/approvals.py::_is_cron_session_id). The hex id is
# all-placeholder and resolves to NO real cron job / Telegram target.
CRON_SESSION = "cron_0000000000aa_20260101_000000"

# Verbatim private payloads observed from a private read, then re-sent. These are
# long enough to clear the provenance min-length gate so the current code's
# fingerprint match fires (the laundering carve-out hinges on this).
CALENDAR_PHRASE = "Project Helios kickoff sync with the legal team on Thursday at 3pm in room B"
EMAIL_PHRASE = "Quarterly roadmap notes mention the private launch window before the board call"
PARAPHRASE_OF_EMAIL = "The roadmap notes brought up an unannounced launch window ahead of the board"


def _deny_llm():
    """A verifier stub that denies — mirrors test_provenance.py's FakeSecurityLlm.

    Under llm mode the real verifier reads the payload and judges it. We pin a
    deny verdict so the observed decision is deterministic and reproducible
    rather than depending on a live model.
    """
    return FakeSecurityLlm(
        {
            "outcome": "deny",
            "risk_level": "high",
            "authorization_level": "unknown",
            "rationale": "tainted private content leaving to an external destination",
        }
    )


def _latest_decision(plugin) -> str:
    rows = plugin._activity_rows({}, limit=1)
    return rows[0]["decision"] if rows else "none"


def _observe_calendar(plugin, session_id: str = "s1") -> None:
    plugin._on_transform_tool_result(
        tool_name="mcp_calendar_list_events",
        result=json.dumps({"events": [{"summary": CALENDAR_PHRASE}]}),
        session_id=session_id,
    )


def _observe_email(plugin, session_id: str = "s1") -> None:
    plugin._on_transform_tool_result(
        tool_name="mcp_gmail_search",
        result=json.dumps({"messages": [{"snippet": EMAIL_PHRASE}]}),
        session_id=session_id,
    )


def _run_scenario(
    *,
    record_id: str,
    category: str,
    tool: str,
    args: dict,
    taint: list[str],
    mode: str,
    laundering: bool = False,
    session_id: str = "s1",
    provenance_read=None,
    use_deny_llm: bool = False,
):
    """Drive one scenario through the live hook and capture the real decision."""
    plugin = load_plugin()
    save_privacy_config(plugin, mode=mode)
    if use_deny_llm:
        plugin.state._PLUGIN_LLM = _deny_llm()
    bind_owner(plugin, session_id=session_id)
    if provenance_read is not None:
        provenance_read(plugin, session_id)
    if taint:
        plugin._taint_session(session_id, set(taint))

    result = plugin._on_pre_tool_call(tool, args, session_id=session_id)

    hook_returned = "block" if result is not None else None
    activity_decision = _latest_decision(plugin)
    # Normalize to a single corpus decision string. A hook that returns a result
    # is a gate/block (the call does not proceed); None means the call is allowed
    # to proceed. We keep the finer activity decision too for replay bucketing.
    if hook_returned == "block":
        decision = activity_decision if activity_decision in {"blocked", "security_blocked"} else "blocked"
    else:
        decision = activity_decision if activity_decision in {"auto_approved", "allowed", "read"} else "allowed"

    return {
        "id": record_id,
        "category": category,
        "tool": tool,
        "args_shape": args,
        "taint": list(taint),
        "mode": mode,
        "decision": decision,
        "hook_returned": hook_returned,
        "activity_decision": activity_decision,
        "laundering": laundering,
    }


# Each entry is kwargs for _run_scenario. Recipients/paths/ids are synthetic.
SCENARIOS = [
    # ---- self-writes (currently GATE under taint; the FP we remove later) ----
    dict(record_id="self_write_local_file_strict", category="self_write",
         tool="write_file", args={"path": "/tmp/notes.txt", "content": "summary"},
         taint=["communications"], mode="strict"),
    dict(record_id="self_write_local_file_llm", category="self_write",
         tool="write_file", args={"path": "/tmp/notes.txt", "content": "summary"},
         taint=["communications"], mode="llm", use_deny_llm=True),
    dict(record_id="self_write_notion_page_strict", category="self_write",
         tool="mcp_notion_create_page", args={"title": "Contact notes"},
         taint=["contacts"], mode="strict"),
    dict(record_id="self_write_calendar_event_strict", category="self_write",
         tool="mcp_calendar_create_event",
         args={"summary": "Dentist", "start": "2026-06-10T09:00"},
         taint=["calendar"], mode="strict"),
    dict(record_id="self_write_memory_strict", category="self_write",
         tool="memory", args={"action": "add", "target": "user", "content": "preference"},
         taint=["memory"], mode="strict"),
    dict(record_id="self_write_todo_strict", category="self_write",
         tool="todo", args={"action": "add", "content": "buy milk"},
         taint=["memory"], mode="strict"),

    # ---- external sends (currently block / require approval) ----
    dict(record_id="external_email_send_strict", category="external_send",
         tool="mcp_gmail_send_message",
         args={"to": "stranger@example.com", "subject": "Hi", "body": "public hello"},
         taint=["communications"], mode="strict"),
    dict(record_id="external_message_send_strict", category="external_send",
         tool="send_message", args={"to": "stranger@example.com", "text": "summarized private context"},
         taint=["communications"], mode="strict"),
    dict(record_id="external_message_send_llm", category="external_send",
         tool="send_message", args={"to": "stranger@example.com", "text": "summarized private context"},
         taint=["communications"], mode="llm", use_deny_llm=True),

    # ---- drafts (compose a draft under taint) ----
    dict(record_id="draft_email_strict", category="draft",
         tool="mcp_gmail_create_draft",
         args={"to": "stranger@example.com", "subject": "Draft", "body": "draft body"},
         taint=["communications"], mode="strict"),

    # ---- shares / invites / publish on an otherwise-self store ----
    dict(record_id="share_drive_file_strict", category="share",
         tool="mcp_drive_share_file",
         args={"file_id": "doc_synthetic_1", "email": "stranger@example.com"},
         taint=["documents"], mode="strict"),
    dict(record_id="share_notion_publish_strict", category="share",
         tool="mcp_notion_share_page",
         args={"page_id": "page_synthetic_1", "email": "stranger@example.com"},
         taint=["documents"], mode="strict"),

    # ---- unknown tools under taint (gate mode) ----
    dict(record_id="unknown_mcp_tool_strict", category="unknown_tool",
         tool="mcp_drive_blobify", args={"path": "/tmp/x"},
         taint=["communications"], mode="strict"),
    dict(record_id="unknown_bare_tool_strict", category="unknown_tool",
         tool="frobnicate_widget", args={"body": "hello"},
         taint=["memory"], mode="strict"),

    # ---- cron egress (unattended session) ----
    dict(record_id="cron_message_send_strict", category="cron_egress",
         tool="send_message", args={"to": "stranger@example.com", "text": "scheduled report body"},
         taint=["communications"], mode="strict", session_id=CRON_SESSION),
    dict(record_id="cron_message_send_llm", category="cron_egress",
         tool="send_message", args={"to": "stranger@example.com", "text": "scheduled report body"},
         taint=["communications"], mode="llm", session_id=CRON_SESSION, use_deny_llm=True),

    # ---- paraphrase: read private content, send an external paraphrase ----
    dict(record_id="paraphrase_email_to_stranger_strict", category="paraphrase",
         tool="send_message", args={"to": "stranger@example.com", "text": PARAPHRASE_OF_EMAIL},
         taint=[], mode="strict", provenance_read=_observe_email),
    dict(record_id="paraphrase_email_to_stranger_llm", category="paraphrase",
         tool="send_message", args={"to": "stranger@example.com", "text": PARAPHRASE_OF_EMAIL},
         taint=[], mode="llm", provenance_read=_observe_email, use_deny_llm=True),

    # ---- verbatim laundering: read private, send VERBATIM externally ----
    # These are the provenance-retirement carve-out cases (doc 04 §7.1). Tagged
    # laundering: true. Under llm mode they currently resolve to a block.
    dict(record_id="laundering_calendar_verbatim_llm", category="verbatim_laundering",
         tool="send_message", args={"to": "stranger@example.com", "text": CALENDAR_PHRASE},
         taint=[], mode="llm", laundering=True,
         provenance_read=_observe_calendar, use_deny_llm=True),
    dict(record_id="laundering_email_verbatim_llm", category="verbatim_laundering",
         tool="send_message", args={"to": "stranger@example.com", "text": EMAIL_PHRASE},
         taint=[], mode="llm", laundering=True,
         provenance_read=_observe_email, use_deny_llm=True),
    dict(record_id="laundering_calendar_verbatim_strict", category="verbatim_laundering",
         tool="send_message", args={"to": "stranger@example.com", "text": CALENDAR_PHRASE},
         taint=[], mode="strict", laundering=True,
         provenance_read=_observe_calendar),
    dict(record_id="laundering_email_verbatim_email_send_llm", category="verbatim_laundering",
         tool="mcp_gmail_send_message",
         args={"to": "stranger@example.com", "subject": "fwd", "body": EMAIL_PHRASE},
         taint=[], mode="llm", laundering=True,
         provenance_read=_observe_email, use_deny_llm=True),

    # ---- untainted controls (normal egress, no taint -> should allow) ----
    # A genuinely non-private message (no PII in recipient or text) is allowed
    # outright even in strict mode: nothing taints it and nothing in the payload
    # raises a data class. This is the clean "untainted allow" control.
    dict(record_id="untainted_clean_message_send_strict", category="untainted",
         tool="send_message", args={"to": "teammate", "text": "status update posted"},
         taint=[], mode="strict"),
    # An untainted send whose *recipient address* is itself PII (an email) raises
    # `contacts` from the payload alone, so it gates even with no prior taint.
    # Recorded to pin that current behavior, not because it "should" gate.
    dict(record_id="untainted_message_send_strict", category="untainted",
         tool="send_message", args={"to": "stranger@example.com", "text": "public hello"},
         taint=[], mode="strict"),
    dict(record_id="untainted_message_send_llm", category="untainted",
         tool="send_message", args={"to": "stranger@example.com", "text": "public hello"},
         taint=[], mode="llm"),
    dict(record_id="untainted_notion_write_strict", category="untainted",
         tool="mcp_notion_create_page", args={"title": "Public roadmap"},
         taint=[], mode="strict"),
]


def main() -> None:
    corpus = [_run_scenario(**scenario) for scenario in SCENARIOS]
    OUT_PATH.write_text(json.dumps(corpus, indent=2, sort_keys=False) + "\n")

    # Quick self-summary on stdout for the generator's own log.
    from collections import Counter

    cats = Counter(r["category"] for r in corpus)
    laundering = [r for r in corpus if r["laundering"]]
    print(f"wrote {len(corpus)} records to {OUT_PATH}")
    print("category breakdown:", dict(cats))
    print(f"laundering-tagged: {len(laundering)}")
    for r in laundering:
        print(f"  {r['id']}: mode={r['mode']} decision={r['decision']}")


if __name__ == "__main__":
    main()
