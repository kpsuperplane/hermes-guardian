"""Capability model: one resolution that produces a ``Capability`` (doc 02 §2, §5, §7).

Phase 2 of the destination-trust refactor. ADDITIVE / SHADOW: this module builds a
``Capability`` for a tool call by ROUTING the existing classifier logic in
``privacy/tool_policy.py`` (the §7 old->new mapping) and resolving the destination's
trust via the Phase 1 resolver (``resolve_destination_trust`` in
``privacy/destinations.py``). It is run alongside the authoritative decision in shadow
mode (``privacy/module.py``); it is NOT yet authoritative (that is Phase 3).

This file follows the exec-loaded loader style (AGENTS.md "Loader And Namespace
Rules"): it does NOT import sibling plugin modules; it references shared globals
(``_egress_tool_action``, ``_session_taint``, ``resolve_destination_trust``,
``_classes_from_content``, ``_mcp_destination``, ``_browser_host``, …) directly. It is
loaded AFTER ``privacy/tool_policy`` and ``privacy/destinations`` (see
``core.py`` ``_CORE_LOGIC_MODULES``). Only standard-library imports appear.

The policy-class / tag split (doc 02 §5): the fine source classes
(communications/contacts/calendar/documents/memory) collapse to the single POLICY
class ``personal_private`` that ``decide`` reasons over, while the fine class is kept
in ``data_tags`` for the audit trail (invariant #6). ``local_system`` and
``browser_private_input`` map to their own policy classes. Tags are DESCRIPTIVE only and
never load-bearing for a block.
"""

from __future__ import annotations

import re


from dataclasses import dataclass, field
from typing import Any


# --- Policy classes / descriptive tags (doc 02 §5) ---------------------------
# POLICY classes are what ``decide`` reasons over. Small and total.
PRIVATE_POLICY_CLASSES = frozenset({"personal_private"})
POLICY_CLASSES = frozenset({"personal_private", "local_system", "browser_private", "public"})

# DESCRIPTIVE fine tags preserved on every record for audit + optional rules.
DATA_TAGS = frozenset({"communications", "contacts", "calendar", "documents", "memory"})

# Mapping from the seven fine taint classes to their POLICY class (doc 02 §5).
# The fine class is also kept as a descriptive tag (only the five personal ones are
# DATA_TAGS; local_system / browser_private are their own policy classes, not tags).
_FINE_TO_POLICY_CLASS = {
    "communications": "personal_private",
    "contacts": "personal_private",
    "calendar": "personal_private",
    "documents": "personal_private",
    "memory": "personal_private",
    "local_system": "local_system",
    "browser_private_input": "browser_private",
}


def _policy_classes_for(fine_classes: Any) -> frozenset[str]:
    """Collapse a set of fine classes to their POLICY classes (doc 02 §5)."""
    out: set[str] = set()
    for cls in fine_classes or ():
        mapped = _FINE_TO_POLICY_CLASS.get(str(cls))
        if mapped:
            out.add(mapped)
    return frozenset(out)


def _data_tags_for(fine_classes: Any) -> frozenset[str]:
    """Keep the fine personal classes as descriptive audit tags (invariant #6)."""
    return frozenset(str(cls) for cls in (fine_classes or ()) if str(cls) in DATA_TAGS)


# --- Capability tuple (doc 02 §2) --------------------------------------------
@dataclass(frozen=True)
class Destination:
    """A sink's destination, resolved to a trust level (doc 02 §2, doc 01 §3).

    ``trust`` is a ``DestinationTrust`` (a ``str`` Enum from ``privacy/destinations``),
    so it compares/serializes as its plain string label while staying typo-proof.
    """

    kind: str
    id: str
    trust: Any  # DestinationTrust (shared global; no plugin import here)


@dataclass(frozen=True)
class Capability:
    """The single resolved description of a tool call (doc 02 §2).

    NOTE (provenance retired, doc 02 §2/§4): there is NO ``exported_source_classes`` /
    ``source_classes`` field. ``decide`` reasons over ambient session taint; the verifier
    does payload-level narrowing in ``llm`` mode.
    """

    direction: str                       # "read" | "write"
    destination: Destination
    data_classes: frozenset[str] = field(default_factory=frozenset)   # POLICY classes
    data_tags: frozenset[str] = field(default_factory=frozenset)      # DESCRIPTIVE tags
    action_subtype: str = ""             # normalized verb


# --- action_family -> destination-resolver inputs (doc 02 §7) -----------------
# Each egress ``action_family`` (from ``_egress_tool_action``) maps to a coarse
# destination ``kind`` understood by ``resolve_destination_trust`` (doc 01 §3). The
# resolver then matches the concrete ``id`` against the self allowlist / identities /
# hosts. The action_subtype is a normalized verb for the resolver + audit.
#
# These are the §7 "_egress_tool_action family table" rows, given a destination kind.
# NOTE on the generic/unknown sink families (``mcp_unknown``, ``tool_write``,
# ``tool_unknown``): these are NOT content-to-own-store writes whose connector + verb
# Guardian recognizes (those are ``mcp_write`` / ``local_write`` / ``kanban_write`` /
# draft). They are the catch-all action sinks — an unrecognized MCP verb, or a generic
# write/delete/admin/financial tool the override table routes here (delete_file,
# create_calendar_event, send_money, ...). Their destination string is a coarse SERVICE
# label, not a proven self content store, and the ACTION itself is unproven. Resolving
# them via the self-store allowlist would be an "ownership/verb absence means safe"
# inference — exactly what charter invariant #2/#4 forbids — and would let a tainted
# session egress through an unknown verb on a self connector (the agentdojo
# ``delete_file`` / external-participant ``create_calendar_event`` leaks). So they map to
# the ``opaque`` kind, which the resolver does not match against the self allowlist; it
# falls through to unknown -> external and gates under taint, fail-closed. A
# participant-free self write through a RECOGNIZED family keeps its self resolution, so
# the FP win is preserved.
_FAMILY_TO_DEST_KIND = {
    "mcp_write": "store",
    "mcp_read_query": "store",
    "mcp_unknown": "opaque",
    "message_send": "messaging",
    "message_list": "messaging",
    "local_write": "local",
    "kanban_write": "store",
    "homeassistant_write": "local",
    "cron_write": "local",
    "model_api": "model",
    "terminal_exec": "terminal",
    "web_api": "host",
    "web_read": "host",
    "browser_read": "host",
    "browser_type": "browser",
    "browser_click": "browser",
    "browser_press": "browser",
    "browser_dialog": "browser",
    "browser_console": "browser",
    "browser_cdp": "browser",
    "computer_use": "local",
    "delegate_task": "subagent",
    "tool_write": "opaque",
    "tool_unknown": "opaque",
    "final_response": "messaging",
}

# Normalized action subtype per family (doc 02 §2). Outward-sharing subtypes
# (share/invite/publish/...) are detected from the tool name below so the resolver's
# §3.1 outward-sharing guard fires; everything else is the family's nominal verb.
_FAMILY_TO_SUBTYPE = {
    "mcp_write": "create",
    "mcp_read_query": "query",
    "mcp_unknown": "write",
    "message_send": "send",
    "message_list": "read",
    "local_write": "write",
    "kanban_write": "write",
    "homeassistant_write": "write",
    "cron_write": "create",
    "model_api": "query",
    "terminal_exec": "exec",
    "web_api": "send",
    "web_read": "read",
    "browser_read": "read",
    "browser_type": "type",
    "browser_click": "click",
    "browser_press": "press",
    "browser_dialog": "dialog",
    "browser_console": "exec",
    "browser_cdp": "exec",
    "computer_use": "write",
    "delegate_task": "delegate",
    "tool_write": "write",
    "tool_unknown": "write",
    "final_response": "send",
}

# Families whose destination is a message recipient, not a store/host. For these the
# resolver judges the recipient identity rather than the connector id (doc 01 §3.2).
_MESSAGING_FAMILIES = frozenset({"message_send", "message_list", "final_response"})

# A compose-draft writes to the user's own draft store; it reaches no other party until
# a separate send (doc 02 §7 "drafts/idempotent-self-writes now resolve to self"). The
# old path classified these as mcp_write and gated them — that is the FP being removed.
# Detected by tool name so it can be routed to Destination(kind="draft"), matching the
# "draft:*" self allowlist token. A SEND verb on the same name disqualifies it.
_DRAFT_TOOL_RE = re.compile(r"(?:^|[^a-z0-9])(create_draft|draft)(?:[^a-z0-9]|$)", re.I)
_DRAFT_SEND_VERB_RE = re.compile(
    r"(?:^|[^a-z0-9])(send|publish|share|deliver|dispatch)(?:[^a-z0-9]|$)", re.I
)


def _is_draft_compose(tool_name: str, action_family: str) -> bool:
    lower = str(tool_name or "").lower()
    if action_family in _MESSAGING_FAMILIES:
        return False
    if _DRAFT_SEND_VERB_RE.search(lower):
        return False
    return bool(_DRAFT_TOOL_RE.search(lower))

# Tool-name verbs that reach other parties even on a self-owned store (doc 01 §3.1).
# Detecting them lets ``resolve_destination_trust`` apply its outward-sharing guard so a
# share/publish on a self connector still resolves to external, not self. ``re`` is a
# shared core global available when core.py exec-loads this module.
_OUTWARD_SHARING_VERB_RE = re.compile(
    r"(?:^|[^a-z0-9])(share|invite|publish|add_collaborator|make_public|set_permissions|"
    r"add_permission|grant)(?:[^a-z0-9]|$)",
    re.I,
)

# Arg keys that name OTHER PARTIES on a write (doc 01 §3.1). A write to a self-owned
# store that carries one of these with a resolvable external recipient reaches a new
# party (e.g. a calendar event with `participants`, a doc created with `cc`), so it is
# outward-sharing even though the destination connector is the operator's own. Detecting
# it lets ``resolve_destination_trust``'s §3.1 guard resolve the call to external, not
# self — closing the "create_calendar_event with external participants" leak while a
# participant-free self write stays intra-boundary (the FP win is preserved).
_RECIPIENT_ARG_KEYS = (
    "participants",
    "attendees",
    "invitees",
    "guests",
    "to",
    "cc",
    "bcc",
    "recipients",
    "emails",
    "members",
)
_EMAIL_LIKE_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def _carries_external_recipient(args: Any) -> bool:
    """True iff a write's args name an other-party recipient (an email-like value under a
    recipient-shaped key). Conservative: only a value that looks like an external address
    counts, so an empty/templated field never spuriously flips a self write to external."""
    if not isinstance(args, dict):
        return False
    for key in _RECIPIENT_ARG_KEYS:
        value = args.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            candidates = [value]
        elif isinstance(value, (list, tuple, set)):
            candidates = [str(v) for v in value]
        else:
            candidates = [str(value)]
        for candidate in candidates:
            if _EMAIL_LIKE_RE.search(candidate):
                return True
    return False


def _dest_kind_for_family(action_family: str) -> str:
    return _FAMILY_TO_DEST_KIND.get(str(action_family or ""), "store")


def _dest_id_for_action(action_family: str, action: Any) -> str:
    """Derive the concrete destination id the resolver matches on (doc 02 §7).

    ``mcp:<server>`` style destinations collapse to the bare connector id so they match
    the self-destination allowlist tokens like ``store:notion``. Messaging destinations
    are handled separately by recipient identity, so id here is just a label.
    """
    family = str(action_family or "")
    destination = str(getattr(action, "destination", "") or "")
    if family in _MESSAGING_FAMILIES:
        return "messaging"
    if destination.startswith("mcp:"):
        # mcp:notion -> "notion"; matches the "store:notion" self allowlist token.
        return destination.split(":", 1)[1] or destination
    return destination


def _action_subtype_for(action_family: str, tool_name: str) -> str:
    """Normalized verb for the family, upgraded to an outward-sharing subtype when the
    tool name implies one (doc 01 §3.1)."""
    lower = str(tool_name or "").lower()
    match = _OUTWARD_SHARING_VERB_RE.search(lower)
    if match:
        return match.group(1).lower()
    return _FAMILY_TO_SUBTYPE.get(str(action_family or ""), "write")


def _read_capability(tool_name: str, args: Any, session_id: str | None) -> Capability:
    """Build a read-direction Capability (doc 02 §7 read rows).

    Reads taint; they are never a blockable egress (charter invariant #3). The
    data_classes/tags here describe what the read *taints with*, derived best-effort
    from the read-side helpers in ``privacy/tool_policy`` — they are not load-bearing
    for any block (``decide`` returns ALLOW for direction="read").
    """
    fine = _classes_from_content(args)
    destination = Destination(
        kind="read",
        id=str(tool_name or ""),
        trust=DestinationTrust.SELF,
    )
    return Capability(
        direction="read",
        destination=destination,
        data_classes=_policy_classes_for(fine),
        data_tags=_data_tags_for(fine),
        action_subtype="read",
    )


def classify(tool_name: str = "", args: Any = None, session: Any = None) -> Capability:
    """Resolve a tool call to a ``Capability`` (doc 02 §2, §7).

    ROUTES the existing classifier: ``_egress_tool_action`` decides whether the call is a
    sink and which ``action_family`` / destination it has (the §7 family table, MCP /
    browser / safe-destination helpers). A non-sink call is a read. The destination
    string is fed to ``resolve_destination_trust`` (Phase 1) to get ``Destination.trust``.

    ``session`` is the session id (string) or None — accepted positionally to match the
    doc 02 signature ``classify(tool_name, args, session)``.
    """
    session_id = session if isinstance(session, str) or session is None else str(session)
    action = _egress_tool_action(tool_name, args, session_id)
    if action is None:
        # Non-sink: a read (or a no-op). direction="read" (doc 02 §7 read rows).
        return _read_capability(tool_name, args, session_id)

    action_family, _legacy_destination = action.as_tuple()
    if _is_draft_compose(tool_name, action_family):
        # Route a compose-draft to the user's own draft store (doc 02 §7). Resolves to
        # self via the "draft:*" allowlist, removing the old gate.
        dest_kind = "draft"
        dest_id = _dest_id_for_action(action_family, action) or "draft"
        subtype = "draft"
    else:
        dest_kind = _dest_kind_for_family(action_family)
        dest_id = _dest_id_for_action(action_family, action)
        subtype = _action_subtype_for(action_family, tool_name)
        # A write to a self store that names an external recipient (e.g. a calendar event
        # with `participants`, a file shared via `cc`) reaches a new party. Upgrade it to
        # an outward-sharing subtype so the resolver's §3.1 guard resolves it to external,
        # not self — UNLESS the tool name already implied outward sharing (keep that verb).
        if (
            action_family not in _MESSAGING_FAMILIES
            and not _OUTWARD_SHARING_VERB_RE.search(str(tool_name or "").lower())
            and _carries_external_recipient(args)
        ):
            subtype = "share"

    # Recipient identity matters only for messaging families (doc 01 §3.2). For those,
    # reuse the raw recipient the existing helper resolved; otherwise it is irrelevant.
    if action_family in _MESSAGING_FAMILIES:
        recipient_identity = _recipient_raw_from_args(args)
    else:
        recipient_identity = ""

    trust = resolve_destination_trust(dest_kind, dest_id, subtype, recipient_identity)

    destination = Destination(kind=dest_kind, id=dest_id, trust=trust)

    # data_classes / data_tags are the POLICY/tag split (doc 02 §5) of the ambient
    # egress class set the existing path computes (content classes ∪ session taint).
    fine = _data_classes_for_egress(session_id, args)
    return Capability(
        direction="write",
        destination=destination,
        data_classes=_policy_classes_for(fine),
        data_tags=_data_tags_for(fine),
        action_subtype=subtype,
    )


# --- Facade bridging (AGENTS.md "Loader And Namespace Rules") -----------------
# The Hermes facade (``__init__.py``) bridges only globals whose names start with ``_``.
# ``classify`` and the dataclasses are public, so expose underscore-prefixed aliases the
# bridge will pick up, mirroring how ``privacy/destinations`` exposes
# ``_resolve_destination_trust`` / ``_DestinationTrust``. Plain aliases, no new behavior.
_classify = classify
_Capability = Capability
_Destination = Destination
_PRIVATE_POLICY_CLASSES = PRIVATE_POLICY_CLASSES
_POLICY_CLASSES = POLICY_CLASSES
_DATA_TAGS = DATA_TAGS
