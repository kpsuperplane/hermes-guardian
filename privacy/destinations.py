"""Destination-trust resolution (doc 01).

The single public entry point is ``resolve_destination_trust``. It is a pure,
local function: it reads only the loaded privacy config and the call arguments,
and performs NO network I/O (no sockets, no DNS, no HTTP). A test asserts this.

Design contract (doc 01 §2-3): every destination resolves to one of seven trust
levels relative to the data owner. The ONLY way this design leaks is to mislabel
an external destination as ``self``; every rule below pushes ambiguity away from
that, and the literal final return is ``unknown`` (which the decision function
treats exactly as ``external`` — doc 01 §3.6).

The active capability classifier calls this resolver for sink destinations before
the policy decision is made. The module imports ``core`` as a module object so
tests and Hermes monkeypatches of shared config helpers are observed at call time.
"""

from __future__ import annotations

# Keep this module self-contained: ``re`` is also available through ``core``, but
# importing it directly makes the resolver's dependencies explicit.
import re
from enum import Enum
from typing import Any

from .. import core


class DestinationTrust(str, Enum):
    """Trust of a sink's destination relative to the data owner (doc 01 §2).

    Subclasses ``str`` so values compare/serialize as their plain string labels
    (the codebase represents modes/classes/destinations as plain strings), while
    still giving callers a small, enumerable, typo-proof set to reason about.
    Ordered most-owned to least-known.
    """

    SELF = "self"
    LOCAL_SYSTEM = "local_system"
    MODEL_PROVIDER = "model_provider"
    TRUSTED_RECIPIENT = "trusted_recipient"
    EXTERNAL = "external"
    PUBLIC = "public"
    # Fail-closed default: ownership could not be proven. The decision function
    # treats this exactly as EXTERNAL (doc 01 §2 "Critical").
    UNKNOWN = "unknown"


# Convenience set of the raw string values, for callers/tests that work in
# strings rather than the enum.
_DESTINATION_TRUST_VALUES = frozenset(member.value for member in DestinationTrust)


def _destinations_config(config: Any) -> dict[str, Any]:
    """Return the privacy config dict, defaulting to the loaded config.

    Passing ``config=None`` reads the live loaded config via the shared
    ``_load_privacy_config`` global; an explicit dict is used as-is. Anything
    else (a malformed value) collapses to an empty dict so resolution still runs
    fail-closed rather than raising.
    """
    if config is None:
        try:
            config = core._load_privacy_config()
        except Exception:
            return {}
    return config if isinstance(config, dict) else {}


def _self_config(config: dict[str, Any]) -> dict[str, Any]:
    block = config.get("self")
    return block if isinstance(block, dict) else {}


def _trusted_recipient_entries(config: dict[str, Any]) -> list[dict[str, Any]]:
    block = config.get("trusted_recipients")
    if not isinstance(block, dict):
        return []
    entries = block.get("entries")
    return [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []


def _outward_sharing_subtypes(config: dict[str, Any]) -> set[str]:
    """The effective outward-sharing subtype set: builtin ∪ extra.

    The builtin set is never narrowable (doc 01 §4 last bullet). Normalization in
    rules.py already guarantees the builtin members are present; here we union
    defensively against the hard-coded builtin set so that even a config that
    somehow dropped a builtin still gets the full guard. ``extra`` may only add.
    """
    block = config.get("outward_sharing")
    block = block if isinstance(block, dict) else {}
    subtypes: set[str] = set(_OUTWARD_SHARING_BUILTIN)
    for key in ("builtin", "extra"):
        raw = block.get(key)
        if isinstance(raw, list):
            for value in raw:
                token = _normalize_subtype(value)
                if token:
                    subtypes.add(token)
    return subtypes


def _normalize_subtype(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalize_identity(value: Any) -> str:
    """Lowercase + trim an identity (address/handle) for comparison.

    Conservative on purpose: a templated/empty recipient normalizes to "" and is
    treated as unresolvable (doc 01 §3.2), never as a match.
    """
    return str(value or "").strip().lower()


# Hard-coded mirror of the builtin outward-sharing set (doc 01 §4). rules.py
# seeds and enforces the same constant; duplicated here so the resolver's guard
# holds even if called with a config that predates / corrupts the block.
_OUTWARD_SHARING_BUILTIN = (
    "share",
    "invite",
    "publish",
    "add_collaborator",
    "make_public",
    "set_permissions",
)


def _matches_self_destination(dest_kind: str, dest_id: str, self_config: dict[str, Any]) -> bool:
    """Match ``(dest_kind, dest_id)`` against ``config.self.destinations``.

    Entries are plain strings of the form ``"store:files"`` or a trailing-``*``
    prefix such as ``"draft:*"``. We match the resolved destination token
    ``"<kind>:<id>"`` by exact equality or by prefix.

    # CONSERVATIVE: an entry with no usable token, or a destination that does not
    # match any entry exactly/by-prefix, does NOT resolve to self here — it falls
    # through to the caller's later rules and ultimately to unknown->external.
    """
    destinations = self_config.get("destinations")
    if not isinstance(destinations, list):
        return False
    kind = str(dest_kind or "").strip().lower()
    ident = str(dest_id or "").strip().lower()
    token = f"{kind}:{ident}" if ident else kind
    for raw in destinations:
        entry = str(raw or "").strip().lower()
        if not entry:
            continue
        if entry.endswith("*"):
            prefix = entry[:-1]
            # Prefix entries like "draft:*" match the kind portion (and any id).
            if token.startswith(prefix) or f"{kind}:".startswith(prefix) or kind == prefix.rstrip(":"):
                return True
        elif entry == token or entry == kind:
            return True
    return False


def _matches_self_host(host: str, self_config: dict[str, Any]) -> bool:
    """Match a network host against ``config.self.hosts`` (doc 01 §3.5).

    # CONSERVATIVE: hosts is EMPTY by default (doc 01 §4); an unfilled list means
    # "I can't prove this host is yours" -> not self.
    """
    hosts = self_config.get("hosts")
    if not isinstance(hosts, list):
        return False
    target = _normalize_host(host)
    if not target:
        return False
    for raw in hosts:
        candidate = _normalize_host(raw)
        if not candidate:
            continue
        if target == candidate or target.endswith("." + candidate):
            return True
    return False


def _normalize_host(value: Any) -> str:
    text = str(value or "").strip().lower()
    # Strip scheme and any path/port — host comparison is host-only. No DNS.
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0]
    text = text.split("@", 1)[-1]
    text = text.split(":", 1)[0]
    return text.strip(". ")


def _recipient_resolves_to_self(recipient_identity: str, config: dict[str, Any]) -> bool:
    """True iff the recipient is one of the operator's own verified identities.

    Reads ``config.self.identities`` (doc 01 §3.2). EMPTY by default, so by
    default this is always False and a send is never self.

    # CONSERVATIVE: a templated, empty, or otherwise unresolvable recipient
    # normalizes to "" and never matches — we never guess a recipient is self
    # (doc 01 §3.2 last bullet).
    """
    target = _normalize_identity(recipient_identity)
    if not target:
        return False
    identities = _self_config(config).get("identities")
    if not isinstance(identities, list):
        return False
    for raw in identities:
        if target == _normalize_identity(raw):
            return True
    return False


def _recipient_trusted_class(recipient_identity: str, config: dict[str, Any]) -> bool:
    """True iff the recipient matches a declared trusted recipient (doc 01 §3.2)."""
    target = _normalize_identity(recipient_identity)
    if not target:
        return False
    for entry in _trusted_recipient_entries(config):
        if str(entry.get("kind") or "identity") != "identity":
            continue
        if target == _normalize_identity(entry.get("value") or entry.get("identity")):
            return True
    return False


def _is_outward_sharing(action_subtype: str, config: dict[str, Any]) -> bool:
    """True iff the action subtype reaches other parties (doc 01 §3.1)."""
    subtype = _normalize_subtype(action_subtype)
    if not subtype:
        return False
    return subtype in _outward_sharing_subtypes(config)


# Action subtypes that send a message to a recipient (doc 01 §3.2). For these,
# trust is a property of the resolved recipient, not the tool/store.
_MESSAGING_SUBTYPES = frozenset({"send", "email", "message", "dm", "reply", "forward"})

# Destination kinds that denote a write/store (doc 01 §3.3-3.4). Resolved against
# the self destination allowlist.
_STORE_KINDS = frozenset({"store", "draft", "memory", "todo", "file", "local"})

# Third-party MCP connector kinds (Fix 1). NOT in _STORE_KINDS: a connector resolves
# to self only against an EXPLICIT `mcp:<name>` / `connector:<name>` self entry, never
# against a seeded `store:<name>` token — so naming a tool `mcp_<seeded-name>_*` can't
# impersonate a first-party store.
_CONNECTOR_KINDS = frozenset({"mcp", "connector"})

# Destination kinds that denote a non-networked local effect (doc 01 §3.4).
_LOCAL_KINDS = frozenset({"local", "file", "memory", "todo", "draft"})


def resolve_destination_trust(
    dest_kind: Any,
    dest_id: Any,
    action_subtype: Any,
    recipient_identity: Any,
    config: Any = None,
) -> DestinationTrust:
    """Resolve a destination to a ``DestinationTrust`` level (doc 01 §3).

    Pure and local: reads only the loaded privacy config (or the explicit
    ``config`` dict) and the arguments. No network I/O.

    Rules are applied IN ORDER, first match wins, with ``unknown`` as the literal
    final return (doc 01 §3.6). The order encodes the safety posture: outward
    sharing is checked before any ownership claim, and every ambiguity resolves
    toward not-self.

    Args:
        dest_kind: coarse destination kind, e.g. ``"store"``, ``"draft"``,
            ``"messaging"``, ``"host"``, ``"model"``, ``"local"``.
        dest_id: the specific destination id within the kind (store name, host,
            etc.); may be empty.
        action_subtype: the resolved action subtype, e.g. ``"write"``, ``"send"``,
            ``"share"``, ``"invite"``.
        recipient_identity: for messaging actions, the resolved recipient
            address/handle; empty/templated => unresolvable.
        config: the privacy config dict, or ``None`` to read the live loaded
            config.
    """
    cfg = _destinations_config(config)
    self_cfg = _self_config(cfg)
    kind = str(dest_kind or "").strip().lower()
    subtype = _normalize_subtype(action_subtype)

    # --- §3.1 Outward-sharing actions are never self, even on a self store. ----
    # Resolved FIRST, before any ownership check (doc 01 §3.1). Sharing/inviting/
    # publishing on a self-owned store still reaches other people.
    if _is_outward_sharing(subtype, cfg):
        # CONSERVATIVE: a share/invite/publish on a self-listed connector is
        # external regardless of which connector it targets.
        return DestinationTrust.EXTERNAL

    # --- §3.2 Messaging: resolve the recipient against owned identities. -------
    if kind in {"messaging", "message", "send"} or subtype in _MESSAGING_SUBTYPES:
        if _recipient_resolves_to_self(recipient_identity, cfg):
            return DestinationTrust.SELF
        if _recipient_trusted_class(recipient_identity, cfg):
            return DestinationTrust.TRUSTED_RECIPIENT
        if not _normalize_identity(recipient_identity):
            # CONSERVATIVE: templated / empty / unresolvable recipient -> unknown
            # (doc 01 §3.2 last bullet). Never guess a recipient is self.
            return DestinationTrust.UNKNOWN
        # A real, resolvable, non-self, non-trusted recipient is external.
        return DestinationTrust.EXTERNAL

    # --- Third-party MCP connector: explicit-self ONLY (Fix 1). ---------------
    # An `mcp:<name>` connector is a third-party server, NOT a first-party Hermes
    # store. It resolves to self ONLY when the operator EXPLICITLY added that
    # connector to their self allowlist (an `mcp:<name>` entry) — never by a seeded
    # `store:<name>` name collision, so a malicious server naming its tool
    # `mcp_<seeded-name>_*` cannot impersonate self. A connector the operator
    # explicitly trusts as a recipient is trusted; otherwise fall through to
    # unknown -> external (gates under taint, fail-closed).
    if kind in _CONNECTOR_KINDS:
        if _matches_self_destination(kind, str(dest_id or ""), self_cfg):
            return DestinationTrust.SELF
        if _recipient_trusted_class(dest_id, cfg):
            return DestinationTrust.TRUSTED_RECIPIENT
        return DestinationTrust.UNKNOWN

    # --- §3.3 / §3.4 Stores & local: match the self-destination allowlist. -----
    if kind in _STORE_KINDS or kind in _LOCAL_KINDS:
        if _matches_self_destination(kind, str(dest_id or ""), self_cfg):
            return DestinationTrust.SELF
        if _recipient_trusted_class(dest_id, cfg):
            # A non-store external service the user explicitly trusts (doc 01 §3.3).
            return DestinationTrust.TRUSTED_RECIPIENT
        if kind in _LOCAL_KINDS:
            # CONSERVATIVE: a non-networked local effect not in the self allowlist
            # is local_system, not self (doc 01 §3.4).
            return DestinationTrust.LOCAL_SYSTEM
        # Store kind, not in the allowlist -> fall through to fallback.

    # --- §3.4 Model provider. --------------------------------------------------
    if kind in {"model", "model_provider", "model_api", "llm"}:
        return DestinationTrust.MODEL_PROVIDER

    # --- §3.5 Network hosts. ---------------------------------------------------
    if kind in {"host", "url", "network", "web", "terminal"}:
        host = str(dest_id or "")
        if _matches_self_host(host, self_cfg):
            return DestinationTrust.SELF
        if _is_public_host(host):
            return DestinationTrust.PUBLIC
        # CONSERVATIVE: an unresolvable / non-self / non-public host is external,
        # not local_system — a networked action never gets local_system
        # (doc 01 §3.4, §3.5). Private/metadata IP handling stays in the security
        # layer (doc 01 §3.5) and is intentionally not duplicated here.
        if host:
            return DestinationTrust.EXTERNAL

    # --- §3.6 Fallback. --------------------------------------------------------
    # CONSERVATIVE: anything unmatched is unknown -> external. This is the safety
    # net and MUST be the literal default return (doc 01 §3.6).
    return DestinationTrust.UNKNOWN


def _is_public_host(host: Any) -> bool:
    """Heuristic: a routable, non-private hostname is public (doc 01 §3.5).

    Pure string inspection — NO DNS resolution. Private/loopback/metadata hosts
    are NOT public here (the security layer owns private-network logic); they
    fall through to external, which is the safe direction.

    # CONSERVATIVE: anything that does not clearly look like a public hostname
    # (e.g. has a dotted public-looking domain and is not a private/metadata
    # host) returns False and the caller treats it as external, not public.
    """
    target = _normalize_host(host)
    if not target:
        return False
    if target in {"localhost"} or target.endswith(".local"):
        return False
    # Private / loopback / link-local / metadata IP ranges are not "public".
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", target):
        if (
            target.startswith("127.")
            or target.startswith("10.")
            or target.startswith("192.168.")
            or target == "169.254.169.254"
            or target.startswith("169.254.")
            or re.match(r"172\.(?:1[6-9]|2\d|3[01])\.", target)
        ):
            return False
        return True
    # A dotted hostname with a public-looking TLD is treated as public.
    return bool(re.search(r"\.[a-z]{2,}$", target))


# --- Facade bridging (AGENTS.md "Loader And Namespace Rules") -----------------
# The Hermes facade (``__init__.py``) bridges selected underscore-prefixed internals.
# These aliases give tests and dashboard-facing helpers a facade-reachable spelling
# for the active resolver types without adding behavior of their own.
_DestinationTrust = DestinationTrust


def _resolve_destination_trust(
    dest_kind: Any,
    dest_id: Any,
    action_subtype: Any,
    recipient_identity: Any,
    config: Any = None,
) -> DestinationTrust:
    """Facade-reachable alias for :func:`resolve_destination_trust` (see above)."""
    return resolve_destination_trust(
        dest_kind, dest_id, action_subtype, recipient_identity, config
    )
