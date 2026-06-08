"""Session taint tracking and deterministic tool action classification."""

from __future__ import annotations

def _normalize_session_id(session_id: str | None) -> str:
    return session_id or _GLOBAL_SESSION_ID


def _hash_identity(platform: str = "", sender_id: str = "") -> str:
    platform = str(platform or "unknown").strip().lower()
    sender_id = str(sender_id or "unknown").strip()
    if platform == "cli" and sender_id in {"", "unknown"}:
        return _CLI_OWNER_HASH
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
    with _LOCK:
        state = _SESSIONS.setdefault(
            sid,
            {
                "taint": set(),
                "owner_hash": owner_hash,
                "browser_host": "",
                "browser_private_hosts": set(),
                "local_system_result_policies": [],
            },
        )
        if owner_hash:
            state["owner_hash"] = owner_hash
            _OWNER_SESSIONS.setdefault(owner_hash, set()).add(sid)
        return state


def _taint_session(session_id: str | None, classes: set[str]) -> None:
    if not classes:
        return
    with _LOCK:
        state = _ensure_session(session_id)
        state["taint"].update(classes)


def _session_taint(session_id: str | None) -> set[str]:
    with _LOCK:
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
    text = _stringify_for_scan(value)
    match = re.search(r"https?://[^\s\"'<>]+", text)
    return match.group(0) if match else ""


def _extract_urls(value: Any) -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for key in ("url", "href", "current_url", "page_url"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                urls.append(candidate)
    text = _stringify_for_scan(value)
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


def _args_send_remote_text(args: Any) -> bool:
    if isinstance(args, dict):
        for key in ("query", "q", "search", "prompt", "text", "body", "input", "message", "content"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
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
    with _LOCK:
        state = _ensure_session(session_id)
        if state.get("browser_host") != host:
            state["browser_host"] = host
            state["browser_private_hosts"].discard(host)


def _mark_browser_private_input(session_id: str | None) -> None:
    with _LOCK:
        state = _ensure_session(session_id)
        host = state.get("browser_host") or "unknown"
        state["taint"].add("browser_private_input")
        state["browser_private_hosts"].add(host)


def _browser_host(session_id: str | None) -> str:
    with _LOCK:
        return str(_ensure_session(session_id).get("browser_host") or "unknown")


def _browser_has_private_input(session_id: str | None) -> bool:
    with _LOCK:
        state = _ensure_session(session_id)
        host = state.get("browser_host") or "unknown"
        return host in state.get("browser_private_hosts", set())


def _browser_result_has_private_context(value: Any) -> bool:
    text = _stringify_for_scan(value)
    if not text:
        return False
    return bool(
        _LANGUAGE_PACKS.browser_private_context_pattern.search(text)
        or re.search(r"\b(csrf|document\.cookie|localStorage|sessionStorage)\b", text, re.I)
        or _EMAIL_ADDRESS_RE.search(text)
    )


def _classes_from_tool_name(tool_name: str) -> set[str]:
    classes: set[str] = set()
    for pattern, rule_classes in _SOURCE_TAINT_RULES:
        if pattern.search(tool_name):
            classes.update(rule_classes)
    return classes


def _classes_from_content(value: Any) -> set[str]:
    text = _stringify_for_scan(value)
    if not text:
        return set()
    classes: set[str] = set()
    if _email_shaped_text(text) or _EMAIL_ADDRESS_RE.search(text):
        classes.add("email")
    if _PHONE_RE.search(text) or _PRIVATE_FIELD_RE.search(text):
        classes.add("contacts")
    if _SSN_RE.search(text):
        classes.add("documents")
    return classes


def _is_local_system_tool(tool_name: str) -> bool:
    return bool(_TERMINAL_TOOL_RE.match(str(tool_name or "").lower()))


def _terminal_command_for_args(args: Any) -> str:
    if isinstance(args, dict):
        return str(args.get("command") or args.get("cmd") or "")
    return ""


def _terminal_command_result_is_metadata_only(command: str) -> bool:
    command = str(command or "").strip()
    if not command:
        return False
    if _LOCAL_SYSTEM_NO_TAINT_DENY_RE.search(command):
        return False
    segments = [segment.strip() for segment in command.split("|")]
    if not segments or not _LOCAL_SYSTEM_NO_TAINT_FIRST_RE.search(segments[0]):
        return False
    return all(_LOCAL_SYSTEM_NO_TAINT_FILTER_RE.search(segment) for segment in segments[1:])


def _terminal_command_is_safe_remote_read(command: str) -> bool:
    command = str(command or "").strip()
    if not command:
        return False
    if not _REMOTE_READ_URL_RE.search(command) or not _REMOTE_READ_TOOL_RE.search(command):
        return False
    if any(_is_private_or_metadata_host(_safe_host_from_url(url)) for url in _extract_urls(command)):
        return False
    if _REMOTE_READ_OUTBOUND_RE.search(command):
        return False
    if _REMOTE_READ_EXECUTION_RE.search(command):
        return False
    if _SENSITIVE_LOCAL_PATH_RE.search(command):
        return False
    if re.search(r">\s*(?!/(?:tmp|var/tmp)/)", command):
        return False
    if re.search(r"\b(?:write_bytes|write_text|open)\b", command) and not _REMOTE_READ_TMP_WRITE_RE.search(command):
        return False
    return True


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
        "ts": _now(),
    }
    _record_shared_context(
        session_id,
        tool_name,
        public_remote_read=bool(entry["remote_read"]),
        local_system_taint=",".join(entry["taint"]),
    )
    with _LOCK:
        state = _ensure_session(session_id)
        policies = state.setdefault("local_system_result_policies", [])
        policies.append(entry)
        del policies[:-10]


def _consume_local_system_result_policy(session_id: str | None, tool_name: str) -> dict[str, Any]:
    if not _is_local_system_tool(tool_name):
        return {}
    shared = _consume_shared_context(session_id, tool_name)
    if shared:
        return {
            "tool_name": str(tool_name or "").lower(),
            "taint": [
                cls
                for cls in str(shared.get("local_system_taint") or "").split(",")
                if cls
            ],
            "remote_read": bool(shared.get("public_remote_read")),
            "ts": float(shared.get("ts") or _now()),
        }
    lower = str(tool_name or "").lower()
    cutoff = _now() - 120
    with _LOCK:
        state = _ensure_session(session_id)
        policies = [
            policy
            for policy in state.get("local_system_result_policies", [])
            if float(policy.get("ts", 0)) >= cutoff
        ]
        state["local_system_result_policies"] = policies
        for index, policy in enumerate(policies):
            if policy.get("tool_name") == lower:
                policies.pop(index)
                return dict(policy)
    return {}


def _taint_classes_for_tool_result(
    tool_name: str,
    result_value: Any,
    status: str = "",
    session_id: str | None = None,
    local_system_policy: dict[str, Any] | None = None,
) -> set[str]:
    if str(status or "").lower() == "error":
        return set()
    if _is_local_system_tool(tool_name):
        classes = _classes_from_content(result_value)
        policy = local_system_policy if local_system_policy is not None else _consume_local_system_result_policy(session_id, tool_name)
        classes.update(set(policy.get("taint") or []))
        return classes
    classes = _classes_from_tool_name(tool_name)
    if classes:
        return classes
    return _classes_from_content(result_value)


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
    classes = _session_taint(session_id)
    classes.update(_classes_from_content(args))
    return classes


class ToolAction:
    __slots__ = ("action_family", "destination")

    def __init__(self, action_family: str, destination: str) -> None:
        self.action_family = action_family
        self.destination = destination

    def as_tuple(self) -> tuple[str, str]:
        return (self.action_family, self.destination)


def _is_mcp_write_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp_") and bool(_MCP_WRITE_RE.search(tool_name))


def _is_mcp_read_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp_") and bool(_MCP_READ_RE.search(tool_name))


def _mcp_read_sends_query(args: Any) -> bool:
    if not isinstance(args, dict):
        return _args_send_remote_text(args)
    for key in ("query", "q", "search", "prompt", "text", "body", "input", "message", "content", "filter"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, (list, dict)) and _stringify_for_scan(value).strip():
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


def _intrinsic_risk_for_tool(tool_name: str, args: Any) -> dict[str, Any] | None:
    lower = str(tool_name or "").lower()
    text = _stringify_for_scan(args)
    if not text:
        return None
    if lower in {"terminal", "execute_code", "code_execution", "shell"}:
        if _LOCAL_SECRET_READ_RE.search(text) and _NETWORK_SINK_RE.search(text):
            return {
                "action_family": "terminal_exec",
                "destination": "network",
                "data_classes": {"local_system"},
                "reason": "same-call local secret read plus network egress",
            }
    if lower in {"browser_console", "browser_cdp"}:
        if _BROWSER_SECRET_READ_RE.search(text) and _NETWORK_SINK_RE.search(text):
            return {
                "action_family": lower,
                "destination": "browser",
                "data_classes": {"browser_private_input"},
                "reason": "same-call browser state read plus network egress",
            }
    return None


def _arg_action(args: Any, default: str = "") -> str:
    if isinstance(args, dict):
        return str(args.get("action") or default).strip().lower()
    return default


def _is_message_send_call(tool_name: str, args: Any) -> bool:
    if not _MESSAGE_TOOL_RE.search(tool_name):
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
    if _MNEMOSYNE_WRITE_TOOL_RE.match(lower):
        return True
    if lower == "skill_manage":
        return _arg_action(args) in {"create", "patch", "edit", "delete", "write_file", "remove_file"}
    return bool(_LOCAL_WRITE_TOOL_RE.match(lower))


def _computer_use_action(args: Any) -> str:
    return _arg_action(args, "capture")


def _is_computer_use_write(args: Any) -> bool:
    return _computer_use_action(args) not in {"capture", "wait", "list_apps"}


def _is_browser_console_eval(args: Any) -> bool:
    return isinstance(args, dict) and args.get("expression") is not None


def _read_arg_classes(args: Any) -> set[str]:
    return _classes_from_content(args)


def _egress_tool_action(tool_name: str, args: Any, session_id: str | None) -> ToolAction | None:
    name = str(tool_name or "")
    lower = name.lower()

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
            bool(_WEB_READ_TOOL_RE.match(lower)) and bool(_session_taint(session_id)) and _args_send_remote_text(args),
            read_private_action,
        ),
        (
            bool(_WEB_READ_TOOL_RE.match(lower)) and bool(_read_arg_classes(args)),
            read_private_action,
        ),
        (lower == "browser_navigate", lambda: None),
        (lower == "browser_type", lambda: ToolAction("browser_type", _browser_host(session_id))),
        (
            lower in {"browser_click", "browser_press", "browser_dialog"} and _browser_has_private_input(session_id),
            lambda: ToolAction(lower, _browser_host(session_id)),
        ),
        (
            lower == "browser_console" and _is_browser_console_eval(args),
            lambda: ToolAction("browser_console", _browser_host(session_id)),
        ),
        (
            lower == "computer_use" and _is_computer_use_write(args),
            lambda: ToolAction("computer_use", "computer"),
        ),
        (lower == "delegate_task", lambda: ToolAction("delegate_task", "subagent")),
        (bool(_MODEL_EGRESS_TOOL_RE.match(lower)), lambda: ToolAction("model_api", lower)),
        (
            _is_cron_write_call(lower, args),
            lambda: ToolAction("cron_write", _safe_destination_from_args(args, default="cron")),
        ),
        (_is_local_write_call(lower, args), lambda: ToolAction("local_write", lower)),
        (bool(_KANBAN_WRITE_TOOL_RE.match(lower)), lambda: ToolAction("kanban_write", "kanban")),
        (lower == "ha_call_service", lambda: ToolAction("homeassistant_write", "homeassistant")),
        (lower == "browser_cdp", lambda: ToolAction("browser_cdp", _browser_host(session_id))),
        (bool(_TERMINAL_TOOL_RE.match(lower)), lambda: ToolAction("terminal_exec", "terminal")),
        (
            _is_message_send_call(lower, args),
            lambda: ToolAction("message_send", _safe_destination_from_args(args, default="messaging")),
        ),
        (lower == "send_message", lambda: None),
        (
            bool(_WEB_EGRESS_TOOL_RE.search(lower)),
            lambda: ToolAction("web_api", _safe_destination_from_args(args, default=lower)),
        ),
        (
            bool(_GENERIC_WRITE_TOOL_RE.search(lower)),
            lambda: ToolAction("tool_write", lower.split("_", 1)[0] or lower),
        ),
    )
    for matches, build_action in rules:
        if matches:
            return build_action()
    return None


def _egress_action_for_tool(tool_name: str, args: Any, session_id: str | None) -> tuple[str, str] | None:
    action = _egress_tool_action(tool_name, args, session_id)
    return action.as_tuple() if action else None


def _read_activity_for_tool(tool_name: str, args: Any, session_id: str | None = None) -> tuple[str, str] | None:
    lower = str(tool_name or "").lower()
    if lower == "send_message" and _arg_action(args, "send") == "list":
        return ("message_list", "messaging")
    if lower == "browser_console" and not _is_browser_console_eval(args):
        return ("browser_read", _browser_host(session_id))
    if not _WEB_READ_TOOL_RE.match(lower):
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
