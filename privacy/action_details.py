"""Sanitized action-detail rendering for activity, approvals, and prompts."""

from __future__ import annotations

import ast
import re
from typing import Any

from . import llm
from . import tool_policy
from .. import core
from ..security import module as security_module

_TERMINAL_PREVIEW_LIMIT = 500
_TERMINAL_STRING_LITERAL_LIMIT = 36


def _redact_action_detail_text(text: str, *, check_sensitive: bool = True) -> str:
    text = str(text or "")
    if check_sensitive:
        reason = security_module._sensitive_reason(text)
        if reason:
            return f"<security-sensitive content redacted: {reason}>"
    text = re.sub(r"https?://[^\s\"'<>]+", lambda m: llm._sanitize_url_for_llm(m.group(0)), text)
    text = core._EMAIL_ADDRESS_RE.sub("<email>", text)
    text = core._PHONE_RE.sub("<phone>", text)
    text = core._SSN_RE.sub("<ssn>", text)
    text = re.sub(r"\b(\d{6,8})\b", "<code>", text)
    text = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)[A-Za-z0-9_]*=)([^\s;&|]+)",
        r"\1<redacted>",
        text,
        flags=re.I,
    )
    text = re.sub(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}", r"\1 <redacted>", text, flags=re.I)
    text = re.sub(r"\b[A-Za-z0-9._~+/=-]{48,}\b", "<token-like>", text)
    return text[:500]


def _redact_terminal_string_literal(value: str) -> str:
    text = str(value or "")
    if not text:
        return text
    if re.search(r"<(?:path:redacted|token-like|string:\d+)>", text):
        return text
    reason = security_module._sensitive_reason(text)
    if reason:
        return f"<security-sensitive:{reason}>"
    redacted = _redact_action_detail_text(text)
    if re.search(r"https?://", text, re.I):
        return redacted
    if re.fullmatch(r"[A-Za-z0-9._~+/=-]{48,}", text):
        return "<token-like>"
    if (
        redacted != text
        or len(text) > _TERMINAL_STRING_LITERAL_LIMIT
        or tool_policy._classes_from_content(text)
        or re.search(r"[/\\]|\b(token|secret|password|credential|auth|cookie|key)\b", text, re.I)
    ):
        return f"<string:{len(text)}>"
    return text


class _TerminalPreviewLiteralTransformer(ast.NodeTransformer):
    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(_redact_terminal_string_literal(node.value)), node)
        return node


def _redact_python_literals_for_terminal_preview(code: str) -> str:
    try:
        tree = ast.parse(str(code or ""))
    except SyntaxError:
        return _redact_action_detail_text(code)
    tree = _TerminalPreviewLiteralTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    try:
        return ast.unparse(tree)
    except Exception:
        return _redact_action_detail_text(code)


def _redact_terminal_heredoc(match: re.Match[str]) -> str:
    body = match.group("body")
    redacted = _redact_python_literals_for_terminal_preview(body)
    return f"{match.group('head')}\n{redacted}\n{match.group('marker')}"


def _redact_terminal_shell_quoted_literal(match: re.Match[str]) -> str:
    quote = match.group("quote")
    body = match.group("body")
    redacted = _redact_terminal_string_literal(body)
    if redacted == body:
        return match.group(0)
    return f"{quote}{redacted}{quote}"


def _terminal_command_preview(command: str) -> str:
    text = str(command or "")
    reason = security_module._sensitive_reason(text)
    if reason:
        return f"<security-sensitive content redacted: {reason}>"

    text = re.sub(
        r"(?P<head>python3?\s+-\s+<<['\"]?(?P<marker>[A-Za-z_][A-Za-z0-9_]*)['\"]?)\n(?P<body>.*?)\n(?P=marker)",
        _redact_terminal_heredoc,
        text,
        flags=re.S,
    )
    text = re.sub(
        r"(?P<quote>['\"])(?P<body>[^'\"\n]{0,2000})(?P=quote)",
        _redact_terminal_shell_quoted_literal,
        text,
    )
    text = _redact_action_detail_text(text, check_sensitive=False)
    text = re.sub(r"(https?://[A-Za-z0-9.-]+)(<path:redacted>)", r"\1/\2", text)
    text = re.sub(
        r"(?P<prefix>(?:['\"])?[A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|AUTH|KEY)[A-Za-z0-9_]*(?:['\"])?\s*[:=]\s*)(?P<quote>['\"]?)[^\s;&|,)]+(?P=quote)",
        r"\g<prefix><redacted>",
        text,
        flags=re.I,
    )
    text = re.sub(r"(?P<flag>--(?:token|password|secret|auth|key)(?:=|\s+))(?P<quote>['\"]?)[^\s;&|]+(?P=quote)", r"\g<flag><redacted>", text, flags=re.I)
    text = re.sub(r"(?P<flag>-(?:p|u)\s+)(?P<quote>['\"]?)[^\s;&|]+(?P=quote)", r"\g<flag><redacted>", text, flags=re.I)
    text = re.sub(r"[ \t]+", " ", text)
    lines = [line.rstrip() for line in text.splitlines()]
    text = "\n".join(lines).strip()
    if len(text) > _TERMINAL_PREVIEW_LIMIT:
        return text[: _TERMINAL_PREVIEW_LIMIT - 3].rstrip() + "..."
    return text


def _redacted_content_note(value: Any) -> str:
    text = str(value or "")
    classes = sorted(tool_policy._classes_from_content(text))
    suffix = f"; classes={','.join(classes)}" if classes else ""
    return f"<redacted {len(text)} chars{suffix}>"


def _redacted_url_action_detail(prefix: str, args: Any, destination: str) -> str:
    url = tool_policy._extract_url(args)
    host = tool_policy._safe_host_from_url(url) if url else ""
    target = host or destination or "remote"
    if url and tool_policy._url_sends_remote_text(url):
        return f"{prefix} {target}: <url path/query redacted>"
    return f"{prefix} {target}"


def _activity_action_detail(tool_name: str, args: Any, action_family: str = "", destination: str = "") -> str:
    lower_tool = str(tool_name or "").lower()
    lower_action = str(action_family or "").lower()
    if isinstance(args, dict):
        if lower_action == "terminal_exec" or lower_tool in {"terminal", "shell"}:
            command = str(args.get("command") or args.get("cmd") or "")
            return "command: " + _terminal_command_preview(command)
        if lower_tool in {"execute_code", "code_execution"}:
            code = str(args.get("code") or args.get("script") or "")
            return f"code: {_redacted_content_note(code)}"
        if lower_action == "browser_type":
            text = str(args.get("text") or args.get("value") or "")
            return f"type into {destination or 'browser'}: {_redacted_content_note(text)}"
        if lower_action == "browser_click":
            target = args.get("ref") or args.get("selector") or args.get("text") or args.get("button") or ""
            return f"click {str(target)[:160]}"
        if lower_action == "browser_press":
            return f"press {str(args.get('key') or '')[:80]}"
        if lower_action == "browser_dialog":
            action = str(args.get("action") or "")[:80]
            prompt = args.get("prompt_text")
            if prompt:
                return f"dialog {action}: {_redacted_content_note(prompt)}"
            return f"dialog {action}"
        if lower_action == "browser_console":
            expression = str(args.get("expression") or "")
            return f"console eval {_redact_action_detail_text(expression)}"
        if lower_action == "browser_cdp":
            method = args.get("method") or args.get("command") or ""
            return f"cdp {str(method)[:160]}"
        if lower_action == "computer_use":
            action = tool_policy._computer_use_action(args)
            if action in {"type", "set_value"}:
                text = args.get("text") if action == "type" else args.get("value")
                return f"computer {action}: {_redacted_content_note(text)}"
            return f"computer {action}"
        if lower_action == "message_send":
            recipient_identity = tool_policy._recipient_identity_from_args(args)
            return f"send via {destination or 'messaging'} to {recipient_identity}: <message redacted>"
        if lower_action == "message_list":
            return "list message targets"
        if lower_action == "web_api":
            return _redacted_url_action_detail("request", args, destination)
        if lower_action in {"web_read", "browser_read"}:
            url = tool_policy._extract_url(args)
            if url:
                return _redacted_url_action_detail("load", args, destination)
            query = str(args.get("query") or args.get("q") or "")
            if query:
                return f"search {_redacted_content_note(query)}"
            return f"load {destination}"
        if lower_action in {"mcp_write", "mcp_unknown", "mcp_read_query"}:
            keys = ",".join(sorted(str(key) for key in args.keys())[:20])
            return f"{tool_name} args={keys}"
        if lower_action == "model_api":
            prompt = args.get("prompt") or args.get("user_prompt") or args.get("text") or args.get("question") or ""
            return f"{tool_name}: {_redacted_content_note(prompt)}"
        if lower_action == "cron_write":
            action = tool_policy._arg_action(args)
            deliver = str(args.get("deliver") or "origin")[:120]
            return f"cron {action} deliver={deliver}: {_redacted_content_note(args.get('prompt') or '')}"
        if lower_action == "local_write":
            target = args.get("path") or args.get("name") or args.get("target") or tool_name
            return f"{tool_name} {str(target)[:160]}: <content redacted>"
        if lower_action == "kanban_write":
            return f"{tool_name}: <content redacted>"
        if lower_action == "homeassistant_write":
            service = args.get("service") or args.get("domain") or ""
            return f"homeassistant {str(service)[:120]}: <args redacted>"
        if lower_action == "tool_write":
            keys = ",".join(sorted(str(key) for key in args.keys())[:20])
            return f"{tool_name} args={keys}: <content redacted>"
        if lower_action == "delegate_task":
            return f"delegate_task: {_redacted_content_note(args.get('goal') or args.get('task') or '')}"
        keys = ",".join(sorted(str(key) for key in args.keys())[:20])
        return f"{tool_name} args={keys}"
    if isinstance(args, str):
        return _redact_action_detail_text(args)
    return str(action_family or tool_name or "")[:160]
