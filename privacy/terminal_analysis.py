"""Typed terminal/code-execution command analysis.

This module is the single owner for terminal-tool structural facts used by the
privacy policy path: safe public remote reads, local metadata-only commands,
local-system result taint, and local artifact execution/persistence. It is
deliberately conservative; unknown shell/code shapes are not safe.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .. import core

_TERMINAL_TOOL_NAMES = frozenset({"terminal", "execute_code", "code_execution", "shell"})
_CODE_TOOL_NAMES = frozenset({"execute_code", "code_execution", "shell"})
_TERMINAL_SHELL_META_RE = re.compile(r"[;&|<>`\n\r]|\$\(")
_SHELL_SPLIT_TOKEN_RE = re.compile(r"\|\||[;\n&]")
_OUTPUT_DISCARD_RE = re.compile(r"(?:[0-9]?>>?|&>>?)\s*/dev/null\b|[0-9]>&[0-9]", re.I)
_CONTROL_KEYWORD_RE = re.compile(r"^(?:if|then|elif|else|fi|do|done)\b\s*", re.I)
_ENV_ASSIGN_RE = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;|&<>`]*(?:\s+|$))+")
_METADATA_WORD_RE = re.compile(
    r"^\s*(pwd|date|whoami|id|uname|hostname|ls|stat|du|df|test|true|false)(\s|$)",
    re.I,
)
_METADATA_SAFE_HEAD_RE = re.compile(
    r"(?:set(?:\s+(?:--|[-+][A-Za-z]+|[a-z]+))+"
    r"|command\s+-v\s+[\w.+/-]+"
    r"|\[{1,2}\s.*\]{1,2}"
    r"|(?:printf|echo)(?:\s+(?:-[A-Za-z]+|'[^'$`]*'|\"[^\"$`]*\"|[^\s'\"$`\\;|&<>]+))*"
    r")",
    re.I | re.S,
)
_METADATA_FILTER_RE = re.compile(r"^\s*(grep|wc|head|tail)(\s|$)", re.I)
_METADATA_DENY_RE = re.compile(
    r"(\b(curl|wget|scp|sftp|ssh|rsync|nc|netcat|telnet|ftp|openssl|base64|node|npm|npx|perl|ruby|php)\b"
    r"|https?://|>>?|<|`|\$\()",
    re.I,
)
_REMOTE_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_REMOTE_READ_TOOL_RE = re.compile(r"\b(curl|wget|urlopen|urllib\.request|requests\.get)\b", re.I)
_REMOTE_OUTBOUND_RE = re.compile(
    r"("
    r"\b(curl|wget)\b.{0,80}(?<!\S)(?:-X\s*(?:POST|PUT|PATCH|DELETE)|--request\s*(?:POST|PUT|PATCH|DELETE)|--data(?:-raw|-binary)?\b|-d(?![a-z])|--form\b|--upload-file\b|-T(?![a-z]))"
    r"|\brequests\.(?:post|put|patch|delete)\b"
    r"|\bmethod\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]"
    r"|\burlopen\s*\([^)]*,\s*data\s*="
    r"|\b(upload|post|send|exfiltrat(?:e|ion)|steal|leak|dump|harvest)\b"
    r")",
    re.I | re.S,
)
_REMOTE_EXECUTION_RE = re.compile(
    r"(\|\s*(?:sh|bash|zsh|python|python3|node|ruby|perl)\b"
    r"|\b(?:sh|bash|zsh|python|python3|node|ruby|perl)\s+/(?:tmp|var/tmp|dev/shm)/"
    r"|\bchmod\s+\+x\b"
    r")",
    re.I,
)
_REMOTE_PERSIST_RE = re.compile(
    r"("
    r"\bcurl\b[^\n;|&]*(?<!\S)(?:-o|--output|-O)\b"
    r"|\bwget\b"
    r"|>\s*\S+"
    r"|\|\s*tee\b"
    r"|\b(?:write_bytes|write_text)\s*\("
    r"|\bopen\s*\([^)]*['\"]w"
    r")",
    re.I | re.S,
)
_WGET_STDOUT_RE = re.compile(r"\bwget\b(?=[^\n;|&]*\s(?:-qO-|-[A-Za-z]*O-\b|--output-document=-\b))", re.I)
_LOCAL_ARTIFACT_EXEC_RE = re.compile(
    r"("
    r"\bchmod\s+(?:[^\n;|&]*\+x|[0-7]{3,4})\b"
    r"|(?:^|[;&|]\s*|\|\|\s*|&&\s*)(?:sudo\s+)?(?:env\s+)?(?:\./|~/|/(?:tmp|var/tmp|dev/shm|home|root)/)[^\s;|&]+"
    r"|\b(?:sh|bash|zsh|python|python3|node|ruby|perl)\s+/(?:tmp|var/tmp|dev/shm)/[^\s;|&]+"
    r"|\b(?:source|\.)\s+/(?:tmp|var/tmp|dev/shm)/[^\s;|&]+"
    r")",
    re.I | re.S,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(/root/\.hermes/(?:\.env|auth\.json|mcp-tokens)\b|~?/\.ssh/(?:id_rsa|id_ed25519|config)\b)",
    re.I,
)
_CODE_LOCAL_SOURCE_RE = re.compile(
    r"("
    r"\bos\.environ\b|\bgetenv\s*\(|\b__import__\s*\(|\b(?:eval|exec|compile)\s*\("
    r"|\bsubprocess\b|\bPopen\s*\(|\bsystem\s*\("
    r"|\b(?:open|read_text|read_bytes|write_text|write_bytes)\s*\("
    r"|\bpathlib\.Path\b|\bPath\.home\s*\(|\bexpanduser\s*\("
    r"|\b(?:glob|iglob|scandir|listdir|walk)\s*\("
    r")",
    re.I | re.S,
)
_PY_HEREDOC_RE = re.compile(
    r"(?P<prefix>^|\s*(?:&&|\|\||;|&|\n)\s*)python3?\s+-\s+<<'PY'\n(?P<body>.*?)\nPY(?=\s*(?:$|&&|\|\||;|&|\n))",
    re.S,
)
_NETWORK_SINK_RE = re.compile(
    r"(https?://|\b(curl|wget|scp|sftp|rsync|nc|netcat)\b|"
    r"requests\.(get|post|put|patch|delete)|urllib\.request|urlopen|fetch\s*\(|"
    r"XMLHttpRequest|sendBeacon|WebSocket|EventSource|\bnew\s+Image\b|"
    r"\bimport\s*\(|\baxios\b|\$\.(?:ajax|get|post|getJSON)\b|window\.open\s*\(|"
    r"webhook|callback|upload)",
    re.I | re.S,
)


@dataclass(frozen=True)
class TerminalAnalysis:
    is_terminal_tool: bool
    command: str
    kind: str
    safe_remote_read: bool = False
    safe_local_metadata: bool = False
    taints_local_system: bool = False
    has_network: bool = False
    persists_artifact: bool = False
    executes_local_artifact: bool = False
    same_call_exfil_risk: bool = False
    sanitized_reason: str = ""


def _command_from_args(args: Any) -> str:
    if isinstance(args, dict):
        return str(args.get("command") or args.get("cmd") or args.get("code") or "")
    return ""


def _tool_kind(tool_name: str) -> str:
    lower = str(tool_name or "").strip().lower()
    if lower == "terminal":
        return "shell"
    if lower in _CODE_TOOL_NAMES:
        return "code"
    return "not_terminal"


def analyze_tool_call(tool_name: str, args: Any) -> TerminalAnalysis:
    kind = _tool_kind(tool_name)
    command = _command_from_args(args)
    if kind == "not_terminal":
        return TerminalAnalysis(False, command, kind, sanitized_reason="not a terminal tool")
    has_network = _has_network(command)
    persists_artifact = _persists_remote_artifact(command)
    executes_local_artifact = _executes_local_artifact(command)
    same_call_exfil_risk = _same_call_exfil_risk(command)
    safe_remote_read = _safe_remote_read(kind, command, persists_artifact)
    safe_local_metadata = (
        kind == "shell"
        and not safe_remote_read
        and not has_network
        and not persists_artifact
        and not executes_local_artifact
        and not same_call_exfil_risk
        and _shell_command_is_metadata_only(command)
    )
    taints = not (safe_remote_read or safe_local_metadata)
    reason = _reason_for(
        safe_remote_read=safe_remote_read,
        safe_local_metadata=safe_local_metadata,
        persists_artifact=persists_artifact,
        executes_local_artifact=executes_local_artifact,
        same_call_exfil_risk=same_call_exfil_risk,
        has_network=has_network,
    )
    return TerminalAnalysis(
        True,
        command,
        kind,
        safe_remote_read=safe_remote_read,
        safe_local_metadata=safe_local_metadata,
        taints_local_system=taints,
        has_network=has_network,
        persists_artifact=persists_artifact,
        executes_local_artifact=executes_local_artifact,
        same_call_exfil_risk=same_call_exfil_risk,
        sanitized_reason=reason,
    )


def _reason_for(
    *,
    safe_remote_read: bool,
    safe_local_metadata: bool,
    persists_artifact: bool,
    executes_local_artifact: bool,
    same_call_exfil_risk: bool,
    has_network: bool,
) -> str:
    if safe_remote_read:
        return "safe public remote read"
    if safe_local_metadata:
        return "safe local metadata computation"
    if same_call_exfil_risk:
        return "same-call source plus network sink"
    if persists_artifact:
        return "remote read persists an artifact"
    if executes_local_artifact:
        return "local artifact execution"
    if has_network:
        return "network-capable terminal command"
    return "content-bearing local command"


def _safe_remote_read(kind: str, command: str, persists_artifact: bool) -> bool:
    command = str(command or "").strip()
    if not command or persists_artifact:
        return False
    if kind == "shell":
        body = _single_python_heredoc_body(command)
        if body is not None:
            return _terminal_code_snippet_is_safe_remote_read(body)
        if _TERMINAL_SHELL_META_RE.search(command):
            return False
        return _terminal_remote_read_text_has_safe_public_target(command)
    if kind == "code":
        return _terminal_code_snippet_is_safe_remote_read(command)
    return False


def _terminal_remote_read_text_has_safe_public_target(text: str) -> bool:
    text = str(text or "").strip()
    if not text:
        return False
    if not _REMOTE_URL_RE.search(text) or not _REMOTE_READ_TOOL_RE.search(text):
        return False
    if core._security_rule_enabled("private_network_reads") and any(
        _terminal_private_or_metadata_host(_terminal_safe_host_from_url(url)) for url in _terminal_extract_urls(text)
    ):
        return False
    if _REMOTE_OUTBOUND_RE.search(text):
        return False
    if _REMOTE_EXECUTION_RE.search(text):
        return False
    if core._COMMAND_SUBSTITUTION_RE.search(text):
        return False
    if _SENSITIVE_PATH_RE.search(text):
        return False
    return True


def _terminal_code_snippet_is_safe_remote_read(code: str) -> bool:
    code = str(code or "").strip()
    if not _terminal_remote_read_text_has_safe_public_target(code):
        return False
    if _CODE_LOCAL_SOURCE_RE.search(code):
        return False
    return True


def _shell_command_is_metadata_only(command: str) -> bool:
    command = str(command or "").strip()
    if not command:
        return False
    prepared, ok = _replace_safe_python_heredocs(command)
    if not ok:
        return False
    screened = _OUTPUT_DISCARD_RE.sub(" ", prepared)
    if _METADATA_DENY_RE.search(screened):
        return False
    return all(_shell_segment_is_metadata_only(segment.strip()) for segment in _split_shell_segments(screened))


def _replace_safe_python_heredocs(command: str) -> tuple[str, bool]:
    ok = True

    def repl(match: re.Match[str]) -> str:
        nonlocal ok
        body = match.group("body")
        if not _python_metadata_body_is_safe(body):
            ok = False
            return match.group(0)
        return f"{match.group('prefix')}true"

    replaced = _PY_HEREDOC_RE.sub(repl, command)
    if "<<" in replaced:
        ok = False
    return replaced, ok


def _single_python_heredoc_body(command: str) -> str | None:
    match = _PY_HEREDOC_RE.fullmatch(command.strip())
    if not match:
        return None
    return str(match.group("body") or "")


def _split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote = ""
    index = 0
    while index < len(command):
        ch = command[index]
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"' and index + 1 < len(command):
                index += 1
                current.append(command[index])
            index += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
            index += 1
            continue
        if command.startswith("&&", index) or command.startswith("||", index):
            segments.append("".join(current))
            current = []
            index += 2
            continue
        if ch in {";", "\n", "&"}:
            segments.append("".join(current))
            current = []
            index += 1
            continue
        current.append(ch)
        index += 1
    segments.append("".join(current))
    return segments


def _split_pipe_parts(segment: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    for ch in segment:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
            continue
        if ch == "|":
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return parts


def _shell_segment_is_metadata_only(segment: str) -> bool:
    while True:
        stripped = _CONTROL_KEYWORD_RE.sub("", segment).strip()
        if stripped == segment:
            break
        segment = stripped
    segment = _ENV_ASSIGN_RE.sub("", segment).strip()
    if not segment:
        return True
    parts = [part.strip() for part in _split_pipe_parts(segment)]
    head = parts[0]
    if not head:
        return False
    if not (_METADATA_WORD_RE.search(head) or _METADATA_SAFE_HEAD_RE.fullmatch(head)):
        return False
    return all(_METADATA_FILTER_RE.search(part) for part in parts[1:])


class _PythonMetadataValidator(ast.NodeVisitor):
    def __init__(self) -> None:
        self.ok = True
        self.names: set[str] = set()

    def generic_visit(self, node: ast.AST) -> None:
        allowed = (
            ast.Module,
            ast.Expr,
            ast.Assign,
            ast.For,
            ast.Name,
            ast.Load,
            ast.Store,
            ast.Constant,
            ast.List,
            ast.Tuple,
            ast.BinOp,
            ast.UnaryOp,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.FloorDiv,
            ast.Mod,
            ast.Pow,
            ast.USub,
            ast.UAdd,
            ast.Call,
        )
        if not isinstance(node, allowed):
            self.ok = False
            return
        super().generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            self.ok = False
            return
        self.visit(node.value)
        self.names.add(node.targets[0].id)

    def visit_For(self, node: ast.For) -> None:
        if not isinstance(node.target, ast.Name) or not isinstance(node.iter, (ast.List, ast.Tuple)):
            self.ok = False
            return
        self.visit(node.iter)
        previous = set(self.names)
        self.names.add(node.target.id)
        for child in node.body:
            self.visit(child)
        if node.orelse:
            self.ok = False
        self.names = previous

    def visit_Call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Name) or node.func.id not in {"print", "round"}:
            self.ok = False
            return
        if node.keywords:
            self.ok = False
            return
        for arg in node.args:
            self.visit(arg)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            return
        if node.id not in self.names and node.id not in {"print", "round"}:
            self.ok = False

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, (int, float, bool)) or node.value is None:
            return
        if isinstance(node.value, str):
            text = node.value
            if len(text) <= 120 and not re.search(r"https?://|[/\\]|\b(env|token|secret|key|password)\b", text, re.I):
                return
        self.ok = False


def _python_metadata_body_is_safe(body: str) -> bool:
    try:
        tree = ast.parse(str(body or ""))
    except SyntaxError:
        return False
    validator = _PythonMetadataValidator()
    validator.visit(tree)
    return validator.ok


def _has_network(command: str) -> bool:
    return bool(_NETWORK_SINK_RE.search(str(command or "")))


def _same_call_exfil_risk(command: str) -> bool:
    text = str(command or "")
    return bool(_has_network(text) and core._COMMAND_SUBSTITUTION_RE.search(text))


def _persists_remote_artifact(command: str) -> bool:
    text = str(command or "")
    if not _NETWORK_SINK_RE.search(text):
        return False
    text = _OUTPUT_DISCARD_RE.sub(" ", text)
    if not _REMOTE_PERSIST_RE.search(text):
        return False
    if re.search(r"\bwget\b", text, re.I) and _WGET_STDOUT_RE.search(text):
        scrubbed = re.sub(r"\bwget\b[^\n;|&]*", "", text, flags=re.I)
        return bool(_REMOTE_PERSIST_RE.search(scrubbed))
    return True


def _executes_local_artifact(command: str) -> bool:
    return bool(_LOCAL_ARTIFACT_EXEC_RE.search(str(command or "")))


def _terminal_safe_host_from_url(value: Any) -> str:
    parsed = urlparse(str(value or ""))
    if parsed.hostname:
        return parsed.hostname.lower()
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text, flags=re.I)
    text = text.split("/", 1)[0].split("@", 1)[-1].split(":", 1)[0]
    return text.lower().strip("[] ")


def _terminal_extract_urls(value: Any) -> list[str]:
    text = str(value or "")
    seen: set[str] = set()
    urls: list[str] = []
    for match in _REMOTE_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,);]")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _terminal_private_or_metadata_host(host: str) -> bool:
    import ipaddress

    host_l = str(host or "").lower().strip("[]").rstrip(".")
    if not host_l:
        return False
    if host_l in {"localhost", "metadata.google.internal"} or host_l.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host_l)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return False


_analyze_tool_call = analyze_tool_call
_TerminalAnalysis = TerminalAnalysis
