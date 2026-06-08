from __future__ import annotations

import json

from support import *  # noqa: F403


def test_spanish_security_sensitive_reasons_detected():
    plugin = load_plugin()

    cases = [
        ("Restablecer tu contraseña ahora", "password reset"),
        ("Solicitud de recuperación de cuenta", "account recovery"),
        ("Tu código de verificación es 123456", "auth code"),
        ("Usa este código de un solo uso", "one-time code"),
        ("Abre tu enlace mágico para iniciar sesión", "magic link"),
        ("Alerta de seguridad: nuevo inicio de sesión", "security alert"),
        ("Se agregó una clave SSH a tu cuenta", "security key change"),
    ]

    for text, expected in cases:
        assert plugin._sensitive_reason(text) == expected


def test_spanish_sensitive_link_blocks_tool_args():
    plugin = load_plugin()

    result = plugin._on_pre_tool_call(
        "browser_navigate",
        {"url": "https://example.com/restablecer-contrasena?token=abc"},
        session_id="s1",
    )

    assert result == {
        "action": "block",
        "message": "Blocked by hermes-guardian: sensitive link detected in tool arguments.",
    }


def test_spanish_private_field_labels_taint_content_and_args():
    plugin = load_plugin()
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        "web_search",
        {"query": "buscar correo electrónico de Kevin"},
        session_id="s1",
    )

    assert result is not None
    assert "Data classes: contacts" in result["message"]
    assert "correo electrónico" not in result["message"]


def test_spanish_browser_private_context_marks_browser_private_input():
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/cuenta")

    plugin._on_transform_tool_result(
        "browser_snapshot",
        json.dumps({"text": "Mi cuenta - cerrar sesión"}),
        session_id="s1",
    )

    assert "browser_private_input" in plugin._session_taint("s1")
    result = plugin._on_pre_tool_call("browser_click", {"ref": "submit"}, session_id="s1")
    assert result is not None
    assert "Action: browser_click" in result["message"]


def test_spanish_security_sensitive_final_output_suppressed():
    plugin = load_plugin()

    transformed = plugin._on_transform_llm_output("Tu código de verificación es 123456")

    assert transformed == "[hermes-guardian omitted security-sensitive final response.]"


def test_spanish_sensitive_tool_result_suppressed():
    plugin = load_plugin()

    transformed = plugin._on_transform_tool_result(
        tool_name="mcp_gmail_read",
        result=json.dumps({"body": "Alerta de seguridad: inicio de sesión sospechoso"}),
        session_id="s1",
    )
    parsed = parse_json(transformed)

    assert parsed["hermes_guardian"]["suppressed"] is True
    assert parsed["hermes_guardian"]["reason"] == "security alert"

