from __future__ import annotations

import json

import pytest

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
        {"query": "buscar correo electrónico de Alex"},
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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("请重置密码", "password reset"),
        ("पासवर्ड रीसेट करें", "password reset"),
        ("Réinitialiser le mot de passe", "password reset"),
        ("إعادة تعيين كلمة المرور", "password reset"),
        ("পাসওয়ার্ড রিসেট করুন", "password reset"),
        ("Redefinir sua senha", "password reset"),
        ("Сбросить пароль", "password reset"),
        ("پاس ورڈ ری سیٹ کریں", "password reset"),
        ("Reset kata sandi sekarang", "password reset"),
        ("Passwort zurücksetzen", "password reset"),
        ("パスワードリセットしてください", "password reset"),
        ("Reset ya password now", "password reset"),
        ("पासवर्ड रीसेट करा", "password reset"),
        ("పాస్వర్డ్ రీసెట్ చేయండి", "password reset"),
        ("Şifre sıfırlama isteği", "password reset"),
        ("கடவுச்சொல் மீட்டமைப்பு", "password reset"),
        ("Đặt lại mật khẩu", "password reset"),
        ("I-reset ang password", "password reset"),
        ("비밀번호 재설정", "password reset"),
        ("بازنشانی رمز عبور", "password reset"),
        ("新しいログイン セキュリティ警告", "security alert"),
        ("تمت إضافة مفتاح ssh", "security key change"),
        ("दो चरण सत्यापन सक्षम करें", "multi-factor auth"),
        ("lien magique pour se connecter", "magic link"),
        ("khôi phục tài khoản", "account recovery"),
    ],
)
def test_world_language_security_sensitive_reasons_detected(text, expected):
    plugin = load_plugin()

    assert plugin._sensitive_reason(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "验证码: 123456",
        "認証コード: 123456",
        "رمز التحقق: 123456",
        "کد تایید: 123456",
        "인증 코드: 123456",
        "कोड: 123456",
    ],
)
def test_world_language_auth_code_labels_detected(text):
    plugin = load_plugin()

    assert plugin._sensitive_reason(text) == "auth code"


@pytest.mark.parametrize(
    ("query", "needle"),
    [
        ("البريد الإلكتروني الخاص بAlex", "البريد الإلكتروني"),
        ("buscar endereço de Alex", "endereço"),
        ("найти телефон Alex", "телефон"),
        ("tìm email của Alex", "email"),
    ],
)
def test_world_language_private_field_labels_taint_args(query, needle):
    plugin = load_plugin()
    bind_owner(plugin)

    result = plugin._on_pre_tool_call(
        "web_search",
        {"query": query},
        session_id="s1",
    )

    assert result is not None
    assert "Data classes: contacts" in result["message"]
    assert needle not in result["message"]


@pytest.mark.parametrize(
    "snapshot",
    [
        "我的账户 - 退出登录",
        "アカウント - ログアウト",
        "حسابي - تسجيل الخروج",
        "내 계정 - 로그아웃",
    ],
)
def test_world_language_browser_private_context_terms_mark_private_input(snapshot):
    plugin = load_plugin()
    bind_owner(plugin)
    plugin._set_browser_host("s1", "https://example.com/account")

    plugin._on_transform_tool_result(
        "browser_snapshot",
        json.dumps({"text": snapshot}),
        session_id="s1",
    )

    assert "browser_private_input" in plugin._session_taint("s1")


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/验证?token=abc",
        "https://example.com/sifirla?token=abc",
        "https://example.com/khoi-phuc?token=abc",
    ],
)
def test_world_language_sensitive_links_block_tool_args(url):
    plugin = load_plugin()

    result = plugin._on_pre_tool_call(
        "browser_navigate",
        {"url": url},
        session_id="s1",
    )

    assert result == {
        "action": "block",
        "message": "Blocked by hermes-guardian: sensitive link detected in tool arguments.",
    }
