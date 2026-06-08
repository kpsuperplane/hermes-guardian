from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from language_packs.en import PACK as EN_PACK
from language_packs.es import PACK as ES_PACK
from language_packs.runtime import (
    _available_language_packs,
    _compile_language_packs,
    _enabled_pack_ids,
    _literal_phrase_pattern,
    _validate_pack,
)


def test_bundled_language_packs_validate():
    for pack in (EN_PACK, ES_PACK):
        normalized = _validate_pack(pack)

        assert normalized["id"] == pack["id"]
        assert normalized["security_sensitive_phrases"]
        assert normalized["auth_code_labels"]
        assert normalized["private_field_labels"]
        assert normalized["browser_private_context_terms"]
        assert normalized["security_link_terms"]


def test_language_pack_selection_defaults_and_forces_english():
    assert _enabled_pack_ids("") == ("en", "es")
    assert _enabled_pack_ids("es") == ("en", "es")
    assert _enabled_pack_ids("all") == ("en", "es")


def test_available_language_pack_metadata_lists_bundled_packs():
    packs = {pack["id"]: pack for pack in _available_language_packs()}

    assert packs["en"]["name"] == "English"
    assert packs["en"]["required"] is True
    assert packs["es"]["name"] == "Spanish"


def test_language_pack_compiler_escapes_literal_phrases():
    pattern = _literal_phrase_pattern(["reset.password", "code?"])

    assert pattern.search("reset.password")
    assert pattern.search("code?")
    assert not pattern.search("reset-password")


def test_malformed_language_pack_fails_validation():
    with pytest.raises(ValueError):
        _validate_pack({"id": "bad"})


def test_compile_language_packs_exposes_multilingual_patterns():
    compiled = _compile_language_packs("en,es")

    assert compiled.auth_code_label_pattern.search("código de verificación")
    assert compiled.private_field_pattern.search("correo electrónico")
    assert compiled.browser_private_context_pattern.search("cerrar sesión")
    assert compiled.security_link_term_pattern.search("restablecer")
