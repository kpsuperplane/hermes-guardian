"""Language pack validation and compiled semantic regex helpers."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import importlib.util
import os
import re
from typing import Any

_KNOWN_LANGUAGE_PACKS = (
    "en",
    "zh",
    "hi",
    "es",
    "fr",
    "ar",
    "bn",
    "pt",
    "ru",
    "ur",
    "id",
    "de",
    "ja",
    "pcm",
    "mr",
    "te",
    "tr",
    "ta",
    "vi",
    "tl",
    "ko",
    "fa",
)
_REQUIRED_PACK_KEYS = {
    "id",
    "name",
    "security_sensitive_phrases",
    "auth_code_labels",
    "private_field_labels",
    "browser_private_context_terms",
    "redaction_markers",
    "redacted_security_terms",
    "security_link_terms",
}
_LIST_KEYS = {
    "auth_code_labels",
    "private_field_labels",
    "browser_private_context_terms",
    "redaction_markers",
    "redacted_security_terms",
    "security_link_terms",
}


def _pack_exists(pack_id: str) -> bool:
    try:
        return importlib.util.find_spec(f"language_packs.{pack_id}") is not None
    except Exception:
        return False


_ALL_PACK_IDS = tuple(pack_id for pack_id in _KNOWN_LANGUAGE_PACKS if _pack_exists(pack_id))
_DEFAULT_LANGUAGE_PACKS = _ALL_PACK_IDS or ("en",)


@dataclass(frozen=True)
class CompiledLanguagePacks:
    ids: tuple[str, ...]
    security_sensitive_patterns: tuple[tuple[re.Pattern[str], str], ...]
    auth_code_label_pattern: re.Pattern[str]
    private_field_pattern: re.Pattern[str]
    browser_private_context_pattern: re.Pattern[str]
    redaction_marker_patterns: tuple[tuple[re.Pattern[str], str], ...]
    security_link_term_pattern: re.Pattern[str]
    redacted_security_context_pattern: re.Pattern[str]


def _pack_env() -> str:
    return os.getenv("HERMES_GUARDIAN_LANGUAGE_PACKS", "")


def _enabled_pack_ids(raw: str | None = None) -> tuple[str, ...]:
    text = _pack_env() if raw is None else str(raw or "")
    if not text.strip():
        return _DEFAULT_LANGUAGE_PACKS
    ids = [
        item.strip().lower()
        for item in re.split(r"[,;\s]+", text)
        if item.strip()
    ]
    if "all" in ids:
        ids = list(_ALL_PACK_IDS)
    if "en" not in ids:
        ids.insert(0, "en")
    deduped: list[str] = []
    for pack_id in ids:
        if (
            re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", pack_id)
            and pack_id in _ALL_PACK_IDS
            and pack_id not in deduped
        ):
            deduped.append(pack_id)
    return tuple(deduped or _DEFAULT_LANGUAGE_PACKS)


def _available_language_packs() -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    for pack_id in _ALL_PACK_IDS:
        pack = _load_pack(pack_id)
        packs.append({
            "id": pack["id"],
            "name": pack["name"],
            "default_enabled": pack["id"] in _DEFAULT_LANGUAGE_PACKS,
            "required": pack["id"] == "en",
        })
    return packs


def _validate_string_list(value: Any, *, field: str, pack_id: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"language pack {pack_id} field {field} must be a non-empty list")
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    if not out:
        raise ValueError(f"language pack {pack_id} field {field} must contain non-empty strings")
    return out


def _validate_pack(pack: Any) -> dict[str, Any]:
    if not isinstance(pack, dict):
        raise ValueError("language pack must be a dict")
    missing = sorted(_REQUIRED_PACK_KEYS - set(pack))
    if missing:
        raise ValueError("language pack missing required keys: " + ", ".join(missing))
    pack_id = str(pack.get("id") or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", pack_id):
        raise ValueError("language pack id is invalid")
    phrases = pack.get("security_sensitive_phrases")
    if not isinstance(phrases, dict) or not phrases:
        raise ValueError(f"language pack {pack_id} security_sensitive_phrases must be a non-empty dict")
    normalized_phrases: dict[str, list[str]] = {}
    for reason, values in phrases.items():
        reason_text = str(reason or "").strip()
        if not reason_text:
            raise ValueError(f"language pack {pack_id} has an empty security reason")
        normalized_phrases[reason_text] = _validate_string_list(values, field=f"security_sensitive_phrases.{reason_text}", pack_id=pack_id)
    normalized: dict[str, Any] = {
        "id": pack_id,
        "name": str(pack.get("name") or pack_id).strip() or pack_id,
        "security_sensitive_phrases": normalized_phrases,
    }
    for key in _LIST_KEYS:
        normalized[key] = _validate_string_list(pack.get(key), field=key, pack_id=pack_id)
    return normalized


def _load_pack(pack_id: str) -> dict[str, Any]:
    module = importlib.import_module(f"language_packs.{pack_id}")
    return _validate_pack(getattr(module, "PACK", None))


def _literal_phrase_pattern(phrases: list[str]) -> re.Pattern[str]:
    alternatives = [
        re.escape(phrase).replace(r"\ ", r"\s+")
        for phrase in sorted(phrases, key=len, reverse=True)
    ]
    return re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(alternatives) + r")(?![A-Za-z0-9_])", re.I | re.S)


def _terms_pattern(terms: list[str]) -> re.Pattern[str]:
    alternatives = [
        re.escape(term).replace(r"\ ", r"\s+")
        for term in sorted(terms, key=len, reverse=True)
    ]
    return re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(alternatives) + r")(?![A-Za-z0-9_])", re.I | re.S)


def _compile_language_packs(raw_ids: str | None = None) -> CompiledLanguagePacks:
    packs = [_load_pack(pack_id) for pack_id in _enabled_pack_ids(raw_ids)]
    loaded_ids = tuple(str(pack["id"]) for pack in packs)

    security_patterns: list[tuple[re.Pattern[str], str]] = []
    redaction_patterns: list[tuple[re.Pattern[str], str]] = []
    auth_labels: list[str] = []
    private_fields: list[str] = []
    browser_terms: list[str] = []
    link_terms: list[str] = []
    redacted_context_terms: list[str] = []

    for pack in packs:
        for reason, phrases in pack["security_sensitive_phrases"].items():
            security_patterns.append((_literal_phrase_pattern(phrases), reason))
        redaction_patterns.append((_literal_phrase_pattern(pack["redaction_markers"]), "redacted sensitive email"))
        auth_labels.extend(pack["auth_code_labels"])
        private_fields.extend(pack["private_field_labels"])
        browser_terms.extend(pack["browser_private_context_terms"])
        link_terms.extend(pack["security_link_terms"])
        redacted_context_terms.extend(pack["redacted_security_terms"])
        redacted_context_terms.extend(pack["auth_code_labels"])
        for phrases in pack["security_sensitive_phrases"].values():
            redacted_context_terms.extend(phrases)

    return CompiledLanguagePacks(
        ids=loaded_ids,
        security_sensitive_patterns=tuple(security_patterns),
        auth_code_label_pattern=_terms_pattern(auth_labels),
        private_field_pattern=_terms_pattern(private_fields),
        browser_private_context_pattern=_terms_pattern(browser_terms),
        redaction_marker_patterns=tuple(redaction_patterns),
        security_link_term_pattern=_terms_pattern(link_terms),
        redacted_security_context_pattern=_terms_pattern(redacted_context_terms),
    )


_COMPILED_LANGUAGE_PACKS = _compile_language_packs()
