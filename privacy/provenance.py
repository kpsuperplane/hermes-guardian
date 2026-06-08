"""Volatile metadata-only provenance for approximate copied-content matching."""

from __future__ import annotations


_PROVENANCE_MIN_CHARS = 24
_PROVENANCE_MIN_TOKENS = 4
_PROVENANCE_MAX_WINDOW_TOKENS = 16
_PROVENANCE_MAX_FINGERPRINTS_PER_TEXT = 96
_PROVENANCE_MAX_ENTRIES_PER_SESSION = 200
_PROVENANCE_MAX_MATCH_INPUT_CHARS = 20_000
_PROVENANCE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@'-]*")


def _provenance_source_label(tool_name: str) -> str:
    safe_tool = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(tool_name or "").strip())[:80]
    return safe_tool or "unknown"


def _provenance_normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _provenance_fingerprint(normalized_text: str) -> str:
    payload = f"provenance-v1:{normalized_text}".encode("utf-8")
    return hmac.new(_guardian_hmac_key(), payload, hashlib.sha256).hexdigest()


def _provenance_text_leaves(value: Any, *, depth: int = 0) -> list[str]:
    if value is None or depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        leaves: list[str] = []
        for item in list(value.values())[:80]:
            leaves.extend(_provenance_text_leaves(item, depth=depth + 1))
        return leaves
    if isinstance(value, (list, tuple)):
        leaves = []
        for item in list(value)[:80]:
            leaves.extend(_provenance_text_leaves(item, depth=depth + 1))
        return leaves
    return []


def _provenance_candidate_phrases(text: str) -> set[str]:
    if _sensitive_reason(text):
        return set()
    normalized = _provenance_normalize_text(text)
    if len(normalized) < _PROVENANCE_MIN_CHARS:
        return set()
    candidates: set[str] = set()
    if len(normalized) <= _PROVENANCE_MAX_MATCH_INPUT_CHARS:
        candidates.add(normalized)
    for segment in re.split(r"[\r\n.!?;]+", text):
        segment_norm = _provenance_normalize_text(segment)
        if len(segment_norm) >= _PROVENANCE_MIN_CHARS:
            candidates.add(segment_norm)
    tokens = [match.group(0).lower() for match in _PROVENANCE_TOKEN_RE.finditer(text)]
    if len(tokens) >= _PROVENANCE_MIN_TOKENS:
        max_window = min(_PROVENANCE_MAX_WINDOW_TOKENS, len(tokens))
        for size in range(_PROVENANCE_MIN_TOKENS, max_window + 1):
            for start in range(0, len(tokens) - size + 1):
                phrase = " ".join(tokens[start:start + size])
                if len(phrase) >= _PROVENANCE_MIN_CHARS:
                    candidates.add(phrase)
                if len(candidates) >= _PROVENANCE_MAX_FINGERPRINTS_PER_TEXT:
                    return candidates
    return candidates


def _provenance_fingerprints_for_value(value: Any) -> set[str]:
    fingerprints: set[str] = set()
    for text in _provenance_text_leaves(value):
        for phrase in _provenance_candidate_phrases(text):
            fingerprints.add(_provenance_fingerprint(phrase))
            if len(fingerprints) >= _PROVENANCE_MAX_FINGERPRINTS_PER_TEXT:
                return fingerprints
    return fingerprints


def _record_provenance_from_tool_result(
    session_id: str | None,
    tool_name: str,
    result_value: Any,
    classes: set[str],
) -> None:
    safe_classes = {str(cls) for cls in classes if str(cls)}
    if not safe_classes:
        return
    fingerprints = _provenance_fingerprints_for_value(result_value)
    if not fingerprints:
        return
    with _LOCK:
        state = _ensure_session(session_id)
        entries = state.setdefault("provenance", [])
        entries.append(
            {
                "fingerprints": fingerprints,
                "classes": safe_classes,
                "source_label": _provenance_source_label(tool_name),
                "ts": _now(),
            }
        )
        del entries[:-_PROVENANCE_MAX_ENTRIES_PER_SESSION]


def _provenance_match_classes(session_id: str | None, value: Any) -> set[str]:
    candidate_fingerprints = _provenance_fingerprints_for_value(value)
    if not candidate_fingerprints:
        return set()
    with _LOCK:
        state = _ensure_session(session_id)
        entries = list(state.get("provenance") or [])
    matched: set[str] = set()
    for entry in entries:
        fingerprints = entry.get("fingerprints") or set()
        if candidate_fingerprints.intersection(fingerprints):
            matched.update(str(cls) for cls in (entry.get("classes") or set()) if str(cls))
    return matched


def _clear_session_provenance(session_id: str | None) -> None:
    with _LOCK:
        _ensure_session(session_id).pop("provenance", None)
